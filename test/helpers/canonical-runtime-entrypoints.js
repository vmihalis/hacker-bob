"use strict";

const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

function flattenExportTargets(value, label, targets = []) {
  if (value === null || value === undefined) return targets;
  if (typeof value === "string") {
    targets.push(value);
    return targets;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      flattenExportTargets(value[index], `${label}[${index}]`, targets);
    }
    return targets;
  }
  if (typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      flattenExportTargets(child, `${label}.${key}`, targets);
    }
    return targets;
  }
  throw new TypeError(`${label} contains a non-path export target`);
}

function declaredRuntimeEntrypoints(runtimeRoot, relativeRoots) {
  const absoluteRuntimeRoot = path.resolve(runtimeRoot);
  const entries = [];
  for (const relativeRoot of relativeRoots) {
    const packageRoot = path.resolve(absoluteRuntimeRoot, relativeRoot);
    const manifestPath = path.join(packageRoot, "package.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const targets = [];
    if (manifest.main !== undefined) {
      if (typeof manifest.main !== "string") {
        throw new TypeError(`${relativeRoot} main must be a string`);
      }
      targets.push(manifest.main);
    }
    flattenExportTargets(manifest.exports, `${relativeRoot} exports`, targets);
    const absoluteTargets = new Set(targets.map((target) => path.resolve(packageRoot, target)));
    for (const absoluteTarget of absoluteTargets) {
      const fromPackage = path.relative(packageRoot, absoluteTarget);
      if (!fromPackage || fromPackage.startsWith("..") || path.isAbsolute(fromPackage)) {
        throw new Error(`${relativeRoot} entrypoint escapes its package root: ${absoluteTarget}`);
      }
      entries.push({
        package_name: manifest.name,
        package_root: relativeRoot.split(path.sep).join("/"),
        entrypoint: path.relative(absoluteRuntimeRoot, absoluteTarget).split(path.sep).join("/"),
      });
    }
  }
  return entries;
}

const ISOLATED_ENTRYPOINT_LOADER = String.raw`
"use strict";
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");

const runtimeRoot = fs.realpathSync(path.resolve(process.argv[1]));
const relativeRoots = JSON.parse(process.argv[2]);

function inside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function flatten(value, label, targets) {
  if (value === null || value === undefined) return;
  if (typeof value === "string") {
    targets.push(value);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((child, index) => flatten(child, label + "[" + index + "]", targets));
    return;
  }
  if (typeof value === "object") {
    Object.entries(value).forEach(([key, child]) => flatten(child, label + "." + key, targets));
    return;
  }
  throw new TypeError(label + " contains a non-path export target");
}

if (!fs.statSync(runtimeRoot).isDirectory()) throw new Error("runtime root is not a directory");
if (process.env.NODE_PATH) throw new Error("NODE_PATH must be empty in the isolated loader");

const resolvedModules = new Set();
const originalLoad = Module._load;
Module._load = function closedCanonicalLoad(request, parent, isMain) {
  if (Module.isBuiltin(request)) {
    return Reflect.apply(originalLoad, this, [request, parent, isMain]);
  }
  const resolved = Module._resolveFilename(request, parent, isMain);
  if (!inside(runtimeRoot, resolved)) {
    throw new Error("canonical runtime resolved outside its extracted root: " + resolved);
  }
  if (resolved.split(path.sep).includes("node_modules")) {
    throw new Error("canonical runtime resolved through node_modules: " + resolved);
  }
  resolvedModules.add(path.relative(runtimeRoot, resolved).split(path.sep).join("/"));
  return Reflect.apply(originalLoad, this, [request, parent, isMain]);
};

const loaded = [];
for (const relativeRoot of relativeRoots) {
  const packageRoot = path.resolve(runtimeRoot, relativeRoot);
  if (!inside(runtimeRoot, packageRoot)) throw new Error("package root escaped runtime root");
  const manifestPath = path.join(packageRoot, "package.json");
  const manifestStat = fs.lstatSync(manifestPath);
  if (!manifestStat.isFile() || manifestStat.isSymbolicLink()) {
    throw new Error(relativeRoot + " manifest is not a regular file");
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const targets = [];
  if (manifest.main !== undefined) {
    if (typeof manifest.main !== "string") throw new TypeError(relativeRoot + " main must be a string");
    targets.push(manifest.main);
  }
  flatten(manifest.exports, relativeRoot + " exports", targets);
  const absoluteTargets = new Set(targets.map((target) => path.resolve(packageRoot, target)));
  for (const absoluteTarget of absoluteTargets) {
    if (!inside(packageRoot, absoluteTarget)) {
      throw new Error(relativeRoot + " entrypoint escaped its package root: " + absoluteTarget);
    }
    const targetStat = fs.lstatSync(absoluteTarget);
    if (!targetStat.isFile() || targetStat.isSymbolicLink()) {
      throw new Error(relativeRoot + " entrypoint is not a regular file: " + absoluteTarget);
    }
    require(absoluteTarget);
    loaded.push({
      package_name: manifest.name,
      package_root: relativeRoot.split(path.sep).join("/"),
      entrypoint: path.relative(runtimeRoot, absoluteTarget).split(path.sep).join("/"),
    });
  }
}

process.stdout.write(JSON.stringify({
  loaded,
  resolved_modules: [...resolvedModules].sort(),
}));
`;

function loadCanonicalRuntimeEntrypoints({
  runtimeRoot,
  relativeRoots,
  isolatedHome,
  requireNoNodeModules = false,
}) {
  const absoluteRuntimeRoot = path.resolve(runtimeRoot);
  const absoluteHome = path.resolve(isolatedHome);
  fs.mkdirSync(absoluteHome, { recursive: true });
  if (requireNoNodeModules) {
    const stack = [absoluteRuntimeRoot];
    while (stack.length > 0) {
      const current = stack.pop();
      for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        if (entry.name === "node_modules") {
          throw new Error(`ambient node_modules is present inside isolated runtime: ${current}`);
        }
        if (entry.isDirectory()) stack.push(path.join(current, entry.name));
      }
    }
  }
  const output = execFileSync(process.execPath, [
    "--no-global-search-paths",
    "-e",
    ISOLATED_ENTRYPOINT_LOADER,
    absoluteRuntimeRoot,
    JSON.stringify(relativeRoots),
  ], {
    cwd: absoluteRuntimeRoot,
    env: {
      ...process.env,
      HOME: absoluteHome,
      NODE_OPTIONS: "",
      NODE_PATH: "",
    },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return JSON.parse(output);
}

module.exports = {
  declaredRuntimeEntrypoints,
  loadCanonicalRuntimeEntrypoints,
};
