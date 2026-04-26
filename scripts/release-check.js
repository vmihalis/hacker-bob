#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const COMPAT_ROOT = path.join(ROOT, "packages", "hacker-bob-cc");
const NPM_CACHE = process.env.HACKER_BOB_RELEASE_NPM_CACHE || path.join(os.tmpdir(), "hacker-bob-release-check-npm-cache");
const args = new Set(process.argv.slice(2));
const registryMode = args.has("--registry");
const allowPublished = args.has("--allow-published");

let failures = 0;
let warnings = 0;

function log(status, message) {
  console.log(`${status} ${message}`);
}

function pass(message) {
  log("OK", message);
}

function info(message) {
  log("INFO", message);
}

function warn(message) {
  warnings += 1;
  log("WARN", message);
}

function fail(message) {
  failures += 1;
  log("FAIL", message);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function exists(filePath) {
  return fs.existsSync(filePath);
}

function sourceTreeFiles(relativeDir) {
  const root = path.join(ROOT, relativeDir);
  if (!exists(root)) return [];
  const files = [];
  const visit = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        visit(full);
      } else if (entry.isFile()) {
        files.push(path.relative(ROOT, full).split(path.sep).join("/"));
      }
    }
  };
  visit(root);
  return files.sort();
}

function expectedCanonicalFiles() {
  return Array.from(new Set([
    "package.json",
    "README.md",
    "LICENSE",
    "NOTICE",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "DISCLAIMER.md",
    "SECURITY.md",
    "install.sh",
    ...sourceTreeFiles(".hacker-bob"),
    ...sourceTreeFiles(".claude"),
    ...sourceTreeFiles("adapters"),
    ...sourceTreeFiles("bin"),
    ...sourceTreeFiles("docs"),
    ...sourceTreeFiles("mcp"),
    ...sourceTreeFiles("prompts"),
    ...sourceTreeFiles("scripts"),
  ])).sort();
}

function run(command, commandArgs, options = {}) {
  return spawnSync(command, commandArgs, {
    cwd: options.cwd || ROOT,
    env: {
      ...process.env,
      npm_config_cache: NPM_CACHE,
      ...(options.env || {}),
    },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function npm(commandArgs, options = {}) {
  return run("npm", commandArgs, options);
}

function parseJsonOutput(result, description) {
  const output = String(result.stdout || "").trim();
  try {
    return JSON.parse(output);
  } catch (error) {
    fail(`${description} did not return parseable JSON: ${error.message}`);
    if (output) info(`${description} stdout: ${output.slice(0, 500)}`);
    if (result.stderr) info(`${description} stderr: ${String(result.stderr).trim().slice(0, 500)}`);
    return null;
  }
}

function pack(cwd, label) {
  const result = npm(["pack", "--dry-run", "--json"], { cwd });
  if (result.status !== 0) {
    fail(`${label} npm pack failed: ${String(result.stderr || result.stdout).trim()}`);
    return null;
  }
  const packs = parseJsonOutput(result, `${label} npm pack`);
  if (!Array.isArray(packs) || packs.length !== 1) {
    fail(`${label} npm pack returned an unexpected result`);
    return null;
  }
  return packs[0];
}

function fileSet(packResult) {
  return new Set((packResult.files || []).map((file) => file.path));
}

function assertEqual(actual, expected, message) {
  if (actual === expected) {
    pass(message);
  } else {
    fail(`${message}: expected ${expected}, got ${actual}`);
  }
}

function assertFile(filePath, message) {
  if (exists(filePath)) {
    pass(message);
  } else {
    fail(`${message}: missing ${path.relative(ROOT, filePath)}`);
  }
}

function checkManifest() {
  const rootPackage = readJson(path.join(ROOT, "package.json"));
  const compatPackage = readJson(path.join(COMPAT_ROOT, "package.json"));

  assertEqual(rootPackage.name, "hacker-bob", "canonical package name is hacker-bob");
  assertEqual(compatPackage.name, "hacker-bob-cc", "compatibility package name is hacker-bob-cc");
  assertEqual(compatPackage.version, rootPackage.version, "compatibility version matches canonical version");
  assertEqual(
    compatPackage.dependencies && compatPackage.dependencies["hacker-bob"],
    rootPackage.version,
    "compatibility dependency pins the canonical package version",
  );

  assertFile(path.join(ROOT, "CHANGELOG.md"), "CHANGELOG.md exists");
  const changelog = fs.readFileSync(path.join(ROOT, "CHANGELOG.md"), "utf8");
  if (changelog.includes(`## [${rootPackage.version}]`)) {
    pass(`CHANGELOG.md has a ${rootPackage.version} section`);
  } else {
    fail(`CHANGELOG.md is missing a ${rootPackage.version} section`);
  }

  assertFile(
    path.join(ROOT, "docs", "releases", `v${rootPackage.version}.md`),
    `release notes exist for v${rootPackage.version}`,
  );

  return { rootPackage, compatPackage };
}

function checkCanonicalPack(rootPackage) {
  const canonical = pack(ROOT, "canonical package");
  if (!canonical) return;
  const files = fileSet(canonical);

  assertEqual(canonical.name, "hacker-bob", "canonical pack name is hacker-bob");
  assertEqual(canonical.version, rootPackage.version, "canonical pack version matches package.json");

  for (const expected of expectedCanonicalFiles()) {
    if (files.has(expected)) {
      pass(`canonical pack includes ${expected}`);
    } else {
      fail(`canonical pack is missing ${expected}`);
    }
  }

  if (canonical.size < 1500000) {
    pass(`canonical pack size ${canonical.size} bytes is under 1.5 MB`);
  } else {
    fail(`canonical pack size ${canonical.size} bytes exceeds 1.5 MB`);
  }

  let foundDisallowed = false;
  for (const file of files) {
    if (file.startsWith("test/") || file.startsWith("tests/")) {
      foundDisallowed = true;
      fail(`canonical pack includes test artifact ${file}`);
    }
    if (file.startsWith("packages/")) {
      foundDisallowed = true;
      fail(`canonical pack includes nested package artifact ${file}`);
    }
    if (file.startsWith(".github/")) {
      foundDisallowed = true;
      fail(`canonical pack includes GitHub metadata ${file}`);
    }
    if (file.startsWith(".cache/") || file.startsWith("cache/") || file.includes("/.cache/")) {
      foundDisallowed = true;
      fail(`canonical pack includes cache artifact ${file}`);
    }
    if (file === ".claude/hooks/bob-update-lib.js") {
      foundDisallowed = true;
      fail("canonical pack includes deprecated hook-local update library");
    }
    if (file.includes("bounty-agent-sessions")) {
      foundDisallowed = true;
      fail(`canonical pack includes session artifact ${file}`);
    }
  }
  if (!foundDisallowed) {
    pass("canonical pack excludes tests, cache files, nested packages, and session artifacts");
  }
}

function checkCompatibilityPack(rootPackage) {
  const compat = pack(COMPAT_ROOT, "compatibility package");
  if (!compat) return;
  const files = Array.from(fileSet(compat)).sort();

  assertEqual(compat.name, "hacker-bob-cc", "compatibility pack name is hacker-bob-cc");
  assertEqual(compat.version, rootPackage.version, "compatibility pack version matches canonical version");

  const expected = ["bin/hacker-bob.js", "package.json"];
  if (JSON.stringify(files) === JSON.stringify(expected)) {
    pass("compatibility pack contains only wrapper and manifest");
  } else {
    fail(`compatibility pack contents mismatch: ${files.join(", ")}`);
  }

  if (compat.size < 3000) {
    pass(`compatibility pack size ${compat.size} bytes is under 3 KB`);
  } else {
    fail(`compatibility pack size ${compat.size} bytes exceeds 3 KB`);
  }
}

function npmJson(commandArgs, description, options = {}) {
  const result = npm([...commandArgs, "--json"], options);
  if (result.status !== 0) {
    if (options.allowFailure) return { ok: false, result };
    fail(`${description} failed: ${String(result.stderr || result.stdout).trim()}`);
    return { ok: false, result };
  }
  return { ok: true, value: parseJsonOutput(result, description), result };
}

function checkPackageRegistry(name, version) {
  const metadata = npmJson(["view", name, "name", "version", "dist-tags"], `npm view ${name}`);
  if (!metadata.ok || !metadata.value) return;

  pass(`${name} resolves on npm`);
  const latest = metadata.value.version || (metadata.value["dist-tags"] && metadata.value["dist-tags"].latest);
  const localVersion = npmJson(
    ["view", `${name}@${version}`, "version"],
    `npm view ${name}@${version}`,
    { allowFailure: true },
  );
  const isPublished = localVersion.ok && localVersion.value === version;

  if (isPublished) {
    if (allowPublished) {
      pass(`${name}@${version} is already published and allowed for this check`);
    } else {
      fail(`${name}@${version} is already published; pass --allow-published when checking an existing release`);
    }
  } else {
    pass(`${name}@${version} is not published yet`);
  }

  if (latest === version) {
    pass(`${name} latest dist-tag matches ${version}`);
  } else if (isPublished) {
    fail(`${name} latest dist-tag is ${latest}; expected ${version}`);
  } else {
    info(`${name} latest dist-tag is ${latest}; it should become ${version} after publish`);
  }
}

function permissionText(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.join(",");
  if (value && typeof value === "object") return JSON.stringify(value);
  return "";
}

function hasReadWrite(value) {
  const text = permissionText(value);
  return text.includes("read-write") || (text.includes("read") && text.includes("write"));
}

function checkRegistry(rootPackage, compatPackage) {
  const whoami = npm(["whoami"]);
  if (whoami.status === 0 && String(whoami.stdout).trim()) {
    pass(`npm whoami succeeds as ${String(whoami.stdout).trim()}`);
  } else {
    fail(`npm whoami failed: ${String(whoami.stderr || whoami.stdout).trim()}`);
  }

  checkPackageRegistry(rootPackage.name, rootPackage.version);
  checkPackageRegistry(compatPackage.name, compatPackage.version);

  const access = npm(["access", "ls-packages", "--json"]);
  if (access.status !== 0) {
    warn(
      "Could not verify npm read-write package access. Ensure the token can read and write hacker-bob and hacker-bob-cc.",
    );
    if (access.stderr) info(`npm access stderr: ${String(access.stderr).trim().slice(0, 500)}`);
    return;
  }

  const accessMap = parseJsonOutput(access, "npm access ls-packages");
  if (!accessMap) return;
  for (const name of [rootPackage.name, compatPackage.name]) {
    if (hasReadWrite(accessMap[name])) {
      pass(`npm access lists ${name} as read-write`);
    } else {
      fail(`npm access does not list ${name} as read-write`);
    }
  }
}

function main() {
  console.log("Hacker Bob release check");
  if (registryMode) info("registry checks enabled");

  const { rootPackage, compatPackage } = checkManifest();
  checkCanonicalPack(rootPackage);
  checkCompatibilityPack(rootPackage);

  if (registryMode) checkRegistry(rootPackage, compatPackage);

  if (failures > 0) {
    console.error(`Release check failed with ${failures} failure(s) and ${warnings} warning(s).`);
    process.exit(1);
  }
  console.log(`Release check passed with ${warnings} warning(s).`);
}

main();
