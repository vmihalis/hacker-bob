"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

const LEGACY_CLAUDE_RESOURCE_DIR = ".claude";
const NEUTRAL_RESOURCE_DIR = ".hacker-bob";

function nonEmptyEnv(name, env = process.env) {
  const value = env[name];
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function packageRoot() {
  return path.resolve(__dirname, "..", "..", "..");
}

function readVersionFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const text = fs.readFileSync(filePath, "utf8").trim();
    return text || null;
  } catch {
    return null;
  }
}

function readPackageVersion(root) {
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    if (manifest && manifest.name === "hacker-bob" && typeof manifest.version === "string") {
      return manifest.version.trim() || null;
    }
  } catch {}
  return null;
}

function bobVersion(env = process.env) {
  const envVersion = typeof env.BOB_VERSION === "string" ? env.BOB_VERSION.trim() : "";
  if (envVersion) return envVersion;

  const project = projectRoot(env);
  const source = packageRoot();
  const projectVersions = project === source ? [] : [
    readVersionFile(path.join(project, NEUTRAL_RESOURCE_DIR, "VERSION")),
    readVersionFile(path.join(project, LEGACY_CLAUDE_RESOURCE_DIR, "bob", "VERSION")),
  ];
  return (
    projectVersions.find(Boolean) ||
    readPackageVersion(source) ||
    readVersionFile(path.join(source, NEUTRAL_RESOURCE_DIR, "VERSION")) ||
    readVersionFile(path.join(source, LEGACY_CLAUDE_RESOURCE_DIR, "bob", "VERSION")) ||
    "0.0.0"
  );
}

function runtimeClient(env = process.env) {
  return nonEmptyEnv("BOB_CLIENT", env) || (nonEmptyEnv("CLAUDE_PROJECT_DIR", env) ? "claude" : "unknown");
}

function projectRoot(env = process.env) {
  return path.resolve(
    nonEmptyEnv("BOB_PROJECT_DIR", env) ||
    nonEmptyEnv("CLAUDE_PROJECT_DIR", env) ||
    packageRoot(),
  );
}

function uniquePaths(paths) {
  const seen = new Set();
  const unique = [];
  for (const candidate of paths) {
    if (!candidate) continue;
    const resolved = path.resolve(candidate);
    if (seen.has(resolved)) continue;
    seen.add(resolved);
    unique.push(resolved);
  }
  return unique;
}

function resourceRoots(env = process.env) {
  const project = projectRoot(env);
  const source = packageRoot();
  return uniquePaths([
    nonEmptyEnv("BOB_RESOURCE_DIR", env),
    path.join(project, NEUTRAL_RESOURCE_DIR),
    path.join(project, LEGACY_CLAUDE_RESOURCE_DIR),
    path.join(source, NEUTRAL_RESOURCE_DIR),
    path.join(source, LEGACY_CLAUDE_RESOURCE_DIR),
    path.join(os.homedir(), NEUTRAL_RESOURCE_DIR),
    path.join(os.homedir(), LEGACY_CLAUDE_RESOURCE_DIR),
  ]);
}

function resourceCandidatePaths(...segments) {
  return resourceRoots().map((root) => path.join(root, ...segments));
}

function resolveResourcePath(...segments) {
  for (const candidate of resourceCandidatePaths(...segments)) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch {}
  }
  return null;
}

function readResourceText(...segments) {
  const filePath = resolveResourcePath(...segments);
  if (!filePath) return null;
  return fs.readFileSync(filePath, "utf8");
}

module.exports = {
  LEGACY_CLAUDE_RESOURCE_DIR,
  NEUTRAL_RESOURCE_DIR,
  bobVersion,
  packageRoot,
  projectRoot,
  readResourceText,
  resolveResourcePath,
  resourceCandidatePaths,
  resourceRoots,
  runtimeClient,
};
