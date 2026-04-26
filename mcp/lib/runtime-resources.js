"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

const LEGACY_CLAUDE_RESOURCE_DIR = ".claude";
const NEUTRAL_RESOURCE_DIR = ".hacker-bob";

function nonEmptyEnv(name) {
  const value = process.env[name];
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function packageRoot() {
  return path.resolve(__dirname, "..", "..");
}

function runtimeClient() {
  return nonEmptyEnv("BOB_CLIENT") || (nonEmptyEnv("CLAUDE_PROJECT_DIR") ? "claude" : "unknown");
}

function projectRoot() {
  return path.resolve(
    nonEmptyEnv("BOB_PROJECT_DIR") ||
    nonEmptyEnv("CLAUDE_PROJECT_DIR") ||
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

function resourceRoots() {
  const project = projectRoot();
  const source = packageRoot();
  return uniquePaths([
    nonEmptyEnv("BOB_RESOURCE_DIR"),
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
  packageRoot,
  projectRoot,
  readResourceText,
  resolveResourcePath,
  resourceCandidatePaths,
  resourceRoots,
  runtimeClient,
};
