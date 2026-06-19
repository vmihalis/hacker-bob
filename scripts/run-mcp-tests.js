#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.join(__dirname, "..");
const MANIFEST_PATH = path.join(ROOT, "test", "mcp-test-manifest.json");
const EGRESS_PROFILES_PATH = path.join(ROOT, ".claude", "bob", "egress-profiles.json");

function ensureEgressProfilesSeed() {
  if (fs.existsSync(EGRESS_PROFILES_PATH)) return null;
  const egress = require(path.join(ROOT, "mcp", "lib", "egress-profiles.js"));
  fs.mkdirSync(path.dirname(EGRESS_PROFILES_PATH), { recursive: true });
  egress.writeEgressProfilesDocument(ROOT, egress.defaultEgressProfilesDocument());
  return () => fs.rmSync(EGRESS_PROFILES_PATH, { force: true });
}

function main() {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  if (!Array.isArray(manifest) || manifest.some((entry) => typeof entry !== "string" || !entry.trim())) {
    throw new Error("test/mcp-test-manifest.json must contain a non-empty array of test file paths");
  }

  const cleanupSeed = ensureEgressProfilesSeed();
  let result;
  try {
    result = spawnSync(process.execPath, ["--test", ...manifest], {
      cwd: ROOT,
      env: process.env,
      stdio: "inherit",
    });
  } finally {
    if (cleanupSeed) cleanupSeed();
  }

  if (result.error) throw result.error;
  if (result.status !== 0) {
    process.exit(result.status || 1);
  }
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message || String(error));
    process.exit(1);
  }
}
