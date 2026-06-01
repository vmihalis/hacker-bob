#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.join(__dirname, "..");
const MANIFEST_PATH = path.join(ROOT, "test", "mcp-test-manifest.json");

function main() {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  if (!Array.isArray(manifest) || manifest.some((entry) => typeof entry !== "string" || !entry.trim())) {
    throw new Error("test/mcp-test-manifest.json must contain a non-empty array of test file paths");
  }

  const testProjectDir = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-mcp-project-"));
  let result;
  try {
    result = spawnSync(process.execPath, ["--test", ...manifest], {
      cwd: ROOT,
      env: {
        ...process.env,
        BOB_PROJECT_DIR: testProjectDir,
      },
      stdio: "inherit",
    });
  } finally {
    fs.rmSync(testProjectDir, { recursive: true, force: true });
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
