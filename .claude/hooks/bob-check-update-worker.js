#!/usr/bin/env node
"use strict";

const path = require("path");
const update = require(path.join(__dirname, "..", "..", "mcp", "lib", "update-check.js"));

async function main() {
  const projectDir = process.argv[2] || process.env.BOB_PROJECT_DIR || process.env.CLAUDE_PROJECT_DIR || process.cwd();
  await update.refreshUpdateCache(projectDir, {
    force: true,
    includeChangelog: false,
    timeoutMs: Number(process.env.HACKER_BOB_UPDATE_TIMEOUT_MS) || 8000,
  });
}

main().catch(() => {
  process.exit(0);
});
