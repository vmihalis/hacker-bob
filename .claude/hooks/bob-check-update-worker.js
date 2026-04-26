#!/usr/bin/env node
"use strict";

const update = require("./bob-update-lib.js");

async function main() {
  const projectDir = process.argv[2] || process.env.CLAUDE_PROJECT_DIR || process.cwd();
  await update.refreshUpdateCache(projectDir, {
    force: true,
    includeChangelog: false,
    timeoutMs: Number(process.env.HACKER_BOB_UPDATE_TIMEOUT_MS) || 8000,
  });
}

main().catch(() => {
  process.exit(0);
});
