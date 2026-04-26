#!/usr/bin/env node
"use strict";

const path = require("path");
const { spawn } = require("child_process");
const update = require("./bob-update-lib.js");

function main() {
  const projectDir = process.argv[2] || process.env.CLAUDE_PROJECT_DIR || process.cwd();
  if (!update.isCacheStale(projectDir)) return;

  const worker = path.join(__dirname, "bob-check-update-worker.js");
  const child = spawn(process.execPath, [worker, projectDir], {
    detached: true,
    stdio: "ignore",
    env: process.env,
  });
  child.unref();
}

try {
  main();
} catch {
  process.exit(0);
}
