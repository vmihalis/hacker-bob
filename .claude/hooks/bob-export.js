#!/usr/bin/env node
"use strict";

const path = require("path");

function projectRootFromHook() {
  return path.resolve(__dirname, "..", "..");
}

function loadExporter(projectRoot) {
  return require(path.join(projectRoot, "mcp", "core", "bob-export.js"));
}

function main(argv) {
  const projectDir = path.resolve(argv[0] || process.env.CLAUDE_PROJECT_DIR || projectRootFromHook());
  const exporter = loadExporter(projectDir);
  const result = exporter.exportBobReleaseBundle({
    projectDir,
    env: {
      ...process.env,
      BOB_PROJECT_DIR: projectDir,
    },
  });
  process.stdout.write(exporter.renderExportResult(result));
}

try {
  main(process.argv.slice(2));
} catch (error) {
  console.error(error && error.message ? error.message : String(error));
  process.exit(1);
}
