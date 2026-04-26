#!/usr/bin/env node
"use strict";

const {
  getAdapter,
} = require("../adapters/index.js");

const CLAUDE_ADAPTER = getAdapter("claude");

function main() {
  const check = process.argv.includes("--check");
  const changed = CLAUDE_ADAPTER.render({ check });
  if (changed && !check) console.log("updated Claude role and command files");
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message || String(error));
    process.exit(1);
  }
}

module.exports = {
  updateClaudeRoleFiles: CLAUDE_ADAPTER.render,
};
