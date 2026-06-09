#!/usr/bin/env node
"use strict";

const {
  getAdapter,
} = require("../adapters/index.js");

const OPENCODE_ADAPTER = getAdapter("opencode");

function main() {
  const check = process.argv.includes("--check");
  const changed = OPENCODE_ADAPTER.render({ check });
  if (changed && !check) console.log("updated OpenCode subagent files");
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
  updateOpencodeRoleFiles: OPENCODE_ADAPTER.render,
};
