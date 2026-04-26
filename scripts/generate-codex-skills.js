#!/usr/bin/env node
"use strict";

const {
  updateCodexSkillFiles,
} = require("./lib/codex-role-renderer.js");

function main() {
  const check = process.argv.includes("--check");
  const changed = updateCodexSkillFiles({ check });
  if (changed && !check) console.log("updated Codex skill files");
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
  updateCodexSkillFiles,
};
