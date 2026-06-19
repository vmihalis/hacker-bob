#!/usr/bin/env node
"use strict";

const path = require("path");
const {
  CLAUDE_ROLE_SPECS,
  renderClaudeRole,
  updateClaudeRoleFile,
} = require("./lib/claude-role-renderer.js");

const ROOT = path.join(__dirname, "..");
const SKILL_PATH = path.join(ROOT, CLAUDE_ROLE_SPECS.orchestrator.output_path);

// Single-skill regenerator preserved for backwards-compat (`npm run check:skill`
// targets this script). All rendering must go through claude-role-renderer.js
// so the frontmatter description/name stays canonical — a previous local
// renderFrontmatter() here drifted from the canonical renderer and shipped
// description-less SKILL.md files into target installs.
function renderSkill() {
  return renderClaudeRole("orchestrator");
}

function updateSkill({ check = false } = {}) {
  return updateClaudeRoleFile("orchestrator", { check, root: ROOT });
}

function main() {
  const check = process.argv.includes("--check");
  const changed = updateSkill({ check });
  if (changed && !check) console.log("updated bob-evaluate-runner skill frontmatter");
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
  renderSkill,
  updateSkill,
};
