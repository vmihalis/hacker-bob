#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const {
  bountyagentSkillAllowedTools,
} = require("../adapters/claude/config.js");
const {
  renderClaudeRole,
  updateClaudeRoleFile,
} = require("./lib/claude-role-renderer.js");

const ROOT = path.join(__dirname, "..");
const SKILL_PATH = path.join(ROOT, ".claude", "skills", "bob-hunt", "SKILL.md");

function splitFrontmatter(document) {
  const match = document.match(/^---\n[\s\S]*?\n---\n/);
  if (!match) return { body: document };
  return { body: document.slice(match[0].length) };
}

function renderFrontmatter() {
  const allowedTools = bountyagentSkillAllowedTools()
    .map((tool) => `  - ${tool}`)
    .join("\n");
  return [
    "---",
    "name: bob-hunt",
    "disable-model-invocation: true",
    'argument-hint: "[target-url | resume <domain> [force-merge]]"',
    "allowed-tools:",
    allowedTools,
    "---",
    "",
  ].join("\n");
}

function renderSkill(document) {
  if (document === undefined) return renderClaudeRole("orchestrator");
  const { body } = splitFrontmatter(document);
  return `${renderFrontmatter()}${body.replace(/^\n+/, "")}`;
}

function updateSkill({ check = false } = {}) {
  return updateClaudeRoleFile("orchestrator", { check, root: ROOT });
}

function main() {
  const check = process.argv.includes("--check");
  const changed = updateSkill({ check });
  if (changed && !check) console.log("updated bob-hunt skill frontmatter");
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
