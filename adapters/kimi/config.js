"use strict";

const path = require("path");

const KIMI_SKILL_SPECS = Object.freeze({
  evaluate: Object.freeze({
    role_id: "orchestrator",
    output_path: path.join("adapters", "kimi", "skills", "bob-evaluate", "SKILL.md"),
    references_path: path.join("adapters", "kimi", "skills", "bob-evaluate", "references"),
    name: "bob-evaluate",
    description: "Run or resume a Hacker Bob bug bounty evaluate in Kimi CLI using the shared MCP runtime.",
    type: "standard",
  }),
  status: Object.freeze({
    role_id: "status",
    output_path: path.join("adapters", "kimi", "skills", "bob-status", "SKILL.md"),
    name: "bob-status",
    description: "Read Hacker Bob session state, wave status, findings, verification, and grade summaries in Kimi CLI.",
    type: "standard",
  }),
  debug: Object.freeze({
    role_id: "debug",
    output_path: path.join("adapters", "kimi", "skills", "bob-debug", "SKILL.md"),
    name: "bob-debug",
    description: "Debug Hacker Bob sessions in Kimi CLI using MCP telemetry and local session artifacts.",
    type: "standard",
  }),
  update: Object.freeze({
    output_path: path.join("adapters", "kimi", "skills", "bob-update", "SKILL.md"),
    name: "bob-update",
    description: "Check for Hacker Bob package updates and guide project-local update installation from Kimi CLI.",
    type: "standard",
  }),
  export: Object.freeze({
    output_path: path.join("adapters", "kimi", "skills", "bob-export", "SKILL.md"),
    name: "bob-export",
    description: "Create a Hacker Bob post-release improvement bundle for the currently installed Bob version.",
    type: "standard",
  }),
  egress: Object.freeze({
    output_path: path.join("adapters", "kimi", "skills", "bob-egress", "SKILL.md"),
    name: "bob-egress",
    description: "List, add, test, enable, disable, or remove Hacker Bob egress profiles from Kimi CLI.",
    type: "standard",
  }),
});

// Kimi adapter ships hook source files in adapters/kimi/hooks/ but does NOT
// install them. The Kimi CLI's ~/.kimi/config.toml PreToolUse registration
// syntax is not yet documented anywhere in this repo, so installing the
// scripts without wiring them would ship a security control that never fires
// — strictly worse than the codex adapter's prompt-only discipline model.
// When a future PR researches the TOML format and ships the wiring, restore
// KIMI_HOOK_FILES + EXECUTABLE_HOOKS here and re-introduce the install block.
const BOB_SKILLS = Object.freeze(["bob-evaluate", "bob-status", "bob-debug", "bob-update", "bob-export", "bob-egress"]);
// bob-hunt (v1) and bob-evaluate-runner (interim v2 misname that copied Claude's
// internal skill name) predate the rename to the user-facing bob-evaluate; list
// them so uninstall and dev-sync sweep stale skill dirs left by prior installs.
const LEGACY_BOB_SKILLS = Object.freeze(["bob-evaluate-runner", "bob-hunt"]);

module.exports = {
  BOB_SKILLS,
  KIMI_SKILL_SPECS,
  LEGACY_BOB_SKILLS,
};
