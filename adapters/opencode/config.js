"use strict";

const path = require("path");

// OpenCode (https://opencode.ai) reads a project-root `opencode.json` config
// file, discovers named subagents from `.opencode/agents/*.md`, and slash
// commands from `.opencode/commands/*.md`. Bob renders one subagent per role
// (orchestrator = mode:primary, the rest = mode:subagent) and wires the MCP
// server into `opencode.json`; the orchestrator dispatches the per-role
// subagents through the task tool (`task(subagent_type: "bob-<role>")` —
// `@bob-<role>` mentions are a manual operator path only).

// Project-root config file Bob merges its MCP entries into. The installer
// preserves every other key the operator already configured.
const CONFIG_FILE = "opencode.json";
const CONFIG_SCHEMA = "https://opencode.ai/config.json";

// Per-role subagent files, OpenCode-native slash commands, and Bob install
// metadata all live under the project-local `.opencode/` directory.
const AGENTS_DIR = path.join(".opencode", "agents");
const COMMANDS_DIR = path.join(".opencode", "commands");
const BOB_DIR = path.join(".opencode", "bob");

// Each command renders to `.opencode/commands/<file>`. The command name is the
// file stem, so `bob-evaluate.md` is invoked as `/bob-evaluate`.
const COMMAND_SPECS = Object.freeze({
  evaluate: Object.freeze({
    file: "bob-evaluate.md",
    command: "bob-evaluate",
    description: "Run or resume a Hacker Bob bug bounty evaluate.",
    argumentHint: "<target|resume target [force-merge]> [--no-auth|--normal|--paranoid|--yolo] [--deep] [--egress <profile>] [--block-internal-hosts|--allow-internal-hosts]",
  }),
  status: Object.freeze({
    file: "bob-status.md",
    command: "bob-status",
    description: "Show the latest Hacker Bob session status.",
    argumentHint: "[target]",
  }),
  debug: Object.freeze({
    file: "bob-debug.md",
    command: "bob-debug",
    description: "Debug the latest or selected Hacker Bob run.",
    argumentHint: "[target] [--deep]",
  }),
  update: Object.freeze({
    file: "bob-update.md",
    command: "bob-update",
    description: "Check or apply Hacker Bob project-local updates.",
    argumentHint: "[check|apply]",
  }),
  export: Object.freeze({
    file: "bob-export.md",
    command: "bob-export",
    description: "Create a Hacker Bob post-release improvement bundle.",
    argumentHint: "[no arguments]",
  }),
  egress: Object.freeze({
    file: "bob-egress.md",
    command: "bob-egress",
    description: "Manage Hacker Bob egress profiles.",
    argumentHint: "[list|add <name>|test <name>|enable <name>|disable <name>|remove <name>]",
  }),
});

module.exports = {
  AGENTS_DIR,
  BOB_DIR,
  COMMANDS_DIR,
  COMMAND_SPECS,
  CONFIG_FILE,
  CONFIG_SCHEMA,
};
