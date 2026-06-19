"use strict";

const fs = require("fs");
const path = require("path");
// Shared, allowlist-guarded PATH probe — the single sink for `command -v`.
// Aliased to defaultCommandExists to preserve the detectAdapterId override hook.
const { commandExists: defaultCommandExists } = require("../scripts/lib/command-exists.js");

const claude = require("./claude/index.js");
const codex = require("./codex/index.js");
const genericMcp = require("./generic-mcp/index.js");
const kimi = require("./kimi/index.js");

const ADAPTERS = Object.freeze({
  [claude.id]: claude,
  [codex.id]: codex,
  [genericMcp.id]: genericMcp,
  [kimi.id]: kimi,
});
const DEFAULT_ADAPTER_ID = "claude";
const ALL_ADAPTER_IDS = Object.freeze(Object.keys(ADAPTERS));

function getAdapter(id) {
  const adapter = ADAPTERS[id];
  if (!adapter) throw new Error(`Unknown Bob adapter: ${id}`);
  return adapter;
}

function normalizeSelection(selection) {
  if (selection == null || selection === "") return [];
  if (Array.isArray(selection)) return selection.flatMap((value) => normalizeSelection(value));
  return String(selection)
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function adapterIdsForSelection(selection, options = {}) {
  const defaultIds = options.defaultIds || [DEFAULT_ADAPTER_ID];
  const rawIds = normalizeSelection(selection);
  const requested = rawIds.length === 0 ? defaultIds : rawIds;
  const expanded = requested.includes("all") ? ALL_ADAPTER_IDS : requested;
  const seen = new Set();
  const ids = [];
  for (const id of expanded) {
    getAdapter(id);
    if (seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
  }
  return ids;
}

function safeIsDir(fsModule, candidate) {
  try {
    return fsModule.statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}

function safeIsFile(fsModule, candidate) {
  try {
    return fsModule.statSync(candidate).isFile();
  } catch {
    return false;
  }
}

// Layered adapter detection for install-time intent. Returns
// { id, reason, layer } so callers can log the decision to stderr.
// Pure given (projectDir, env, commandExists, fs); no global state read.
//
// Reinstall metadata is intentionally NOT consulted here — that signal lives
// in scripts/install.js where the install metadata path already factors in.
function detectAdapterId(projectDir, options = {}) {
  const env = options.env || process.env;
  const commandExists = options.commandExists || defaultCommandExists;
  const fsModule = options.fs || fs;

  // Layer 1: host environment markers — strongest live signal that an AI
  // agent or operator was invoked from inside a specific host CLI.
  if (env.CLAUDE_PROJECT_DIR) {
    return { id: "claude", reason: "env_CLAUDE_PROJECT_DIR", layer: "env" };
  }
  if (env.CODEX_HOME) {
    return { id: "codex", reason: "env_CODEX_HOME", layer: "env" };
  }
  if (env.KIMI_PROJECT_DIR) {
    return { id: "kimi", reason: "env_KIMI_PROJECT_DIR", layer: "env" };
  }

  // Layer 2: project artifacts — the user is inside a project that already
  // has host-specific tooling configured.
  if (projectDir) {
    if (safeIsDir(fsModule, path.join(projectDir, ".claude"))) {
      return { id: "claude", reason: "project_dot_claude", layer: "project" };
    }
    if (safeIsDir(fsModule, path.join(projectDir, ".codex", "plugins"))) {
      return { id: "codex", reason: "project_codex_plugins", layer: "project" };
    }
    if (safeIsDir(fsModule, path.join(projectDir, ".agents", "plugins"))) {
      return { id: "codex", reason: "project_agents_plugins", layer: "project" };
    }
    if (safeIsDir(fsModule, path.join(projectDir, ".kimi"))) {
      return { id: "kimi", reason: "project_dot_kimi", layer: "project" };
    }
    if (safeIsFile(fsModule, path.join(projectDir, ".mcp.json"))) {
      return { id: "generic-mcp", reason: "project_mcp_json", layer: "project" };
    }
  }

  // Layer 3: CLI on PATH — a capability signal, weakest of the live signals.
  // Both available means we cannot disambiguate; fall through to default.
  const claudeOnPath = commandExists("claude");
  const codexOnPath = commandExists("codex");
  const kimiOnPath = commandExists("kimi");
  if (claudeOnPath && !codexOnPath && !kimiOnPath) {
    return { id: "claude", reason: "cli_on_path_claude", layer: "cli" };
  }
  if (codexOnPath && !claudeOnPath && !kimiOnPath) {
    return { id: "codex", reason: "cli_on_path_codex", layer: "cli" };
  }
  if (kimiOnPath && !claudeOnPath && !codexOnPath) {
    return { id: "kimi", reason: "cli_on_path_kimi", layer: "cli" };
  }

  // Layer 4: hard-coded fallback.
  return { id: DEFAULT_ADAPTER_ID, reason: "default_fallback", layer: "fallback" };
}

module.exports = {
  ADAPTERS,
  ALL_ADAPTER_IDS,
  DEFAULT_ADAPTER_ID,
  adapterIdsForSelection,
  detectAdapterId,
  getAdapter,
};
