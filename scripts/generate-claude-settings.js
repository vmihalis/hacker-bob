#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const {
  defaultClaudeSettings,
  permissionsForAllTools,
} = require("../adapters/claude/config.js");
const {
  STALE_GLOBAL_MCP_PERMISSIONS,
} = require("./merge-claude-config.js");

const ROOT = path.join(__dirname, "..");
const SETTINGS_PATH = path.join(ROOT, ".claude", "settings.json");
const PROJECT_DIR_EXPR = "${CLAUDE_PROJECT_DIR:-$PWD}";
const APPROVAL_GATE_MATCHER = "mcp__hacker-bob__bob_advance_session|mcp__hacker-bob__bob_finalize_report";

function uniqueStrings(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.trim())));
}

// Canonical permission allow-list for the source-tree .claude/settings.json.
// Mirrors the install-time merge in scripts/merge-claude-config.js:377-384, but
// without seeding from an existing operator allow list — the source tree must
// reflect ONLY the canonical merge so drift is observable. Operator-personal
// entries belong in .claude/settings.local.json.
function canonicalAllow() {
  const bob = defaultClaudeSettings();
  return uniqueStrings([
    ...bob.permissions.allow,
    ...permissionsForAllTools().filter((permission) => !STALE_GLOBAL_MCP_PERMISSIONS.includes(permission)),
  ]);
}

function approvalGateHookEntry() {
  return {
    matcher: APPROVAL_GATE_MATCHER,
    hooks: [
      {
        type: "command",
        command: `bash "${PROJECT_DIR_EXPR}/.claude/hooks/bob-approval-gate.sh"`,
        timeout: 5,
      },
    ],
  };
}

function isAgentcoreBranch() {
  return process.env.BOB_AGENTCORE === "1";
}

function withApprovalGateMatcher(preToolUseHooks) {
  const withoutApprovalGate = preToolUseHooks.filter((entry) => (
    !(entry && entry.matcher === APPROVAL_GATE_MATCHER)
  ));
  if (isAgentcoreBranch()) {
    withoutApprovalGate.push(approvalGateHookEntry());
  }
  return withoutApprovalGate;
}

function readJsonIfExists(filePath, fallback) {
  if (!fs.existsSync(filePath)) return fallback;
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

// Build the next settings object: preserve every top-level key on `existing`
// (hooks, statusLine, plus any future operator additions) and every non-`allow`
// key on `existing.permissions`. Only `permissions.allow` is overwritten with
// the canonical list.
function renderSettings(existing) {
  const base = existing && typeof existing === "object" && !Array.isArray(existing)
    ? existing
    : {};
  const existingPermissions = base.permissions && typeof base.permissions === "object" && !Array.isArray(base.permissions)
    ? base.permissions
    : {};
  const existingHooks = base.hooks && typeof base.hooks === "object" && !Array.isArray(base.hooks)
    ? base.hooks
    : {};
  const existingPreToolUse = Array.isArray(existingHooks.PreToolUse)
    ? existingHooks.PreToolUse
    : [];
  return {
    ...base,
    permissions: {
      ...existingPermissions,
      allow: canonicalAllow(),
    },
    hooks: {
      ...existingHooks,
      PreToolUse: withApprovalGateMatcher(existingPreToolUse),
    },
  };
}

function serialize(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function updateSettings({ check = false } = {}) {
  const existingRaw = fs.existsSync(SETTINGS_PATH)
    ? fs.readFileSync(SETTINGS_PATH, "utf8")
    : "";
  const existing = readJsonIfExists(SETTINGS_PATH, {});
  const next = renderSettings(existing);
  const nextRaw = serialize(next);
  if (nextRaw === existingRaw) return false;
  if (check) {
    const existingAllow = Array.isArray(existing && existing.permissions && existing.permissions.allow)
      ? existing.permissions.allow
      : [];
    const canonical = canonicalAllow();
    const missing = canonical.filter((entry) => !existingAllow.includes(entry));
    const extra = existingAllow.filter((entry) => !canonical.includes(entry));
    const parts = [`${path.relative(ROOT, SETTINGS_PATH)} is stale; run node scripts/generate-claude-settings.js`];
    if (missing.length > 0) {
      parts.push(`(${missing.length} missing, e.g. ${missing[0]})`);
    }
    if (extra.length > 0) {
      parts.push(`(${extra.length} extra, e.g. ${extra[0]})`);
    }
    throw new Error(parts.join(" "));
  }
  fs.mkdirSync(path.dirname(SETTINGS_PATH), { recursive: true });
  fs.writeFileSync(SETTINGS_PATH, nextRaw, "utf8");
  return true;
}

function main() {
  const check = process.argv.includes("--check");
  const changed = updateSettings({ check });
  if (changed && !check) console.log("updated .claude/settings.json permissions.allow");
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
  APPROVAL_GATE_MATCHER,
  approvalGateHookEntry,
  canonicalAllow,
  isAgentcoreBranch,
  renderSettings,
  updateSettings,
  withApprovalGateMatcher,
};
