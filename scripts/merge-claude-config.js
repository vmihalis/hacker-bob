#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const {
  defaultClaudeSettings,
  permissionsForAllTools,
} = require("../adapters/claude/config.js");
const {
  STALE_HOOK_SCRIPT_NAMES,
} = require("./lib/package-policy.js");

function readJsonIfExists(filePath, fallback) {
  if (!fs.existsSync(filePath)) return fallback;
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function uniqueStrings(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.trim())));
}

const STALE_GLOBAL_MCP_PERMISSIONS = Object.freeze([
  "mcp__hacker-bob__bob_merge_wave_handoffs",
  "mcp__bountyagent__bob_merge_wave_handoffs",
]);

// Legacy MCP server key from v1.x installs. v2.0.0 renames the server key to
// `hacker-bob` and rewrites permission strings accordingly. The migration shim
// (`migrateLegacyServerKey`) auto-rewrites existing `.mcp.json` and
// `.claude/settings.json` files on install/update so operator-managed sibling
// servers and custom permissions are preserved.
const LEGACY_SERVER_KEY = "bountyagent";
const CANONICAL_SERVER_KEY = "hacker-bob";
const LEGACY_PERMISSION_PREFIX = `mcp__${LEGACY_SERVER_KEY}__`;
const CANONICAL_PERMISSION_PREFIX = `mcp__${CANONICAL_SERVER_KEY}__`;

// Hook command-string rewrites applied to merged `.claude/settings.json` so
// operator-customized hook arrays that reference filenames from prior rename
// generations (`hunter-subagent-stop.js` -> `agent-run-stop.js`,
// `bounty-statusline.js` -> `bob-statusline.js`) point at the canonical hook
// files this install ships. Filename-only rewrites; the project-dir prefix
// and surrounding quoting in the command string are preserved verbatim.
const LEGACY_HOOK_COMMAND_REWRITES = Object.freeze([
  Object.freeze({ from: "hunter-subagent-stop.js", to: "agent-run-stop.js" }),
  Object.freeze({ from: "bounty-statusline.js", to: "bob-statusline.js" }),
]);

// Permission-string tool-name rewrites applied to merged `.claude/settings.json`
// so v1.x installs that allow-listed `mcp__hacker-bob__bounty_*` (the legacy
// tool-suffix from the pre-P.1 rename generation) get their canonical
// `mcp__hacker-bob__bob_*` permission on upgrade. Server-key migration is
// handled separately by `rewriteLegacyPermissionString` (bountyagent ->
// hacker-bob); this rewrite is layered on top to also normalize the suffix.
//
// Excludes the bona-fide P.1 deprecation-shim tool names — those have their
// own registry modules and route through their own handler with the legacy
// argument schema; their permission strings must remain `bounty_*`.
const PRESERVED_BOUNTY_TOOL_NAMES = Object.freeze([
  "bounty_transition_phase",
  "bounty_report_written",
]);
const LEGACY_TOOL_NAME_PREFIX = "bounty_";
const CANONICAL_TOOL_NAME_PREFIX = "bob_";
const HACKER_BOB_BOUNTY_PERMISSION_PATTERN = new RegExp(
  `^${CANONICAL_PERMISSION_PREFIX.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")}${LEGACY_TOOL_NAME_PREFIX}(.+)$`,
);

function rewriteLegacyPermissionString(value) {
  if (typeof value !== "string") return value;
  if (!value.startsWith(LEGACY_PERMISSION_PREFIX)) return value;
  return `${CANONICAL_PERMISSION_PREFIX}${value.slice(LEGACY_PERMISSION_PREFIX.length)}`;
}

function rewriteLegacyToolNamePermission(value) {
  if (typeof value !== "string") return value;
  const match = HACKER_BOB_BOUNTY_PERMISSION_PATTERN.exec(value);
  if (!match) return value;
  const suffix = match[1];
  const fullToolName = `${LEGACY_TOOL_NAME_PREFIX}${suffix}`;
  // Bona-fide P.1 shim tools own their own handler and keep the bounty_
  // prefix in the permission allow-list because the server still dispatches
  // them under that exact name (they are not aliases of a bob_ primary).
  if (PRESERVED_BOUNTY_TOOL_NAMES.includes(fullToolName)) return value;
  return `${CANONICAL_PERMISSION_PREFIX}${CANONICAL_TOOL_NAME_PREFIX}${suffix}`;
}

function migrateLegacyMcp(existing) {
  if (!existing || typeof existing !== "object" || Array.isArray(existing)) {
    return { value: existing, migrated: false };
  }
  if (!existing.mcpServers || typeof existing.mcpServers !== "object" || Array.isArray(existing.mcpServers)) {
    return { value: existing, migrated: false };
  }
  if (!Object.prototype.hasOwnProperty.call(existing.mcpServers, LEGACY_SERVER_KEY)) {
    return { value: existing, migrated: false };
  }
  // Idempotency: if the canonical key already exists alongside the legacy key,
  // drop the legacy key without overwriting the operator-current canonical
  // entry.
  const nextServers = { ...existing.mcpServers };
  const legacyEntry = nextServers[LEGACY_SERVER_KEY];
  delete nextServers[LEGACY_SERVER_KEY];
  if (!Object.prototype.hasOwnProperty.call(nextServers, CANONICAL_SERVER_KEY)) {
    nextServers[CANONICAL_SERVER_KEY] = legacyEntry;
  }
  return {
    value: { ...existing, mcpServers: nextServers },
    migrated: true,
  };
}

function migrateLegacySettings(existing) {
  if (!existing || typeof existing !== "object" || Array.isArray(existing)) {
    return { value: existing, migrated: false };
  }
  if (!existing.permissions || typeof existing.permissions !== "object") {
    return { value: existing, migrated: false };
  }
  const allow = Array.isArray(existing.permissions.allow) ? existing.permissions.allow : null;
  if (!allow) {
    return { value: existing, migrated: false };
  }
  let touched = false;
  // Two layered rewrites: first the server-key prefix (bountyagent ->
  // hacker-bob), then the tool-name suffix (bounty_* -> bob_*) for permissions
  // that already sit under the canonical server key. The order matters because
  // the suffix rewrite only fires on strings that already start with the
  // canonical prefix.
  const rewritten = allow.map((permission) => {
    const afterServerKey = rewriteLegacyPermissionString(permission);
    const afterToolName = rewriteLegacyToolNamePermission(afterServerKey);
    if (afterToolName !== permission) touched = true;
    return afterToolName;
  });
  if (!touched) return { value: existing, migrated: false };
  // Idempotency: dedupe in case both the legacy and canonical permission
  // strings already coexist (e.g. operator added a custom mcp__hacker-bob__*
  // permission before the migration ran).
  const deduped = uniqueStrings(rewritten);
  return {
    value: {
      ...existing,
      permissions: {
        ...existing.permissions,
        allow: deduped,
      },
    },
    migrated: true,
  };
}

function migrateLegacyServerKey({ mcp, settings, logger } = {}) {
  const mcpResult = migrateLegacyMcp(mcp);
  const settingsPermissions = migrateLegacySettings(settings);
  const settingsHooks = migrateLegacyHookCommands(settingsPermissions.value);
  const settingsMigrated = settingsPermissions.migrated || settingsHooks.migrated;
  if (logger && (mcpResult.migrated || settingsMigrated)) {
    const surfaces = [];
    if (mcpResult.migrated) surfaces.push(".mcp.json");
    if (settingsMigrated) surfaces.push(".claude/settings.json");
    logger(`migrating legacy MCP server key ${LEGACY_SERVER_KEY} -> ${CANONICAL_SERVER_KEY} in: ${surfaces.join(", ")}`);
  }
  return {
    mcp: mcpResult.value,
    settings: settingsHooks.value,
    migrated: mcpResult.migrated || settingsMigrated,
  };
}

function rewriteLegacyHookCommand(command) {
  if (typeof command !== "string") return command;
  let next = command;
  for (const rewrite of LEGACY_HOOK_COMMAND_REWRITES) {
    if (next.includes(rewrite.from)) {
      // Restrict replacement to the embedded `.claude/hooks/<file>` segment so
      // unrelated tokens that happen to contain the same substring (e.g. a
      // path comment) are not rewritten.
      next = next.split(`.claude/hooks/${rewrite.from}`).join(`.claude/hooks/${rewrite.to}`);
    }
  }
  return next;
}

function rewriteHookEntry(entry) {
  if (!entry || typeof entry !== "object" || !Array.isArray(entry.hooks)) return { entry, changed: false };
  let touched = false;
  const hooks = entry.hooks.map((hook) => {
    if (!hook || typeof hook !== "object" || typeof hook.command !== "string") return hook;
    const next = rewriteLegacyHookCommand(hook.command);
    if (next === hook.command) return hook;
    touched = true;
    return { ...hook, command: next };
  });
  if (!touched) return { entry, changed: false };
  return { entry: { ...entry, hooks }, changed: true };
}

function dedupeHookEntries(entries) {
  if (!Array.isArray(entries)) return { entries, changed: false };
  let changed = false;
  const out = [];
  for (const entry of entries) {
    if (!entry || typeof entry !== "object" || !Array.isArray(entry.hooks)) {
      out.push(entry);
      continue;
    }
    const seenScripts = new Set();
    const hooks = [];
    for (const hook of entry.hooks) {
      const scriptName = hookScriptName(hook && hook.command);
      if (scriptName) {
        if (seenScripts.has(scriptName)) {
          changed = true;
          continue;
        }
        seenScripts.add(scriptName);
      }
      hooks.push(hook);
    }
    if (hooks.length === entry.hooks.length) {
      out.push(entry);
    } else {
      out.push({ ...entry, hooks });
    }
  }
  return { entries: out, changed };
}

function migrateLegacyHookCommands(existing) {
  if (!existing || typeof existing !== "object" || Array.isArray(existing)) {
    return { value: existing, migrated: false };
  }
  let touched = false;
  let next = existing;

  // statusLine: rewrite the embedded hook filename if it points at a legacy
  // script name.
  if (existing.statusLine && typeof existing.statusLine === "object" && typeof existing.statusLine.command === "string") {
    const nextStatusLineCommand = rewriteLegacyHookCommand(existing.statusLine.command);
    if (nextStatusLineCommand !== existing.statusLine.command) {
      touched = true;
      next = {
        ...next,
        statusLine: { ...existing.statusLine, command: nextStatusLineCommand },
      };
    }
  }

  // hooks.*: walk every event -> entry -> hook and rewrite, then dedupe by
  // script filename so a legacy-pointing entry and a canonical-pointing entry
  // for the same trigger collapse to a single canonical entry.
  if (existing.hooks && typeof existing.hooks === "object" && !Array.isArray(existing.hooks)) {
    const nextHooks = { ...existing.hooks };
    let hooksTouched = false;
    for (const [eventName, entries] of Object.entries(existing.hooks)) {
      if (!Array.isArray(entries)) continue;
      let eventTouched = false;
      const rewrittenEntries = entries.map((entry) => {
        const result = rewriteHookEntry(entry);
        if (result.changed) eventTouched = true;
        return result.entry;
      });
      const dedupedResult = dedupeHookEntries(rewrittenEntries);
      if (eventTouched || dedupedResult.changed) {
        nextHooks[eventName] = dedupedResult.entries;
        hooksTouched = true;
      }
    }
    if (hooksTouched) {
      touched = true;
      next = { ...next, hooks: nextHooks };
    }
  }

  return { value: next, migrated: touched };
}

function hookKey(hook) {
  return JSON.stringify({
    type: hook && hook.type,
    command: hook && hook.command,
    timeout: hook && hook.timeout,
  });
}

function hookScriptName(command) {
  const match = String(command || "").match(/\.claude\/hooks\/([^"'\s]+)/);
  return match ? match[1] : null;
}

function isStaleHook(hook) {
  const scriptName = hookScriptName(hook && hook.command);
  return !!scriptName && STALE_HOOK_SCRIPT_NAMES.includes(scriptName);
}

function mergeHookEntries(existingHooks, bobHooks) {
  const byMatcher = new Map();
  for (const entry of [...(Array.isArray(existingHooks) ? existingHooks : [])]) {
    if (!entry || typeof entry.matcher !== "string") continue;
    const existingEntryHooks = Array.isArray(entry.hooks) ? entry.hooks : [];
    const hooks = existingEntryHooks.filter((hook) => !isStaleHook(hook));
    if (existingEntryHooks.length > 0 && hooks.length === 0) continue;
    byMatcher.set(entry.matcher, {
      ...entry,
      hooks,
    });
  }

  for (const bobEntry of bobHooks) {
    const current = byMatcher.get(bobEntry.matcher) || { matcher: bobEntry.matcher, hooks: [] };
    for (const hook of bobEntry.hooks || []) {
      const scriptName = hookScriptName(hook.command);
      if (scriptName) {
        current.hooks = current.hooks.filter((existingHook) => (
          hookScriptName(existingHook.command) !== scriptName ||
          hookKey(existingHook) === hookKey(hook)
        ));
      }
      const seen = new Set(current.hooks.map(hookKey));
      const key = hookKey(hook);
      if (seen.has(key)) continue;
      current.hooks.push({ ...hook });
    }
    byMatcher.set(bobEntry.matcher, current);
  }

  return Array.from(byMatcher.values());
}

function mergePreToolUseHooks(existingHooks, bobHooks) {
  return mergeHookEntries(existingHooks, bobHooks);
}

function mergeHooks(existingHooks, bobHooks) {
  const next = existingHooks && typeof existingHooks === "object" && !Array.isArray(existingHooks)
    ? { ...existingHooks }
    : {};
  const bob = bobHooks && typeof bobHooks === "object" && !Array.isArray(bobHooks)
    ? bobHooks
    : {};

  for (const [eventName, bobEntries] of Object.entries(bob)) {
    next[eventName] = mergeHookEntries(next[eventName], bobEntries);
  }
  return next;
}

function mergeSettings(existing, bobSettings) {
  const permissionsMigrated = migrateLegacySettings(existing).value;
  const hooksMigrated = migrateLegacyHookCommands(permissionsMigrated).value;
  const next = hooksMigrated && typeof hooksMigrated === "object" && !Array.isArray(hooksMigrated)
    ? { ...hooksMigrated }
    : {};
  const existingPermissions = next.permissions && typeof next.permissions === "object"
    ? next.permissions
    : {};
  const existingAllow = Array.isArray(existingPermissions.allow) ? existingPermissions.allow : [];
  // Permission allow-list assembly:
  //   1. Surviving operator entries (after dropping stale globals).
  //   2. Generated defaults from defaultClaudeSettings() — keeps the source-of-
  //      truth ordering for tools that satisfy `global_preapproval: true`.
  //   3. Every canonical primary tool from permissionsForAllTools(), minus the
  //      stale-global list. On upgrade this guarantees newly-shipped tools
  //      (e.g. browser-driver + pack telemetry) land in the workspace allow-
  //      list even when they are not part of the globally-preapproved default
  //      set, so agents whose brief mentions them can invoke without per-call
  //      permission churn. Aliases are filtered out by permissionsForAllTools();
  //      the bona-fide `bounty_transition_phase` and `bounty_report_written`
  //      shim tools own their own primary registry entries and are surfaced
  //      here under their canonical (and only) names.
  next.permissions = {
    ...existingPermissions,
    allow: uniqueStrings([
      ...existingAllow.filter((permission) => !STALE_GLOBAL_MCP_PERMISSIONS.includes(permission)),
      ...bobSettings.permissions.allow,
      ...permissionsForAllTools().filter((permission) => !STALE_GLOBAL_MCP_PERMISSIONS.includes(permission)),
    ]),
  };

  const existingHooks = next.hooks && typeof next.hooks === "object" ? next.hooks : {};
  next.hooks = mergeHooks(existingHooks, bobSettings.hooks);
  next.statusLine = bobSettings.statusLine;
  return next;
}

// External adversarial-roast MCP server consumed by the brutalist-verifier
// role. Optional — registered alongside hacker-bob but not required at
// runtime. See prompts/roles/brutalist-verifier.md for the graceful-fallback
// contract.
const BRUTALIST_MCP_SERVER = Object.freeze({
  command: "npx",
  args: ["-y", "@brutalist/mcp@1.14.7"],
});

function mergeMcp(existing, serverPath) {
  const migrated = migrateLegacyMcp(existing).value;
  const next = migrated && typeof migrated === "object" && !Array.isArray(migrated)
    ? { ...migrated }
    : {};
  next.mcpServers = next.mcpServers && typeof next.mcpServers === "object" && !Array.isArray(next.mcpServers)
    ? { ...next.mcpServers }
    : {};
  next.mcpServers[CANONICAL_SERVER_KEY] = {
    command: "node",
    args: [serverPath],
  };
  next.mcpServers.brutalist = { ...BRUTALIST_MCP_SERVER, args: [...BRUTALIST_MCP_SERVER.args] };
  return next;
}

function main() {
  const target = path.resolve(process.argv[2] || ".");
  const serverPath = path.join(target, "mcp", "server.js");
  const mcpPath = path.join(target, ".mcp.json");
  const settingsPath = path.join(target, ".claude", "settings.json");
  const bobSettings = defaultClaudeSettings();

  // Migration shim: rewrite any legacy `bountyagent` server key + permission
  // strings to `hacker-bob` before the regular merge step. Idempotent; no-op
  // when the canonical key is already present.
  const existingMcp = readJsonIfExists(mcpPath, {});
  const existingSettings = readJsonIfExists(settingsPath, {});
  const migration = migrateLegacyServerKey({
    mcp: existingMcp,
    settings: existingSettings,
    logger: (message) => console.log(message),
  });

  writeJson(mcpPath, mergeMcp(migration.mcp, serverPath));
  writeJson(settingsPath, mergeSettings(migration.settings, bobSettings));

  console.log(`merged ${mcpPath}`);
  console.log(`merged ${settingsPath}`);
}

if (require.main === module) {
  main();
}

module.exports = {
  BRUTALIST_MCP_SERVER,
  CANONICAL_SERVER_KEY,
  CANONICAL_TOOL_NAME_PREFIX,
  LEGACY_HOOK_COMMAND_REWRITES,
  LEGACY_SERVER_KEY,
  LEGACY_PERMISSION_PREFIX,
  CANONICAL_PERMISSION_PREFIX,
  LEGACY_TOOL_NAME_PREFIX,
  PRESERVED_BOUNTY_TOOL_NAMES,
  STALE_GLOBAL_MCP_PERMISSIONS,
  STALE_HOOK_SCRIPT_NAMES,
  hookScriptName,
  mergeMcp,
  mergeHookEntries,
  mergeHooks,
  mergePreToolUseHooks,
  mergeSettings,
  migrateLegacyHookCommands,
  migrateLegacyMcp,
  migrateLegacySettings,
  migrateLegacyServerKey,
  rewriteLegacyHookCommand,
  rewriteLegacyPermissionString,
  rewriteLegacyToolNamePermission,
};
