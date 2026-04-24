#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const {
  defaultClaudeSettings,
} = require("../mcp/lib/claude-config.js");

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

function hookKey(hook) {
  return JSON.stringify({
    type: hook && hook.type,
    command: hook && hook.command,
    timeout: hook && hook.timeout,
  });
}

function mergeHookEntries(existingHooks, bobHooks) {
  const byMatcher = new Map();
  for (const entry of [...(Array.isArray(existingHooks) ? existingHooks : [])]) {
    if (!entry || typeof entry.matcher !== "string") continue;
    byMatcher.set(entry.matcher, {
      ...entry,
      hooks: Array.isArray(entry.hooks) ? entry.hooks.slice() : [],
    });
  }

  for (const bobEntry of bobHooks) {
    const current = byMatcher.get(bobEntry.matcher) || { matcher: bobEntry.matcher, hooks: [] };
    const seen = new Set(current.hooks.map(hookKey));
    for (const hook of bobEntry.hooks || []) {
      const key = hookKey(hook);
      if (seen.has(key)) continue;
      current.hooks.push({ ...hook });
      seen.add(key);
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
  const next = existing && typeof existing === "object" && !Array.isArray(existing)
    ? { ...existing }
    : {};
  const existingPermissions = next.permissions && typeof next.permissions === "object"
    ? next.permissions
    : {};
  next.permissions = {
    ...existingPermissions,
    allow: uniqueStrings([
      ...(Array.isArray(existingPermissions.allow) ? existingPermissions.allow : []),
      ...bobSettings.permissions.allow,
    ]),
  };

  const existingHooks = next.hooks && typeof next.hooks === "object" ? next.hooks : {};
  next.hooks = mergeHooks(existingHooks, bobSettings.hooks);
  next.statusLine = bobSettings.statusLine;
  return next;
}

function mergeMcp(existing, serverPath) {
  const next = existing && typeof existing === "object" && !Array.isArray(existing)
    ? { ...existing }
    : {};
  next.mcpServers = next.mcpServers && typeof next.mcpServers === "object" && !Array.isArray(next.mcpServers)
    ? { ...next.mcpServers }
    : {};
  next.mcpServers.bountyagent = {
    command: "node",
    args: [serverPath],
  };
  return next;
}

function main() {
  const target = path.resolve(process.argv[2] || ".");
  const serverPath = path.join(target, "mcp", "server.js");
  const mcpPath = path.join(target, ".mcp.json");
  const settingsPath = path.join(target, ".claude", "settings.json");
  const bobSettings = defaultClaudeSettings();

  writeJson(mcpPath, mergeMcp(readJsonIfExists(mcpPath, {}), serverPath));
  writeJson(settingsPath, mergeSettings(readJsonIfExists(settingsPath, {}), bobSettings));

  console.log(`merged ${mcpPath}`);
  console.log(`merged ${settingsPath}`);
}

if (require.main === module) {
  main();
}

module.exports = {
  mergeMcp,
  mergeHookEntries,
  mergeHooks,
  mergePreToolUseHooks,
  mergeSettings,
};
