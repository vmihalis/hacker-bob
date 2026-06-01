"use strict";

const fs = require("fs");
const path = require("path");
const config = require("./config.js");
const {
  BRUTALIST_MCP_SERVER,
  mergeMcp,
  mergeSettings,
  STALE_GLOBAL_MCP_PERMISSIONS,
} = require("../../scripts/merge-claude-config.js");
const {
  updateClaudeRoleFiles,
} = require("../../scripts/lib/claude-role-renderer.js");
const { createSafeInstallFs } = require("../../scripts/lib/install-fs.js");

const id = "claude";
const DEFAULT_ROOT = path.join(__dirname, "..", "..");

const HOOK_FILES = Object.freeze([
  "session-read-guard.sh",
  "session-write-guard.sh",
  "bounty-statusline.js",
  "hunter-subagent-stop.js",
  "bob-egress.js",
  "bob-export.js",
  "bob-update.js",
  "bob-check-update.js",
  "bob-check-update-worker.js",
]);

const STALE_HOOK_FILES = Object.freeze([
  "bob-update-lib.js",
  "scope-guard.sh",
  "scope-guard-mcp.sh",
]);

const EXECUTABLE_HOOKS = Object.freeze([
  "session-read-guard.sh",
  "session-write-guard.sh",
  "hunter-subagent-stop.js",
  "bob-egress.js",
  "bob-export.js",
  "bob-update.js",
  "bob-check-update.js",
  "bob-check-update-worker.js",
]);

const BOB_COMMAND_FILES = Object.freeze([
  "bob-update.md",
  "bob-egress.md",
  "bob-export.md",
]);

const LEGACY_BOB_COMMAND_FILES = Object.freeze([
  "hunt.md",
  "status.md",
  "debug.md",
  "update.md",
]);

const COMMAND_SPECS = Object.freeze({
  update: Object.freeze({
    file: "bob-update.md",
    slash: "/bob-update",
  }),
  export: Object.freeze({
    file: "bob-export.md",
    slash: "/bob-export",
  }),
});

const BOB_SKILLS = Object.freeze([
  "bob-hunt",
  "bob-oss",
  "bob-status",
  "bob-debug",
]);

const LEGACY_BOB_SKILLS = Object.freeze([
  "bountyagent",
  "bountyagentdebug",
  "bountyagentstatus",
]);

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function sourceDirFiles(sourceRoot, relativeDir, predicate) {
  const dir = path.join(sourceRoot, relativeDir);
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) return [];
  return fs.readdirSync(dir)
    .sort()
    .filter((name) => fs.statSync(path.join(dir, name)).isFile())
    .filter((name) => !predicate || predicate(name))
    .map((name) => path.join(relativeDir, name));
}

function managedFiles(sourceRoot) {
  return [
    ...sourceDirFiles(sourceRoot, path.join(".claude", "agents"), (name) => name.endsWith(".md")),
    ...BOB_COMMAND_FILES.map((name) => path.join(".claude", "commands", name)),
    ...LEGACY_BOB_COMMAND_FILES.map((name) => path.join(".claude", "commands", "bob", name)),
    ...BOB_SKILLS.map((skill) => path.join(".claude", "skills", skill, "SKILL.md")),
    ...LEGACY_BOB_SKILLS.map((skill) => path.join(".claude", "skills", skill, "SKILL.md")),
    ...sourceDirFiles(sourceRoot, path.join(".claude", "rules"), (name) => name.endsWith(".md")),
    ...HOOK_FILES.map((name) => path.join(".claude", "hooks", name)),
    ...STALE_HOOK_FILES.map((name) => path.join(".claude", "hooks", name)),
    path.join(".claude", "bob", "VERSION"),
    path.join(".claude", "bob", "install.json"),
  ];
}

function managedDirs() {
  return [
    path.join(".claude", "commands", "bob"),
    path.join(".claude", "commands"),
    path.join(".claude", "skills", "bob-hunt"),
    path.join(".claude", "skills", "bob-oss"),
    path.join(".claude", "skills", "bob-status"),
    path.join(".claude", "skills", "bob-debug"),
    path.join(".claude", "skills", "bountyagent"),
    path.join(".claude", "skills", "bountyagentdebug"),
    path.join(".claude", "skills", "bountyagentstatus"),
    path.join(".claude", "skills"),
    path.join(".claude", "agents"),
    path.join(".claude", "rules"),
    path.join(".claude", "bypass-tables"),
    path.join(".claude", "knowledge"),
    path.join(".claude", "hooks"),
    path.join(".claude", "bob"),
  ];
}

function mergeConfig({ existingMcp, existingSettings, serverPath }) {
  return {
    mcp: mergeMcp(existingMcp || {}, serverPath),
    settings: mergeSettings(existingSettings || {}, config.defaultClaudeSettings()),
  };
}

function commandSpec(commandId) {
  const spec = COMMAND_SPECS[commandId];
  if (!spec) throw new Error(`Unknown Claude command: ${commandId}`);
  return spec;
}

function commandIds() {
  return Object.keys(COMMAND_SPECS);
}

function renderUpdateCommand() {
  return [
    "---",
    "allowed-tools:",
    "  - Bash",
    "  - AskUserQuestion",
    "---",
    "Run the installed Hacker Bob update workflow for this project.",
    "",
    "1. Run:",
    '   `node "${CLAUDE_PROJECT_DIR:-$PWD}/.claude/hooks/bob-update.js" plan "${CLAUDE_PROJECT_DIR:-$PWD}"`',
    "2. If the helper says Hacker Bob is already up to date or cannot reach npm, report that result and stop.",
    "3. If an update is available or the install is legacy, ask the operator exactly: `Update now?`",
    "4. Only when the operator confirms, run:",
    '   `npx -y hacker-bob@latest install "${CLAUDE_PROJECT_DIR:-$PWD}"`',
    "5. Then run:",
    '   `node "${CLAUDE_PROJECT_DIR:-$PWD}/.claude/hooks/bob-update.js" clear-cache "${CLAUDE_PROJECT_DIR:-$PWD}"`',
    "6. Tell the operator to fully restart Claude Code in this project before continuing.",
    "",
  ].join("\n");
}

function renderExportCommand() {
  return [
    "---",
    "allowed-tools:",
    "  - Bash",
    "---",
    "Create a Hacker Bob post-release improvement bundle for the currently installed Bob version.",
    "",
    "Run:",
    '   `node "${CLAUDE_PROJECT_DIR:-$PWD}/.claude/hooks/bob-export.js" "${CLAUDE_PROJECT_DIR:-$PWD}"`',
    "",
    "Report the helper output exactly. Do not add flags or run a hunt.",
    "",
  ].join("\n");
}

function renderCommand(commandId) {
  if (commandId === "update") return renderUpdateCommand();
  if (commandId === "export") return renderExportCommand();
  throw new Error(`Unknown Claude command: ${commandId}`);
}

function commandOutputPath(commandId, { root = DEFAULT_ROOT } = {}) {
  return path.join(root, ".claude", "commands", commandSpec(commandId).file);
}

function writeTextFile(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content, "utf8");
}

function updateCommandFiles({ check = false, root = DEFAULT_ROOT } = {}) {
  let changed = false;
  for (const commandId of commandIds()) {
    const filePath = commandOutputPath(commandId, { root });
    const current = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : null;
    const next = renderCommand(commandId);
    if (current === next) continue;
    if (check) {
      throw new Error(`${path.relative(root, filePath)} is stale; run node scripts/generate-claude-roles.js`);
    }
    fs.writeFileSync(filePath, next, "utf8");
    changed = true;
  }
  return changed;
}

function expectedMcpServer(targetAbs) {
  return {
    command: "node",
    args: [path.join(targetAbs, "mcp", "server.js")],
  };
}

function mcpServerMatches(server, targetAbs) {
  return JSON.stringify(server) === JSON.stringify(expectedMcpServer(targetAbs));
}

function hookKey(hook) {
  return JSON.stringify({
    type: hook && hook.type,
    command: hook && hook.command,
    timeout: hook && hook.timeout,
  });
}

function hooksContain(hooks, expectedHook) {
  if (!Array.isArray(hooks)) return false;
  const expected = hookKey(expectedHook);
  return hooks.some((hook) => hookKey(hook) === expected);
}

function hookEntryHasHooks(entries, expectedEntry) {
  if (!Array.isArray(entries)) return false;
  return entries.some((entry) => {
    if (!entry || entry.matcher !== expectedEntry.matcher) return false;
    return (expectedEntry.hooks || []).every((hook) => hooksContain(entry.hooks, hook));
  });
}

function settingsHasHookEntries(settings, bobSettings) {
  const missing = [];
  const hooks = isPlainObject(settings && settings.hooks) ? settings.hooks : {};
  for (const [eventName, expectedEntries] of Object.entries(bobSettings.hooks || {})) {
    for (const expectedEntry of expectedEntries || []) {
      if (!hookEntryHasHooks(hooks[eventName], expectedEntry)) {
        missing.push(`${eventName}:${expectedEntry.matcher}`);
      }
    }
  }
  return missing;
}

function statusLineMatches(settings, bobSettings) {
  return JSON.stringify(settings && settings.statusLine) === JSON.stringify(bobSettings.statusLine);
}

function requiredBobMcpPermissions(bobSettings) {
  return (bobSettings.permissions && Array.isArray(bobSettings.permissions.allow)
    ? bobSettings.permissions.allow
    : []
  ).filter((permission) => permission.startsWith("mcp__bountyagent__"));
}

function settingsMissingPermissions(settings, bobSettings) {
  const allow = settings && settings.permissions && Array.isArray(settings.permissions.allow)
    ? settings.permissions.allow
    : [];
  const present = new Set(allow);
  return requiredBobMcpPermissions(bobSettings).filter((permission) => !present.has(permission));
}

function removeMatchingHooks(existingEntries, expectedEntries) {
  if (!Array.isArray(existingEntries)) return existingEntries;
  const expectedByMatcher = new Map();
  for (const entry of expectedEntries || []) {
    expectedByMatcher.set(entry.matcher, new Set((entry.hooks || []).map(hookKey)));
  }

  const nextEntries = [];
  let removed = 0;
  for (const entry of existingEntries) {
    if (!entry || typeof entry.matcher !== "string" || !Array.isArray(entry.hooks)) {
      nextEntries.push(entry);
      continue;
    }
    const expectedKeys = expectedByMatcher.get(entry.matcher);
    if (!expectedKeys) {
      nextEntries.push(entry);
      continue;
    }
    const hooks = entry.hooks.filter((hook) => {
      if (expectedKeys.has(hookKey(hook))) {
        removed += 1;
        return false;
      }
      return true;
    });
    if (hooks.length > 0) {
      nextEntries.push({ ...entry, hooks });
    }
  }
  return { entries: nextEntries, removed };
}

function objectWithoutEmptyKnownContainers(settings) {
  const next = { ...settings };
  if (isPlainObject(next.permissions)) {
    const permissions = { ...next.permissions };
    if (Array.isArray(permissions.allow) && permissions.allow.length === 0) delete permissions.allow;
    if (Object.keys(permissions).length === 0) {
      delete next.permissions;
    } else {
      next.permissions = permissions;
    }
  }
  if (isPlainObject(next.hooks) && Object.keys(next.hooks).length === 0) delete next.hooks;
  return next;
}

function render(options = {}) {
  const rolesChanged = updateClaudeRoleFiles(options);
  const commandsChanged = updateCommandFiles(options);
  return rolesChanged || commandsChanged;
}

function install({
  sourceRoot,
  targetAbs,
  copyDirFiles,
  copyFile,
  commitSha,
  installedAt,
  installerSource,
  manifest,
  packageName,
  readJsonIfExists,
  removeIfExists,
  serverPath,
  writeJson,
  installFs,
}) {
  const safeFs = installFs || createSafeInstallFs(targetAbs, { label: "install target" });
  const safeReadJsonIfExists = readJsonIfExists || ((filePath, fallback) => safeFs.readJsonIfExists(filePath, fallback, {
    kind: "config file",
    symlink: "reject",
  }));
  const safeWriteJson = writeJson || ((filePath, value, optionsForFile = {}) => safeFs.writeJson(filePath, value, optionsForFile));
  const safeRemoveIfExists = removeIfExists || ((filePath) => safeFs.removePath(filePath));
  const safeCopyDirFiles = copyDirFiles || ((sourceDir, destinationDir, predicate) => safeFs.copyDirFiles(sourceDir, destinationDir, predicate));
  const safeCopyFile = copyFile || ((source, destination, mode) => safeFs.copyFile(source, destination, mode));
  const claudeDir = path.join(targetAbs, ".claude");
  safeFs.mkdirp(claudeDir);
  for (const dirname of ["agents", "commands", "rules", "hooks", "skills", "bob"]) {
    safeFs.mkdirp(path.join(claudeDir, dirname));
  }
  for (const hook of STALE_HOOK_FILES) {
    safeRemoveIfExists(path.join(claudeDir, "hooks", hook));
  }

  const agents = safeCopyDirFiles(
    path.join(sourceRoot, ".claude", "agents"),
    path.join(claudeDir, "agents"),
    (name) => name.endsWith(".md"),
  );

  safeRemoveIfExists(path.join(claudeDir, "commands", "bountyagent.md"));
  safeRemoveIfExists(path.join(claudeDir, "commands", "bountyagentdebug.md"));
  for (const legacyCommand of LEGACY_BOB_COMMAND_FILES) {
    safeRemoveIfExists(path.join(claudeDir, "commands", "bob", legacyCommand));
  }
  safeFs.removeEmptyDirIfExists(path.join(claudeDir, "commands", "bob"));
  for (const legacySkill of LEGACY_BOB_SKILLS) {
    safeFs.removePath(path.join(claudeDir, "skills", legacySkill), { recursive: true });
  }
  for (const commandId of commandIds()) {
    safeFs.writeTextFile(
      path.join(claudeDir, "commands", commandSpec(commandId).file),
      renderCommand(commandId),
      { kind: "generated file" },
    );
  }

  // Copy static command files (not renderer-driven). bob-egress.md is hand-
  // authored and shipped verbatim; the renderer pattern is only used for
  // commands that have dynamic per-host content like bob-update.md.
  safeCopyFile(
    path.join(sourceRoot, ".claude", "commands", "bob-egress.md"),
    path.join(claudeDir, "commands", "bob-egress.md"),
  );

  for (const skill of BOB_SKILLS) {
    safeCopyFile(
      path.join(sourceRoot, ".claude", "skills", skill, "SKILL.md"),
      path.join(claudeDir, "skills", skill, "SKILL.md"),
    );
  }

  const rules = safeCopyDirFiles(
    path.join(sourceRoot, ".claude", "rules"),
    path.join(claudeDir, "rules"),
    (name) => name.endsWith(".md"),
  );

  for (const hook of HOOK_FILES) {
    const mode = EXECUTABLE_HOOKS.includes(hook) ? 0o755 : undefined;
    safeCopyFile(
      path.join(sourceRoot, ".claude", "hooks", hook),
      path.join(claudeDir, "hooks", hook),
      mode,
    );
  }

  // Egress profiles example + operator config.
  // ensureEgressProfilesExample writes a versioned example operators can copy;
  // ensureEgressProfilesConfig writes a default profile only when no operator
  // file exists yet, preserving operator edits across reinstalls.
  const {
    ensureEgressProfilesConfig,
    ensureEgressProfilesExample,
  } = require("../../mcp/lib/egress-profiles.js");
  ensureEgressProfilesExample(targetAbs, { installFs: safeFs });
  ensureEgressProfilesConfig(targetAbs, { installFs: safeFs });

  const mcpPath = path.join(targetAbs, ".mcp.json");
  const settingsPath = path.join(claudeDir, "settings.json");
  const mergedConfig = mergeConfig({
    existingMcp: safeReadJsonIfExists(mcpPath, {}),
    existingSettings: safeReadJsonIfExists(settingsPath, {}),
    serverPath,
  });
  safeWriteJson(mcpPath, mergedConfig.mcp, {
    kind: ".mcp.json",
    rejectExistingSymlink: true,
  });
  safeWriteJson(settingsPath, mergedConfig.settings, {
    kind: ".claude/settings.json",
    rejectExistingSymlink: true,
  });

  const installManifest = manifest || {};
  safeFs.writeTextFile(path.join(claudeDir, "bob", "VERSION"), `${installManifest.version || "0.0.0"}\n`, {
    kind: ".claude/bob/VERSION",
  });
  safeWriteJson(path.join(claudeDir, "bob", "install.json"), {
    schema_version: 1,
    bob_version: installManifest.version || "0.0.0",
    installed_at: installedAt || new Date().toISOString(),
    package_name: packageName || installManifest.name || "hacker-bob",
    install_target: targetAbs,
    installer_source: installerSource || "cli",
    commit_sha: commitSha || null,
  });

  return {
    agents: agents.length,
    claudeDir,
    rules: rules.length,
  };
}

function doctor({
  targetAbs,
  checks,
  addCheck,
  fileExists,
  idPrefix = "",
  jsonReadCheck,
  relativeDisplay,
}) {
  const checkId = (id) => `${idPrefix}${id}`;
  const claudeDir = path.join(targetAbs, ".claude");
  const versionPath = path.join(claudeDir, "bob", "VERSION");
  let installedVersion = null;
  if (fileExists(versionPath)) {
    installedVersion = fs.readFileSync(versionPath, "utf8").trim();
    if (installedVersion) {
      addCheck(checks, "ok", checkId("installed_version"), `Installed Bob version is ${installedVersion}`, {
        installed_version: installedVersion,
      });
    } else {
      addCheck(checks, "error", checkId("installed_version"), ".claude/bob/VERSION is empty");
    }
  } else {
    addCheck(checks, "error", checkId("installed_version"), ".claude/bob/VERSION is missing");
  }

  const installMetaPath = path.join(claudeDir, "bob", "install.json");
  const installMeta = jsonReadCheck(checks, installMetaPath, checkId("install_metadata_json"), targetAbs);
  if (installMeta) {
    const metadataErrors = [];
    if (installMeta.schema_version !== 1) metadataErrors.push("schema_version must be 1");
    if (!installMeta.bob_version) metadataErrors.push("bob_version is missing");
    if (installedVersion && installMeta.bob_version !== installedVersion) {
      metadataErrors.push("bob_version does not match VERSION");
    }
    if (installMeta.install_target !== targetAbs) metadataErrors.push("install_target does not match this project");
    if (!installMeta.package_name) metadataErrors.push("package_name is missing");
    if (metadataErrors.length === 0) {
      addCheck(checks, "ok", checkId("install_metadata"), "Install metadata matches this project");
    } else {
      addCheck(checks, "error", checkId("install_metadata"), "Install metadata is incomplete or mismatched", {
        errors: metadataErrors,
      });
    }
  }

  const missingCommands = BOB_COMMAND_FILES
    .map((name) => path.join(".claude", "commands", name))
    .filter((relative) => !fileExists(path.join(targetAbs, relative)));
  if (missingCommands.length === 0) {
    addCheck(checks, "ok", checkId("commands"), "Bob slash commands are installed");
  } else {
    addCheck(checks, "error", checkId("commands"), "Bob slash commands are missing", {
      missing: missingCommands,
    });
  }

  const missingHooks = HOOK_FILES
    .map((name) => path.join(".claude", "hooks", name))
    .filter((relative) => !fileExists(path.join(targetAbs, relative)));
  if (missingHooks.length === 0) {
    addCheck(checks, "ok", checkId("hook_files"), "Bob hook files are installed");
  } else {
    addCheck(checks, "error", checkId("hook_files"), "Bob hook files are missing", {
      missing: missingHooks,
    });
  }

  const nonExecutableHooks = EXECUTABLE_HOOKS
    .map((name) => path.join(claudeDir, "hooks", name))
    .filter((hookPath) => fileExists(hookPath) && (fs.statSync(hookPath).mode & 0o111) === 0)
    .map((hookPath) => relativeDisplay(targetAbs, hookPath));
  if (nonExecutableHooks.length === 0) {
    addCheck(checks, "ok", checkId("hook_modes"), "Executable Bob hooks have executable mode");
  } else {
    addCheck(checks, "error", checkId("hook_modes"), "Some executable Bob hooks are not executable", {
      files: nonExecutableHooks,
    });
  }

  const mcpPath = path.join(targetAbs, ".mcp.json");
  const mcp = jsonReadCheck(checks, mcpPath, checkId("mcp_json"), targetAbs);
  if (mcp && mcpServerMatches(mcp.mcpServers && mcp.mcpServers.bountyagent, targetAbs)) {
    addCheck(checks, "ok", checkId("mcp_server_config"), ".mcp.json points bountyagent at this project's mcp/server.js");
  } else if (mcp) {
    addCheck(checks, "error", checkId("mcp_server_config"), ".mcp.json is missing the Bob-managed bountyagent server entry");
  }

  // brutalist MCP is optional — check is informational only, never errors.
  // brutalist-verifier falls back gracefully when this server is missing.
  const brutalistEntry = mcp && mcp.mcpServers && mcp.mcpServers.brutalist;
  if (brutalistEntry && brutalistEntry.command === BRUTALIST_MCP_SERVER.command) {
    addCheck(checks, "ok", checkId("mcp_brutalist_optional"), ".mcp.json registers the optional @brutalist/mcp server for the brutalist verifier");
  } else if (mcp) {
    addCheck(checks, "info", checkId("mcp_brutalist_optional"), ".mcp.json does not register @brutalist/mcp — brutalist verifier will fall back gracefully");
  }

  const bobSettings = config.defaultClaudeSettings();
  const settingsPath = path.join(claudeDir, "settings.json");
  const settings = jsonReadCheck(checks, settingsPath, checkId("settings_json"), targetAbs);
  if (settings) {
    const missingHookEntries = settingsHasHookEntries(settings, bobSettings);
    if (missingHookEntries.length === 0) {
      addCheck(checks, "ok", checkId("settings_hooks"), ".claude/settings.json contains Bob hooks");
    } else {
      addCheck(checks, "error", checkId("settings_hooks"), ".claude/settings.json is missing Bob hooks", {
        missing: missingHookEntries,
      });
    }

    const missingPermissions = settingsMissingPermissions(settings, bobSettings);
    if (missingPermissions.length === 0) {
      addCheck(checks, "ok", checkId("settings_permissions"), ".claude/settings.json contains Bob MCP permissions");
    } else {
      addCheck(checks, "error", checkId("settings_permissions"), ".claude/settings.json is missing Bob MCP permissions", {
        missing: missingPermissions,
      });
    }

    if (statusLineMatches(settings, bobSettings)) {
      addCheck(checks, "ok", checkId("settings_statusline"), ".claude/settings.json contains Bob statusline");
    } else {
      addCheck(checks, "error", checkId("settings_statusline"), ".claude/settings.json is missing the Bob statusline");
    }
  }

  // Egress profile config: example + operator file + dependency check.
  const {
    egressProfilesPath,
    egressProfilesExamplePath,
    normalizeEgressProfilesDocument,
  } = require("../../mcp/lib/egress-profiles.js");
  const egressExample = egressProfilesExamplePath(targetAbs);
  if (fileExists(egressExample)) {
    addCheck(checks, "ok", checkId("egress_profiles_example"), ".claude/bob/egress-profiles.example.json is installed");
  } else {
    addCheck(checks, "warn", checkId("egress_profiles_example"), ".claude/bob/egress-profiles.example.json is missing; reinstall to restore the operator template");
  }
  const egressConfigPath = egressProfilesPath(targetAbs);
  if (!fileExists(egressConfigPath)) {
    addCheck(checks, "warn", checkId("egress_profiles_config"), ".claude/bob/egress-profiles.json is missing; egress defaults to direct local connections");
  } else {
    try {
      const egressConfig = normalizeEgressProfilesDocument(JSON.parse(fs.readFileSync(egressConfigPath, "utf8")));
      addCheck(checks, "ok", checkId("egress_profiles_config"), ".claude/bob/egress-profiles.json is valid");
      const nonDefaultEnabled = egressConfig.profiles.some((profile) => profile.name !== "default" && profile.enabled);
      if (nonDefaultEnabled) {
        addCheck(checks, "ok", checkId("egress_profiles_non_default"), "At least one non-default egress profile is enabled");
      } else {
        addCheck(checks, "warn", checkId("egress_profiles_non_default"), "No enabled non-default egress profiles are configured; this is optional");
      }
    } catch (error) {
      addCheck(checks, "error", checkId("egress_profiles_config"), ".claude/bob/egress-profiles.json is invalid", {
        error: error && error.message ? error.message : String(error),
      });
    }
  }

  // proxy-agent dependency for non-default egress profiles.
  let proxyAgentInstalled = false;
  try {
    require.resolve("proxy-agent", { paths: [path.join(targetAbs, "mcp"), targetAbs] });
    proxyAgentInstalled = true;
  } catch {}
  if (proxyAgentInstalled) {
    addCheck(checks, "ok", checkId("mcp_dependency_proxy_agent"), "proxy-agent is available for egress profiles");
  } else {
    addCheck(checks, "warn", checkId("mcp_dependency_proxy_agent"), "proxy-agent is missing; non-default egress profiles will not work until dependencies are installed");
  }

  // Policy replay harness: installed diagnostic files under testing/policy-replay/.
  const POLICY_REPLAY_FILES = [
    "replay.mjs",
    "tune.mjs",
    "synth-session.mjs",
    "case-schema.mjs",
    "bench.mjs",
    "README.md",
    path.join("cases", "sample-hunter-refusal.json"),
  ];
  const missingPolicyReplay = POLICY_REPLAY_FILES
    .map((name) => path.join("testing", "policy-replay", name))
    .filter((relative) => !fileExists(path.join(targetAbs, relative)));
  if (missingPolicyReplay.length === 0) {
    addCheck(checks, "ok", checkId("policy_replay_harness"), "Policy replay harness is installed");
  } else {
    addCheck(checks, "warn", checkId("policy_replay_harness"), "Policy replay harness files are missing; developer replay diagnostics are unavailable", {
      missing: missingPolicyReplay,
    });
  }
}

function removeMcpConfig(targetAbs, result, helpers) {
  const { fileExists, readJson, writeJson } = helpers;
  const mcpPath = path.join(targetAbs, ".mcp.json");
  if (!fileExists(mcpPath)) return;
  let mcp;
  try {
    mcp = readJson(mcpPath);
  } catch (error) {
    result.skipped.push({ type: "config", path: ".mcp.json", reason: `invalid JSON: ${error.message || String(error)}` });
    return;
  }
  if (!isPlainObject(mcp) || !isPlainObject(mcp.mcpServers) || !("bountyagent" in mcp.mcpServers)) return;
  if (!mcpServerMatches(mcp.mcpServers.bountyagent, targetAbs)) {
    result.skipped.push({ type: "config", path: ".mcp.json", reason: "bountyagent server entry is not Bob-managed" });
    return;
  }
  const next = { ...mcp, mcpServers: { ...mcp.mcpServers } };
  delete next.mcpServers.bountyagent;
  // Also remove the Bob-managed brutalist entry if present and unmodified.
  // Operator overrides (different command/args) are preserved.
  if (
    next.mcpServers.brutalist
    && next.mcpServers.brutalist.command === BRUTALIST_MCP_SERVER.command
  ) {
    delete next.mcpServers.brutalist;
  }
  if (Object.keys(next.mcpServers).length === 0) delete next.mcpServers;
  result.actions.push({ type: Object.keys(next).length === 0 ? "remove_config_file" : "update_config", path: ".mcp.json" });
  if (result.dry_run) return;
  if (Object.keys(next).length === 0) {
    fs.rmSync(mcpPath, { force: true });
  } else {
    writeJson(mcpPath, next);
  }
}

function removeSettingsConfig(targetAbs, result, helpers) {
  const { fileExists, readJson, writeJson } = helpers;
  const settingsPath = path.join(targetAbs, ".claude", "settings.json");
  if (!fileExists(settingsPath)) return;
  let settings;
  try {
    settings = readJson(settingsPath);
  } catch (error) {
    result.skipped.push({
      type: "config",
      path: path.join(".claude", "settings.json"),
      reason: `invalid JSON: ${error.message || String(error)}`,
    });
    return;
  }
  if (!isPlainObject(settings)) return;

  const bobSettings = config.defaultClaudeSettings();
  let changed = false;
  let next = { ...settings };

  if (isPlainObject(next.permissions) && Array.isArray(next.permissions.allow)) {
    const bobPermissions = new Set([
      ...requiredBobMcpPermissions(bobSettings),
      ...STALE_GLOBAL_MCP_PERMISSIONS,
    ]);
    const allow = next.permissions.allow.filter((permission) => !bobPermissions.has(permission));
    if (allow.length !== next.permissions.allow.length) {
      next.permissions = { ...next.permissions, allow };
      changed = true;
    }
  }

  if (isPlainObject(next.hooks)) {
    const hooks = { ...next.hooks };
    for (const [eventName, expectedEntries] of Object.entries(bobSettings.hooks || {})) {
      const removal = removeMatchingHooks(hooks[eventName], expectedEntries);
      if (removal && removal.removed > 0) {
        changed = true;
        if (removal.entries.length === 0) {
          delete hooks[eventName];
        } else {
          hooks[eventName] = removal.entries;
        }
      }
    }
    next.hooks = hooks;
  }

  if (statusLineMatches(next, bobSettings)) {
    delete next.statusLine;
    changed = true;
  }

  next = objectWithoutEmptyKnownContainers(next);
  if (!changed) return;

  result.actions.push({
    type: Object.keys(next).length === 0 ? "remove_config_file" : "update_config",
    path: path.join(".claude", "settings.json"),
  });
  if (result.dry_run) return;
  if (Object.keys(next).length === 0) {
    fs.rmSync(settingsPath, { force: true });
  } else {
    writeJson(settingsPath, next);
  }
}

function removeGeneratedEgressConfig(targetAbs, result) {
  // Egress profile config under .claude/bob/egress-profiles.json is operator-
  // owned at runtime — they may add proxies, env-var refs, regions. Preserve
  // it on uninstall unless it's still the untouched default. Detection lives
  // in egress-profiles.js so adapters and tests share one rule.
  const {
    egressProfilesPath,
    isUntouchedGeneratedEgressConfig,
  } = require("../../mcp/lib/egress-profiles.js");
  const configPath = egressProfilesPath(targetAbs);
  const relativePath = path.join(".claude", "bob", "egress-profiles.json");
  if (!fs.existsSync(configPath)) return;
  if (!isUntouchedGeneratedEgressConfig(targetAbs)) {
    result.skipped.push({
      type: "config",
      path: relativePath,
      reason: "operator-owned egress profile config is preserved",
    });
    return;
  }
  result.actions.push({ type: "remove_file", path: relativePath });
  if (!result.dry_run) fs.rmSync(configPath, { force: true });
}

function uninstall({
  sourceRoot,
  targetAbs,
  result,
  helpers,
  preserveMcpConfig = false,
}) {
  if (!preserveMcpConfig) removeMcpConfig(targetAbs, result, helpers);
  removeSettingsConfig(targetAbs, result, helpers);
  removeGeneratedEgressConfig(targetAbs, result);

  for (const relativePath of managedFiles(sourceRoot)) {
    helpers.maybeRemoveFile(targetAbs, relativePath, result);
  }

  return result;
}

module.exports = {
  BOB_COMMAND_FILES,
  BOB_SKILLS,
  COMMAND_SPECS,
  EXECUTABLE_HOOKS,
  HOOK_FILES,
  LEGACY_BOB_COMMAND_FILES,
  LEGACY_BOB_SKILLS,
  config,
  commandIds,
  commandOutputPath,
  doctor,
  id,
  install,
  managedDirs,
  managedFiles,
  mergeConfig,
  render,
  renderCommand,
  uninstall,
  updateCommandFiles,
};
