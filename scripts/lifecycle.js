"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const {
  EXECUTABLE_HOOKS,
  HOOK_FILES,
  commandExists,
  patchrightAvailable,
} = require("./install.js");
const {
  STALE_GLOBAL_MCP_PERMISSIONS,
} = require("./merge-claude-config.js");
const {
  defaultClaudeSettings,
} = require("../mcp/lib/claude-config.js");

const BOB_COMMAND_FILES = Object.freeze([
  "bob-update.md",
]);

const LEGACY_BOB_COMMAND_FILES = Object.freeze([
  "hunt.md",
  "status.md",
  "debug.md",
  "update.md",
]);

const BOB_SKILLS = Object.freeze([
  "bob-debug",
  "bob-hunt",
  "bob-status",
]);

const LEGACY_BOB_SKILLS = Object.freeze([
  "bountyagent",
  "bountyagentdebug",
  "bountyagentstatus",
]);

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function relativeDisplay(targetAbs, filePath) {
  const relative = path.relative(targetAbs, filePath);
  return relative && !relative.startsWith("..") ? relative : filePath;
}

function addCheck(checks, status, id, message, detail) {
  const check = { id, status, message };
  if (detail !== undefined) check.detail = detail;
  checks.push(check);
  return check;
}

function nodeMajor(version) {
  const major = String(version || "").split(".")[0];
  const parsed = Number.parseInt(major, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

function fileExists(filePath) {
  try {
    return fs.statSync(filePath).isFile();
  } catch {
    return false;
  }
}

function dirExists(dirPath) {
  try {
    return fs.statSync(dirPath).isDirectory();
  } catch {
    return false;
  }
}

function jsonReadCheck(checks, filePath, id, targetAbs) {
  if (!fileExists(filePath)) {
    addCheck(checks, "error", id, `${relativeDisplay(targetAbs, filePath)} is missing`);
    return null;
  }
  try {
    const value = readJson(filePath);
    addCheck(checks, "ok", id, `${relativeDisplay(targetAbs, filePath)} is valid JSON`);
    return value;
  } catch (error) {
    addCheck(
      checks,
      "error",
      id,
      `${relativeDisplay(targetAbs, filePath)} is not valid JSON`,
      { error: error.message || String(error) },
    );
    return null;
  }
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

function expectedMcpServer(targetAbs) {
  return {
    command: "node",
    args: [path.join(targetAbs, "mcp", "server.js")],
  };
}

function mcpServerMatches(server, targetAbs) {
  return JSON.stringify(server) === JSON.stringify(expectedMcpServer(targetAbs));
}

function loadServerCheck(serverPath) {
  const script = [
    "const server = require(process.argv[1]);",
    "if (!Array.isArray(server.TOOLS) || server.TOOLS.length === 0) process.exit(2);",
  ].join(" ");
  return spawnSync(process.execPath, ["-e", script, serverPath], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function httpxAvailable() {
  return commandExists("httpx") || fileExists(path.join(os.homedir(), "go", "bin", "httpx"));
}

function doctorProject(projectDir, options = {}) {
  const sourceRoot = path.resolve(options.sourceRoot || path.join(__dirname, ".."));
  const targetAbs = path.resolve(projectDir || ".");
  const checks = [];

  if (nodeMajor(process.versions.node) >= 20) {
    addCheck(checks, "ok", "node_version", `Node.js ${process.versions.node} satisfies >=20`);
  } else {
    addCheck(checks, "error", "node_version", `Node.js ${process.versions.node} is below required >=20`);
  }

  if (!dirExists(targetAbs)) {
    addCheck(checks, "error", "target_directory", `${targetAbs} is not a directory`);
    return {
      ok: false,
      target: targetAbs,
      checks,
    };
  }
  addCheck(checks, "ok", "target_directory", `${targetAbs} is a directory`);

  for (const tool of ["curl", "python3"]) {
    if (commandExists(tool)) {
      addCheck(checks, "ok", `required_tool_${tool}`, `${tool} is available`);
    } else {
      addCheck(checks, "error", `required_tool_${tool}`, `${tool} is missing`);
    }
  }

  const claudeDir = path.join(targetAbs, ".claude");
  const versionPath = path.join(claudeDir, "bob", "VERSION");
  let installedVersion = null;
  if (fileExists(versionPath)) {
    installedVersion = fs.readFileSync(versionPath, "utf8").trim();
    if (installedVersion) {
      addCheck(checks, "ok", "installed_version", `Installed Bob version is ${installedVersion}`, {
        installed_version: installedVersion,
      });
    } else {
      addCheck(checks, "error", "installed_version", ".claude/bob/VERSION is empty");
    }
  } else {
    addCheck(checks, "error", "installed_version", ".claude/bob/VERSION is missing");
  }

  const installMetaPath = path.join(claudeDir, "bob", "install.json");
  const installMeta = jsonReadCheck(checks, installMetaPath, "install_metadata_json", targetAbs);
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
      addCheck(checks, "ok", "install_metadata", "Install metadata matches this project");
    } else {
      addCheck(checks, "error", "install_metadata", "Install metadata is incomplete or mismatched", {
        errors: metadataErrors,
      });
    }
  }

  const missingCommands = BOB_COMMAND_FILES
    .map((name) => path.join(".claude", "commands", name))
    .filter((relative) => !fileExists(path.join(targetAbs, relative)));
  if (missingCommands.length === 0) {
    addCheck(checks, "ok", "commands", "Bob slash commands are installed");
  } else {
    addCheck(checks, "error", "commands", "Bob slash commands are missing", {
      missing: missingCommands,
    });
  }

  const missingHooks = HOOK_FILES
    .map((name) => path.join(".claude", "hooks", name))
    .filter((relative) => !fileExists(path.join(targetAbs, relative)));
  if (missingHooks.length === 0) {
    addCheck(checks, "ok", "hook_files", "Bob hook files are installed");
  } else {
    addCheck(checks, "error", "hook_files", "Bob hook files are missing", {
      missing: missingHooks,
    });
  }

  const nonExecutableHooks = EXECUTABLE_HOOKS
    .map((name) => path.join(claudeDir, "hooks", name))
    .filter((hookPath) => fileExists(hookPath) && (fs.statSync(hookPath).mode & 0o111) === 0)
    .map((hookPath) => relativeDisplay(targetAbs, hookPath));
  if (nonExecutableHooks.length === 0) {
    addCheck(checks, "ok", "hook_modes", "Executable Bob hooks have executable mode");
  } else {
    addCheck(checks, "error", "hook_modes", "Some executable Bob hooks are not executable", {
      files: nonExecutableHooks,
    });
  }

  const mcpPath = path.join(targetAbs, ".mcp.json");
  const mcp = jsonReadCheck(checks, mcpPath, "mcp_json", targetAbs);
  if (mcp && mcpServerMatches(mcp.mcpServers && mcp.mcpServers.bountyagent, targetAbs)) {
    addCheck(checks, "ok", "mcp_server_config", ".mcp.json points bountyagent at this project's mcp/server.js");
  } else if (mcp) {
    addCheck(checks, "error", "mcp_server_config", ".mcp.json is missing the Bob-managed bountyagent server entry");
  }

  const bobSettings = defaultClaudeSettings();
  const settingsPath = path.join(claudeDir, "settings.json");
  const settings = jsonReadCheck(checks, settingsPath, "settings_json", targetAbs);
  if (settings) {
    const missingHookEntries = settingsHasHookEntries(settings, bobSettings);
    if (missingHookEntries.length === 0) {
      addCheck(checks, "ok", "settings_hooks", ".claude/settings.json contains Bob hooks");
    } else {
      addCheck(checks, "error", "settings_hooks", ".claude/settings.json is missing Bob hooks", {
        missing: missingHookEntries,
      });
    }

    const missingPermissions = settingsMissingPermissions(settings, bobSettings);
    if (missingPermissions.length === 0) {
      addCheck(checks, "ok", "settings_permissions", ".claude/settings.json contains Bob MCP permissions");
    } else {
      addCheck(checks, "error", "settings_permissions", ".claude/settings.json is missing Bob MCP permissions", {
        missing: missingPermissions,
      });
    }

    if (statusLineMatches(settings, bobSettings)) {
      addCheck(checks, "ok", "settings_statusline", ".claude/settings.json contains Bob statusline");
    } else {
      addCheck(checks, "error", "settings_statusline", ".claude/settings.json is missing the Bob statusline");
    }
  }

  const serverPath = path.join(targetAbs, "mcp", "server.js");
  if (!fileExists(serverPath)) {
    addCheck(checks, "error", "mcp_server_file", "mcp/server.js is missing");
  } else {
    addCheck(checks, "ok", "mcp_server_file", "mcp/server.js is installed");
    const loadResult = loadServerCheck(serverPath);
    if (loadResult.status === 0) {
      addCheck(checks, "ok", "mcp_server_loadable", "mcp/server.js loads successfully");
    } else {
      addCheck(checks, "error", "mcp_server_loadable", "mcp/server.js failed to load", {
        exit_status: loadResult.status,
        stderr: (loadResult.stderr || "").trim(),
      });
    }
  }

  for (const tool of ["subfinder", "nuclei"]) {
    if (commandExists(tool)) {
      addCheck(checks, "ok", `optional_tool_${tool}`, `${tool} is available`);
    } else {
      addCheck(checks, "warn", `optional_tool_${tool}`, `${tool} is missing; related recon steps will be skipped`);
    }
  }

  if (httpxAvailable()) {
    addCheck(checks, "ok", "optional_tool_httpx", "httpx is available");
  } else {
    addCheck(checks, "warn", "optional_tool_httpx", "httpx is missing; related recon steps will be skipped");
  }

  if (patchrightAvailable(targetAbs, sourceRoot)) {
    addCheck(checks, "ok", "optional_patchright", "patchright is available");
  } else {
    addCheck(checks, "warn", "optional_patchright", "patchright is missing; Tier 2 auto-signup is disabled");
  }

  if (process.env.CAPSOLVER_API_KEY) {
    addCheck(checks, "ok", "optional_capsolver", "CAPSOLVER_API_KEY is set");
  } else {
    addCheck(checks, "warn", "optional_capsolver", "CAPSOLVER_API_KEY is not set; CAPTCHA solving is disabled");
  }

  return {
    ok: checks.every((check) => check.status !== "error"),
    target: targetAbs,
    checks,
  };
}

function printDoctorReport(result, stream = process.stdout) {
  stream.write(`Hacker Bob doctor: ${result.target}\n\n`);
  for (const check of result.checks) {
    stream.write(`${check.status.toUpperCase()}: ${check.id} - ${check.message}\n`);
    if (check.detail && check.detail.missing && check.detail.missing.length) {
      for (const missing of check.detail.missing) {
        stream.write(`  missing: ${missing}\n`);
      }
    }
    if (check.detail && check.detail.errors && check.detail.errors.length) {
      for (const error of check.detail.errors) {
        stream.write(`  error: ${error}\n`);
      }
    }
  }
  stream.write(`\n${result.ok ? "No required problems found." : "Required problems found."}\n`);
}

function sourceDirFiles(sourceRoot, relativeDir, predicate) {
  const dir = path.join(sourceRoot, relativeDir);
  if (!dirExists(dir)) return [];
  return fs.readdirSync(dir)
    .sort()
    .filter((name) => fileExists(path.join(dir, name)))
    .filter((name) => !predicate || predicate(name))
    .map((name) => path.join(relativeDir, name));
}

function sourceTreeFiles(sourceRoot, relativeDir) {
  const root = path.join(sourceRoot, relativeDir);
  if (!dirExists(root)) return [];
  const files = [];
  const visit = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        visit(full);
      } else if (entry.isFile()) {
        files.push(path.relative(sourceRoot, full));
      }
    }
  };
  visit(root);
  return files.sort();
}

function managedClaudeFiles(sourceRoot) {
  return [
    ...sourceDirFiles(sourceRoot, path.join(".claude", "agents"), (name) => name.endsWith(".md")),
    ...BOB_COMMAND_FILES.map((name) => path.join(".claude", "commands", name)),
    ...LEGACY_BOB_COMMAND_FILES.map((name) => path.join(".claude", "commands", "bob", name)),
    ...BOB_SKILLS.map((skill) => path.join(".claude", "skills", skill, "SKILL.md")),
    ...LEGACY_BOB_SKILLS.map((skill) => path.join(".claude", "skills", skill, "SKILL.md")),
    ...sourceDirFiles(sourceRoot, path.join(".claude", "rules"), (name) => name.endsWith(".md")),
    ...sourceDirFiles(sourceRoot, path.join(".claude", "bypass-tables"), (name) => name.endsWith(".txt")),
    ...sourceDirFiles(sourceRoot, path.join(".claude", "knowledge"), (name) => name.endsWith(".json")),
    ...HOOK_FILES.map((name) => path.join(".claude", "hooks", name)),
    path.join(".claude", "bob", "VERSION"),
    path.join(".claude", "bob", "install.json"),
  ];
}

function managedRuntimeFiles(sourceRoot) {
  return sourceTreeFiles(sourceRoot, "mcp");
}

function maybeRemoveFile(targetAbs, relativePath, result) {
  const filePath = path.join(targetAbs, relativePath);
  if (!fs.existsSync(filePath)) return;
  const stat = fs.lstatSync(filePath);
  if (stat.isDirectory()) {
    result.skipped.push({ type: "file", path: relativePath, reason: "expected file but found directory" });
    return;
  }
  result.actions.push({ type: "remove_file", path: relativePath });
  if (!result.dry_run) fs.rmSync(filePath, { force: true });
}

function maybeRemoveEmptyDir(targetAbs, relativePath, result) {
  const dirPath = path.join(targetAbs, relativePath);
  if (!dirExists(dirPath)) return;
  if (fs.readdirSync(dirPath).length !== 0) return;
  result.actions.push({ type: "remove_empty_dir", path: relativePath });
  if (!result.dry_run) fs.rmdirSync(dirPath);
}

function pruneManagedDirs(targetAbs, result) {
  for (const relativePath of [
    path.join(".claude", "commands", "bob"),
    path.join(".claude", "commands"),
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
    path.join("mcp", "lib", "tools"),
    path.join("mcp", "lib"),
    "mcp",
  ]) {
    maybeRemoveEmptyDir(targetAbs, relativePath, result);
  }
}

function removeMcpConfig(targetAbs, result) {
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
  if (Object.keys(next.mcpServers).length === 0) delete next.mcpServers;
  result.actions.push({ type: Object.keys(next).length === 0 ? "remove_config_file" : "update_config", path: ".mcp.json" });
  if (result.dry_run) return;
  if (Object.keys(next).length === 0) {
    fs.rmSync(mcpPath, { force: true });
  } else {
    writeJson(mcpPath, next);
  }
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

function removeSettingsConfig(targetAbs, result) {
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

  const bobSettings = defaultClaudeSettings();
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

function uninstallProject(projectDir, options = {}) {
  const sourceRoot = path.resolve(options.sourceRoot || path.join(__dirname, ".."));
  const targetAbs = path.resolve(projectDir || ".");
  if (!dirExists(targetAbs)) {
    throw new Error(`Uninstall target does not exist or is not a directory: ${targetAbs}`);
  }
  const result = {
    ok: true,
    dry_run: options.dryRun !== false,
    target: targetAbs,
    actions: [],
    skipped: [],
  };

  removeMcpConfig(targetAbs, result);
  removeSettingsConfig(targetAbs, result);

  for (const relativePath of [
    ...managedClaudeFiles(sourceRoot),
    ...managedRuntimeFiles(sourceRoot),
  ]) {
    maybeRemoveFile(targetAbs, relativePath, result);
  }

  pruneManagedDirs(targetAbs, result);
  return result;
}

function printUninstallReport(result, stream = process.stdout) {
  stream.write(`Hacker Bob uninstall: ${result.target}\n`);
  stream.write(result.dry_run ? "Mode: dry-run (pass --yes to remove)\n\n" : "Mode: remove\n\n");
  if (result.actions.length === 0) {
    stream.write("No Bob-managed files or config entries found.\n");
  } else {
    for (const action of result.actions) {
      stream.write(`${result.dry_run ? "WOULD " : ""}${action.type}: ${action.path}\n`);
    }
  }
  if (result.skipped.length > 0) {
    stream.write("\nSkipped:\n");
    for (const skipped of result.skipped) {
      stream.write(`SKIP ${skipped.type}: ${skipped.path} (${skipped.reason})\n`);
    }
  }
}

module.exports = {
  BOB_COMMAND_FILES,
  LEGACY_BOB_COMMAND_FILES,
  BOB_SKILLS,
  LEGACY_BOB_SKILLS,
  doctorProject,
  expectedMcpServer,
  managedClaudeFiles,
  managedRuntimeFiles,
  printDoctorReport,
  printUninstallReport,
  uninstallProject,
};
