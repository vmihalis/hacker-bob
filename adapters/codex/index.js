"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  CODEX_SKILL_SPECS,
  updateCodexSkillFiles,
} = require("../../scripts/lib/codex-role-renderer.js");

const id = "codex";
const PLUGIN_NAME = "hacker-bob";
const PLUGIN_SOURCE_DIR = path.join("adapters", "codex", PLUGIN_NAME);
const PLUGIN_TARGET_DIR = path.join(".codex", "plugins", PLUGIN_NAME);
const MARKETPLACE_PATH = path.join(".agents", "plugins", "marketplace.json");
const MARKETPLACE_NAME = "hacker-bob-local";
const PLUGIN_CONFIG_ID = `${PLUGIN_NAME}@${MARKETPLACE_NAME}`;
const LEGACY_SKILL_DIRS = Object.freeze([
  "hacker-bob-hunt",
  "hacker-bob-status",
  "hacker-bob-debug",
  "hacker-bob-update",
]);
const COMMAND_SPECS = Object.freeze({
  hunt: Object.freeze({
    file: "hunt.md",
    skill: "hunt",
    description: "Run or resume a Hacker Bob bug bounty hunt.",
    argumentHint: "<target|resume target [force-merge]> [--no-auth|--normal|--paranoid|--yolo]",
  }),
  status: Object.freeze({
    file: "status.md",
    skill: "status",
    description: "Show the latest Hacker Bob session status.",
    argumentHint: "[target]",
  }),
  debug: Object.freeze({
    file: "debug.md",
    skill: "debug",
    description: "Debug the latest or selected Hacker Bob run.",
    argumentHint: "[target] [--deep]",
  }),
  update: Object.freeze({
    file: "update.md",
    skill: "update",
    description: "Check or apply Hacker Bob project-local updates.",
    argumentHint: "[check|apply]",
  }),
});

function pluginSourceRoot(sourceRoot) {
  return path.join(sourceRoot, PLUGIN_SOURCE_DIR);
}

function pluginTargetRoot(targetAbs) {
  return path.join(targetAbs, PLUGIN_TARGET_DIR);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function writeText(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, value, "utf8");
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

function copyTree(sourceDir, destinationDir) {
  const copied = [];
  const visit = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const source = path.join(current, entry.name);
      const relative = path.relative(sourceDir, source);
      const destination = path.join(destinationDir, relative);
      if (entry.isDirectory()) {
        fs.mkdirSync(destination, { recursive: true });
        visit(source);
      } else if (entry.isFile()) {
        fs.mkdirSync(path.dirname(destination), { recursive: true });
        fs.copyFileSync(source, destination);
        copied.push(relative);
      }
    }
  };
  fs.mkdirSync(destinationDir, { recursive: true });
  visit(sourceDir);
  return copied.sort();
}

function removeDirContents(dirPath) {
  if (!dirExists(dirPath)) return;
  for (const entry of fs.readdirSync(dirPath)) {
    fs.rmSync(path.join(dirPath, entry), { recursive: true, force: true });
  }
}

function managedFiles(sourceRoot) {
  return [
    ...sourceTreeFiles(sourceRoot, PLUGIN_SOURCE_DIR)
      .map((relative) => path.join(PLUGIN_TARGET_DIR, path.relative(PLUGIN_SOURCE_DIR, relative))),
    ...commandIds().map((commandId) => path.join(PLUGIN_TARGET_DIR, "commands", commandSpec(commandId).file)),
    ...LEGACY_SKILL_DIRS.map((dir) => path.join(PLUGIN_TARGET_DIR, "skills", dir, "SKILL.md")),
  ];
}

function managedDirs() {
  return [
    ...Object.values(CODEX_SKILL_SPECS).map((spec) => (
      path.join(PLUGIN_TARGET_DIR, "skills", path.basename(path.dirname(spec.output_path)))
    )),
    ...LEGACY_SKILL_DIRS.map((dir) => path.join(PLUGIN_TARGET_DIR, "skills", dir)),
    path.join(PLUGIN_TARGET_DIR, "commands"),
    path.join(PLUGIN_TARGET_DIR, "skills"),
    path.join(PLUGIN_TARGET_DIR, ".codex-plugin"),
    PLUGIN_TARGET_DIR,
    path.join(".codex", "plugins"),
    ".codex",
    path.join(".agents", "plugins"),
    ".agents",
  ];
}

function mergeConfig({ serverPath }) {
  return {
    mcpServers: {
      bountyagent: {
        command: "node",
        args: [serverPath],
      },
    },
  };
}

function render(options = {}) {
  return updateCodexSkillFiles(options);
}

function commandSpec(commandId) {
  const spec = COMMAND_SPECS[commandId];
  if (!spec) throw new Error(`Unknown Codex command: ${commandId}`);
  return spec;
}

function commandIds() {
  return Object.keys(COMMAND_SPECS);
}

function renderCommand(commandId) {
  const spec = commandSpec(commandId);
  return [
    "---",
    `description: ${spec.description}`,
    `argument-hint: ${spec.argumentHint}`,
    "---",
    "",
    `# Hacker Bob ${commandId}`,
    "",
    `Use the installed \`$hacker-bob:${spec.skill}\` skill for this command.`,
    "",
    "The operator invoked this command with:",
    "",
    "```text",
    "$ARGUMENTS",
    "```",
    "",
    `Read \`skills/${spec.skill}/SKILL.md\`, treat \`$ARGUMENTS\` as that workflow's exact input, and follow the skill's guardrails.`,
    "",
  ].join("\n");
}

function writeCommandFiles(pluginDir) {
  for (const commandId of commandIds()) {
    writeText(path.join(pluginDir, "commands", commandSpec(commandId).file), renderCommand(commandId));
  }
}

function marketplaceEntry() {
  return {
    name: PLUGIN_NAME,
    source: {
      source: "local",
      path: `./${PLUGIN_TARGET_DIR.split(path.sep).join("/")}`,
    },
    policy: {
      installation: "INSTALLED_BY_DEFAULT",
      authentication: "ON_INSTALL",
    },
    category: "Developer Tools",
  };
}

function mergeMarketplace(existing) {
  const entry = marketplaceEntry();
  const base = existing && typeof existing === "object" && !Array.isArray(existing)
    ? existing
    : {};
  const plugins = Array.isArray(base.plugins) ? base.plugins.slice() : [];
  const index = plugins.findIndex((plugin) => plugin && plugin.name === PLUGIN_NAME);
  if (index === -1) {
    plugins.push(entry);
  } else {
    plugins[index] = {
      ...plugins[index],
      ...entry,
      policy: entry.policy,
      source: entry.source,
      category: entry.category,
    };
  }
  const existingInterface = base.interface && typeof base.interface === "object" && !Array.isArray(base.interface)
    ? base.interface
    : {};
  return {
    ...base,
    name: base.name || MARKETPLACE_NAME,
    interface: {
      displayName: "Project Local",
      ...existingInterface,
    },
    plugins,
  };
}

function installMarketplace(targetAbs) {
  const marketplacePath = path.join(targetAbs, MARKETPLACE_PATH);
  const existing = fileExists(marketplacePath) ? readJson(marketplacePath) : null;
  writeJson(marketplacePath, mergeMarketplace(existing));
}

function codexHome() {
  return path.resolve(process.env.CODEX_HOME || path.join(os.homedir(), ".codex"));
}

function tomlString(value) {
  return `"${String(value).replace(/\\/g, "\\\\").replace(/"/g, "\\\"")}"`;
}

function upsertTomlSection(text, header, bodyLines) {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  const section = [header, ...bodyLines];
  const start = lines.findIndex((line) => line.trim() === header);
  if (start === -1) {
    if (lines.length > 0 && lines[lines.length - 1] !== "") lines.push("");
    lines.push(...section);
    return `${lines.join("\n")}\n`;
  }
  let end = start + 1;
  while (end < lines.length && !/^\s*\[/.test(lines[end])) end += 1;
  const replacement = end < lines.length ? [...section, ""] : section;
  lines.splice(start, end - start, ...replacement);
  return `${lines.join("\n").replace(/\n+$/g, "")}\n`;
}

function removeTomlSection(text, header) {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  const start = lines.findIndex((line) => line.trim() === header);
  if (start === -1) return text;
  let end = start + 1;
  while (end < lines.length && !/^\s*\[/.test(lines[end])) end += 1;
  while (start > 0 && lines[start - 1] === "" && end < lines.length && lines[end] === "") {
    end += 1;
  }
  lines.splice(start, end - start);
  return `${lines.join("\n").replace(/\n+$/g, "")}\n`;
}

function tomlSectionBody(text, header) {
  const normalized = text.replace(/\r\n/g, "\n");
  const start = normalized.split("\n").findIndex((line) => line.trim() === header);
  if (start === -1) return "";
  const lines = normalized.split("\n");
  let end = start + 1;
  while (end < lines.length && !/^\s*\[/.test(lines[end])) end += 1;
  return lines.slice(start + 1, end).join("\n");
}

function codexConfigPath(home = codexHome()) {
  return path.join(home, "config.toml");
}

function pluginVersion(pluginDir) {
  const manifest = readJson(path.join(pluginDir, ".codex-plugin", "plugin.json"));
  return manifest.version || "0.0.0";
}

function codexCacheRoot({ home = codexHome(), version }) {
  return path.join(home, "plugins", "cache", MARKETPLACE_NAME, PLUGIN_NAME, version);
}

function activateCodexPlugin({ targetAbs, pluginDir }) {
  const home = codexHome();
  const configPath = codexConfigPath(home);
  const version = pluginVersion(pluginDir);
  const cacheBase = path.join(home, "plugins", "cache", MARKETPLACE_NAME, PLUGIN_NAME);
  const cacheDir = codexCacheRoot({ home, version });
  fs.mkdirSync(cacheBase, { recursive: true });
  removeDirContents(cacheBase);
  copyTree(pluginDir, cacheDir);

  const existingConfig = fileExists(configPath) ? fs.readFileSync(configPath, "utf8") : "";
  const withPlugin = upsertTomlSection(existingConfig, `[plugins.${tomlString(PLUGIN_CONFIG_ID)}]`, [
    "enabled = true",
  ]);
  const withMarketplace = upsertTomlSection(withPlugin, `[marketplaces.${MARKETPLACE_NAME}]`, [
    `last_updated = ${tomlString(new Date().toISOString())}`,
    "source_type = \"local\"",
    `source = ${tomlString(targetAbs)}`,
  ]);
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, withMarketplace, "utf8");
  return {
    ok: true,
    cacheDir,
    configPath,
    pluginId: PLUGIN_CONFIG_ID,
  };
}

function maybeActivateCodexPlugin({ activate, targetAbs, pluginDir }) {
  if (!activate) {
    return { ok: false, skipped: true, reason: "activation disabled" };
  }
  try {
    return activateCodexPlugin({ targetAbs, pluginDir });
  } catch (error) {
    return {
      ok: false,
      skipped: false,
      reason: error && error.message ? error.message : String(error),
    };
  }
}

function codexActivationStatus(targetAbs) {
  const home = codexHome();
  const configPath = codexConfigPath(home);
  const pluginDir = pluginTargetRoot(targetAbs);
  let version = null;
  try {
    version = pluginVersion(pluginDir);
  } catch {
    version = null;
  }
  const cacheDir = version ? codexCacheRoot({ home, version }) : null;
  const config = fileExists(configPath) ? fs.readFileSync(configPath, "utf8") : "";
  const pluginHeader = `[plugins.${tomlString(PLUGIN_CONFIG_ID)}]`;
  const marketplaceHeader = `[marketplaces.${MARKETPLACE_NAME}]`;
  const pluginConfig = tomlSectionBody(config, pluginHeader);
  const marketplaceConfig = tomlSectionBody(config, marketplaceHeader);
  return {
    configPath,
    cacheDir,
    hasCache: cacheDir ? dirExists(cacheDir) : false,
    hasPluginConfig: /enabled\s*=\s*true/.test(pluginConfig),
    hasMarketplaceConfig: marketplaceConfig.includes(`source = ${tomlString(targetAbs)}`),
  };
}

function install({ sourceRoot, targetAbs, serverPath, activate = false }) {
  const source = pluginSourceRoot(sourceRoot);
  const destination = pluginTargetRoot(targetAbs);
  for (const dir of LEGACY_SKILL_DIRS) {
    fs.rmSync(path.join(destination, "skills", dir), { recursive: true, force: true });
  }
  const copied = copyTree(source, destination);
  writeCommandFiles(destination);
  writeJson(path.join(destination, ".mcp.json"), mergeConfig({ serverPath }));
  installMarketplace(targetAbs);
  const activation = maybeActivateCodexPlugin({ activate, targetAbs, pluginDir: destination });
  return {
    activation,
    commands: commandIds().length,
    pluginDir: destination,
    files: copied.length,
    skills: Object.keys(CODEX_SKILL_SPECS).length,
  };
}

function addCheck(checks, status, id, message, detail) {
  const check = { id, status, message };
  if (detail !== undefined) check.detail = detail;
  checks.push(check);
  return check;
}

function doctor({ targetAbs }) {
  const checks = [];
  const pluginDir = pluginTargetRoot(targetAbs);
  if (dirExists(pluginDir)) {
    addCheck(checks, "ok", "codex_plugin_dir", `${PLUGIN_TARGET_DIR} is installed`);
  } else {
    addCheck(checks, "error", "codex_plugin_dir", `${PLUGIN_TARGET_DIR} is missing`);
  }

  const manifestPath = path.join(pluginDir, ".codex-plugin", "plugin.json");
  let manifest = null;
  if (!fileExists(manifestPath)) {
    addCheck(checks, "error", "codex_plugin_manifest", ".codex-plugin/plugin.json is missing");
  } else {
    try {
      manifest = readJson(manifestPath);
      if (manifest.name === PLUGIN_NAME && manifest.skills === "./skills/" && manifest.mcpServers === "./.mcp.json") {
        addCheck(checks, "ok", "codex_plugin_manifest", "Codex plugin manifest is valid");
      } else {
        addCheck(checks, "error", "codex_plugin_manifest", "Codex plugin manifest is incomplete or mismatched");
      }
    } catch (error) {
      addCheck(checks, "error", "codex_plugin_manifest", ".codex-plugin/plugin.json is not valid JSON", {
        error: error.message || String(error),
      });
    }
  }

  const missingSkills = Object.values(CODEX_SKILL_SPECS)
    .map((spec) => path.join("skills", path.basename(path.dirname(spec.output_path)), "SKILL.md"))
    .filter((relative) => !fileExists(path.join(pluginDir, relative)));
  if (missingSkills.length === 0) {
    addCheck(checks, "ok", "codex_plugin_skills", "Codex Bob skills are installed");
  } else {
    addCheck(checks, "error", "codex_plugin_skills", "Codex Bob skills are missing", { missing: missingSkills });
  }

  const missingCommands = commandIds()
    .map((commandId) => path.join("commands", commandSpec(commandId).file))
    .filter((relative) => !fileExists(path.join(pluginDir, relative)));
  if (missingCommands.length === 0) {
    addCheck(checks, "ok", "codex_plugin_commands", "Codex Bob plugin command wrappers are installed");
  } else {
    addCheck(checks, "error", "codex_plugin_commands", "Codex Bob plugin command wrappers are missing", { missing: missingCommands });
  }

  const marketplacePath = path.join(targetAbs, MARKETPLACE_PATH);
  if (!fileExists(marketplacePath)) {
    addCheck(checks, "error", "codex_plugin_marketplace", `${MARKETPLACE_PATH} is missing`);
  } else {
    try {
      const marketplace = readJson(marketplacePath);
      const entry = marketplace && Array.isArray(marketplace.plugins)
        ? marketplace.plugins.find((plugin) => plugin && plugin.name === PLUGIN_NAME)
        : null;
      if (
        entry &&
        entry.source &&
        entry.source.source === "local" &&
        entry.source.path === marketplaceEntry().source.path &&
        entry.policy &&
        entry.policy.installation === "INSTALLED_BY_DEFAULT"
      ) {
        addCheck(checks, "ok", "codex_plugin_marketplace", "Codex marketplace entry is installed");
      } else {
        addCheck(checks, "error", "codex_plugin_marketplace", "Codex marketplace entry is missing or mismatched");
      }
    } catch (error) {
      addCheck(checks, "error", "codex_plugin_marketplace", `${MARKETPLACE_PATH} is not valid JSON`, {
        error: error.message || String(error),
      });
    }
  }

  const activation = codexActivationStatus(targetAbs);
  if (activation.hasCache && activation.hasPluginConfig && activation.hasMarketplaceConfig) {
    addCheck(checks, "ok", "codex_plugin_activation", "Codex plugin is activated in Codex cache");
  } else {
    addCheck(checks, "warn", "codex_plugin_activation", "Codex plugin files are present, but Codex may not show slash commands until activation completes", {
      configPath: activation.configPath,
      cacheDir: activation.cacheDir,
      hasCache: activation.hasCache,
      hasPluginConfig: activation.hasPluginConfig,
      hasMarketplaceConfig: activation.hasMarketplaceConfig,
    });
  }

  const mcpPath = path.join(pluginDir, ".mcp.json");
  if (!fileExists(mcpPath)) {
    addCheck(checks, "error", "codex_plugin_mcp", "Codex plugin .mcp.json is missing");
  } else {
    try {
      const mcp = readJson(mcpPath);
      const expected = mergeConfig({ serverPath: path.join(targetAbs, "mcp", "server.js") });
      if (JSON.stringify(mcp) === JSON.stringify(expected)) {
        addCheck(checks, "ok", "codex_plugin_mcp", "Codex plugin MCP config points at this project's mcp/server.js");
      } else {
        addCheck(checks, "error", "codex_plugin_mcp", "Codex plugin MCP config is not Bob-managed");
      }
    } catch (error) {
      addCheck(checks, "error", "codex_plugin_mcp", "Codex plugin .mcp.json is not valid JSON", {
        error: error.message || String(error),
      });
    }
  }

  for (const relativeDir of [
    path.join(".hacker-bob", "knowledge"),
    path.join(".hacker-bob", "bypass-tables"),
  ]) {
    const full = path.join(targetAbs, relativeDir);
    const idSuffix = path.basename(relativeDir).replace(/-/g, "_");
    if (dirExists(full) && fs.readdirSync(full).some((name) => fileExists(path.join(full, name)))) {
      addCheck(checks, "ok", `codex_resource_${idSuffix}`, `${relativeDir} is available`);
    } else {
      addCheck(checks, "error", `codex_resource_${idSuffix}`, `${relativeDir} is missing or empty`);
    }
  }

  return {
    ok: checks.every((check) => check.status !== "error"),
    target: targetAbs,
    adapter: id,
    manifest,
    checks,
  };
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

function removeMarketplaceEntry(targetAbs, result) {
  const marketplacePath = path.join(targetAbs, MARKETPLACE_PATH);
  if (!fileExists(marketplacePath)) return;
  let marketplace;
  try {
    marketplace = readJson(marketplacePath);
  } catch (error) {
    result.skipped.push({ type: "config", path: MARKETPLACE_PATH, reason: `invalid JSON: ${error.message || String(error)}` });
    return;
  }
  if (!marketplace || !Array.isArray(marketplace.plugins)) return;
  const plugins = marketplace.plugins.filter((plugin) => !(plugin && plugin.name === PLUGIN_NAME));
  if (plugins.length === marketplace.plugins.length) return;
  const next = { ...marketplace, plugins };
  const removeFile = plugins.length === 0 && marketplace.name === MARKETPLACE_NAME;
  result.actions.push({ type: removeFile ? "remove_config_file" : "update_config", path: MARKETPLACE_PATH });
  if (result.dry_run) return;
  if (removeFile) {
    fs.rmSync(marketplacePath, { force: true });
  } else {
    writeJson(marketplacePath, next);
  }
}

function removeCodexActivation(targetAbs, result) {
  const activation = codexActivationStatus(targetAbs);
  if (!activation.hasMarketplaceConfig) {
    if (activation.hasCache || activation.hasPluginConfig) {
      result.skipped.push({
        type: "codex_activation",
        path: activation.configPath,
        reason: "Codex activation does not point at this install target",
      });
    }
    return;
  }
  if (activation.cacheDir && dirExists(activation.cacheDir)) {
    const cacheBase = path.dirname(activation.cacheDir);
    result.actions.push({ type: "remove_codex_cache", path: cacheBase });
    if (!result.dry_run) fs.rmSync(cacheBase, { recursive: true, force: true });
  }

  const configPath = activation.configPath;
  if (!fileExists(configPath)) return;
  const original = fs.readFileSync(configPath, "utf8");
  let next = removeTomlSection(original, `[plugins.${tomlString(PLUGIN_CONFIG_ID)}]`);
  next = removeTomlSection(next, `[marketplaces.${MARKETPLACE_NAME}]`);
  if (next === original) return;
  const removeConfig = next.trim() === "";
  result.actions.push({ type: removeConfig ? "remove_codex_config" : "update_codex_config", path: configPath });
  if (result.dry_run) return;
  if (removeConfig) {
    fs.rmSync(configPath, { force: true });
  } else {
    fs.writeFileSync(configPath, next, "utf8");
  }
}

function uninstall({ sourceRoot, targetAbs, dryRun = true }) {
  const result = {
    ok: true,
    dry_run: dryRun,
    target: targetAbs,
    adapter: id,
    actions: [],
    skipped: [],
  };
  removeCodexActivation(targetAbs, result);
  removeMarketplaceEntry(targetAbs, result);
  for (const relativePath of managedFiles(sourceRoot)) {
    maybeRemoveFile(targetAbs, relativePath, result);
  }
  for (const relativePath of managedDirs()) {
    maybeRemoveEmptyDir(targetAbs, relativePath, result);
  }
  return result;
}

module.exports = {
  CODEX_SKILL_SPECS,
  COMMAND_SPECS,
  LEGACY_SKILL_DIRS,
  MARKETPLACE_PATH,
  PLUGIN_CONFIG_ID,
  PLUGIN_NAME,
  PLUGIN_SOURCE_DIR,
  PLUGIN_TARGET_DIR,
  activateCodexPlugin,
  codexActivationStatus,
  codexCacheRoot,
  codexConfigPath,
  codexHome,
  commandIds,
  commandSpec,
  doctor,
  id,
  install,
  managedDirs,
  managedFiles,
  mergeConfig,
  marketplaceEntry,
  pluginTargetRoot,
  render,
  renderCommand,
  uninstall,
};
