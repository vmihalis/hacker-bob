"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const config = require("./config.js");
const { createSafeInstallFs } = require("../../scripts/lib/install-fs.js");
const {
  AGENTS_SOURCE_DIR,
  OPENCODE_ROLE_SPECS,
  renderOpencodePromptBody,
  roleBody,
  updateOpencodeRoleFiles,
} = require("../../scripts/lib/opencode-role-renderer.js");

const id = "opencode";

const {
  AGENTS_DIR,
  BOB_DIR,
  COMMANDS_DIR,
  COMMAND_SPECS,
  CONFIG_FILE,
  CONFIG_SCHEMA,
} = config;

function agentSpecList() {
  return Object.values(OPENCODE_ROLE_SPECS);
}

// Install-target-relative `.opencode/agents/bob-*.md` paths (the @mention targets).
function agentTargetFiles() {
  return agentSpecList().map((spec) => path.join(AGENTS_DIR, `${spec.name}.md`));
}

// status/debug commands render the shared read-only role bodies; the rest map to
// node helpers or the orchestrator agent.
const COMMAND_ROLE_IDS = Object.freeze({ status: "status", debug: "debug" });

// External adversarial-roast MCP server consumed by the brutalist-verifier
// role. Optional — registered alongside hacker-bob but not required at runtime.
// See prompts/roles/brutalist-verifier.md for the graceful-fallback contract.
const BRUTALIST_COMMAND = Object.freeze(["npx", "-y", "@brutalist/mcp@latest"]);

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
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

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

// OpenCode local stdio MCP entry shape: { type, command[], enabled }. This is
// intentionally different from the Claude/Codex/Kimi `mcpServers: { command,
// args }` shape — OpenCode reads a flat `command` array under the `mcp` key.
function bobMcpEntry(serverPath) {
  return { type: "local", command: ["node", serverPath], enabled: true };
}

function brutalistMcpEntry() {
  return { type: "local", command: [...BRUTALIST_COMMAND], enabled: true };
}

function mergeConfig({ serverPath }) {
  return {
    mcp: {
      "hacker-bob": bobMcpEntry(serverPath),
      brutalist: brutalistMcpEntry(),
    },
  };
}

function expectedBobEntry(targetAbs) {
  return bobMcpEntry(path.join(targetAbs, "mcp", "server.js"));
}

function bobEntryMatches(entry, targetAbs) {
  return JSON.stringify(entry) === JSON.stringify(expectedBobEntry(targetAbs));
}

// The /bob-evaluate command routes to the bob-orchestrator primary agent (whose
// rendered contract carries the full runbook). status/debug inline the shared
// read-only role bodies; update/export/egress call the mcp/lib helpers directly
// (OpenCode has no hooks dir, so there is nothing to wrap).
function renderEvaluateCommand(spec) {
  return [
    "---",
    `description: ${spec.description}`,
    "agent: bob-orchestrator",
    "---",
    "",
    "Run or resume a Hacker Bob bug bounty evaluation. The operator invoked this",
    "command with:",
    "",
    "```text",
    "$ARGUMENTS",
    "```",
    "",
    "You are the `bob-orchestrator` agent. Treat `$ARGUMENTS` as the target/resume",
    "input, drive the six-state lifecycle, and dispatch the per-role `@bob-*`",
    "subagents by mention. The project-local `hacker-bob` MCP server is the source",
    "of truth for all durable session state; honor every guardrail in your agent",
    "contract.",
    "",
  ].join("\n");
}

function renderRoleCommand(commandId, spec) {
  const roleId = COMMAND_ROLE_IDS[commandId];
  const body = renderOpencodePromptBody(roleId, roleBody(roleId));
  return [
    "---",
    `description: ${spec.description}`,
    "---",
    "",
    `The operator invoked /${spec.command} with: \`$ARGUMENTS\` (optional target selector).`,
    "Use it to choose the Hacker Bob session, then follow the workflow below.",
    "",
    body.trimEnd(),
    "",
  ].join("\n");
}

function renderUpdateCommand(spec) {
  return [
    "---",
    `description: ${spec.description}`,
    "---",
    "",
    "# Hacker Bob Update",
    "",
    "Check, plan, or apply Hacker Bob project-local updates. Operator input:",
    "`$ARGUMENTS` (`check` or `apply`; default `check`).",
    "",
    "Read the passive local cache without network access:",
    "```bash",
    'node -e "const update=require(\'./mcp/lib/update-check.js\'); console.log(JSON.stringify(update.readUpdateCache(process.cwd()) || null, null, 2));"',
    "```",
    "",
    "Check latest only when the operator explicitly asks to check:",
    "```bash",
    'node -e "const update=require(\'./mcp/lib/update-check.js\'); update.checkForUpdate(process.cwd(), { includeChangelog: true }).then((r) => console.log(update.renderUpdatePlan(r))).catch((e) => { console.error(e.message || String(e)); process.exit(1); });"',
    "```",
    "",
    "Apply only after the operator confirms. From the project root:",
    "```bash",
    'npx -y hacker-bob@latest install "$PWD" --adapter opencode',
    "```",
    "",
    "After installing, tell the operator to restart OpenCode in this project.",
    "",
  ].join("\n");
}

function renderExportCommand(spec) {
  return [
    "---",
    `description: ${spec.description}`,
    "---",
    "",
    "# Hacker Bob Export",
    "",
    "Create a post-release improvement bundle. The command takes no arguments.",
    "From the project root:",
    "```bash",
    'node -e "const exporter=require(\'./mcp/lib/bob-export.js\'); const result=exporter.exportBobReleaseBundle({ projectDir: process.cwd() }); process.stdout.write(exporter.renderExportResult(result));"',
    "```",
    "",
    "Report the helper output exactly. This exports telemetry and session summaries",
    "to improve Hacker Bob; it does not hunt, resume sessions, or interact with targets.",
    "",
  ].join("\n");
}

function renderEgressCommand(spec) {
  return [
    "---",
    `description: ${spec.description}`,
    "---",
    "",
    "# Hacker Bob Egress",
    "",
    "List, add, test, enable, disable, or remove Hacker Bob egress profiles.",
    "Operator input: `$ARGUMENTS` (`list`, `add <name>`, `test <name>`,",
    "`enable <name>`, `disable <name>`, or `remove <name>`).",
    "",
    "From the project root:",
    "```bash",
    'node ./mcp/lib/egress-cli.js "$PWD" $ARGUMENTS',
    "```",
    "",
    "Rules:",
    "- If no subcommand is provided, use `list`.",
    "- For `add <name>`, prefer an environment-variable reference such as",
    "  `--proxy-env BOB_EGRESS_<NAME>_PROXY`; never ask the operator to paste",
    "  credentials into chat.",
    "- For `remove <name>`, confirm with the operator, then rerun with `--yes`.",
    "- Report profile names, enabled status, region, description, and whether a",
    "  proxy is configured. Never print proxy URLs or credentials.",
    "",
  ].join("\n");
}

function renderCommand(commandId) {
  const spec = commandSpec(commandId);
  switch (commandId) {
    case "evaluate": return renderEvaluateCommand(spec);
    case "status":
    case "debug": return renderRoleCommand(commandId, spec);
    case "update": return renderUpdateCommand(spec);
    case "export": return renderExportCommand(spec);
    case "egress": return renderEgressCommand(spec);
    default: throw new Error(`Unknown OpenCode command: ${commandId}`);
  }
}

function commandSpec(commandId) {
  const spec = COMMAND_SPECS[commandId];
  if (!spec) throw new Error(`Unknown OpenCode command: ${commandId}`);
  return spec;
}

function commandIds() {
  return Object.keys(COMMAND_SPECS);
}

function render(options = {}) {
  // Regenerate the committed per-role subagent files (.opencode/agents/bob-*.md)
  // from the shared role model. Command files are rendered at install time.
  return updateOpencodeRoleFiles(options);
}

function managedFiles() {
  return [
    ...agentTargetFiles(),
    ...commandIds().map((commandId) => path.join(COMMANDS_DIR, commandSpec(commandId).file)),
    path.join(BOB_DIR, "VERSION"),
    path.join(BOB_DIR, "install.json"),
  ];
}

function managedDirs() {
  return [
    AGENTS_DIR,
    COMMANDS_DIR,
    BOB_DIR,
    ".opencode",
  ];
}

function mergeOpencodeConfig(existing, serverPath) {
  const base = isPlainObject(existing) ? { ...existing } : {};
  if (!base.$schema) base.$schema = CONFIG_SCHEMA;
  base.mcp = {
    ...(isPlainObject(base.mcp) ? base.mcp : {}),
    ...mergeConfig({ serverPath }).mcp,
  };
  return base;
}

function install({
  sourceRoot,
  targetAbs,
  serverPath,
  commitSha,
  installedAt,
  installerSource,
  installFs,
  manifest,
  packageName,
}) {
  const safeFs = installFs || createSafeInstallFs(targetAbs, { label: "install target" });

  // 1. Merge the project-root opencode.json MCP wiring, preserving every other
  // operator-configured key and MCP server.
  const configPath = path.join(targetAbs, CONFIG_FILE);
  const existing = safeFs.readJsonIfExists(configPath, {}, {
    kind: CONFIG_FILE,
    symlink: "reject",
  });
  safeFs.writeJson(configPath, mergeOpencodeConfig(existing, serverPath), {
    kind: CONFIG_FILE,
    rejectExistingSymlink: true,
  });

  // 2. Copy the committed per-role subagent files into .opencode/agents/.
  // These are pre-rendered from the shared role model (copy-only, like the
  // Codex/Kimi skills); the orchestrator dispatches them via @bob-<role>.
  let agents = 0;
  for (const spec of agentSpecList()) {
    safeFs.copyFile(
      path.join(sourceRoot, AGENTS_SOURCE_DIR, `${spec.name}.md`),
      path.join(targetAbs, AGENTS_DIR, `${spec.name}.md`),
    );
    agents += 1;
  }

  // 3. Render OpenCode-native slash commands.
  for (const commandId of commandIds()) {
    safeFs.writeTextFile(
      path.join(targetAbs, COMMANDS_DIR, commandSpec(commandId).file),
      renderCommand(commandId),
      { kind: "generated file" },
    );
  }

  // 4. Write neutral install metadata under .opencode/bob/.
  const installManifest = manifest || {};
  safeFs.writeTextFile(
    path.join(targetAbs, BOB_DIR, "VERSION"),
    `${installManifest.version || "0.0.0"}\n`,
    { kind: ".opencode/bob/VERSION" },
  );
  safeFs.writeJson(path.join(targetAbs, BOB_DIR, "install.json"), {
    schema_version: 1,
    bob_version: installManifest.version || "0.0.0",
    installed_at: installedAt || new Date().toISOString(),
    package_name: packageName || installManifest.name || "hacker-bob",
    install_target: targetAbs,
    installer_source: installerSource || "cli",
    commit_sha: commitSha || null,
  }, { kind: ".opencode/bob/install.json" });

  return {
    configPath,
    agents,
    commands: commandIds().length,
  };
}

function addCheck(checks, status, checkId, message, detail) {
  const check = { id: checkId, status, message };
  if (detail !== undefined) check.detail = detail;
  checks.push(check);
  return check;
}

function doctor({ targetAbs }) {
  const checks = [];

  const configPath = path.join(targetAbs, CONFIG_FILE);
  if (!fileExists(configPath)) {
    addCheck(checks, "error", "opencode_config", `${CONFIG_FILE} is missing`);
  } else {
    try {
      const cfg = readJson(configPath);
      const entry = cfg.mcp && cfg.mcp["hacker-bob"];
      if (bobEntryMatches(entry, targetAbs)) {
        addCheck(checks, "ok", "opencode_config", `${CONFIG_FILE} points hacker-bob at this project's mcp/server.js`);
      } else {
        addCheck(checks, "error", "opencode_config", `${CONFIG_FILE} is missing the Bob-managed hacker-bob MCP entry`);
      }
      const brutalistEntry = cfg.mcp && cfg.mcp.brutalist;
      if (brutalistEntry && Array.isArray(brutalistEntry.command) && brutalistEntry.command[0] === BRUTALIST_COMMAND[0]) {
        addCheck(checks, "ok", "opencode_brutalist_optional", `${CONFIG_FILE} registers the optional @brutalist/mcp server`);
      } else {
        addCheck(checks, "info", "opencode_brutalist_optional", `${CONFIG_FILE} does not register @brutalist/mcp — brutalist verifier will fall back gracefully`);
      }
    } catch (error) {
      addCheck(checks, "error", "opencode_config", `${CONFIG_FILE} is not valid JSON`, {
        error: error.message || String(error),
      });
    }
  }

  const serverPath = path.join(targetAbs, "mcp", "server.js");
  if (!fileExists(serverPath)) {
    addCheck(checks, "error", "opencode_server", "mcp/server.js is missing");
  } else {
    addCheck(checks, "ok", "opencode_server", "mcp/server.js is present");
  }

  const missingAgents = agentTargetFiles()
    .filter((relative) => !fileExists(path.join(targetAbs, relative)));
  if (missingAgents.length === 0) {
    addCheck(checks, "ok", "opencode_agents", `All ${agentSpecList().length} Bob subagents are installed`);
  } else {
    addCheck(checks, "error", "opencode_agents", "OpenCode Bob subagents are missing", { missing: missingAgents });
  }

  const missingCommands = commandIds()
    .map((commandId) => path.join(COMMANDS_DIR, commandSpec(commandId).file))
    .filter((relative) => !fileExists(path.join(targetAbs, relative)));
  if (missingCommands.length === 0) {
    addCheck(checks, "ok", "opencode_commands", "OpenCode Bob slash commands are installed");
  } else {
    addCheck(checks, "error", "opencode_commands", "OpenCode Bob slash commands are missing", { missing: missingCommands });
  }

  const versionPath = path.join(targetAbs, BOB_DIR, "VERSION");
  if (fileExists(versionPath)) {
    const installedVersion = fs.readFileSync(versionPath, "utf8").trim();
    if (installedVersion) {
      addCheck(checks, "ok", "opencode_installed_version", `Installed Bob version is ${installedVersion}`, {
        installed_version: installedVersion,
      });
    } else {
      addCheck(checks, "error", "opencode_installed_version", ".opencode/bob/VERSION is empty");
    }
  } else {
    addCheck(checks, "error", "opencode_installed_version", ".opencode/bob/VERSION is missing");
  }

  const metaPath = path.join(targetAbs, BOB_DIR, "install.json");
  if (!fileExists(metaPath)) {
    addCheck(checks, "error", "opencode_install_metadata", ".opencode/bob/install.json is missing");
  } else {
    try {
      const meta = readJson(metaPath);
      if (meta.install_target === targetAbs) {
        addCheck(checks, "ok", "opencode_install_metadata", "install.json metadata matches this project");
      } else {
        addCheck(checks, "error", "opencode_install_metadata", "install.json install_target does not match this project", {
          recorded: meta.install_target,
          expected: targetAbs,
        });
      }
    } catch (error) {
      addCheck(checks, "error", "opencode_install_metadata", "install.json is not valid JSON", {
        error: error.message || String(error),
      });
    }
  }

  // BYOK — Bob never configures the operator's provider auth.
  addCheck(checks, "info", "opencode_auth", "OpenCode is BYOK: set your provider's key (e.g. OPENROUTER_API_KEY) or run `opencode auth login`. Bob does not manage model/provider auth.");

  const opencodeOnPath = spawnSync("sh", ["-c", "command -v opencode"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (opencodeOnPath.status === 0) {
    addCheck(checks, "ok", "opencode_cli_on_path", "opencode is available on PATH");
  } else {
    addCheck(checks, "warn", "opencode_cli_on_path", "opencode is not on PATH; install OpenCode before using Bob commands");
  }

  return {
    ok: checks.every((check) => check.status !== "error"),
    target: targetAbs,
    adapter: id,
    checks,
  };
}

function removeMcpConfig(targetAbs, result) {
  const configPath = path.join(targetAbs, CONFIG_FILE);
  if (!fileExists(configPath)) return;
  let cfg;
  try {
    cfg = readJson(configPath);
  } catch (error) {
    result.skipped.push({ type: "config", path: CONFIG_FILE, reason: `invalid JSON: ${error.message || String(error)}` });
    return;
  }
  if (!isPlainObject(cfg) || !isPlainObject(cfg.mcp)) return;
  if (!("hacker-bob" in cfg.mcp) && !("brutalist" in cfg.mcp)) return;
  if ("hacker-bob" in cfg.mcp && !bobEntryMatches(cfg.mcp["hacker-bob"], targetAbs)) {
    result.skipped.push({ type: "config", path: CONFIG_FILE, reason: "hacker-bob MCP entry is not Bob-managed" });
    return;
  }
  const nextMcp = { ...cfg.mcp };
  delete nextMcp["hacker-bob"];
  const brutalist = nextMcp.brutalist;
  if (brutalist && Array.isArray(brutalist.command) && brutalist.command[0] === BRUTALIST_COMMAND[0]) {
    delete nextMcp.brutalist;
  }
  const next = { ...cfg };
  if (Object.keys(nextMcp).length === 0) {
    delete next.mcp;
  } else {
    next.mcp = nextMcp;
  }
  // Drop a Bob-only config file (just $schema left, or fully empty).
  const remainingKeys = Object.keys(next).filter((key) => key !== "$schema");
  const removeFile = remainingKeys.length === 0;
  result.actions.push({ type: removeFile ? "remove_config_file" : "update_config", path: CONFIG_FILE });
  if (result.dry_run) return;
  if (removeFile) {
    fs.rmSync(configPath, { force: true });
  } else {
    writeJson(configPath, next);
  }
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

function uninstall({ targetAbs, dryRun = true, preserveMcpConfig = false }) {
  const result = {
    ok: true,
    dry_run: dryRun,
    target: targetAbs,
    adapter: id,
    actions: [],
    skipped: [],
  };
  if (!preserveMcpConfig) removeMcpConfig(targetAbs, result);
  for (const relativePath of managedFiles()) {
    maybeRemoveFile(targetAbs, relativePath, result);
  }
  for (const relativePath of managedDirs()) {
    maybeRemoveEmptyDir(targetAbs, relativePath, result);
  }
  return result;
}

module.exports = {
  AGENTS_DIR,
  BRUTALIST_COMMAND,
  COMMAND_SPECS,
  CONFIG_FILE,
  CONFIG_SCHEMA,
  agentTargetFiles,
  bobMcpEntry,
  commandIds,
  commandSpec,
  doctor,
  id,
  install,
  managedDirs,
  managedFiles,
  mergeConfig,
  render,
  renderCommand,
  uninstall,
};
