"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const config = require("./config.js");
const { createSafeInstallFs } = require("../../scripts/lib/install-fs.js");
const { BRUTALIST_MCP_SERVER } = require("../../scripts/merge-claude-config.js");
const {
  AGENTS_SOURCE_DIR,
  OPENCODE_ROLE_SPECS,
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

// Install-target-relative `.opencode/agents/bob-*.md` paths (the task-tool
// `subagent_type` targets).
function agentTargetFiles() {
  return agentSpecList().map((spec) => path.join(AGENTS_DIR, `${spec.name}.md`));
}

// status/debug commands bind to their dedicated read-only subagents; the rest
// map to node helpers or the orchestrator agent. The role id keys the
// OPENCODE_ROLE_SPECS lookup that resolves the bound `bob-<role>` agent name.
const COMMAND_ROLE_IDS = Object.freeze({ status: "status", debug: "debug" });

// External adversarial-roast MCP server consumed by the brutalist-verifier
// role. Optional — registered alongside hacker-bob but not required at runtime.
// See prompts/roles/brutalist-verifier.md for the graceful-fallback contract.
// OpenCode reads a flat `command` array, but the package name and PINNED version
// are the single source of truth shared with the Claude/Codex/Kimi/generic
// adapters (BRUTALIST_MCP_SERVER = { command, args: ["-y", "@brutalist/mcp@<pin>"] }).
// Deriving from it keeps the reviewed version in lockstep instead of letting
// OpenCode installs float on `@latest` and silently execute a newer release.
const BRUTALIST_COMMAND = Object.freeze([
  BRUTALIST_MCP_SERVER.command,
  ...BRUTALIST_MCP_SERVER.args,
]);

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

// Strip a trailing `@version` from an npm package spec, scope-aware:
// "@brutalist/mcp@1.14.7" -> "@brutalist/mcp", "@brutalist/mcp" -> itself.
function npmSpecBase(spec) {
  if (typeof spec !== "string") return null;
  const at = spec.lastIndexOf("@");
  return at > 0 ? spec.slice(0, at) : spec;
}

// The reviewed @brutalist/mcp package (without its pinned version) Bob launches.
const BRUTALIST_PACKAGE_BASE = npmSpecBase(BRUTALIST_COMMAND[BRUTALIST_COMMAND.length - 1]);

// A `brutalist` entry is Bob-managed when it launches Bob's reviewed
// @brutalist/mcp package via the same npx invocation Bob writes — at ANY pinned
// version, not only the current one. Matching any pin (not the exact current
// command) lets install REFRESH a stale entry after a pin/security bump and
// lets uninstall remove an entry Bob wrote under an earlier version, while a
// genuinely operator-owned server that merely reuses the `brutalist` key (e.g.
// a local `node my-brutalist.js`, a different launcher/shape) is preserved.
function isBobManagedBrutalistEntry(entry) {
  return isPlainObject(entry)
    && Array.isArray(entry.command)
    && entry.command.length === BRUTALIST_COMMAND.length
    && entry.command.slice(0, -1).every((token, index) => token === BRUTALIST_COMMAND[index])
    && npmSpecBase(entry.command[entry.command.length - 1]) === BRUTALIST_PACKAGE_BASE;
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

// A `hacker-bob` entry is Bob-managed when it launches THIS install's
// mcp/server.js via the same `node <target>/mcp/server.js` command Bob writes.
// Ownership is classified from the command path alone — NOT byte-equality of the
// whole entry. The operator may have toggled `enabled: false` (or carry
// incidental extra keys), and uninstall must still remove Bob's own entry rather
// than leave it dangling at a now-deleted server. An entry the operator
// REPOINTED at a different server.js has a different command and is correctly
// preserved. Mirrors the command-based, enabled-agnostic recognizer used for the
// brutalist key.
function bobEntryMatches(entry, targetAbs) {
  if (!isPlainObject(entry) || !Array.isArray(entry.command)) return false;
  const expectedCommand = expectedBobEntry(targetAbs).command;
  return entry.command.length === expectedCommand.length
    && entry.command.every((token, index) => token === expectedCommand[index]);
}

// The /bob-evaluate command routes to the bob-orchestrator primary agent (whose
// rendered contract carries the full runbook). status/debug bind to their
// dedicated read-only subagents (bob-status / bob-debug). update/export/egress
// run node/npx maintenance helpers directly (OpenCode has no hooks dir, nothing
// to wrap), so they bind to the built-in bash-capable `build` primary: an
// agent-less command inherits the CURRENT agent, and after /bob-evaluate that
// is bob-orchestrator (rendered bash:false), which would deny their shell
// snippets. `build` is a primary (not a `bob-*` Task subagent), so it stays out
// of the orchestrator's Task allow-list.
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
    "input, drive the six-state lifecycle, and dispatch the per-role Bob subagents",
    "through the `task` tool (`task(subagent_type: \"bob-<role>\", ...)`). The",
    "project-local `hacker-bob` MCP server is the source of truth for all durable",
    "session state; honor every guardrail in your agent contract.",
    "",
  ].join("\n");
}

function renderRoleCommand(commandId, spec) {
  // status/debug bind to their dedicated read-only subagents (bob-status /
  // bob-debug) via `agent:`, mirroring how /bob-evaluate routes to
  // bob-orchestrator. OpenCode command frontmatter cannot restrict tools itself
  // and otherwise runs under the CURRENT agent (e.g. the primary orchestrator
  // with its mutating MCP surface), so the agent binding is the read-only
  // enforcement boundary — the subagent file carries the role body plus its
  // locked-down tool/permission frontmatter.
  const agentName = OPENCODE_ROLE_SPECS[COMMAND_ROLE_IDS[commandId]].name;
  return [
    "---",
    `description: ${spec.description}`,
    `agent: ${agentName}`,
    "---",
    "",
    `The operator invoked /${spec.command} with: \`$ARGUMENTS\` (optional target selector).`,
    `You are the read-only \`${agentName}\` agent. Treat \`$ARGUMENTS\` as the Hacker Bob`,
    "session selector and follow your agent contract. Do not mutate lifecycle,",
    "verification, grade, or report state.",
    "",
  ].join("\n");
}

function renderUpdateCommand(spec) {
  return [
    "---",
    `description: ${spec.description}`,
    // Bind to the built-in bash-capable `build` primary so the node/npx helper
    // below runs regardless of which (possibly bash:false) agent is active.
    "agent: build",
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
    // Bash-capable agent binding — see renderUpdateCommand.
    "agent: build",
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
    // Bash-capable agent binding — see renderUpdateCommand.
    "agent: build",
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
  const mcp = isPlainObject(base.mcp) ? { ...base.mcp } : {};
  // The hacker-bob key is Bob-owned and always re-asserted. The optional
  // brutalist key is (re)written when it is absent OR a Bob-managed entry from a
  // prior install — the latter so a pin/security bump to BRUTALIST_COMMAND
  // actually takes effect on reinstall instead of leaving stale external MCP
  // code wired. A genuinely operator-owned server that reuses the key is
  // preserved untouched.
  mcp["hacker-bob"] = bobMcpEntry(serverPath);
  const existingBrutalist = mcp.brutalist;
  if (!("brutalist" in mcp)) {
    mcp.brutalist = brutalistMcpEntry();
  } else if (isBobManagedBrutalistEntry(existingBrutalist)) {
    // Refresh a Bob-managed entry (possibly a stale pin) to the current
    // reviewed command, but carry over the operator's enabled/disabled toggle
    // rather than silently re-enabling a server they turned off.
    const refreshed = brutalistMcpEntry();
    if (typeof existingBrutalist.enabled === "boolean") {
      refreshed.enabled = existingBrutalist.enabled;
    }
    mcp.brutalist = refreshed;
  }
  base.mcp = mcp;
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
  // Codex/Kimi skills); the orchestrator dispatches them via the task tool
  // (subagent_type: "bob-<role>").
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
      if (isBobManagedBrutalistEntry(brutalistEntry)) {
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
  // lstat (not stat) so a symlinked config is detected instead of followed:
  // rewriting through a symlink would modify an arbitrary user-owned file
  // outside the install target. Install rejects symlinks via
  // createSafeInstallFs; uninstall must hold the same line.
  let stat;
  try {
    stat = fs.lstatSync(configPath);
  } catch {
    return;
  }
  if (stat.isSymbolicLink()) {
    result.skipped.push({ type: "config", path: CONFIG_FILE, reason: "refusing to follow symlinked config file" });
    return;
  }
  if (!stat.isFile()) return;
  let cfg;
  try {
    cfg = readJson(configPath);
  } catch (error) {
    result.skipped.push({ type: "config", path: CONFIG_FILE, reason: `invalid JSON: ${error.message || String(error)}` });
    return;
  }
  if (!isPlainObject(cfg) || !isPlainObject(cfg.mcp)) return;
  if (!("hacker-bob" in cfg.mcp) && !("brutalist" in cfg.mcp)) return;
  const nextMcp = { ...cfg.mcp };
  // The hacker-bob and brutalist keys are evaluated independently. A hacker-bob
  // entry the operator repointed away from this install is preserved (and the
  // skip recorded), but that must NOT block removal of a Bob-managed brutalist
  // entry sitting alongside it — otherwise uninstall would leave an external
  // npx-spawned MCP server wired after Bob is gone.
  if ("hacker-bob" in cfg.mcp) {
    if (bobEntryMatches(cfg.mcp["hacker-bob"], targetAbs)) {
      delete nextMcp["hacker-bob"];
    } else {
      result.skipped.push({ type: "config", path: CONFIG_FILE, reason: "hacker-bob MCP entry is not Bob-managed" });
    }
  }
  if (isBobManagedBrutalistEntry(nextMcp.brutalist)) {
    delete nextMcp.brutalist;
  }
  // Nothing Bob-owned was actually removed (e.g. a custom hacker-bob with no
  // Bob brutalist alongside it): leave the operator's file byte-for-byte
  // untouched rather than rewriting/reformatting it for a no-op.
  if (Object.keys(nextMcp).length === Object.keys(cfg.mcp).length) return;
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

// Walk the directory chain above a managed path. If any intermediate component
// is a symlink, removing the leaf through it would escape the install target —
// e.g. a symlinked `.opencode` or `.opencode/agents` pointing at a shared
// ~/.config/opencode/agents, where `fs.rmSync` would delete Bob-named files in
// the symlink TARGET. Install rejects symlinked parents via createSafeInstallFs;
// uninstall must hold the same line. We skip-and-continue (matching
// removeMcpConfig) rather than throwing, so one aliased path never aborts the
// rest of a legitimate uninstall.
function parentComponentsSafe(targetAbs, relativePath, result, type) {
  const parents = relativePath.split(path.sep).filter(Boolean).slice(0, -1);
  let current = targetAbs;
  for (const part of parents) {
    current = path.join(current, part);
    let stat;
    try {
      stat = fs.lstatSync(current);
    } catch {
      // Missing parent: the leaf cannot exist below it, nothing to remove.
      return true;
    }
    if (stat.isSymbolicLink()) {
      result.skipped.push({
        type,
        path: relativePath,
        reason: `refusing to follow symlinked parent directory ${path.relative(targetAbs, current)}`,
      });
      return false;
    }
    if (!stat.isDirectory()) return true;
  }
  return true;
}

function maybeRemoveFile(targetAbs, relativePath, result) {
  if (!parentComponentsSafe(targetAbs, relativePath, result, "file")) return;
  const filePath = path.join(targetAbs, relativePath);
  // lstat (not existsSync, which follows links) so a symlinked leaf is detected
  // rather than dereferenced — removing it would either delete an arbitrary
  // target or leave a dangling link, neither of which is a Bob-owned file.
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch {
    return;
  }
  if (stat.isSymbolicLink()) {
    result.skipped.push({ type: "file", path: relativePath, reason: "refusing to remove symlinked file" });
    return;
  }
  if (stat.isDirectory()) {
    result.skipped.push({ type: "file", path: relativePath, reason: "expected file but found directory" });
    return;
  }
  result.actions.push({ type: "remove_file", path: relativePath });
  if (!result.dry_run) fs.rmSync(filePath, { force: true });
}

function maybeRemoveEmptyDir(targetAbs, relativePath, result) {
  if (!parentComponentsSafe(targetAbs, relativePath, result, "dir")) return;
  const dirPath = path.join(targetAbs, relativePath);
  // lstat the leaf too: a symlinked managed dir (e.g. `.opencode` aliasing a
  // shared config dir) must not be swept through or rmdir'd.
  let stat;
  try {
    stat = fs.lstatSync(dirPath);
  } catch {
    return;
  }
  if (stat.isSymbolicLink()) {
    result.skipped.push({ type: "dir", path: relativePath, reason: "refusing to remove symlinked directory" });
    return;
  }
  if (!stat.isDirectory()) return;
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
  isBobManagedBrutalistEntry,
  managedDirs,
  managedFiles,
  mergeConfig,
  render,
  renderCommand,
  uninstall,
};
