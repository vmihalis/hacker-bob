"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const config = require("./config.js");
const {
  updateKimiSkillFiles,
} = require("../../scripts/lib/kimi-role-renderer.js");
const { createSafeInstallFs } = require("../../scripts/lib/install-fs.js");
const { BRUTALIST_MCP_SERVER } = require("../../scripts/merge-claude-config.js");

const id = "kimi";
const DEFAULT_ROOT = path.join(__dirname, "..", "..");

const { BOB_SKILLS, LEGACY_BOB_SKILLS } = config;

// Functional PreToolUse guards copied under <target>/.kimi/hooks/ and registered
// in ~/.kimi/config.toml. scope-guard.sh is a deliberate no-op and is treated as
// STALE (never registered), mirroring the Claude adapter.
const HOOK_FILES = Object.freeze([
  "session-read-guard.sh",
  "session-write-guard.sh",
]);

// All copied .sh guards are executable. Kept as its own list for parity with the
// Claude adapter's EXECUTABLE_HOOKS, even though here it equals HOOK_FILES.
const EXECUTABLE_HOOKS = Object.freeze([
  "session-read-guard.sh",
  "session-write-guard.sh",
]);

// Non-executable data the guards READ. write-guard-tables.json is the generated
// allow/deny manifest (rendered from mcp/lib/paths.js AUDIT_GRADED_PATHS). It must
// land beside the guards so $(dirname "$0")/write-guard-tables.json resolves. Kept
// separate from HOOK_FILES so it never enters EXECUTABLE_HOOKS / the chmod loop /
// the doctor executable-bit check. Mirrors the Claude HOOK_DATA_FILES.
const HOOK_DATA_FILES = Object.freeze([
  "write-guard-tables.json",
]);

// scope-guard.sh ships under adapters/kimi/hooks/ but is a no-op; sweep it from
// any prior hand-install so it cannot mislead. Mirrors STALE_HOOK_FILES on Claude.
const STALE_HOOK_FILES = Object.freeze([
  "scope-guard.sh",
]);

// Sentinel-fenced Bob block inside ~/.kimi/config.toml. The upsert/remove key.
// [[hooks]] is a TOML array-of-tables (identical headers), so a header-keyed
// upsert would corrupt operator hooks; the sentinel block is the safe boundary.
const KIMI_HOOK_BLOCK_BEGIN = "# >>> hacker-bob managed hooks (do not edit) >>>";
const KIMI_HOOK_BLOCK_END = "# <<< hacker-bob managed hooks <<<";
// Wide matcher regexes: Kimi's tool names are not pinned (docs show Shell/WriteFile;
// Claude emits Bash/Write/Read). Erring wide is fail-safer — a name Kimi never emits
// is harmless, a missed name is a silent fail-open.
const KIMI_WRITE_MATCHER = "Shell|Bash|Write|WriteFile|Edit|MultiEdit";
const KIMI_READ_MATCHER = "Shell|Bash|Read|ReadFile|Cat";

function kimiHome() {
  // KIMI_SHARE_DIR is Kimi CLI's documented override for the ~/.kimi data dir
  // (holds config.toml/sessions/logs). Honoring it gives parity with the live
  // CLI and lets install-smoke redirect the home write into a temp dir, exactly
  // as the Codex test redirects CODEX_HOME.
  return path.resolve(process.env.KIMI_SHARE_DIR || path.join(os.homedir(), ".kimi"));
}

function kimiConfigPath(home = kimiHome()) {
  return path.join(home, "config.toml");
}

function tomlString(value) {
  return `"${String(value).replace(/\\/g, "\\\\").replace(/"/g, "\\\"")}"`;
}

// POSIX single-quote escaping for a shell word. Kimi's hook `command` is run as
// a shell command (docs: it is the shell command to execute), so a bare
// double-quoted path lets $(...), backticks, and $VAR in the install path expand
// at hook runtime — installing Bob into a project whose path contains shell
// metacharacters would then persist arbitrary command execution. Single-quoting
// the path makes it an inert literal; an embedded single quote becomes '\''.
function shellSingleQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function renderKimiHookBlock(targetAbs) {
  // shellSingleQuote the path (shell safety), then tomlString the whole command
  // (TOML string correctness). The two layers compose: TOML decodes to
  // `bash '<path>'`, and the shell then treats <path> as a literal.
  const writeCmd = `bash ${shellSingleQuote(path.join(targetAbs, ".kimi", "hooks", "session-write-guard.sh"))}`;
  const readCmd = `bash ${shellSingleQuote(path.join(targetAbs, ".kimi", "hooks", "session-read-guard.sh"))}`;
  return [
    KIMI_HOOK_BLOCK_BEGIN,
    "[[hooks]]",
    'event = "PreToolUse"',
    `matcher = ${tomlString(KIMI_WRITE_MATCHER)}`,
    `command = ${tomlString(writeCmd)}`,
    "timeout = 5",
    "",
    "[[hooks]]",
    'event = "PreToolUse"',
    `matcher = ${tomlString(KIMI_READ_MATCHER)}`,
    `command = ${tomlString(readCmd)}`,
    "timeout = 5",
    KIMI_HOOK_BLOCK_END,
  ].join("\n");
}

// Idempotent merge-not-clobber: replace the sentinel block in place, or append it.
function upsertKimiHookBlock(text, targetAbs) {
  const block = renderKimiHookBlock(targetAbs);
  const normalized = (text || "").replace(/\r\n/g, "\n");
  const begin = normalized.indexOf(KIMI_HOOK_BLOCK_BEGIN);
  if (begin === -1) {
    const base = normalized.replace(/\n*$/g, "");
    const sep = base === "" ? "" : "\n\n";
    return `${base}${sep}${block}\n`;
  }
  const endMarker = normalized.indexOf(KIMI_HOOK_BLOCK_END, begin);
  const end = endMarker === -1 ? normalized.length : endMarker + KIMI_HOOK_BLOCK_END.length;
  return `${normalized.slice(0, begin)}${block}${normalized.slice(end)}`.replace(/\n*$/g, "") + "\n";
}

function removeKimiHookBlock(text) {
  const normalized = (text || "").replace(/\r\n/g, "\n");
  const begin = normalized.indexOf(KIMI_HOOK_BLOCK_BEGIN);
  if (begin === -1) return text;
  const endMarker = normalized.indexOf(KIMI_HOOK_BLOCK_END, begin);
  const end = endMarker === -1 ? normalized.length : endMarker + KIMI_HOOK_BLOCK_END.length;
  // Also swallow a single leading blank-line separator if present.
  let cut = begin;
  if (cut >= 1 && normalized[cut - 1] === "\n" && (cut < 2 || normalized[cut - 2] === "\n")) cut -= 1;
  const result = `${normalized.slice(0, cut)}${normalized.slice(end)}`.replace(/\n*$/g, "");
  return result === "" ? "" : `${result}\n`;
}

function hasKimiHookBlock(text) {
  return typeof text === "string" && text.includes(KIMI_HOOK_BLOCK_BEGIN);
}

// True only when the sentinel block references THIS project's guard paths. The
// global ~/.kimi/config.toml holds a single Bob block; when Bob is installed
// into project A then B, the block points at B. Uninstalling A must not remove
// B's block (that would silently disable B's guards). Match the write-guard
// path inside the block, not anywhere in the file.
function kimiHookBlockMatchesTarget(text, targetAbs) {
  const normalized = (text || "").replace(/\r\n/g, "\n");
  const begin = normalized.indexOf(KIMI_HOOK_BLOCK_BEGIN);
  if (begin === -1) return false;
  const endMarker = normalized.indexOf(KIMI_HOOK_BLOCK_END, begin);
  const end = endMarker === -1 ? normalized.length : endMarker + KIMI_HOOK_BLOCK_END.length;
  const block = normalized.slice(begin, end);
  const writePath = path.join(targetAbs, ".kimi", "hooks", "session-write-guard.sh");
  return block.includes(writePath);
}

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
    ...BOB_SKILLS.map((skill) => path.join(".kimi", "skills", skill, "SKILL.md")),
    ...LEGACY_BOB_SKILLS.map((skill) => path.join(".kimi", "skills", skill, "SKILL.md")),
    ...HOOK_FILES.map((name) => path.join(".kimi", "hooks", name)),
    ...HOOK_DATA_FILES.map((name) => path.join(".kimi", "hooks", name)),
    ...STALE_HOOK_FILES.map((name) => path.join(".kimi", "hooks", name)),
    path.join(".kimi", "bob", "VERSION"),
    path.join(".kimi", "bob", "install.json"),
    path.join(".kimi", "mcp.json"),
  ];
}

function managedDirs() {
  const skillDirs = [...BOB_SKILLS, ...LEGACY_BOB_SKILLS]
    .map((skill) => path.join(".kimi", "skills", skill));
  return [
    ...skillDirs,
    path.join(".kimi", "skills"),
    path.join(".kimi", "hooks"),
    path.join(".kimi", "bob"),
    path.join(".kimi"),
  ];
}

function mergeConfig({ serverPath }) {
  return {
    mcpServers: {
      // Canonical v2.0 server key. v1.x installs used the legacy `bountyagent`
      // key; install() migrates a Bob-managed legacy entry to this key and
      // uninstall() removes either (CHANGELOG v2.0 + docs/TROUBLESHOOTING.md).
      "hacker-bob": {
        command: "node",
        args: [serverPath],
      },
      brutalist: { ...BRUTALIST_MCP_SERVER, args: [...BRUTALIST_MCP_SERVER.args] },
    },
  };
}

function render(options = {}) {
  return updateKimiSkillFiles(options);
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
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
  const kimiDir = path.join(targetAbs, ".kimi");
  safeFs.mkdirp(kimiDir);
  for (const dirname of ["skills", "bob"]) {
    safeFs.mkdirp(path.join(kimiDir, dirname));
  }

  // Sweep stale skill dirs left by prior installs (bob-hunt v1,
  // bob-evaluate-runner interim misname) before copying current skills, so a
  // normal install/update never leaves old prompts/tool names beside the
  // current bob-evaluate skill. Mirrors the Codex removeLegacyDirectSkillDirs
  // sweep and Claude's legacy-skill rmSync loop; uninstall and dev-sync already
  // remove these. Idempotent: a no-op when the legacy dirs are absent.
  for (const legacySkill of LEGACY_BOB_SKILLS) {
    safeFs.removePath(path.join(kimiDir, "skills", legacySkill), { recursive: true });
  }

  for (const skill of BOB_SKILLS) {
    const sourceSkillDir = path.join(sourceRoot, "adapters", "kimi", "skills", skill);
    const targetSkillDir = path.join(kimiDir, "skills", skill);
    if (fs.existsSync(sourceSkillDir)) {
      safeFs.copyDirFiles(sourceSkillDir, targetSkillDir, () => true);
    }
  }

  // Sweep no-op/stale hooks from prior hand-installs so they cannot mislead.
  for (const stale of STALE_HOOK_FILES) {
    safeFs.removePath(path.join(kimiDir, "hooks", stale));
  }
  safeFs.mkdirp(path.join(kimiDir, "hooks"));
  for (const hook of HOOK_FILES) {
    const source = path.join(sourceRoot, "adapters", "kimi", "hooks", hook);
    const dest = path.join(kimiDir, "hooks", hook);
    if (fs.existsSync(source)) {
      // Executable bit, mirroring the Claude EXECUTABLE_HOOKS chmod.
      safeFs.copyFile(source, dest, 0o755);
    }
  }
  // Non-executable manifest the write-guard reads via $(dirname "$0")/<name>.
  // Source is the generated artifact emitted under .claude/hooks/ in the tree.
  for (const dataFile of HOOK_DATA_FILES) {
    const source = path.join(sourceRoot, ".claude", "hooks", dataFile);
    const dest = path.join(kimiDir, "hooks", dataFile);
    if (fs.existsSync(source)) {
      safeFs.copyFile(source, dest);
    }
  }

  const mcpPath = path.join(targetAbs, ".kimi", "mcp.json");
  const existingMcp = safeFs.readJsonIfExists(mcpPath, {}, {
    kind: ".kimi/mcp.json",
    symlink: "reject",
  });
  const existingServers = { ...((existingMcp && existingMcp.mcpServers) || {}) };
  // Migrate the legacy v1.x `bountyagent` server key to the canonical
  // `hacker-bob` key when it is Bob-managed, so reinstalls/updates do not leave
  // a duplicate server entry behind (CHANGELOG v2.0 + docs/TROUBLESHOOTING.md).
  if (existingServers.bountyagent && mcpServerMatches(existingServers.bountyagent, targetAbs)) {
    delete existingServers.bountyagent;
  }
  const nextMcp = {
    ...existingMcp,
    mcpServers: {
      ...existingServers,
      ...mergeConfig({ serverPath }).mcpServers,
    },
  };
  safeFs.writeJson(mcpPath, nextMcp, {
    kind: ".kimi/mcp.json",
    rejectExistingSymlink: true,
  });

  const installManifest = manifest || {};
  safeFs.writeTextFile(path.join(kimiDir, "bob", "VERSION"), `${installManifest.version || "0.0.0"}\n`, {
    kind: ".kimi/bob/VERSION",
  });
  safeFs.writeJson(path.join(kimiDir, "bob", "install.json"), {
    schema_version: 1,
    bob_version: installManifest.version || "0.0.0",
    installed_at: installedAt || new Date().toISOString(),
    package_name: packageName || installManifest.name || "hacker-bob",
    install_target: targetAbs,
    installer_source: installerSource || "cli",
    commit_sha: commitSha || null,
  });

  // Register PreToolUse guards in ~/.kimi/config.toml (KIMI_SHARE_DIR-aware).
  // Best-effort: never throw out of install() — a missing/locked home config
  // must not fail the whole install (mirrors Codex maybeActivateCodexPlugin's
  // try/catch). The [[hooks]] array-of-tables is merged via the sentinel block,
  // so operator hooks and other sections are preserved.
  let hookRegistration = { ok: false, skipped: true, reason: "not attempted" };
  try {
    const home = kimiHome();
    const homeFs = createSafeInstallFs(home, { label: "KIMI_SHARE_DIR", createRoot: true });
    const configPath = kimiConfigPath(home);
    const existing = homeFs.readTextIfExists(configPath, "", {
      kind: "Kimi config",
      symlink: "reject",
    });
    const next = upsertKimiHookBlock(existing, targetAbs);
    homeFs.writeTextFile(configPath, next, {
      kind: "Kimi config",
      rejectExistingSymlink: true,
    });
    hookRegistration = { ok: true, configPath };
  } catch (error) {
    hookRegistration = {
      ok: false,
      skipped: false,
      reason: error && error.message ? error.message : String(error),
    };
  }

  return {
    kimiDir,
    skills: BOB_SKILLS.length,
    hooks: HOOK_FILES.length,
    hookRegistration,
  };
}

function addCheck(checks, status, checkId, message, detail) {
  const check = { id: checkId, status, message };
  if (detail !== undefined) check.detail = detail;
  checks.push(check);
  return check;
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

function doctor({ targetAbs }) {
  const checks = [];
  const kimiDir = path.join(targetAbs, ".kimi");

  const versionPath = path.join(kimiDir, "bob", "VERSION");
  let installedVersion = null;
  if (fileExists(versionPath)) {
    installedVersion = fs.readFileSync(versionPath, "utf8").trim();
    if (installedVersion) {
      addCheck(checks, "ok", "kimi_installed_version", `Installed Bob version is ${installedVersion}`, {
        installed_version: installedVersion,
      });
    } else {
      addCheck(checks, "error", "kimi_installed_version", ".kimi/bob/VERSION is empty");
    }
  } else {
    addCheck(checks, "error", "kimi_installed_version", ".kimi/bob/VERSION is missing");
  }

  const installMetaPath = path.join(kimiDir, "bob", "install.json");
  if (fileExists(installMetaPath)) {
    try {
      const installMeta = readJson(installMetaPath);
      const metadataErrors = [];
      if (installMeta.schema_version !== 1) metadataErrors.push("schema_version must be 1");
      if (!installMeta.bob_version) metadataErrors.push("bob_version is missing");
      if (installedVersion && installMeta.bob_version !== installedVersion) {
        metadataErrors.push("bob_version does not match VERSION");
      }
      if (installMeta.install_target !== targetAbs) metadataErrors.push("install_target does not match this project");
      if (!installMeta.package_name) metadataErrors.push("package_name is missing");
      if (metadataErrors.length === 0) {
        addCheck(checks, "ok", "kimi_install_metadata", "Install metadata matches this project");
      } else {
        addCheck(checks, "error", "kimi_install_metadata", "Install metadata is incomplete or mismatched", {
          errors: metadataErrors,
        });
      }
    } catch (error) {
      addCheck(checks, "error", "kimi_install_metadata_json", ".kimi/bob/install.json is not valid JSON", {
        error: error.message || String(error),
      });
    }
  } else {
    addCheck(checks, "error", "kimi_install_metadata_json", ".kimi/bob/install.json is missing");
  }

  const missingSkills = BOB_SKILLS
    .map((name) => path.join(".kimi", "skills", name, "SKILL.md"))
    .filter((relative) => !fileExists(path.join(targetAbs, relative)));
  if (missingSkills.length === 0) {
    addCheck(checks, "ok", "kimi_skills", "Bob skills are installed");
  } else {
    addCheck(checks, "error", "kimi_skills", "Bob skills are missing", {
      missing: missingSkills,
    });
  }

  const mcpPath = path.join(kimiDir, "mcp.json");
  if (fileExists(mcpPath)) {
    try {
      const mcp = readJson(mcpPath);
      if (mcpServerMatches(mcp.mcpServers && mcp.mcpServers["hacker-bob"], targetAbs)) {
        addCheck(checks, "ok", "kimi_mcp_server_config", ".kimi/mcp.json points hacker-bob at this project's mcp/server.js");
      } else {
        addCheck(checks, "error", "kimi_mcp_server_config", ".kimi/mcp.json is missing the Bob-managed hacker-bob server entry");
      }
      const brutalistEntry = mcp.mcpServers && mcp.mcpServers.brutalist;
      if (brutalistEntry && brutalistEntry.command === BRUTALIST_MCP_SERVER.command) {
        addCheck(checks, "ok", "kimi_mcp_brutalist_optional", ".kimi/mcp.json registers the optional @brutalist/mcp server");
      } else {
        addCheck(checks, "info", "kimi_mcp_brutalist_optional", ".kimi/mcp.json does not register @brutalist/mcp — brutalist verifier will fall back gracefully");
      }
    } catch (error) {
      addCheck(checks, "error", "kimi_mcp_json", ".kimi/mcp.json is not valid JSON", {
        error: error.message || String(error),
      });
    }
  } else {
    addCheck(checks, "error", "kimi_mcp_json", ".kimi/mcp.json is missing");
  }

  // Hook files present + executable.
  const missingHooks = HOOK_FILES
    .map((name) => path.join(".kimi", "hooks", name))
    .filter((relative) => !fileExists(path.join(targetAbs, relative)));
  if (missingHooks.length === 0) {
    addCheck(checks, "ok", "kimi_hook_files", "Bob PreToolUse guard scripts are installed");
  } else {
    addCheck(checks, "error", "kimi_hook_files", "Bob PreToolUse guard scripts are missing", { missing: missingHooks });
  }

  const nonExecHooks = EXECUTABLE_HOOKS
    .map((name) => path.join(kimiDir, "hooks", name))
    .filter((p) => fileExists(p) && (fs.statSync(p).mode & 0o111) === 0);
  if (nonExecHooks.length === 0) {
    addCheck(checks, "ok", "kimi_hook_modes", "Bob guard scripts have executable mode");
  } else {
    addCheck(checks, "error", "kimi_hook_modes", "Some Bob guard scripts are not executable", { files: nonExecHooks });
  }

  // T3 manifest present beside the guards.
  const missingData = HOOK_DATA_FILES
    .map((name) => path.join(".kimi", "hooks", name))
    .filter((relative) => !fileExists(path.join(targetAbs, relative)));
  if (missingData.length === 0) {
    addCheck(checks, "ok", "kimi_hook_manifest", "write-guard-tables.json is installed beside the guards");
  } else {
    addCheck(checks, "warn", "kimi_hook_manifest",
      "write-guard-tables.json is missing; guards fall back to fail-closed default-block tables", { missing: missingData });
  }

  // config.toml registration present and points at THIS project's guards.
  const configPath = kimiConfigPath();
  const configText = fileExists(configPath) ? fs.readFileSync(configPath, "utf8") : "";
  const expectWrite = path.join(targetAbs, ".kimi", "hooks", "session-write-guard.sh");
  const expectRead = path.join(targetAbs, ".kimi", "hooks", "session-read-guard.sh");
  if (configText.includes(KIMI_HOOK_BLOCK_BEGIN)
      && configText.includes(expectWrite) && configText.includes(expectRead)) {
    addCheck(checks, "ok", "kimi_hook_registration",
      "~/.kimi/config.toml registers Bob PreToolUse guards for this project", { configPath });
  } else if (configText.includes(KIMI_HOOK_BLOCK_BEGIN)) {
    addCheck(checks, "warn", "kimi_hook_registration",
      "~/.kimi/config.toml has a Bob hook block, but it points at a different project (a different Bob install owns the shared global config)", { configPath });
  } else {
    addCheck(checks, "error", "kimi_hook_registration",
      "~/.kimi/config.toml does not register Bob PreToolUse guards", { configPath });
  }

  // MANDATORY best-effort caveat — surfaced regardless of the above, because the
  // Kimi tool-name strings and stdin payload shape are not pinned to the
  // installed Kimi CLI version. This is a warn (never fails doctor) but is always
  // visible: T9 wires registration faithfully but does NOT assert runtime Y-P13
  // enforcement on Kimi.
  addCheck(checks, "warn", "kimi_hook_best_effort",
    "Kimi hook registration is best-effort: the matcher tool-names and PreToolUse payload shape are not pinned to your Kimi CLI version. Verify a guard actually fires (e.g. attempt a blocked write) before relying on Y-P13 enforcement on Kimi.");

  const kimiOnPath = spawnSync("sh", ["-c", "command -v kimi"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (kimiOnPath.status === 0) {
    addCheck(checks, "ok", "kimi_cli_on_path", "kimi is available on PATH");
  } else {
    addCheck(checks, "warn", "kimi_cli_on_path", "kimi is not on PATH; install Kimi CLI before using Bob skills");
  }

  return {
    ok: checks.every((check) => check.status !== "error"),
    target: targetAbs,
    adapter: id,
    checks,
  };
}

function removeMcpConfig(targetAbs, result) {
  const mcpPath = path.join(targetAbs, ".kimi", "mcp.json");
  if (!fileExists(mcpPath)) return;
  let mcp;
  try {
    mcp = readJson(mcpPath);
  } catch (error) {
    result.skipped.push({ type: "config", path: ".kimi/mcp.json", reason: `invalid JSON: ${error.message || String(error)}` });
    return;
  }
  if (!isPlainObject(mcp) || !isPlainObject(mcp.mcpServers)) return;
  // Remove the canonical `hacker-bob` key and the legacy v1.x `bountyagent`
  // key (whichever is Bob-managed), mirroring the generic-mcp uninstall path.
  const candidates = ["hacker-bob", "bountyagent"].filter((key) => key in mcp.mcpServers);
  if (candidates.length === 0) return;
  const mismatched = candidates.filter((key) => !mcpServerMatches(mcp.mcpServers[key], targetAbs));
  if (mismatched.length === candidates.length) {
    result.skipped.push({ type: "config", path: ".kimi/mcp.json", reason: `${mismatched.join(", ")} server entry is not Bob-managed` });
    return;
  }
  const next = { ...mcp, mcpServers: { ...mcp.mcpServers } };
  for (const key of candidates) {
    if (mcpServerMatches(mcp.mcpServers[key], targetAbs)) delete next.mcpServers[key];
  }
  if (
    next.mcpServers.brutalist
    && next.mcpServers.brutalist.command === BRUTALIST_MCP_SERVER.command
  ) {
    delete next.mcpServers.brutalist;
  }
  if (Object.keys(next.mcpServers).length === 0) delete next.mcpServers;
  result.actions.push({ type: Object.keys(next).length === 0 ? "remove_config_file" : "update_config", path: ".kimi/mcp.json" });
  if (result.dry_run) return;
  if (Object.keys(next).length === 0) {
    fs.rmSync(mcpPath, { force: true });
  } else {
    writeJson(mcpPath, next);
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

function removeKimiHookRegistration(targetAbs, result) {
  const home = kimiHome();
  const configPath = kimiConfigPath(home);
  if (!fileExists(configPath)) return;
  // Refuse to follow a symlinked config: rewriting it would clobber the link
  // target (e.g. a dotfile-managed Kimi config) outside Bob-owned files. Install
  // already rejects symlinked configs via createSafeInstallFs; mirror that here.
  let lst;
  try {
    lst = fs.lstatSync(configPath);
  } catch {
    return;
  }
  if (lst.isSymbolicLink()) {
    result.skipped.push({ type: "config", path: configPath, reason: "refusing to rewrite a symlinked Kimi config" });
    return;
  }
  let original;
  try {
    original = fs.readFileSync(configPath, "utf8");
  } catch (error) {
    result.skipped.push({ type: "config", path: configPath, reason: `unreadable: ${error.message || String(error)}` });
    return;
  }
  if (!hasKimiHookBlock(original)) return; // not Bob-managed / already gone
  // Only remove the block when it belongs to THIS install. A block pointing at a
  // different project means another Bob install owns the shared global config;
  // removing it would disable that install's guards.
  if (!kimiHookBlockMatchesTarget(original, targetAbs)) {
    result.skipped.push({ type: "config", path: configPath, reason: "Kimi hook block belongs to a different project install" });
    return;
  }
  const next = removeKimiHookBlock(original);
  if (next === original) return;
  const removeFile = next.trim() === "";
  result.actions.push({ type: removeFile ? "remove_kimi_config" : "update_kimi_config", path: configPath });
  if (result.dry_run) return;
  if (removeFile) fs.rmSync(configPath, { force: true });
  else fs.writeFileSync(configPath, next, "utf8");
}

function uninstall({ sourceRoot, targetAbs, dryRun = true, preserveMcpConfig = false }) {
  const result = {
    ok: true,
    dry_run: dryRun,
    target: targetAbs,
    adapter: id,
    actions: [],
    skipped: [],
  };
  if (!preserveMcpConfig) removeMcpConfig(targetAbs, result);
  removeKimiHookRegistration(targetAbs, result);
  for (const relativePath of managedFiles(sourceRoot)) {
    maybeRemoveFile(targetAbs, relativePath, result);
  }
  for (const relativePath of managedDirs()) {
    maybeRemoveEmptyDir(targetAbs, relativePath, result);
  }
  return result;
}

module.exports = {
  id,
  install,
  doctor,
  uninstall,
  render,
  managedFiles,
  managedDirs,
  mergeConfig,
  kimiHome,
  kimiConfigPath,
  upsertKimiHookBlock,
  removeKimiHookBlock,
  renderKimiHookBlock,
  shellSingleQuote,
  kimiHookBlockMatchesTarget,
  HOOK_FILES,
  HOOK_DATA_FILES,
  EXECUTABLE_HOOKS,
  STALE_HOOK_FILES,
};
