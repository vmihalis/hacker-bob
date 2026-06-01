"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const config = require("./config.js");
const {
  updateKimiSkillFiles,
} = require("../../scripts/lib/kimi-role-renderer.js");
const { createSafeInstallFs } = require("../../scripts/lib/install-fs.js");

const id = "kimi";
const DEFAULT_ROOT = path.join(__dirname, "..", "..");

const BRUTALIST_MCP_SERVER = Object.freeze({
  command: "npx",
  args: ["-y", "@brutalist/mcp@latest"],
});

const { BOB_SKILLS, LEGACY_BOB_SKILLS } = config;

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
    path.join(".kimi", "bob"),
    path.join(".kimi"),
  ];
}

function mergeConfig({ serverPath }) {
  return {
    mcpServers: {
      bountyagent: {
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

  for (const skill of BOB_SKILLS) {
    const sourceSkillDir = path.join(sourceRoot, "adapters", "kimi", "skills", skill);
    const targetSkillDir = path.join(kimiDir, "skills", skill);
    if (fs.existsSync(sourceSkillDir)) {
      safeFs.copyDirFiles(sourceSkillDir, targetSkillDir, () => true);
    }
  }

  const mcpPath = path.join(targetAbs, ".kimi", "mcp.json");
  const existingMcp = safeFs.readJsonIfExists(mcpPath, {}, {
    kind: ".kimi/mcp.json",
    symlink: "reject",
  });
  const nextMcp = {
    ...existingMcp,
    mcpServers: {
      ...((existingMcp && existingMcp.mcpServers) || {}),
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

  return {
    kimiDir,
    skills: BOB_SKILLS.length,
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
      if (mcpServerMatches(mcp.mcpServers && mcp.mcpServers.bountyagent, targetAbs)) {
        addCheck(checks, "ok", "kimi_mcp_server_config", ".kimi/mcp.json points bountyagent at this project's mcp/server.js");
      } else {
        addCheck(checks, "error", "kimi_mcp_server_config", ".kimi/mcp.json is missing the Bob-managed bountyagent server entry");
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
  if (!isPlainObject(mcp) || !isPlainObject(mcp.mcpServers) || !("bountyagent" in mcp.mcpServers)) return;
  if (!mcpServerMatches(mcp.mcpServers.bountyagent, targetAbs)) {
    result.skipped.push({ type: "config", path: ".kimi/mcp.json", reason: "bountyagent server entry is not Bob-managed" });
    return;
  }
  const next = { ...mcp, mcpServers: { ...mcp.mcpServers } };
  delete next.mcpServers.bountyagent;
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
};
