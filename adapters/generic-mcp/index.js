"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const id = "generic-mcp";
const PROMPT_SOURCE_DIR = path.join("adapters", "generic-mcp", "prompts");
const PROMPT_TARGET_DIR = path.join(".hacker-bob", "generic-mcp");
const PROMPT_FILES = Object.freeze([
  "hacker-bob.md",
]);

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
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

function render() {
  return false;
}

function managedFiles() {
  return [
    ...PROMPT_FILES.map((name) => path.join(PROMPT_TARGET_DIR, name)),
  ];
}

function managedDirs() {
  return [
    PROMPT_TARGET_DIR,
  ];
}

function copyPromptDocs(sourceRoot, targetAbs) {
  let copied = 0;
  for (const name of PROMPT_FILES) {
    const source = path.join(sourceRoot, PROMPT_SOURCE_DIR, name);
    const destination = path.join(targetAbs, PROMPT_TARGET_DIR, name);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(source, destination);
    copied += 1;
  }
  return copied;
}

function install({ sourceRoot, targetAbs, serverPath, readJsonIfExists }) {
  const mcpPath = path.join(targetAbs, ".mcp.json");
  const existing = readJsonIfExists ? readJsonIfExists(mcpPath, {}) : fileExists(mcpPath) ? readJson(mcpPath) : {};
  const next = {
    ...existing,
    mcpServers: {
      ...((existing && existing.mcpServers) || {}),
      ...mergeConfig({ serverPath }).mcpServers,
    },
  };
  writeJson(mcpPath, next);
  return {
    promptDocs: copyPromptDocs(sourceRoot, targetAbs),
    mcpPath,
  };
}

function addCheck(checks, status, checkId, message, detail) {
  const check = { id: checkId, status, message };
  if (detail !== undefined) check.detail = detail;
  checks.push(check);
  return check;
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

function doctor({ targetAbs }) {
  const checks = [];
  const expected = mergeConfig({ serverPath: path.join(targetAbs, "mcp", "server.js") });
  const mcpPath = path.join(targetAbs, ".mcp.json");
  if (!fileExists(mcpPath)) {
    addCheck(checks, "error", "generic_mcp_config", ".mcp.json is missing");
  } else {
    try {
      const mcp = readJson(mcpPath);
      if (JSON.stringify(mcp.mcpServers && mcp.mcpServers.bountyagent) === JSON.stringify(expected.mcpServers.bountyagent)) {
        addCheck(checks, "ok", "generic_mcp_config", ".mcp.json points bountyagent at this project's mcp/server.js");
      } else {
        addCheck(checks, "error", "generic_mcp_config", ".mcp.json is missing the Bob-managed bountyagent server entry");
      }
    } catch (error) {
      addCheck(checks, "error", "generic_mcp_config", ".mcp.json is not valid JSON", {
        error: error.message || String(error),
      });
    }
  }

  const serverPath = path.join(targetAbs, "mcp", "server.js");
  if (!fileExists(serverPath)) {
    addCheck(checks, "error", "generic_mcp_server", "mcp/server.js is missing");
  } else {
    const loaded = loadServerCheck(serverPath);
    if (loaded.status === 0) {
      addCheck(checks, "ok", "generic_mcp_server", "mcp/server.js loads and exposes MCP tools");
    } else {
      addCheck(checks, "error", "generic_mcp_server", "mcp/server.js failed to load", {
        exit_status: loaded.status,
        stderr: (loaded.stderr || "").trim(),
      });
    }
  }

  const missingDocs = PROMPT_FILES
    .map((name) => path.join(PROMPT_TARGET_DIR, name))
    .filter((relative) => !fileExists(path.join(targetAbs, relative)));
  if (missingDocs.length === 0) {
    addCheck(checks, "ok", "generic_mcp_prompt_docs", "Generic MCP prompt docs are installed");
  } else {
    addCheck(checks, "error", "generic_mcp_prompt_docs", "Generic MCP prompt docs are missing", { missing: missingDocs });
  }

  return {
    ok: checks.every((check) => check.status !== "error"),
    target: targetAbs,
    adapter: id,
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
  const expected = mergeConfig({ serverPath: path.join(targetAbs, "mcp", "server.js") });
  if (!mcp || !mcp.mcpServers || !mcp.mcpServers.bountyagent) return;
  if (JSON.stringify(mcp.mcpServers.bountyagent) !== JSON.stringify(expected.mcpServers.bountyagent)) {
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
  PROMPT_FILES,
  PROMPT_SOURCE_DIR,
  PROMPT_TARGET_DIR,
  doctor,
  id,
  install,
  managedDirs,
  managedFiles,
  mergeConfig,
  render,
  uninstall,
};
