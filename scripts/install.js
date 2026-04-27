"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const {
  mergeMcp,
  mergeSettings,
} = require("./merge-claude-config.js");
const {
  defaultClaudeSettings,
} = require("../mcp/lib/claude-config.js");

const HOOK_FILES = Object.freeze([
  "scope-guard.sh",
  "scope-guard-mcp.sh",
  "session-write-guard.sh",
  "bounty-statusline.js",
  "hunter-subagent-stop.js",
  "bob-update-lib.js",
  "bob-update.js",
  "bob-check-update.js",
  "bob-check-update-worker.js",
]);

const EXECUTABLE_HOOKS = Object.freeze([
  "scope-guard.sh",
  "scope-guard-mcp.sh",
  "session-write-guard.sh",
  "hunter-subagent-stop.js",
  "bob-update.js",
  "bob-check-update.js",
  "bob-check-update-worker.js",
]);

function readJsonIfExists(filePath, fallback) {
  if (!fs.existsSync(filePath)) return fallback;
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function copyFile(source, destination, mode) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination);
  if (mode != null) fs.chmodSync(destination, mode);
}

function copyDirFiles(sourceDir, destinationDir, predicate) {
  fs.mkdirSync(destinationDir, { recursive: true });
  const copied = [];
  for (const name of fs.readdirSync(sourceDir).sort()) {
    const source = path.join(sourceDir, name);
    if (!fs.statSync(source).isFile()) continue;
    if (predicate && !predicate(name)) continue;
    const destination = path.join(destinationDir, name);
    copyFile(source, destination);
    copied.push(name);
  }
  return copied;
}

function copyDirRecursive(sourceDir, destinationDir, predicate) {
  fs.mkdirSync(destinationDir, { recursive: true });
  const copied = [];
  for (const name of fs.readdirSync(sourceDir).sort()) {
    const source = path.join(sourceDir, name);
    const destination = path.join(destinationDir, name);
    const stat = fs.statSync(source);
    if (stat.isDirectory()) {
      if (name === "node_modules") continue;
      copied.push(...copyDirRecursive(source, destination, predicate));
      continue;
    }
    if (!stat.isFile()) continue;
    const relative = path.relative(sourceDir, source);
    if (predicate && !predicate(relative, name)) continue;
    copyFile(source, destination);
    copied.push(path.relative(destinationDir, destination));
  }
  return copied;
}

function removeIfExists(filePath) {
  fs.rmSync(filePath, { force: true });
}

function removeRecursiveIfExists(targetPath) {
  fs.rmSync(targetPath, { force: true, recursive: true });
}

function packageManifest(sourceRoot) {
  return readJsonIfExists(path.join(sourceRoot, "package.json"), {
    name: "hacker-bob-cc",
    version: "0.0.0",
  });
}

function sourceCommitSha(sourceRoot) {
  if (process.env.HACKER_BOB_COMMIT_SHA) return process.env.HACKER_BOB_COMMIT_SHA;
  if (!fs.existsSync(path.join(sourceRoot, ".git"))) return null;
  const result = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: sourceRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.status !== 0) return null;
  const sha = result.stdout.trim();
  return sha || null;
}

function commandExists(command) {
  const result = spawnSync("sh", ["-c", `command -v ${command}`], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  return result.status === 0;
}

function patchrightAvailable(targetAbs, sourceRoot) {
  try {
    require.resolve("patchright", { paths: [targetAbs, sourceRoot] });
    return true;
  } catch {
    return false;
  }
}

function installProject(projectDir, options = {}) {
  const sourceRoot = path.resolve(options.sourceRoot || path.join(__dirname, ".."));
  const targetAbs = path.resolve(projectDir || ".");
  const claudeDir = path.join(targetAbs, ".claude");
  const manifest = packageManifest(sourceRoot);

  if (!fs.existsSync(targetAbs) || !fs.statSync(targetAbs).isDirectory()) {
    throw new Error(`Install target does not exist or is not a directory: ${targetAbs}`);
  }

  fs.mkdirSync(claudeDir, { recursive: true });
  for (const dirname of ["agents", "commands", "rules", "hooks", "knowledge", "skills", "bob"]) {
    fs.mkdirSync(path.join(claudeDir, dirname), { recursive: true });
  }

  const agents = copyDirFiles(
    path.join(sourceRoot, ".claude", "agents"),
    path.join(claudeDir, "agents"),
    (name) => name.endsWith(".md"),
  );

  removeIfExists(path.join(claudeDir, "commands", "bountyagent.md"));
  removeIfExists(path.join(claudeDir, "commands", "bountyagentdebug.md"));
  removeIfExists(path.join(claudeDir, "commands", "bob", "hunt.md"));
  removeIfExists(path.join(claudeDir, "commands", "bob", "status.md"));
  removeIfExists(path.join(claudeDir, "commands", "bob", "debug.md"));
  removeIfExists(path.join(claudeDir, "commands", "bob", "update.md"));
  removeRecursiveIfExists(path.join(claudeDir, "commands", "bob"));
  removeRecursiveIfExists(path.join(claudeDir, "skills", "bountyagent"));
  removeRecursiveIfExists(path.join(claudeDir, "skills", "bountyagentstatus"));
  removeRecursiveIfExists(path.join(claudeDir, "skills", "bountyagentdebug"));
  for (const command of ["bob-update.md"]) {
    copyFile(
      path.join(sourceRoot, ".claude", "commands", command),
      path.join(claudeDir, "commands", command),
    );
  }

  for (const skill of ["bob-hunt", "bob-debug", "bob-status"]) {
    copyFile(
      path.join(sourceRoot, ".claude", "skills", skill, "SKILL.md"),
      path.join(claudeDir, "skills", skill, "SKILL.md"),
    );
  }

  const rules = copyDirFiles(
    path.join(sourceRoot, ".claude", "rules"),
    path.join(claudeDir, "rules"),
    (name) => name.endsWith(".md"),
  );

  const bypassSource = path.join(sourceRoot, ".claude", "bypass-tables");
  if (!fs.existsSync(bypassSource)) {
    throw new Error(".claude/bypass-tables/ is missing. HUNT phase requires these files.");
  }
  const bypassTables = copyDirFiles(
    bypassSource,
    path.join(claudeDir, "bypass-tables"),
    (name) => name.endsWith(".txt"),
  );
  if (bypassTables.length === 0) {
    throw new Error(".claude/bypass-tables/ is empty. HUNT phase requires these files.");
  }

  const knowledge = copyDirFiles(
    path.join(sourceRoot, ".claude", "knowledge"),
    path.join(claudeDir, "knowledge"),
    (name) => name.endsWith(".json"),
  );

  for (const hook of HOOK_FILES) {
    const mode = EXECUTABLE_HOOKS.includes(hook) ? 0o755 : undefined;
    copyFile(
      path.join(sourceRoot, ".claude", "hooks", hook),
      path.join(claudeDir, "hooks", hook),
      mode,
    );
  }

  const mcpDir = path.join(targetAbs, "mcp");
  fs.mkdirSync(path.join(mcpDir, "lib", "tools"), { recursive: true });
  for (const file of ["server.js", "auto-signup.js", "redaction.js"]) {
    copyFile(path.join(sourceRoot, "mcp", file), path.join(mcpDir, file));
  }
  fs.chmodSync(path.join(mcpDir, "server.js"), 0o755);
  copyDirFiles(path.join(sourceRoot, "mcp", "lib"), path.join(mcpDir, "lib"), (name) => name.endsWith(".js"));
  fs.rmSync(path.join(mcpDir, "lib", "tools"), { recursive: true, force: true });
  copyDirFiles(
    path.join(sourceRoot, "mcp", "lib", "tools"),
    path.join(mcpDir, "lib", "tools"),
    (name) => name.endsWith(".js"),
  );

  const policyReplay = copyDirRecursive(
    path.join(sourceRoot, "testing", "policy-replay"),
    path.join(targetAbs, "testing", "policy-replay"),
    (relative) =>
      /\.(?:mjs|md|json)$/.test(relative) &&
      !relative.split(path.sep).includes("node_modules"),
  );

  const mcpPath = path.join(targetAbs, ".mcp.json");
  const settingsPath = path.join(claudeDir, "settings.json");
  const serverPath = path.join(targetAbs, "mcp", "server.js");
  const bobSettings = defaultClaudeSettings();
  writeJson(mcpPath, mergeMcp(readJsonIfExists(mcpPath, {}), serverPath));
  writeJson(settingsPath, mergeSettings(readJsonIfExists(settingsPath, {}), bobSettings));

  fs.mkdirSync(path.join(os.homedir(), "bounty-agent-sessions"), { recursive: true });

  const installedAt = new Date().toISOString();
  fs.writeFileSync(path.join(claudeDir, "bob", "VERSION"), `${manifest.version}\n`, "utf8");
  writeJson(path.join(claudeDir, "bob", "install.json"), {
    schema_version: 1,
    bob_version: manifest.version,
    installed_at: installedAt,
    package_name: manifest.name || "hacker-bob-cc",
    install_target: targetAbs,
    installer_source: options.installerSource || process.env.HACKER_BOB_INSTALLER_SOURCE || "cli",
    commit_sha: sourceCommitSha(sourceRoot),
  });

  return {
    targetAbs,
    claudeDir,
    packageName: manifest.name || "hacker-bob-cc",
    version: manifest.version,
    agents: agents.length,
    rules: rules.length,
    bypassTables: bypassTables.length,
    knowledge: knowledge.length,
    policyReplay: policyReplay.length,
    patchrightAvailable: patchrightAvailable(targetAbs, sourceRoot),
  };
}

function printInstallSummary(summary) {
  console.log(`Installing Hacker Bob ${summary.version} into ${summary.claudeDir}/`);
  console.log("");
  console.log(`  ${summary.agents} agent definitions`);
  console.log("  command shim (/bob-update)");
  console.log("  bob-hunt + bob-status + bob-debug skills");
  console.log(`  ${summary.rules} rules`);
  console.log(`  ${summary.bypassTables} bypass tables`);
  console.log(`  ${summary.knowledge} hunter knowledge files`);
  console.log(`  ${summary.policyReplay} policy replay harness files`);
  console.log("  scope/session/update guard hooks + status line");
  console.log("  MCP runtime (mcp/server.js, auto-signup.js, redaction.js, lib/*.js, lib/tools/*.js)");
  console.log("  .mcp.json merged");
  console.log("  settings.json merged (permissions + hooks + statusLine)");
  console.log("  .claude/bob/VERSION and install.json");
  console.log("  ~/bounty-agent-sessions/");
  console.log("");
  console.log("Dependency check:");
  console.log("");
  for (const tool of ["node", "curl", "python3"]) {
    console.log(`  ${commandExists(tool) ? "OK" : "MISSING"}: ${tool}${commandExists(tool) ? "" : " (REQUIRED)"}`);
  }
  console.log("");
  console.log("Optional browser automation (auto-signup with CAPTCHA solving):");
  if (summary.patchrightAvailable) {
    console.log("  OK: patchright");
  } else {
    console.log("  MISSING: patchright (optional - enables Tier 2 auto-signup)");
    console.log(`    Install: cd ${summary.targetAbs} && npm init -y && npm install patchright && npx patchright install chromium`);
  }
  if (process.env.CAPSOLVER_API_KEY) {
    console.log("  OK: CAPSOLVER_API_KEY is set");
  } else {
    console.log("  NOT SET: CAPSOLVER_API_KEY (optional - enables CAPTCHA solving)");
    console.log("    Get a key at https://capsolver.com and export CAPSOLVER_API_KEY=...");
  }
  console.log("");
  console.log("Optional recon tools (hunting works without these, recon steps are skipped):");
  for (const tool of ["subfinder", "nuclei"]) {
    console.log(`  ${commandExists(tool) ? "OK" : "MISSING"}: ${tool}`);
  }
  console.log(`  ${commandExists("httpx") || fs.existsSync(path.join(os.homedir(), "go", "bin", "httpx")) ? "OK" : "MISSING"}: httpx`);
  console.log("");
  console.log("Install recon tools (optional):");
  console.log("  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest");
  console.log("  go install github.com/projectdiscovery/httpx/cmd/httpx@latest");
  console.log("  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest");
  console.log("");
  console.log(`Done. Restart Claude Code in ${summary.targetAbs}, then run: /bob-hunt target.com`);
}

module.exports = {
  EXECUTABLE_HOOKS,
  HOOK_FILES,
  commandExists,
  installProject,
  patchrightAvailable,
  printInstallSummary,
};
