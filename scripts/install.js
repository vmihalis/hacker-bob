"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const {
  ALL_ADAPTER_IDS,
  adapterIdsForSelection,
  getAdapter,
} = require("../adapters/index.js");

const BOB_RESOURCE_DIR = ".hacker-bob";
const NEUTRAL_INSTALL_SCHEMA_VERSION = 2;
const RESOURCE_SETS = Object.freeze([
  {
    name: "bypassTables",
    source: path.join(BOB_RESOURCE_DIR, "bypass-tables"),
    destination: path.join(BOB_RESOURCE_DIR, "bypass-tables"),
    predicate: (name) => name.endsWith(".txt"),
    missingMessage: ".hacker-bob/bypass-tables/ is missing. HUNT phase requires these files.",
    emptyMessage: ".hacker-bob/bypass-tables/ is empty. HUNT phase requires these files.",
  },
  {
    name: "knowledge",
    source: path.join(BOB_RESOURCE_DIR, "knowledge"),
    destination: path.join(BOB_RESOURCE_DIR, "knowledge"),
    predicate: (name) => name.endsWith(".json"),
    missingMessage: ".hacker-bob/knowledge/ is missing. HUNT phase requires these files.",
    emptyMessage: ".hacker-bob/knowledge/ is empty. HUNT phase requires these files.",
  },
]);

function normalizeAdapterIdList(ids) {
  const selected = new Set(adapterIdsForSelection(ids, { defaultIds: [] }));
  return ALL_ADAPTER_IDS.filter((id) => selected.has(id));
}

function neutralVersionPath(targetAbs) {
  return path.join(targetAbs, BOB_RESOURCE_DIR, "VERSION");
}

function neutralInstallMetadataPath(targetAbs) {
  return path.join(targetAbs, BOB_RESOURCE_DIR, "install.json");
}

function readJsonIfExists(filePath, fallback) {
  if (!fs.existsSync(filePath)) return fallback;
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function readNeutralInstallMetadata(targetAbs, fallback = null) {
  return readJsonIfExists(neutralInstallMetadataPath(targetAbs), fallback);
}

function detectInstalledAdapterIds(targetAbs) {
  const ids = [];
  if (
    fs.existsSync(path.join(targetAbs, ".claude", "bob", "VERSION")) ||
    fs.existsSync(path.join(targetAbs, ".claude", "commands", "bob-update.md")) ||
    fs.existsSync(path.join(targetAbs, ".claude", "commands", "bob", "hunt.md")) ||
    fs.existsSync(path.join(targetAbs, ".claude", "skills", "bob-hunt", "SKILL.md"))
  ) {
    ids.push("claude");
  }
  if (fs.existsSync(path.join(targetAbs, ".codex", "plugins", "hacker-bob"))) {
    ids.push("codex");
  }
  if (fs.existsSync(path.join(targetAbs, BOB_RESOURCE_DIR, "generic-mcp", "hacker-bob.md"))) {
    ids.push("generic-mcp");
  }
  return normalizeAdapterIdList(ids);
}

function installedAdapterIds(targetAbs) {
  let metadata = null;
  try {
    metadata = readNeutralInstallMetadata(targetAbs, null);
  } catch {
    metadata = null;
  }
  const metadataIds = Array.isArray(metadata && metadata.installed_adapters)
    ? metadata.installed_adapters
    : [];
  return normalizeAdapterIdList([
    ...metadataIds,
    ...detectInstalledAdapterIds(targetAbs),
  ]);
}

function writeNeutralInstallMetadata({
  targetAbs,
  manifest,
  installedAt,
  packageName,
  installerSource,
  commitSha,
  adapterIds,
}) {
  const installManifest = manifest || {};
  const version = installManifest.version || "0.0.0";
  const metadataPath = neutralInstallMetadataPath(targetAbs);
  const existing = readJsonIfExists(metadataPath, {});
  fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
  fs.writeFileSync(neutralVersionPath(targetAbs), `${version}\n`, "utf8");
  writeJson(metadataPath, {
    schema_version: NEUTRAL_INSTALL_SCHEMA_VERSION,
    bob_version: version,
    installed_at: existing.installed_at || installedAt || new Date().toISOString(),
    updated_at: installedAt || new Date().toISOString(),
    package_name: packageName || installManifest.name || "hacker-bob",
    install_target: targetAbs,
    installer_source: installerSource || "cli",
    commit_sha: commitSha || null,
    installed_adapters: normalizeAdapterIdList(adapterIds),
  });
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

function copyResourceSet(sourceRoot, targetAbs, resourceSet) {
  const sourceDir = path.join(sourceRoot, resourceSet.source);
  if (!fs.existsSync(sourceDir)) {
    throw new Error(resourceSet.missingMessage);
  }
  const copied = copyDirFiles(
    sourceDir,
    path.join(targetAbs, resourceSet.destination),
    resourceSet.predicate,
  );
  if (copied.length === 0) {
    throw new Error(resourceSet.emptyMessage);
  }
  return copied;
}

function sourceResourceNames(sourceRoot, resourceSet) {
  const sourceDir = path.join(sourceRoot, resourceSet.source);
  if (!fs.existsSync(sourceDir)) return [];
  return fs.readdirSync(sourceDir)
    .sort()
    .filter((name) => {
      const source = path.join(sourceDir, name);
      return fs.statSync(source).isFile() && (!resourceSet.predicate || resourceSet.predicate(name));
    });
}

function removeEmptyDirIfExists(dirPath) {
  if (!fs.existsSync(dirPath) || !fs.statSync(dirPath).isDirectory()) return;
  if (fs.readdirSync(dirPath).length === 0) fs.rmdirSync(dirPath);
}

function removeLegacyResourceCopies(sourceRoot, targetAbs) {
  let removed = 0;
  for (const resourceSet of RESOURCE_SETS) {
    const legacyDir = path.join(targetAbs, ".claude", path.basename(resourceSet.destination));
    for (const name of sourceResourceNames(sourceRoot, resourceSet)) {
      const legacyPath = path.join(legacyDir, name);
      if (fs.existsSync(legacyPath) && fs.statSync(legacyPath).isFile()) {
        fs.rmSync(legacyPath, { force: true });
        removed += 1;
      }
    }
    removeEmptyDirIfExists(legacyDir);
  }
  return removed;
}

function removeIfExists(filePath) {
  fs.rmSync(filePath, { force: true });
}

function packageManifest(sourceRoot) {
  return readJsonIfExists(path.join(sourceRoot, "package.json"), {
    name: "hacker-bob",
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
  const bobResourceDir = path.join(targetAbs, BOB_RESOURCE_DIR);
  const manifest = packageManifest(sourceRoot);
  const adapterIds = adapterIdsForSelection(options.adapter || options.adapters);
  const installerSource = options.installerSource || process.env.HACKER_BOB_INSTALLER_SOURCE || "cli";

  if (!fs.existsSync(targetAbs) || !fs.statSync(targetAbs).isDirectory()) {
    throw new Error(`Install target does not exist or is not a directory: ${targetAbs}`);
  }

  const existingAdapters = installedAdapterIds(targetAbs);
  fs.mkdirSync(bobResourceDir, { recursive: true });

  const copiedResources = {};
  for (const resourceSet of RESOURCE_SETS) {
    copiedResources[resourceSet.name] = copyResourceSet(sourceRoot, targetAbs, resourceSet);
  }
  const legacyResourcesRemoved = removeLegacyResourceCopies(sourceRoot, targetAbs);

  const mcpDir = path.join(targetAbs, "mcp");
  fs.mkdirSync(path.join(mcpDir, "lib", "tools"), { recursive: true });
  for (const file of ["server.js", "auto-signup.js", "redaction.js"]) {
    copyFile(path.join(sourceRoot, "mcp", file), path.join(mcpDir, file));
  }
  fs.chmodSync(path.join(mcpDir, "server.js"), 0o755);
  copyDirFiles(path.join(sourceRoot, "mcp", "lib"), path.join(mcpDir, "lib"), (name) => name.endsWith(".js"));
  const sourceToolsDir = path.join(sourceRoot, "mcp", "lib", "tools");
  const targetToolsDir = path.join(mcpDir, "lib", "tools");
  if (path.resolve(sourceToolsDir) !== path.resolve(targetToolsDir)) {
    fs.rmSync(targetToolsDir, { recursive: true, force: true });
    copyDirFiles(sourceToolsDir, targetToolsDir, (name) => name.endsWith(".js"));
  }

  const serverPath = path.join(targetAbs, "mcp", "server.js");
  const installedAt = new Date().toISOString();
  const packageName = manifest.name || "hacker-bob";
  const commitSha = sourceCommitSha(sourceRoot);
  const adapterResults = {};
  for (const adapterId of adapterIds) {
    const adapter = getAdapter(adapterId);
    if (adapterId === "claude") {
      adapterResults[adapterId] = adapter.install({
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
      });
    } else if (adapterId === "generic-mcp") {
      adapterResults[adapterId] = adapter.install({
        sourceRoot,
        targetAbs,
        readJsonIfExists,
        serverPath,
      });
    } else {
      adapterResults[adapterId] = adapter.install({
        activate: options.activateCodex !== false && process.env.HACKER_BOB_CODEX_AUTO_INSTALL !== "0",
        sourceRoot,
        targetAbs,
        serverPath,
      });
    }
  }

  const metadataAdapters = normalizeAdapterIdList([
    ...existingAdapters,
    ...adapterIds,
  ]);
  writeNeutralInstallMetadata({
    targetAbs,
    manifest,
    installedAt,
    packageName,
    installerSource,
    commitSha,
    adapterIds: metadataAdapters,
  });

  fs.mkdirSync(path.join(os.homedir(), "bounty-agent-sessions"), { recursive: true });

  return {
    adapters: adapterIds,
    installedAdapters: metadataAdapters,
    adapterResults,
    targetAbs,
    claudeDir: adapterResults.claude ? adapterResults.claude.claudeDir : null,
    bobResourceDir,
    packageName,
    version: manifest.version,
    agents: adapterResults.claude ? adapterResults.claude.agents : 0,
    rules: adapterResults.claude ? adapterResults.claude.rules : 0,
    codexSkills: adapterResults.codex ? adapterResults.codex.skills : 0,
    codexCommands: adapterResults.codex ? adapterResults.codex.commands : 0,
    codexActivation: adapterResults.codex ? adapterResults.codex.activation : null,
    genericPromptDocs: adapterResults["generic-mcp"] ? adapterResults["generic-mcp"].promptDocs : 0,
    bypassTables: copiedResources.bypassTables.length,
    knowledge: copiedResources.knowledge.length,
    legacyResourcesRemoved,
    patchrightAvailable: patchrightAvailable(targetAbs, sourceRoot),
  };
}

function printInstallSummary(summary) {
  console.log(`Installing Hacker Bob ${summary.version} into ${summary.targetAbs}/`);
  console.log("");
  console.log(`  host adapters: ${summary.adapters.join(", ")}`);
  if (summary.adapterResults.claude) {
    console.log(`  ${summary.agents} Claude agent definitions`);
    console.log("  Claude command shim (/bob-update)");
    console.log("  Claude bob-hunt + bob-status + bob-debug skills");
    console.log(`  ${summary.rules} Claude rules`);
    console.log("  Claude scope/session/update guard hooks + status line");
    console.log("  Claude .mcp.json and settings.json merged");
    console.log("  .claude/bob/VERSION and install.json compatibility metadata");
  }
  if (summary.adapterResults.codex) {
    console.log("  Codex plugin (.codex/plugins/hacker-bob) for MCP wiring");
    console.log(`  Codex skills ($bob-hunt, $bob-status, $bob-debug, $bob-update) in ~/.codex/skills`);
    console.log(`  Codex plugin command wrappers (${summary.codexCommands}) and .agents/plugins/marketplace.json`);
    if (summary.codexActivation && summary.codexActivation.ok) {
      console.log("  Codex plugin cache/config activated for MCP discovery");
    } else if (summary.codexActivation && summary.codexActivation.skipped) {
      console.log(`  Codex plugin activation skipped (${summary.codexActivation.reason})`);
    } else if (summary.codexActivation) {
      console.log(`  Codex plugin activation warning: ${summary.codexActivation.reason}`);
    }
  }
  if (summary.adapterResults["generic-mcp"]) {
    console.log(`  Generic MCP prompt docs (${summary.genericPromptDocs}) and .mcp.json merged`);
  }
  console.log(`  ${summary.bypassTables} neutral bypass tables`);
  console.log(`  ${summary.knowledge} neutral hunter knowledge files`);
  console.log("  MCP runtime (mcp/server.js, auto-signup.js, redaction.js, lib/*.js, lib/tools/*.js)");
  console.log("  .hacker-bob/ resources");
  console.log("  .hacker-bob/VERSION and install.json");
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
  if (summary.adapters.length === 1 && summary.adapters[0] === "claude") {
    console.log(`Done. Restart Claude Code in ${summary.targetAbs}, then run: /bob-hunt target.com`);
  } else if (summary.adapters.length === 1 && summary.adapters[0] === "codex") {
    console.log(`Done. Restart Codex in ${summary.targetAbs}, then run: $bob-hunt target.com`);
  } else if (summary.adapters.length === 1 && summary.adapters[0] === "generic-mcp") {
    console.log(`Done. Connect your MCP host to ${path.join(summary.targetAbs, "mcp", "server.js")} and read .hacker-bob/generic-mcp/hacker-bob.md.`);
  } else {
    console.log(`Done. Restart the selected host CLIs in ${summary.targetAbs} before continuing.`);
  }
}

module.exports = {
  BOB_RESOURCE_DIR,
  NEUTRAL_INSTALL_SCHEMA_VERSION,
  RESOURCE_SETS,
  commandExists,
  detectInstalledAdapterIds,
  installProject,
  installedAdapterIds,
  neutralInstallMetadataPath,
  neutralVersionPath,
  patchrightAvailable,
  printInstallSummary,
  readNeutralInstallMetadata,
  writeNeutralInstallMetadata,
};
