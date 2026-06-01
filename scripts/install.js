"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const {
  ALL_ADAPTER_IDS,
  adapterIdsForSelection,
  detectAdapterId,
  getAdapter,
} = require("../adapters/index.js");
const { clearUpdateCache } = require("../mcp/lib/update-check.js");
const { createSafeInstallFs } = require("./lib/install-fs.js");

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

function readNeutralInstallMetadata(targetAbs, fallback = null, installFs = null) {
  const safeFs = installFs || createSafeInstallFs(targetAbs, { label: "install target" });
  return safeFs.readJsonIfExists(neutralInstallMetadataPath(targetAbs), fallback, {
    kind: ".hacker-bob/install.json",
    symlink: "missing",
  });
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
  if (
    fs.existsSync(path.join(targetAbs, ".kimi", "bob", "VERSION")) ||
    fs.existsSync(path.join(targetAbs, ".kimi", "skills", "bob-hunt", "SKILL.md"))
  ) {
    ids.push("kimi");
  }
  if (fs.existsSync(path.join(targetAbs, BOB_RESOURCE_DIR, "generic-mcp", "hacker-bob.md"))) {
    ids.push("generic-mcp");
  }
  return normalizeAdapterIdList(ids);
}

function installedAdapterIds(targetAbs, installFs = null) {
  let metadata = null;
  try {
    metadata = readNeutralInstallMetadata(targetAbs, null, installFs);
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
  installFs,
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
  const safeFs = installFs || createSafeInstallFs(targetAbs, { label: "install target" });
  const existing = safeFs.readJsonIfExists(metadataPath, {}, {
    kind: ".hacker-bob/install.json",
    symlink: "missing",
  });
  safeFs.writeTextFile(neutralVersionPath(targetAbs), `${version}\n`, {
    kind: ".hacker-bob/VERSION",
  });
  safeFs.writeJson(metadataPath, {
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

function copyFile(installFs, source, destination, mode) {
  installFs.copyFile(source, destination, mode);
}

function copyDirRecursive(installFs, sourceDir, destinationDir, predicate) {
  return installFs.copyDirRecursive(sourceDir, destinationDir, predicate);
}

function copyDirFiles(installFs, sourceDir, destinationDir, predicate) {
  return installFs.copyDirFiles(sourceDir, destinationDir, predicate);
}

function copyResourceSet(installFs, sourceRoot, targetAbs, resourceSet) {
  const sourceDir = path.join(sourceRoot, resourceSet.source);
  if (!fs.existsSync(sourceDir)) {
    throw new Error(resourceSet.missingMessage);
  }
  const copied = copyDirFiles(
    installFs,
    sourceDir,
    path.join(targetAbs, resourceSet.destination),
    resourceSet.predicate,
  );
  if (copied.length === 0) {
    throw new Error(resourceSet.emptyMessage);
  }
  return copied;
}

function copyRuntimeNodeDependencies(installFs, sourceRoot, mcpDir) {
  const manifest = packageManifest(sourceRoot);
  const copied = [];
  const queued = [];
  for (const name of Object.keys(manifest.dependencies || {}).sort()) {
    queued.push({ name, optional: false });
  }
  for (const name of Object.keys(manifest.optionalDependencies || {}).sort()) {
    queued.push({ name, optional: true });
  }
  const visited = new Set();
  const targetNodeModules = path.join(mcpDir, "node_modules");
  while (queued.length > 0) {
    const { name: packageName, optional } = queued.shift();
    if (!packageName || visited.has(packageName)) continue;
    const sourceDir = path.join(sourceRoot, "node_modules", ...packageName.split("/"));
    if (!fs.existsSync(sourceDir) || !fs.statSync(sourceDir).isDirectory()) {
      if (optional) continue;
      throw new Error(`Runtime dependency ${packageName} is missing; run npm install before installing Bob into a project`);
    }
    visited.add(packageName);
    const dependencyManifest = JSON.parse(fs.readFileSync(path.join(sourceDir, "package.json"), "utf8"));
    for (const dependencyName of Object.keys(dependencyManifest.dependencies || {}).sort()) {
      if (!visited.has(dependencyName)) queued.push({ name: dependencyName, optional });
    }
    for (const dependencyName of Object.keys(dependencyManifest.optionalDependencies || {}).sort()) {
      if (!visited.has(dependencyName)) queued.push({ name: dependencyName, optional: true });
    }
    const destinationDir = path.join(targetNodeModules, packageName);
    if (path.resolve(sourceDir) === path.resolve(destinationDir)) continue;
    installFs.removePath(destinationDir, { recursive: true });
    copied.push(...copyDirRecursive(installFs, sourceDir, destinationDir).map((file) => path.join(packageName, file)));
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

function removeEmptyDirIfExists(installFs, dirPath) {
  installFs.removeEmptyDirIfExists(dirPath);
}

function removeLegacyResourceCopies(installFs, sourceRoot, targetAbs) {
  let removed = 0;
  for (const resourceSet of RESOURCE_SETS) {
    const legacyDir = path.join(targetAbs, ".claude", path.basename(resourceSet.destination));
    for (const name of sourceResourceNames(sourceRoot, resourceSet)) {
      const legacyPath = path.join(legacyDir, name);
      if (installFs.fileExists(legacyPath)) {
        installFs.removePath(legacyPath);
        removed += 1;
      }
    }
    removeEmptyDirIfExists(installFs, legacyDir);
  }
  return removed;
}

function removeIfExists(installFs, filePath) {
  installFs.removePath(filePath);
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

function commandOrGoBinExists(command) {
  return commandExists(command) || fs.existsSync(path.join(os.homedir(), "go", "bin", command));
}

function jwtToolExists() {
  return commandExists("jwt_tool")
    || commandExists("jwt_tool.py")
    || fs.existsSync(path.join(os.homedir(), "jwt_tool", "jwt_tool.py"));
}

function patchrightAvailable(targetAbs, sourceRoot) {
  try {
    require.resolve("patchright", { paths: [targetAbs, sourceRoot] });
    return true;
  } catch {
    return false;
  }
}

// Resolve which adapters to install when --adapter may be omitted.
// Precedence: explicit flag → reinstall metadata → layered detection.
// Returns { ids, reason, detection? } so the caller can log the decision.
function resolveInstallAdapters(targetAbs, options = {}) {
  const explicit = adapterIdsForSelection(options.adapter || options.adapters, { defaultIds: [] });
  if (explicit.length > 0) {
    return { ids: explicit, reason: "explicit_flag" };
  }

  let existing = [];
  try {
    existing = installedAdapterIds(targetAbs, options.installFs || null);
  } catch {
    existing = [];
  }
  if (existing.length > 0) {
    return { ids: existing, reason: "reinstall_metadata" };
  }

  const detection = detectAdapterId(targetAbs, options.detectionOptions || {});
  return { ids: [detection.id], reason: detection.reason, detection };
}

function defaultLogResolution(resolution) {
  if (resolution.reason === "explicit_flag") return;
  const noun = resolution.ids.length > 1 ? "adapters" : "adapter";
  process.stderr.write(
    `hacker-bob: auto-selected ${noun} ${resolution.ids.join(", ")} (reason: ${resolution.reason})\n` +
    `  Override with --adapter <claude|codex|generic-mcp|kimi|all>\n`,
  );
}

function installProject(projectDir, options = {}) {
  const sourceRoot = path.resolve(options.sourceRoot || path.join(__dirname, ".."));
  const targetAbs = path.resolve(projectDir || ".");
  const bobResourceDir = path.join(targetAbs, BOB_RESOURCE_DIR);
  const manifest = packageManifest(sourceRoot);
  const installerSource = options.installerSource || process.env.HACKER_BOB_INSTALLER_SOURCE || "cli";

  if (!fs.existsSync(targetAbs) || !fs.statSync(targetAbs).isDirectory()) {
    throw new Error(`Install target does not exist or is not a directory: ${targetAbs}`);
  }
  const installFs = createSafeInstallFs(targetAbs, { label: "install target" });

  const adapterResolution = resolveInstallAdapters(targetAbs, {
    ...options,
    installFs,
  });
  const adapterIds = adapterResolution.ids;
  const logResolution = options.onAdapterResolution || defaultLogResolution;
  logResolution(adapterResolution);

  const existingAdapters = installedAdapterIds(targetAbs, installFs);
  installFs.mkdirp(bobResourceDir);

  const copiedResources = {};
  for (const resourceSet of RESOURCE_SETS) {
    copiedResources[resourceSet.name] = copyResourceSet(installFs, sourceRoot, targetAbs, resourceSet);
  }
  const legacyResourcesRemoved = removeLegacyResourceCopies(installFs, sourceRoot, targetAbs);

  const mcpDir = path.join(targetAbs, "mcp");
  installFs.mkdirp(path.join(mcpDir, "lib", "tools"));
  for (const file of ["server.js", "auto-signup.js", "redaction.js"]) {
    const mode = file === "server.js" ? 0o755 : undefined;
    copyFile(installFs, path.join(sourceRoot, "mcp", file), path.join(mcpDir, file), mode);
  }
  copyDirFiles(installFs, path.join(sourceRoot, "mcp", "lib"), path.join(mcpDir, "lib"), (name) => name.endsWith(".js"));
  const sourceToolsDir = path.join(sourceRoot, "mcp", "lib", "tools");
  const targetToolsDir = path.join(mcpDir, "lib", "tools");
  if (path.resolve(sourceToolsDir) !== path.resolve(targetToolsDir)) {
    installFs.removePath(targetToolsDir, { recursive: true });
    copyDirFiles(installFs, sourceToolsDir, targetToolsDir, (name) => name.endsWith(".js"));
  }
  const copiedRuntimeDependencies = copyRuntimeNodeDependencies(installFs, sourceRoot, mcpDir);

  // Policy-replay diagnostic harness. Adapter-agnostic tooling under
  // testing/policy-replay/ in the target. Skip node_modules to avoid bloat.
  const sourcePolicyReplayDir = path.join(sourceRoot, "testing", "policy-replay");
  const targetPolicyReplayDir = path.join(targetAbs, "testing", "policy-replay");
  if (fs.existsSync(sourcePolicyReplayDir) && path.resolve(sourcePolicyReplayDir) !== path.resolve(targetPolicyReplayDir)) {
    copyDirRecursive(
      installFs,
      sourcePolicyReplayDir,
      targetPolicyReplayDir,
      (relative) => /\.(?:mjs|md|json)$/.test(relative) && !relative.split(path.sep).includes("node_modules"),
    );
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
        copyDirFiles: (...args) => copyDirFiles(installFs, ...args),
        copyFile: (...args) => copyFile(installFs, ...args),
        commitSha,
        installedAt,
        installerSource,
        installFs,
        manifest,
        packageName,
        readJsonIfExists: (filePath, fallback) => installFs.readJsonIfExists(filePath, fallback, {
          kind: "config file",
          symlink: "reject",
        }),
        removeIfExists: (filePath) => removeIfExists(installFs, filePath),
        serverPath,
        writeJson: (filePath, value, optionsForFile = {}) => installFs.writeJson(filePath, value, optionsForFile),
      });
    } else if (adapterId === "generic-mcp") {
      adapterResults[adapterId] = adapter.install({
        installFs,
        sourceRoot,
        targetAbs,
        readJsonIfExists: (filePath, fallback) => installFs.readJsonIfExists(filePath, fallback, {
          kind: "config file",
          symlink: "reject",
        }),
        serverPath,
      });
    } else if (adapterId === "kimi") {
      adapterResults[adapterId] = adapter.install({
        sourceRoot,
        targetAbs,
        copyDirFiles: (...args) => copyDirFiles(installFs, ...args),
        copyFile: (...args) => copyFile(installFs, ...args),
        commitSha,
        installedAt,
        installerSource,
        installFs,
        manifest,
        packageName,
        serverPath,
      });
    } else {
      adapterResults[adapterId] = adapter.install({
        activate: options.activateCodex !== false && process.env.HACKER_BOB_CODEX_AUTO_INSTALL !== "0",
        installFs,
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
    installFs,
    targetAbs,
    manifest,
    installedAt,
    packageName,
    installerSource,
    commitSha,
    adapterIds: metadataAdapters,
  });
  try {
    clearUpdateCache(targetAbs);
  } catch {
    // A stale update hint is cosmetic; never fail an otherwise valid install.
  }

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
    kimiSkills: adapterResults.kimi ? adapterResults.kimi.skills : 0,
    bypassTables: copiedResources.bypassTables.length,
    knowledge: copiedResources.knowledge.length,
    legacyResourcesRemoved,
    runtimeDependencyFiles: copiedRuntimeDependencies.length,
    patchrightAvailable: patchrightAvailable(targetAbs, sourceRoot),
  };
}

function printInstallSummary(summary) {
  console.log(`Installing Hacker Bob ${summary.version} into ${summary.targetAbs}/`);
  console.log("");
  console.log(`  host adapters: ${summary.adapters.join(", ")}`);
  if (summary.adapterResults.claude) {
    console.log(`  ${summary.agents} Claude agent definitions`);
    console.log("  Claude command shims (/bob-update, /bob-egress, /bob-export)");
    console.log("  Claude bob-hunt + bob-oss + bob-status + bob-debug skills");
    console.log(`  ${summary.rules} Claude rules`);
    console.log("  Claude session guard hooks, update/export helpers, and status line");
    console.log("  Claude .mcp.json and settings.json merged");
    console.log("  .claude/bob/VERSION and install.json compatibility metadata");
  }
  if (summary.adapterResults.codex) {
    console.log("  Codex plugin (.codex/plugins/hacker-bob) for MCP wiring");
    console.log("  Codex skills ($bob-hunt, $bob-oss, $bob-status, $bob-debug, $bob-update, $bob-export, $bob-egress) in ~/.codex/skills");
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
  if (summary.adapterResults.kimi) {
    console.log(`  Kimi skills (${summary.kimiSkills}) installed to .kimi/`);
    console.log("  Kimi .kimi/mcp.json merged");
    console.log("  .kimi/bob/VERSION and install.json compatibility metadata");
  }
  console.log(`  ${summary.bypassTables} neutral bypass tables`);
  console.log(`  ${summary.knowledge} neutral hunter knowledge files`);
  console.log(`  MCP runtime (mcp/server.js, auto-signup.js, redaction.js, lib/*.js, lib/tools/*.js, dependency files ${summary.runtimeDependencyFiles})`);
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
  for (const tool of ["subfinder", "httpx", "nuclei", "amass", "assetfinder", "chaos", "dnsx", "tlsx", "katana", "subzy"]) {
    console.log(`  ${commandOrGoBinExists(tool) ? "OK" : "MISSING"}: ${tool}`);
  }
  console.log(`  ${jwtToolExists() ? "OK" : "MISSING"}: jwt_tool`);
  console.log("");
  console.log("Install recon tools (optional):");
  console.log("  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest");
  console.log("  go install github.com/projectdiscovery/httpx/cmd/httpx@latest");
  console.log("  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest");
  console.log("  go install github.com/owasp-amass/amass/v4/...@latest");
  console.log("  go install github.com/tomnomnom/assetfinder@latest");
  console.log("  go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest");
  console.log("  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest");
  console.log("  go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest");
  console.log("  go install github.com/projectdiscovery/katana/cmd/katana@latest");
  console.log("  go install -v github.com/PentestPad/subzy@latest");
  console.log("  git clone https://github.com/ticarpi/jwt_tool ~/jwt_tool && python3 -m pip install -r ~/jwt_tool/requirements.txt");
  console.log("");
  if (summary.adapters.length === 1 && summary.adapters[0] === "claude") {
    console.log(`Done. Restart Claude Code in ${summary.targetAbs}, then run: /bob-hunt target.com`);
  } else if (summary.adapters.length === 1 && summary.adapters[0] === "codex") {
    console.log(`Done. Restart Codex in ${summary.targetAbs}, then run: $bob-hunt target.com`);
  } else if (summary.adapters.length === 1 && summary.adapters[0] === "generic-mcp") {
    console.log(`Done. Connect your MCP host to ${path.join(summary.targetAbs, "mcp", "server.js")} and read .hacker-bob/generic-mcp/hacker-bob.md.`);
  } else if (summary.adapters.length === 1 && summary.adapters[0] === "kimi") {
    console.log(`Done. Launch Kimi CLI in ${summary.targetAbs} with:`);
    console.log(`  kimi --mcp-config-file .kimi/mcp.json`);
    console.log(`Then run: /skill:bob-hunt target.com`);
  } else {
    console.log(`Done. Restart the selected host CLIs in ${summary.targetAbs} before continuing.`);
  }
}

module.exports = {
  BOB_RESOURCE_DIR,
  NEUTRAL_INSTALL_SCHEMA_VERSION,
  RESOURCE_SETS,
  commandExists,
  defaultLogResolution,
  detectInstalledAdapterIds,
  installProject,
  installedAdapterIds,
  neutralInstallMetadataPath,
  neutralVersionPath,
  patchrightAvailable,
  printInstallSummary,
  readNeutralInstallMetadata,
  resolveInstallAdapters,
  writeNeutralInstallMetadata,
};
