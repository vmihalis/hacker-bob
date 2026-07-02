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
const { commandExists } = require("./lib/command-exists.js");

const BOB_RESOURCE_DIR = ".hacker-bob";
const NEUTRAL_INSTALL_SCHEMA_VERSION = 2;

// The top-level mcp/ runtime files the installer ships (server.js loads/spawns each). An EXPLICIT
// manifest, NOT a glob: deny-by-default so a stray top-level mcp/*.js (a scratch/test file) never
// ships to every install. Completeness is enforced mechanically by test/install-smoke.test.js, which
// asserts this set EQUALS the real top-level mcp/*.js on disk — so a NEW runtime file (as
// browser-driver.js, the Patchright DRIVER_SCRIPT_PATH server.js spawns, once was) that is added to
// mcp/ but forgotten here FAILS the test instead of silently freezing the operational copy (the drift
// that broke the offensive mass-read producer's authed_fetch transport while older commands worked).
const MCP_TOP_LEVEL_RUNTIME_FILES = Object.freeze([
  "server.js",
  "auto-signup.js",
  "redaction.js",
  "browser-driver.js",
]);
const RESOURCE_SETS = Object.freeze([
  {
    name: "bypassTables",
    source: path.join(BOB_RESOURCE_DIR, "bypass-tables"),
    destination: path.join(BOB_RESOURCE_DIR, "bypass-tables"),
    predicate: (name) => name.endsWith(".txt"),
    missingMessage: ".hacker-bob/bypass-tables/ is missing. EVALUATE phase requires these files.",
    emptyMessage: ".hacker-bob/bypass-tables/ is empty. EVALUATE phase requires these files.",
  },
  {
    name: "knowledge",
    source: path.join(BOB_RESOURCE_DIR, "knowledge"),
    destination: path.join(BOB_RESOURCE_DIR, "knowledge"),
    predicate: (name) => name.endsWith(".json"),
    missingMessage: ".hacker-bob/knowledge/ is missing. EVALUATE phase requires these files.",
    emptyMessage: ".hacker-bob/knowledge/ is empty. EVALUATE phase requires these files.",
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
    fs.existsSync(path.join(targetAbs, ".claude", "commands", "bob", "evaluate.md")) ||
    fs.existsSync(path.join(targetAbs, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")) ||
    // Legacy detection: prior installs created bob-evaluate (or bob-hunt) skill
    // dirs before the rename to bob-evaluate-runner. Detect those so reinstall
    // metadata still resolves to the Claude adapter.
    fs.existsSync(path.join(targetAbs, ".claude", "skills", "bob-evaluate", "SKILL.md"))
  ) {
    ids.push("claude");
  }
  if (fs.existsSync(path.join(targetAbs, ".codex", "plugins", "hacker-bob"))) {
    ids.push("codex");
  }
  if (
    fs.existsSync(path.join(targetAbs, ".kimi", "bob", "VERSION")) ||
    fs.existsSync(path.join(targetAbs, ".kimi", "skills", "bob-evaluate", "SKILL.md"))
  ) {
    ids.push("kimi");
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

function copyRuntimeNodeDependencies(sourceRoot, mcpDir) {
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
    fs.rmSync(destinationDir, { recursive: true, force: true });
    copied.push(...copyDirRecursive(sourceDir, destinationDir).map((file) => path.join(packageName, file)));
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
    existing = installedAdapterIds(targetAbs);
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
    `  Override with --adapter <claude|codex|generic-mcp|all>\n`,
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

  const adapterResolution = resolveInstallAdapters(targetAbs, options);
  const adapterIds = adapterResolution.ids;
  const logResolution = options.onAdapterResolution || defaultLogResolution;
  logResolution(adapterResolution);

  const existingAdapters = installedAdapterIds(targetAbs);

  // PRE-FLIGHT (atomicity). If the Claude adapter will merge .claude/settings.json, validate
  // that every legacy bounty_* permission migrates to a live canonical bob_* twin BEFORE any
  // file is copied. The settings merge runs AFTER the runtime/agent/hook copies, so a stale-
  // permission throw there would abort mid-install and leave a half-upgraded project. Failing
  // here — before the first mutation — keeps a doomed upgrade from touching the target at all.
  if (adapterIds.includes("claude")) {
    const { assertLegacyToolPermissionsMigratable } = require("./merge-claude-config.js");
    const existingClaudeSettings = readJsonIfExists(path.join(targetAbs, ".claude", "settings.json"), {});
    assertLegacyToolPermissionsMigratable(existingClaudeSettings);
  }

  fs.mkdirSync(bobResourceDir, { recursive: true });

  const copiedResources = {};
  for (const resourceSet of RESOURCE_SETS) {
    copiedResources[resourceSet.name] = copyResourceSet(sourceRoot, targetAbs, resourceSet);
  }
  const legacyResourcesRemoved = removeLegacyResourceCopies(sourceRoot, targetAbs);

  const mcpDir = path.join(targetAbs, "mcp");
  fs.mkdirSync(path.join(mcpDir, "lib", "tools"), { recursive: true });
  // Copy Bob's top-level mcp/ runtime files from the explicit MCP_TOP_LEVEL_RUNTIME_FILES manifest.
  // copyFile OVERWRITES, so a reinstall refreshes a stale prior version — that is what fixes the frozen
  // browser-driver.js this PR is about. We deliberately do NOT delete other top-level mcp/*.js: the
  // install target is the user's project and may hold files Bob never placed, so deleting by negation
  // would destroy them (Codex/glm round-4). A Bob runtime file later renamed/removed lingers harmlessly
  // (server.js never require()s it). The manifest is the single source of truth; install-smoke.test.js
  // pins it EQUAL to the real top-level mcp/*.js, so a NEW runtime file can't be silently forgotten —
  // the drift that hid browser-driver.js. lib/ + its subdirs are copied separately below.
  for (const file of MCP_TOP_LEVEL_RUNTIME_FILES) {
    copyFile(path.join(sourceRoot, "mcp", file), path.join(mcpDir, file));
  }
  fs.chmodSync(path.join(mcpDir, "server.js"), 0o755);
  // Recursively copy the whole mcp/lib tree so EVERY split-module subdir lands --
  // tools/, waves/, body-resolvers/, belief/, and any future one. server.js requires
  // these at module-load time, so a dropped subdir crashes startup with a "Cannot
  // find module" error. Copying the tree (not an enumerated subdir list) makes that
  // silent-drop class impossible. The managed subdirs are cleared first so a
  // renamed/removed module does not linger across re-installs.
  const sourceLibDir = path.join(sourceRoot, "mcp", "lib");
  const targetLibDir = path.join(mcpDir, "lib");
  if (path.resolve(sourceLibDir) !== path.resolve(targetLibDir)) {
    for (const name of fs.readdirSync(sourceLibDir).sort()) {
      const source = path.join(sourceLibDir, name);
      if (name !== "node_modules" && fs.statSync(source).isDirectory()) {
        fs.rmSync(path.join(targetLibDir, name), { recursive: true, force: true });
      }
    }
    // Copy .js modules plus any .sh build assets a module reads at load time
    // (e.g. repo-env.js resolves a native-fuzz build script under mcp/lib/fuzz/).
    // Dropping a load-time .sh asset crashes mcp/server.js startup the same way a
    // dropped subdir would, so the runtime-copy must carry both.
    copyDirRecursive(
      sourceLibDir,
      targetLibDir,
      (relative, name) => name.endsWith(".js") || name.endsWith(".sh"),
    );
  }
  // The offensive arsenal image digest lockfile is operator-minted JSON data (scripts/build-offensive-image.sh).
  // The recursive mcp/lib copy above is .js/.sh-only, so copy this .json explicitly. Absent until the image is pinned.
  const offensiveImageLock = path.join(sourceRoot, "mcp", "lib", "offensive-image.json");
  const targetImageLock = path.join(mcpDir, "lib", "offensive-image.json");
  if (fs.existsSync(offensiveImageLock)) {
    copyFile(offensiveImageLock, targetImageLock);
  } else {
    // Unpinned source: remove any stale target lockfile so the runtime fails closed instead of
    // resolving a previously-installed (now removed) digest.
    fs.rmSync(targetImageLock, { force: true });
  }
  const copiedRuntimeDependencies = copyRuntimeNodeDependencies(sourceRoot, mcpDir);

  // Policy-replay diagnostic harness. Adapter-agnostic tooling under
  // testing/policy-replay/ in the target. Skip node_modules to avoid bloat.
  const sourcePolicyReplayDir = path.join(sourceRoot, "testing", "policy-replay");
  const targetPolicyReplayDir = path.join(targetAbs, "testing", "policy-replay");
  if (fs.existsSync(sourcePolicyReplayDir) && path.resolve(sourcePolicyReplayDir) !== path.resolve(targetPolicyReplayDir)) {
    copyDirRecursive(
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
  try {
    clearUpdateCache(targetAbs);
  } catch {
    // A stale update hint is cosmetic; never fail an otherwise valid install.
  }

  fs.mkdirSync(path.join(os.homedir(), "hacker-bob-sessions"), { recursive: true });

  // Y.10 (Y-D12 / D6 + D14) — provision the operator session-cap nonce at
  // ~/.bob/session-cap (mode 0600) so bob_set_queue_policy({partial_surface_
  // advance_acknowledgements: [...]}) acknowledgements have a real nonce to
  // match against. The runtime gate (mcp/lib/lifecycle-gates.js) consults
  // verifyAttestationToken; without an install-managed nonce the gate would
  // fall back to non-empty-string validation and offer no operator-attest
  // authority. Idempotent: existing nonces are preserved and the mode is
  // re-enforced.
  let sessionCap = null;
  try {
    const { ensureSessionCapNonce, sessionCapPath } = require(
      path.join(targetAbs, "mcp", "lib", "session-cap.js"),
    );
    ensureSessionCapNonce();
    sessionCap = sessionCapPath();
  } catch {
    // Best-effort: the runtime gate degrades gracefully when the nonce file
    // is absent (cap_status: "uninitialized"); we never block install on
    // session-cap provisioning errors.
    sessionCap = null;
  }

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
    console.log("  Claude bob-evaluate-runner + bob-status + bob-debug + bob-diff-review skills");
    console.log(`  ${summary.rules} Claude rules`);
    console.log("  Claude session guard hooks, update/export helpers, and status line");
    console.log("  Claude .mcp.json and settings.json merged");
    console.log("  .claude/bob/VERSION and install.json compatibility metadata");
  }
  if (summary.adapterResults.codex) {
    console.log("  Codex plugin (.codex/plugins/hacker-bob) for MCP wiring");
    console.log("  Codex skills ($bob-evaluate, $bob-status, $bob-debug, $bob-update, $bob-export, $bob-egress) in ~/.codex/skills");
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
  console.log(`  ${summary.knowledge} neutral evaluator knowledge files`);
  console.log(`  MCP runtime (mcp/{${MCP_TOP_LEVEL_RUNTIME_FILES.join(", ")}}, lib/*.js, lib/tools/*.js, dependency files ${summary.runtimeDependencyFiles})`);
  console.log("  .hacker-bob/ resources");
  console.log("  .hacker-bob/VERSION and install.json");
  console.log("  ~/hacker-bob-sessions/  (canonical session root; run with --purge-legacy-session-root to remove a pre-v2.0 ~/bounty-agent-sessions/)");
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
  console.log("Optional surface-discovery tools (evaluating works without these, surface-discovery steps are skipped):");
  for (const tool of ["subfinder", "httpx", "nuclei", "amass", "assetfinder", "chaos", "dnsx", "tlsx", "katana", "subzy"]) {
    console.log(`  ${commandOrGoBinExists(tool) ? "OK" : "MISSING"}: ${tool}`);
  }
  console.log(`  ${jwtToolExists() ? "OK" : "MISSING"}: jwt_tool`);
  console.log("");
  console.log("Install surface-discovery tools (optional):");
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
    console.log(`Done. Restart Claude Code in ${summary.targetAbs}, then run: /bob-evaluate target.com`);
  } else if (summary.adapters.length === 1 && summary.adapters[0] === "codex") {
    console.log(`Done. Restart Codex in ${summary.targetAbs}, then run: $bob-evaluate target.com`);
  } else if (summary.adapters.length === 1 && summary.adapters[0] === "generic-mcp") {
    console.log(`Done. Connect your MCP host to ${path.join(summary.targetAbs, "mcp", "server.js")} and read .hacker-bob/generic-mcp/hacker-bob.md.`);
  } else if (summary.adapters.length === 1 && summary.adapters[0] === "kimi") {
    console.log(`Done. Launch Kimi from ${summary.targetAbs} with: kimi --mcp-config-file .kimi/mcp.json  (Kimi does not auto-discover .kimi/mcp.json, so this flag is mandatory), then run: /skill:bob-evaluate target.com`);
  } else {
    console.log(`Done. Restart the selected host CLIs in ${summary.targetAbs} before continuing.`);
  }
}

// Opt-in, destructive cleanup of a leftover pre-v2.0 session root. The runtime
// no longer auto-resolves or auto-copies `~/bounty-agent-sessions`; this removes
// a stale legacy root once an operator has confirmed they no longer need it.
// Dry-run by default; `--yes` (confirmed: true) is required to delete. NEVER
// touches the canonical `~/hacker-bob-sessions` root or the home directory.
function purgeLegacySessionRoot({ dryRun = true, confirmed = false, home = os.homedir(), includeTelemetry = false } = {}) {
  const homeDir = home;
  const legacyRoot = path.join(homeDir, "bounty-agent-sessions");
  const canonicalRoot = path.join(homeDir, "hacker-bob-sessions");
  const legacyTelemetryDir = path.join(homeDir, "bounty-agent-telemetry");

  const report = {
    legacy_root: legacyRoot,
    canonical_root: canonicalRoot,
    dry_run: dryRun || !confirmed,
    purged: false,
    would_delete: [],
    deleted_root: null,
    count: 0,
    telemetry_root: includeTelemetry ? legacyTelemetryDir : null,
    telemetry_purged: false,
    reason: null,
  };

  // Fail-closed guards. Refuse if the legacy root itself is a symlink (so a
  // recursive delete cannot escape through it), collapses onto the canonical
  // root, or is the home directory / filesystem root. The leaf-symlink check
  // uses lstat so an ancestor symlink (e.g. macOS /var -> /private/var) does
  // not spuriously block a genuine `~/bounty-agent-sessions` directory.
  function purgeBlocked() {
    if (legacyRoot === canonicalRoot) return "legacy_equals_canonical";
    if (legacyRoot === homeDir) return "legacy_equals_home";
    if (path.dirname(legacyRoot) === legacyRoot) return "legacy_is_fs_root";
    if (path.basename(legacyRoot) !== "bounty-agent-sessions") return "legacy_basename_mismatch";
    let legacyStat;
    try {
      legacyStat = fs.lstatSync(legacyRoot);
    } catch (error) {
      if (error && error.code === "ENOENT") return null;
      return `lstat_failed:${error && error.code ? error.code : "unknown"}`;
    }
    if (legacyStat.isSymbolicLink()) return "legacy_root_symlink_escape";
    if (!legacyStat.isDirectory()) return "legacy_root_not_directory";
    return null;
  }

  const blocked = purgeBlocked();
  if (blocked) {
    report.reason = blocked;
    return report;
  }

  if (!fs.existsSync(legacyRoot)) {
    report.reason = "no_legacy_root";
    return report;
  }

  let domains = [];
  try {
    domains = fs.readdirSync(legacyRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();
  } catch (_) {
    domains = [];
  }
  report.would_delete = domains;
  report.count = domains.length;

  if (report.dry_run) {
    report.reason = "dry_run";
    return report;
  }

  // Confirmed: delete ONLY the legacy root. The canonical root is never even a
  // candidate for deletion.
  fs.rmSync(legacyRoot, { recursive: true, force: true });
  report.purged = true;
  report.deleted_root = legacyRoot;
  report.reason = "purged";

  if (includeTelemetry && fs.existsSync(legacyTelemetryDir)) {
    fs.rmSync(legacyTelemetryDir, { recursive: true, force: true });
    report.telemetry_purged = true;
  }

  return report;
}

function printPurgeLegacySessionRootReport(report) {
  if (report.reason === "no_legacy_root") {
    console.log(`No legacy session root to purge (${report.legacy_root} does not exist).`);
    return;
  }
  if (report.reason && report.reason !== "dry_run" && report.reason !== "purged") {
    console.log(`Refused to purge legacy session root (${report.reason}). No files were deleted.`);
    console.log(`  Legacy root: ${report.legacy_root}`);
    return;
  }
  if (report.dry_run) {
    console.log(`DRY RUN — would delete the legacy session root and ${report.count} session director${report.count === 1 ? "y" : "ies"}:`);
    console.log(`  ${report.legacy_root}`);
    for (const domain of report.would_delete) {
      console.log(`    - ${domain}`);
    }
    console.log(`  Canonical root ${report.canonical_root} is NOT affected.`);
    console.log("  Re-run with --yes to actually delete. This is irreversible.");
    return;
  }
  console.log(`Deleted legacy session root ${report.deleted_root} (${report.count} director${report.count === 1 ? "y" : "ies"}).`);
  if (report.telemetry_purged) {
    console.log(`Deleted legacy telemetry directory ${report.telemetry_root}.`);
  }
  console.log(`Canonical root ${report.canonical_root} was not touched.`);
}

module.exports = {
  BOB_RESOURCE_DIR,
  MCP_TOP_LEVEL_RUNTIME_FILES,
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
  printPurgeLegacySessionRootReport,
  purgeLegacySessionRoot,
  readNeutralInstallMetadata,
  resolveInstallAdapters,
  writeNeutralInstallMetadata,
};
