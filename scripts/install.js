"use strict";

const crypto = require("node:crypto");
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
const {
  CANONICAL_INSTALL_SUPPORT_FILES,
  CANONICAL_RUNTIME_PACKAGE_ROOTS,
  MCP_TOP_LEVEL_RUNTIME_FILES,
  isCanonicalRuntimePackageFile,
  sourceTreeFiles,
} = require("./lib/package-policy.js");
const {
  retainDirectoryAncestry,
  sameFilesystemIdentity,
} = require("./lib/optional-provider-lifecycle.js");
// Drift guard. Family A's copyFile/removeIfExists below route through this so
// a locally modified installed file is preserved-and-reported instead of
// silently destroyed. scripts/lib/install-fs.js (family B) requires the SAME
// module — one implementation, two copy stacks.
const {
  INSTALLED_FILE_OWNERSHIP_KEY,
  PRESERVED_LOCAL_SUFFIX,
  activeInstallDriftGuard,
  beginInstallDriftGuard,
  formatPreservedSummary,
  guardBeforeDelete,
  guardBeforeTreeReplace,
  guardBeforeWrite,
  recordInstalledFile,
} = require("./lib/install-drift.js");
const {
  executeLifecycleMutation,
} = require("./lib/lifecycle-custodian.js");
const {
  SESSIONS_ROOT_ENV_VAR,
  defaultSessionsRoot,
  defaultSessionsRootHasSessions,
  ensureSessionsRoot,
  pinnedSessionsRootFromMcpConfig,
  pinnedSessionsRootFromSettings,
  resolveWorkspaceSessionsRoot,
  workspaceSessionsRoot,
} = require("./lib/workspace-sessions-root.js");

const BOB_RESOURCE_DIR = ".hacker-bob";
const NEUTRAL_INSTALL_SCHEMA_VERSION = 2;
const MCP_TOP_LEVEL_OWNERSHIP_RECEIPT_VERSION = 1;
const MAX_MCP_TOP_LEVEL_RUNTIME_FILE_BYTES = 16 * 1024 * 1024;
const MCP_TOP_LEVEL_RUNTIME_NAME_PATTERN = /^[A-Za-z0-9._-]+\.js$/u;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/u;
const MAX_RUNTIME_DEPENDENCY_MANIFEST_BYTES = 1024 * 1024;
const MAX_RUNTIME_DEPENDENCY_FILE_BYTES = 512 * 1024 * 1024;
const MAX_RUNTIME_DEPENDENCY_FILES = 100_000;
// The agent SDK ships a native Claude CLI. darwin-arm64 0.3.241 is about
// 325 MB unpacked, so the per-file ceiling needs real headroom above 256 MB.
// The total graph bound below remains the independent runaway-tree backstop.
// It also covers layouts with more than one platform variant, such as Linux
// installs that contain both gnu and musl builds.
const MAX_RUNTIME_DEPENDENCY_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_RUNTIME_DEPENDENCY_DEPTH = 32;
const MAX_RUNTIME_DEPENDENCY_DIRECTORIES = 4096;
const MAX_RUNTIME_DEPENDENCY_PACKAGES = 4096;
const MAX_RUNTIME_DEPENDENCY_EDGES = 20_000;
const MAX_RUNTIME_DEPENDENCY_SPEC_BYTES = 2048;
const MAX_RUNTIME_DEPENDENCY_ANCESTORS = 32;
const RUNTIME_DEPENDENCY_NAME_PATTERN = /^(?:@[a-z0-9][a-z0-9._-]{0,127}\/)?[a-z0-9][a-z0-9._-]{0,127}$/u;

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
  mcpTopLevelRuntimeOwnership,
  installedFileOwnership = null,
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
    mcp_top_level_runtime_ownership: mcpTopLevelRuntimeOwnership,
    // ADDITIVE (schema_version stays 2): per-installed-file digests, the
    // record the drift guard compares each destination against on the NEXT
    // install. Omitted when no guard ran; an install.json without the key is
    // still valid and simply makes every file "possibly local".
    ...(installedFileOwnership ? { [INSTALLED_FILE_OWNERSHIP_KEY]: installedFileOwnership } : {}),
  });
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function buildMcpTopLevelRuntimeOwnership(sourceRoot) {
  return Object.freeze({
    version: MCP_TOP_LEVEL_OWNERSHIP_RECEIPT_VERSION,
    files: Object.freeze(MCP_TOP_LEVEL_RUNTIME_FILES.map((name) => Object.freeze({
      name,
      byte_size: fs.statSync(path.join(sourceRoot, "mcp", name)).size,
      sha256: sha256File(path.join(sourceRoot, "mcp", name)),
    }))),
  });
}

function normalizeMcpTopLevelRuntimeOwnership(metadata, targetAbs) {
  if (metadata == null || typeof metadata !== "object" || Array.isArray(metadata)
      || metadata.schema_version !== NEUTRAL_INSTALL_SCHEMA_VERSION
      || metadata.install_target !== targetAbs) return [];
  const receipt = metadata.mcp_top_level_runtime_ownership;
  if (receipt == null || typeof receipt !== "object" || Array.isArray(receipt)
      || Object.keys(receipt).length !== 2
      || receipt.version !== MCP_TOP_LEVEL_OWNERSHIP_RECEIPT_VERSION
      || !Array.isArray(receipt.files)
      || receipt.files.length > 128) return [];
  const seen = new Set();
  const normalized = [];
  for (const file of receipt.files) {
    if (file == null || typeof file !== "object" || Array.isArray(file)
        || Object.keys(file).length !== 3
        || typeof file.name !== "string"
        || !MCP_TOP_LEVEL_RUNTIME_NAME_PATTERN.test(file.name)
        || path.basename(file.name) !== file.name
        || !Number.isSafeInteger(file.byte_size)
        || file.byte_size < 0
        || file.byte_size > MAX_MCP_TOP_LEVEL_RUNTIME_FILE_BYTES
        || typeof file.sha256 !== "string"
        || !SHA256_HEX_PATTERN.test(file.sha256)
        || seen.has(file.name)) return [];
    seen.add(file.name);
    normalized.push({ name: file.name, byte_size: file.byte_size, sha256: file.sha256 });
  }
  return normalized;
}

function pruneRetiredMcpTopLevelRuntimeFiles(targetAbs, metadata) {
  const currentNames = new Set(MCP_TOP_LEVEL_RUNTIME_FILES);
  const mcpDir = path.join(targetAbs, "mcp");
  const removed = [];
  for (const record of normalizeMcpTopLevelRuntimeOwnership(metadata, targetAbs)) {
    if (currentNames.has(record.name)) continue;
    const candidate = path.join(mcpDir, record.name);
    let fd = null;
    try {
      // The mixed-ownership mcp/ root is not pruned by negation. A retired
      // filename is unlinked only when the installed regular file still has
      // the exact digest Bob recorded on the preceding install. A symlink,
      // modified former runtime, malformed receipt, or changed file identity
      // is preserved because Bob can no longer prove exclusive ownership.
      fd = fs.openSync(
        candidate,
        fs.constants.O_RDONLY
          | (fs.constants.O_NOFOLLOW || 0)
          | (fs.constants.O_NONBLOCK || 0)
          | (fs.constants.O_CLOEXEC || 0),
      );
      const opened = fs.fstatSync(fd);
      if (!opened.isFile() || opened.size !== record.byte_size) continue;
      const digest = crypto.createHash("sha256").update(fs.readFileSync(fd)).digest("hex");
      if (digest !== record.sha256) continue;
      const current = fs.lstatSync(candidate);
      if (!current.isFile() || current.dev !== opened.dev || current.ino !== opened.ino) continue;
      fs.unlinkSync(candidate);
      removed.push(record.name);
    } catch (error) {
      if (!error || !["ENOENT", "ELOOP", "EMLINK"].includes(error.code)) throw error;
    } finally {
      if (fd != null) fs.closeSync(fd);
    }
  }
  return removed.sort();
}

// FAMILY A lowest-level VERBATIM write. It lands the neutral resource sets, the
// mcp/ runtime copies, and — through the copyFile/copyDirFiles injected into
// adapters/claude/index.js — .claude/agents, .claude/rules, .claude/skills,
// .claude/hooks and .claude/commands/bob-egress.md. This is the write that
// destroyed .claude/agents/report-writer.md, so the guard belongs HERE, not
// only in the createSafeInstallFs twin.
//
// NOT "everything the Claude adapter installs": that adapter also runs writes
// this file never sees, and they are NOT guarded. Pinned by SYMBOL, never by
// line number — the five citations that used to sit here rotted by exactly +8
// the instant this node inserted its own writeTextFile seam into that adapter,
// and a comment aiming a reader at the wrong line is the same class of false
// justification as a wrong claim. Each substring below is asserted to still
// occur in adapters/claude/index.js by test/install-drift.test.js
// ("the unguarded-adapter-write inventory pins symbols that still exist"), so
// this list cannot rot silently:
//   fs.writeFileSync(path.join(claudeDir, "bob", "VERSION"), ...) install stamp
//   fs.rmSync(mcpPath, { force: true });                          removeMcpConfig
//   fs.rmSync(settingsPath, { force: true });                     removeSettingsConfig
//   fs.rmSync(configPath, { force: true });                       removeGeneratedEgressConfig
// The three removeMcpConfig/removeSettingsConfig/removeGeneratedEgressConfig
// entries are UNINSTALL-path deletes of Bob-generated config, not install-path
// writes; the VERSION stamp is regenerated content Bob owns outright.
// TWO entries have LEFT this list because they are now guarded, not because
// they were reclassified:
//   - the renderer-driven commands (bob-evaluate/bob-update/bob-export.md) go
//     through the guarded writeTextFile below, injected alongside copyFile;
//   - the LEGACY_BOB_SKILLS loop's recursive rmSync goes through the injected
//     removeDirIfExists, which sweeps the doomed tree with
//     guardBeforeTreeReplace first. That one destroyed an operator marker in
//     .claude/skills/bob-evaluate/SKILL.md with no sidecar and no summary line
//     while every neighbouring delete in the same function was already guarded.
function copyFile(source, destination, mode) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  const guard = guardBeforeWrite(destination, { sourcePath: source });
  fs.copyFileSync(source, destination);
  if (mode != null) fs.chmodSync(destination, mode);
  recordInstalledFile(destination, guard);
}

// FAMILY A's GENERATED-file write — the twin of copyFile for content Bob
// RENDERS rather than copies, and injected into adapters/claude/index.js for
// exactly that reason. A wholesale render destroys an operator's edit precisely
// as a verbatim copy does: adapters/claude/index.js writes bob-evaluate.md,
// bob-update.md and bob-export.md from renderCommand() with no merge semantics
// whatsoever, so all three were silently destroyed while the fourth command
// file (bob-egress.md, a real copyFile) was preserved. Same guard, same module,
// no third path.
function writeTextFile(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const guard = guardBeforeWrite(filePath, { contents: content });
  fs.writeFileSync(filePath, content, "utf8");
  recordInstalledFile(filePath, guard);
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

// Non-vacuity floor for the ONE tree this installer replaces wholesale. The
// shipped runtime carries ~540 modules; anything near zero means an empty
// source directory, a partial tarball extraction, or a packaging change that
// moved the modules off the copy predicate. Hardcoded on purpose: "copied
// something" is satisfied by copying one file, and the destination has already
// been removed by the time the copy runs.
const MIN_MCP_LIB_RUNTIME_MODULES = 50;

// Counts what copyDirRecursive WOULD copy, without copying it, so the refusal
// can happen BEFORE the destination is destroyed rather than after.
function countTreeFiles(sourceDir, predicate) {
  let total = 0;
  const walk = (dir) => {
    for (const name of fs.readdirSync(dir).sort()) {
      const source = path.join(dir, name);
      const stat = fs.statSync(source);
      if (stat.isDirectory()) {
        if (name === "node_modules") continue;
        walk(source);
        continue;
      }
      if (!stat.isFile()) continue;
      if (predicate && !predicate(path.relative(sourceDir, source), name)) continue;
      total += 1;
    }
  };
  if (fs.existsSync(sourceDir)) walk(sourceDir);
  return total;
}

// Reuses the shape of copyResourceSet's empty-guard below (`if
// (copied.length === 0) throw new Error(resourceSet.emptyMessage)`), raised
// from "not empty" to a real floor because this destination is wiped first.
function assertRuntimeModuleFloor(count, { stage, sourceDir }) {
  if (count >= MIN_MCP_LIB_RUNTIME_MODULES) return count;
  throw new Error(
    `Refusing to replace the installed mcp/lib runtime: ${stage} reports ${count} modules from ${sourceDir}, `
    + `below the required floor of ${MIN_MCP_LIB_RUNTIME_MODULES}. `
    + "Installing this would leave the runtime wiped. Re-fetch or re-extract the Bob source and try again.",
  );
}

// Non-vacuity floors for the two Claude resource trees this installer ships
// through the INJECTED copyDirFiles. They are package.json globs
// (`.claude/agents/**/*`, `.claude/rules/**/*`) of exactly the shape
// `mcp/lib/**/*.js` has, but unlike the neutral resource sets — which
// copyResourceSet below refuses empty via `throw new Error(
// resourceSet.emptyMessage)` — copyDirFiles has no empty guard of its own and
// the adapter adds none. An emptied or mis-globbed source therefore installed
// ZERO agents, printed "  0 Claude agent definitions", printed "Done.", and
// reported success. `.claude/agents` is the directory report-writer.md lives in
// — the file whose silent destruction this whole guard exists to prevent — so a
// Bob that silently ships without it is the same failure wearing a different
// hat. Hardcoded on purpose, exactly like MIN_MCP_LIB_RUNTIME_MODULES:
// "copied something" is satisfied by copying one file.
//
// HEADROOM IS DELIBERATE. These are NON-VACUITY floors, not content
// assertions: they exist to catch an emptied or mis-globbed source, and they
// must not fire on a legitimate shrink. The repo ships 21 agents and 2 rules
// today, but commit 933df67 ("Regenerate evaluation agent surfaces") is the
// in-tree proof that ordinary regeneration commits DELETE from exactly these
// two globs — it removed .claude/rules/hunting.md and renamed five
// hunter-*-agent.md definitions to evaluator-*. That commit happened to stay
// count-neutral (it added .claude/rules/evaluating.md in the same breath, so
// rules went 2 -> 2 and agents 16 -> 16); a consolidation that only deletes
// would not. Pinned at the live count, the very next such commit turns a
// legitimate content change into "Refusing to finish the install", which sends
// the operator hunting a corrupt download that does not exist. Agents have also
// grown 16 -> 21 over recent history, so the live count is a moving ceiling,
// never a floor. Rules gets 1 rather than 2 for the same reason: at a live
// count of 2 a floor of 2 has NO headroom at all, and 1 still catches the zero
// case these floors were written for.
const MIN_CLAUDE_AGENT_FILES = 15;
const MIN_CLAUDE_RULE_FILES = 1;

function assertClaudeResourceFloor(count, { label, floor, sourceDir }) {
  if (Number.isInteger(count) && count >= floor) return count;
  throw new Error(
    `Refusing to finish the install: ${label} installed ${count} files from ${sourceDir}, `
    + `below the required floor of ${floor}. An empty, mis-globbed, or partially extracted source `
    + "would leave Bob running without those definitions and say nothing. "
    + "Re-fetch or re-extract the Bob source and try again.",
  );
}

// Runs the instant the Claude adapter returns, on the SAME counts the run
// summary reports at `agents:` / `rules:` below, so the refusal cannot disagree
// with what the operator is shown.
function assertClaudeResourceFloors(claudeResult, { sourceRoot }) {
  // NOT `if (!claudeResult) return claudeResult`. That early return was the
  // vacuity hole these floors exist to close: an adapter that returned nothing
  // skipped BOTH floors and the install reported success — the same silent pass
  // as installing zero agents, reached one level up. The only call site
  // (installProject below) invokes this with the Claude adapter's own return
  // value, which is always an object, so a falsy value here is a broken
  // adapter, not an absent one. Refuse rather than wave it through.
  if (!claudeResult || typeof claudeResult !== "object") {
    throw new Error(
      "Refusing to finish the install: the Claude adapter returned no result, so the "
      + ".claude/agents and .claude/rules floors could not be checked at all. "
      + "An install that cannot verify those trees must not report success.",
    );
  }
  assertClaudeResourceFloor(claudeResult.agents, {
    label: "the Claude agent definitions (.claude/agents)",
    floor: MIN_CLAUDE_AGENT_FILES,
    sourceDir: path.join(sourceRoot, ".claude", "agents"),
  });
  assertClaudeResourceFloor(claudeResult.rules, {
    label: "the Claude always-on rules (.claude/rules)",
    floor: MIN_CLAUDE_RULE_FILES,
    sourceDir: path.join(sourceRoot, ".claude", "rules"),
  });
  return claudeResult;
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

function copyCanonicalInstallSupportFiles(sourceRoot, targetAbs) {
  return CANONICAL_INSTALL_SUPPORT_FILES.map((entry) => {
    const source = path.join(sourceRoot, entry.source);
    if (!fs.existsSync(source) || !fs.statSync(source).isFile()) {
      throw new Error(`Canonical install support file is missing: ${entry.source}`);
    }
    copyFile(source, path.join(targetAbs, entry.destination));
    return entry.destination;
  });
}

function runtimeDependencyError(message, reasonCode) {
  const error = new Error(message);
  Object.defineProperty(error, "code", {
    value: "runtime_dependency_source_rejected",
    enumerable: false,
  });
  Object.defineProperty(error, "reason_code", {
    value: reasonCode,
    enumerable: false,
  });
  return error;
}

function runtimeDependencyTargetError(message, reasonCode) {
  const error = new Error(message);
  Object.defineProperty(error, "code", {
    value: "runtime_dependency_target_rejected",
    enumerable: false,
  });
  Object.defineProperty(error, "reason_code", {
    value: reasonCode,
    enumerable: false,
  });
  return error;
}

function pathIsWithin(parentPath, candidatePath) {
  const relative = path.relative(path.resolve(parentPath), path.resolve(candidatePath));
  return relative === "" || (!relative.startsWith(`..${path.sep}`)
    && relative !== ".." && !path.isAbsolute(relative));
}

function pathsOverlap(left, right) {
  return pathIsWithin(left, right) || pathIsWithin(right, left);
}

function containingNodeModulesRoot(packageRoot) {
  const absolute = path.resolve(packageRoot);
  const parent = path.dirname(absolute);
  if (path.basename(parent) === "node_modules") return parent;
  const grandparent = path.dirname(parent);
  if (path.basename(grandparent) === "node_modules"
      && /^@[a-z0-9][a-z0-9._-]{0,127}$/u.test(path.basename(parent))) {
    return grandparent;
  }
  return null;
}

function runtimeDependencyResolutionBoundary(sourceRoot) {
  const absolute = path.resolve(sourceRoot);
  let current = absolute;
  let boundary = absolute;
  let count = 0;
  for (;;) {
    if (count > MAX_RUNTIME_DEPENDENCY_ANCESTORS) {
      throw runtimeDependencyError(
        "Runtime dependency source ancestry exceeded its bound",
        "source_ancestor_bound_exceeded",
      );
    }
    if (path.basename(current) === "node_modules") boundary = path.dirname(current);
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
    count += 1;
  }
  return boundary;
}

function runtimeDependencySearchRoots(parentDir, boundary) {
  const absoluteParent = path.resolve(parentDir);
  const absoluteBoundary = path.resolve(boundary);
  if (!pathIsWithin(absoluteBoundary, absoluteParent)) {
    throw runtimeDependencyError(
      "Runtime dependency resolution escaped its bounded source ancestry",
      "source_ancestry_unowned",
    );
  }
  const roots = [];
  let current = absoluteParent;
  for (let count = 0; count <= MAX_RUNTIME_DEPENDENCY_ANCESTORS; count += 1) {
    if (path.basename(current) !== "node_modules") {
      roots.push(path.join(current, "node_modules"));
    }
    if (current === absoluteBoundary) return Array.from(new Set(roots));
    const parent = path.dirname(current);
    if (parent === current || !pathIsWithin(absoluteBoundary, parent)) break;
    current = parent;
  }
  throw runtimeDependencyError(
    "Runtime dependency source ancestry exceeded its bound",
    "source_ancestor_bound_exceeded",
  );
}

function assertRuntimeDependencyDirectory(directoryPath, expectedUid, guard, options = {}) {
  let stat;
  try {
    stat = fs.lstatSync(directoryPath);
  } catch (error) {
    if (error && error.code === "ENOENT") return false;
    throw runtimeDependencyError(
      "Runtime dependency source ancestry was rejected",
      "source_ancestry_unreadable",
    );
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()
      || (Number.isInteger(expectedUid) && Number.isInteger(stat.uid) && stat.uid !== expectedUid)) {
    throw runtimeDependencyError(
      "Runtime dependency source ancestry was rejected",
      "source_ancestry_unowned_or_nonregular",
    );
  }
  try {
    // Retain only the bounded graph anchors selected by the caller. Internal
    // package directories are bound by their recorded identities/name sets;
    // retaining an FD per directory would turn empty-directory fanout into FD
    // exhaustion while still not qualifying same-UID races.
    if (options.retain === true) guard.add(directoryPath);
    guard.revalidate();
  } catch (error) {
    if (error && error.code === "runtime_dependency_source_rejected") throw error;
    throw runtimeDependencyError(
      "Runtime dependency source ancestry changed during inspection",
      "source_ancestry_substituted",
    );
  }
  return true;
}

function sameRuntimeDependencyFileSnapshot(left, right) {
  return sameFilesystemIdentity(left, right)
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.size === right.size
    && left.uid === right.uid
    && left.gid === right.gid
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function sameRuntimeDependencyDirectorySnapshot(left, right) {
  return left != null && right != null
    && left.isDirectory() && right.isDirectory()
    && !left.isSymbolicLink() && !right.isSymbolicLink()
    && sameFilesystemIdentity(left, right)
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function snapshotRuntimeDependencyFile({
  source,
  expectedUid,
  sourceGuard,
  maxBytes = MAX_RUNTIME_DEPENDENCY_FILE_BYTES,
  captureBytes = false,
}) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  let descriptor;
  try {
    const before = fs.lstatSync(source);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
        || before.size > maxBytes
        || (Number.isInteger(expectedUid) && Number.isInteger(before.uid)
          && before.uid !== expectedUid)) {
      throw runtimeDependencyError(
        "Runtime dependency file was rejected",
        "package_file_rejected",
      );
    }
    descriptor = fs.openSync(source, flags);
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || !sameRuntimeDependencyFileSnapshot(before, opened)) {
      throw runtimeDependencyError(
        "Runtime dependency file changed while opening",
        "package_file_substituted",
      );
    }
    sourceGuard.revalidate();
    const hash = crypto.createHash("sha256");
    const chunks = captureBytes ? [] : null;
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let total = 0;
    for (;;) {
      const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk);
      if (chunks) chunks.push(Buffer.from(chunk));
      total += bytesRead;
      if (total > maxBytes) {
        throw runtimeDependencyError(
          "Runtime dependency file exceeded its inspection bound",
          "package_file_bound_exceeded",
        );
      }
    }
    const afterDescriptor = fs.fstatSync(descriptor);
    const afterPath = fs.lstatSync(source);
    if (total !== opened.size
        || !sameRuntimeDependencyFileSnapshot(opened, afterDescriptor)
        || !sameRuntimeDependencyFileSnapshot(afterDescriptor, afterPath)) {
      throw runtimeDependencyError(
        "Runtime dependency file changed during inspection",
        "package_file_substituted",
      );
    }
    sourceGuard.revalidate();
    return Object.freeze({
      source,
      snapshot: opened,
      sha256: hash.digest("hex"),
      contents: chunks ? Buffer.concat(chunks, total) : null,
    });
  } catch (error) {
    if (error && error.code === "runtime_dependency_source_rejected") throw error;
    throw runtimeDependencyError(
      "Runtime dependency file changed during inspection",
      "package_file_substituted",
    );
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readRuntimeDependencyManifest(sourceDir, expectedName, expectedUid, guard) {
  const manifestPath = path.join(sourceDir, "package.json");
  const record = snapshotRuntimeDependencyFile({
    source: manifestPath,
    expectedUid,
    sourceGuard: guard,
    maxBytes: MAX_RUNTIME_DEPENDENCY_MANIFEST_BYTES,
    captureBytes: true,
  });
  if (record.snapshot.size < 2) {
    throw runtimeDependencyError(
      `Runtime dependency ${expectedName || "root"} package manifest was rejected`,
      "package_manifest_nonregular",
    );
  }
  let manifest;
  try {
    manifest = JSON.parse(record.contents.toString("utf8"));
  } catch {
    throw runtimeDependencyError(
      `Runtime dependency ${expectedName || "root"} package manifest was rejected`,
      "package_manifest_invalid",
    );
  }
  if (manifest == null || typeof manifest !== "object" || Array.isArray(manifest)
      || (expectedName != null && manifest.name !== expectedName)) {
    throw runtimeDependencyError(
      `Runtime dependency ${expectedName || "root"} package identity was rejected`,
      "package_identity_mismatch",
    );
  }
  return Object.freeze({ manifest, record });
}

function dependencyField(manifest, fieldName) {
  const value = manifest[fieldName];
  if (value === undefined) return new Map();
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw runtimeDependencyError(
      `Runtime dependency ${fieldName} metadata was rejected`,
      "dependency_metadata_invalid",
    );
  }
  const result = new Map();
  for (const name of Object.keys(value).sort()) {
    const spec = value[name];
    if (!RUNTIME_DEPENDENCY_NAME_PATTERN.test(name)
        || typeof spec !== "string" || spec.length < 1
        || Buffer.byteLength(spec, "utf8") > MAX_RUNTIME_DEPENDENCY_SPEC_BYTES) {
      throw runtimeDependencyError(
        `Runtime dependency ${fieldName} metadata was rejected`,
        "dependency_metadata_invalid",
      );
    }
    result.set(name, spec);
  }
  return result;
}

function runtimeDependencyEdges(manifest) {
  const dependencies = dependencyField(manifest, "dependencies");
  const optionalDependencies = dependencyField(manifest, "optionalDependencies");
  const peers = dependencyField(manifest, "peerDependencies");
  const peerMetaValue = manifest.peerDependenciesMeta;
  const peerMeta = new Map();
  if (peerMetaValue !== undefined) {
    if (peerMetaValue == null || typeof peerMetaValue !== "object" || Array.isArray(peerMetaValue)) {
      throw runtimeDependencyError(
        "Runtime dependency peer metadata was rejected",
        "dependency_metadata_invalid",
      );
    }
    for (const name of Object.keys(peerMetaValue).sort()) {
      const metadata = peerMetaValue[name];
      if (!RUNTIME_DEPENDENCY_NAME_PATTERN.test(name)
          || metadata == null || typeof metadata !== "object"
          || Array.isArray(metadata)
          || Object.keys(metadata).some((key) => key !== "optional")
          || (Object.hasOwn(metadata, "optional") && typeof metadata.optional !== "boolean")) {
        throw runtimeDependencyError(
          "Runtime dependency peer metadata was rejected",
          "dependency_metadata_invalid",
        );
      }
      // npm manifests in the wild (for example debug@4) can retain optional
      // peer metadata after removing the corresponding peer declaration. It
      // carries no graph edge, but its shape is still validated and ignored.
      if (peers.has(name)) peerMeta.set(name, metadata.optional === true);
    }
  }

  const edges = new Map();
  for (const [name, spec] of dependencies) {
    edges.set(name, Object.freeze({ name, spec, optional: false, kind: "dependency" }));
  }
  for (const [name, spec] of optionalDependencies) {
    edges.set(name, Object.freeze({ name, spec, optional: true, kind: "optional_dependency" }));
  }
  for (const [name, spec] of peers) {
    if (!edges.has(name)) {
      edges.set(name, Object.freeze({
        name,
        spec,
        optional: peerMeta.get(name) === true,
        kind: "peer_dependency",
      }));
    }
  }
  return Array.from(edges.values()).sort((left, right) => left.name.localeCompare(right.name));
}

function inspectRuntimeDependencyTree({
  packageRoot,
  sourceUid,
  sourceGuard,
  budget,
  manifestRecord,
}) {
  const directories = [];
  const files = [];
  const visit = (currentSource, relativePrefix, depth) => {
    if (depth > MAX_RUNTIME_DEPENDENCY_DEPTH) {
      throw runtimeDependencyError(
        "Runtime dependency tree exceeded its depth bound",
        "package_tree_depth_exceeded",
      );
    }
    budget.directories += 1;
    if (budget.directories > MAX_RUNTIME_DEPENDENCY_DIRECTORIES) {
      throw runtimeDependencyError(
        "Runtime dependency tree exceeded its directory bound",
        "package_tree_directory_bound_exceeded",
      );
    }
    if (!assertRuntimeDependencyDirectory(currentSource, sourceUid, sourceGuard)) {
      throw runtimeDependencyError(
        "Runtime dependency tree changed during inspection",
        "package_tree_substituted",
      );
    }
    const before = fs.lstatSync(currentSource);
    let names;
    try {
      names = fs.readdirSync(currentSource).sort();
    } catch {
      throw runtimeDependencyError(
        "Runtime dependency tree was unreadable",
        "package_tree_unreadable",
      );
    }
    directories.push(Object.freeze({
      source: currentSource,
      relative: relativePrefix,
      snapshot: before,
      names: Object.freeze([...names]),
    }));
    for (const name of names) {
      const source = path.join(currentSource, name);
      const relative = relativePrefix ? path.join(relativePrefix, name) : name;
      let stat;
      try {
        stat = fs.lstatSync(source);
      } catch {
        throw runtimeDependencyError(
          "Runtime dependency tree changed during inspection",
          "package_tree_substituted",
        );
      }
      if (stat.isSymbolicLink()
          || (Number.isInteger(sourceUid) && Number.isInteger(stat.uid) && stat.uid !== sourceUid)) {
        throw runtimeDependencyError(
          "Runtime dependency tree contains a linked or unowned entry",
          "package_tree_unowned_or_nonregular",
        );
      }
      if (stat.isDirectory()) {
        if (name !== "node_modules") visit(source, relative, depth + 1);
        continue;
      }
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_RUNTIME_DEPENDENCY_FILE_BYTES) {
        throw runtimeDependencyError(
          "Runtime dependency tree contains a non-regular or oversized file",
          "package_file_rejected",
        );
      }
      budget.files += 1;
      budget.bytes += stat.size;
      if (budget.files > MAX_RUNTIME_DEPENDENCY_FILES
          || budget.bytes > MAX_RUNTIME_DEPENDENCY_BYTES) {
        throw runtimeDependencyError(
          "Runtime dependency tree exceeded its copy bound",
          "package_tree_bound_exceeded",
        );
      }
      if (relative === "package.json"
          && (!sameRuntimeDependencyFileSnapshot(stat, manifestRecord.record.snapshot)
            || source !== manifestRecord.record.source)) {
        throw runtimeDependencyError(
          "Runtime dependency manifest changed during graph preflight",
          "package_manifest_substituted",
        );
      }
      // Payload bytes are streamed exactly once during the direct copy. The
      // source preflight binds their complete filesystem snapshots; package
      // manifests additionally carry the parsed-byte SHA-256 binding.
      files.push(Object.freeze({
        source,
        relative,
        snapshot: stat,
        sha256: relative === "package.json" ? manifestRecord.record.sha256 : null,
      }));
    }
    const after = fs.lstatSync(currentSource);
    if (!sameRuntimeDependencyDirectorySnapshot(before, after)) {
      throw runtimeDependencyError(
        "Runtime dependency tree changed during inspection",
        "package_tree_substituted",
      );
    }
  };
  visit(packageRoot, "", 0);
  return Object.freeze({
    directories: Object.freeze(directories),
    files: Object.freeze(files),
  });
}

function compareResolutionContexts(left, right, sourceDir, boundary) {
  for (const searchRoot of runtimeDependencySearchRoots(sourceDir, boundary)) {
    if (left.get(searchRoot) !== right.get(searchRoot)) return false;
  }
  return true;
}

function resolveRuntimeDependencySource({
  parent,
  boundary,
  packageName,
  expectedUid,
  guard,
}) {
  if (!RUNTIME_DEPENDENCY_NAME_PATTERN.test(packageName)) {
    throw runtimeDependencyError(
      "Runtime dependency package name was rejected",
      "package_name_invalid",
    );
  }
  for (const searchRoot of runtimeDependencySearchRoots(parent.sourceDir, boundary)) {
    if (!assertRuntimeDependencyDirectory(searchRoot, expectedUid, guard)) continue;
    let sourceDir = searchRoot;
    let complete = true;
    for (const component of packageName.split("/")) {
      sourceDir = path.join(sourceDir, component);
      if (!assertRuntimeDependencyDirectory(sourceDir, expectedUid, guard)) {
        complete = false;
        break;
      }
    }
    if (!complete) continue;
    if (!parent.resolutionContext.has(searchRoot)) {
      throw runtimeDependencyError(
        `Runtime dependency ${packageName} cannot preserve its Node resolution context`,
        "dependency_path_context_unmapped",
      );
    }
    return Object.freeze({
      sourceDir,
      searchRoot,
      destinationRoot: parent.resolutionContext.get(searchRoot),
    });
  }
  return null;
}

function childResolutionContext(parent, resolved, destination) {
  const context = new Map(parent.resolutionContext);
  const ownNodeModules = path.join(resolved.sourceDir, "node_modules");
  const ownDestination = path.join(destination, "node_modules");
  const existing = context.get(ownNodeModules);
  if (existing !== undefined && existing !== ownDestination) {
    throw runtimeDependencyError(
      "Runtime dependency graph has an ambiguous nested placement",
      "dependency_placement_conflict",
    );
  }
  context.set(ownNodeModules, ownDestination);
  return context;
}

function buildRuntimeDependencyGraph({ sourceRoot, sourceUid, sourceGuard, boundary }) {
  const rootManifest = readRuntimeDependencyManifest(
    sourceRoot,
    null,
    sourceUid,
    sourceGuard,
  );
  const rootContext = new Map();
  for (const searchRoot of runtimeDependencySearchRoots(sourceRoot, boundary)) {
    rootContext.set(searchRoot, "");
  }
  const resolutionRoots = new Set(rootContext.keys());
  const root = Object.freeze({
    sourceDir: sourceRoot,
    destination: "",
    manifestRecord: rootManifest,
    resolutionContext: rootContext,
  });
  const queue = [{ parent: root, edge: null }];
  const nodes = [];
  const nodesByPlacement = new Map();
  const states = new Map();
  const budget = { files: 0, bytes: 0, directories: 0 };
  let edgeCount = 0;

  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const pending = queue[cursor];
    let node = pending.parent;
    if (pending.edge != null) {
      edgeCount += 1;
      if (edgeCount > MAX_RUNTIME_DEPENDENCY_EDGES) {
        throw runtimeDependencyError(
          "Runtime dependency graph exceeded its edge bound",
          "dependency_graph_edge_bound_exceeded",
        );
      }
      const resolved = resolveRuntimeDependencySource({
        parent: pending.parent,
        boundary,
        packageName: pending.edge.name,
        expectedUid: sourceUid,
        guard: sourceGuard,
      });
      if (!resolved) {
        if (pending.edge.optional) continue;
        throw runtimeDependencyError(
          `Runtime dependency ${pending.edge.name} is missing; run npm install before installing Bob into a project`,
          pending.edge.kind === "peer_dependency"
            ? "required_peer_dependency_missing"
            : "required_dependency_missing",
        );
      }
      resolutionRoots.add(resolved.searchRoot);
      const destination = path.join(
        resolved.destinationRoot,
        ...pending.edge.name.split("/"),
      );
      const priorSource = nodesByPlacement.get(destination);
      if (priorSource !== undefined && priorSource !== resolved.sourceDir) {
        throw runtimeDependencyError(
          `Runtime dependency ${pending.edge.name} conflicts at its relocated path`,
          "dependency_placement_conflict",
        );
      }
      const context = childResolutionContext(pending.parent, resolved, destination);
      const stateKey = `${resolved.sourceDir}\0${destination}`;
      const priorState = states.get(stateKey);
      if (priorState) {
        if (!compareResolutionContexts(
          priorState.resolutionContext,
          context,
          resolved.sourceDir,
          boundary,
        )) {
          throw runtimeDependencyError(
            `Runtime dependency ${pending.edge.name} has incompatible resolution contexts`,
            "dependency_path_context_conflict",
          );
        }
        continue;
      }
      const manifestRecord = readRuntimeDependencyManifest(
        resolved.sourceDir,
        pending.edge.name,
        sourceUid,
        sourceGuard,
      );
      const tree = inspectRuntimeDependencyTree({
        packageRoot: resolved.sourceDir,
        sourceUid,
        sourceGuard,
        budget,
        manifestRecord,
      });
      const manifestFile = tree.files.find((file) => file.relative === "package.json");
      if (!manifestFile
          || manifestFile.sha256 !== manifestRecord.record.sha256
          || !sameRuntimeDependencyFileSnapshot(
            manifestFile.snapshot,
            manifestRecord.record.snapshot,
          )) {
        throw runtimeDependencyError(
          `Runtime dependency ${pending.edge.name} manifest changed during graph preflight`,
          "package_manifest_substituted",
        );
      }
      node = Object.freeze({
        sourceDir: resolved.sourceDir,
        destination,
        manifestRecord,
        resolutionContext: context,
        tree,
      });
      states.set(stateKey, node);
      nodesByPlacement.set(destination, resolved.sourceDir);
      nodes.push(node);
      if (nodes.length > MAX_RUNTIME_DEPENDENCY_PACKAGES) {
        throw runtimeDependencyError(
          "Runtime dependency graph exceeded its package bound",
          "dependency_graph_package_bound_exceeded",
        );
      }
    }

    for (const edge of runtimeDependencyEdges(node.manifestRecord.manifest)) {
      queue.push({ parent: node, edge });
    }
  }
  return Object.freeze({
    boundary,
    rootManifest,
    nodes: Object.freeze(nodes),
    resolutionRoots: Object.freeze(Array.from(resolutionRoots).sort()),
    file_count: budget.files,
    byte_count: budget.bytes,
  });
}

function revalidateRuntimeDependencyGraph(graph, sourceUid, sourceGuard) {
  const manifests = [graph.rootManifest, ...graph.nodes.map((node) => node.manifestRecord)];
  for (const manifest of manifests) {
    let observed;
    try {
      observed = snapshotRuntimeDependencyFile({
        source: manifest.record.source,
        expectedUid: sourceUid,
        sourceGuard,
        maxBytes: MAX_RUNTIME_DEPENDENCY_MANIFEST_BYTES,
      });
    } catch (error) {
      if (!error || error.code !== "runtime_dependency_source_rejected") throw error;
      throw runtimeDependencyError(
        "Runtime dependency manifest changed after graph preflight",
        "package_manifest_substituted",
      );
    }
    if (observed.sha256 !== manifest.record.sha256
        || !sameRuntimeDependencyFileSnapshot(observed.snapshot, manifest.record.snapshot)) {
      throw runtimeDependencyError(
        "Runtime dependency manifest changed after graph preflight",
        "package_manifest_substituted",
      );
    }
  }
  for (const node of graph.nodes) {
    for (const directory of node.tree.directories) {
      let observed;
      let names;
      try {
        observed = fs.lstatSync(directory.source);
        names = fs.readdirSync(directory.source).sort();
      } catch {
        throw runtimeDependencyError(
          "Runtime dependency tree changed after graph preflight",
          "package_tree_substituted",
        );
      }
      if (!sameRuntimeDependencyDirectorySnapshot(observed, directory.snapshot)
          || JSON.stringify(names) !== JSON.stringify(directory.names)) {
        throw runtimeDependencyError(
          "Runtime dependency tree changed after graph preflight",
          "package_tree_substituted",
        );
      }
    }
    for (const file of node.tree.files) {
      let observed;
      try {
        observed = fs.lstatSync(file.source);
      } catch {
        throw runtimeDependencyError(
          "Runtime dependency file changed after graph preflight",
          "package_file_substituted",
        );
      }
      if (!sameRuntimeDependencyFileSnapshot(observed, file.snapshot)) {
        throw runtimeDependencyError(
          "Runtime dependency file changed after graph preflight",
          "package_file_substituted",
        );
      }
    }
  }
  try {
    sourceGuard.revalidate();
  } catch {
    throw runtimeDependencyError(
      "Runtime dependency source ancestry changed after graph preflight",
      "source_ancestry_substituted",
    );
  }
}

function assertRuntimeDependencyTargetPreflight({
  mcpDir,
  targetNodeModules,
  graph,
  sourceRoot,
  allowMissingMcpDir = false,
}) {
  let targetStat;
  let targetAnchor = mcpDir;
  try {
    targetStat = fs.lstatSync(mcpDir);
  } catch (error) {
    if (!error || error.code !== "ENOENT" || allowMissingMcpDir !== true) {
      throw runtimeDependencyTargetError(
        "Runtime dependency target root was rejected",
        "target_root_unreadable",
      );
    }
    let current = path.dirname(mcpDir);
    for (let count = 0; count <= MAX_RUNTIME_DEPENDENCY_ANCESTORS; count += 1) {
      try {
        targetStat = fs.lstatSync(current);
        targetAnchor = current;
        break;
      } catch (anchorError) {
        if (!anchorError || anchorError.code !== "ENOENT") {
          throw runtimeDependencyTargetError(
            "Runtime dependency target ancestry was rejected",
            "target_ancestry_unreadable",
          );
        }
      }
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
    if (!targetStat) {
      throw runtimeDependencyTargetError(
        "Runtime dependency target ancestry exceeded its bound",
        "target_ancestor_bound_exceeded",
      );
    }
  }
  if (!targetStat.isDirectory() || targetStat.isSymbolicLink()) {
    throw runtimeDependencyTargetError(
      "Runtime dependency target root was rejected",
      "target_root_nonregular",
    );
  }
  const targetUid = Number.isInteger(targetStat.uid) ? targetStat.uid : null;
  if (targetAnchor === mcpDir) {
    try {
      const existing = fs.lstatSync(targetNodeModules);
      if (!existing.isDirectory() || existing.isSymbolicLink()
          || (Number.isInteger(targetUid) && Number.isInteger(existing.uid)
            && existing.uid !== targetUid)) {
        throw runtimeDependencyTargetError(
          "Runtime dependency target node_modules was rejected",
          "target_ancestry_unowned_or_nonregular",
        );
      }
    } catch (error) {
      if (error && error.code === "runtime_dependency_target_rejected") throw error;
      if (!error || error.code !== "ENOENT") {
        throw runtimeDependencyTargetError(
          "Runtime dependency target node_modules was unreadable",
          "target_ancestry_unreadable",
        );
      }
    }
    for (const destination of new Set(graph.nodes.map((node) => node.destination))) {
      assertDirectRuntimeDependencyDestination(
        targetNodeModules,
        destination,
        targetUid,
      );
    }
  }

  const sourcePaths = [
    sourceRoot,
    ...graph.nodes.map((node) => node.sourceDir),
    ...graph.resolutionRoots,
  ];
  let realTarget = targetNodeModules;
  try {
    const realAnchor = fs.realpathSync.native(targetAnchor);
    realTarget = path.join(
      realAnchor,
      path.relative(targetAnchor, mcpDir),
      "node_modules",
    );
  } catch {
    // The existing anchor was lstat-validated; lexical overlap checks remain.
  }
  for (const sourcePath of sourcePaths) {
    let realSource = sourcePath;
    try {
      realSource = fs.realpathSync.native(sourcePath);
    } catch {
      // Source graph validation reports unreadable source paths separately.
    }
    if (pathsOverlap(targetNodeModules, sourcePath) || pathsOverlap(realTarget, realSource)) {
      throw runtimeDependencyTargetError(
        "Runtime dependency source and target trees overlap",
        "source_target_overlap",
      );
    }
  }
  return targetUid;
}

function runtimeDependencyDestinationDepth(destination) {
  return destination.split(path.sep).filter(Boolean).length;
}

function assertDirectRuntimeDependencyDestination(targetNodeModules, destination, targetUid) {
  const components = destination.split(path.sep).filter(Boolean);
  let current = targetNodeModules;
  for (let index = 0; index < components.length; index += 1) {
    current = path.join(current, components[index]);
    let stat;
    try {
      stat = fs.lstatSync(current);
    } catch (error) {
      if (error && error.code === "ENOENT") return null;
      throw runtimeDependencyTargetError(
        "Runtime dependency destination was unreadable",
        "target_destination_unreadable",
      );
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()
        || (Number.isInteger(targetUid) && Number.isInteger(stat.uid)
          && stat.uid !== targetUid)) {
      throw runtimeDependencyTargetError(
        "Runtime dependency destination ancestry was rejected",
        "target_destination_nonregular",
      );
    }
  }
  return current;
}

function removeDirectRuntimeDependencyDestination(targetNodeModules, destination, targetUid) {
  const current = assertDirectRuntimeDependencyDestination(
    targetNodeModules,
    destination,
    targetUid,
  );
  if (current == null) return;
  try {
    fs.rmSync(current, { recursive: true, force: true });
  } catch {
    throw runtimeDependencyTargetError(
      "Runtime dependency destination replacement failed",
      "target_destination_remove_failed",
    );
  }
}

function ensureDirectRuntimeDependencyTargetDirectory(directoryPath, targetUid) {
  try {
    fs.mkdirSync(directoryPath, { recursive: true, mode: 0o755 });
    const stat = fs.lstatSync(directoryPath);
    if (!stat.isDirectory() || stat.isSymbolicLink()
        || (Number.isInteger(targetUid) && Number.isInteger(stat.uid) && stat.uid !== targetUid)) {
      throw new Error("nonregular");
    }
  } catch {
    throw runtimeDependencyTargetError(
      "Runtime dependency target directory was rejected during direct copy",
      "target_directory_rejected",
    );
  }
}

function copyStableRuntimeDependencyFile({
  file,
  destination,
  expectedUid,
  sourceGuard,
}) {
  const sourceFlags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  let sourceDescriptor;
  let destinationDescriptor;
  let destinationCreated = false;
  try {
    const before = fs.lstatSync(file.source);
    if (!sameRuntimeDependencyFileSnapshot(before, file.snapshot)) {
      throw runtimeDependencyError(
        "Runtime dependency file changed before direct copy",
        "package_file_substituted",
      );
    }
    sourceDescriptor = fs.openSync(file.source, sourceFlags);
    const opened = fs.fstatSync(sourceDescriptor);
    if (!opened.isFile() || !sameRuntimeDependencyFileSnapshot(before, opened)
        || (Number.isInteger(expectedUid) && Number.isInteger(opened.uid)
          && opened.uid !== expectedUid)) {
      throw runtimeDependencyError(
        "Runtime dependency file changed while opening for direct copy",
        "package_file_substituted",
      );
    }
    sourceGuard.revalidate();
    destinationDescriptor = fs.openSync(
      destination,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
        | (fs.constants.O_NOFOLLOW || 0),
      opened.mode & 0o777,
    );
    destinationCreated = true;
    const hash = file.sha256 == null ? null : crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let total = 0;
    for (;;) {
      const bytesRead = fs.readSync(sourceDescriptor, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      const nextTotal = total + bytesRead;
      if (nextTotal > file.snapshot.size
          || nextTotal > MAX_RUNTIME_DEPENDENCY_FILE_BYTES) {
        throw runtimeDependencyError(
          "Runtime dependency file exceeded its preflight size during direct copy",
          "package_file_bound_exceeded",
        );
      }
      if (hash) hash.update(buffer.subarray(0, bytesRead));
      let written = 0;
      while (written < bytesRead) {
        written += fs.writeSync(
          destinationDescriptor,
          buffer,
          written,
          bytesRead - written,
          null,
        );
      }
      total = nextTotal;
    }
    const afterDescriptor = fs.fstatSync(sourceDescriptor);
    const afterPath = fs.lstatSync(file.source);
    if (total !== opened.size || (hash && hash.digest("hex") !== file.sha256)
        || !sameRuntimeDependencyFileSnapshot(opened, afterDescriptor)
        || !sameRuntimeDependencyFileSnapshot(afterDescriptor, afterPath)) {
      throw runtimeDependencyError(
        "Runtime dependency file changed during direct copy",
        "package_file_substituted",
      );
    }
    fs.fchmodSync(destinationDescriptor, opened.mode & 0o777);
    sourceGuard.revalidate();
  } catch (error) {
    if (destinationDescriptor !== undefined) {
      try {
        fs.closeSync(destinationDescriptor);
      } catch {
        // Direct copy is already failing and is explicitly not crash-atomic.
      }
      destinationDescriptor = undefined;
    }
    if (destinationCreated) {
      try {
        fs.rmSync(destination, { force: true });
      } catch {
        // Remove only the incomplete file; never claim rollback of the closure.
      }
    }
    if (error && (error.code === "runtime_dependency_source_rejected"
        || error.code === "runtime_dependency_target_rejected")) throw error;
    throw runtimeDependencyTargetError(
      "Runtime dependency target file copy failed",
      "target_file_copy_failed",
    );
  } finally {
    if (destinationDescriptor !== undefined) fs.closeSync(destinationDescriptor);
    if (sourceDescriptor !== undefined) fs.closeSync(sourceDescriptor);
  }
}

function closeRuntimeNodeDependencyCopyPlan(plan) {
  if (!plan || plan.closed === true) return;
  plan.closed = true;
  plan.sourceGuard.close();
}

function prepareRuntimeNodeDependencyCopy(sourceRoot, mcpDir) {
  const absoluteSourceRoot = path.resolve(sourceRoot);
  const absoluteMcpDir = path.resolve(mcpDir);
  let sourceStat;
  try {
    sourceStat = fs.lstatSync(absoluteSourceRoot);
  } catch {
    throw runtimeDependencyError(
      "Runtime dependency source root was rejected",
      "source_root_unreadable",
    );
  }
  if (!sourceStat.isDirectory() || sourceStat.isSymbolicLink()) {
    throw runtimeDependencyError(
      "Runtime dependency source root was rejected",
      "source_root_nonregular",
    );
  }
  const expectedUid = Number.isInteger(sourceStat.uid) ? sourceStat.uid : null;
  const boundary = runtimeDependencyResolutionBoundary(absoluteSourceRoot);
  let sourceGuard;
  try {
    sourceGuard = retainDirectoryAncestry(
      boundary,
      "runtime_dependency_source_ancestry_rejected",
    );
    assertRuntimeDependencyDirectory(boundary, expectedUid, sourceGuard, { retain: true });
    if (boundary !== absoluteSourceRoot) {
      let current = absoluteSourceRoot;
      for (let count = 0; count <= MAX_RUNTIME_DEPENDENCY_ANCESTORS; count += 1) {
        assertRuntimeDependencyDirectory(current, expectedUid, sourceGuard, { retain: true });
        if (current === boundary) break;
        current = path.dirname(current);
      }
    }

    // This entire graph, every required peer, each relocation, and all source
    // file snapshots are established before any caller-authorized mutation.
    const graph = buildRuntimeDependencyGraph({
      sourceRoot: absoluteSourceRoot,
      sourceUid: expectedUid,
      sourceGuard,
      boundary,
    });
    const targetNodeModules = path.join(absoluteMcpDir, "node_modules");
    assertRuntimeDependencyTargetPreflight({
      mcpDir: absoluteMcpDir,
      targetNodeModules,
      graph,
      sourceRoot: absoluteSourceRoot,
      allowMissingMcpDir: true,
    });
    revalidateRuntimeDependencyGraph(graph, expectedUid, sourceGuard);
    return {
      closed: false,
      sourceRoot: absoluteSourceRoot,
      mcpDir: absoluteMcpDir,
      targetNodeModules,
      expectedUid,
      sourceGuard,
      graph,
    };
  } catch (error) {
    let rejected = error;
    if (error && error.code === "optional_provider_package_rejected") {
      rejected = runtimeDependencyError(
        "Runtime dependency source ancestry changed during installation",
        "source_ancestry_substituted",
      );
    }
    if (sourceGuard) sourceGuard.close();
    throw rejected;
  }
}

function applyRuntimeNodeDependencyCopy(plan) {
  if (!plan || plan.closed === true || !plan.sourceGuard || !plan.graph) {
    throw runtimeDependencyError(
      "Runtime dependency copy plan was rejected",
      "dependency_copy_plan_rejected",
    );
  }
  try {
    const targetUid = assertRuntimeDependencyTargetPreflight({
      mcpDir: plan.mcpDir,
      targetNodeModules: plan.targetNodeModules,
      graph: plan.graph,
      sourceRoot: plan.sourceRoot,
      allowMissingMcpDir: false,
    });
    revalidateRuntimeDependencyGraph(plan.graph, plan.expectedUid, plan.sourceGuard);

    // Deliberately direct and non-atomic: this portable JS installer has no
    // descriptor-relative target authority, rollback guarantee, or same-UID
    // race qualification. It replaces only dependency destinations in this
    // graph, preserving foreign packages and .bin; stale entries that no longer
    // appear in the graph are not pruned. Doctor reports each limitation.
    ensureDirectRuntimeDependencyTargetDirectory(plan.targetNodeModules, targetUid);
    const destinations = Array.from(new Set(plan.graph.nodes.map((node) => node.destination)))
      .sort((left, right) => (
        runtimeDependencyDestinationDepth(left) - runtimeDependencyDestinationDepth(right)
        || left.localeCompare(right)
      ));
    for (const destination of destinations) {
      removeDirectRuntimeDependencyDestination(
        plan.targetNodeModules,
        destination,
        targetUid,
      );
    }

    const copied = [];
    const nodes = [...plan.graph.nodes].sort((left, right) => (
      runtimeDependencyDestinationDepth(left.destination)
        - runtimeDependencyDestinationDepth(right.destination)
      || left.destination.localeCompare(right.destination)
    ));
    for (const node of nodes) {
      const destinationDir = path.join(plan.targetNodeModules, node.destination);
      ensureDirectRuntimeDependencyTargetDirectory(destinationDir, targetUid);
      for (const directory of node.tree.directories) {
        if (!directory.relative) continue;
        ensureDirectRuntimeDependencyTargetDirectory(
          path.join(destinationDir, directory.relative),
          targetUid,
        );
      }
      for (const file of node.tree.files) {
        const destination = path.join(destinationDir, file.relative);
        ensureDirectRuntimeDependencyTargetDirectory(path.dirname(destination), targetUid);
        copyStableRuntimeDependencyFile({
          file,
          destination,
          expectedUid: plan.expectedUid,
          sourceGuard: plan.sourceGuard,
        });
        copied.push(path.join(node.destination, file.relative));
      }
    }
    return copied;
  } finally {
    closeRuntimeNodeDependencyCopyPlan(plan);
  }
}

function copyRuntimeNodeDependencies(sourceRoot, mcpDir) {
  const plan = prepareRuntimeNodeDependencyCopy(sourceRoot, mcpDir);
  try {
    return applyRuntimeNodeDependencyCopy(plan);
  } finally {
    closeRuntimeNodeDependencyCopyPlan(plan);
  }
}

// Plane-PH runtime modules deliberately live in nested packages beside mcp/;
// several MCP modules resolve them through relative imports. The npm tarball
// already admits only each package's package.json, declared root entrypoints,
// and flat lib/*.js runtime files. Project-local installation must reproduce
// that exact surface or an installed server fails during eager tool-registry
// loading. Reuse package-policy as the single file-admission authority instead
// of maintaining a second, drifting installer allowlist.
function readCanonicalSourceFile(sourceDir, sourcePath, guard) {
  const relative = path.relative(sourceDir, sourcePath);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Canonical runtime source escaped its package root");
  }
  let current = sourceDir;
  for (const component of path.dirname(relative).split(path.sep).filter((entry) => entry !== ".")) {
    current = path.join(current, component);
    guard.add(current);
  }
  guard.revalidate();
  const before = fs.lstatSync(sourcePath);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) {
    throw new Error("Canonical runtime source contains a non-regular or linked file");
  }
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  let descriptor;
  try {
    descriptor = fs.openSync(sourcePath, flags);
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink !== 1
        || !sameFilesystemIdentity(before, opened)) {
      throw new Error("Canonical runtime source identity changed while opening");
    }
    const contents = fs.readFileSync(descriptor);
    const afterDescriptor = fs.fstatSync(descriptor);
    const afterPath = fs.lstatSync(sourcePath);
    if (!sameFilesystemIdentity(opened, afterDescriptor)
        || !sameFilesystemIdentity(afterDescriptor, afterPath)
        || afterDescriptor.size !== opened.size
        || afterDescriptor.mtimeMs !== opened.mtimeMs
        || contents.length !== opened.size) {
      throw new Error("Canonical runtime source identity changed while reading");
    }
    guard.revalidate();
    return contents;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function copyCanonicalRuntimePackagesWithAuthority(sourceRoot, targetAbs, targetAuthority) {
  const copied = [];
  for (const relativeRoot of CANONICAL_RUNTIME_PACKAGE_ROOTS) {
    const sourceDir = path.join(sourceRoot, relativeRoot);
    const targetDir = path.join(targetAbs, relativeRoot);
    if (path.resolve(sourceDir) === path.resolve(targetDir)) continue;
    let sourceGuard;
    try {
      sourceGuard = retainDirectoryAncestry(sourceDir,
        "canonical_source_ancestry_rejected");
      const admitted = sourceTreeFiles(sourceRoot, relativeRoot)
        .filter(isCanonicalRuntimePackageFile);
      sourceGuard.revalidate();
      if (!admitted.includes(`${relativeRoot}/package.json`)) {
        throw new Error(`Canonical runtime package has no admitted package.json: ${relativeRoot}`);
      }
      const files = admitted.map((file) => {
        const sourcePath = path.join(sourceRoot, ...file.split("/"));
        const contents = readCanonicalSourceFile(sourceDir, sourcePath, sourceGuard);
        return {
          path: file.slice(relativeRoot.length + 1),
          contents,
          mode: 0o644,
        };
      });
      executeLifecycleMutation(targetAuthority, {
        operation: "replace",
        selection: `canonical:${relativeRoot}`,
        files,
      });
      copied.push(...admitted);
    } catch (error) {
      if (error && error.code === "optional_provider_package_rejected") {
        throw new Error(`Canonical runtime package ancestry was rejected: ${relativeRoot}`);
      }
      throw error;
    } finally {
      if (sourceGuard) sourceGuard.close();
    }
  }
  return copied;
}

function writeFreshCanonicalPackageFile(destination, contents) {
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
    | (fs.constants.O_NOFOLLOW || 0);
  let descriptor;
  try {
    descriptor = fs.openSync(destination, flags, 0o600);
    fs.writeFileSync(descriptor, contents);
    fs.fsyncSync(descriptor);
    fs.fchmodSync(descriptor, 0o644);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

// Canonical JS runtime packages are part of the ordinary project installer,
// not optional native-provider activation. They use a preflighted, staged
// Node filesystem transaction so a missing native lifecycle custodian cannot
// make the entire Hacker Bob installer unusable. Optional/native provider
// roots remain exclusively behind the qualified custodian.
function copyCanonicalRuntimePackagesDirect(sourceRoot, targetAbs) {
  const plans = [];
  for (const relativeRoot of CANONICAL_RUNTIME_PACKAGE_ROOTS) {
    const sourceDir = path.join(sourceRoot, relativeRoot);
    const targetDir = path.join(targetAbs, relativeRoot);
    if (path.resolve(sourceDir) === path.resolve(targetDir)) continue;
    let sourceGuard;
    try {
      sourceGuard = retainDirectoryAncestry(sourceDir, "canonical_source_ancestry_rejected");
      const admitted = sourceTreeFiles(sourceRoot, relativeRoot)
        .filter(isCanonicalRuntimePackageFile);
      sourceGuard.revalidate();
      if (!admitted.includes(`${relativeRoot}/package.json`)) {
        throw new Error(`Canonical runtime package has no admitted package.json: ${relativeRoot}`);
      }
      const files = admitted.map((file) => {
        const relative = file.slice(relativeRoot.length + 1);
        if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
          throw new Error(`Canonical runtime package path escaped its root: ${file}`);
        }
        return {
          relative,
          contents: readCanonicalSourceFile(
            sourceDir,
            path.join(sourceRoot, ...file.split("/")),
            sourceGuard,
          ),
        };
      });
      sourceGuard.revalidate();
      plans.push({ relativeRoot, targetDir, admitted, files });
    } finally {
      if (sourceGuard) sourceGuard.close();
    }
  }
  if (plans.length === 0) return [];

  const targetGuard = retainDirectoryAncestry(targetAbs, "canonical_target_ancestry_rejected");
  const packagesDir = path.join(targetAbs, "packages");
  try {
    const packagesStat = (() => {
      try { return fs.lstatSync(packagesDir); } catch (error) {
        if (error && error.code === "ENOENT") return null;
        throw error;
      }
    })();
    if (packagesStat == null) fs.mkdirSync(packagesDir, { mode: 0o755 });
    else if (!packagesStat.isDirectory() || packagesStat.isSymbolicLink()) {
      throw new Error(
        "Canonical runtime package target ancestry was rejected: parent is not a retained directory",
      );
    }
    targetGuard.add(packagesDir);

    const copied = [];
    for (const plan of plans) {
      targetGuard.revalidate();
      const token = crypto.randomBytes(12).toString("hex");
      const packageName = path.basename(plan.targetDir);
      const stagingDir = path.join(packagesDir, `.bob-install-${packageName}-${token}`);
      const backupDir = path.join(packagesDir, `.bob-backup-${packageName}-${token}`);
      let priorMoved = false;
      let promoted = false;
      try {
        fs.mkdirSync(stagingDir, { mode: 0o700 });
        for (const file of plan.files) {
          const destination = path.join(stagingDir, ...file.relative.split("/"));
          const relative = path.relative(stagingDir, destination);
          if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
            throw new Error("Canonical runtime package staging path escaped its root");
          }
          fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o755 });
          writeFreshCanonicalPackageFile(destination, file.contents);
        }
        const existing = (() => {
          try { return fs.lstatSync(plan.targetDir); } catch (error) {
            if (error && error.code === "ENOENT") return null;
            throw error;
          }
        })();
        if (existing != null) {
          // WHOLESALE REPLACE. The rename below moves the whole installed root
          // into a backup slot that is rmSync'd on success, so every local
          // edit under it dies before any per-file guard could see it — the
          // same shape as the mcp/lib replace, and the same fix.
          // package-policy.js defines CANONICAL_RUNTIME_OWNED_ROOTS as
          // ["mcp/lib", ...CANONICAL_RUNTIME_PACKAGE_ROOTS]: ONE class of
          // nine, of which only mcp/lib was swept. Reuse
          // preserveBeforeTreeReplace for the other eight rather than write a
          // second sweep.
          //
          // Quiet on the clean path by construction: the sweep skips every
          // file whose bytes already equal its counterpart in the incoming
          // source tree, and every file still matching Bob's recorded digest.
          // The sibling quarantine is safe here (unlike .claude/skills): the
          // workspaces list in package.json is an explicit set of names, not a
          // packages/* glob, so a `<root>.bob-local` sibling is never resolved
          // as a package.
          // Ancestry first, ALWAYS. A hostile root swap must be detected before
          // any other decision — including before the drift refusal below.
          // Ordering matters: the refusal is newer than this check, and if it
          // runs first it MASKS the swap rejection, turning a security failure
          // into a confusing "guard disarmed" error. Caught by
          // test/optional-provider-lifecycle.test.js:2751 ("rejects a root
          // swap"), which exercises this path without a full install.
          targetGuard.revalidate();
          let vacatedByGuard = false;
          if (existing.isDirectory()) {
            // Positive control, as at the mcp/lib replace: guardBeforeTreeReplace
            // returns [] both when it preserved nothing AND when no guard is
            // armed. Refuse the destructive path rather than confuse the two.
            if (!activeInstallDriftGuard()) {
              throw new Error(
                `Refusing to replace the installed canonical runtime package ${plan.relativeRoot} with the `
                + "install drift guard disarmed: local edits under it would be destroyed with no preserved "
                + "copy and no warning.",
              );
            }
            guardBeforeTreeReplace({
              targetTree: plan.targetDir,
              sourceTree: path.join(sourceRoot, plan.relativeRoot),
              preservedTree: `${plan.targetDir}${PRESERVED_LOCAL_SUFFIX}`,
            });
          } else {
            // A regular file or a symlink where a package ROOT belongs is a
            // prior failed install or operator work by construction — Bob only
            // ever promotes a directory here — and the rename-then-rmSync below
            // destroys it just as silently as it destroyed the tree. The file
            // twin already knows how to preserve both shapes; a true return
            // means the rename already vacated the path, so there is nothing
            // left to move into the backup slot.
            vacatedByGuard = guardBeforeDelete(plan.targetDir);
          }
          if (!vacatedByGuard) {
            // The package root is an exclusively Bob-owned leaf. Rename the leaf
            // itself into the retained-parent backup slot regardless of whether
            // a prior failed/local install left a directory, file, or symlink.
            // rename(2) does not follow a leaf symlink. The parent ancestry is
            // retained and revalidated before promotion; no sibling is touched.
            fs.renameSync(plan.targetDir, backupDir);
            priorMoved = true;
          }
        }
        targetGuard.revalidate();
        fs.renameSync(stagingDir, plan.targetDir);
        promoted = true;
        // Record what was just promoted in the ownership receipt. WITHOUT this
        // the sweep above has no recorded digest to compare against, so the
        // FIRST upgrade that legitimately changes a lib/*.js would preserve
        // every changed file as "no_recorded_digest" — a sidecar for work the
        // operator never did, on every release. The same-source reinstall stays
        // quiet either way (the source-identity skip covers it); it is the
        // upgrade that needs the receipt.
        for (const file of plan.files) {
          recordInstalledFile(path.join(plan.targetDir, ...file.relative.split("/")));
        }
        targetGuard.sync();
        if (priorMoved) fs.rmSync(backupDir, { recursive: true, force: true });
        copied.push(...plan.admitted);
      } catch (error) {
        if (!promoted && priorMoved) {
          try {
            if (!fs.existsSync(plan.targetDir)) fs.renameSync(backupDir, plan.targetDir);
          } catch {
            // Preserve the original failure; a retained backup remains for
            // explicit operator recovery rather than being deleted blindly.
          }
        }
        throw error;
      } finally {
        if (!promoted) fs.rmSync(stagingDir, { recursive: true, force: true });
      }
    }
    return copied;
  } finally {
    targetGuard.close();
  }
}

function copyCanonicalRuntimePackages(sourceRoot, targetAbs, targetAuthority = null) {
  const mutations = CANONICAL_RUNTIME_PACKAGE_ROOTS.filter((relativeRoot) =>
    path.resolve(path.join(sourceRoot, relativeRoot))
      !== path.resolve(path.join(targetAbs, relativeRoot)));
  if (mutations.length === 0) return [];
  if (targetAuthority != null) {
    return copyCanonicalRuntimePackagesWithAuthority(sourceRoot, targetAbs, targetAuthority);
  }
  return copyCanonicalRuntimePackagesDirect(sourceRoot, targetAbs);
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

// Pre-v2 resource copies under .claude/. This sweep is a DELETE path like any
// other, so it routes through removeIfExists rather than calling rmSync itself
// — a file the operator edited at a legacy location is preserved-and-reported,
// not deleted outright. (It ran zero times on a modern tree, which is exactly
// why the unguarded rmSync here survived: an empty loop proves nothing.)
function removeLegacyResourceCopies(sourceRoot, targetAbs) {
  let removed = 0;
  for (const resourceSet of RESOURCE_SETS) {
    const legacyDir = path.join(targetAbs, ".claude", path.basename(resourceSet.destination));
    for (const name of sourceResourceNames(sourceRoot, resourceSet)) {
      const legacyPath = path.join(legacyDir, name);
      if (fs.existsSync(legacyPath) && fs.statSync(legacyPath).isFile()) {
        removeIfExists(legacyPath);
        removed += 1;
      }
    }
    // Skipped when a preserved sidecar still sits in the legacy directory,
    // which is correct: the operator's copy has to stay reachable.
    removeEmptyDirIfExists(legacyDir);
  }
  return removed;
}

// The delete twin of copyFile. The Claude adapter sweeps STALE_HOOK_FILES,
// LEGACY_AGENT_FILES, LEGACY_HOOK_FILES and LEGACY_BOB_COMMAND_FILES through
// this. Deleting a file the operator edited is the same destruction as
// overwriting it, so a drifted or unrecorded file is renamed aside instead —
// guardBeforeDelete returns true once the path is already vacated.
function removeIfExists(filePath) {
  if (guardBeforeDelete(filePath)) return;
  fs.rmSync(filePath, { force: true });
}

// Where a family-A DIRECTORY sweep parks the operator's copies.
//
// NOT a sibling `<dir>.bob-local`. The only family-A recursive sweep is the
// Claude adapter's legacy-skill loop, and Claude Code discovers skills by
// scanning every directory under .claude/skills for a SKILL.md — so a sibling
// would reinstate the exact stale skill the sweep exists to retire, under a
// new name. Family B reached the same conclusion for $CODEX_HOME/skills and
// answers it with ONE quarantine root at the install root mirroring the
// original layout (scripts/lib/install-fs.js preservedTreeFor). Same answer,
// same PRESERVED_LOCAL_SUFFIX spelling, here — the operator learns one word.
//
// The install root comes from the armed guard, which is the same root every
// ownership key is relative to. The sibling fallback is for the one case that
// root cannot express — a directory outside the install root — and is never
// reached from removeDirIfExists, which refuses outright when no guard is
// armed. It only has to be OUTSIDE the doomed tree, which a sibling is.
function preservedQuarantineDirFor(absDir) {
  const guard = activeInstallDriftGuard();
  const root = guard ? guard.targetAbs : null;
  if (root) {
    const relative = path.relative(root, absDir);
    if (relative && !relative.startsWith("..") && !path.isAbsolute(relative)) {
      return path.join(root, PRESERVED_LOCAL_SUFFIX, relative);
    }
  }
  return `${absDir}${PRESERVED_LOCAL_SUFFIX}`;
}

// The DIRECTORY twin of removeIfExists, injected into adapters/claude/index.js
// beside it. A recursive rmSync destroys every file under the directory before
// any per-file hook could see them, which is the same shape as the wholesale
// mcp/lib replace — so it uses the same guardBeforeTreeReplace sweep rather
// than a second one.
//
// `sourceTree` is deliberately null: a legacy directory is legacy precisely
// because the source no longer ships it, so there is nothing to compare
// against and every file that is not already in Bob's receipt is treated as
// the operator's. Idempotent, because the second install finds the directory
// gone and the sweep returns without touching anything.
function removeDirIfExists(dirPath) {
  const abs = path.resolve(dirPath);
  let stat = null;
  try {
    stat = fs.lstatSync(abs);
  } catch (error) {
    if (!error || error.code !== "ENOENT") throw error;
  }
  if (stat && stat.isDirectory()) {
    // Same positive control as the mcp/lib replace below: guardBeforeTreeReplace
    // returns [] both when it preserved nothing AND when no guard is armed —
    // identical return, opposite meanings — and the next statement is a
    // recursive delete. Refuse to run it unarmed rather than let "the guard ran
    // and found nothing" be indistinguishable from "no guard ran".
    if (!activeInstallDriftGuard()) {
      throw new Error(
        `Refusing to remove the installed directory ${abs} with the install drift guard disarmed: `
        + "local edits under it would be destroyed with no preserved copy and no warning.",
      );
    }
    guardBeforeTreeReplace({
      targetTree: abs,
      sourceTree: null,
      preservedTree: preservedQuarantineDirFor(abs),
    });
  } else if (guardBeforeDelete(abs)) {
    // Preserved instead: the rename already vacated the path, so deleting now
    // would destroy the copy that was just saved.
    return;
  }
  fs.rmSync(abs, { force: true, recursive: true });
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

function installProjectWithTargetAuthority(projectDir, options, targetAuthority) {
  const sourceRoot = path.resolve(options.sourceRoot || path.join(__dirname, ".."));
  const targetAbs = path.resolve(projectDir || ".");
  const bobResourceDir = path.join(targetAbs, BOB_RESOURCE_DIR);
  const manifest = packageManifest(sourceRoot);
  const installerSource = options.installerSource || process.env.HACKER_BOB_INSTALLER_SOURCE || "cli";
  let previousInstallMetadata = null;
  try {
    previousInstallMetadata = readNeutralInstallMetadata(targetAbs, null);
  } catch {
    // A malformed/unreadable receipt never authorizes pruning. The existing
    // metadata write path will still surface malformed JSON before completion.
    previousInstallMetadata = null;
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

  const mcpDir = path.join(targetAbs, "mcp");
  const runtimeDependencyPlan = prepareRuntimeNodeDependencyCopy(sourceRoot, mcpDir);
  const mcpTopLevelRuntimeOwnership = buildMcpTopLevelRuntimeOwnership(sourceRoot);
  // Arm the drift guard BEFORE the first mutation and disarm it in the finally
  // below, so an aborted install cannot leave an armed ambient guard behind.
  // It reads the PREVIOUS install.json for the recorded digests and collects
  // the digests of everything this run writes.
  const driftGuardSession = beginInstallDriftGuard({
    targetAbs,
    previousMetadata: previousInstallMetadata,
  });
  try {
    fs.mkdirSync(bobResourceDir, { recursive: true });

  const copiedResources = {};
  for (const resourceSet of RESOURCE_SETS) {
    copiedResources[resourceSet.name] = copyResourceSet(sourceRoot, targetAbs, resourceSet);
  }
  const copiedInstallSupportFiles = copyCanonicalInstallSupportFiles(sourceRoot, targetAbs);
  const legacyResourcesRemoved = removeLegacyResourceCopies(sourceRoot, targetAbs);

  fs.mkdirSync(mcpDir, { recursive: true });
  // Copy Bob's top-level mcp/ runtime files from the explicit MCP_TOP_LEVEL_RUNTIME_FILES manifest.
  // copyFile OVERWRITES, so a reinstall refreshes a stale prior version — that is what fixes the frozen
  // browser-driver.js this PR is about. The surrounding mcp/ root is mixed ownership, so Bob never
  // deletes other top-level files by negation. Instead, a preceding install's bounded ownership receipt
  // permits deletion of a retired Bob filename only while its bytes and filesystem identity still match;
  // operator-created or locally modified siblings survive. The manifest is the single source of truth;
  // install-smoke.test.js pins it EQUAL to the real source top-level mcp/*.js so additions/deletions
  // cannot silently drift. lib/ + its subdirs are copied separately below.
  const removedRetiredMcpTopLevelRuntimeFiles = pruneRetiredMcpTopLevelRuntimeFiles(
    targetAbs,
    previousInstallMetadata,
  );
  for (const file of MCP_TOP_LEVEL_RUNTIME_FILES) {
    copyFile(path.join(sourceRoot, "mcp", file), path.join(mcpDir, file));
  }
  fs.chmodSync(path.join(mcpDir, "server.js"), 0o755);
  // mcp/lib is a wholly Bob-owned runtime root (unlike the surrounding mcp/
  // directory, where operators may keep their own top-level files). Replace the
  // complete owned root before copying so a root module or whole subdirectory
  // removed by a newer Bob release cannot survive an upgrade and later be loaded
  // through a fixed-path dynamic require. mcp/node_modules is a sibling and is
  // intentionally untouched: the dependency copier preserves its foreign/stale
  // packages and operator-owned .bin entries under its separately disclosed
  // assurance contract. The enrolled lifecycle-custodian mutation registry has
  // no mcp/lib selection and its production helper remains deliberately
  // unavailable, so this canonical root still uses a pathname-based Node replace;
  // doctor's lifecycle-custodian check remains non-authorizing until that native
  // contract is expanded and qualified.
  const sourceLibDir = path.join(sourceRoot, "mcp", "lib");
  const targetLibDir = path.join(mcpDir, "lib");
  if (path.resolve(sourceLibDir) !== path.resolve(targetLibDir)) {
    // The rmSync below is a WHOLESALE replace, so it destroys local work
    // before any copyFile guard can see the destination. Sweep drifted or
    // unrecorded files into mcp/lib.bob-local first — OUTSIDE the root being
    // removed, or the rmSync would take the preserved copies with it. Files
    // that already match the incoming source, and files that still match
    // Bob's recorded digest (including modules a newer release drops), are
    // left for the replace exactly as before.
    // Copy .js modules plus any .sh build assets a module reads at load time
    // (e.g. repo-env.js resolves a native-fuzz build script under mcp/lib/fuzz/).
    // Dropping a load-time .sh asset crashes mcp/server.js startup the same way a
    // dropped subdir would, so the runtime-copy must carry both.
    const runtimeModulePredicate = (relative, name) => name.endsWith(".js") || name.endsWith(".sh");
    // FLOOR FIRST, before anything is destroyed. The preservation sweep below
    // cannot rescue this case by design — it skips every file still matching
    // its recorded digest — so an empty or gutted source would wipe the
    // installed runtime, preserve nothing, warn nothing, and report success.
    assertRuntimeModuleFloor(countTreeFiles(sourceLibDir, runtimeModulePredicate), {
      stage: "the shipped source",
      sourceDir: sourceLibDir,
    });
    guardBeforeTreeReplace({
      targetTree: targetLibDir,
      sourceTree: sourceLibDir,
      preservedTree: `${targetLibDir}${PRESERVED_LOCAL_SUFFIX}`,
    });
    // POSITIVE CONTROL for the sweep immediately above. guardBeforeTreeReplace
    // returns [] both when it preserved nothing AND when no guard is armed at
    // all — identical return, opposite meanings — and the next line is the most
    // destructive statement in this installer. Refuse to run it unarmed rather
    // than let "the guard ran and found nothing" be indistinguishable from "no
    // guard ran". This is also the real consumer of activeInstallDriftGuard().
    if (!activeInstallDriftGuard()) {
      throw new Error(
        "Refusing to replace the installed mcp/lib runtime with the install drift guard disarmed: "
        + "local edits under mcp/lib would be destroyed with no sidecar and no warning.",
      );
    }
    fs.rmSync(targetLibDir, { recursive: true, force: true });
    // The return value is NOT discarded: a copy that starts healthy and ends
    // short (a mid-copy failure, a source mutated underneath us) is the same
    // wiped runtime as an empty source.
    const copiedRuntimeModules = copyDirRecursive(
      sourceLibDir,
      targetLibDir,
      runtimeModulePredicate,
    );
    assertRuntimeModuleFloor(copiedRuntimeModules.length, {
      stage: "the completed copy",
      sourceDir: sourceLibDir,
    });
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
  const copiedRuntimePackageFiles = copyCanonicalRuntimePackages(
    sourceRoot,
    targetAbs,
    targetAuthority,
  );
  const copiedRuntimeDependencies = applyRuntimeNodeDependencyCopy(runtimeDependencyPlan);

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

  // Per-workspace session root. mcp/lib/engine-lock.js elects exactly ONE
  // engine per session root (the fx-gate-bypass defense), so two workspaces can
  // only run engines concurrently when their roots are DISJOINT. Resolved ONCE
  // here — before any adapter writes config — and stamped into every host's
  // config so all adapters in this workspace agree on one root.
  // Tolerant reads: these files are consulted only for an already-configured
  // root. A malformed host config is the owning adapter's error to raise (the
  // Claude adapter still throws on its own read); it must not turn an unrelated
  // adapter's install into a JSON parse crash.
  const readConfigForSessionRoot = (filePath) => {
    try {
      return readJsonIfExists(filePath, {});
    } catch {
      return {};
    }
  };
  const existingMcpConfig = readConfigForSessionRoot(path.join(targetAbs, ".mcp.json"));
  const existingKimiMcpConfig = readConfigForSessionRoot(path.join(targetAbs, ".kimi", "mcp.json"));
  const existingClaudeSettingsConfig = readConfigForSessionRoot(path.join(targetAbs, ".claude", "settings.json"));
  const defaultRootHadSessions = defaultSessionsRootHasSessions();
  const sessionRootResolution = resolveWorkspaceSessionsRoot({
    targetAbs,
    pinned: [
      pinnedSessionsRootFromMcpConfig(existingMcpConfig),
      pinnedSessionsRootFromMcpConfig(existingKimiMcpConfig),
      pinnedSessionsRootFromSettings(existingClaudeSettingsConfig),
    ],
    previouslyInstalled: !!previousInstallMetadata || existingAdapters.length > 0,
  });
  const sessionsRoot = sessionRootResolution.sessionsRoot;

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
        // The DIRECTORY twin of removeIfExists. Required, not defaulted, for
        // the same reason removeIfExists is: a fallback here would be an
        // unguarded recursive rmSync, which is the defect this injection
        // exists to close. A missing injection is a loud TypeError.
        removeDirIfExists,
        serverPath,
        sessionsRoot,
        writeJson,
        // Guarded family-A render write. Without this the adapter falls back to
        // its own bare fs.writeFileSync and the three renderer-driven command
        // files are destroyed without a sidecar or a summary line.
        writeTextFile,
      });
      // Empty-source floor on the two globbed Claude resource trees, checked
      // here rather than at the summary so the refusal lands before the run
      // claims success.
      assertClaudeResourceFloors(adapterResults[adapterId], { sourceRoot });
    } else if (adapterId === "generic-mcp") {
      adapterResults[adapterId] = adapter.install({
        sourceRoot,
        targetAbs,
        readJsonIfExists,
        serverPath,
        sessionsRoot,
      });
    } else {
      adapterResults[adapterId] = adapter.install({
        activate: options.activateCodex !== false && process.env.HACKER_BOB_CODEX_AUTO_INSTALL !== "0",
        sourceRoot,
        targetAbs,
        serverPath,
        sessionsRoot,
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
    mcpTopLevelRuntimeOwnership,
    // Every copyFile in BOTH families has run by now; install.json itself is
    // not a guarded copy, so it never appears in its own receipt.
    installedFileOwnership: driftGuardSession.guard.ownership(),
  });
  try {
    clearUpdateCache(targetAbs);
  } catch {
    // A stale update hint is cosmetic; never fail an otherwise valid install.
  }

  // 0700 so the root already satisfies the ownership/mode assertions
  // mcp/lib/paths.js and mcp/lib/engine-lock.js apply at engine boot.
  const effectiveSessionsRoot = sessionsRoot || defaultSessionsRoot();
  ensureSessionsRoot(effectiveSessionsRoot);

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
    sessionsRoot: effectiveSessionsRoot,
    sessionsRootSource: sessionRootResolution.source,
    sessionsRootDefault: defaultSessionsRoot(),
    sessionsRootCandidate: workspaceSessionsRoot(targetAbs),
    defaultSessionsRootHasSessions: defaultRootHadSessions,
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
    installSupportFiles: copiedInstallSupportFiles.length,
    legacyResourcesRemoved,
    removedRetiredMcpTopLevelRuntimeFiles,
    runtimePackageFiles: copiedRuntimePackageFiles.length,
    runtimeDependencyFiles: copiedRuntimeDependencies.length,
    patchrightAvailable: patchrightAvailable(targetAbs, sourceRoot),
    // EMPTY on the clean path, so printInstallSummary prints nothing new.
    preservedLocalFiles: driftGuardSession.guard.preservedFiles(),
    // Also EMPTY on the clean path. Non-empty means one of the guard's bounds
    // fired and protection was incomplete — printed, never swallowed.
    driftGuardWarnings: driftGuardSession.guard.warnings(),
    installedFileOwnershipCount: driftGuardSession.guard.writtenFileCount(),
    // How many records the PREVIOUS install's receipt actually yielded. Zero on
    // a first install; a sudden zero on a reinstall means the receipt was
    // rejected wholesale, which is why the guard warns about it and why the
    // tests floor this value instead of leaving the accessor unconsumed.
    driftGuardRecordedCount: driftGuardSession.guard.recordedFileCount(),
    // True when the receipt filled up and stopped recording. The operator sees
    // it as a warning line either way; this is the machine-readable form, so
    // the accessor has a consumer outside its own tests.
    driftGuardOwnershipOverflowed: driftGuardSession.guard.ownershipOverflowed(),
    };
  } finally {
    driftGuardSession.end();
    closeRuntimeNodeDependencyCopyPlan(runtimeDependencyPlan);
  }
}

function installProject(projectDir, options = {}) {
  const targetAbs = path.resolve(projectDir || ".");
  return installProjectWithTargetAuthority(targetAbs, options, null);
}

// Session-root operator notice. Each workspace gets its OWN root so two
// workspaces can run engines concurrently; the engine singleton lock still
// elects one engine per root, so a SHARED root means the second workspace is
// refused. The two cases that need operator attention are (a) this workspace
// moved off the shared default root that still holds sessions, and (b) this
// workspace stayed on the shared default root because moving would have
// orphaned those sessions.
function printSessionRootNotice(summary) {
  if (summary.sessionsRootSource === "derived" && summary.defaultSessionsRootHasSessions) {
    console.log(`    NOTE: ${summary.sessionsRootDefault}/ still holds sessions from a shared-root install.`);
    console.log("          They are NOT lost — this workspace simply no longer reads that root. Move any you still want:");
    console.log(`            mv ${summary.sessionsRootDefault}/<target-domain> ${summary.sessionsRoot}/`);
    return;
  }
  if (summary.sessionsRootSource === "shared_default") {
    console.log("    NOTE: keeping the shared default root because it still holds sessions from this install.");
    console.log("          Concurrent engines need DISJOINT roots. To give this workspace its own:");
    console.log(`            mv ${summary.sessionsRootDefault}/<target-domain> ${summary.sessionsRootCandidate}/`);
    console.log("          then re-run the installer (an empty default root resolves to the per-workspace root).");
    return;
  }
  if (summary.sessionsRootSource === "operator_pinned") {
    console.log(`    (pinned by ${SESSIONS_ROOT_ENV_VAR} in this workspace's config; operator-owned, preserved verbatim)`);
  }
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
  console.log(`  MCP runtime (mcp/{${MCP_TOP_LEVEL_RUNTIME_FILES.join(", ")}}, lib/*.js, lib/tools/*.js, nested package files ${summary.runtimePackageFiles}, dependency files ${summary.runtimeDependencyFiles})`);
  console.log("  .hacker-bob/ resources");
  console.log("  .hacker-bob/VERSION and install.json");
  console.log(`  ${summary.sessionsRoot}/  (this workspace's session root; run with --purge-legacy-session-root to remove a pre-v2.0 ~/bounty-agent-sessions/)`);
  printSessionRootNotice(summary);
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
    console.log(`Done. Restart Claude Code in ${summary.targetAbs}, then run against an authorized target: /bob-evaluate <authorized-target>`);
  } else if (summary.adapters.length === 1 && summary.adapters[0] === "codex") {
    console.log(`Done. Restart Codex in ${summary.targetAbs}, then run against an authorized target: $bob-evaluate <authorized-target>`);
  } else if (summary.adapters.length === 1 && summary.adapters[0] === "generic-mcp") {
    console.log(`Done. Connect your MCP host to ${path.join(summary.targetAbs, "mcp", "server.js")} and read .hacker-bob/generic-mcp/hacker-bob.md.`);
  } else if (summary.adapters.length === 1 && summary.adapters[0] === "kimi") {
    console.log(`Done. Launch Kimi from ${summary.targetAbs} with: kimi --mcp-config-file .kimi/mcp.json  (Kimi does not auto-discover .kimi/mcp.json, so this flag is mandatory), then run against an authorized target: /skill:bob-evaluate <authorized-target>`);
  } else {
    console.log(`Done. Restart the selected host CLIs in ${summary.targetAbs} before continuing.`);
  }
  // LAST THING THIS FUNCTION PRINTS. A warning the operator scrolls past is
  // nearly as bad as no warning, so the preserved-file notice comes after
  // "Done." and after every optional tool hint. NOT literally the final line on
  // screen on every path: `bin/hacker-bob.js` prints its own epilogue after
  // calling printInstallSummary ("Update complete. Fully restart Claude
  // Code…", plus an optional --purge-legacy-session-root report), so the notice
  // is last within the summary, not last within the process. Prints NOTHING
  // when nothing was preserved, which is the clean path.
  for (const line of formatPreservedSummary(summary.preservedLocalFiles, summary.driftGuardWarnings)) {
    console.log(line);
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
  copyCanonicalRuntimePackages,
  copyRuntimeNodeDependencies,
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
  // Exported so the disarmed-guard refusal inside it is DIRECTLY testable.
  // The refusal is the only thing standing between a recursive rmSync and an
  // unprotected tree, and a guard whose failure mode is untested is a guard
  // nobody has checked.
  removeDirIfExists,
  resolveInstallAdapters,
  writeNeutralInstallMetadata,
};
