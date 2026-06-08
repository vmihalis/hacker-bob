"use strict";

// Cycle O.1 of Plane O: repo-bound target axis. This module owns the
// SessionNucleus and state.json initialization path for OSS sessions.
// A repo session derives its `target_domain` from the absolute repo
// path so reopening the same checkout from any working directory
// always lands on the same session.
//
// Plane O invariant O-P1 (local-repo first) is enforced via
// governance-contracts.assertRepoRootPath: the path must exist as a
// local directory before binding. No clone-from-remote happens here.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const {
  assertBoolean,
  assertNonEmptyString,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertSafeDomain,
  repoChecksJsonlPath,
  repoInventoryPath,
  sessionDir,
  sessionNucleusPath,
  statePath,
} = require("./paths.js");
const {
  buildSessionNucleus,
  normalizeTargetRepo,
} = require("./governance-contracts.js");
const {
  resolveEgressProfile,
} = require("./egress-profiles.js");
const {
  buildInitialSessionState,
  egressProfileStateFields,
  deriveBlockInternalHostsPolicy,
} = require("./session-state-contracts.js");
const {
  appendJsonlLine,
  isSessionDirEffectivelyEmpty,
  withSessionLock,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  hashDocumentExcluding,
  writeJsonDocument,
} = require("./fabric-common.js");
const {
  writeSessionStateDocument,
} = require("./session-state-store.js");
const {
  readSessionNucleus,
} = require("./governance-store.js");
const {
  appendSessionEvent,
} = require("./session-events.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-events.js");
const {
  buildGovernanceContextFromNucleus,
} = require("./governance-context.js");
const {
  appendFrontierEvent,
} = require("./frontier-events.js");
const {
  scheduleMaterialization,
} = require("./frontier-materialize-debounce.js");
const {
  redactTextSensitiveValues,
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");
const {
  classifyRepoReachability,
} = require("./reachability.js");
const {
  NATIVE_SOURCE_EXTENSIONS,
} = require("./native-extensions.js");

// Cycle O.1: SAFE_NAME_PATTERN keeps the basename safe for the
// target_domain slug. Any character outside `[A-Za-z0-9._-]` is folded
// to a single dash; leading/trailing dashes are trimmed. Empty
// basenames (e.g. trailing slash on root) fall back to "repo".
function safeBasename(value) {
  const base = path.basename(value || "").trim();
  if (!base) return "repo";
  const folded = base.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return folded || "repo";
}

function sha8(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 8);
}

function sha64(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function deriveRepoTargetDomain(realpathValue) {
  const name = safeBasename(realpathValue);
  return `repo-${name}-${sha8(realpathValue)}`;
}

function deriveRepoHashFromPath(realpathValue) {
  // Stable 64-hex digest of the canonical path. Trimmed to 64 chars so
  // it shares the validation envelope with explicit git commit hashes
  // (which can be 40 hex chars).
  return sha64(realpathValue);
}

// Translate a friendly error code from assertRepoRootPath into a
// structured ToolError so callers (bob_init_repo_session) surface the
// repo_path_not_found / repo_path_not_directory contract explicitly.
function repoPathError(error) {
  if (error && error.code === "repo_path_not_found") {
    return new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || "repo path not found", {
      repo_error_code: "repo_path_not_found",
    });
  }
  if (error && error.code === "repo_path_not_directory") {
    return new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || "repo path is not a directory", {
      repo_error_code: "repo_path_not_directory",
    });
  }
  return null;
}

const GIT_REF_MAX_CHARS = 120;
const HEX_REF_RE = /^[0-9a-f]{7,64}$/i;
const FULL_HEX_OBJECT_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;
const LOCAL_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$/;
const AMBIGUOUS_OBJECT_PREFIX = Symbol("ambiguous-object-prefix");

function gitMetadataError(message, repoErrorCode, details = {}) {
  return new ToolError(ERROR_CODES.INVALID_ARGUMENTS, message, {
    repo_error_code: repoErrorCode,
    ...details,
  });
}

function normalizeHistoryRef(ref, fieldName = "checkout.ref") {
  const normalized = assertNonEmptyString(ref, fieldName);
  if (normalized.length > GIT_REF_MAX_CHARS) {
    throw gitMetadataError(
      `${fieldName} must be at most ${GIT_REF_MAX_CHARS} characters`,
      "invalid_differential_ref",
    );
  }
  if (HEX_REF_RE.test(normalized)) return normalized;
  if (!LOCAL_REF_RE.test(normalized)
      || normalized.includes("..")
      || normalized.includes("//")
      || normalized.includes("@{")
      || normalized.endsWith("/")
      || normalized.endsWith(".")
      || normalized.endsWith(".lock")) {
    throw gitMetadataError(
      `${fieldName} must be a 7-64 hex object prefix or safe local git ref`,
      "invalid_differential_ref",
    );
  }
  return normalized;
}

function pathContains(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === "" || (!!relative && !relative.startsWith("..") && !path.isAbsolute(relative));
}

function realpathIfPossible(filePath) {
  try {
    return fs.realpathSync(filePath);
  } catch {
    return path.resolve(filePath);
  }
}

function gitMetadataErrorForEscape(message, details = {}) {
  return gitMetadataError(message, "repo_git_metadata_outside_repo", details);
}

function gitMetadataFilePath(baseDir, relPath) {
  const filePath = gitRelativePath(baseDir, relPath);
  if (!filePath || !fs.existsSync(filePath)) return null;
  const baseReal = realpathIfPossible(baseDir);
  const lstat = fs.lstatSync(filePath);
  if (lstat.isSymbolicLink()) {
    throw gitMetadataErrorForEscape(
      `git metadata file must not be a symlink: ${filePath}`,
      { git_metadata_path: filePath },
    );
  }
  const real = realpathIfPossible(filePath);
  if (!pathContains(baseReal, real)) {
    throw gitMetadataErrorForEscape(
      `git metadata file resolves outside its metadata boundary: ${real}`,
      { git_metadata_path: real },
    );
  }
  if (!fs.statSync(real).isFile()) return null;
  return real;
}

function readGitMetadataFile(baseDir, relPath) {
  const filePath = gitMetadataFilePath(baseDir, relPath);
  if (!filePath) return null;
  const raw = fs.readFileSync(filePath, "utf8").trim();
  return raw || null;
}

function standardSiblingWorktreeBoundary(repoRootReal, candidateReal) {
  const parentReal = path.dirname(repoRootReal);
  if (!pathContains(parentReal, candidateReal)) return null;
  const parts = path.relative(parentReal, candidateReal).split(path.sep);
  const gitIndex = parts.indexOf(".git");
  if (gitIndex < 1) return null;
  if (parts[gitIndex + 1] !== "worktrees") return null;
  if (parts.length !== gitIndex + 3) return null;
  const rawReverseGitDir = readGitMetadataFile(candidateReal, "gitdir");
  if (!rawReverseGitDir) return null;
  const reverseGitDir = realpathIfPossible(path.resolve(candidateReal, rawReverseGitDir));
  if (reverseGitDir !== realpathIfPossible(path.join(repoRootReal, ".git"))) return null;
  return { parentReal };
}

function assertGitDirBoundary(repoRoot, gitDir) {
  const repoRootReal = realpathIfPossible(repoRoot);
  const gitDirReal = realpathIfPossible(gitDir);
  if (pathContains(repoRootReal, gitDirReal)) {
    return { path: gitDirReal, kind: "embedded" };
  }
  const siblingWorktree = standardSiblingWorktreeBoundary(repoRootReal, gitDirReal);
  if (siblingWorktree) {
    return { path: gitDirReal, kind: "sibling_worktree", parentReal: siblingWorktree.parentReal };
  }
  throw gitMetadataError(
    `.git gitdir pointer resolves outside the repo/worktree metadata boundary: ${gitDirReal}`,
    "repo_git_metadata_outside_repo",
    { git_dir: gitDirReal },
  );
}

function assertCommonGitDirBoundary(repoRoot, commonDir, gitBoundary) {
  const repoRootReal = realpathIfPossible(repoRoot);
  const commonDirReal = realpathIfPossible(commonDir);
  if (pathContains(repoRootReal, commonDirReal)) return commonDirReal;
  if (gitBoundary.kind === "sibling_worktree") {
    const parts = path.relative(gitBoundary.parentReal, commonDirReal).split(path.sep);
    if (parts.length === 2 && parts[1] === ".git") return commonDirReal;
  }
  throw gitMetadataError(
    `commondir resolves outside the repo/worktree metadata boundary: ${commonDirReal}`,
    "repo_git_metadata_outside_repo",
    { common_git_dir: commonDirReal },
  );
}

function resolveGitFilePointer(repoRoot, dotGitPath) {
  const content = fs.readFileSync(dotGitPath, "utf8").trim();
  const match = content.match(/^gitdir:\s*(.+)$/i);
  if (!match) {
    throw gitMetadataError(
      `.git file is not a gitdir pointer: ${dotGitPath}`,
      "repo_git_metadata_invalid",
    );
  }
  const rawGitDir = match[1].trim();
  return path.resolve(repoRoot, rawGitDir);
}

function resolveCommonGitDir(gitDir) {
  const raw = readGitMetadataFile(gitDir, "commondir");
  if (!raw) return gitDir;
  return path.resolve(gitDir, raw);
}

function detectGitObjectFormat(gitDir, commonDir) {
  for (const base of [gitDir, commonDir]) {
    const raw = readGitMetadataFile(base, "config");
    if (!raw) continue;
    const match = raw.match(/^\s*objectformat\s*=\s*(sha1|sha256)\s*$/mi);
    if (match) return match[1].toLowerCase();
  }
  return "sha1";
}

function resolveGitDirectories(repoRoot) {
  const dotGitPath = path.join(repoRoot, ".git");
  if (!fs.existsSync(dotGitPath)) {
    throw gitMetadataError(
      `repo is missing .git metadata: ${repoRoot}`,
      "repo_git_metadata_missing",
    );
  }
  const stat = fs.lstatSync(dotGitPath);
  if (stat.isSymbolicLink()) {
    throw gitMetadataErrorForEscape(
      `.git metadata path must not be a symlink: ${dotGitPath}`,
      { git_metadata_path: dotGitPath },
    );
  }
  const gitBoundary = stat.isDirectory()
    ? { path: realpathIfPossible(dotGitPath), kind: "embedded" }
    : assertGitDirBoundary(repoRoot, resolveGitFilePointer(repoRoot, dotGitPath));
  const gitDir = gitBoundary.path;
  if (!fs.existsSync(gitDir) || !fs.statSync(gitDir).isDirectory()) {
    throw gitMetadataError(
      `gitdir does not exist for repo: ${gitDir}`,
      "repo_git_metadata_missing",
    );
  }
  const commonDir = assertCommonGitDirBoundary(repoRoot, resolveCommonGitDir(gitDir), gitBoundary);
  if (!fs.existsSync(commonDir) || !fs.statSync(commonDir).isDirectory()) {
    throw gitMetadataError(
      `commondir does not exist for repo: ${commonDir}`,
      "repo_git_metadata_missing",
    );
  }
  return { gitDir, commonDir, objectFormat: detectGitObjectFormat(gitDir, commonDir) };
}

function gitRelativePath(baseDir, relPath) {
  const resolved = path.resolve(baseDir, relPath);
  const root = `${path.resolve(baseDir)}${path.sep}`;
  if (resolved !== path.resolve(baseDir) && !resolved.startsWith(root)) return null;
  return resolved;
}

function refNameCandidates(ref) {
  if (ref === "HEAD") return ["HEAD"];
  if (ref.startsWith("refs/")) return [ref];
  return [
    `refs/heads/${ref}`,
    `refs/tags/${ref}`,
    `refs/remotes/${ref}`,
  ];
}

function readLooseRefValue(baseDir, refName) {
  return readGitMetadataFile(baseDir, refName);
}

function packedRefObject(ref, { gitDir, commonDir }) {
  const names = new Set(refNameCandidates(ref));
  for (const packedRefsPath of [path.join(gitDir, "packed-refs"), path.join(commonDir, "packed-refs")]) {
    const raw = readGitMetadataFile(path.dirname(packedRefsPath), path.basename(packedRefsPath));
    if (!raw) continue;
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("^")) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2 && names.has(parts[1]) && FULL_HEX_OBJECT_RE.test(parts[0])) return parts[0];
    }
  }
  return null;
}

function resolveRefToObject(ref, gitDirs, seen = new Set()) {
  if (seen.has(ref)) return null;
  seen.add(ref);
  for (const candidate of refNameCandidates(ref)) {
    for (const base of [gitDirs.gitDir, gitDirs.commonDir]) {
      const value = readLooseRefValue(base, candidate);
      if (!value) continue;
      if (value.startsWith("ref:")) {
        const targetRef = value.slice(4).trim();
        const resolved = resolveRefToObject(targetRef, gitDirs, seen);
        if (resolved) return resolved;
        continue;
      }
      if (FULL_HEX_OBJECT_RE.test(value)) return value;
    }
  }
  return packedRefObject(ref, gitDirs);
}

function looseObjectForPrefix(hexRef, commonDir) {
  const normalized = hexRef.toLowerCase();
  const objectDir = path.join(commonDir, "objects", normalized.slice(0, 2));
  if (!fs.existsSync(objectDir) || !fs.statSync(objectDir).isDirectory()) return null;
  const suffix = normalized.slice(2);
  if (normalized.length === 40 || normalized.length === 64) {
    return fs.existsSync(path.join(objectDir, suffix)) ? normalized : null;
  }
  const matches = fs.readdirSync(objectDir).filter((name) => name.startsWith(suffix));
  if (matches.length !== 1) return null;
  return `${normalized.slice(0, 2)}${matches[0]}`;
}

function packIndexObjectForPrefix(idxPath, hexRef, shaBytes) {
  const prefix = hexRef.toLowerCase();
  if (prefix.length > shaBytes * 2) return null;
  const data = fs.readFileSync(idxPath);
  if (data.length < 8 + 256 * 4) return null;
  if (data.readUInt32BE(0) !== 0xff744f63) return null;
  const version = data.readUInt32BE(4);
  if (version !== 2) return null;
  const objectCount = data.readUInt32BE(8 + 255 * 4);
  const namesOffset = 8 + 256 * 4;
  const namesEnd = namesOffset + objectCount * shaBytes;
  if (namesEnd > data.length) return null;
  const objectNameAt = (index) => {
    const start = namesOffset + index * shaBytes;
    return data.subarray(start, start + shaBytes).toString("hex");
  };
  let low = 0;
  let high = objectCount;
  while (low < high) {
    const mid = Math.floor((low + high) / 2);
    if (objectNameAt(mid) < prefix) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }
  if (low >= objectCount) return null;
  const match = objectNameAt(low);
  if (!match.startsWith(prefix)) return null;
  if (prefix.length < shaBytes * 2 && low + 1 < objectCount) {
    const next = objectNameAt(low + 1);
    if (next.startsWith(prefix) && next !== match) return AMBIGUOUS_OBJECT_PREFIX;
  }
  return match;
}

function packedObjectForPrefix(hexRef, commonDir, objectFormat) {
  const packDir = path.join(commonDir, "objects", "pack");
  if (!fs.existsSync(packDir) || !fs.statSync(packDir).isDirectory()) return null;
  const shaBytes = objectFormat === "sha256" ? 32 : 20;
  let resolved = null;
  for (const entry of fs.readdirSync(packDir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".idx")) continue;
    const idxPath = path.join(packDir, entry.name);
    try {
      const object = packIndexObjectForPrefix(idxPath, hexRef, shaBytes);
      if (object === AMBIGUOUS_OBJECT_PREFIX) return null;
      if (object) {
        if (resolved && resolved !== object) return null;
        resolved = object;
      }
    } catch {
      // Ignore unreadable/corrupt pack indexes; absence is handled by the
      // caller as a loud ref_not_in_local_history refusal.
    }
  }
  return resolved;
}

function objectForPrefix(hexRef, commonDir, objectFormat) {
  return looseObjectForPrefix(hexRef, commonDir)
    || packedObjectForPrefix(hexRef, commonDir, objectFormat);
}

function objectExists(hexRef, commonDir, objectFormat = "sha1") {
  return !!objectForPrefix(hexRef, commonDir, objectFormat);
}

function refAvailableInLocalHistory(ref, gitDirs) {
  if (HEX_REF_RE.test(ref)) {
    return objectForPrefix(ref, gitDirs.commonDir, gitDirs.objectFormat);
  }
  const resolvedObject = resolveRefToObject(ref, gitDirs);
  return resolvedObject && objectExists(resolvedObject, gitDirs.commonDir, gitDirs.objectFormat)
    ? resolvedObject.toLowerCase()
    : null;
}

function assertHistoryAvailableForRef(repoRoot, ref) {
  const root = assertNonEmptyString(repoRoot, "repo_root");
  const normalizedRef = normalizeHistoryRef(ref);
  const gitDirs = resolveGitDirectories(root);
  if (fs.existsSync(path.join(gitDirs.gitDir, "shallow"))
      || fs.existsSync(path.join(gitDirs.commonDir, "shallow"))) {
    throw gitMetadataError(
      `Differential checkout refused for shallow clone: ${root}. Deepen the local clone before retrying.`,
      "shallow_clone_blocks_differential",
      { checkout_ref: normalizedRef },
    );
  }
  const checkoutObject = refAvailableInLocalHistory(normalizedRef, gitDirs);
  if (!checkoutObject) {
    throw gitMetadataError(
      `Differential checkout ref is not present in local git history: ${normalizedRef}`,
      "ref_not_in_local_history",
      { checkout_ref: normalizedRef },
    );
  }
  return {
    repo_root: root,
    checkout_ref: normalizedRef,
    checkout_object: checkoutObject,
    checkout_object_format: gitDirs.objectFormat,
    git_dir: gitDirs.gitDir,
    common_git_dir: gitDirs.commonDir,
  };
}

function initRepoSession({
  repo_path: repoPath,
  target_domain: requestedTargetDomain = null,
  source_url: sourceUrl = null,
  branch = null,
  commit = null,
  deep_mode: deepMode = false,
  egress_profile: requestedEgressProfile = null,
} = {}) {
  let targetRepo;
  try {
    targetRepo = normalizeTargetRepo({
      root_path: repoPath,
      source_url: sourceUrl,
      branch,
      commit,
    }, "target_repo");
  } catch (error) {
    const mapped = repoPathError(error);
    if (mapped) throw mapped;
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error));
  }

  const canonicalRoot = targetRepo.root_path;
  const derivedDomain = deriveRepoTargetDomain(canonicalRoot);

  let domain;
  if (requestedTargetDomain != null) {
    const trimmed = assertNonEmptyString(requestedTargetDomain, "target_domain");
    assertSafeDomain(trimmed);
    // Accept any safe slug the operator provides — supports the documented
    // --target-id <id> override for stable/memorable repo session names. The
    // derived slug remains the default when no override is supplied.
    domain = trimmed;
  } else {
    domain = derivedDomain;
  }

  const repoHash = (targetRepo.commit && /^[0-9a-f]{8,64}$/i.test(targetRepo.commit))
    ? targetRepo.commit.toLowerCase()
    : deriveRepoHashFromPath(canonicalRoot);

  const normalizedDeepMode = deepMode == null ? false : assertBoolean(deepMode, "deep_mode");
  const profileName = requestedEgressProfile == null
    ? "default"
    : assertNonEmptyString(requestedEgressProfile, "egress_profile");

  return withSessionLock(domain, () => {
    const dir = sessionDir(domain);
    const filePath = statePath(domain);

    if (fs.existsSync(filePath)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session already initialized: ${filePath}`);
    }
    if (!isSessionDirEffectivelyEmpty(dir)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session directory is not empty: ${dir}`);
    }

    const egressProfile = resolveEgressProfile(profileName);
    const egressFields = egressProfileStateFields(egressProfile);
    const internalHostPolicy = deriveBlockInternalHostsPolicy({
      checkpointMode: "normal",
      legacyDefault: false,
    });

    const sessionNucleus = buildSessionNucleus({
      target_domain: domain,
      target_repo: targetRepo,
      repo_hash: repoHash,
      scope_policy: {
        target_domain: domain,
        target_repo: targetRepo,
        ...internalHostPolicy,
      },
      egress_identity: egressFields,
      auth_context: {
        auth_status: "pending",
      },
      operator_constraint: {
        handoff_provenance_required: true,
      },
    });
    writeJsonDocument(sessionNucleusPath(domain), sessionNucleus);
    appendSessionEvent({
      target_domain: domain,
      kind: "governance.session.initialized",
      nucleus_hash: sessionNucleus.nucleus_hash,
      payload: {
        nucleus_hash: sessionNucleus.nucleus_hash,
        scope_policy_hash: hashCanonicalJson(sessionNucleus.scope_policy),
        egress_identity_hash: hashCanonicalJson(sessionNucleus.egress_identity),
        auth_context_hash: hashCanonicalJson(sessionNucleus.auth_context),
        operator_constraint_hash: hashCanonicalJson(sessionNucleus.operator_constraint),
        repo_hash: sessionNucleus.repo_hash,
      },
    });

    const state = buildInitialSessionState(domain, null, {
      deepMode: normalizedDeepMode,
      egressProfile,
      blockInternalHostsPolicy: sessionNucleus.scope_policy,
      targetRepo,
      repoHash,
    });
    writeSessionStateDocument(domain, {}, state);
    safeAppendPipelineEventDirect(domain, "session_started", {
      lifecycle_state: state.lifecycle_state,
      source: "bob_init_repo_session",
      deep_mode: state.deep_mode,
      checkpoint_mode: state.checkpoint_mode,
      block_internal_hosts: state.block_internal_hosts,
      block_internal_hosts_source: state.block_internal_hosts_source,
      repo_hash: repoHash,
      ...egressFields,
    }, buildGovernanceContextFromNucleus(sessionNucleus));

    return {
      created: true,
      session_dir: dir,
      target_domain: domain,
      target_repo: targetRepo,
      repo_hash: repoHash,
      nucleus_hash: sessionNucleus.nucleus_hash,
      lifecycle_state: state.lifecycle_state,
      deep_mode: state.deep_mode,
      egress_profile: state.egress_profile,
    };
  });
}

function readRepoSession(targetDomain) {
  const domain = assertNonEmptyString(targetDomain, "target_domain");
  const nucleus = readSessionNucleus(domain);
  if (!nucleus || nucleus.scope_policy == null || nucleus.scope_policy.target_repo == null) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `target_domain ${domain} is not a repo session`,
    );
  }
  return {
    target_domain: nucleus.target_domain,
    target_repo: nucleus.scope_policy.target_repo,
    repo_hash: nucleus.repo_hash || null,
    nucleus_hash: nucleus.nucleus_hash,
    lifecycle_state: nucleus.lifecycle_state,
  };
}

// Cycle O.2: repo-inventory walks the bound repo and emits frontier
// `surface.observed` events for each enumerated artefact. The walker
// honours `.gitignore`, default-excludes heavy build/vendor trees,
// halts on symlink loops, and caps the walk at 50k files so that
// `init_repo_session(node_modules-monorepo/)` does not exhaust memory.

const REPO_INVENTORY_VERSION = 1;
const REPO_WALK_MAX_FILES = 50000;
const REPO_WALK_PROBE_MAX_BYTES = 64 * 1024; // cap text probes (NFS detection)
const SEED_CORPUS_SUMMARY_LIMIT = 16;
const SEED_CORPUS_SAMPLE_RELS_LIMIT = 10;

// Default-excluded directory names (per O.2 spec). These are layered ON TOP
// of .gitignore patterns; .gitignore is the authoritative source for a
// per-repo override, the default list captures heavy directories that are
// almost always ignored even when no .gitignore exists.
const DEFAULT_EXCLUDED_DIRS = Object.freeze(new Set([
  ".git",
  "node_modules",
  "target",
  "build",
  "dist",
  "vendor",
  ".venv",
  "__pycache__",
  "coverage",
]));

const SEED_CORPUS_DIR_NAMES = Object.freeze(new Set([
  "testdata",
  "corpus",
  "seeds",
]));
const SEED_CORPUS_NESTED_DIRS = Object.freeze([
  "fuzz/corpus",
]);
const OSS_FUZZ_SEED_CORPUS_DIR_RE = /(?:^|\/)[^/]+_seed_corpus$/i;
const OSS_FUZZ_SEED_CORPUS_ZIP_RE = /(?:^|\/)[^/]+_seed_corpus\.zip$/i;

// Manifest filenames that flag a package/module surface.
const MANIFEST_NAMES = Object.freeze(new Set([
  "package.json",
  "Cargo.toml",
  "go.mod",
  "requirements.txt",
  "setup.py",
  "pyproject.toml",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "Gemfile",
  "composer.json",
]));

// Lockfiles paired with the manifest for "has_lockfile" signalling.
const LOCKFILE_NAMES = Object.freeze(new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "Cargo.lock",
  "go.sum",
  "Pipfile.lock",
  "poetry.lock",
  "Gemfile.lock",
  "composer.lock",
]));

// Native build files — presence promotes the repo to NATIVE-CODE surface.
const NATIVE_BUILD_NAMES = Object.freeze(new Set([
  "CMakeLists.txt",
  "configure.ac",
  "Makefile.am",
  "Makefile",
  "meson.build",
]));

// CI/CD config paths. The first match wins; we want the file relative path
// to land on the materialized surface so downstream readers can locate it.
const CI_CONFIG_MATCHERS = Object.freeze([
  (rel) => rel.startsWith(".github/workflows/") && /\.ya?ml$/i.test(rel),
  (rel) => rel === ".gitlab-ci.yml",
  (rel) => rel === "Jenkinsfile",
  (rel) => rel === ".circleci/config.yml",
]);

// Entry-point detectors. Each returns true when the file/path indicates an
// executable / main entry. Directory-shaped patterns are also recognised so
// e.g. `bin/foo` and `cmd/server/main.go` both surface.
const ENTRY_POINT_MATCHERS = Object.freeze([
  (rel) => rel.startsWith("bin/"),
  (rel) => rel.startsWith("cmd/"),
  (rel) => /(^|\/)src\/main\.[a-z0-9]+$/i.test(rel),
  (rel) => /(^|\/)index\.[a-z0-9]+$/i.test(rel),
  (rel) => /(^|\/)__main__\.py$/.test(rel),
]);

// Special config names that should surface as their own "config" event.
const CONFIG_MATCHERS = Object.freeze([
  (rel) => /(^|\/)\.env(\..+)?$/.test(rel),
  (rel) => rel === "Dockerfile",
  (rel) => /(^|\/)Dockerfile(\..+)?$/.test(rel),
  (rel) => rel === "docker-compose.yml" || rel === "docker-compose.yaml",
  (rel) => rel.startsWith(".devcontainer/"),
]);

// File-extension → language hint map. Lightweight and intentionally bounded;
// the hypergraph only needs a per-module language signal, not full LOC.
const LANGUAGE_BY_EXT = Object.freeze({
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".py": "python",
  ".go": "go",
  ".rs": "rust",
  ".rb": "ruby",
  ".php": "php",
  ".java": "java",
  ".kt": "kotlin",
  ".kts": "kotlin",
  ".scala": "scala",
  ".cs": "csharp",
  ".c": "c",
  ".h": "c",
  ".cc": "cpp",
  ".cpp": "cpp",
  ".cxx": "cpp",
  ".hh": "cpp",
  ".hpp": "cpp",
  ".swift": "swift",
  ".m": "objc",
  ".mm": "objc",
});

// Ecosystem mapping for dependency observations.
const ECOSYSTEM_BY_MANIFEST = Object.freeze({
  "package.json": "npm",
  "Cargo.toml": "cargo",
  "go.mod": "go",
  "requirements.txt": "pypi",
  "setup.py": "pypi",
  "pyproject.toml": "pypi",
  "pom.xml": "maven",
  "build.gradle": "gradle",
  "build.gradle.kts": "gradle",
  "Gemfile": "rubygems",
  "composer.json": "composer",
});

// NFS/XDR shape detection — when present, prepare_env can preload extra
// libtirpc/krb5/ssl/nfs packages. We deliberately read a small probe of the
// build file rather than scanning every .c file.
const NFS_XDR_SIGNALS = Object.freeze([
  /libtirpc/i,
  /libnfs\.h/i,
  /rpc\/xdr\.h/i,
  /\bxdr_/i,
]);

const RESIDUAL_TARGET_LIMIT = 20;
const RESIDUAL_SOURCE_LINE_LIMIT = 12;
const RESIDUAL_SECURITY_LINE_RE = /\b(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+|buffer overflow|heap overflow|stack overflow|overflow|underflow|use-after-free|uaf|out[- ]of[- ]bounds|oob|memory corruption|crash|segfault|security|vulnerab)\b/i;
const RESIDUAL_SOURCE_FILE_RE = /(^|\/)(CHANGELOG|CHANGES|NEWS|RELEASES?|SECURITY)(\.[^/]*)?$/i;

// Minimal .gitignore parser. Supports negation (`!pattern`), trailing slashes
// (directory-only), and glob characters via a converted RegExp. We do not
// implement the full git wildmatch semantics — the tradeoff is intentional:
// the bounded surface enumeration here is a hint to the orchestrator, not
// the authoritative file ACL. The session-read-guard remains the trust root
// for sensitive paths.
function compileGitignorePatterns(text) {
  const lines = text.split(/\r?\n/);
  const patterns = [];
  for (const raw of lines) {
    const trimmed = raw.replace(/\s+$/, "");
    if (!trimmed || trimmed.startsWith("#")) continue;
    let pattern = trimmed;
    let negated = false;
    if (pattern.startsWith("!")) {
      negated = true;
      pattern = pattern.slice(1);
    }
    let directoryOnly = false;
    if (pattern.endsWith("/")) {
      directoryOnly = true;
      pattern = pattern.slice(0, -1);
    }
    if (!pattern) continue;
    const anchoredAtRoot = pattern.startsWith("/");
    if (anchoredAtRoot) pattern = pattern.slice(1);
    // Convert glob → regex. * matches anything but `/`; ** matches across
    // path separators; ? matches single non-`/` char. Other regex metas
    // are escaped.
    let regex = "";
    for (let i = 0; i < pattern.length; i++) {
      const ch = pattern[i];
      if (ch === "*" && pattern[i + 1] === "*") {
        regex += ".*";
        i += 1;
      } else if (ch === "*") {
        regex += "[^/]*";
      } else if (ch === "?") {
        regex += "[^/]";
      } else if (/[.+^${}()|[\]\\]/.test(ch)) {
        regex += "\\" + ch;
      } else {
        regex += ch;
      }
    }
    const prefix = anchoredAtRoot ? "^" : "(?:^|.*/)";
    const compiled = new RegExp(`${prefix}${regex}${directoryOnly ? "(?:/|$)" : "$"}`);
    patterns.push({ regex: compiled, negated, directoryOnly });
  }
  return patterns;
}

function matchesGitignore(patterns, relativePath, isDirectory) {
  let ignored = false;
  for (const { regex, negated, directoryOnly } of patterns) {
    if (directoryOnly && !isDirectory) continue;
    if (regex.test(relativePath)) {
      ignored = !negated;
    }
  }
  return ignored;
}

function loadGitignore(rootPath) {
  const candidate = path.join(rootPath, ".gitignore");
  if (!fs.existsSync(candidate)) return [];
  try {
    const raw = fs.readFileSync(candidate, "utf8");
    return compileGitignorePatterns(raw);
  } catch {
    return [];
  }
}

// Symlink-loop guard. Tracks the device+inode pair for every directory we
// descend into; a repeat visit halts that branch cleanly without throwing.
function statKey(stat) {
  return `${stat.dev}:${stat.ino}`;
}

class RepoTooLargeError extends Error {
  constructor(limit) {
    super(`repo_too_large: walked over ${limit} files; rerun against a narrower repo_path`);
    this.code = "repo_too_large";
    this.limit = limit;
  }
}

function walkRepo(rootPath, gitignorePatterns) {
  const files = [];
  const rootReal = fs.realpathSync(rootPath);
  const visited = new Set();
  const queue = [{ absPath: rootPath, relPath: "" }];
  while (queue.length > 0) {
    if (files.length > REPO_WALK_MAX_FILES) {
      throw new RepoTooLargeError(REPO_WALK_MAX_FILES);
    }
    const { absPath, relPath } = queue.shift();
    let stat;
    try {
      stat = fs.statSync(absPath);
    } catch {
      continue;
    }
    if (!stat.isDirectory()) continue;
    const key = statKey(stat);
    if (visited.has(key)) continue;
    visited.add(key);
    let entries;
    try {
      entries = fs.readdirSync(absPath, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const childAbs = path.join(absPath, entry.name);
      const childRel = relPath ? `${relPath}/${entry.name}` : entry.name;
      let isDir = entry.isDirectory();
      let isFile = entry.isFile();
      if (entry.isSymbolicLink()) {
        try {
          const childReal = fs.realpathSync(childAbs);
          if (!pathWithinRoot(rootReal, childReal)) continue;
          const linkStat = fs.statSync(childAbs);
          isDir = linkStat.isDirectory();
          isFile = linkStat.isFile();
        } catch {
          continue;
        }
      }
      if (isDir) {
        if (DEFAULT_EXCLUDED_DIRS.has(entry.name)) continue;
        if (matchesGitignore(gitignorePatterns, childRel, true)) continue;
        queue.push({ absPath: childAbs, relPath: childRel });
      } else if (isFile) {
        if (matchesGitignore(gitignorePatterns, childRel, false)) continue;
        if (files.length >= REPO_WALK_MAX_FILES) {
          throw new RepoTooLargeError(REPO_WALK_MAX_FILES);
        }
        files.push(childRel);
      }
    }
  }
  return files.sort();
}

function pathWithinRoot(rootReal, candidateReal) {
  const relative = path.relative(rootReal, candidateReal);
  return relative === "" || (relative && !relative.startsWith("..") && !path.isAbsolute(relative));
}

function safeReadProbe(rootPath, relPath, maxBytes = REPO_WALK_PROBE_MAX_BYTES) {
  try {
    const rootReal = fs.realpathSync(rootPath);
    const absPath = path.resolve(rootReal, relPath);
    const realPath = fs.realpathSync(absPath);
    if (!pathWithinRoot(rootReal, realPath)) return null;
    const fd = fs.openSync(realPath, "r");
    try {
      const buf = Buffer.alloc(maxBytes);
      const bytesRead = fs.readSync(fd, buf, 0, maxBytes, 0);
      const slice = buf.subarray(0, bytesRead);
      if (slice.includes(0)) return null;
      return slice.toString("utf8");
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
}

function safeFileStatWithinRoot(rootPath, relPath) {
  try {
    const rootReal = fs.realpathSync(rootPath);
    const absPath = path.resolve(rootReal, relPath);
    const realPath = fs.realpathSync(absPath);
    if (!pathWithinRoot(rootReal, realPath)) return null;
    const stat = fs.statSync(realPath);
    return stat.isFile() ? stat : null;
  } catch {
    return null;
  }
}

function detectNfsXdrShape(rootPath, files) {
  // Scan a bounded number of native-build files for NFS/XDR signals. The
  // probe stays under 64KiB per file so a pathological CMakeLists does not
  // dominate the inventory time budget.
  for (const file of files) {
    const base = path.basename(file);
    if (!NATIVE_BUILD_NAMES.has(base)) continue;
    const probe = safeReadProbe(rootPath, file);
    if (!probe) continue;
    for (const re of NFS_XDR_SIGNALS) {
      if (re.test(probe)) return true;
    }
  }
  // Also check for libnfs.h / rpc/xdr.h in any header file path.
  for (const file of files) {
    if (/libnfs\.h$/i.test(file)) return true;
    if (/(^|\/)rpc\/xdr\.h$/i.test(file)) return true;
  }
  return false;
}

function uniqueStrings(values, limit = null) {
  const out = [];
  const seen = new Set();
  for (const value of values) {
    if (typeof value !== "string") continue;
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
    if (limit != null && out.length >= limit) break;
  }
  return out;
}

function detectResidualLinesFromFiles(repoRoot, files) {
  const targets = [];
  for (const file of files) {
    if (!RESIDUAL_SOURCE_FILE_RE.test(file)) continue;
    const text = safeReadProbe(repoRoot, file);
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    let captured = 0;
    for (const line of lines) {
      const trimmed = line.trim().replace(/^\s*[-*]\s*/, "");
      if (!trimmed || !RESIDUAL_SECURITY_LINE_RE.test(trimmed)) continue;
      const excerpt = redactTextSensitiveValues(trimmed);
      const capped = excerpt.length > REPO_CHECK_MAX_EXCERPT_CHARS
        ? `${excerpt.slice(0, REPO_CHECK_MAX_EXCERPT_CHARS)}…`
        : excerpt;
      targets.push(`${file}: ${capped}`);
      captured += 1;
      if (captured >= RESIDUAL_SOURCE_LINE_LIMIT) break;
    }
  }
  return targets;
}

function detectResidualHuntTargets(repoRoot, files, modules) {
  const nativeModules = modules.filter((mod) => mod && (mod.nativeSource || mod.nativeBuild));
  if (nativeModules.length === 0) return [];
  return uniqueStrings(detectResidualLinesFromFiles(repoRoot, files), RESIDUAL_TARGET_LIMIT);
}

function detectEcosystemForManifest(base) {
  return ECOSYSTEM_BY_MANIFEST[base] || null;
}

function findLockfileForManifest(manifestRel, files) {
  const dir = path.dirname(manifestRel);
  for (const file of files) {
    if (path.dirname(file) !== dir) continue;
    if (LOCKFILE_NAMES.has(path.basename(file))) return file;
  }
  return null;
}

function matchingNestedSeedCorpusDir(segments) {
  for (let index = 0; index < segments.length - 1; index += 1) {
    for (const nested of SEED_CORPUS_NESTED_DIRS) {
      const nestedSegments = nested.split("/");
      const slice = segments.slice(index, index + nestedSegments.length);
      if (slice.length === nestedSegments.length && slice.join("/") === nested) {
        return segments.slice(0, index + nestedSegments.length).join("/");
      }
    }
  }
  return null;
}

function seedCorpusForRel(rel) {
  const normalized = String(rel || "").split(path.sep).join("/");
  if (!normalized) return null;
  if (OSS_FUZZ_SEED_CORPUS_ZIP_RE.test(normalized)) {
    return { dir: normalized, isZip: true };
  }
  const segments = normalized.split("/").filter(Boolean);
  const nested = matchingNestedSeedCorpusDir(segments);
  if (nested) return { dir: nested, isZip: false };
  for (let index = 0; index < segments.length - 1; index += 1) {
    const base = segments[index];
    const dir = segments.slice(0, index + 1).join("/");
    if (SEED_CORPUS_DIR_NAMES.has(base)) {
      return { dir, isZip: false };
    }
    if (OSS_FUZZ_SEED_CORPUS_DIR_RE.test(dir)) {
      return { dir, isZip: false };
    }
  }
  return null;
}

function buildSeedCorpusSummary(entries) {
  const summaries = [];
  const sortedEntries = Array.from(entries.entries()).sort(([a], [b]) => a.localeCompare(b));
  for (const [relPath, entry] of sortedEntries.slice(0, SEED_CORPUS_SUMMARY_LIMIT)) {
    const summary = {
      rel_path: relPath,
      file_count: entry.fileCount,
      total_bytes: entry.totalBytes,
      has_zip: entry.hasZip,
      sample_rels: entry.sampleRels.slice(),
      truncated: entry.fileCount > entry.sampleRels.length,
    };
    summary.manifest_hash = hashDocumentExcluding(summary, ["manifest_hash"]);
    summaries.push(summary);
  }
  return summaries;
}

function classifyFile(rel) {
  const base = path.basename(rel);
  const ext = path.extname(rel).toLowerCase();
  const manifest = MANIFEST_NAMES.has(base);
  const ci = CI_CONFIG_MATCHERS.some((fn) => fn(rel));
  const config = CONFIG_MATCHERS.some((fn) => fn(rel));
  const entry = ENTRY_POINT_MATCHERS.some((fn) => fn(rel));
  const language = LANGUAGE_BY_EXT[ext] || null;
  const nativeSource = NATIVE_SOURCE_EXTENSIONS.has(ext);
  const nativeBuild = NATIVE_BUILD_NAMES.has(base);
  const seedCorpus = seedCorpusForRel(rel);
  return {
    base,
    ext,
    manifest,
    ci,
    config,
    entry,
    language,
    nativeSource,
    nativeBuild,
    seedCorpus,
  };
}

function safeSurfaceId(rel, prefix) {
  // Convert a relative path into a deterministic, path-safe surface id.
  // The surface id flows into materialized indexes so it must avoid path
  // characters that surface-router or downstream consumers may interpret.
  const slug = rel.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return `${prefix}:${slug || "root"}`;
}

function emitSurfaceObserved({
  domain,
  surfaceId,
  kind,
  title,
  payload,
  emittedCount,
}) {
  const safePayload = { ...payload, kind, title };
  // O-P7: every Plane O frontier payload pre-flighted before append. The
  // normalizePlainObject path inside appendFrontierEvent already invokes
  // validateNoSensitiveMaterial; this redundant call gives a stable
  // error path in tests when a producer regression slips through.
  validateNoSensitiveMaterial(safePayload, `repo_inventory.${kind}`);
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    surface_id: surfaceId,
    payload: safePayload,
    source: { artifact: "repo-inventory.json", tool: "bob_repo_inventory" },
  });
  emittedCount.value += 1;
}

function buildInventoryProjection(domain, repoRoot, files) {
  const modules = [];
  const dependencies = [];
  const entryPoints = [];
  const ciPipelines = [];
  const configs = [];
  const seedCorpusEntries = new Map();
  const manifests = [];
  const languageCounts = {};
  let nativeSourceCount = 0;
  let nativeBuildCount = 0;

  for (const rel of files) {
    const info = classifyFile(rel);
    if (info.language) {
      languageCounts[info.language] = (languageCounts[info.language] || 0) + 1;
      // Emit a code_module surface per source file so the frontier carries
      // every code-shaped signal. To avoid blowing the materialized index
      // for very large repos we only emit code_module for native sources
      // here; non-native languages still aggregate via the language counts
      // and per-language dependency observations.
    }
    if (info.nativeSource) {
      nativeSourceCount += 1;
      modules.push({
        rel,
        language: info.language || "c",
        nativeSource: true,
        nativeBuild: false,
      });
    }
    if (info.nativeBuild) {
      nativeBuildCount += 1;
      modules.push({
        rel,
        language: "c",
        nativeSource: false,
        nativeBuild: true,
      });
    }
    if (info.manifest) {
      manifests.push(rel);
      const ecosystem = detectEcosystemForManifest(info.base) || "unknown";
      const hasLockfile = findLockfileForManifest(rel, files) != null;
      dependencies.push({ rel, ecosystem, hasLockfile });
    }
    if (info.ci) ciPipelines.push(rel);
    if (info.entry) entryPoints.push(rel);
    if (info.config) configs.push(rel);
    if (info.seedCorpus) {
      const stat = safeFileStatWithinRoot(repoRoot, rel);
      if (stat) {
        const relPath = info.seedCorpus.dir;
        let entry = seedCorpusEntries.get(relPath);
        if (!entry) {
          entry = {
            fileCount: 0,
            totalBytes: 0,
            hasZip: false,
            sampleRels: [],
          };
          seedCorpusEntries.set(relPath, entry);
        }
        entry.fileCount += 1;
        entry.totalBytes += stat.size;
        entry.hasZip = entry.hasZip || info.seedCorpus.isZip || /\.zip$/i.test(rel);
        if (entry.sampleRels.length < SEED_CORPUS_SAMPLE_RELS_LIMIT) {
          entry.sampleRels.push(rel);
        }
      }
    }
  }

  const nfsShape = detectNfsXdrShape(repoRoot, files);
  const residualHuntTargets = detectResidualHuntTargets(repoRoot, files, modules);
  const seedCorpus = buildSeedCorpusSummary(seedCorpusEntries);
  const seedCorpusCount = seedCorpusEntries.size;
  const seedCorpusHash = hashCanonicalJson({ seed_corpus: seedCorpus });
  return {
    modules,
    dependencies,
    entryPoints,
    ciPipelines,
    configs,
    manifests,
    languageCounts,
    nativeSourceCount,
    nativeBuildCount,
    nfsShape,
    residualHuntTargets,
    seedCorpus,
    seedCorpusCount,
    seedCorpusHash,
  };
}

function buildRepoInventory({ target_domain: targetDomain, repo_path: repoPathOverride } = {}) {
  const domain = assertSafeDomain(targetDomain);
  const repoSession = readRepoSession(domain);
  const requestedRoot = repoPathOverride
    ? assertNonEmptyString(repoPathOverride, "repo_path")
    : repoSession.target_repo.root_path;
  if (!fs.existsSync(requestedRoot) || !fs.statSync(requestedRoot).isDirectory()) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `repo_path is not a directory: ${requestedRoot}`);
  }
  const canonicalRoot = fs.realpathSync(requestedRoot);
  const canonicalSessionRoot = fs.realpathSync(repoSession.target_repo.root_path);
  const relativeToSessionRoot = path.relative(canonicalSessionRoot, canonicalRoot);
  if (relativeToSessionRoot.startsWith("..") || path.isAbsolute(relativeToSessionRoot)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "repo_path must stay within the initialized repo session root", {
      repo_error_code: "repo_path_mismatch",
    });
  }
  const root = canonicalRoot;
  const subdirPrefix = relativeToSessionRoot
    ? relativeToSessionRoot.split(path.sep).join("/")
    : "";
  const rootRel = (rel) => {
    const normalized = String(rel || "").split(path.sep).join("/");
    if (!normalized) return normalized;
    return subdirPrefix ? `${subdirPrefix}/${normalized}` : normalized;
  };
  const rootRelArray = (values) => (
    Array.isArray(values) ? values.map((value) => rootRel(value)) : values
  );
  const rootRelResidualTarget = (target) => {
    const separator = typeof target === "string" ? target.indexOf(": ") : -1;
    if (separator === -1) return rootRel(target);
    return `${rootRel(target.slice(0, separator))}${target.slice(separator)}`;
  };
  const rootRelSeedCorpusEntry = (entry) => ({
    ...entry,
    rel_path: rootRel(entry.rel_path),
    sample_rels: rootRelArray(entry.sample_rels),
  });
  const rootRelReachabilityMap = (value) => {
    if (value == null || typeof value !== "object" || Array.isArray(value)) return value;
    return {
      ...value,
      network_reachable_anchors: rootRelArray(value.network_reachable_anchors),
      network_reachable_dirs: rootRelArray(value.network_reachable_dirs),
      local_only_candidate_dirs: rootRelArray(value.local_only_candidate_dirs),
    };
  };

  const gitignorePatterns = loadGitignore(root);
  let files;
  try {
    files = walkRepo(root, gitignorePatterns);
  } catch (error) {
    if (error && error.code === "repo_too_large") {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message, {
        repo_error_code: "repo_too_large",
        limit: error.limit,
      });
    }
    throw error;
  }
  const projection = buildInventoryProjection(domain, root, files);
  const reachability = classifyRepoReachability({
    repoRoot: root,
    files,
    projection,
    surfaceIdForRel: (rel) => safeSurfaceId(rootRel(rel), "repo:module"),
  });
  const inventoryResidualHuntTargets = projection.residualHuntTargets.map(rootRelResidualTarget);
  const inventorySeedCorpus = projection.seedCorpus.map(rootRelSeedCorpusEntry);
  const inventorySeedCorpusHash = hashCanonicalJson({ seed_corpus: inventorySeedCorpus });
  const reachabilitySummary = {
    ...reachability.reachability,
    surface_ceilings: Array.isArray(reachability.reachability.surface_ceilings)
      ? reachability.reachability.surface_ceilings.map((entry) => ({
        ...entry,
        file_path: rootRel(entry.file_path),
      }))
      : reachability.reachability.surface_ceilings,
    native_attack_vector_map: rootRelReachabilityMap(reachability.reachability.native_attack_vector_map),
  };

  return withSessionLock(domain, () => {
    const generatedAt = new Date().toISOString();
    const emittedCount = { value: 0 };

    // Per-module frontier events.
    for (const mod of projection.modules) {
      const reachabilityStamp = reachability.perSurface.get(mod.rel);
      const modRel = rootRel(mod.rel);
      emitSurfaceObserved({
        domain,
        surfaceId: safeSurfaceId(modRel, "repo:module"),
        kind: "code_module",
        title: modRel,
        payload: {
          file_path: modRel,
          surface_type: mod.nativeSource || mod.nativeBuild ? "oss_native_code" : "code_module",
          language: mod.language,
          native_source: mod.nativeSource,
          native_build: mod.nativeBuild,
          ...(reachabilityStamp ? {
            network_reachable: reachabilityStamp.network_reachable,
            attack_vector: reachabilityStamp.attack_vector,
            severity_ceiling: reachabilityStamp.severity_ceiling,
            network_reachable_anchors: rootRelArray(reachabilityStamp.network_reachable_anchors),
            network_reachable_dirs: rootRelArray(reachabilityStamp.network_reachable_dirs),
            local_only_candidate_dirs: rootRelArray(reachabilityStamp.local_only_candidate_dirs),
          } : {}),
        },
        emittedCount,
      });
    }

    // Per-manifest frontier event.
    for (const manifestPath of projection.manifests) {
      const ecosystem = detectEcosystemForManifest(path.basename(manifestPath)) || "unknown";
      const manifestRel = rootRel(manifestPath);
      emitSurfaceObserved({
        domain,
        surfaceId: safeSurfaceId(manifestRel, "repo:manifest"),
        kind: "manifest",
        title: manifestRel,
        payload: {
          file_path: manifestRel,
          surface_type: "oss_dependency",
          ecosystem,
        },
        emittedCount,
      });
    }

    // Per-dependency frontier event (one per manifest, top-level only).
    for (const dep of projection.dependencies) {
      const depRel = rootRel(dep.rel);
      emitSurfaceObserved({
        domain,
        surfaceId: safeSurfaceId(`${depRel}#deps`, "repo:dependency"),
        kind: "dependency",
        title: depRel,
        payload: {
          manifest_path: depRel,
          surface_type: "oss_dependency",
          ecosystem: dep.ecosystem,
          has_lockfile: dep.hasLockfile,
        },
        emittedCount,
      });
    }

    // Per-CI-pipeline frontier event.
    for (const ci of projection.ciPipelines) {
      const ciRel = rootRel(ci);
      emitSurfaceObserved({
        domain,
        surfaceId: safeSurfaceId(ciRel, "repo:ci"),
        kind: "ci_pipeline",
        title: ciRel,
        payload: {
          file_path: ciRel,
          surface_type: "oss_ci_cd",
        },
        emittedCount,
      });
    }

    // Per-entry-point frontier event.
    for (const entry of projection.entryPoints) {
      const entryRel = rootRel(entry);
      emitSurfaceObserved({
        domain,
        surfaceId: safeSurfaceId(entryRel, "repo:entry"),
        kind: "entry_point",
        title: entryRel,
        payload: {
          file_path: entryRel,
          surface_type: "oss_api_schema",
        },
        emittedCount,
      });
    }

    // Per-config frontier event (NEVER reads file contents — just the path
    // and basename. Secret values live in the file itself and would land in
    // session-read-guard's protected list, not in the inventory payload).
    for (const cfg of projection.configs) {
      const cfgRel = rootRel(cfg);
      emitSurfaceObserved({
        domain,
        surfaceId: safeSurfaceId(cfgRel, "repo:config"),
        kind: "config",
        title: cfgRel,
        payload: {
          file_path: cfgRel,
          surface_type: "oss_secrets_config",
        },
        emittedCount,
      });
    }

    try {
      scheduleMaterialization(domain);
    } catch {
      // Best-effort: the next producer event will trigger materialization.
    }

    const inventory = {
      version: REPO_INVENTORY_VERSION,
      target_domain: domain,
      repo_path: root,
      generated_at: generatedAt,
      counts: {
        files: files.length,
        manifests: projection.manifests.length,
        dependencies: projection.dependencies.length,
        entry_points: projection.entryPoints.length,
        ci_pipelines: projection.ciPipelines.length,
        configs: projection.configs.length,
        code_modules: projection.modules.length,
        native_source_files: projection.nativeSourceCount,
        native_build_files: projection.nativeBuildCount,
        residual_hunt_targets: projection.residualHuntTargets.length,
        seed_corpus: projection.seedCorpusCount,
        surface_events_emitted: emittedCount.value,
      },
      languages: projection.languageCounts,
      nfs_xdr_shape: projection.nfsShape,
      residual_hunt_targets: inventoryResidualHuntTargets,
      seed_corpus: inventorySeedCorpus,
      seed_corpus_hash: inventorySeedCorpusHash,
      reachability: reachabilitySummary,
      manifests: projection.manifests.map(rootRel),
      ci_pipelines: projection.ciPipelines.map(rootRel),
      entry_points: projection.entryPoints.map(rootRel),
      configs: projection.configs.map(rootRel),
    };
    // O-P7: validate the persisted document before it lands on disk. The
    // inventory carries only file paths and structural counts — no file
    // contents — but the scrub is still asserted so future fields don't
    // accidentally leak.
    validateNoSensitiveMaterial(inventory, "repo_inventory");
    inventory.inventory_hash = hashDocumentExcluding(inventory, [
      "generated_at",
      "inventory_hash",
    ]);
    writeJsonDocument(repoInventoryPath(domain), inventory);
    return {
      created: true,
      target_domain: domain,
      repo_path: root,
      repo_inventory_path: repoInventoryPath(domain),
      counts: inventory.counts,
      inventory_hash: inventory.inventory_hash,
      nfs_xdr_shape: projection.nfsShape,
      residual_hunt_targets: inventoryResidualHuntTargets,
      seed_corpus: inventory.seed_corpus,
      seed_corpus_hash: inventory.seed_corpus_hash,
      reachability: inventory.reachability,
    };
  });
}

// Cycle O.5: read-only repo evidence probe. `bob_repo_check` performs a
// bounded file lookup (existence + optional literal-substring or regex
// match) and appends a structured JSONL row to `repo-checks.jsonl`. Per
// O-P1 it never mutates the bound repo. Per O-P7, every excerpt of a
// matched line MUST flow through `redactTextSensitiveValues` before
// landing on disk so that grepping a synthetic `.env` for `API_KEY=.*`
// does not leak the literal secret bytes into a session artifact.
//
// Read cap is 4 MB. Files larger than the cap produce a structured
// `file_too_large` error; the operator can re-target a narrower probe
// (semgrep / grep) instead of slurping a multi-GiB asset into RAM.

const REPO_CHECK_VERSION = 1;
const REPO_CHECK_MAX_FILE_BYTES = 4 * 1024 * 1024; // 4 MB hard cap
// Cap the number of excerpts written per check so a regex like `.*` against a
// gigantic file does not produce a multi-megabyte JSONL row. The matched_lines
// array is then truncated and `matched_lines_truncated` is set on the row.
const REPO_CHECK_MAX_EXCERPTS = 200;
// Cap each excerpt's pre-redaction length so a single very-long line does not
// bloat the JSONL row beyond the 4 KB sensitive-material text cap. The
// validator throws if a string exceeds 4000 chars; we trim defensively before
// invoking it so callers see a structured `excerpt_too_long` truncation
// rather than a thrown error mid-write.
const REPO_CHECK_MAX_EXCERPT_CHARS = 1024;
const REPO_CHECK_TYPES = Object.freeze(new Set([
  "file_exists",
  "file_contains",
  "regex_match",
]));

const REPO_CHECK_REPLAY_CONTEXT_KEYS = Object.freeze(new Set([
  "wave",
  "agent",
  "surface_id",
  "task_lens",
  "technique_pack_id",
  "purpose",
  "operator_note",
]));

// Reuse the same {wave, agent, ...} shape as bob_repo_docker_run so an
// evaluator can correlate a check against the dispatch context that
// produced it. Out-of-band keys are silently dropped; string values are
// trimmed to 256 chars; numbers pass through. Anything else throws.
function normalizeRepoCheckReplayContext(value) {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "replay_context must be an object when provided",
    );
  }
  const out = {};
  for (const [key, raw] of Object.entries(value)) {
    if (!REPO_CHECK_REPLAY_CONTEXT_KEYS.has(key)) continue;
    if (raw == null) continue;
    if (typeof raw === "number") {
      out[key] = raw;
      continue;
    }
    if (typeof raw === "string") {
      const trimmed = raw.trim();
      if (trimmed.length > 256) {
        throw new ToolError(
          ERROR_CODES.INVALID_ARGUMENTS,
          `replay_context.${key} must be at most 256 characters`,
        );
      }
      if (trimmed) out[key] = trimmed;
      continue;
    }
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `replay_context.${key} must be a string or number`,
    );
  }
  return Object.keys(out).length > 0 ? out : null;
}

// Validate a relative file_path against the session's bound repo root. The
// returned absolute path is guaranteed to be inside the repo root (escape via
// `..` segments or absolute paths is rejected) so the probe can't read
// arbitrary files on the operator's machine (e.g. `/etc/shadow`).
function resolveRepoFilePath(repoRoot, filePath) {
  const raw = assertNonEmptyString(filePath, "file_path");
  if (path.isAbsolute(raw)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "file_path must be a relative path under the bound repo root",
      { repo_error_code: "file_path_must_be_relative" },
    );
  }
  const joined = path.join(repoRoot, raw);
  const resolved = path.resolve(joined);
  // Re-resolve the repo root too so symlinks at the root don't shift the
  // containment check.
  const rootResolved = path.resolve(repoRoot);
  const rel = path.relative(rootResolved, resolved);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "file_path escapes the bound repo root",
      { repo_error_code: "file_path_escapes_repo_root" },
    );
  }
  return resolved;
}

// Compile a regex pattern with optional flags after the trailing `/`. The
// pattern shape we accept is the operator's raw string; we always enforce
// the multi-line flag because matched_lines walks per line. The pattern
// arrives un-anchored so callers can probe substrings without ^/$.
function compileRepoCheckRegex(pattern) {
  const raw = assertNonEmptyString(pattern, "regex");
  let body = raw;
  let flags = "m";
  // Allow `/pattern/flags` shape for symmetry with grep/semgrep operator
  // habits, but treat a bare string as the literal regex body.
  const slashMatch = /^\/(.+)\/([gimsuy]*)$/.exec(raw);
  if (slashMatch) {
    body = slashMatch[1];
    flags = slashMatch[2] || "";
    if (!flags.includes("m")) flags += "m";
  }
  try {
    return new RegExp(body, flags);
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `regex pattern is invalid: ${error.message || error}`,
      { repo_error_code: "regex_invalid" },
    );
  }
}

// Per Plane O tests, a probe of a binary file MUST NOT crash and MUST NOT
// land the binary blob inside an excerpt. We probe the first 8 KiB of the
// file for a NUL byte (the canonical "binary" signal) and bail out before
// any decoding work happens. The caller still gets `matched: false` plus a
// `binary: true` flag on the row so a reviewer can see the probe ran.
function probeIsBinary(buffer) {
  const head = buffer.subarray(0, Math.min(buffer.length, 8192));
  return head.includes(0);
}

function hashBuffer(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

// Build matched_lines[]. Each entry carries the 1-based line number, the
// 0-based byte offset of the line within the file, and a REDACTED excerpt.
// Per O-P7 the excerpt MUST flow through `redactTextSensitiveValues`
// BEFORE any append; the redaction is the load-bearing primitive, not a
// downstream nicety. The validator runs after the redaction as a
// belt-and-suspenders fail-closed: if a future change accidentally widens
// the excerpt format to carry a key/value pair shaped like a credential,
// `validateNoSensitiveMaterial` raises and the write never lands.
function buildMatchedLines(text, predicate) {
  const lines = text.split(/\r?\n/);
  const matched = [];
  let truncated = false;
  let scanned = 0;
  let charOffset = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (predicate(line)) {
      if (matched.length >= REPO_CHECK_MAX_EXCERPTS) {
        truncated = true;
        break;
      }
      const rawExcerpt = line.length > REPO_CHECK_MAX_EXCERPT_CHARS
        ? `${line.slice(0, REPO_CHECK_MAX_EXCERPT_CHARS)}…`
        : line;
      const redacted = redactTextSensitiveValues(rawExcerpt);
      matched.push({
        line: i + 1,
        offset: charOffset,
        excerpt: redacted,
      });
    }
    scanned += 1;
    charOffset += line.length + 1; // account for the line terminator
  }
  return { matched, truncated, scanned };
}

// Plane X Cycle X.7 (X-P9 retrofit): distilled summary for a repo_check
// row. Brief renderers inline this; matched_lines[] stays as the body
// (resolved via `bob_resolve_body(repo_check:<check_id>)`). The summary
// shape is bounded by construction — top 3 matches, 120-char excerpts,
// fixed scalar fields — so the X-P9 2KB hard cap is structurally honored.
const REPO_CHECK_SUMMARY_EXCERPT_MAX_CHARS = 120;
const REPO_CHECK_SUMMARY_TOP_N = 3;

function buildRepoCheckSummary({ check_id, file_path: filePath, file_hash, matched_lines }) {
  const lines = Array.isArray(matched_lines) ? matched_lines : [];
  const top = lines.slice(0, REPO_CHECK_SUMMARY_TOP_N).map((entry) => {
    const excerpt = typeof entry.excerpt === "string" ? entry.excerpt : "";
    const redacted = excerpt.length > REPO_CHECK_SUMMARY_EXCERPT_MAX_CHARS
      ? `${excerpt.slice(0, REPO_CHECK_SUMMARY_EXCERPT_MAX_CHARS)}…`
      : excerpt;
    return {
      line_num: entry.line,
      excerpt_hash: crypto.createHash("sha256").update(excerpt).digest("hex"),
      redacted_excerpt: redacted,
    };
  });
  return {
    check_id,
    file_path: filePath,
    file_hash,
    match_count: lines.length,
    top_3_match_lines: top,
  };
}

function repoCheck({
  target_domain: targetDomain,
  check_type: checkType = null,
  file_path: filePath = null,
  pattern = null,
  regex = null,
  replay_context: replayContextRaw = null,
} = {}) {
  const domain = assertSafeDomain(targetDomain);
  const repoSession = readRepoSession(domain);
  const repoRoot = repoSession.target_repo.root_path;

  // Resolve check_type. When unspecified, infer from the optional pattern/regex
  // arguments: `regex` → regex_match, `pattern` → file_contains, else
  // file_exists. Explicit `check_type` always wins.
  let normalizedType;
  if (checkType != null) {
    normalizedType = assertNonEmptyString(checkType, "check_type");
    if (!REPO_CHECK_TYPES.has(normalizedType)) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `check_type must be one of ${Array.from(REPO_CHECK_TYPES).join(", ")}`,
        { repo_error_code: "check_type_invalid" },
      );
    }
  } else if (regex != null && String(regex).trim()) {
    normalizedType = "regex_match";
  } else if (pattern != null && String(pattern).trim()) {
    normalizedType = "file_contains";
  } else {
    normalizedType = "file_exists";
  }

  if (filePath == null || !String(filePath).trim()) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "file_path is required",
      { repo_error_code: "file_path_required" },
    );
  }

  const normalizedReplayContext = normalizeRepoCheckReplayContext(replayContextRaw);

  // Pattern/regex shape requirements per check_type. file_exists ignores
  // both inputs; file_contains requires `pattern`; regex_match requires
  // `regex`. The explicit guard makes the row's `pattern`/`regex` fields
  // unambiguous downstream.
  let literalPattern = null;
  let regexPattern = null;
  let compiledRegex = null;
  if (normalizedType === "file_contains") {
    literalPattern = assertNonEmptyString(pattern, "pattern");
  } else if (normalizedType === "regex_match") {
    regexPattern = assertNonEmptyString(regex, "regex");
    compiledRegex = compileRepoCheckRegex(regexPattern);
  }

  const absPath = resolveRepoFilePath(repoRoot, filePath);

  let stat;
  try {
    stat = fs.statSync(absPath);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      // file_exists is the canonical "answer is no" path; record the row
      // and return cleanly. file_contains / regex_match on a missing file
      // also returns matched:false but with `not_found:true` so the
      // operator can distinguish "file present, no match" from "file
      // never existed".
      const row = {
        version: REPO_CHECK_VERSION,
        check_id: `chk_${sha8(`${domain}|${filePath}|${normalizedType}|${Date.now()}`)}_${Date.now()}`,
        check_type: normalizedType,
        target_domain: domain,
        file_path: filePath,
        pattern: literalPattern,
        regex: regexPattern,
        matched: false,
        matched_lines: [],
        file_hash: null,
        not_found: true,
        ts: new Date().toISOString(),
      };
      if (normalizedReplayContext) row.replay_context = normalizedReplayContext;
      row.summary = buildRepoCheckSummary({
        check_id: row.check_id,
        file_path: filePath,
        file_hash: null,
        matched_lines: [],
      });
      validateNoSensitiveMaterial(row, "repo_checks");
      withSessionLock(domain, () => {
        appendJsonlLine(repoChecksJsonlPath(domain), row);
      });
      return {
        created: true,
        check_id: row.check_id,
        check_type: normalizedType,
        target_domain: domain,
        file_path: filePath,
        matched: false,
        not_found: true,
        matched_lines: [],
        file_hash: null,
        summary: row.summary,
      };
    }
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `file_path stat failed: ${error.message || error}`,
      { repo_error_code: "file_stat_failed" },
    );
  }

  if (!stat.isFile()) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "file_path is not a regular file",
      { repo_error_code: "file_path_not_a_file" },
    );
  }

  if (stat.size > REPO_CHECK_MAX_FILE_BYTES) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `file_path exceeds ${REPO_CHECK_MAX_FILE_BYTES} byte cap (size=${stat.size})`,
      {
        repo_error_code: "file_too_large",
        limit_bytes: REPO_CHECK_MAX_FILE_BYTES,
        size_bytes: stat.size,
      },
    );
  }

  const buffer = fs.readFileSync(absPath);
  const fileHash = hashBuffer(buffer);
  const isBinary = probeIsBinary(buffer);

  let matched = false;
  let matchedLines = [];
  let matchedLinesTruncated = false;
  let scannedLines = 0;

  if (normalizedType === "file_exists") {
    matched = true;
  } else if (isBinary) {
    // Binary file: never decode, never excerpt. Record matched:false plus a
    // `binary:true` flag so the reviewer can see the probe ran.
    matched = false;
  } else {
    const text = buffer.toString("utf8");
    let predicate;
    if (normalizedType === "file_contains") {
      predicate = (line) => line.includes(literalPattern);
    } else {
      // For regex_match, predicate must use a per-line probe; the `m` flag
      // is enforced by the compiler so multiline patterns work too.
      predicate = (line) => {
        compiledRegex.lastIndex = 0;
        return compiledRegex.test(line);
      };
    }
    const result = buildMatchedLines(text, predicate);
    matched = result.matched.length > 0;
    matchedLines = result.matched;
    matchedLinesTruncated = result.truncated;
    scannedLines = result.scanned;
  }

  const row = {
    version: REPO_CHECK_VERSION,
    check_id: `chk_${sha8(`${domain}|${filePath}|${normalizedType}|${Date.now()}`)}_${Date.now()}`,
    check_type: normalizedType,
    target_domain: domain,
    file_path: filePath,
    pattern: literalPattern,
    regex: regexPattern,
    matched,
    matched_lines: matchedLines,
    matched_lines_truncated: matchedLinesTruncated,
    scanned_lines: scannedLines,
    file_hash: fileHash,
    file_size: stat.size,
    binary: isBinary,
    not_found: false,
    ts: new Date().toISOString(),
  };
  if (normalizedReplayContext) row.replay_context = normalizedReplayContext;
  // Plane X Cycle X.7 (X-P9 retrofit): distilled summary field.
  // matched_lines[] stays as the body (existing readers unchanged); the
  // summary becomes the brief-inlinable form. Per X-P9 the summary is
  // bounded by its shape (top_3 + 120-char excerpt), so it stays well
  // under the 2KB hard cap regardless of file size or match count.
  row.summary = buildRepoCheckSummary({
    check_id: row.check_id,
    file_path: filePath,
    file_hash: fileHash,
    matched_lines: matchedLines,
  });

  // O-P7: dual-mode scrubbing. matched_lines[].excerpt is already redacted
  // via redactTextSensitiveValues above (the load-bearing primitive for
  // free-form excerpts that legitimately contain `KEY=value` syntax).
  // The rest of the row (file_path, pattern, regex, replay_context,
  // metadata) goes through validateNoSensitiveMaterial as a
  // belt-and-suspenders check against structural regressions — a future
  // change that renamed `excerpt` to `api_key_value` would trip the
  // SENSITIVE_KEY_RE and fail closed before append. We validate a deep
  // copy of the row with the already-redacted excerpts stripped so the
  // structural check sees only fields under its contract.
  const validationProbe = {
    ...row,
    matched_lines: matchedLines.map(({ line, offset }) => ({ line, offset })),
    // The X.7 summary inlines redacted excerpts (already scrubbed via
    // redactTextSensitiveValues); strip them from the probe so the
    // structural validator sees only the scalar fields under its
    // contract, mirroring the matched_lines treatment above.
    summary: row.summary ? {
      ...row.summary,
      top_3_match_lines: row.summary.top_3_match_lines.map(({ line_num, excerpt_hash }) => ({ line_num, excerpt_hash })),
    } : undefined,
  };
  validateNoSensitiveMaterial(validationProbe, "repo_checks");
  withSessionLock(domain, () => {
    appendJsonlLine(repoChecksJsonlPath(domain), row);
  });

  return {
    created: true,
    check_id: row.check_id,
    check_type: normalizedType,
    target_domain: domain,
    file_path: filePath,
    matched,
    matched_lines: matchedLines,
    matched_lines_truncated: matchedLinesTruncated,
    scanned_lines: scannedLines,
    file_hash: fileHash,
    file_size: stat.size,
    binary: isBinary,
    not_found: false,
    summary: row.summary,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Cycle O.6 — OSS observation kinds.
//
// These are `kind` VALUES inside `observation.recorded` payloads — NOT new
// top-level FRONTIER_EVENT_KINDS. Producers stamp them on
// `payload.observation_kind` (matching the T.5 jwt_observed precedent).
// Pack-surfacing predicates (cli-tool-packs.js applicable_when) read the
// observation list and fire on these kind values.
//
// Per O-P7 every payload must pass `validateNoSensitiveMaterial`. The
// recorder builds the payload, validates it, then appends a `surface.observed`
// or `observation.recorded` event with the appropriate observation_kind
// stamped on `payload`.
//
// NO raw secret values. config_misuse_observed carries `value_hash` (sha256)
// not the raw value; dependency_observed carries only `known_cve_ids[]` plus
// metadata (no advisory body); unsafe_sink_observed carries only the symbol
// name + sink classification (no code snippet); crash_observed carries an
// `asan_report_hash` (sha256) not the raw report.

const OSS_OBSERVATION_KIND_VALUES = Object.freeze([
  "dependency_observed",
  "unsafe_sink_observed",
  "crash_observed",
  "config_misuse_observed",
]);

function isOssObservationKind(value) {
  return typeof value === "string" && OSS_OBSERVATION_KIND_VALUES.includes(value);
}

// Cycle Y.1 — Capability observation kinds register at the same
// `observation.recorded` dispatch point as OSS kinds and the T.5
// jwt_observed precedent. They are SIBLINGS of OSS_OBSERVATION_KIND_VALUES
// — no top-level FRONTIER_EVENT_KIND is added (Y-P1 / X-P8). The shape +
// witness validators live in capability-observations.js; this module
// re-exports the closed-enum predicate so producers that already filter
// `observation.recorded` payloads by kind family can branch on capability
// kinds without crossing module boundaries.
const {
  CAPABILITY_OBSERVATION_KIND_VALUES,
  isCapabilityObservationKind,
} = require("./capability-observations.js");

// Field-shape validators per observation kind. Each returns the normalized
// payload (after a deep-clone-and-validate pass) or throws a structured
// ToolError when the shape is wrong. The validator does NOT enrich the
// payload — producers are responsible for providing every required field.

function assertNonEmptyStringField(value, fieldName) {
  if (typeof value !== "string" || !value.trim()) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `${fieldName} must be a non-empty string`,
    );
  }
  return value.trim();
}

function assertOptionalStringField(value, fieldName) {
  if (value == null) return null;
  return assertNonEmptyStringField(value, fieldName);
}

function assertOptionalIntegerField(value, fieldName) {
  if (value == null) return null;
  if (!Number.isInteger(value)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `${fieldName} must be an integer`,
    );
  }
  return value;
}

function assertOptionalStringArray(value, fieldName) {
  if (value == null) return null;
  if (!Array.isArray(value)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `${fieldName} must be a string array`,
    );
  }
  const out = [];
  for (let i = 0; i < value.length; i += 1) {
    const entry = value[i];
    if (typeof entry !== "string" || !entry.trim()) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `${fieldName}[${i}] must be a non-empty string`,
      );
    }
    out.push(entry.trim());
  }
  return out;
}

function assertBooleanField(value, fieldName) {
  if (typeof value !== "boolean") {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `${fieldName} must be a boolean`,
    );
  }
  return value;
}

function buildDependencyObservedPayload(input) {
  const payload = {
    observation_kind: "dependency_observed",
    ecosystem: assertNonEmptyStringField(input.ecosystem, "ecosystem"),
    package: assertNonEmptyStringField(input.package, "package"),
    version: assertNonEmptyStringField(input.version, "version"),
    manifest_path: assertNonEmptyStringField(input.manifest_path, "manifest_path"),
    has_lockfile: assertBooleanField(input.has_lockfile, "has_lockfile"),
  };
  const cveIds = assertOptionalStringArray(input.known_cve_ids, "known_cve_ids");
  if (cveIds && cveIds.length > 0) {
    payload.known_cve_ids = cveIds;
  }
  validateNoSensitiveMaterial(payload, "oss_observation.dependency_observed");
  return payload;
}

function buildUnsafeSinkObservedPayload(input) {
  const payload = {
    observation_kind: "unsafe_sink_observed",
    file_path: assertNonEmptyStringField(input.file_path, "file_path"),
    symbol: assertNonEmptyStringField(input.symbol, "symbol"),
    sink_kind: assertNonEmptyStringField(input.sink_kind, "sink_kind"),
    language: assertNonEmptyStringField(input.language, "language"),
  };
  validateNoSensitiveMaterial(payload, "oss_observation.unsafe_sink_observed");
  return payload;
}

function buildCrashObservedPayload(input) {
  const payload = {
    observation_kind: "crash_observed",
    harness: assertNonEmptyStringField(input.harness, "harness"),
    exit_code: assertOptionalIntegerField(input.exit_code, "exit_code"),
    asan_report_hash: assertNonEmptyStringField(input.asan_report_hash, "asan_report_hash"),
  };
  if (payload.exit_code == null) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "exit_code is required for crash_observed",
    );
  }
  const filePath = assertOptionalStringField(input.file_path, "file_path");
  if (filePath) payload.file_path = filePath;
  const signal = assertOptionalStringField(input.signal, "signal");
  if (signal) payload.signal = signal;
  validateNoSensitiveMaterial(payload, "oss_observation.crash_observed");
  return payload;
}

function buildConfigMisuseObservedPayload(input) {
  // `key` carries the config key name (not the secret value); `value_hash` is
  // a sha256 of the value bytes so downstream can dedupe / fingerprint without
  // ever persisting the raw value. The sensitive-material guard will reject
  // payloads where `key` matches the SENSITIVE_KEY_RE pattern unless the
  // suffix is safe; producers SHOULD pass a safe-shaped key like
  // `config_misuse_key` and stash the raw key in a separate field — but here
  // we accept the raw config key because operators expect to see
  // "TLS_CIPHER_LIST" or "debug_mode" verbatim. The guard runs against the
  // OUTER payload object's keys, not on the string value held in `key`.
  const payload = {
    observation_kind: "config_misuse_observed",
    file_path: assertNonEmptyStringField(input.file_path, "file_path"),
    key: assertNonEmptyStringField(input.key, "key"),
    value_hash: assertNonEmptyStringField(input.value_hash, "value_hash"),
    misuse_class: assertNonEmptyStringField(input.misuse_class, "misuse_class"),
  };
  validateNoSensitiveMaterial(payload, "oss_observation.config_misuse_observed");
  return payload;
}

const OSS_OBSERVATION_BUILDERS = Object.freeze({
  dependency_observed: buildDependencyObservedPayload,
  unsafe_sink_observed: buildUnsafeSinkObservedPayload,
  crash_observed: buildCrashObservedPayload,
  config_misuse_observed: buildConfigMisuseObservedPayload,
});

function buildOssObservationPayload(kind, input) {
  const builder = OSS_OBSERVATION_BUILDERS[kind];
  if (!builder) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `Unknown OSS observation kind: ${kind}`,
    );
  }
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `OSS observation payload for ${kind} must be a plain object`,
    );
  }
  return builder(input);
}

// Emit an `observation.recorded` frontier event carrying an OSS observation
// payload. Producers (static analyzers via bob_repo_check, fuzz runs via
// bob_repo_docker_run, dependency walkers via bob_repo_inventory follow-ups)
// call this with the kind + structured payload.
function recordOssObservation({
  target_domain: targetDomain,
  surface_id: surfaceId,
  observation_kind: observationKind,
  payload,
  source_ref: sourceRef = null,
} = {}) {
  const domain = assertSafeDomain(targetDomain);
  const sid = assertNonEmptyStringField(surfaceId, "surface_id");
  const kind = assertNonEmptyStringField(observationKind, "observation_kind");
  if (!isOssObservationKind(kind)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `observation_kind must be one of ${OSS_OBSERVATION_KIND_VALUES.join(", ")}`,
    );
  }
  const builtPayload = buildOssObservationPayload(kind, payload);
  const event = appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    surface_id: sid,
    payload: builtPayload,
    source: {
      artifact: "repo-inventory.json",
      ref: sourceRef == null ? null : String(sourceRef),
    },
  });
  try {
    scheduleMaterialization(domain);
  } catch {
    // Best-effort: the next producer event will trigger materialization.
  }
  return event;
}

module.exports = {
  assertHistoryAvailableForRef,
  deriveRepoTargetDomain,
  deriveRepoHashFromPath,
  normalizeHistoryRef,
  initRepoSession,
  readRepoSession,
  buildRepoInventory,
  repoCheck,
  buildRepoCheckSummary,
  // Exposed for cross-module reuse / tests.
  REPO_CHECK_MAX_FILE_BYTES,
  REPO_CHECK_MAX_EXCERPTS,
  REPO_CHECK_SUMMARY_EXCERPT_MAX_CHARS,
  REPO_CHECK_SUMMARY_TOP_N,
  REPO_CHECK_TYPES,
  REPO_WALK_MAX_FILES,
  SEED_CORPUS_SUMMARY_LIMIT,
  SEED_CORPUS_SAMPLE_RELS_LIMIT,
  RepoTooLargeError,
  safeBasename,
  sha8,
  // Cycle O.6 OSS observation kinds.
  OSS_OBSERVATION_KIND_VALUES,
  OSS_OBSERVATION_BUILDERS,
  isOssObservationKind,
  buildOssObservationPayload,
  recordOssObservation,
  // Cycle Y.1 capability observation kinds (siblings of OSS kinds; both
  // ride observation.recorded — Y-P1 / X-P8 honored).
  CAPABILITY_OBSERVATION_KIND_VALUES,
  isCapabilityObservationKind,
};

// Quieter shadow imports kept for parity with other session-init paths.
// eslint-disable-next-line no-unused-vars
const _unusedNormalizeOptionalText = normalizeOptionalText;
