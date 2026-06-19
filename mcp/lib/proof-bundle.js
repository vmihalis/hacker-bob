"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  parseFindingId,
} = require("./validation.js");
const {
  proofBundlePaths,
  evidencePackPaths,
  repoCommandRunsJsonlPath,
  repoRunsDir,
  verificationRoundPaths,
} = require("./paths.js");
const {
  loadJsonDocumentStrict,
  readFileUtf8,
  withSessionLock,
  writeFileAtomic,
  writeMarkdownMirror,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");
const {
  findingIdSetForVerificationContext,
} = require("./verification-finding-id-adapter.js");
const {
  normalizeVerificationRoundDocument,
} = require("./verification-round-store.js");
const {
  safeGovernanceContextForDomain,
} = require("./governance-context.js");
const {
  hashCanonicalJson,
  isPlainObject,
} = require("./verification-contracts.js");
const {
  classifyFoundryOutcome,
  computeInvariantRunHash,
  invariantFoundryResultHash,
} = require("./invariant-runner.js");

const PROOF_BUNDLES_VERSION = 1;
const PROOF_BUNDLE_KINDS = Object.freeze(["replay_script", "invariant", "differential"]);
const MAX_REPLAY_COMMAND_TOKENS = 64;
const MAX_REPLAY_COMMAND_TOKEN_CHARS = 2048;
const MAX_REPLAY_SUMMARY_CHARS = 2000;
const MAX_SNIPPET_CHARS = 4000;
const MAX_JSON_VALUE_CHARS = 8000;
const HEX64_RE = /^[0-9a-f]{64}$/i;
const REPO_RUN_ID_RE = /^[a-z0-9][a-z0-9-]{0,127}$/;
const DISALLOWED_REPO_COMMAND_EXIT_CODES = Object.freeze([125, 126, 127]);
const TIMESTAMP_FIELD_RE = /(?:^|_)(?:at|time|timestamp)$/i;

function assertMaxChars(text, fieldName, maxChars) {
  if (text.length > maxChars) {
    throw new Error(`${fieldName} must be at most ${maxChars} characters`);
  }
  return text;
}

function assertHex64(value, fieldName) {
  if (typeof value !== "string" || !HEX64_RE.test(value)) {
    throw new Error(`${fieldName} must be a 64-hex content digest`);
  }
  return value.toLowerCase();
}

function assertRepoRunId(value, fieldName) {
  const normalized = assertNonEmptyString(value, fieldName);
  if (!REPO_RUN_ID_RE.test(normalized)) {
    throw new Error(`${fieldName} must be a path-safe repo run id`);
  }
  return normalized;
}

function cloneJsonValue(value, fieldName) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new Error(`${fieldName} must be JSON-serializable`);
  }
  if (serialized == null) {
    throw new Error(`${fieldName} must be JSON-serializable`);
  }
  if (serialized.length > MAX_JSON_VALUE_CHARS) {
    throw new Error(`${fieldName} is too large; keep proof bundle artifacts bounded`);
  }
  return JSON.parse(serialized);
}

function normalizeOptionalBoundedText(value, fieldName, maxChars) {
  if (value == null) return null;
  const normalized = assertMaxChars(assertRequiredText(value, fieldName), fieldName, maxChars);
  validateNoSensitiveMaterial(normalized, fieldName);
  return normalized;
}

function readJsonlRows(filePath, label) {
  if (!fs.existsSync(filePath)) return [];
  const raw = readFileUtf8(filePath, { label });
  const rows = [];
  let lineNumber = 0;
  for (const line of raw.split(/\r?\n/)) {
    lineNumber += 1;
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (!isPlainObject(parsed)) throw new Error("row is not an object");
      rows.push(parsed);
    } catch (error) {
      throw new Error(`${label} contains malformed JSON at line ${lineNumber}: ${error.message || String(error)}`);
    }
  }
  return rows;
}

function readRepoCommandRunRows(domain) {
  return readJsonlRows(repoCommandRunsJsonlPath(domain), "repo-command-runs.jsonl");
}

function readInvariantRunRows(domain) {
  const { readInvariantRunCorpus } = require("./invariant-runner.js");
  return readInvariantRunCorpus({ target_domain: domain }).runs;
}

function assertReplayNetworkMode(row, fieldName) {
  if (row.network_mode !== "none") {
    throw new Error(`${fieldName} must reference a --network none repo docker run`);
  }
  return "none";
}

function normalizeReplayWorkMountMode(row, fieldName) {
  if (row.work_mount_mode == null) {
    return {
      value: "read_write",
      legacy_assumed: true,
    };
  }
  if (row.work_mount_mode !== "read_write") {
    throw new Error(`${fieldName} must reference a read-write /work repo docker run`);
  }
  return {
    value: row.work_mount_mode,
    legacy_assumed: false,
  };
}

function assertReplayRunFindingBinding(row, findingId, fieldName) {
  const replayContext = isPlainObject(row.replay_context) ? row.replay_context : null;
  if (!replayContext || replayContext.finding_id == null) {
    throw new Error(`${fieldName} must carry replay_context.finding_id for proof bundle binding`);
  }
  const actual = parseFindingId(replayContext.finding_id);
  if (actual !== findingId) {
    throw new Error(`${fieldName} replay_context.finding_id ${actual} does not match proof bundle finding_id ${findingId}`);
  }
  return actual;
}

function assertBaselineReplayRun(row, fieldName) {
  const checkoutFields = [
    "checkout_ref",
    "checkout_kind",
    "checkout_object",
    "checkout_object_format",
    "checkout_patch_hash",
  ];
  const present = checkoutFields.filter((field) => row[field] != null);
  if (present.length > 0) {
    throw new Error(`${fieldName} must reference a baseline repo docker run without checkout fields; use bundle_kind differential for control or patched-tree runs`);
  }
}

function readRepoCommandRunRow(rows, runId, fieldName, expectedFindingId = null) {
  const normalizedRunId = assertRepoRunId(runId, fieldName);
  const matchingRows = rows.filter((entry) => entry && entry.run_id === normalizedRunId);
  if (matchingRows.length === 0) {
    throw new Error(`${fieldName} does not match a repo-command-runs.jsonl row`);
  }
  if (matchingRows.length > 1) {
    const rowHashes = new Set(matchingRows.map((row) => hashCanonicalJson(row)));
    if (rowHashes.size > 1) {
      throw new Error(`${fieldName} has ambiguous duplicate entries in repo-command-runs.jsonl; re-run is required`);
    }
  }
  const row = matchingRows[0];
  if (row.dry_run !== false) {
    throw new Error(`${fieldName} must reference a live non-dry-run repo docker run`);
  }
  if (row.timed_out === true) {
    throw new Error(`${fieldName} must reference a completed repo docker run, not a timed-out run`);
  }
  if (DISALLOWED_REPO_COMMAND_EXIT_CODES.includes(row.exit_code)) {
    throw new Error(`${fieldName} must not reference a Docker/runtime infrastructure failure exit code`);
  }
  assertBaselineReplayRun(row, fieldName);
  assertReplayNetworkMode(row, fieldName);
  if (row.mount_mode !== "read_only") {
    throw new Error(`${fieldName} must reference a read-only /src repo docker run`);
  }
  normalizeReplayWorkMountMode(row, fieldName);
  if (typeof row.image_tag !== "string" || !row.image_tag.trim()) {
    throw new Error(`${fieldName} must carry the O-D6 image_tag for replay`);
  }
  if (typeof row.replay_command_hash !== "string" || !HEX64_RE.test(row.replay_command_hash)) {
    throw new Error(`${fieldName} must carry a replay_command_hash for proof bundle replay`);
  }
  if (expectedFindingId) {
    assertReplayRunFindingBinding(row, expectedFindingId, fieldName);
  }
  return row;
}

function sha256FileChunked(filePath) {
  let fd = null;
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return null;
    fd = fs.openSync(filePath, "r");
    const hash = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let bytesRead = 0;
    do {
      bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead > 0) hash.update(buffer.subarray(0, bytesRead));
    } while (bytesRead > 0);
    return hash.digest("hex");
  } catch {
    return null;
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

function assertCapturedOutputHash(domain, row, fieldName, streamName) {
  const runId = assertRepoRunId(row.run_id, `${fieldName}.run_id`);
  const recorded = assertHex64(row[`${streamName}_hash`], `${fieldName}.${streamName}_hash`);
  const observed = sha256FileChunked(path.join(repoRunsDir(domain), `${runId}.${streamName}`));
  if (observed == null) {
    throw new Error(`${fieldName}.${streamName} file is missing or unreadable; cannot verify proof bundle run integrity`);
  }
  if (observed !== recorded) {
    throw new Error(`${fieldName}.${streamName}_hash does not match the captured ${streamName} file`);
  }
  return observed;
}

function normalizeReplayCommand(value, row, fieldName) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${fieldName} must be a non-empty command token array`);
  }
  if (value.length > MAX_REPLAY_COMMAND_TOKENS) {
    throw new Error(`${fieldName} must contain at most ${MAX_REPLAY_COMMAND_TOKENS} tokens`);
  }
  const command = value.map((token, index) => {
    const normalized = assertMaxChars(
      assertRequiredText(token, `${fieldName}[${index}]`),
      `${fieldName}[${index}]`,
      MAX_REPLAY_COMMAND_TOKEN_CHARS,
    );
    validateNoSensitiveMaterial(normalized, `${fieldName}[${index}]`);
    return normalized;
  });
  const observedHash = crypto.createHash("sha256").update(JSON.stringify(command)).digest("hex");
  if (row.replay_command_hash.toLowerCase() !== observedHash) {
    throw new Error(`${fieldName} does not match repo-command-runs replay_command_hash`);
  }
  return command;
}

function replayImageIdentity(imageTag, domain, fieldName) {
  const normalized = assertNonEmptyString(imageTag, fieldName);
  const targetScopedPrefix = `bob-oss-${domain}:`;
  if (normalized.startsWith(targetScopedPrefix)) {
    return `bob-oss:${normalized.slice(targetScopedPrefix.length)}`;
  }
  return normalized;
}

function stableRepoRunProjection(domain, row, fieldName, findingId) {
  const imageTag = assertNonEmptyString(row.image_tag, `${fieldName}.image_tag`);
  const workMountMode = normalizeReplayWorkMountMode(row, `${fieldName}.work_mount_mode`);
  const replayFindingId = assertReplayRunFindingBinding(row, findingId, fieldName);
  const projection = {
    run_id: assertRepoRunId(row.run_id, `${fieldName}.run_id`),
    replay_finding_id: replayFindingId,
    dry_run: row.dry_run,
    exit_code: Number.isInteger(row.exit_code) ? row.exit_code : null,
    signal: typeof row.signal === "string" ? row.signal : null,
    timed_out: row.timed_out === true,
    command_hash: assertHex64(row.command_hash, `${fieldName}.command_hash`),
    replay_command_hash: assertHex64(row.replay_command_hash, `${fieldName}.replay_command_hash`),
    argv_hash: row.argv_hash == null ? null : assertHex64(row.argv_hash, `${fieldName}.argv_hash`),
    network_mode: assertReplayNetworkMode(row, `${fieldName}.network_mode`),
    src_mount_mode: row.mount_mode,
    work_mount_mode: workMountMode.value,
    image_tag: imageTag,
    image_identity: replayImageIdentity(imageTag, domain, `${fieldName}.image_tag`),
    stdout_hash: assertCapturedOutputHash(domain, row, fieldName, "stdout"),
    stderr_hash: assertCapturedOutputHash(domain, row, fieldName, "stderr"),
  };
  if (workMountMode.legacy_assumed) projection.work_mount_mode_legacy_assumed = true;
  if (Number.isInteger(row.timeout_ms)) projection.timeout_ms = row.timeout_ms;
  if (Number.isInteger(row.stdout_size_bytes)) projection.stdout_size_bytes = row.stdout_size_bytes;
  else if (Number.isInteger(row.stdout_bytes)) projection.stdout_size_bytes = row.stdout_bytes;
  if (Number.isInteger(row.stderr_size_bytes)) projection.stderr_size_bytes = row.stderr_size_bytes;
  else if (Number.isInteger(row.stderr_bytes)) projection.stderr_size_bytes = row.stderr_bytes;
  if (typeof row.stdout_truncated === "boolean") projection.stdout_truncated = row.stdout_truncated;
  if (typeof row.stderr_truncated === "boolean") projection.stderr_truncated = row.stderr_truncated;
  return projection;
}

function normalizeReplayArtifact(artifact, { domain, repoCommandRunRows, index, findingId }) {
  if (!isPlainObject(artifact)) {
    throw new Error(`artifacts[${index}] must be an object`);
  }
  const row = readRepoCommandRunRow(repoCommandRunRows, artifact.run_id, `artifacts[${index}].run_id`, findingId);
  const replayCommand = normalizeReplayCommand(artifact.replay_command, row, `artifacts[${index}].replay_command`);
  const runProjection = stableRepoRunProjection(domain, row, `artifacts[${index}].repo_run`, findingId);
  const runHash = hashCanonicalJson(runProjection);
  if (artifact.run_hash != null && assertHex64(artifact.run_hash, `artifacts[${index}].run_hash`) !== runHash) {
    throw new Error(`artifacts[${index}].run_hash does not match the repo docker run handle`);
  }
  const normalized = {
    artifact_kind: "replay_script",
    replay_command: replayCommand,
    run_id: runProjection.run_id,
    replay_finding_id: runProjection.replay_finding_id,
    run_hash: runHash,
    image_tag: runProjection.image_tag,
    image_identity: runProjection.image_identity,
    network_mode: runProjection.network_mode,
    src_mount_mode: runProjection.src_mount_mode,
    work_mount_mode: runProjection.work_mount_mode,
    command_hash: runProjection.command_hash,
    replay_command_hash: runProjection.replay_command_hash,
    stdout_hash: runProjection.stdout_hash,
    stderr_hash: runProjection.stderr_hash,
  };
  if (runProjection.work_mount_mode_legacy_assumed) {
    normalized.work_mount_mode_legacy_assumed = true;
  }
  for (const key of [
    "exit_code",
    "signal",
    "timed_out",
    "timeout_ms",
    "stdout_size_bytes",
    "stderr_size_bytes",
    "stdout_truncated",
    "stderr_truncated",
  ]) {
    if (runProjection[key] != null) normalized[key] = runProjection[key];
  }
  const replaySummary = normalizeOptionalBoundedText(
    artifact.replay_summary,
    `artifacts[${index}].replay_summary`,
    MAX_REPLAY_SUMMARY_CHARS,
  );
  if (replaySummary) normalized.replay_summary = replaySummary;
  const snippet = normalizeOptionalBoundedText(artifact.snippet, `artifacts[${index}].snippet`, MAX_SNIPPET_CHARS);
  if (snippet) normalized.snippet = snippet;
  validateNoSensitiveMaterial(normalized, `artifacts[${index}]`);
  return normalized;
}

function readInvariantRunRow(rows, runHash, fieldName, expectedFindingId) {
  const normalizedRunHash = assertHex64(runHash, fieldName);
  const matchingRows = rows.filter((entry) => entry && entry.run_hash === normalizedRunHash);
  if (matchingRows.length === 0) {
    throw new Error(`${fieldName} does not match an invariant-runs.jsonl row`);
  }
  if (matchingRows.length > 1) {
    const rowHashes = new Set(matchingRows.map((row) => hashCanonicalJson(row)));
    if (rowHashes.size > 1) {
      throw new Error(`${fieldName} has ambiguous duplicate entries in invariant-runs.jsonl`);
    }
  }
  const row = matchingRows[0];
  if (row.dry_run !== false) {
    throw new Error(`${fieldName} must reference an executed invariant run, not a dry-run plan`);
  }
  if (row.finding_id == null) {
    throw new Error(
      `${fieldName} references a legacy invariant row without finding_id; re-run the invariant for proof bundle finding_id ${expectedFindingId}`,
    );
  }
  if (row.finding_id !== expectedFindingId) {
    throw new Error(`${fieldName} finding_id does not match proof bundle finding_id ${expectedFindingId}`);
  }
  const expectedFoundryResultHash = invariantFoundryResultHash(row.foundry_result);
  if (row.foundry_result_hash != null && row.foundry_result_hash !== expectedFoundryResultHash) {
    throw new Error(`${fieldName} foundry_result_hash does not match invariant run result payload`);
  }
  const expectedRunHash = computeInvariantRunHash(row);
  if (expectedRunHash !== normalizedRunHash) {
    throw new Error(`${fieldName} does not bind the invariant run outcome and Foundry result; re-run the invariant before writing proof bundles`);
  }
  const classifiedOutcome = classifyFoundryOutcome(row.foundry_result);
  if (classifiedOutcome !== row.outcome) {
    throw new Error(`${fieldName} outcome does not match invariant run Foundry result`);
  }
  if (row.outcome !== "test_passed") {
    throw new Error(`${fieldName} must reference a reproducing invariant run with outcome test_passed`);
  }
  return row;
}

function normalizeInvariantArtifact(artifact, { invariantRunRows, index, findingId }) {
  if (!isPlainObject(artifact)) {
    throw new Error(`artifacts[${index}] must be an object`);
  }
  const row = readInvariantRunRow(invariantRunRows, artifact.run_hash, `artifacts[${index}].run_hash`, findingId);
  const normalized = {
    artifact_kind: "invariant",
    finding_id: row.finding_id,
    run_hash: assertHex64(row.run_hash, `artifacts[${index}].run_hash`),
    outcome: assertNonEmptyString(row.outcome || "unknown", `artifacts[${index}].outcome`),
  };
  for (const key of ["template_id", "contract_name", "function_name", "execution_context_hash"]) {
    if (row[key] != null) normalized[key] = assertNonEmptyString(row[key], `artifacts[${index}].${key}`);
  }
  const snippet = normalizeOptionalBoundedText(artifact.snippet, `artifacts[${index}].snippet`, MAX_SNIPPET_CHARS);
  if (snippet) normalized.snippet = snippet;
  validateNoSensitiveMaterial(normalized, `artifacts[${index}]`);
  return normalized;
}

function readEvidencePackDifferential(domain, findingId) {
  const doc = loadJsonDocumentStrict(evidencePackPaths(domain).json, "evidence packs JSON");
  const packs = Array.isArray(doc && doc.packs) ? doc.packs : [];
  const pack = packs.find((entry) => entry && entry.finding_id === findingId);
  if (!pack || !isPlainObject(pack.differential)) {
    throw new Error(`differential proof for ${findingId} must match an evidence pack differential`);
  }
  return pack.differential;
}

function assertDifferentialBoundToFinding(domain, findingId, rawDifferential, normalizedDifferential) {
  if (rawDifferential.finding_id != null) {
    const suppliedFindingId = parseFindingId(rawDifferential.finding_id);
    if (suppliedFindingId !== findingId) {
      throw new Error(`differential.finding_id ${suppliedFindingId} does not match proof bundle finding_id ${findingId}`);
    }
  }
  const evidenceDifferential = readEvidencePackDifferential(domain, findingId);
  if (hashCanonicalJson(evidenceDifferential) !== hashCanonicalJson(normalizedDifferential)) {
    throw new Error(`differential proof for ${findingId} must match the same finding's evidence pack differential`);
  }
}

function normalizeDifferentialArtifact(artifact, { domain, index, findingId }) {
  if (!isPlainObject(artifact)) {
    throw new Error(`artifacts[${index}] must be an object`);
  }
  const rawDifferential = isPlainObject(artifact.differential) ? artifact.differential : artifact;
  const { normalizeDifferential } = require("./evidence.js");
  const differential = normalizeDifferential(rawDifferential, { domain });
  assertDifferentialBoundToFinding(domain, findingId, rawDifferential, differential);
  const normalized = {
    artifact_kind: "differential",
    differential: cloneJsonValue(differential, `artifacts[${index}].differential`),
  };
  validateNoSensitiveMaterial(normalized, `artifacts[${index}]`);
  return normalized;
}

function normalizeArtifacts(pack, bundleKind, {
  domain,
  findingId,
  repoCommandRunRows = null,
  invariantRunRows = null,
}) {
  if (!Array.isArray(pack.artifacts) || pack.artifacts.length === 0) {
    throw new Error("artifacts must be a non-empty array");
  }
  return pack.artifacts.map((artifact, index) => {
    if (bundleKind === "replay_script") {
      return normalizeReplayArtifact(artifact, {
        domain,
        repoCommandRunRows: repoCommandRunRows || readRepoCommandRunRows(domain),
        index,
        findingId,
      });
    }
    if (bundleKind === "invariant") {
      return normalizeInvariantArtifact(artifact, {
        invariantRunRows: invariantRunRows || readInvariantRunRows(domain),
        index,
        findingId,
      });
    }
    return normalizeDifferentialArtifact(artifact, { domain, index, findingId });
  });
}

function zeroTimestampFields(value) {
  if (Array.isArray(value)) {
    return value.map((item) => zeroTimestampFields(item));
  }
  if (isPlainObject(value)) {
    const out = {};
    for (const [key, child] of Object.entries(value)) {
      out[key] = TIMESTAMP_FIELD_RE.test(key) ? "0000-00-00T00:00:00.000Z" : zeroTimestampFields(child);
    }
    return out;
  }
  return value;
}

function proofBundleHashArtifact(artifact) {
  if (!isPlainObject(artifact)) return zeroTimestampFields(artifact);
  const normalized = {};
  for (const [key, value] of Object.entries(artifact)) {
    // Replay run_id/run_hash and raw image_tag include random or target-scoped
    // row identity; the bundle hash binds target-independent replay fields.
    if (artifact.artifact_kind === "replay_script" && (key === "run_id" || key === "run_hash")) {
      continue;
    }
    if (artifact.artifact_kind === "replay_script" && key === "image_tag") {
      continue;
    }
    normalized[key] = zeroTimestampFields(value);
  }
  return normalized;
}

function computeProofBundleHash(pack) {
  return hashCanonicalJson({
    finding_id: pack.finding_id,
    bundle_kind: pack.bundle_kind,
    artifacts: Array.isArray(pack.artifacts) ? pack.artifacts.map(proofBundleHashArtifact) : [],
  });
}

function normalizeProofBundle(pack, {
  domain,
  findingIdSet,
  finalReportableIdSet,
  repoCommandRunRows = null,
  invariantRunRows = null,
}) {
  if (!isPlainObject(pack)) {
    throw new Error("packs entries must be objects");
  }
  const findingId = parseFindingId(pack.finding_id);
  if (!findingIdSet.has(findingId)) {
    throw new Error(`Unknown finding_id: ${findingId}`);
  }
  if (!finalReportableIdSet.has(findingId)) {
    throw new Error(`Proof bundle references non-reportable final finding_id: ${findingId}`);
  }
  const bundleKind = assertEnumValue(pack.bundle_kind, PROOF_BUNDLE_KINDS, "bundle_kind");
  const normalized = {
    finding_id: findingId,
    bundle_kind: bundleKind,
    artifacts: normalizeArtifacts(pack, bundleKind, {
      domain,
      findingId,
      repoCommandRunRows,
      invariantRunRows,
    }),
  };
  normalized.bundle_hash = computeProofBundleHash(normalized);
  if (pack.bundle_hash != null) {
    const suppliedHash = assertHex64(pack.bundle_hash, "bundle_hash");
    if (suppliedHash !== normalized.bundle_hash) {
      throw new Error(`bundle_hash for ${findingId} does not match canonical proof bundle payload`);
    }
  }
  validateNoSensitiveMaterial(normalized, `proof_bundle.${findingId}`);
  return normalized;
}

function normalizeProofBundlesDocument(document, {
  expectedDomain = null,
  findingIdSet = null,
  finalReportableIdSet = null,
  verificationBinding = null,
} = {}) {
  if (!isPlainObject(document)) {
    throw new Error("proof bundles document must be an object");
  }
  const domain = assertNonEmptyString(document.target_domain, "target_domain");
  if (expectedDomain != null && domain !== expectedDomain) {
    throw new Error(`proof bundles target_domain mismatch: expected ${expectedDomain}`);
  }
  if (!Array.isArray(document.packs)) {
    throw new Error("packs must be an array");
  }
  const normalized = {
    version: assertInteger(document.version, "version", { min: 1, max: 1 }),
    target_domain: domain,
    packs: [],
  };
  for (const field of ["verification_attempt_id", "verification_snapshot_hash", "final_verification_hash"]) {
    if (verificationBinding) {
      const actual = assertNonEmptyString(document[field], field);
      if (actual !== verificationBinding[field]) {
        throw new Error(`${field} does not match current final verification`);
      }
      normalized[field] = actual;
    } else if (document[field] != null) {
      normalized[field] = assertNonEmptyString(document[field], field);
    }
  }

  if (!(findingIdSet instanceof Set)) {
    throw new Error("findingIdSet is required for proof bundle normalization");
  }
  if (!(finalReportableIdSet instanceof Set)) {
    throw new Error("finalReportableIdSet is required for proof bundle normalization");
  }
  const knownFindingIds = findingIdSet;
  const reportableIds = finalReportableIdSet;
  const needsRepoRows = document.packs.some((pack) => isPlainObject(pack) && pack.bundle_kind === "replay_script");
  const needsInvariantRows = document.packs.some((pack) => isPlainObject(pack) && pack.bundle_kind === "invariant");
  const repoCommandRunRows = needsRepoRows ? readRepoCommandRunRows(domain) : null;
  const invariantRunRows = needsInvariantRows ? readInvariantRunRows(domain) : null;
  const seen = new Set();
  for (const pack of document.packs) {
    const normalizedPack = normalizeProofBundle(pack, {
      domain,
      findingIdSet: knownFindingIds,
      finalReportableIdSet: reportableIds,
      repoCommandRunRows,
      invariantRunRows,
    });
    if (seen.has(normalizedPack.finding_id)) {
      throw new Error(`Duplicate finding_id in proof bundles: ${normalizedPack.finding_id}`);
    }
    seen.add(normalizedPack.finding_id);
    normalized.packs.push(normalizedPack);
  }
  normalized.packs.sort((a, b) => a.finding_id.localeCompare(b.finding_id));
  return normalized;
}

function verificationLib() {
  return require("./verification.js");
}

function pipelineEventsLib() {
  return require("./pipeline-events.js");
}

function loadFinalVerification(domain, findingIdSet, action = "proof bundle writing") {
  const paths = verificationRoundPaths(domain, "final");
  try {
    const document = loadJsonDocumentStrict(paths.json, "final verification round JSON");
    let effectiveFindingIdSet = findingIdSet;
    let v2Current = null;
    if (document && document.version === 2) {
      v2Current = verificationLib().requireV2State(domain);
      effectiveFindingIdSet = new Set(v2Current.snapshot.finding_ids);
    }
    const normalized = normalizeVerificationRoundDocument(document, {
      expectedDomain: domain,
      expectedRound: "final",
      findingIdSet: effectiveFindingIdSet,
    });
    if (normalized.version === 2) {
      verificationLib().assertCurrentV2RoundDocument(domain, normalized, {
        expectedRound: "final",
        state: v2Current.state,
        snapshot: v2Current.snapshot,
      });
    }
    return normalized;
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Final verification must exist and be valid before ${action}: ${error.message || String(error)}`,
    );
  }
}

function finalReportableIds(document) {
  return document.results
    .filter((result) => result.reportable === true)
    .map((result) => result.finding_id);
}

function readFindingIdSet(domain) {
  const { readFrozenEvidenceFindingIdSet } = require("./evidence.js");
  const frozen = readFrozenEvidenceFindingIdSet(domain);
  if (frozen.size > 0) return frozen;
  return findingIdSetForVerificationContext({ domain });
}

function escapeMarkdownText(value) {
  return String(value)
    .replace(/\\/g, "\\\\")
    .replace(/`/g, "\\`")
    .replace(/\r?\n/g, " ");
}

function renderProofBundlesMarkdown(document) {
  const lines = [
    "# Proof Bundles",
    `- Target: ${document.target_domain}`,
    ...(document.verification_attempt_id
      ? [
        `- Verification Attempt: ${document.verification_attempt_id}`,
        `- Verification Snapshot: ${document.verification_snapshot_hash}`,
        `- Final Verification Hash: ${document.final_verification_hash}`,
      ]
      : []),
    `- Bundles: ${document.packs.length}`,
    "",
  ];
  if (document.packs.length === 0) {
    lines.push("No proof bundles have been attached.");
    lines.push("");
    return `${lines.join("\n")}\n`;
  }
  for (const pack of document.packs) {
    lines.push(`## ${pack.finding_id}`);
    lines.push(`- Kind: ${pack.bundle_kind}`);
    lines.push(`- Bundle Hash: ${pack.bundle_hash}`);
    lines.push(`- Artifacts: ${pack.artifacts.length}`);
    for (const artifact of pack.artifacts) {
      if (artifact.artifact_kind === "replay_script") {
        lines.push(`  - Replay Run: ${artifact.run_id}`);
        lines.push(`  - Run Hash: ${artifact.run_hash}`);
        lines.push(`  - Image Tag: ${escapeMarkdownText(artifact.image_tag)}`);
        lines.push(`  - Network: ${artifact.network_mode}`);
        lines.push(`  - Mounts: /src ${artifact.src_mount_mode}; /work ${artifact.work_mount_mode}`);
      } else if (artifact.artifact_kind === "invariant") {
        lines.push(`  - Invariant Run Hash: ${artifact.run_hash}`);
        lines.push(`  - Outcome: ${artifact.outcome}`);
        if (artifact.template_id) lines.push(`  - Template: ${artifact.template_id}`);
      } else if (artifact.artifact_kind === "differential") {
        lines.push(`  - Differential: ${artifact.differential.control_kind} / ${artifact.differential.verdict}`);
        lines.push(`  - Vulnerable Run: ${artifact.differential.vuln_run_id}`);
        lines.push(`  - Control Run: ${artifact.differential.control_run_id}`);
      }
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

function writeProofBundles(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  if (!Array.isArray(args.packs)) {
    throw new Error("packs must be an array");
  }
  return withSessionLock(domain, () => {
    const findingIdSet = readFindingIdSet(domain);
    const finalRound = loadFinalVerification(domain, findingIdSet, "proof bundle writing");
    const verificationBinding = finalRound.version === 2
      ? verificationLib().evidenceBindingForFinal(domain, finalRound)
      : null;
    const reportableIds = finalReportableIds(finalRound);
    const finalReportableIdSet = new Set(reportableIds);
    const document = normalizeProofBundlesDocument({
      version: PROOF_BUNDLES_VERSION,
      target_domain: domain,
      ...(verificationBinding || {}),
      packs: args.packs,
    }, {
      expectedDomain: domain,
      findingIdSet,
      finalReportableIdSet,
      verificationBinding,
    });
    if (verificationBinding) {
      verificationLib().assertEvidenceMatchesFinal(domain, document, finalRound);
    }
    const writtenIds = new Set(document.packs.map((pack) => pack.finding_id));
    const missingFindingIds = reportableIds.filter((id) => !writtenIds.has(id));
    const paths = proofBundlePaths(domain);
    writeFileAtomic(paths.json, `${JSON.stringify(document, null, 2)}\n`);
    const response = {
      bundles_count: document.packs.length,
      reportable_findings: reportableIds.length,
      missing_finding_ids: missingFindingIds,
      written_json: paths.json,
    };
    if (verificationBinding) {
      response.verification_attempt_id = verificationBinding.verification_attempt_id;
      response.verification_snapshot_hash = verificationBinding.verification_snapshot_hash;
      response.final_verification_hash = verificationBinding.final_verification_hash;
    }
    writeMarkdownMirror(paths.markdown, renderProofBundlesMarkdown(document), response);
    pipelineEventsLib().safeAppendPipelineEventDirect(domain, "proof_bundle_written", {
      phase: "VERIFY",
      status: document.packs.length === 0 ? "empty" : (missingFindingIds.length > 0 ? "partial" : "written"),
      source: "bob_write_proof_bundle",
      verification_attempt_id: verificationBinding ? verificationBinding.verification_attempt_id : undefined,
      verification_snapshot_hash: verificationBinding ? verificationBinding.verification_snapshot_hash : undefined,
      final_verification_hash: verificationBinding ? verificationBinding.final_verification_hash : undefined,
      counts: {
        bundles: document.packs.length,
        reportable_findings: reportableIds.length,
        missing_findings: missingFindingIds.length,
      },
    }, safeGovernanceContextForDomain(domain));
    if (verificationBinding) verificationLib().refreshVerificationManifest(domain, { throw_on_error: true });
    return JSON.stringify(response);
  });
}

module.exports = {
  PROOF_BUNDLE_KINDS,
  PROOF_BUNDLES_VERSION,
  computeProofBundleHash,
  normalizeProofBundle,
  normalizeProofBundlesDocument,
  renderProofBundlesMarkdown,
  writeProofBundles,
};
