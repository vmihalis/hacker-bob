"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  normalizeOptionalText,
  parseFindingId,
} = require("./validation.js");
const {
  evidencePackPaths,
  repoCommandRunsJsonlPath,
  repoRunsDir,
  verificationRoundPaths,
} = require("./paths.js");
const {
  readFileUtf8,
  loadJsonDocumentStrict,
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
  readCurrentClaimFreeze,
} = require("./claim-freeze.js");
const {
  claimIdSetFromFindingIds,
  findingIdSetForVerificationContext,
} = require("./verification-finding-id-adapter.js");
const {
  normalizeVerificationRoundDocument,
} = require("./verification-round-store.js");
const {
  safeGovernanceContextForDomain,
} = require("./governance-context.js");
const {
  normalizeHistoryRef,
} = require("./repo-target.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");

const EVIDENCE_PACKS_VERSION = 1;
const MAX_SAMPLE_COUNT = 1000;
const MAX_REPRESENTATIVE_SAMPLES = 10;
const MAX_SENSITIVE_CLUSTERS = 20;
const MAX_TEXT_CHARS = 4000;
const MAX_REPLAY_SUMMARY_CHARS = 2000;
const MAX_REDACTION_NOTES_CHARS = 1000;
const MAX_JSON_VALUE_CHARS = 8000;
const DIFFERENTIAL_CONTROL_KINDS = Object.freeze(["upstream_fix", "self_patch", "pre_introduction"]);
const DIFFERENTIAL_VERDICTS = Object.freeze([
  "residual_confirmed",
  "patch_fixes",
  "regression_localized",
  "inconclusive",
]);
const MAX_CONTROL_SUMMARY_CHARS = 1000;
const MAX_CONTROL_REF_CHARS = 120;
const HEX64_RE = /^[0-9a-f]{64}$/i;
const GIT_OBJECT_ID_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;
const REPO_RUN_ID_RE = /^[a-z0-9][a-z0-9-]{0,127}$/;
const DISALLOWED_REPO_COMMAND_EXIT_CODES = Object.freeze([125, 126, 127]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function assertMaxChars(text, fieldName, maxChars) {
  if (text.length > maxChars) {
    throw new Error(`${fieldName} must be at most ${maxChars} characters`);
  }
  return text;
}

function cloneJsonValue(value, fieldName) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch (error) {
    throw new Error(`${fieldName} must be JSON-serializable`);
  }
  if (serialized == null) {
    throw new Error(`${fieldName} must be JSON-serializable`);
  }
  if (serialized.length > MAX_JSON_VALUE_CHARS) {
    throw new Error(`${fieldName} is too large; keep evidence samples bounded`);
  }
  return JSON.parse(serialized);
}

function readRepoCommandRunRows(domain) {
  const filePath = repoCommandRunsJsonlPath(domain);
  if (!fs.existsSync(filePath)) return [];
  const raw = readFileUtf8(filePath, { label: "repo-command-runs.jsonl" });
  const rows = [];
  let lineNumber = 0;
  for (const line of raw.split(/\r?\n/)) {
    lineNumber += 1;
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (!isPlainObject(parsed)) {
        throw new Error("row is not an object");
      }
      rows.push(parsed);
    } catch (error) {
      throw new Error(
        `repo-command-runs.jsonl contains malformed JSON at line ${lineNumber}; repair or re-run repo docker evidence before writing C10 differential evidence`,
      );
    }
  }
  return rows;
}

function readRepoCommandRunRow(rows, runId, fieldName, expectedCheckout = null) {
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
  if (row.network_mode !== "none") {
    throw new Error(`${fieldName} must reference a --network none repo docker run`);
  }
  if (row.mount_mode !== "read_only") {
    throw new Error(`${fieldName} must reference a read-only /src repo docker run`);
  }
  if (expectedCheckout) {
    if (row.checkout_ref !== expectedCheckout.ref || row.checkout_kind !== expectedCheckout.kind) {
      throw new Error(`${fieldName} must reference a matching S14 checkout run`);
    }
    const checkoutObject = assertGitObjectId(row.checkout_object, `${fieldName}.checkout_object`);
    assertGitObjectFormat(row.checkout_object_format, checkoutObject, `${fieldName}.checkout_object_format`);
  }
  return row;
}

function assertRepoRunId(value, fieldName) {
  const normalized = assertNonEmptyString(value, fieldName);
  if (!REPO_RUN_ID_RE.test(normalized)) {
    throw new Error(`${fieldName} must be a path-safe repo run id`);
  }
  return normalized;
}

function assertHex64(value, fieldName) {
  if (typeof value !== "string" || !HEX64_RE.test(value)) {
    throw new Error(`${fieldName} must be a 64-hex content digest`);
  }
  return value.toLowerCase();
}

function assertGitObjectId(value, fieldName) {
  if (typeof value !== "string" || !GIT_OBJECT_ID_RE.test(value)) {
    throw new Error(`${fieldName} must be a 40-hex SHA-1 or 64-hex SHA-256 git object id`);
  }
  return value.toLowerCase();
}

function assertGitObjectFormat(value, objectId, fieldName) {
  const fallback = objectId.length === 64 ? "sha256" : "sha1";
  const format = value == null ? fallback : assertEnumValue(value, ["sha1", "sha256"], fieldName);
  if ((format === "sha1" && objectId.length !== 40) || (format === "sha256" && objectId.length !== 64)) {
    throw new Error(`${fieldName} does not match checkout_object length`);
  }
  return format;
}

function exitCodeForRun(row, fieldName) {
  if (!Number.isInteger(row.exit_code)) {
    throw new Error(`${fieldName} must carry an integer exit_code for C10 firedness review`);
  }
  return row.exit_code;
}

function replayCommandHashForRun(row, fieldName) {
  if (typeof row.replay_command_hash === "string" && HEX64_RE.test(row.replay_command_hash)) {
    return row.replay_command_hash.toLowerCase();
  }
  throw new Error(`${fieldName} must carry a replay_command_hash for C10 comparison`);
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
      try {
        fs.closeSync(fd);
      } catch {
        // Caller treats read failures as missing hashes.
      }
    }
  }
}

function stdoutHashForRun(domain, row, fieldName) {
  const runId = assertRepoRunId(row.run_id, `${fieldName}.run_id`);
  const recordedHash = assertHex64(row.stdout_hash, `${fieldName}.stdout_hash`);
  const observedHash = sha256FileChunked(path.join(repoRunsDir(domain), `${runId}.stdout`));
  if (observedHash == null) {
    throw new Error(`${fieldName}.stdout file is missing or unreadable; cannot verify C10 stdout integrity`);
  }
  if (observedHash !== recordedHash) {
    throw new Error(`${fieldName}.stdout_hash does not match the captured stdout file`);
  }
  return observedHash;
}

// C10 differential verdict contract:
// - upstream_fix: vuln_fired=true and control_fired=true -> residual_confirmed
// - self_patch: vuln_fired=true and control_fired=false -> patch_fixes
// - pre_introduction: vuln_fired=true and control_fired=false -> regression_localized
// Any other fired pattern is recorded as inconclusive. Inconsistent supplied
// verdicts are downgraded to inconclusive rather than rejected so control runs
// never suppress a final reportable finding.
function expectedDifferentialVerdict(controlKind, vulnFired, controlFired) {
  if (controlKind === "upstream_fix" && vulnFired === true && controlFired === true) {
    return "residual_confirmed";
  }
  if (controlKind === "self_patch" && vulnFired === true && controlFired === false) {
    return "patch_fixes";
  }
  if (controlKind === "pre_introduction" && vulnFired === true && controlFired === false) {
    return "regression_localized";
  }
  return "inconclusive";
}

function normalizeDifferential(differential, { domain, repoCommandRunRows = null }) {
  if (!isPlainObject(differential)) {
    throw new Error("differential must be an object");
  }
  const controlKind = assertEnumValue(differential.control_kind, DIFFERENTIAL_CONTROL_KINDS, "differential.control_kind");
  const suppliedVerdict = assertEnumValue(differential.verdict, DIFFERENTIAL_VERDICTS, "differential.verdict");
  const vulnRunId = assertNonEmptyString(differential.vuln_run_id, "differential.vuln_run_id");
  const controlRunId = assertNonEmptyString(differential.control_run_id, "differential.control_run_id");
  if (vulnRunId === controlRunId) {
    throw new Error("differential.vuln_run_id and differential.control_run_id must differ");
  }
  const controlRef = assertMaxChars(
    normalizeHistoryRef(
      assertRequiredText(differential.control_ref, "differential.control_ref"),
      "differential.control_ref",
    ),
    "differential.control_ref",
    MAX_CONTROL_REF_CHARS,
  );
  const allRows = repoCommandRunRows || readRepoCommandRunRows(domain);
  const vulnRow = readRepoCommandRunRow(allRows, vulnRunId, "differential.vuln_run_id");
  if (vulnRow.checkout_ref != null || vulnRow.checkout_kind != null) {
    throw new Error("differential.vuln_run_id must reference a baseline non-checkout run");
  }
  const controlRow = readRepoCommandRunRow(allRows, controlRunId, "differential.control_run_id", {
    ref: controlRef,
    kind: controlKind,
  });
  const controlCheckoutObject = assertGitObjectId(controlRow.checkout_object, "differential.control_checkout_object");
  const controlCheckoutObjectFormat = assertGitObjectFormat(
    controlRow.checkout_object_format,
    controlCheckoutObject,
    "differential.control_checkout_object_format",
  );
  const vulnExitCode = exitCodeForRun(vulnRow, "differential.vuln_run_id");
  const controlExitCode = exitCodeForRun(controlRow, "differential.control_run_id");
  const vulnReplayCommandHash = replayCommandHashForRun(vulnRow, "differential.vuln_run_id");
  const controlReplayCommandHash = replayCommandHashForRun(controlRow, "differential.control_run_id");
  if (vulnReplayCommandHash !== controlReplayCommandHash) {
    throw new Error("differential runs must use the same replay command hash");
  }
  const patchHash = controlKind === "self_patch"
    ? assertHex64(controlRow.checkout_patch_hash, "differential.patch_hash")
    : null;
  const controlSummary = assertMaxChars(
    assertRequiredText(differential.control_summary, "differential.control_summary"),
    "differential.control_summary",
    MAX_CONTROL_SUMMARY_CHARS,
  );
  const vulnFired = typeof differential.vuln_fired === "boolean"
    ? differential.vuln_fired
    : (() => { throw new Error("differential.vuln_fired must be a boolean"); })();
  const controlFired = typeof differential.control_fired === "boolean"
    ? differential.control_fired
    : (() => { throw new Error("differential.control_fired must be a boolean"); })();
  const expectedVerdict = expectedDifferentialVerdict(controlKind, vulnFired, controlFired);
  const verdict = suppliedVerdict === expectedVerdict ? suppliedVerdict : "inconclusive";
  const normalized = {
    control_kind: controlKind,
    vuln_run_id: vulnRunId,
    control_run_id: controlRunId,
    control_ref: controlRef,
    control_checkout_object: controlCheckoutObject,
    control_checkout_object_format: controlCheckoutObjectFormat,
    vuln_exit_code: vulnExitCode,
    control_exit_code: controlExitCode,
    vuln_fired: vulnFired,
    control_fired: controlFired,
    firedness_source: "agent_asserted_from_replay_output",
    verdict,
    control_summary: controlSummary,
    replay_command_hash: vulnReplayCommandHash,
    vuln_stdout_hash: stdoutHashForRun(domain, vulnRow, "differential.vuln_run_id"),
    control_stdout_hash: stdoutHashForRun(domain, controlRow, "differential.control_run_id"),
  };
  if (patchHash) normalized.patch_hash = patchHash;
  if (suppliedVerdict !== expectedVerdict) {
    normalized._verdict_overridden = true;
    normalized._supplied_verdict = suppliedVerdict;
    normalized._expected_verdict = expectedVerdict;
    normalized.verdict_warning = `supplied=${suppliedVerdict}; expected=${expectedVerdict}; recorded=inconclusive`;
  }
  normalized.firedness_semantics = "agent_asserted; Bob verifies run identity, exit codes, replay command hash, stdout hashes, and patch hash but does not infer exploit semantics from arbitrary output";
  validateNoSensitiveMaterial(normalized, "differential");
  return normalized;
}

function normalizeAggregateCounts(value) {
  if (!isPlainObject(value)) {
    throw new Error("aggregate_counts must be an object");
  }
  validateNoSensitiveMaterial(value, "aggregate_counts");
  const normalized = {};
  for (const [key, count] of Object.entries(value)) {
    const safeKey = assertNonEmptyString(key, "aggregate_counts key");
    if (!Number.isInteger(count) || count < 0) {
      throw new Error(`aggregate_counts.${safeKey} must be a non-negative integer`);
    }
    normalized[safeKey] = count;
  }
  return normalized;
}

function normalizeRepresentativeSamples(value) {
  if (!Array.isArray(value)) {
    throw new Error("representative_samples must be an array");
  }
  if (value.length > MAX_REPRESENTATIVE_SAMPLES) {
    throw new Error(`representative_samples must contain at most ${MAX_REPRESENTATIVE_SAMPLES} items`);
  }
  return value.map((sample, index) => {
    if (!isPlainObject(sample)) {
      throw new Error(`representative_samples[${index}] must be an object`);
    }
    validateNoSensitiveMaterial(sample, `representative_samples[${index}]`);
    return cloneJsonValue(sample, `representative_samples[${index}]`);
  });
}

function normalizeSensitiveClusters(value) {
  if (!Array.isArray(value)) {
    throw new Error("sensitive_clusters must be an array");
  }
  if (value.length > MAX_SENSITIVE_CLUSTERS) {
    throw new Error(`sensitive_clusters must contain at most ${MAX_SENSITIVE_CLUSTERS} items`);
  }
  return value.map((cluster, index) => {
    if (typeof cluster !== "string" && !isPlainObject(cluster)) {
      throw new Error(`sensitive_clusters[${index}] must be a string or object`);
    }
    validateNoSensitiveMaterial(cluster, `sensitive_clusters[${index}]`);
    return cloneJsonValue(cluster, `sensitive_clusters[${index}]`);
  });
}

function pipelineEventsLib() {
  return require("./pipeline-events.js");
}

function verificationLib() {
  return require("./verification.js");
}

// Cycle C.5: derive the evidence pipeline's work-set from the frozen
// EvidenceReference set on claim-freeze.json. Each CandidateClaim in the
// freeze carries evidence_refs[] entries with kind="finding" + finding_id;
// folding those produces the set of finding ids the evidence pipeline must
// cover. When no freeze exists yet (legacy/pre-claim sessions) the live
// findings.jsonl scan acts as a fallback.
function readFrozenEvidenceFindingIdSet(domain) {
  const freeze = readCurrentClaimFreeze(domain);
  if (!freeze || !Array.isArray(freeze.claims)) return new Set();
  const ids = new Set();
  for (const claim of freeze.claims) {
    if (!claim || !Array.isArray(claim.evidence_refs)) continue;
    for (const ref of claim.evidence_refs) {
      if (ref && typeof ref === "object" && ref.kind === "finding" && typeof ref.finding_id === "string") {
        ids.add(ref.finding_id);
      }
    }
  }
  return ids;
}

function readFindingIdSet(domain) {
  const frozen = readFrozenEvidenceFindingIdSet(domain);
  if (frozen.size > 0) return frozen;
  return findingIdSetForVerificationContext({ domain });
}

function loadFinalVerification(domain, findingIdSet, action = "evidence validation") {
  const paths = verificationRoundPaths(domain, "final");
  let document;
  try {
    document = loadJsonDocumentStrict(paths.json, "final verification round JSON");
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

function normalizeEvidencePack(pack, {
  domain,
  findingIdSet,
  finalReportableIdSet,
  repoCommandRunRows = null,
}) {
  if (!isPlainObject(pack)) {
    throw new Error("packs entries must be objects");
  }
  const findingId = parseFindingId(pack.finding_id);
  if (!findingIdSet.has(findingId)) {
    throw new Error(`Unknown finding_id: ${findingId}`);
  }
  if (!finalReportableIdSet.has(findingId)) {
    throw new Error(`Evidence pack references non-reportable final finding_id: ${findingId}`);
  }

  const sampleType = assertMaxChars(assertRequiredText(pack.sample_type, "sample_type"), "sample_type", 80);
  const sampleCount = assertInteger(pack.sample_count, "sample_count", { min: 0, max: MAX_SAMPLE_COUNT });
  const representativeSamples = normalizeRepresentativeSamples(pack.representative_samples);
  if (sampleCount < representativeSamples.length) {
    throw new Error(`sample_count for ${findingId} must be >= representative_samples length`);
  }

  const replaySummary = assertMaxChars(
    assertRequiredText(pack.replay_summary, "replay_summary"),
    "replay_summary",
    MAX_REPLAY_SUMMARY_CHARS,
  );
  const redactionNotes = pack.redaction_notes == null
    ? null
    : assertMaxChars(normalizeOptionalText(pack.redaction_notes, "redaction_notes") || "", "redaction_notes", MAX_REDACTION_NOTES_CHARS);
  const reportSnippet = assertMaxChars(
    assertRequiredText(pack.report_snippet, "report_snippet"),
    "report_snippet",
    MAX_TEXT_CHARS,
  );

  validateNoSensitiveMaterial(replaySummary, "replay_summary");
  if (redactionNotes) validateNoSensitiveMaterial(redactionNotes, "redaction_notes");
  validateNoSensitiveMaterial(reportSnippet, "report_snippet");

  const normalized = {
    finding_id: findingId,
    sample_type: sampleType,
    sample_count: sampleCount,
    aggregate_counts: normalizeAggregateCounts(pack.aggregate_counts),
    representative_samples: representativeSamples,
    sensitive_clusters: normalizeSensitiveClusters(pack.sensitive_clusters),
    replay_summary: replaySummary,
    redaction_notes: redactionNotes,
    report_snippet: reportSnippet,
  };
  if (pack.differential != null) {
    normalized.differential = normalizeDifferential(pack.differential, { domain, repoCommandRunRows });
  }
  return normalized;
}

function normalizeEvidencePacksDocument(document, {
  expectedDomain = null,
  findingIdSet = null,
  finalReportableIdSet = null,
  verificationBinding = null,
} = {}) {
  if (!isPlainObject(document)) {
    throw new Error("evidence packs document must be an object");
  }

  const domain = assertNonEmptyString(document.target_domain, "target_domain");
  if (expectedDomain != null && domain !== expectedDomain) {
    throw new Error(`evidence packs target_domain mismatch: expected ${expectedDomain}`);
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

  const knownFindingIds = findingIdSet || new Set(document.packs.map((pack) => parseFindingId(pack.finding_id)));
  const reportableIds = finalReportableIdSet || knownFindingIds;
  const repoCommandRunRows = document.packs.some((pack) => isPlainObject(pack) && pack.differential != null)
    ? readRepoCommandRunRows(domain)
    : null;
  const seen = new Set();
  for (const pack of document.packs) {
    const normalizedPack = normalizeEvidencePack(pack, {
      domain,
      findingIdSet: knownFindingIds,
      finalReportableIdSet: reportableIds,
      repoCommandRunRows,
    });
    if (seen.has(normalizedPack.finding_id)) {
      throw new Error(`Duplicate finding_id in evidence packs: ${normalizedPack.finding_id}`);
    }
    seen.add(normalizedPack.finding_id);
    normalized.packs.push(normalizedPack);
  }

  const missing = [...reportableIds].filter((id) => !seen.has(id));
  if (missing.length > 0) {
    throw new Error(`Evidence packs missing final reportable finding(s): ${missing.join(", ")}`);
  }

  return normalized;
}

function evidenceValidationError(message) {
  return new ToolError(
    ERROR_CODES.STATE_CONFLICT,
    `Evidence packs are required for final reportable findings and must be valid: ${message}`,
  );
}

function buildEvidenceValidationResult(domain, paths, document, finalReportableIds, { skipped = false } = {}) {
  return {
    valid: true,
    skipped,
    exists: fs.existsSync(paths.json),
    path: paths.json,
    document,
    packs_count: document.packs.length,
    representative_samples_count: document.packs.reduce(
      (total, pack) => total + pack.representative_samples.length,
      0,
    ),
    final_reportable_count: finalReportableIds.length,
    reportable_findings_covered: finalReportableIds.length,
    missing_finding_ids: [],
    duplicate_finding_ids: [],
    extra_finding_ids: [],
    target_domain: domain,
  };
}

// LEGACY: removed in Plane D — accepts the older `{ finding_ids: [...] }`
// shape from callers that have not migrated to the snapshot/freeze projection.
// Routes the raw id array through the verification finding-id adapter so the
// evidence pipeline still surfaces an authoritative finding-id set without the
// adapter dependency leaking past this function.
function resolveFindingIdSet(domain, { findingIdSet = null, finding_ids = null } = {}) {
  if (findingIdSet instanceof Set) return findingIdSet;
  if (Array.isArray(findingIdSet)) return new Set(findingIdSet);
  if (Array.isArray(finding_ids)) {
    // LEGACY: removed in Plane D
    claimIdSetFromFindingIds(domain, finding_ids); // touches the adapter so the contract is exercised
    return new Set(finding_ids);
  }
  return readFindingIdSet(domain);
}

function requireValidEvidencePacksForFinalReportableFindings(domain, options = {}) {
  const normalizedDomain = assertNonEmptyString(domain, "target_domain");
  const knownFindingIds = resolveFindingIdSet(normalizedDomain, options);
  const finalRound = loadFinalVerification(normalizedDomain, knownFindingIds);
  const verificationBinding = finalRound.version === 2
    ? verificationLib().evidenceBindingForFinal(normalizedDomain, finalRound)
    : null;
  const reportableIds = finalReportableIds(finalRound);
  const reportableIdSet = new Set(reportableIds);
  const paths = evidencePackPaths(normalizedDomain);

  if (!fs.existsSync(paths.json)) {
    if (reportableIds.length === 0) {
      const document = {
        version: EVIDENCE_PACKS_VERSION,
        target_domain: normalizedDomain,
        ...(verificationBinding || {}),
        packs: [],
      };
      return buildEvidenceValidationResult(normalizedDomain, paths, document, reportableIds, {
        skipped: true,
      });
    }
    throw evidenceValidationError(`Missing evidence packs JSON: ${paths.json}`);
  }

  let document;
  try {
    document = loadJsonDocumentStrict(paths.json, "evidence packs JSON");
    const normalized = normalizeEvidencePacksDocument(document, {
      expectedDomain: normalizedDomain,
      findingIdSet: knownFindingIds,
      finalReportableIdSet: reportableIdSet,
      verificationBinding,
    });
    if (verificationBinding) {
      verificationLib().assertEvidenceMatchesFinal(normalizedDomain, normalized, finalRound);
    }
    return buildEvidenceValidationResult(normalizedDomain, paths, normalized, reportableIds);
  } catch (error) {
    if (error instanceof ToolError) throw error;
    throw evidenceValidationError(error.message || String(error));
  }
}

// Cycle C.5 — evidence-completeness gate against the frozen claim batch.
// For each CandidateClaim in the freeze, all required EvidenceReference[]
// entries must be observed in the evidence pack (or other supplied refs) and
// their content_hash must match. This gates the GRADE phase: an incomplete
// evidence work-set blocks the verdict.
function assertEvidenceCompletenessForFreeze(domain, { suppliedRefs = null } = {}) {
  const normalizedDomain = assertNonEmptyString(domain, "target_domain");
  const freeze = readCurrentClaimFreeze(normalizedDomain);
  if (!freeze) {
    return {
      complete: false,
      required: 0,
      satisfied: 0,
      missing: [],
      mismatched: [],
      extras: [],
      blocker_reason: "no claim freeze available",
    };
  }
  let observedRefs = suppliedRefs;
  if (observedRefs == null) {
    // Pull the evidence-pack manifest's content_hash projection from disk if
    // the caller has not supplied an explicit ref set.
    observedRefs = [];
    const paths = evidencePackPaths(normalizedDomain);
    if (fs.existsSync(paths.json)) {
      try {
        const document = loadJsonDocumentStrict(paths.json, "evidence packs JSON");
        if (Array.isArray(document.packs)) {
          for (const pack of document.packs) {
            if (!pack || typeof pack !== "object") continue;
            // Evidence packs are keyed by finding_id; project them as refs the
            // completeness gate can match against the frozen evidence_refs[].
            if (typeof pack.finding_id === "string") {
              observedRefs.push({
                kind: "finding",
                finding_id: pack.finding_id,
                // The frozen ref's content_hash is checked against the
                // observed pack's content_hash when the pack carries one; the
                // evidence-pack document does not currently embed the
                // finding's source content_hash, so completeness defaults to
                // "kind+id" identity matching.
                content_hash: typeof pack.content_hash === "string"
                  ? pack.content_hash
                  : null,
              });
            }
          }
        }
      } catch {
        // fall through with empty observed set
      }
    }
    // O.8: fold in code-bound observed refs projected from on-disk
    // repo-checks.jsonl and repo-runs/<run_id>.stdout. The projection helpers
    // return only refs whose underlying artifact is present; missing files
    // surface as `missing` entries via the gate's standard logic.
    const {
      projectCodeBoundObservedRefs,
    } = require("./claim-freeze.js");
    const codeBoundObservedRefs = projectCodeBoundObservedRefs(normalizedDomain, freeze);
    for (const ref of codeBoundObservedRefs) observedRefs.push(ref);
  }
  const { assertCompletenessAgainstFreeze } = require("./claim-freeze.js");
  return assertCompletenessAgainstFreeze(freeze, observedRefs);
}

function renderEvidencePacksMarkdown(document) {
  const lines = [
    "# Evidence Packs",
    `- Target: ${document.target_domain}`,
    ...(document.verification_attempt_id
      ? [
        `- Verification Attempt: ${document.verification_attempt_id}`,
        `- Verification Snapshot: ${document.verification_snapshot_hash}`,
        `- Final Verification Hash: ${document.final_verification_hash}`,
      ]
      : []),
    `- Packs: ${document.packs.length}`,
    "",
  ];

  if (document.packs.length === 0) {
    lines.push("No final reportable findings required evidence packs.");
    lines.push("");
    return `${lines.join("\n")}\n`;
  }

  for (const pack of document.packs) {
    lines.push(`## ${pack.finding_id}`);
    lines.push(`- Sample Type: ${pack.sample_type}`);
    lines.push(`- Sample Count: ${pack.sample_count}`);
    lines.push(`- Aggregate Counts: ${JSON.stringify(pack.aggregate_counts)}`);
    lines.push(`- Replay Summary: ${pack.replay_summary}`);
    lines.push(`- Redaction Notes: ${pack.redaction_notes || "N/A"}`);
    lines.push("- Representative Samples:");
    lines.push("```json");
    lines.push(JSON.stringify(pack.representative_samples, null, 2));
    lines.push("```");
    lines.push("- Sensitive Clusters:");
    lines.push("```json");
    lines.push(JSON.stringify(pack.sensitive_clusters, null, 2));
    lines.push("```");
    lines.push("- Report Snippet:");
    lines.push("```");
    lines.push(pack.report_snippet);
    lines.push("```");
    if (pack.differential) {
      lines.push("- Differential:");
      lines.push(`  - Control Kind: ${pack.differential.control_kind}`);
      lines.push(`  - Verdict: ${pack.differential.verdict}`);
      if (pack.differential._verdict_overridden) {
        lines.push(`  - Verdict Override: supplied=${pack.differential._supplied_verdict}; expected=${pack.differential._expected_verdict}`);
      }
      if (pack.differential.verdict_warning) {
        lines.push(`  - Verdict Warning: ${markdownInline(pack.differential.verdict_warning)}`);
      }
      lines.push(`  - Vulnerable Run: ${pack.differential.vuln_run_id}`);
      lines.push(`  - Control Run: ${pack.differential.control_run_id}`);
      lines.push(`  - Control Ref: ${pack.differential.control_ref}`);
      lines.push(`  - Vulnerable Exit Code: ${pack.differential.vuln_exit_code}`);
      lines.push(`  - Control Exit Code: ${pack.differential.control_exit_code}`);
      lines.push(`  - Firedness Source: ${pack.differential.firedness_source}`);
      if (pack.differential.firedness_semantics) {
        lines.push(`  - Firedness Semantics: ${markdownInline(pack.differential.firedness_semantics)}`);
      }
      lines.push(`  - Replay Command Hash: ${pack.differential.replay_command_hash}`);
      if (pack.differential.patch_hash) {
        lines.push(`  - Patch Hash: ${pack.differential.patch_hash}`);
      }
      lines.push(`  - Vulnerable Stdout Hash: ${pack.differential.vuln_stdout_hash || "missing"}`);
      lines.push(`  - Control Stdout Hash: ${pack.differential.control_stdout_hash || "missing"}`);
      lines.push(`  - Control Summary: ${markdownInline(pack.differential.control_summary)}`);
    }
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function markdownInline(value) {
  return String(value).replace(/[\r\n]+/g, " ").trim();
}

function writeEvidencePacks(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  if (!Array.isArray(args.packs)) {
    throw new Error("packs must be an array");
  }

  return withSessionLock(domain, () => {
    const findingIdSet = readFindingIdSet(domain);
    const finalRound = loadFinalVerification(domain, findingIdSet, "evidence collection");
    const verificationBinding = finalRound.version === 2
      ? verificationLib().evidenceBindingForFinal(domain, finalRound)
      : null;
    const reportableIds = finalReportableIds(finalRound);
    const finalReportableIdSet = new Set(reportableIds);
    const document = normalizeEvidencePacksDocument({
      version: EVIDENCE_PACKS_VERSION,
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

    const paths = evidencePackPaths(domain);
    writeFileAtomic(paths.json, `${JSON.stringify(document, null, 2)}\n`);
    const response = {
      packs_count: document.packs.length,
      representative_samples_count: document.packs.reduce((total, pack) => total + pack.representative_samples.length, 0),
      reportable_findings_covered: reportableIds.length,
      written_json: paths.json,
    };
    if (verificationBinding) {
      response.verification_attempt_id = verificationBinding.verification_attempt_id;
      response.verification_snapshot_hash = verificationBinding.verification_snapshot_hash;
      response.final_verification_hash = verificationBinding.final_verification_hash;
    }
    writeMarkdownMirror(paths.markdown, renderEvidencePacksMarkdown(document), response);
    pipelineEventsLib().safeAppendPipelineEventDirect(domain, "evidence_written", {
      phase: "VERIFY",
      status: document.packs.length === 0 ? "empty" : "written",
      source: "bob_write_evidence_packs",
      verification_attempt_id: verificationBinding ? verificationBinding.verification_attempt_id : undefined,
      verification_snapshot_hash: verificationBinding ? verificationBinding.verification_snapshot_hash : undefined,
      final_verification_hash: verificationBinding ? verificationBinding.final_verification_hash : undefined,
      counts: {
        packs: document.packs.length,
        representative_samples: response.representative_samples_count,
        reportable_findings_covered: reportableIds.length,
      },
    }, safeGovernanceContextForDomain(domain));
    if (verificationBinding) verificationLib().refreshVerificationManifest(domain, { throw_on_error: true });
    return JSON.stringify(response);
  });
}

function readEvidencePacks(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const validation = requireValidEvidencePacksForFinalReportableFindings(domain);
  if (validation.skipped) {
    return JSON.stringify({
      ...validation.document,
      skipped: true,
    });
  }
  return JSON.stringify(validation.document);
}

module.exports = {
  DIFFERENTIAL_CONTROL_KINDS,
  DIFFERENTIAL_VERDICTS,
  EVIDENCE_PACKS_VERSION,
  MAX_CONTROL_REF_CHARS,
  MAX_CONTROL_SUMMARY_CHARS,
  assertEvidenceCompletenessForFreeze,
  normalizeDifferential,
  normalizeEvidencePacksDocument,
  readEvidencePacks,
  readFrozenEvidenceFindingIdSet,
  requireValidEvidencePacksForFinalReportableFindings,
  renderEvidencePacksMarkdown,
  writeEvidencePacks,
};
