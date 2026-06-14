"use strict";

const fs = require("fs");
const path = require("path");
const {
  CHAIN_ATTEMPT_OUTCOME_VALUES,
  CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES,
  COVERAGE_STATUS_VALUES,
  TECHNIQUE_ATTEMPT_STATUS_VALUES,
  VERIFICATION_ROUND_VALUES,
} = require("./constants.js");
const {
  assertNonEmptyString,
  normalizeStringArray,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const {
  chainAttemptsJsonlPath,
  claimsJsonlPath,
  coverageJsonlPath,
  evidencePackPaths,
  httpAuditJsonlPath,
  reportMarkdownPath,
  sessionDir,
  statePath,
  techniqueAttemptsJsonlPath,
  techniquePackReadsJsonlPath,
  verificationAdjudicationPath,
  verificationRoundPaths,
  verificationSnapshotPath,
} = require("./paths.js");
const {
  readFileUtf8,
  readJsonFile,
} = require("./storage.js");
const {
  loadWaveAssignments,
} = require("./assignments.js");
const {
  readHandoffSigningKey,
} = require("./handoff-signing-key.js");
const {
  assignmentRequiresToken,
  validateHandoffProvenance,
} = require("./wave-handoff-contracts.js");
const {
  requireValidEvidencePacksForFinalReportableFindings,
} = require("./evidence.js");
const {
  buildCircuitBreakerSummary,
  readHttpAuditRecordsFromJsonl,
  summarizeHttpAuditRecords,
} = require("./http-records.js");
const {
  summarizeGradeVerdictArtifact,
} = require("./grade-verdict-store.js");
const {
  validateSessionAuthorityState,
} = require("./session-authority.js");
const {
  findingPayloadsFromClaims,
} = require("./tools/record-candidate-claim.js");
const {
  listArchivedVerificationAttempts,
  summarizeVerificationRoundStatus,
} = require("./verification-status-contracts.js");
const verificationStatusLib = require("./verification.js");
const {
  normalizeSessionStateDocument,
} = require("./session-state-contracts.js");
const {
  capString,
  isPlainObject,
  timestampMs,
} = require("./pipeline-events.js");
const {
  currentSurfaces,
} = require("./frontier-projections.js");

const HANDOFF_ANALYTICS_MAX_FILES = 1000;
const WAVE_READINESS_MAX_ASSIGNMENT_FILES = 200;

function compactErrorMessage(error) {
  return error && error.message ? error.message : String(error);
}

function fileMtimeIso(filePath) {
  try {
    return new Date(fs.statSync(filePath).mtimeMs).toISOString();
  } catch {
    return null;
  }
}

function updateLatestIso(current, candidate) {
  if (!candidate) return current;
  if (!current) return candidate;
  return timestampMs(candidate) > timestampMs(current) ? candidate : current;
}

function readJsonSafe(filePath, label) {
  const result = {
    exists: fs.existsSync(filePath),
    path: filePath,
    document: null,
    error: null,
    mtime: fileMtimeIso(filePath),
  };
  if (!result.exists) return result;
  try {
    result.document = readJsonFile(filePath);
  } catch (error) {
    result.error = `Malformed ${label}: ${error.message || String(error)}`;
  }
  return result;
}

function readJsonlSafe(filePath, label) {
  const result = {
    exists: fs.existsSync(filePath),
    path: filePath,
    records: [],
    malformed_lines: 0,
    error: null,
    mtime: fileMtimeIso(filePath),
  };
  if (!result.exists) return result;
  let content;
  try {
    content = readFileUtf8(filePath, { label });
  } catch (error) {
    result.error = `Unreadable ${label}: ${error.message || String(error)}`;
    return result;
  }
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line);
      if (!isPlainObject(parsed)) {
        result.malformed_lines += 1;
        continue;
      }
      result.records.push(parsed);
    } catch {
      result.malformed_lines += 1;
    }
  }
  return result;
}

function normalizePositiveLimit(limit, fallback) {
  return Number.isInteger(limit) && limit > 0 ? limit : fallback;
}

function listWaveAssignmentNumbers(targetDomain, {
  pendingWave = null,
  limit = WAVE_READINESS_MAX_ASSIGNMENT_FILES,
} = {}) {
  const dir = sessionDir(targetDomain);
  const normalizedLimit = normalizePositiveLimit(limit, WAVE_READINESS_MAX_ASSIGNMENT_FILES);
  const assignmentNumbers = fs.existsSync(dir) ? fs.readdirSync(dir)
    .map((fileName) => {
      const match = fileName.match(/^wave-([1-9][0-9]*)-assignments\.json$/);
      return match ? Number(match[1]) : null;
    })
    .filter((waveNumber) => Number.isInteger(waveNumber))
    .sort((a, b) => a - b) : [];
  const waveNumberSet = new Set(assignmentNumbers);
  if (Number.isInteger(pendingWave) && pendingWave > 0) waveNumberSet.add(pendingWave);
  const allWaveNumbers = Array.from(waveNumberSet).sort((a, b) => a - b);
  let selected = allWaveNumbers;
  if (allWaveNumbers.length > normalizedLimit) {
    selected = allWaveNumbers.slice(-normalizedLimit);
    if (Number.isInteger(pendingWave) && pendingWave > 0 && !selected.includes(pendingWave)) {
      selected = [pendingWave, ...selected.slice(1)];
    }
    selected = Array.from(new Set(selected)).sort((a, b) => a - b);
  }
  return {
    wave_numbers: selected,
    assignment_files_total: assignmentNumbers.length,
    wave_numbers_total: allWaveNumbers.length,
    waves_considered: selected.length,
    waves_omitted: Math.max(0, allWaveNumbers.length - selected.length),
    waves_truncated: allWaveNumbers.length > selected.length,
    limit: normalizedLimit,
    pending_wave_included: !(Number.isInteger(pendingWave) && pendingWave > 0) || selected.includes(pendingWave),
  };
}

const HANDOFF_FILE_RE = /^handoff-(w[1-9][0-9]*)-(a[1-9][0-9]*)\.json$/;

function listSessionHandoffFiles(dir, { limit = HANDOFF_ANALYTICS_MAX_FILES } = {}) {
  if (!fs.existsSync(dir)) {
    const normalizedLimit = Number.isInteger(limit) && limit > 0 ? limit : HANDOFF_ANALYTICS_MAX_FILES;
    return { files: [], total: 0, omitted: 0, limit: normalizedLimit };
  }
  const files = fs.readdirSync(dir)
    .filter((fileName) => HANDOFF_FILE_RE.test(fileName))
    .sort();
  const normalizedLimit = Number.isInteger(limit) && limit > 0 ? limit : HANDOFF_ANALYTICS_MAX_FILES;
  return {
    files: files.slice(0, normalizedLimit),
    total: files.length,
    omitted: Math.max(0, files.length - normalizedLimit),
    limit: normalizedLimit,
  };
}

function listHandoffFiles(dir, waveId, handoffListing = null) {
  const listing = handoffListing || listSessionHandoffFiles(dir);
  return listing.files
    .filter((fileName) => fileName.startsWith(`handoff-${waveId}-`) && fileName.endsWith(".json"));
}

function signingKeyForAssignments(targetDomain, assignments) {
  return assignments.some((assignment) => assignmentRequiresToken(assignment))
    ? readHandoffSigningKey(targetDomain)
    : null;
}

function validateHandoffMetadata(document, { targetDomain, wave, agent, surfaceId, assignment, signingKey }) {
  if (!isPlainObject(document)) throw new Error("handoff payload must be an object");
  if (document.target_domain != null && document.target_domain !== targetDomain) throw new Error("target_domain mismatch");
  if (parseWaveId(document.wave) !== wave) throw new Error("wave mismatch");
  if (parseAgentId(document.agent) !== agent) throw new Error("agent mismatch");
  if (assertNonEmptyString(document.surface_id, "surface_id") !== surfaceId) throw new Error("surface_id mismatch");
  if (!["complete", "partial"].includes(capString(document.surface_status, 40))) {
    throw new Error("invalid surface_status");
  }
  validateHandoffProvenance(document, assignment, { signingKey });
}

function readWaveReadiness(targetDomain, waveNumber, handoffListing = null) {
  const wave = `w${waveNumber}`;
  const result = {
    wave_number: waveNumber,
    assignments_total: 0,
    handoffs_total: 0,
    received_agents: [],
    missing_agents: [],
    invalid_agents: [],
    unexpected_agents: [],
    is_complete: false,
    error: null,
  };

  let artifacts;
  try {
    artifacts = loadWaveAssignments(targetDomain, waveNumber);
  } catch (error) {
    result.error = error.message || String(error);
    return result;
  }

  result.assignments_total = artifacts.assignments.length;
  let signingKey = null;
  let signingKeyError = null;
  try {
    signingKey = signingKeyForAssignments(targetDomain, artifacts.assignments);
  } catch (error) {
    signingKeyError = error;
  }
  const handoffFiles = listHandoffFiles(artifacts.dir, wave, handoffListing);
  result.handoffs_total = handoffFiles.length;
  const handoffPathByAgent = new Map();
  for (const fileName of handoffFiles) {
    const agent = fileName.slice(`handoff-${wave}-`.length, -".json".length);
    if (!artifacts.assignmentByAgent.has(agent)) {
      result.unexpected_agents.push(agent);
    } else {
      handoffPathByAgent.set(agent, path.join(artifacts.dir, fileName));
    }
  }

  for (const assignment of artifacts.assignments) {
    const handoffPath = handoffPathByAgent.get(assignment.agent);
    if (!handoffPath) {
      result.missing_agents.push(assignment.agent);
      continue;
    }
    try {
      if (assignmentRequiresToken(assignment) && signingKeyError) {
        throw signingKeyError;
      }
      validateHandoffMetadata(readJsonFile(handoffPath), {
        targetDomain,
        wave,
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
        assignment,
        signingKey,
      });
      result.received_agents.push(assignment.agent);
    } catch {
      result.invalid_agents.push(assignment.agent);
    }
  }

  result.is_complete = result.missing_agents.length === 0 && result.invalid_agents.length === 0;
  return result;
}

function summarizeFindingsJsonl(targetDomain) {
  // Cycle D.2: candidate claims are the authoritative ledger. Findings are
  // projected from each claim's embedded finding payload, so the summary
  // counts (by severity, total) read off claims.jsonl rather than the legacy
  // findings.jsonl artifact.
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const claimsPath = claimsJsonlPath(targetDomain);
  let mtime = null;
  try {
    mtime = new Date(fs.statSync(claimsPath).mtimeMs).toISOString();
  } catch {}
  let total = 0;
  let exists = false;
  try {
    exists = fs.existsSync(claimsPath);
  } catch {}
  let error = null;
  if (exists) {
    try {
      for (const finding of findingPayloadsFromClaims(targetDomain)) {
        total += 1;
        if (Object.prototype.hasOwnProperty.call(bySeverity, finding.severity)) {
          bySeverity[finding.severity] += 1;
        }
      }
    } catch (err) {
      error = err && err.message ? err.message : String(err);
    }
  }
  return {
    exists,
    total,
    by_severity: bySeverity,
    malformed_lines: 0,
    error,
    mtime,
  };
}

function summarizeCoverageJsonl(targetDomain) {
  const read = readJsonlSafe(coverageJsonlPath(targetDomain), "coverage.jsonl");
  const byStatus = COVERAGE_STATUS_VALUES.reduce((result, status) => {
    result[status] = 0;
    return result;
  }, {});
  const surfaces = new Set();
  for (const record of read.records) {
    const status = capString(record.status, 40);
    if (Object.prototype.hasOwnProperty.call(byStatus, status)) {
      byStatus[status] += 1;
    }
    if (typeof record.surface_id === "string" && record.surface_id.trim()) {
      surfaces.add(record.surface_id.trim());
    }
  }
  return {
    exists: read.exists,
    total_records: read.records.length,
    surface_count: surfaces.size,
    by_status: byStatus,
    malformed_lines: read.malformed_lines,
    error: read.error,
    mtime: read.mtime,
  };
}

function summarizeTechniqueAttemptsJsonl(targetDomain) {
  const read = readJsonlSafe(techniqueAttemptsJsonlPath(targetDomain), "technique-attempts.jsonl");
  const byStatus = TECHNIQUE_ATTEMPT_STATUS_VALUES.reduce((result, status) => {
    result[status] = 0;
    return result;
  }, {});
  const surfaces = new Set();
  const packs = new Set();
  let total = 0;
  let invalidRecords = 0;

  for (const record of read.records) {
    const status = capString(record.status, 40);
    const surfaceId = capString(record.surface_id, 200);
    const packId = capString(record.pack_id, 128);
    if (
      record.target_domain !== targetDomain ||
      !TECHNIQUE_ATTEMPT_STATUS_VALUES.includes(status) ||
      !surfaceId ||
      !packId
    ) {
      invalidRecords += 1;
      continue;
    }
    total += 1;
    byStatus[status] += 1;
    surfaces.add(surfaceId);
    packs.add(packId);
  }

  return {
    exists: read.exists,
    total_records: total,
    surface_count: surfaces.size,
    pack_count: packs.size,
    by_status: byStatus,
    malformed_lines: read.malformed_lines + invalidRecords,
    error: read.error,
    mtime: read.mtime,
  };
}

function summarizeTechniquePackReadsJsonl(targetDomain) {
  const read = readJsonlSafe(techniquePackReadsJsonlPath(targetDomain), "technique-pack-reads.jsonl");
  const surfaces = new Set();
  const packs = new Set();
  let fullReads = 0;
  let invalidRecords = 0;

  for (const record of read.records) {
    const mode = capString(record.mode, 40);
    const surfaceId = capString(record.surface_id, 200);
    const packId = capString(record.pack_id, 128);
    if (record.target_domain !== targetDomain || mode !== "full" || !surfaceId || !packId) {
      invalidRecords += 1;
      continue;
    }
    fullReads += 1;
    surfaces.add(surfaceId);
    packs.add(packId);
  }

  return {
    exists: read.exists,
    total_records: fullReads,
    full_reads: fullReads,
    surface_count: surfaces.size,
    pack_count: packs.size,
    malformed_lines: read.malformed_lines + invalidRecords,
    error: read.error,
    mtime: read.mtime,
  };
}

function summarizeChainAttemptsJsonl(targetDomain) {
  const read = readJsonlSafe(chainAttemptsJsonlPath(targetDomain), "chain-attempts.jsonl");
  const byOutcome = CHAIN_ATTEMPT_OUTCOME_VALUES.reduce((result, outcome) => {
    result[outcome] = 0;
    return result;
  }, {});
  let total = 0;
  let terminalTotal = 0;
  let invalidRecords = 0;

  for (const record of read.records) {
    const outcome = capString(record.outcome, 40);
    if (record.target_domain !== targetDomain || !CHAIN_ATTEMPT_OUTCOME_VALUES.includes(outcome)) {
      invalidRecords += 1;
      continue;
    }
    total += 1;
    byOutcome[outcome] += 1;
    if (CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES.includes(outcome)) {
      terminalTotal += 1;
    }
  }

  return {
    exists: read.exists,
    total,
    terminal_total: terminalTotal,
    by_outcome: byOutcome,
    malformed_lines: read.malformed_lines + invalidRecords,
    error: read.error,
    mtime: read.mtime,
  };
}

function summarizeHttpAuditJsonl(targetDomain) {
  const filePath = httpAuditJsonlPath(targetDomain);
  const summary = {
    exists: fs.existsSync(filePath),
    total: 0,
    errors: 0,
    scope_blocked: 0,
    network_unreachable_target: 0,
    egress: { by_profile: {}, by_region: {}, by_identity_hash: {}, identities: [] },
    geofence_warning: {
      threshold: 3,
      warning: false,
      code: null,
      note: null,
      hosts: [],
    },
    circuit_breaker_summary: buildCircuitBreakerSummary([]),
    error: null,
    mtime: fileMtimeIso(filePath),
  };
  if (!summary.exists) return summary;
  try {
    const records = readHttpAuditRecordsFromJsonl(targetDomain);
    const auditSummary = summarizeHttpAuditRecords(records, { targetDomain });
    summary.total = auditSummary.total;
    summary.errors = auditSummary.errors;
    summary.scope_blocked = auditSummary.scope_blocked;
    summary.network_unreachable_target = auditSummary.network_unreachable_target;
    if (auditSummary.block_internal_hosts) {
      summary.block_internal_hosts = auditSummary.block_internal_hosts;
    }
    summary.egress = auditSummary.egress;
    summary.geofence_warning = auditSummary.geofence_warning;
    summary.circuit_breaker_summary = buildCircuitBreakerSummary(records);
  } catch (error) {
    summary.error = `Malformed http-audit.jsonl: ${error.message || String(error)}`;
  }
  return summary;
}

// Cap on chain_notes contribution from handoffs without a verifiable assignment
// file. This bounds an attacker's ability to inflate chain_notes_count (which
// feeds the chain_phase_no_attempts gate at pipeline-analytics.js) by leaving
// a handoff file but removing the assignment file. The fallback only covers
// the missing-file case; validation failures (tampered signatures, metadata
// mismatch) remain strict drops.
const UNSIGNED_HANDOFF_CHAIN_NOTES_FALLBACK_CAP = 10;

function isMissingAssignmentFileError(error) {
  if (!error) return false;
  const message = error.message || String(error);
  // assignments.js:28 throws "Missing assignment file: <path>"; fs-level ENOENT
  // can also bubble through readJsonFile.
  return /Missing assignment file/.test(message) || error.code === "ENOENT";
}

function summarizeStructuredHandoffChainNotes(targetDomain, handoffListing = null) {
  const dir = sessionDir(targetDomain);
  const summary = {
    chain_notes_count: 0,
    handoff_count: 0,
    handoff_refs: [],
    handoff_files_total: 0,
    handoff_files_omitted: 0,
    malformed_files: 0,
    // R1-HIGH-#3 resilience: chain_notes from handoffs whose wave-N-assignments
    // .json is missing are counted up to UNSIGNED_HANDOFF_CHAIN_NOTES_FALLBACK_CAP
    // (legitimate pre-v1.3.5 sessions and crash-recovery cases). Operators can
    // see the gap via this counter without losing the underlying chain_notes
    // from analytics. Validation failures (tampering) remain strict drops.
    unsigned_handoff_count: 0,
  };
  if (!fs.existsSync(dir)) return summary;
  const assignmentContexts = new Map();

  function contextFor(wave, agent) {
    if (!assignmentContexts.has(wave)) {
      const waveNumber = Number(wave.slice(1));
      let artifacts = null;
      let signingKey = null;
      let signingKeyError = null;
      try {
        artifacts = loadWaveAssignments(targetDomain, waveNumber);
        signingKey = signingKeyForAssignments(targetDomain, artifacts.assignments);
      } catch (error) {
        signingKeyError = error;
      }
      assignmentContexts.set(wave, { artifacts, signingKey, signingKeyError });
    }
    const context = assignmentContexts.get(wave);
    if (!context.artifacts) throw context.signingKeyError || new Error(`Missing assignment file for ${wave}`);
    const assignment = context.artifacts.assignmentByAgent.get(agent);
    if (!assignment) throw new Error(`Unexpected handoff agent ${agent} in ${wave}`);
    if (assignmentRequiresToken(assignment) && context.signingKeyError) throw context.signingKeyError;
    return { assignment, signingKey: context.signingKey };
  }

  let unsignedFallbackBudget = UNSIGNED_HANDOFF_CHAIN_NOTES_FALLBACK_CAP;

  const listing = handoffListing || listSessionHandoffFiles(dir);
  summary.handoff_files_total = listing.total;
  summary.handoff_files_omitted = listing.omitted;
  for (const fileName of listing.files) {
    const match = fileName.match(HANDOFF_FILE_RE);
    let document;
    try {
      document = readJsonFile(path.join(dir, fileName));
    } catch {
      summary.malformed_files += 1;
      continue;
    }
    if (!isPlainObject(document)) {
      summary.malformed_files += 1;
      continue;
    }
    let chainNotes;
    let fallbackUsed = false;
    try {
      const { assignment, signingKey } = contextFor(match[1], match[2]);
      validateHandoffMetadata(document, {
        targetDomain,
        wave: match[1],
        agent: match[2],
        surfaceId: assignment.surface_id,
        assignment,
        signingKey,
      });
      chainNotes = normalizeStringArray(document.chain_notes, "chain_notes");
    } catch (error) {
      // Only fall back when the underlying problem is a missing assignment
      // file (legitimate state for pre-v1.3.5 or post-crash sessions). For
      // validation failures (signature mismatch, target_domain mismatch,
      // surface_id mismatch), keep the strict drop so an attacker who tampers
      // a handoff can't inflate chain_notes_count.
      if (!isMissingAssignmentFileError(error)) {
        summary.malformed_files += 1;
        continue;
      }
      try {
        chainNotes = normalizeStringArray(document.chain_notes, "chain_notes");
      } catch {
        summary.malformed_files += 1;
        continue;
      }
      fallbackUsed = true;
    }
    if (chainNotes.length === 0) continue;
    if (fallbackUsed) {
      summary.unsigned_handoff_count += 1;
      // Cap fallback contribution to bound attacker-controlled inflation of
      // the chain_phase_no_attempts gate via crafted unsigned chain_notes.
      const remaining = Math.max(0, unsignedFallbackBudget);
      const contributed = Math.min(chainNotes.length, remaining);
      unsignedFallbackBudget -= contributed;
      summary.chain_notes_count += contributed;
      if (contributed === 0) continue;
    } else {
      summary.chain_notes_count += chainNotes.length;
    }
    summary.handoff_count += 1;
    summary.handoff_refs.push({
      wave: match[1],
      agent: match[2],
      surface_id: capString(document.surface_id, 200),
      chain_notes_count: chainNotes.length,
    });
  }

  return summary;
}

function summarizeVerificationArtifacts(targetDomain, state = null) {
  const rounds = {};
  let latestMtime = null;
  const errors = [];
  let finalReportableIds = [];
  const verificationStatus = verificationStatusLib;
  const snapshotRead = readJsonSafe(verificationSnapshotPath(targetDomain), "verification input snapshot JSON");
  const adjudicationRead = readJsonSafe(verificationAdjudicationPath(targetDomain), "verification adjudication JSON");
  latestMtime = updateLatestIso(latestMtime, snapshotRead.mtime);
  latestMtime = updateLatestIso(latestMtime, adjudicationRead.mtime);
  const snapshot = {
    exists: snapshotRead.exists,
    schema_version: isPlainObject(snapshotRead.document) && Number.isInteger(snapshotRead.document.schema_version)
      ? snapshotRead.document.schema_version
      : null,
    attempt_id: isPlainObject(snapshotRead.document) ? capString(snapshotRead.document.verification_attempt_id, 120) : null,
    snapshot_hash: isPlainObject(snapshotRead.document) ? capString(snapshotRead.document.snapshot_hash, 128) : null,
    finding_count: isPlainObject(snapshotRead.document) && Array.isArray(snapshotRead.document.finding_ids)
      ? snapshotRead.document.finding_ids.length
      : 0,
    input_hashes: isPlainObject(snapshotRead.document) && isPlainObject(snapshotRead.document.input_hashes)
      ? snapshotRead.document.input_hashes
      : null,
    mtime: snapshotRead.mtime,
    error: snapshotRead.error,
  };
  if (snapshotRead.error) errors.push(snapshotRead.error);
  const semanticAdjudicationStatus = verificationStatus.adjudicationStatus(targetDomain, state);
  const adjudication = {
    ...semanticAdjudicationStatus,
    exists: adjudicationRead.exists,
    current_attempt_id: isPlainObject(adjudicationRead.document) ? capString(adjudicationRead.document.verification_attempt_id, 120) : null,
    snapshot_hash: isPlainObject(adjudicationRead.document) ? capString(adjudicationRead.document.verification_snapshot_hash, 128) : null,
    adjudication_plan_hash: semanticAdjudicationStatus.adjudication_plan_hash || (isPlainObject(adjudicationRead.document) ? capString(adjudicationRead.document.adjudication_plan_hash, 128) : null),
    agreed_count: isPlainObject(adjudicationRead.document) && Array.isArray(adjudicationRead.document.agreed)
      ? adjudicationRead.document.agreed.length
      : 0,
    disagreement_count: isPlainObject(adjudicationRead.document) && Array.isArray(adjudicationRead.document.disagreements)
      ? adjudicationRead.document.disagreements.length
      : 0,
    replay_required_count: isPlainObject(adjudicationRead.document) && Array.isArray(adjudicationRead.document.replay_required_ids)
      ? adjudicationRead.document.replay_required_ids.length
      : 0,
    qa_sample_count: isPlainObject(adjudicationRead.document) && Array.isArray(adjudicationRead.document.qa_sampled_ids)
      ? adjudicationRead.document.qa_sampled_ids.length
      : 0,
    mtime: adjudicationRead.mtime,
    error: adjudicationRead.error,
  };
  if (adjudicationRead.error) errors.push(adjudicationRead.error);
  for (const round of VERIFICATION_ROUND_VALUES) {
    const paths = verificationRoundPaths(targetDomain, round);
    const read = readJsonSafe(paths.json, `${round} verification round JSON`);
    latestMtime = updateLatestIso(latestMtime, read.mtime);
    const summary = summarizeVerificationRoundStatus({
      targetDomain,
      round,
      exists: read.exists,
      document: read.document,
      state,
      mtime: read.mtime,
      error: read.error,
      schemaVersionForContext: verificationStatus.schemaVersionForContext,
      decorateVerificationRoundRead: verificationStatus.decorateVerificationRoundRead,
    });
    if (read.error) errors.push(read.error);
    if (round === "final") {
      finalReportableIds = summary.final_reportable_ids.slice();
    }
    if (summary.error && !read.error) {
      errors.push(summary.error);
    }
    rounds[round] = summary;
  }
  const schemaVersion = (
    snapshot.exists ||
    adjudication.exists ||
    Object.values(rounds).some((round) => round.schema_version === 2)
  )
    ? 2
    : (Object.values(rounds).some((round) => round.schema_version === 1) ? 1 : null);
  return {
    schema_version: schemaVersion,
    current_attempt_id: snapshot.attempt_id,
    snapshot_hash: snapshot.snapshot_hash,
    snapshot,
    adjudication,
    archived_attempts: listArchivedVerificationAttempts(targetDomain),
    rounds,
    final_results_count: rounds.final.results_count,
    final_reportable_count: rounds.final.reportable_count,
    final_reportable_ids: finalReportableIds,
    errors,
    latest_mtime: latestMtime,
  };
}

function summarizeEvidenceArtifacts(targetDomain, finalReportableIds) {
  const paths = evidencePackPaths(targetDomain);
  const read = readJsonSafe(paths.json, "evidence packs JSON");
  const finalReportableSet = new Set(finalReportableIds);
  const summary = {
    exists: read.exists,
    valid: false,
    skipped: finalReportableIds.length === 0 && !read.exists,
    packs_count: 0,
    representative_samples_count: 0,
    reportable_findings_covered: 0,
    final_reportable_count: finalReportableIds.length,
    missing_finding_ids: finalReportableIds.slice(),
    duplicate_finding_ids: [],
    extra_finding_ids: [],
    verification_attempt_id: isPlainObject(read.document) ? capString(read.document.verification_attempt_id, 120) : null,
    verification_snapshot_hash: isPlainObject(read.document) ? capString(read.document.verification_snapshot_hash, 128) : null,
    final_verification_hash: isPlainObject(read.document) ? capString(read.document.final_verification_hash, 128) : null,
    error: read.error,
    mtime: read.mtime,
  };

  if (finalReportableIds.length === 0 && !read.exists) {
    summary.valid = true;
    return summary;
  }

  if (isPlainObject(read.document) && Array.isArray(read.document.packs)) {
    if (read.document.version !== 1 || read.document.target_domain !== targetDomain) {
      summary.error = "evidence packs artifact metadata mismatch";
    }

    const seen = new Set();
    const duplicateIds = new Set();
    for (const pack of read.document.packs) {
      if (!isPlainObject(pack) || typeof pack.finding_id !== "string") {
        summary.error = summary.error || "evidence packs artifact has malformed pack entries";
        continue;
      }
      summary.packs_count += 1;
      if (seen.has(pack.finding_id)) {
        duplicateIds.add(pack.finding_id);
      }
      seen.add(pack.finding_id);
      if (Array.isArray(pack.representative_samples)) {
        summary.representative_samples_count += pack.representative_samples.length;
      }
    }

    summary.duplicate_finding_ids = Array.from(duplicateIds).sort();
    summary.missing_finding_ids = finalReportableIds.filter((id) => !seen.has(id));
    summary.extra_finding_ids = Array.from(seen).filter((id) => !finalReportableSet.has(id)).sort();
    summary.reportable_findings_covered = finalReportableIds.filter((id) => seen.has(id)).length;
  } else if (read.exists && !read.error) {
    summary.error = "evidence packs artifact metadata mismatch";
  }

  try {
    const validation = requireValidEvidencePacksForFinalReportableFindings(targetDomain);
    summary.exists = validation.exists;
    summary.valid = true;
    summary.skipped = validation.skipped;
    summary.packs_count = validation.packs_count;
    summary.representative_samples_count = validation.representative_samples_count;
    summary.reportable_findings_covered = validation.reportable_findings_covered;
    summary.final_reportable_count = validation.final_reportable_count;
    summary.missing_finding_ids = [];
    summary.duplicate_finding_ids = [];
    summary.extra_finding_ids = [];
    summary.verification_attempt_id = validation.document.verification_attempt_id || null;
    summary.verification_snapshot_hash = validation.document.verification_snapshot_hash || null;
    summary.final_verification_hash = validation.document.final_verification_hash || null;
    summary.error = null;
  } catch (error) {
    summary.valid = false;
    summary.error = compactErrorMessage(error);
    if (summary.missing_finding_ids.length === 0 && finalReportableIds.length > 0 && summary.reportable_findings_covered < finalReportableIds.length) {
      summary.missing_finding_ids = finalReportableIds.slice();
    }
  }
  return summary;
}

function summarizeAttackSurfaceCoverage(targetDomain, state) {
  // Surface coverage reads from currentSurfaces (Cycle F.5): the materialized
  // surface-index.json is the authoritative read source. The mtime reported
  // back to dashboards reflects the underlying source (surface-index.json
  // when present, attack_surface.json only in the legacy fallback).
  let surfaceList = [];
  let sourcePath = null;
  let exists = false;
  let error = null;
  try {
    const projection = currentSurfaces(targetDomain);
    surfaceList = projection.surfaces || [];
    sourcePath = projection.path;
    exists = projection.source !== "missing";
  } catch (err) {
    error = compactErrorMessage(err);
  }
  const mtime = sourcePath ? fileMtimeIso(sourcePath) : null;
  if (!exists || error) {
    return {
      exists,
      error,
      total_surfaces: 0,
      non_low_total: 0,
      non_low_explored: 0,
      non_low_terminally_blocked: 0,
      coverage_pct: null,
      closed_pct: null,
      unexplored_high: 0,
      blocked_high: 0,
      mtime,
    };
  }
  // Explored / terminally-blocked sets derive from the frontier ledger
  // projection (Cycle D.3). The legacy state arrays were removed; the
  // frontier-projections fold is the sole source of surface-level closure
  // and blocker truth.
  let exploredSet = new Set();
  let terminallyBlockedSet = new Set();
  if (state && typeof state.target === "string" && state.target) {
    try {
      const projections = require("./frontier-projections.js");
      exploredSet = new Set(projections.currentClosures(state.target).map((entry) => entry.surface_id));
      terminallyBlockedSet = new Set(projections.currentBlockers(state.target).map((entry) => entry.surface_id));
    } catch {
      // Ledger projection unavailable; counts default to 0 / empty.
    }
  }
  const surfaces = surfaceList.filter((surface) => isPlainObject(surface) && typeof surface.id === "string");
  const nonLowSurfaces = surfaces.filter((surface) => (surface.priority || "HIGH").toUpperCase() !== "LOW");
  const highSurfaces = surfaces.filter((surface) => ["CRITICAL", "HIGH"].includes((surface.priority || "HIGH").toUpperCase()));
  const exploredNonLow = nonLowSurfaces.filter((surface) => exploredSet.has(surface.id)).length;
  const blockedNonLow = nonLowSurfaces.filter((surface) => terminallyBlockedSet.has(surface.id)).length;
  const closedNonLow = exploredNonLow + blockedNonLow;
  return {
    exists: true,
    error: null,
    total_surfaces: surfaces.length,
    non_low_total: nonLowSurfaces.length,
    non_low_explored: exploredNonLow,
    non_low_terminally_blocked: blockedNonLow,
    // coverage_pct keeps the explored-only meaning for back-compat with
    // existing dashboards. closed_pct is the post-Cycle-2 measure that
    // also counts terminally_blocked surfaces (classified blocked, not
    // neglected). low_coverage analytics fires on closed_pct so blocked
    // surfaces correctly count as "off the queue".
    coverage_pct: nonLowSurfaces.length ? Math.round((exploredNonLow / nonLowSurfaces.length) * 100) : 100,
    closed_pct: nonLowSurfaces.length ? Math.round((closedNonLow / nonLowSurfaces.length) * 100) : 100,
    unexplored_high: highSurfaces.filter((surface) => !exploredSet.has(surface.id) && !terminallyBlockedSet.has(surface.id)).length,
    blocked_high: highSurfaces.filter((surface) => terminallyBlockedSet.has(surface.id)).length,
    mtime,
  };
}

function readSessionArtifactSummary(targetDomain, { validateAuthority = false } = {}) {
  const dir = sessionDir(targetDomain);
  const stateRead = readJsonSafe(statePath(targetDomain), "session state");
  const rawState = isPlainObject(stateRead.document) ? stateRead.document : null;
  let state = rawState;
  let authorityError = null;
  if (validateAuthority) {
    try {
      validateSessionAuthorityState(targetDomain);
    } catch (error) {
      authorityError = error && error.authority ? error.authority.authority_error_code : "invalid_session_authority";
      state = null;
    }
  }
  if (!stateRead.error && rawState) {
    if (!authorityError) {
      try {
        state = normalizeSessionStateDocument(stateRead.document, targetDomain);
      } catch {
        state = rawState;
      }
    }
  }
  const waveListing = listWaveAssignmentNumbers(targetDomain, { pendingWave: state?.pending_wave });

  const handoffListing = listSessionHandoffFiles(dir);
  const waves = waveListing.wave_numbers.map((waveNumber) => readWaveReadiness(targetDomain, waveNumber, handoffListing));
  const findings = summarizeFindingsJsonl(targetDomain);
  const coverage = summarizeCoverageJsonl(targetDomain);
  const techniqueAttempts = summarizeTechniqueAttemptsJsonl(targetDomain);
  const techniquePackReads = summarizeTechniquePackReadsJsonl(targetDomain);
  const httpAudit = summarizeHttpAuditJsonl(targetDomain);
  const chainAttempts = summarizeChainAttemptsJsonl(targetDomain);
  const chainHandoffs = summarizeStructuredHandoffChainNotes(targetDomain, handoffListing);
  const attackSurfaceCoverage = summarizeAttackSurfaceCoverage(targetDomain, state);
  const verification = summarizeVerificationArtifacts(targetDomain, state);
  const evidence = summarizeEvidenceArtifacts(targetDomain, verification.final_reportable_ids);
  const grade = summarizeGradeVerdictArtifact(targetDomain);
  const reportPath = reportMarkdownPath(targetDomain);
  const reportMtime = fileMtimeIso(reportPath);

  let latestMtime = null;
  for (const value of [
    stateRead.mtime,
    findings.mtime,
    coverage.mtime,
    techniqueAttempts.mtime,
    techniquePackReads.mtime,
    httpAudit.mtime,
    chainAttempts.mtime,
    attackSurfaceCoverage.mtime,
    verification.latest_mtime,
    evidence.mtime,
    grade.mtime,
    reportMtime,
  ]) {
    latestMtime = updateLatestIso(latestMtime, value);
  }

  const artifactErrors = [];
  if (!stateRead.exists) artifactErrors.push("Missing session state");
  if (stateRead.error) artifactErrors.push(stateRead.error);
  if (authorityError) artifactErrors.push(`Session authority invalid: ${authorityError}`);
  if (findings.error) artifactErrors.push(findings.error);
  if (coverage.error) artifactErrors.push(coverage.error);
  if (techniqueAttempts.error) artifactErrors.push(techniqueAttempts.error);
  if (techniquePackReads.error) artifactErrors.push(techniquePackReads.error);
  if (httpAudit.error) artifactErrors.push(httpAudit.error);
  if (chainAttempts.error) artifactErrors.push(chainAttempts.error);
  if (findings.malformed_lines > 0) artifactErrors.push(`Malformed findings.jsonl lines: ${findings.malformed_lines}`);
  if (coverage.malformed_lines > 0) artifactErrors.push(`Malformed coverage.jsonl lines: ${coverage.malformed_lines}`);
  if (techniqueAttempts.malformed_lines > 0) artifactErrors.push(`Malformed technique-attempts.jsonl lines: ${techniqueAttempts.malformed_lines}`);
  if (techniquePackReads.malformed_lines > 0) artifactErrors.push(`Malformed technique-pack-reads.jsonl lines: ${techniquePackReads.malformed_lines}`);
  if (chainAttempts.malformed_lines > 0) artifactErrors.push(`Malformed chain-attempts.jsonl lines: ${chainAttempts.malformed_lines}`);
  if (chainHandoffs.malformed_files > 0) artifactErrors.push(`Malformed chain handoff files: ${chainHandoffs.malformed_files}`);
  for (const wave of waves) {
    if (wave.error) artifactErrors.push(`Wave ${wave.wave_number}: ${wave.error}`);
  }
  artifactErrors.push(...verification.errors);
  if (evidence.error) artifactErrors.push(evidence.error);
  if (grade.error) artifactErrors.push(grade.error);

  return {
    target_domain: targetDomain,
    session_dir: dir,
    state: {
      exists: stateRead.exists,
      phase: capString(state?.phase, 40),
      auth_status: capString(state?.auth_status, 40),
      checkpoint_mode: capString(state?.checkpoint_mode, 40),
      block_internal_hosts: authorityError ? null : state?.block_internal_hosts === true,
      block_internal_hosts_source: capString(state?.block_internal_hosts_source, 80),
      egress_profile: capString(state?.egress_profile, 80),
      egress_region: capString(state?.egress_region, 80),
      proxy_configured: authorityError ? null : state?.proxy_configured === true,
      egress_profile_identity_hash: capString(state?.egress_profile_identity_hash, 128),
      egress_profile_identity_version: Number.isInteger(state?.egress_profile_identity_version)
        ? state.egress_profile_identity_version
        : null,
      evaluation_wave: Number.isInteger(state?.evaluation_wave) ? state.evaluation_wave : 0,
      pending_wave: Number.isInteger(state?.pending_wave) ? state.pending_wave : null,
      total_findings: Number.isInteger(state?.total_findings) ? state.total_findings : findings.total,
      hold_count: Number.isInteger(state?.hold_count) ? state.hold_count : 0,
      verification_schema_version: Number.isInteger(state?.verification_schema_version) ? state.verification_schema_version : null,
      verification_attempt_id: capString(state?.verification_attempt_id, 120),
      verification_snapshot_hash: capString(state?.verification_snapshot_hash, 128),
      verification_entered_at: capString(state?.verification_entered_at, 80),
      mtime: stateRead.mtime,
      error: stateRead.error,
    },
    wave_bounds: {
      assignment_file_scan_limit: waveListing.limit,
      assignment_files_total: waveListing.assignment_files_total,
      wave_numbers_total: waveListing.wave_numbers_total,
      waves_considered: waveListing.waves_considered,
      waves_omitted: waveListing.waves_omitted,
      waves_truncated: waveListing.waves_truncated,
      pending_wave_included: waveListing.pending_wave_included,
    },
    waves,
    findings,
    coverage,
    technique_attempts: techniqueAttempts,
    technique_pack_reads: techniquePackReads,
    http_audit: httpAudit,
    chain_attempts: chainAttempts,
    chain_handoffs: chainHandoffs,
    attack_surface_coverage: attackSurfaceCoverage,
    verification,
    evidence,
    grade,
    report: {
      present: fs.existsSync(reportPath),
      path: reportPath,
      mtime: reportMtime,
    },
    artifact_errors: artifactErrors,
    latest_artifact_ts: latestMtime,
  };
}

// Recorded chain work that must yield a terminal structured chain attempt
// before CLAIM_FREEZE: two or more findings, or any wave-handoff chain note.
// The single source of truth shared by the pipeline-analytics
// `chain_phase_no_attempts` issue and the `chain_work_terminal` scheduler
// precondition, so the observed signal and the hard gate cannot diverge.
function chainWorkRequired(artifacts) {
  const findingsTotal = artifacts && artifacts.findings && Number.isInteger(artifacts.findings.total)
    ? artifacts.findings.total
    : 0;
  const chainNotesCount = artifacts && artifacts.chain_handoffs
    && Number.isInteger(artifacts.chain_handoffs.chain_notes_count)
    ? artifacts.chain_handoffs.chain_notes_count
    : 0;
  return findingsTotal >= 2 || chainNotesCount > 0;
}

module.exports = {
  HANDOFF_ANALYTICS_MAX_FILES,
  WAVE_READINESS_MAX_ASSIGNMENT_FILES,
  readSessionArtifactSummary,
  chainWorkRequired,
};
