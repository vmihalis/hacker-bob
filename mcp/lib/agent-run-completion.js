"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const {
  assertNonEmptyString,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const {
  buildWaveHandoffsDocument,
} = require("./wave-handoff-store.js");
const {
  loadWaveAssignments,
} = require("./assignments.js");
const {
  sessionDir,
  agentRunStopSeenDir,
} = require("./paths.js");
const {
  readJsonFile,
  writeFileAtomic,
} = require("./storage.js");

const EVIDENCE_MODE = "evidence";

function cleanString(value) {
  if (typeof value !== "string") return "";
  return value.trim();
}

function markerMode(marker) {
  return cleanString(marker && marker.mode);
}

function isEvidenceMarker(marker) {
  return markerMode(marker) === EVIDENCE_MODE;
}

// Validate the post-report evidence marker shape — distinct from wave-mode
// markers because evidence runs have no wave/agent context. The orchestrator
// permits these only after REPORT (or during EXPLORE) when an operator asks
// the evaluator to amplify a single finding's evidence.
function evidenceMarkerValidationError(marker) {
  if (!cleanString(marker && marker.target_domain)) {
    return {
      block_code: "malformed_marker",
      reason: "Post-report evidence marker is missing required field: target_domain",
    };
  }
  if (cleanString(marker.wave) || cleanString(marker.agent)) {
    return {
      block_code: "malformed_marker",
      reason: "Post-report evidence marker must not include wave or agent; use the normal wave marker for EXPLORE evaluators.",
    };
  }
  return null;
}

// Read state.phase from disk (not via MCP) because the hook process may not
// have the MCP server in scope at SubagentStop time. Phase must be REPORT or
// EXPLORE for evidence runs to be allowed; outside that window we block to
// prevent accidental evidence collection during EVALUATE/CHAIN/VERIFY/GRADE.
function evaluateEvidenceCompletion(marker) {
  const targetDomain = cleanString(marker && marker.target_domain);
  if (!targetDomain) {
    return {
      ok: false,
      block_code: "evidence_state_unreadable",
      reason: "Post-report evidence marker missing target_domain.",
    };
  }
  const home = os.homedir();
  if (!home) {
    return {
      ok: false,
      block_code: "evidence_state_unreadable",
      reason: "Post-report evidence marker could not resolve $HOME for session state read.",
    };
  }
  const statePath = path.join(sessionDir(targetDomain), "state.json");
  let state;
  try {
    state = readJsonFile(statePath, { label: "state.json" });
  } catch (error) {
    return {
      ok: false,
      block_code: "evidence_state_unreadable",
      reason: `Post-report evidence marker could not read session state: ${error.message || String(error)}`,
    };
  }
  // Post-report evidence runs are allowed only when the session has reached
  // REPORT (or re-entered OPEN_FRONTIER from REPORT — the legacy EXPLORE
  // window). The lifecycle vocabulary is lossy here: OPEN_FRONTIER covers both
  // active EVALUATE (block) and post-report EXPLORE (allow), so the legacy
  // phase remains the discriminator for that one ambiguous lifecycle state.
  //
  // Step 4: session-nucleus.json is the single source of truth for lifecycle
  // state; state.json is a projection of it. Source lifecycle_state from the
  // nucleus so a partially-written / drifted state.json can never gate this
  // hook against the authoritative lifecycle (the REPORT vs CLAIM_FREEZE drift
  // class). The nucleus read is best-effort: the hook process may not have the
  // MCP server in scope at SubagentStop time (and the session may predate the
  // nucleus), so on any read failure fall back to state.json's own copy.
  const allowedLifecycleStates = new Set(["REPORT", "OPEN_FRONTIER"]);
  const allowedLegacyPhases = new Set(["REPORT", "EXPLORE"]);
  let lifecycleState = state && state.lifecycle_state;
  const legacyPhase = state && state.phase;
  try {
    const { readSessionNucleus } = require("./governance-store.js");
    const nucleus = readSessionNucleus(targetDomain);
    if (nucleus && typeof nucleus.lifecycle_state === "string") {
      lifecycleState = nucleus.lifecycle_state;
    }
  } catch (_error) {
    // Nucleus unavailable (hook out of MCP scope, or legacy session without a
    // nucleus). Keep the state.json-derived lifecycle_state above.
  }
  // REPORT is unambiguous at the lifecycle level and is sourced from the
  // nucleus. OPEN_FRONTIER is ambiguous (EVALUATE vs EXPLORE), so it is only an
  // evidence window when the legacy phase confirms the EXPLORE re-entry. When
  // no lifecycle_state is available at all (legacy disk), fall back entirely to
  // the legacy phase.
  const lifecycleAllowed = lifecycleState === "REPORT"
    || (lifecycleState === "OPEN_FRONTIER" && legacyPhase && allowedLegacyPhases.has(legacyPhase));
  const legacyAllowed = !lifecycleState && legacyPhase && allowedLegacyPhases.has(legacyPhase);
  if (!state || (!lifecycleAllowed && !legacyAllowed)) {
    return {
      ok: false,
      block_code: "evidence_phase_mismatch",
      reason: `Post-report evidence marker is allowed only when lifecycle_state is REPORT or OPEN_FRONTIER (legacy phase REPORT or EXPLORE); current lifecycle_state is ${lifecycleState || "unknown"} / phase ${legacyPhase || "unknown"}.`,
    };
  }
  return {
    ok: true,
    handoff: {
      present: false,
      valid: true,
      provenance: "post_report_evidence",
      surface_status: "evidence",
      summary_present: cleanString(marker.summary) !== "",
      chain_notes_count: 0,
    },
  };
}

function evidenceTelemetryInput({
  marker,
  status,
  block_code = null,
  handoff = null,
  transcript_path = null,
  now = new Date(),
}) {
  return {
    ok: status === "allowed",
    runType: EVIDENCE_MODE,
    status,
    block_code,
    target_domain: cleanString(marker && marker.target_domain) || null,
    wave: null,
    agent: null,
    surface_id: cleanString(marker && marker.surface_id) || null,
    transcript_path,
    handoff,
    telemetry_source: "evaluator-evidence-stop",
    now,
  };
}
const {
  readCoverageRecordsFromJsonl,
} = require("./coverage.js");
const {
  findingPayloadsFromClaims,
} = require("./tools/record-candidate-claim.js");
const {
  readTechniqueAttemptRecordsFromJsonl,
} = require("./technique-packs.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  safeRecordToolInvocationTelemetry,
  telemetryEnabled,
} = require("./tool-telemetry.js");
const {
  safeRecordEvaluatorStoppedPipelineEvent,
} = require("./pipeline-events.js");
const {
  safeGovernanceContextForDomain,
} = require("./governance-context.js");

const TECHNIQUE_ATTEMPT_COMPLETION_STATUSES = new Set([
  "attempted",
  "not_applicable",
  "promising",
  "validated",
  "failed",
  "skipped",
]);

function handoffTelemetry(handoff, { present = true, valid = true } = {}) {
  return {
    present,
    valid,
    provenance: handoff && handoff.provenance ? handoff.provenance : null,
    surface_status: handoff && handoff.surface_status ? handoff.surface_status : null,
    summary_present: typeof (handoff && handoff.summary) === "string" && handoff.summary.trim() !== "",
    chain_notes_count: Array.isArray(handoff && handoff.chain_notes) ? handoff.chain_notes.length : 0,
  };
}

function summarizeCoverageForRun(marker) {
  const summary = { total: 0, by_status: {} };
  if (!marker) return summary;

  try {
    const records = readCoverageRecordsFromJsonl(marker.target_domain);
    for (const record of records) {
      if (
        record.wave !== marker.wave ||
        record.agent !== marker.agent ||
        record.surface_id !== marker.surface_id
      ) {
        continue;
      }
      summary.total += 1;
      summary.by_status[record.status] = (summary.by_status[record.status] || 0) + 1;
    }
  } catch {}
  return summary;
}

function summarizeFindingsForRun(marker) {
  const summary = { count: 0 };
  if (!marker) return summary;

  try {
    const findings = findingPayloadsFromClaims(marker.target_domain);
    summary.count = findings.filter((finding) => (
      finding.wave === marker.wave &&
      finding.agent === marker.agent &&
      finding.surface_id === marker.surface_id
    )).length;
  } catch {}
  return summary;
}

function evaluateTechniqueAttemptRequirement(marker, assignment) {
  if (
    !assignment ||
    !assignment.context_budget ||
    assignment.context_budget.attempt_log_required !== true
  ) {
    return null;
  }

  let attempts;
  try {
    attempts = readTechniqueAttemptRecordsFromJsonl(marker.target_domain);
  } catch (error) {
    return {
      ok: false,
      status: "blocked",
      block_code: "invalid_technique_attempt_log",
      reason: `Evaluator ${marker.wave}/${marker.agent} has unreadable technique attempt history: ${error.message || String(error)}`,
      marker,
      handoff: null,
    };
  }

  // wave/agent are OPTIONAL on bob_log_technique_attempt (technique-packs.js
  // resolves the route directly when they are omitted), so a valid
  // completion-status attempt may be recorded with no wave/agent at all. Only
  // reject on a wave/agent MISMATCH (a value that belongs to a different run);
  // an absent wave/agent on a same-domain, same-surface, completion-status
  // attempt satisfies the requirement. This prevents a phantom
  // missing_technique_attempt_log on a genuinely-evaluated surface.
  //
  // Accepted residual: an attempt logged WITHOUT wave/agent for a stable
  // surface_id that is later requeued into a new wave would also satisfy that
  // new wave's finalize. This is bounded and acceptable — the gate is an
  // anti-laziness signal, not a security boundary; the wave handoff itself
  // stays wave-bound (a lazy later-wave run must still produce a fresh handoff),
  // and the evaluator prompt now mandates passing wave/agent, so a compliant
  // attempt carries the wave and is mismatch-rejected for any other wave.
  const matchingAttempt = attempts.find((attempt) =>
    attempt.target_domain === marker.target_domain &&
    attempt.surface_id === marker.surface_id &&
    (attempt.wave == null || attempt.wave === marker.wave) &&
    (attempt.agent == null || attempt.agent === marker.agent) &&
    TECHNIQUE_ATTEMPT_COMPLETION_STATUSES.has(attempt.status)
  );
  if (matchingAttempt) return null;

  return {
    ok: false,
    status: "blocked",
    block_code: "missing_technique_attempt_log",
    reason: `Evaluator ${marker.wave}/${marker.agent} must call bob_log_technique_attempt with a real attempt outcome before finalizing this surface.`,
    marker,
    handoff: null,
  };
}

function evaluateOssCompletionCoverage(marker, assignment, handoff) {
  if (!assignment || !assignment.capability_pack || !assignment.capability_pack.startsWith("oss_")) {
    return null;
  }
  if (!handoff || handoff.surface_status !== "complete") return null;

  const coverage = summarizeCoverageForRun(marker);
  const findings = summarizeFindingsForRun(marker);
  if (coverage.total > 0 || findings.count > 0) return null;

  return {
    ok: false,
    status: "blocked",
    block_code: "missing_oss_coverage",
    reason: `Evaluator ${marker.wave}/${marker.agent} cannot mark OSS surface ${marker.surface_id} complete with zero coverage rows and zero findings; log concrete repo checks/build attempts or set surface_status to partial with blockers.`,
    marker,
    handoff: null,
  };
}

function normalizeFinalizeArgs(args) {
  const targetDomain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  return {
    target_domain: targetDomain,
    wave,
    agent,
    surface_id: surfaceId,
  };
}

function evaluateAgentCompletion(args) {
  const marker = normalizeFinalizeArgs(args);
  const waveNumber = Number(marker.wave.slice(1));
  let waveAssignments;
  try {
    waveAssignments = loadWaveAssignments(marker.target_domain, waveNumber);
  } catch (error) {
    return {
      ok: false,
      status: "blocked",
      block_code: "unreadable_wave_assignments",
      reason: `Evaluator ${marker.wave}/${marker.agent} could not read wave assignments: ${error.message || String(error)}`,
      marker,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }

  let handoffs;
  try {
    handoffs = buildWaveHandoffsDocument(marker.target_domain, [waveNumber]);
  } catch (error) {
    return {
      ok: false,
      status: "blocked",
      block_code: "unreadable_wave_assignments",
      reason: `Evaluator ${marker.wave}/${marker.agent} could not evaluate wave assignments: ${error.message || String(error)}`,
      marker,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }

  const missing = (handoffs.missing_handoffs || []).find((item) => item.agent === marker.agent);
  if (missing) {
    return {
      ok: false,
      status: "blocked",
      block_code: "missing_handoff",
      reason: `Evaluator ${marker.wave}/${marker.agent} must call bob_write_wave_handoff before finalizing.`,
      marker,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }

  const invalid = (handoffs.invalid_handoffs || []).find((item) => item.agent === marker.agent);
  if (invalid) {
    return {
      ok: false,
      status: "blocked",
      block_code: "invalid_handoff",
      reason: `Evaluator ${marker.wave}/${marker.agent} wrote an invalid handoff: ${invalid.error || "validation failed"}`,
      marker,
      handoff: handoffTelemetry(null, { present: true, valid: false }),
    };
  }

  const handoff = (handoffs.handoffs || []).find((item) => item.agent === marker.agent);
  if (!handoff) {
    return {
      ok: false,
      status: "blocked",
      block_code: "missing_handoff",
      reason: `Evaluator ${marker.wave}/${marker.agent} handoff was not found in structured wave handoffs.`,
      marker,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }

  if (handoff.wave !== marker.wave || handoff.surface_id !== marker.surface_id) {
    return {
      ok: false,
      status: "blocked",
      block_code: "handoff_mismatch",
      reason: `Evaluator finalization does not match structured handoff for ${marker.wave}/${marker.agent}.`,
      marker,
      handoff: handoffTelemetry(handoff),
    };
  }

  const assignment = waveAssignments.assignmentByAgent.get(marker.agent);
  const techniqueAttemptBlock = evaluateTechniqueAttemptRequirement(marker, assignment);
  if (techniqueAttemptBlock) {
    return {
      ...techniqueAttemptBlock,
      handoff: handoffTelemetry(handoff),
    };
  }

  const ossCoverageBlock = evaluateOssCompletionCoverage(marker, assignment, handoff);
  if (ossCoverageBlock) {
    return {
      ...ossCoverageBlock,
      handoff: handoffTelemetry(handoff),
    };
  }

  return {
    ok: true,
    status: "allowed",
    block_code: null,
    reason: "handoff valid",
    marker,
    handoff: handoffTelemetry(handoff),
  };
}

function telemetryInput(evaluation, {
  transcript_path: transcriptPath = null,
  telemetry_source: telemetrySource = "bob_finalize_agent_run",
  now = new Date(),
} = {}) {
  const marker = evaluation && evaluation.marker ? evaluation.marker : null;
  return {
    runType: "evaluator",
    status: evaluation.status,
    blockCode: evaluation.block_code,
    target_domain: marker && marker.target_domain,
    wave: marker && marker.wave,
    agent: marker && marker.agent,
    surface_id: marker && marker.surface_id,
    transcript_path: transcriptPath,
    handoff: evaluation.handoff,
    coverage: summarizeCoverageForRun(marker),
    findings: summarizeFindingsForRun(marker),
    telemetry_source: telemetrySource,
    now,
  };
}

// A "phantom null-coord block row" is the telemetry shape the SubagentStop hook
// emits when an agent stops without USABLE coordinates: status "blocked", a
// block_code of "missing_marker" (no marker at all) or "malformed_marker" (the
// MARKER string present but unparseable, or a parsed marker missing every
// coordinate), AND null target_domain/wave/agent. The hook's block() re-fires
// this identical row on every exit(2)-forced continuation of the same subagent,
// so it is the row class that needs per-subagent deduping.
//
// malformed_marker is widened in here DELIBERATELY but ONLY for the null-coord
// shape: a malformed_marker that carries a real target_domain/wave/agent (the
// common partial-marker case — e.g. a "w0" wave that fails the positive-wN
// regex) keeps its coordinates and is therefore NOT gated. The all-coords-null
// discriminator is exactly what isolates the un-attributable storm shape from an
// attributable, individually-meaningful block.
const PHANTOM_NULL_COORD_BLOCK_CODES = new Set(["missing_marker", "malformed_marker"]);

function isPhantomNullCoordBlockRow(input) {
  return Boolean(input)
    && input.status === "blocked"
    && PHANTOM_NULL_COORD_BLOCK_CODES.has(input.blockCode)
    && input.target_domain == null && input.wave == null && input.agent == null;
}

// Stable 16-hex dedupe key for a phantom row's transcript_path. Returns null
// when there is no usable transcript key (missing / non-string / blank). A null
// key is the caller's FAIL-OPEN signal: a keyless row is always recorded and
// never deduped, so unrelated keyless rows can never collapse onto one shared
// (empty-string) key and cross-suppress each other.
function phantomTranscriptKey(input) {
  const transcriptPath = input && typeof input.transcript_path === "string"
    ? input.transcript_path.trim()
    : "";
  if (!transcriptPath) return null;
  return crypto.createHash("sha256").update(transcriptPath).digest("hex").slice(0, 16);
}

// Per-transcript phantom-row dedupe. The storm re-fires within ONE transcript
// are SEQUENTIAL (stop -> hook -> exit(2) -> continue -> stop ...), so the
// per-transcript marker file needs no cross-process lock; concurrency happens
// only ACROSS transcripts, which hash to DISTINCT marker files. Invariants:
//   * row-before-mark: a marker is created only AFTER recordRow() reports the
//     first row was actually written, so a sink failure can never suppress an
//     unwritten first row (the fail-CLOSED hole is closed).
//   * fail-open: telemetry disabled, no usable transcript key, or ANY fault in
//     this path -> record the row (treat as a first occurrence).
//   * bounded growth: exactly one small marker file per DISTINCT phantom
//     transcript; same-transcript re-fires only bump that file's own counter.
// recordRow() must return true iff the invocation row was actually written.
function recordPhantomBlockRowOnce(input, recordRow, env = process.env) {
  // Telemetry opt-out: the dedupe machinery writes nothing; the row sink honors
  // the same opt-out, so the gate as a whole writes nothing.
  if (!telemetryEnabled(env)) {
    recordRow();
    return;
  }
  const key = phantomTranscriptKey(input);
  if (!key) {
    // No usable transcript key -> cannot dedupe safely. Fail open: record.
    recordRow();
    return;
  }
  let markerFile;
  try {
    markerFile = path.join(agentRunStopSeenDir(env), key);
  } catch {
    recordRow();
    return;
  }
  // Duplicate re-fire for this transcript: suppress the row, but COUNT it in the
  // transcript's OWN marker file. Same-transcript re-fires are sequential, so
  // this read-modify-write has no concurrent writer for the same key.
  if (fs.existsSync(markerFile)) {
    bumpPhantomTranscriptSuppressed(markerFile);
    return;
  }
  // First occurrence for this transcript: write the row FIRST, then mark seen.
  // If the row sink could not write it, leave the transcript UNMARKED so the
  // next re-fire records again (fail open; never a marker without a written
  // first row).
  if (recordRow() !== true) return;
  try {
    writeFileAtomic(markerFile, JSON.stringify({ version: 1, suppressed: 0 }));
  } catch {
    // Mark failed -> stays unmarked; a later re-fire will record again.
  }
}

// Increment one transcript's suppressed-re-fire counter. Best-effort and
// isolated to that transcript's marker file: a corrupt/unreadable marker is
// rewritten with a fresh count rather than throwing into the telemetry path.
function bumpPhantomTranscriptSuppressed(markerFile) {
  try {
    let suppressed = 0;
    try {
      const state = readJsonFile(markerFile);
      if (state && Number.isInteger(state.suppressed) && state.suppressed >= 0) {
        suppressed = state.suppressed;
      }
    } catch {
      // Unreadable/corrupt marker -> restart its count from 0.
    }
    writeFileAtomic(markerFile, JSON.stringify({ version: 1, suppressed: suppressed + 1 }));
  } catch {
    // Counter bump is best-effort; never throw.
  }
}

function recordAgentCompletionTelemetry(evaluation, options = {}) {
  // Evidence-mode input is already a fully-formed telemetry record (the hook
  // builds it directly because evidence runs have no wave/agent and skip the
  // structured-handoff evaluation path). Detect that shape by the runType
  // field and pass it through to the recorders unchanged.
  if (evaluation && evaluation.runType === "evidence") {
    safeRecordToolInvocationTelemetry(evaluation);
    safeRecordEvaluatorStoppedPipelineEvent(
      evaluation,
      safeGovernanceContextForDomain(evaluation.target_domain),
    );
    return evaluation;
  }
  const input = telemetryInput(evaluation, options);
  // recordRow writes the invocation row + the (phantom-row no-op) pipeline
  // event, returning true iff the invocation row was actually written. The
  // pipeline-event sink short-circuits on a null target_domain, so for phantom
  // rows only the invocation sink decides "was the row written".
  const recordRow = () => {
    const recorded = safeRecordToolInvocationTelemetry(input);
    safeRecordEvaluatorStoppedPipelineEvent(
      input,
      safeGovernanceContextForDomain(input.target_domain),
    );
    return recorded != null;
  };
  // Phantom null-coord block-row dedupe. The SubagentStop hook's block()
  // re-fires the same null-coord row on every exit(2)-forced continuation of one
  // subagent; record the FIRST per transcript and COUNT the re-fires. exit(2)
  // lives in block() and is untouched — this only decides whether the telemetry
  // row is written.
  if (isPhantomNullCoordBlockRow(input)) {
    recordPhantomBlockRowOnce(input, recordRow);
    return input;
  }
  recordRow();
  return input;
}

function finalizeAgentCompletion(args, options = {}) {
  const evaluation = evaluateAgentCompletion(args);
  recordAgentCompletionTelemetry(evaluation, options);
  return evaluation;
}

function finalizeAgentRun(args) {
  const evaluation = finalizeAgentCompletion(args, {
    telemetry_source: "bob_finalize_agent_run",
  });
  if (!evaluation.ok) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, evaluation.reason, {
      block_code: evaluation.block_code,
      target_domain: evaluation.marker.target_domain,
      wave: evaluation.marker.wave,
      agent: evaluation.marker.agent,
      surface_id: evaluation.marker.surface_id,
      handoff: evaluation.handoff,
    });
  }

  return JSON.stringify({
    version: 1,
    status: evaluation.status,
    target_domain: evaluation.marker.target_domain,
    wave: evaluation.marker.wave,
    agent: evaluation.marker.agent,
    surface_id: evaluation.marker.surface_id,
    message: evaluation.reason,
    handoff: evaluation.handoff,
  });
}

module.exports = {
  EVIDENCE_MODE,
  evaluateEvidenceCompletion,
  evaluateAgentCompletion,
  evaluateTechniqueAttemptRequirement,
  evidenceMarkerValidationError,
  evidenceTelemetryInput,
  finalizeAgentCompletion,
  finalizeAgentRun,
  handoffTelemetry,
  isEvidenceMarker,
  markerMode,
  recordAgentCompletionTelemetry,
  summarizeCoverageForRun,
  summarizeFindingsForRun,
  telemetryInput,
};
