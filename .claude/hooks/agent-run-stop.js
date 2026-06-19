#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const MARKER = "BOB_AGENT_RUN_DONE";

function readStdin() {
  return fs.readFileSync(0, "utf8");
}

function textFromValue(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(textFromValue).filter(Boolean).join("\n");
  if (!value || typeof value !== "object") return "";
  if (typeof value.text === "string") return value.text;
  if (typeof value.content === "string") return value.content;
  if (Array.isArray(value.content)) return textFromValue(value.content);
  if (typeof value.message === "string") return value.message;
  return "";
}

function readTranscriptLastAssistant(transcriptPath) {
  if (!transcriptPath || !fs.existsSync(transcriptPath)) return "";
  const lines = fs.readFileSync(transcriptPath, "utf8").trim().split(/\r?\n/).filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    try {
      const event = JSON.parse(lines[index]);
      const role = event.role || event.message?.role;
      if (role !== "assistant") continue;
      return textFromValue(event.message || event);
    } catch {}
  }
  return "";
}

function lastAssistantMessage(payload) {
  return textFromValue(
    payload.last_assistant_message ||
    payload.lastAssistantMessage ||
    payload.assistant_message ||
    payload.message,
  ) || readTranscriptLastAssistant(payload.transcript_path);
}

function parseMarker(message) {
  return parseMarkerWithStatus(message).marker;
}

function parseMarkerWithStatus(message) {
  const markerPattern = new RegExp(`${MARKER}\\s+(\\{[^\\n]+\\})`, "g");
  let match;
  let malformed = typeof message === "string" && message.includes(MARKER);
  while ((match = markerPattern.exec(message)) !== null) {
    try {
      const parsed = JSON.parse(match[1]);
      if (parsed && typeof parsed === "object") {
        return { marker: parsed, malformed: false };
      }
      malformed = true;
    } catch {
      malformed = true;
    }
  }
  return { marker: null, malformed };
}

function block(reason, telemetryInput = null) {
  recordAgentCompletionTelemetry(telemetryInput);
  console.error(reason);
  process.exit(2);
}

function projectRoot() {
  return process.env.BOB_PROJECT_DIR || process.env.CLAUDE_PROJECT_DIR || path.resolve(__dirname, "..", "..");
}

function loadAgentCompletion() {
  return require(path.join(projectRoot(), "mcp", "lib", "agent-run-completion.js"));
}

function loadAgentRuns() {
  return require(path.join(projectRoot(), "mcp", "lib", "agent-runs.js"));
}

function loadAssignments() {
  return require(path.join(projectRoot(), "mcp", "lib", "assignments.js"));
}

function loadPaths() {
  return require(path.join(projectRoot(), "mcp", "lib", "paths.js"));
}

function loadHandoffSigningKey() {
  return require(path.join(projectRoot(), "mcp", "lib", "handoff-signing-key.js"));
}

function loadWaveHandoffStore() {
  return require(path.join(projectRoot(), "mcp", "lib", "wave-handoff-store.js"));
}

// Step 2a: the maximum number of `failed` rows the stop hook will append for a
// single (wave, agent, surface) marker before it gives up looping and writes a
// single labelled `abandoned` row instead. Without this, a recoverable tooling
// gap (e.g. a promoted-lead surface whose technique-attempt row cannot be
// logged) made the agent retry-finalize indefinitely (~4.5h / ~960k tokens),
// each retry appending another `failed` row that poisoned the merge gate.
const TERMINAL_RETRY_CAP = 3;

// Which block_codes represent a recoverable coordination/tooling gap (an agent
// allowed to escape to a clean `abandoned` terminal after a bounded number of
// retries instead of looping forever and poisoning the ledger with `failed`
// rows) is decided per-marker by isRecoverableBlock below — a
// `missing_technique_attempt_log` is recoverable only for promoted-lead
// surfaces, and `missing_handoff`/`invalid_handoff` only with a verified
// handoff on disk.

// Count prior `failed` AgentRun rows already appended for this marker's run
// lineage. Used to bound the stop-hook retry loop (Step 2a). Best-effort: any
// read error yields 0 so the hook behaves as before (writes a `failed` row).
function priorFailedRunCountForMarker(marker) {
  try {
    const { readAgentRuns, syntheticTaskIdForWaveAssignment } = loadAgentRuns();
    const taskId = syntheticTaskIdForWaveAssignment({
      targetDomain: marker.target_domain,
      wave: marker.wave,
      agent: marker.agent,
      surfaceId: marker.surface_id || null,
    });
    const runs = readAgentRuns(marker.target_domain);
    let count = 0;
    for (const run of runs) {
      if (run && run.task_id === taskId && run.agent_id === marker.agent && run.status === "failed") {
        count += 1;
      }
    }
    return count;
  } catch {
    return 0;
  }
}

// Decide whether a finalize block_code is recoverable for THIS marker. A
// `missing_technique_attempt_log` is recoverable ONLY for promoted-lead
// surfaces (surface_id starting with "lead-"), where the genuine tooling gap
// lives — a promoted lead-* surface cannot always log a technique attempt. For
// an ordinary "surface-*" assignment the registry's `attempt_log_required`
// control is terminal, NOT a recoverable gap: letting it escape to `abandoned`
// after the retry cap would bypass that control via the merge gate's
// verified-handoff relaxation. A self-induced `missing_handoff`/`invalid_handoff`
// is recoverable ONLY when a cryptographically verified handoff is present on
// disk — i.e. the stop-hook's own `failed` row is masking a settleable run.
// A forged/absent handoff is NOT recoverable and stays a genuine failure.
function isRecoverableBlock(marker, blockCode) {
  if (!blockCode) return false;
  if (blockCode === "missing_technique_attempt_log") {
    return Boolean(marker)
      && typeof marker.surface_id === "string"
      && marker.surface_id.startsWith("lead-");
  }
  if (blockCode === "missing_handoff" || blockCode === "invalid_handoff") {
    return verifiedHandoffPresentForMarker(marker);
  }
  return false;
}

// Re-validate the on-disk handoff for this marker through the same full HMAC
// provenance path the merge gate uses (validateWaveHandoffPayload +
// validateHandoffProvenance). Best-effort: any error yields false so the hook
// falls back to treating the block as genuinely terminal.
function verifiedHandoffPresentForMarker(marker) {
  try {
    const { loadWaveArtifacts, readSigningKeyForArtifacts, verifiedHandoffOnDiskForAssignment } = loadWaveHandoffStore();
    const waveNumber = Number(marker.wave.slice(1));
    if (!Number.isInteger(waveNumber) || waveNumber < 1) return false;
    const artifacts = loadWaveArtifacts(marker.target_domain, waveNumber);
    const assignment = artifacts.assignmentByAgent
      ? artifacts.assignmentByAgent.get(marker.agent)
      : null;
    if (!assignment) return false;
    let signingKey = null;
    let signingKeyError = null;
    try {
      signingKey = readSigningKeyForArtifacts(marker.target_domain, artifacts);
    } catch (error) {
      signingKeyError = error;
    }
    return verifiedHandoffOnDiskForAssignment(marker.target_domain, artifacts, assignment, {
      signingKey,
      signingKeyError,
    });
  } catch {
    return false;
  }
}

// Settle the AgentRun ledger row through the same signed-handoff provenance
// the merge path uses. Best-effort: hook failure must not block the agent's
// stop, and the merge gate's file-presence fallback still protects readiness.
function settleAgentRunForMarker(marker) {
  if (!marker || !marker.target_domain || !marker.wave || !marker.agent || !marker.surface_id) return;
  try {
    const { settleAgentRunFromHandoff } = loadAgentRuns();
    const { loadWaveAssignments } = loadAssignments();
    const { sessionDir } = loadPaths();
    const { readHandoffSigningKey } = loadHandoffSigningKey();
    const waveNumber = Number(marker.wave.slice(1));
    if (!Number.isInteger(waveNumber) || waveNumber < 1) return;
    const assignments = loadWaveAssignments(marker.target_domain, waveNumber);
    const assignment = assignments && assignments.assignmentByAgent
      ? assignments.assignmentByAgent.get(marker.agent)
      : null;
    if (!assignment) return;
    const handoffPath = path.join(
      sessionDir(marker.target_domain),
      `handoff-${marker.wave}-${marker.agent}.json`,
    );
    if (!fs.existsSync(handoffPath)) return;
    let handoffJson;
    try {
      handoffJson = JSON.parse(fs.readFileSync(handoffPath, "utf8"));
    } catch {
      return;
    }
    let signingKey = null;
    try {
      signingKey = readHandoffSigningKey(marker.target_domain);
    } catch {
      signingKey = null;
    }
    settleAgentRunFromHandoff({
      target_domain: marker.target_domain,
      wave: marker.wave,
      agent: marker.agent,
      surface_id: marker.surface_id,
      assignment,
      handoff: handoffJson,
      signing_key: signingKey,
    }, { write: true });
  } catch {
    // Ledger write is best-effort during the dual-write window.
  }
}

// Append a terminal non-settled row (failed/abandoned) so the merge gate can
// distinguish "evaluator stopped without valid handoff" from "evaluator still
// running". The file-presence fallback keeps the merge gate functional even
// when this write fails.
function markAgentRunTerminalForMarker(marker, { status, reason, blockCode = null, failureKind = null }) {
  if (!marker || !marker.target_domain || !marker.wave || !marker.agent) return;
  try {
    const { markAgentRunTerminal } = loadAgentRuns();
    markAgentRunTerminal({
      targetDomain: marker.target_domain,
      wave: marker.wave,
      agent: marker.agent,
      surfaceId: marker.surface_id || null,
      status,
      failureReason: typeof reason === "string" && reason.length > 0 ? reason.slice(0, 240) : null,
      blockCode: typeof blockCode === "string" && blockCode.length > 0 ? blockCode : null,
      failureKind: typeof failureKind === "string" && failureKind.length > 0 ? failureKind : null,
    });
  } catch {
    // Best-effort ledger write.
  }
}

function recordAgentCompletionTelemetry(input) {
  if (!input) return;
  try {
    const completion = loadAgentCompletion();
    if (completion && typeof completion.recordAgentCompletionTelemetry === "function") {
      completion.recordAgentCompletionTelemetry(input, {
        transcript_path: input.transcript_path,
        telemetry_source: input.telemetry_source || "agent-run-stop",
        now: input.now,
      });
    }
  } catch {}
}

function markerValidationError(marker) {
  const completion = loadAgentCompletion();
  if (completion && typeof completion.isEvidenceMarker === "function" && completion.isEvidenceMarker(marker)) {
    return completion.evidenceMarkerValidationError(marker);
  }
  const missing = ["target_domain", "wave", "agent", "surface_id"].filter((field) => {
    return typeof marker[field] !== "string" || marker[field].trim() === "";
  });
  if (missing.length) {
    return {
      block_code: "malformed_marker",
      reason: `Evaluator final marker is missing required field(s): ${missing.join(", ")}`,
    };
  }
  if (!/^w[1-9][0-9]*$/.test(marker.wave)) {
    return {
      block_code: "malformed_marker",
      reason: "Evaluator final marker wave must look like positive wN",
    };
  }
  if (!/^a[1-9][0-9]*$/.test(marker.agent)) {
    return {
      block_code: "malformed_marker",
      reason: "Evaluator final marker agent must look like positive aN",
    };
  }
  return null;
}

function inspectEvidenceRun(marker) {
  const completion = loadAgentCompletion();
  return completion.evaluateEvidenceCompletion(marker);
}

function evidenceTelemetryInput({ payload, marker, now, status, block_code = null, handoff = null }) {
  const completion = loadAgentCompletion();
  return completion.evidenceTelemetryInput({
    marker,
    status,
    block_code,
    handoff,
    transcript_path: transcriptPathFromPayload(payload),
    now,
  });
}

function isEvidenceMarker(marker) {
  const completion = loadAgentCompletion();
  return completion && typeof completion.isEvidenceMarker === "function" && completion.isEvidenceMarker(marker);
}

function transcriptPathFromPayload(payload) {
  if (typeof payload.transcript_path === "string") return payload.transcript_path;
  if (typeof payload.transcriptPath === "string") return payload.transcriptPath;
  return null;
}

function finalizeMarker(marker, payload, now) {
  const completion = loadAgentCompletion();
  return completion.finalizeAgentCompletion(marker, {
    transcript_path: transcriptPathFromPayload(payload),
    telemetry_source: "agent-run-stop",
    now,
  });
}

function markerTelemetryInput({
  payload,
  marker = null,
  now,
  status,
  block_code = null,
  handoff = null,
}) {
  return {
    ok: status === "allowed",
    status,
    block_code,
    reason: null,
    marker,
    handoff,
    target_domain: marker?.target_domain,
    wave: marker?.wave,
    agent: marker?.agent,
    surface_id: marker?.surface_id,
    transcript_path: transcriptPathFromPayload(payload),
    telemetry_source: "agent-run-stop",
    now,
  };
}

function main() {
  const now = new Date();
  let payload = {};
  let marker = null;
  try {
    payload = JSON.parse(readStdin() || "{}");
  } catch {
    payload = {};
  }

  const message = lastAssistantMessage(payload);
  const markerResult = parseMarkerWithStatus(message);
  marker = markerResult.marker;
  if (!marker) {
    // No marker at all: the agent stopped without finalizing. We have no
    // (wave, agent) anchor to attribute the AgentRun row to, so the ledger
    // gets nothing here. The merge gate's file-presence fallback (Pact P2)
    // keeps the gate closed until a real handoff lands.
    block(
      `Evaluator stop blocked: write the wave handoff with bob_write_wave_handoff, then emit ${MARKER} {"target_domain":"...","wave":"wN","agent":"aN","surface_id":"..."}.`,
      markerTelemetryInput({
        payload,
        now,
        status: "blocked",
        block_code: markerResult.malformed ? "malformed_marker" : "missing_marker",
      }),
    );
  }

  const markerError = markerValidationError(marker);
  if (markerError) {
    if (isEvidenceMarker(marker)) {
      block(markerError.reason, evidenceTelemetryInput({
        payload, marker, now, status: "blocked", block_code: markerError.block_code,
      }));
    } else {
      // Malformed wave marker: agent had partial coordinates but the row is
      // not settleable. Record as failed so the merge gate sees a terminal
      // state rather than a stuck `running` row.
      markAgentRunTerminalForMarker(marker, {
        status: "failed",
        reason: markerError.reason,
      });
      block(markerError.reason, markerTelemetryInput({
        payload, marker, now, status: "blocked", block_code: markerError.block_code,
      }));
    }
  }

  if (isEvidenceMarker(marker)) {
    const evidenceResult = inspectEvidenceRun(marker);
    if (!evidenceResult.ok) {
      block(evidenceResult.reason, evidenceTelemetryInput({
        payload, marker, now, status: "blocked",
        block_code: evidenceResult.block_code,
      }));
    }
    recordAgentCompletionTelemetry(evidenceTelemetryInput({
      payload, marker, now, status: "allowed",
      handoff: evidenceResult.handoff,
    }));
    console.log(JSON.stringify({ ok: true, message: "post-report evidence run accepted" }));
    process.exit(0);
  }

  const finalization = finalizeMarker(marker, payload, now);
  if (!finalization.ok) {
    const blockCode = finalization.block_code || null;
    // Step 2a: classify the block. A RECOVERABLE gap (a promoted-lead surface
    // whose technique-attempt row cannot be logged, or a self-induced
    // missing/invalid handoff that nonetheless has a provenance-verified file
    // on disk) must NOT loop forever appending `failed` rows. After a bounded
    // number of retries, append exactly one labelled `abandoned` row and exit
    // 0 so the agent terminates cleanly instead of burning ~4.5h / ~960k
    // tokens and poisoning the merge gate with a pile of `failed` rows.
    if (isRecoverableBlock(marker, blockCode)) {
      const priorFailed = priorFailedRunCountForMarker(marker);
      if (priorFailed >= TERMINAL_RETRY_CAP) {
        markAgentRunTerminalForMarker(marker, {
          status: "abandoned",
          reason: finalization.reason,
          blockCode,
          failureKind: "recoverable_tooling_gap",
        });
        console.log(JSON.stringify({
          ok: true,
          terminated: "abandoned",
          block_code: blockCode,
          message: `Evaluator ${marker.wave}/${marker.agent} abandoned after ${priorFailed} retries on recoverable block "${blockCode}": ${finalization.reason}`,
        }));
        process.exit(0);
      }
      // Below the cap: append a `failed` row (so the merge gate still sees a
      // terminal state) but tag it so the retry counter and audit can tell a
      // tooling gap from a genuine failure.
      markAgentRunTerminalForMarker(marker, {
        status: "failed",
        reason: finalization.reason,
        blockCode,
        failureKind: "recoverable_tooling_gap",
      });
      console.error(finalization.reason);
      process.exit(2);
    }
    // Genuinely terminal: handoff is missing/invalid with no verified file on
    // disk. Append a `failed` AgentRun row so the merge gate's state-driven
    // path can refuse to merge without waiting for a wall-clock timeout.
    markAgentRunTerminalForMarker(marker, {
      status: "failed",
      reason: finalization.reason,
      blockCode,
    });
    console.error(finalization.reason);
    process.exit(2);
  }
  // Handoff was validated and finalization succeeded — settle the AgentRun
  // ledger through the same signed-handoff provenance the merge path uses.
  settleAgentRunForMarker(marker);
  console.log(JSON.stringify({ ok: true, message: finalization.reason }));
  process.exit(0);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    block(error.message || String(error));
  }
}

module.exports = {
  MARKER,
  lastAssistantMessage,
  parseMarker,
  parseMarkerWithStatus,
};
