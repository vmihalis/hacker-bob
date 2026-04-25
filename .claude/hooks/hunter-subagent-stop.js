#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const MARKER = "BOB_HUNTER_DONE";

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
  recordHunterTelemetry(telemetryInput);
  console.error(reason);
  process.exit(2);
}

function allow(message, telemetryInput = null) {
  recordHunterTelemetry(telemetryInput);
  if (message) {
    console.log(JSON.stringify({ ok: true, message }));
  }
  process.exit(0);
}

function projectRoot() {
  return process.env.CLAUDE_PROJECT_DIR || path.resolve(__dirname, "..", "..");
}

function loadServer() {
  return require(path.join(projectRoot(), "mcp", "server.js"));
}

function loadTelemetry() {
  return require(path.join(projectRoot(), "mcp", "lib", "tool-telemetry.js"));
}

function recordHunterTelemetry(input) {
  if (!input) return;
  try {
    const telemetry = loadTelemetry();
    if (telemetry && typeof telemetry.safeRecordAgentRunTelemetry === "function") {
      telemetry.safeRecordAgentRunTelemetry(input);
    }
  } catch {}
}

function parseToolJson(raw, label) {
  const value = typeof raw === "string" ? JSON.parse(raw) : raw;
  if (value && value.ok === true && value.data) return value.data;
  if (value && value.ok === false) {
    throw new Error(`${label} failed: ${value.error?.message || value.error?.code || "unknown error"}`);
  }
  return value;
}

function markerValidationError(marker) {
  const missing = ["target_domain", "wave", "agent", "surface_id"].filter((field) => {
    return typeof marker[field] !== "string" || marker[field].trim() === "";
  });
  if (missing.length) {
    return {
      block_code: "malformed_marker",
      reason: `Hunter final marker is missing required field(s): ${missing.join(", ")}`,
    };
  }
  if (!/^w[1-9][0-9]*$/.test(marker.wave)) {
    return {
      block_code: "malformed_marker",
      reason: "Hunter final marker wave must look like positive wN",
    };
  }
  if (!/^a[1-9][0-9]*$/.test(marker.agent)) {
    return {
      block_code: "malformed_marker",
      reason: "Hunter final marker agent must look like positive aN",
    };
  }
  return null;
}

function handoffTelemetry(handoff, { present = true, valid = true } = {}) {
  return {
    present,
    valid,
    provenance: handoff?.provenance || null,
    surface_status: handoff?.surface_status || null,
    summary_present: typeof handoff?.summary === "string" && handoff.summary.trim() !== "",
    chain_notes_count: Array.isArray(handoff?.chain_notes) ? handoff.chain_notes.length : 0,
  };
}

function inspectStructuredHandoff(server, marker, waveNumber) {
  const handoffs = parseToolJson(server.readWaveHandoffs({
    target_domain: marker.target_domain,
    wave_number: waveNumber,
  }), "bounty_read_wave_handoffs");

  const missing = (handoffs.missing_handoffs || []).find((item) => item.agent === marker.agent);
  if (missing) {
    return {
      ok: false,
      block_code: "missing_handoff",
      reason: `Hunter ${marker.wave}/${marker.agent} must call bounty_write_wave_handoff before stopping and then emit ${MARKER}.`,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }

  const invalid = (handoffs.invalid_handoffs || []).find((item) => item.agent === marker.agent);
  if (invalid) {
    return {
      ok: false,
      block_code: "invalid_handoff",
      reason: `Hunter ${marker.wave}/${marker.agent} wrote an invalid handoff: ${invalid.error || "validation failed"}`,
      handoff: handoffTelemetry(null, { present: true, valid: false }),
    };
  }

  const handoff = (handoffs.handoffs || []).find((item) => item.agent === marker.agent);
  if (!handoff) {
    return {
      ok: false,
      block_code: "missing_handoff",
      reason: `Hunter ${marker.wave}/${marker.agent} handoff was not found in structured wave handoffs.`,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }
  if (handoff.wave !== marker.wave || handoff.surface_id !== marker.surface_id) {
    return {
      ok: false,
      block_code: "handoff_mismatch",
      reason: `Hunter final marker does not match structured handoff for ${marker.wave}/${marker.agent}.`,
      handoff: handoffTelemetry(handoff),
    };
  }

  return {
    ok: true,
    handoff: handoffTelemetry(handoff),
  };
}

function transcriptPathFromPayload(payload) {
  if (typeof payload.transcript_path === "string") return payload.transcript_path;
  if (typeof payload.transcriptPath === "string") return payload.transcriptPath;
  return null;
}

function summarizeCoverageForRun(server, marker) {
  const summary = { total: 0, by_status: {} };
  if (!server || typeof server.readCoverageRecordsFromJsonl !== "function" || !marker) {
    return summary;
  }

  try {
    const records = server.readCoverageRecordsFromJsonl(marker.target_domain);
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

function summarizeFindingsForRun(server, marker) {
  const summary = { count: 0 };
  if (!server || typeof server.readFindingsFromJsonl !== "function" || !marker) {
    return summary;
  }

  try {
    const findings = server.readFindingsFromJsonl(marker.target_domain);
    summary.count = findings.filter((finding) => (
      finding.wave === marker.wave &&
      finding.agent === marker.agent &&
      finding.surface_id === marker.surface_id
    )).length;
  } catch {}
  return summary;
}

function runStats(server, marker) {
  return {
    coverage: summarizeCoverageForRun(server, marker),
    findings: summarizeFindingsForRun(server, marker),
  };
}

function telemetryInput({
  payload,
  marker = null,
  now,
  status,
  block_code = null,
  server = null,
  handoff = null,
}) {
  const stats = runStats(server, marker);
  return {
    runType: "hunter",
    status,
    blockCode: block_code,
    target_domain: marker?.target_domain,
    wave: marker?.wave,
    agent: marker?.agent,
    surface_id: marker?.surface_id,
    transcript_path: transcriptPathFromPayload(payload),
    handoff,
    coverage: stats.coverage,
    findings: stats.findings,
    telemetry_source: "hunter-subagent-stop",
    now,
  };
}

function main() {
  const now = new Date();
  let payload = {};
  let marker = null;
  let server = null;
  try {
    payload = JSON.parse(readStdin() || "{}");
  } catch {
    payload = {};
  }

  const message = lastAssistantMessage(payload);
  const markerResult = parseMarkerWithStatus(message);
  marker = markerResult.marker;
  if (!marker) {
    block(
      `Hunter stop blocked: write the wave handoff with bounty_write_wave_handoff, then emit ${MARKER} {"target_domain":"...","wave":"wN","agent":"aN","surface_id":"..."}.`,
      telemetryInput({
        payload,
        now,
        status: "blocked",
        block_code: markerResult.malformed ? "malformed_marker" : "missing_marker",
      }),
    );
  }

  const markerError = markerValidationError(marker);
  if (markerError) {
    block(markerError.reason, telemetryInput({
      payload,
      marker,
      now,
      status: "blocked",
      block_code: markerError.block_code,
    }));
  }

  server = loadServer();
  const waveNumber = Number(marker.wave.slice(1));
  const handoffResult = inspectStructuredHandoff(server, marker, waveNumber);
  if (!handoffResult.ok) {
    block(handoffResult.reason, telemetryInput({
      payload,
      marker,
      now,
      status: "blocked",
      block_code: handoffResult.block_code,
      server,
      handoff: handoffResult.handoff,
    }));
  }
  allow("handoff valid", telemetryInput({
    payload,
    marker,
    now,
    status: "allowed",
    server,
    handoff: handoffResult.handoff,
  }));
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
