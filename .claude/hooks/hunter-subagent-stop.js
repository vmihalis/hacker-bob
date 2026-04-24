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
  const markerPattern = new RegExp(`${MARKER}\\s+(\\{[^\\n]+\\})`, "g");
  let match;
  while ((match = markerPattern.exec(message)) !== null) {
    try {
      const parsed = JSON.parse(match[1]);
      if (parsed && typeof parsed === "object") return parsed;
    } catch {}
  }
  return null;
}

function block(reason) {
  console.error(reason);
  process.exit(2);
}

function allow(message) {
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

function parseToolJson(raw, label) {
  const value = typeof raw === "string" ? JSON.parse(raw) : raw;
  if (value && value.ok === true && value.data) return value.data;
  if (value && value.ok === false) {
    throw new Error(`${label} failed: ${value.error?.message || value.error?.code || "unknown error"}`);
  }
  return value;
}

function assertMarker(marker) {
  const missing = ["target_domain", "wave", "agent", "surface_id"].filter((field) => {
    return typeof marker[field] !== "string" || marker[field].trim() === "";
  });
  if (missing.length) {
    block(`Hunter final marker is missing required field(s): ${missing.join(", ")}`);
  }
  if (!/^w[0-9]+$/.test(marker.wave)) {
    block("Hunter final marker wave must look like wN");
  }
  if (!/^a[0-9]+$/.test(marker.agent)) {
    block("Hunter final marker agent must look like aN");
  }
}

function verifyStructuredHandoff(server, marker, waveNumber) {
  const handoffs = parseToolJson(server.readWaveHandoffs({
    target_domain: marker.target_domain,
    wave_number: waveNumber,
  }), "bounty_read_wave_handoffs");

  const missing = (handoffs.missing_handoffs || []).find((item) => item.agent === marker.agent);
  if (missing) {
    block(`Hunter ${marker.wave}/${marker.agent} must call bounty_write_wave_handoff before stopping and then emit ${MARKER}.`);
  }

  const invalid = (handoffs.invalid_handoffs || []).find((item) => item.agent === marker.agent);
  if (invalid) {
    block(`Hunter ${marker.wave}/${marker.agent} wrote an invalid handoff: ${invalid.error || "validation failed"}`);
  }

  const handoff = (handoffs.handoffs || []).find((item) => item.agent === marker.agent);
  if (!handoff) {
    block(`Hunter ${marker.wave}/${marker.agent} handoff was not found in structured wave handoffs.`);
  }
  if (handoff.wave !== marker.wave || handoff.surface_id !== marker.surface_id) {
    block(`Hunter final marker does not match structured handoff for ${marker.wave}/${marker.agent}.`);
  }
}

function maybeMergeWave(server, marker, waveNumber) {
  const stateSummary = parseToolJson(server.readStateSummary({
    target_domain: marker.target_domain,
  }), "bounty_read_state_summary");
  const pendingWave = stateSummary.state?.pending_wave;
  if (pendingWave == null || pendingWave !== waveNumber) {
    allow("wave is not pending");
  }

  const readiness = parseToolJson(server.waveHandoffStatus({
    target_domain: marker.target_domain,
    wave_number: waveNumber,
  }), "bounty_wave_handoff_status");
  if (!readiness.is_complete) {
    allow("wave still has pending handoffs");
  }

  const merge = parseToolJson(server.applyWaveMerge({
    target_domain: marker.target_domain,
    wave_number: waveNumber,
    force_merge: false,
  }), "bounty_apply_wave_merge");
  if (merge.status !== "merged") {
    block(`Wave ${waveNumber} did not merge cleanly: ${merge.status || "unknown status"}`);
  }
  allow(`merged wave ${waveNumber}`);
}

function main() {
  let payload = {};
  try {
    payload = JSON.parse(readStdin() || "{}");
  } catch {
    payload = {};
  }

  const message = lastAssistantMessage(payload);
  const marker = parseMarker(message);
  if (!marker) {
    block(`Hunter stop blocked: write the wave handoff with bounty_write_wave_handoff, then emit ${MARKER} {"target_domain":"...","wave":"wN","agent":"aN","surface_id":"..."}.`);
  }
  assertMarker(marker);

  const server = loadServer();
  const waveNumber = Number(marker.wave.slice(1));
  verifyStructuredHandoff(server, marker, waveNumber);
  maybeMergeWave(server, marker, waveNumber);
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
};
