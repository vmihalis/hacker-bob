"use strict";

// T.7 — Drain the in-driver record-mode buffer for a browser session.
//
// Returns { flushed_count, recorded[] } AND simultaneously pipes the captured
// requests through importHttpTraffic so they land in traffic.jsonl with
// source: "browser_capture" and source_meta carrying the session_id. The
// ingestion path holds the per-domain session lock (see http-records.js
// withSessionLock), which is the T-R5 guarantee — browser captures never race
// other writers.
//
// Limitation (T-R7): captured requests reflect the wire-level HTTP that the
// browser issued; we do not capture or replay WebAuthn ceremonies. A captured
// fetch posting to /webauthn/verify can be replayed via bob_http_scan, but the
// signed challenge it carries was minted by a real authenticator and cannot
// be re-minted from this buffer alone.

const {
  importHttpTraffic,
} = require("../http-records.js");
const {
  browserSessions,
  ensureSessionMatchesDomain,
  envelopeFromError,
  envelopeSuccess,
  patchrightUnavailableEnvelope,
  safeSessionId,
  safeTargetDomain,
} = require("../browser-tools-shared.js");

const BROWSER_BUNDLES = ["evaluator-shared", "surface-discovery", "deep-surface-discovery"];

// Per-flush cap mirrors the http-records traffic import cap so a noisy SPA
// can't blow the ingestion budget in one call. Excess records are still
// returned to the caller in `recorded[]` so they can be re-pulled on a
// subsequent flush via a follow-up call.
const MAX_FLUSH_RECORDS = 500;

function buildImportEntry(record) {
  const headers = record && record.headers && typeof record.headers === "object" ? record.headers : {};
  return {
    method: record.method,
    url: record.url,
    headers,
    request_headers: headers,
    request: { method: record.method, url: record.url, headers, post_data: record.post_data || null },
    post_data: record.post_data || null,
    ts: record.timestamp ? new Date(record.timestamp).toISOString() : undefined,
    source_meta: {
      kind: "browser_capture",
      session_id: record.__session_id || null,
      resource_type: record.resource_type || null,
      frame_url: record.frame_url || null,
    },
  };
}

async function handler(args = {}) {
  if (!browserSessions.isPatchrightAvailable()) {
    return JSON.stringify(patchrightUnavailableEnvelope());
  }
  try {
    const targetDomain = safeTargetDomain(args.target_domain);
    const sessionId = safeSessionId(args.session_id);
    const entry = ensureSessionMatchesDomain(sessionId, targetDomain);
    if (!entry.recordMode) {
      const err = new Error(
        `browser_session_not_recording: session ${sessionId} was not started with record_mode. Use bob_browser_session_start_recording instead of bob_browser_session_start.`,
      );
      err.code = "browser_session_not_recording";
      throw err;
    }

    const flushResult = await browserSessions.flushRecordedRequests(sessionId);
    const buffered = Array.isArray(flushResult && flushResult.recorded) ? flushResult.recorded : [];
    // The first MAX_FLUSH_RECORDS entries go through ingestion this round.
    // Anything beyond is returned in `recorded[]` so the caller can decide
    // whether to make another flush (the driver buffer is already drained).
    const ingestSlice = buffered.slice(0, MAX_FLUSH_RECORDS);
    const overflow = buffered.length - ingestSlice.length;

    let importEnvelope = null;
    let importSummary = { imported: 0, duplicates: 0, rejected: 0 };
    if (ingestSlice.length > 0) {
      const entries = ingestSlice.map((record) => buildImportEntry({
        ...record,
        __session_id: sessionId,
      }));
      try {
        const raw = importHttpTraffic({
          target_domain: targetDomain,
          source: "browser_capture",
          source_meta: { kind: "browser_capture", session_id: sessionId },
          entries,
        });
        importEnvelope = typeof raw === "string" ? JSON.parse(raw) : raw;
        if (importEnvelope && typeof importEnvelope === "object") {
          importSummary = {
            imported: importEnvelope.imported || 0,
            duplicates: importEnvelope.duplicates || 0,
            rejected: importEnvelope.rejected || 0,
            traffic_path: importEnvelope.traffic_path || null,
          };
        }
      } catch (err) {
        // Ingestion failure surfaces structured but does not lose the buffer
        // contents — the caller still receives the raw records and can retry.
        importSummary = {
          imported: 0,
          duplicates: 0,
          rejected: 0,
          error: err && err.message ? err.message : String(err),
        };
      }
    }

    return envelopeSuccess({
      session_id: sessionId,
      target_domain: targetDomain,
      flushed_count: buffered.length,
      ingested_count: importSummary.imported || 0,
      duplicates: importSummary.duplicates || 0,
      rejected: importSummary.rejected || 0,
      overflow_count: overflow > 0 ? overflow : 0,
      traffic_path: importSummary.traffic_path || null,
      recorded: buffered,
    });
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_flush_recorded_requests",
  description:
    "Drain the record_mode buffer for a Patchright session and pipe the captured HTTP(S) requests through the same import path used by bob_import_http_traffic. Returns the buffer and ingestion summary; on success the records land in traffic.jsonl with source: \"browser_capture\" and source_meta.session_id set to this session. Subsequent calls return the records captured since the previous flush; the second call in a row returns an empty buffer until more traffic accumulates. Only http(s) requests are captured — data:, blob:, chrome-extension:, and ws:// schemes are excluded by the driver.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string", description: "Session anchor; must match the session's target_domain." },
      session_id: { type: "string", description: "session_id from bob_browser_session_start_recording." },
    },
    required: ["target_domain", "session_id"],
  },
  handler,
  role_bundles: BROWSER_BUNDLES,
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: true,
  scope_required: true,
  sensitive_output: false,
  session_artifacts_written: ["traffic.jsonl"],
});
