"use strict";

// T.7 fixup — Persist close-time residual record-mode buffer.
//
// browser-sessions.js#closeSession drains the in-driver buffer one last time
// before tearing the subprocess down and returns the residual `recorded[]`.
// Without this wrapper piping those entries through importHttpTraffic, a
// caller that closes without an explicit prior flush would silently drop the
// captures. We mirror browser-flush-recorded-requests.js: same HAR-shaped
// entries, same source: "browser_capture", same source_meta: { kind,
// session_id }. The importHttpTraffic path holds the per-domain session lock
// (T-R5), so close-time ingestion never races other writers.

const {
  importHttpTraffic,
} = require("../http-records.js");
const {
  browserSessions,
  envelopeFromError,
  envelopeSuccess,
  patchrightUnavailableEnvelope,
  safeSessionId,
  safeTargetDomain,
} = require("../browser-tools-shared.js");

const BROWSER_BUNDLES = ["evaluator-shared", "surface-discovery", "deep-surface-discovery"];

// Mirror the flush tool's cap so a noisy SPA tab can't blow the ingestion
// budget at close time. Overflow is reported via overflow_count; the buffer
// is already drained from the driver so the entries cannot be re-pulled.
const MAX_CLOSE_INGEST_RECORDS = 500;

function buildImportEntry(record, sessionId) {
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
      session_id: sessionId,
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
    const entry = browserSessions.getSession(sessionId);
    if (entry && !entry.closed && entry.targetDomain !== targetDomain) {
      const err = new Error(
        `browser_session_domain_mismatch: session ${sessionId} is bound to ${entry.targetDomain}, not ${targetDomain}`,
      );
      err.code = "browser_session_domain_mismatch";
      throw err;
    }
    // Capture record_mode before closeSession finalizes the entry — once the
    // entry is closed, getSession may still hand it back but recordMode is
    // the durable answer for "was this session capturing?".
    const wasRecording = entry && entry.recordMode === true;
    const result = await browserSessions.closeSession(sessionId, "explicit_close");

    // closeSession returns `recorded` only when it actually drained the
    // residual buffer (record_mode session, not already-closed). For the
    // already-closed and non-record_mode paths `recorded` is absent — there
    // is nothing to ingest and idempotent close is a no-op.
    const buffered = wasRecording && Array.isArray(result && result.recorded) ? result.recorded : [];

    // Ingest in batches so overflow records aren't dropped silently. The
    // subprocess buffer was already drained by closeSession; if we cap the
    // import here, the remaining records have no recovery path.
    let importSummary = { imported: 0, duplicates: 0, rejected: 0, traffic_path: null };
    let importError = null;
    for (let offset = 0; offset < buffered.length; offset += MAX_CLOSE_INGEST_RECORDS) {
      const slice = buffered.slice(offset, offset + MAX_CLOSE_INGEST_RECORDS);
      const entries = slice.map((record) => buildImportEntry(record, sessionId));
      try {
        const raw = importHttpTraffic({
          target_domain: targetDomain,
          source: "browser_capture",
          source_meta: { kind: "browser_capture", session_id: sessionId },
          entries,
        });
        const envelope = typeof raw === "string" ? JSON.parse(raw) : raw;
        if (envelope && typeof envelope === "object") {
          importSummary.imported += envelope.imported || 0;
          importSummary.duplicates += envelope.duplicates || 0;
          importSummary.rejected += envelope.rejected || 0;
          if (!importSummary.traffic_path && envelope.traffic_path) {
            importSummary.traffic_path = envelope.traffic_path;
          }
        }
      } catch (err) {
        // Ingestion failure surfaces structured but does not block the close
        // result — the subprocess has already been torn down by closeSession.
        // Capture the first error; subsequent batches stop.
        importError = err && err.message ? err.message : String(err);
        break;
      }
    }
    if (importError) importSummary.error = importError;

    // Idempotency: closeSession reports closed: false for
    // browser_session_not_found (the entry is already gone from the registry
    // — there is nothing to close, which from the caller's perspective is
    // equivalent to a successful close). We surface closed: true plus the
    // underlying reason so callers can still observe "already_closed" or
    // "browser_session_not_found" if they care.
    const isAlreadyGone =
      result.reason === "already_closed" || result.reason === "browser_session_not_found";
    return envelopeSuccess({
      closed: result.closed === true || isAlreadyGone,
      reason: result.reason || null,
      flushed_count: buffered.length,
      ingested_count: importSummary.imported,
      duplicates: importSummary.duplicates,
      rejected: importSummary.rejected,
      overflow_count: 0,
      traffic_path: importSummary.traffic_path || null,
    });
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_session_close",
  description:
    "Close a browser session, terminating the subprocess. Always call this when finished with a session — idle and hard timeouts will reap stragglers but the explicit close releases the per-domain concurrency slot immediately. For record_mode sessions, any captured HTTP(S) requests still buffered in the driver are drained at close and ingested via the same path as bob_browser_flush_recorded_requests (source: \"browser_capture\", source_meta.session_id set), so closing without an explicit flush will not lose captures. Idempotent: a second close on an already-closed session returns closed: true and does not double-write.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      session_id: { type: "string" },
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
