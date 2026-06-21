"use strict";

// X8 — Live in-run observability tail reader.
//
// Folds the two append-only session ledgers — frontier-events.jsonl
// (frontierEventsJsonlPath) and pipeline-events.jsonl (pipelineEventsJsonlPath)
// — into one timestamp-ordered frame stream that the dashboard's SSE route
// (GET /api/session/:domain/events) flushes to the operator's browser.
//
// Doctrine:
//  * READ-ONLY (S2): never writes session state.
//  * TOLERANT: unlike readJsonlStrict (fabric-common.js), a malformed or
//    partial trailing line is SKIPPED, never thrown — the route tails files
//    being concurrently appended to.
//  * NO LEAK (S1/S7): frontier payloads are surfaced through a strict KEY
//    ALLOWLIST (structural/enum/numeric keys only) — type-filtering alone is
//    insufficient because a scalar string field could carry a secret. Every
//    surfaced string is additionally run through the repo redactor and control
//    chars are stripped, and each frame's data is hard-capped (MAX_FRAME_BYTES,
//    measured in BYTES).
//
// Frame id = `${ts}|${source}|${recordId}` (control-char-sanitized) and doubles
// as the SSE `id:` line, so a reconnecting browser's Last-Event-ID resumes by
// ORDERING KEY (ts, source_rank, recordId) — never by line count, which would
// break under the front-trimming both ledgers do at their max-records cap.
// Records with an unparseable timestamp are rejected (they would otherwise sort
// to the epoch and collide), and duplicate record ids within a read are
// disambiguated so two same-content events are never silently deduped.

const fs = require("fs");
const {
  assertSafeDomain,
  frontierEventsJsonlPath,
  pipelineEventsJsonlPath,
} = require("./paths.js");
const { hashCanonicalJson } = require("./verification-contracts.js");
const { redactTextSensitiveValues, SENSITIVE_VALUE_RE } = require("./sensitive-material.js");
const {
  normalizePipelineEventForRead,
  timestampMs,
} = require("./pipeline-events.js");

// Per-frame `data:` payload cap (REVIEW context-budget: 2 KB, BYTE-measured).
const MAX_FRAME_BYTES = 2048;
// Bound how much of a ledger we read into memory — beyond this we tail-read the
// last MAX_LEDGER_READ_BYTES, so a large/runaway ledger cannot OOM the process.
const MAX_LEDGER_READ_BYTES = 8 * 1024 * 1024;
// Lower rank sorts first when two frames share a timestamp.
const SOURCE_RANK = Object.freeze({ frontier: 0, pipeline: 1 });

// Structural / enum / numeric payload keys safe to surface on the live wire.
// A strict allowlist (not a type filter) so a freeform scalar field — which
// could carry a token/secret — never reaches the unauthenticated stream.
const FRONTIER_PAYLOAD_KEY_ALLOWLIST = new Set([
  "surface_type", "chain_family", "method", "framework", "status",
  "severity", "decision", "outcome", "verdict", "kind", "state",
  "from_state", "to_state", "node_kind", "count", "total", "score",
]);

// Drop ASCII control chars (code < 32) and DEL (127) so a crafted ledger value
// cannot inject SSE fields (CR/LF) when used in a frame id, and so no control
// bytes reach the wire. Printable characters are preserved exactly.
function stripControlChars(value) {
  let out = "";
  for (const ch of String(value)) {
    const code = ch.codePointAt(0);
    if (code >= 32 && code !== 127) out += ch;
  }
  return out;
}

// redactTextSensitiveValues (mcp/redaction.js) masks URL / Authorization / secret-
// assignment FORMS, but NOT bare standalone tokens (AKIA…, ghp_…, eyJ… JWTs, PEM
// keys). sensitive-material's SENSITIVE_VALUE_RE — the canonical write-time secret
// definition — does. The two ledgers validate only a couple of freeform fields at
// write time, so a bare token in e.g. pipeline `status`/`source` could otherwise
// reach the unauthenticated wire. Apply the canonical patterns on the read path too.
const BARE_SECRET_RES = SENSITIVE_VALUE_RE.map(
  (re) => new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`),
);
function maskBareSecrets(text) {
  let out = text;
  for (const re of BARE_SECRET_RES) out = out.replace(re, "REDACTED");
  return out;
}

// Run BOTH redactors: the form-based repo redactor and the bare-token secret
// patterns. Used by every surfaced string.
function scrub(value) {
  return maskBareSecrets(redactTextSensitiveValues(stripControlChars(value == null ? "" : value)));
}

// Sanitize a value for the SSE `id:` line / Last-Event-ID cursor: strip control
// chars (SSE field-injection guard) AND scrub secrets. An operator-supplied
// explicit frontier event_id is embedded verbatim here (bob_append_frontier_event
// accepts explicit ids), so a secret-shaped id must be masked too (S1/S7). Scrub is
// deterministic, so the cursor still round-trips for Last-Event-ID resume.
function sanitizeIdComponent(value) {
  return scrub(value).slice(0, 256);
}

// Surface a string safely: strip control chars, scrub secret forms AND bare
// tokens, cap length.
function safeStr(value, max = 200) {
  return scrub(value).slice(0, max);
}

// Tolerant JSONL read: skip blank/partial/corrupt lines instead of throwing.
// A genuine IO error other than ENOENT (e.g. EACCES) is surfaced; a missing
// ledger is simply an empty stream.
function readJsonlTolerant(filePath, maxBytes = MAX_LEDGER_READ_BYTES) {
  // Reject non-regular files BEFORE opening: a symlink would let the unauthenticated
  // tail read outside the session root, and a FIFO would block the event loop on
  // open. lstat does not follow the symlink; a missing ledger is just an empty stream.
  let link;
  try {
    link = fs.lstatSync(filePath);
  } catch (error) {
    if (error && error.code === "ENOENT") return [];
    throw error;
  }
  if (!link.isFile()) return [];
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
  } catch (error) {
    if (error && error.code === "ENOENT") return [];
    throw error;
  }
  try {
    const stat = fs.fstatSync(fd);
    // TOCTOU guard: the opened fd must still be a regular file (not swapped post-lstat)
    if (!stat.isFile()) return [];
    const size = stat.size;
    const length = size > maxBytes ? maxBytes : size;
    const start = size > maxBytes ? size - maxBytes : 0;
    let raw = "";
    if (length > 0) {
      const buffer = Buffer.allocUnsafe(length);
      const read = fs.readSync(fd, buffer, 0, length, start);
      raw = buffer.toString("utf8", 0, read);
    }
    // when we tail-read past the head, the first line is partial — drop it
    if (start > 0) {
      const newline = raw.indexOf("\n");
      raw = newline >= 0 ? raw.slice(newline + 1) : "";
    }
    const records = [];
    for (const line of raw.split(/\r?\n/)) {
      const text = line.trim();
      if (!text) continue;
      try {
        records.push(JSON.parse(text));
      } catch {
        // partial trailing line or corrupt row — skip
      }
    }
    return records;
  } finally {
    fs.closeSync(fd);
  }
}

// Frontier events are structured + append-time validated; surface an
// allowlisted, redacted projection so no raw/freeform content can leak.
function compactFrontierEvent(record) {
  const out = {};
  for (const key of [
    "event_id", "ts", "kind", "surface_id", "frontier_item_id",
    "task_id", "claim_id", "actor", "event_hash",
  ]) {
    if (typeof record[key] === "string" && record[key]) out[key] = safeStr(record[key], 256);
  }
  if (Array.isArray(record.tags)) {
    const tags = record.tags
      .filter((tag) => typeof tag === "string")
      .slice(0, 12)
      .map((tag) => safeStr(tag, 64));
    if (tags.length) out.tags = tags;
  }
  if (record.payload && typeof record.payload === "object" && !Array.isArray(record.payload)) {
    const payload = {};
    for (const [key, value] of Object.entries(record.payload)) {
      if (!FRONTIER_PAYLOAD_KEY_ALLOWLIST.has(key)) continue;
      if (typeof value === "string") payload[key] = safeStr(value, 200);
      else if (typeof value === "number" || typeof value === "boolean") payload[key] = value;
    }
    if (Object.keys(payload).length) out.payload = payload;
  }
  return out;
}

// Redact a value of any shape: every string at any depth goes through the repo
// redactor, and nested object KEYS too (e.g. a `counts{}` sub-object whose labels
// are freeform) — the module contract (header) is that NO string reaches the wire
// unredacted, and a shallow pass would let nested keys/values through verbatim.
// Numbers / booleans / null pass through unchanged.
function redactDeepValue(value) {
  if (typeof value === "string") return safeStr(value, 1000);
  if (Array.isArray(value)) return value.map(redactDeepValue);
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, nested] of Object.entries(value)) {
      out[safeStr(key, 200)] = redactDeepValue(nested);
    }
    return out;
  }
  return value;
}

// Pipeline events are surfaced via normalizePipelineEventForRead, which caps but
// does not redact freeform fields (status / source / *_reason / counts labels) —
// deeply redact on the read path (S1/S7), matching the frontier treatment. Top-level
// keys are the structural event schema and are preserved; their values are redacted.
function redactPipelineEvent(event) {
  const out = {};
  for (const [key, value] of Object.entries(event)) {
    out[key] = redactDeepValue(value);
  }
  return out;
}

// Hard-cap a frame's serialized event by BYTE length AND fail-safe-screen it for
// any residual secret shape (defense in depth beyond the per-field scrub — catches
// anything a non-string/overlooked path slipped through). On either, collapse to a
// minimal, id-preserving, flagged stub; the stub fields (event_id already scrubbed,
// ts, enum kind/type) carry no secret. SENSITIVE_VALUE_RE (non-global) is used for
// the membership test to avoid the stateful-lastIndex footgun of the global copies.
function enforceFrameBudget(event, source) {
  let data;
  try {
    data = JSON.stringify(event);
  } catch {
    data = "";
  }
  const oversized = !data || Buffer.byteLength(data, "utf8") > MAX_FRAME_BYTES;
  const secretShape = data ? SENSITIVE_VALUE_RE.some((re) => re.test(data)) : false;
  if (!oversized && !secretShape) return event;
  const minimal = { event_id: event.event_id, ts: event.ts };
  if (oversized) minimal._truncated = true;
  if (secretShape) minimal._redacted = true;
  if (source === "frontier" && typeof event.kind === "string") minimal.kind = event.kind;
  if (source === "pipeline" && typeof event.type === "string") minimal.type = event.type;
  return minimal;
}

function buildFrames(domain, source, records) {
  const frames = [];
  const idCounts = new Map();
  for (const record of records) {
    if (!record || typeof record !== "object" || Array.isArray(record)) continue;
    let event;
    let baseRecordId;
    let ts;
    if (source === "frontier") {
      // domain affinity: the pipeline path rejects cross-domain rows
      // (normalizePipelineEventForRead); mirror it here as defense-in-depth against
      // a corrupt/mis-routed row in the per-domain frontier ledger. Absent → allow.
      if (typeof record.target_domain === "string" && record.target_domain && record.target_domain !== domain) continue;
      event = compactFrontierEvent(record);
      ts = typeof record.ts === "string" ? record.ts : null;
      baseRecordId = typeof record.event_id === "string" && record.event_id
        ? record.event_id
        : `FE-${hashCanonicalJson(record).slice(0, 24)}`;
    } else {
      // pipeline rows lack a per-event id and may be malformed → normalize
      // tolerantly (null on a non-conforming row) and synthesize a
      // content-addressed PE-<hash> from the normalized projection.
      const normalized = normalizePipelineEventForRead(record, domain);
      if (!normalized) continue;
      // require a valid PERSISTED ts: normalizePipelineEventForRead fills a missing
      // OR unparseable ts with now(), which re-hashes the PE-<id> on every read and
      // replays the row as a fresh event each poll. Drop such rows (matching the
      // frontier branch, which drops non-string/empty ts via the shared check below).
      if (!(typeof record.ts === "string" && record.ts.trim() && timestampMs(record.ts) > 0)) continue;
      ts = normalized.ts;
      baseRecordId = `PE-${hashCanonicalJson(normalized).slice(0, 24)}`;
      event = redactPipelineEvent(normalized);
    }
    if (typeof ts !== "string" || !ts) continue;
    const tsMs = timestampMs(ts);
    // reject unparseable timestamps before key construction (timestampMs → 0)
    if (!Number.isFinite(tsMs) || tsMs <= 0) continue;
    // disambiguate duplicate ids within this read so two same-content events are
    // not silently deduped by the poll loop's ordering-key comparison.
    let recordId = sanitizeIdComponent(baseRecordId);
    const seen = idCounts.get(recordId) || 0;
    idCounts.set(recordId, seen + 1);
    if (seen > 0) recordId = `${recordId}~${seen}`;
    event.event_id = recordId;
    frames.push({
      id: `${sanitizeIdComponent(ts)}|${source}|${recordId}`,
      source,
      ts,
      ts_ms: tsMs,
      record_id: recordId,
      event: enforceFrameBudget(event, source),
    });
  }
  return frames;
}

function frameKey(frame) {
  return {
    ts_ms: frame.ts_ms,
    source_rank: SOURCE_RANK[frame.source] == null ? 99 : SOURCE_RANK[frame.source],
    record_id: frame.record_id,
  };
}

// Total order = (ts_ms, source_rank, record_id). The record_id tiebreaker is a
// content hash, NOT append order — so two frames sharing an exact millisecond AND
// source are ordered by hash. Accepted, documented consequence: the live poll's
// high-water-mark (startSseEventStream) can skip a same-ms/same-source frame that
// is appended late but hashes lower than the last one emitted. It still appears
// on any full backlog read (fresh connect / snapshot auto-refresh), so the live
// ticker self-heals; a perfect fix needs server-side per-event sequence numbers,
// which this content-addressed, front-trim-safe cursor model deliberately avoids.
function compareFrameKeys(a, b) {
  if (a.ts_ms !== b.ts_ms) return a.ts_ms - b.ts_ms;
  if (a.source_rank !== b.source_rank) return a.source_rank - b.source_rank;
  if (a.record_id < b.record_id) return -1;
  if (a.record_id > b.record_id) return 1;
  return 0;
}

function parseCursor(lastEventId) {
  if (typeof lastEventId !== "string" || !lastEventId) return null;
  const first = lastEventId.indexOf("|");
  const second = lastEventId.indexOf("|", first + 1);
  if (first < 0 || second < 0) return null;
  const ts = lastEventId.slice(0, first);
  const source = lastEventId.slice(first + 1, second);
  const recordId = lastEventId.slice(second + 1);
  if (!ts || !source || !recordId) return null;
  return {
    ts_ms: timestampMs(ts),
    source_rank: SOURCE_RANK[source] == null ? 99 : SOURCE_RANK[source],
    record_id: recordId,
  };
}

// Read + fold both ledgers into one ascending, ordered frame list.
function readSessionEventFrames(domain, { sources = ["frontier", "pipeline"] } = {}) {
  const safe = assertSafeDomain(domain);
  const frames = [];
  if (sources.includes("frontier")) {
    frames.push(...buildFrames(safe, "frontier", readJsonlTolerant(frontierEventsJsonlPath(safe))));
  }
  if (sources.includes("pipeline")) {
    frames.push(...buildFrames(safe, "pipeline", readJsonlTolerant(pipelineEventsJsonlPath(safe))));
  }
  frames.sort((a, b) => compareFrameKeys(frameKey(a), frameKey(b)));
  return frames;
}

// Cheap change-stamp over the two ledgers (size+mtime) so the SSE poll can skip
// the O(N) read+parse+sort when nothing has been appended.
function sessionLedgerStamp(domain) {
  const safe = assertSafeDomain(domain);
  const parts = [];
  for (const filePath of [frontierEventsJsonlPath(safe), pipelineEventsJsonlPath(safe)]) {
    try {
      const stat = fs.statSync(filePath);
      parts.push(`${stat.size}:${stat.mtimeMs}`);
    } catch {
      parts.push("0:0");
    }
  }
  return parts.join("|");
}

// Resume helper: return the frames strictly after the Last-Event-ID cursor.
// `resync` is true when the cursor is gone AND its OWN source ledger has been
// front-trimmed past it (every surviving frame from that source sorts after the
// cursor). The two ledgers trim independently at their max-records cap, so the
// check must be PER-SOURCE: a peer ledger that still holds an older frame must
// not mask a real front-trim gap in the cursor's source.
function framesAfter(frames, lastEventId) {
  const cursor = parseCursor(lastEventId);
  if (!cursor) return { frames, resync: false };
  const after = frames.filter((frame) => compareFrameKeys(frameKey(frame), cursor) > 0);
  const cursorPresent = frames.some((frame) => frame.id === lastEventId);
  // [].every(...) === true handles a fully-trimmed cursor source (→ resync).
  const sourceTrimmedPastCursor = frames
    .filter((frame) => frameKey(frame).source_rank === cursor.source_rank)
    .every((frame) => compareFrameKeys(frameKey(frame), cursor) > 0);
  const resync = !cursorPresent && frames.length > 0 && sourceTrimmedPastCursor;
  return { frames: after, resync };
}

module.exports = {
  MAX_FRAME_BYTES,
  SOURCE_RANK,
  FRONTIER_PAYLOAD_KEY_ALLOWLIST,
  stripControlChars,
  readJsonlTolerant,
  compactFrontierEvent,
  enforceFrameBudget,
  readSessionEventFrames,
  sessionLedgerStamp,
  framesAfter,
  frameKey,
  compareFrameKeys,
  parseCursor,
};
