"use strict";

// X8 — Live in-run observability tail reader.
//
// Folds the two append-only session ledgers — frontier-events.jsonl
// (frontierEventsJsonlPath) and pipeline-events.jsonl (pipelineEventsJsonlPath)
// — into one timestamp-ordered frame stream that the dashboard's SSE route
// (GET /api/session/:domain/events) flushes to the operator's browser.
//
// Doctrine:
//  * READ-ONLY (S2): this module never writes session state. It only reads the
//    two ledgers; a write or lifecycle advance here would be a regression.
//  * TOLERANT: unlike readJsonlStrict (fabric-common.js), a malformed or
//    partial trailing line is SKIPPED, never thrown — the route tails files that
//    another process is concurrently appending to, so a half-written final line
//    must not 500 the stream.
//  * NO LEAK (S1/S7): frames carry only the already-sanitized, content-addressed
//    fields the two ledgers persist (ids, hashes like nucleus_hash /
//    egress_identity_hash, enums, counts) plus a primitive-only payload
//    projection. Nested objects/arrays in a frontier payload are dropped so no
//    raw artifact body or secret-bearing field can reach the stream, and each
//    frame's data is hard-capped (MAX_FRAME_BYTES).
//
// Frame id = `${ts}|${source}|${recordId}` and doubles as the SSE `id:` line, so
// a reconnecting browser's Last-Event-ID resumes by ORDERING KEY
// (ts, source_rank, recordId) — never by line count, which would break under the
// front-trimming both ledgers do at their max-records cap.

const fs = require("fs");
const {
  assertSafeDomain,
  frontierEventsJsonlPath,
  pipelineEventsJsonlPath,
} = require("./paths.js");
const { hashCanonicalJson } = require("./verification-contracts.js");
const {
  normalizePipelineEventForRead,
  timestampMs,
} = require("./pipeline-events.js");

// Per-frame `data:` payload cap (REVIEW context-budget: 2 KB, truncate-and-flag).
const MAX_FRAME_BYTES = 2048;
// Lower rank sorts first when two frames share a timestamp.
const SOURCE_RANK = Object.freeze({ frontier: 0, pipeline: 1 });

// Tolerant JSONL read: skip blank/partial/corrupt lines instead of throwing.
// A genuine IO error other than ENOENT (e.g. EACCES) is surfaced; a missing
// ledger is simply an empty stream.
function readJsonlTolerant(filePath) {
  let raw;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    if (error && error.code === "ENOENT") return [];
    throw error;
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
}

// Frontier events are structured + append-time validated; surface a primitive-only
// projection (allowlisted scalar fields + primitive payload values) so nested raw
// content can never leak through the live tail.
function compactFrontierEvent(record) {
  const out = {};
  for (const key of [
    "event_id",
    "ts",
    "kind",
    "surface_id",
    "frontier_item_id",
    "task_id",
    "claim_id",
    "actor",
    "event_hash",
  ]) {
    if (typeof record[key] === "string" && record[key]) {
      out[key] = record[key].slice(0, 256);
    }
  }
  if (Array.isArray(record.tags)) {
    const tags = record.tags
      .filter((tag) => typeof tag === "string")
      .slice(0, 12)
      .map((tag) => tag.slice(0, 64));
    if (tags.length) out.tags = tags;
  }
  if (record.payload && typeof record.payload === "object" && !Array.isArray(record.payload)) {
    const payload = {};
    for (const [key, value] of Object.entries(record.payload)) {
      if (typeof value === "string") payload[key] = value.slice(0, 200);
      else if (typeof value === "number" || typeof value === "boolean") payload[key] = value;
      // nested objects/arrays intentionally dropped (no raw-body leak)
    }
    if (Object.keys(payload).length) out.payload = payload;
  }
  return out;
}

// Hard-cap a frame's serialized event; on overflow, collapse to a minimal,
// id-preserving, flagged stub so the stream never emits an oversized data block.
function enforceFrameBudget(event, source) {
  let data;
  try {
    data = JSON.stringify(event);
  } catch {
    data = "";
  }
  if (data && data.length <= MAX_FRAME_BYTES) return event;
  const minimal = { event_id: event.event_id, ts: event.ts, _truncated: true };
  if (source === "frontier" && typeof event.kind === "string") minimal.kind = event.kind;
  if (source === "pipeline" && typeof event.type === "string") minimal.type = event.type;
  return minimal;
}

function buildFrames(domain, source, records) {
  const frames = [];
  for (const record of records) {
    if (!record || typeof record !== "object" || Array.isArray(record)) continue;
    let event;
    let recordId;
    let ts;
    if (source === "frontier") {
      event = compactFrontierEvent(record);
      ts = event.ts;
      recordId = event.event_id || `FE-${hashCanonicalJson(record).slice(0, 24)}`;
      event.event_id = recordId;
    } else {
      // pipeline rows lack a per-event id and may be malformed → normalize
      // tolerantly (returns null on a non-conforming row) and synthesize a
      // content-addressed PE-<hash> from the normalized projection.
      const normalized = normalizePipelineEventForRead(record, domain);
      if (!normalized) continue;
      event = normalized;
      ts = normalized.ts;
      recordId = `PE-${hashCanonicalJson(normalized).slice(0, 24)}`;
      event.event_id = recordId;
    }
    if (typeof ts !== "string" || !ts) continue;
    frames.push({
      id: `${ts}|${source}|${recordId}`,
      source,
      ts,
      ts_ms: timestampMs(ts),
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

// Resume helper: return the frames strictly after the Last-Event-ID cursor.
// `resync` is true when the cursor itself is no longer present AND every
// surviving frame sorts after it — i.e. the cursor (and possibly frames after
// it) were trimmed off the front, so the client must assume a gap.
function framesAfter(frames, lastEventId) {
  const cursor = parseCursor(lastEventId);
  if (!cursor) return { frames, resync: false };
  const after = frames.filter((frame) => compareFrameKeys(frameKey(frame), cursor) > 0);
  const cursorPresent = frames.some((frame) => frame.id === lastEventId);
  const resync = !cursorPresent && frames.length > 0 && after.length === frames.length;
  return { frames: after, resync };
}

module.exports = {
  MAX_FRAME_BYTES,
  SOURCE_RANK,
  readJsonlTolerant,
  compactFrontierEvent,
  readSessionEventFrames,
  framesAfter,
  frameKey,
  compareFrameKeys,
  parseCursor,
};
