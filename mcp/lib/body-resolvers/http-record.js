"use strict";

// Plane X Cycle X.7 — body resolver for the `http_record` X-D12 prefix.
//
// Reads from `traffic.jsonl` and returns the full traffic record whose
// `request_id` equals `refId`. Returns null when no record matches.
//
// `request_id` is the retrofit-time identifier (see http-records.js
// `importHttpTraffic` retrofit in Cycle X.7) — a deterministic sha256
// digest of `{method, url, status, has_auth, ts}` truncated to 16 hex
// chars. Two responses with identical surface keys collapse to the same
// `request_id` (matching the existing trafficRecordKey dedup behavior).
//
// The body is the full canonical JSON of the record. Bodies-from-disk
// are pull-only; the brief renderer + the X.6 verifier resolve through
// this helper so the on-disk record is the single source of truth.

const fs = require("fs");
const crypto = require("crypto");
const {
  trafficJsonlPath,
} = require("../paths.js");

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function resolve(targetDomain, refId) {
  const filePath = trafficJsonlPath(targetDomain);
  if (!fs.existsSync(filePath)) return null;
  const content = fs.readFileSync(filePath, "utf8");
  if (!content.trim()) return null;
  const lines = content.split("\n");
  for (const line of lines) {
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    if (parsed && parsed.request_id === refId) {
      const body = JSON.stringify(parsed, null, 2);
      return {
        body,
        content_hash: sha256Hex(body),
        body_size_bytes: Buffer.byteLength(body, "utf8"),
      };
    }
  }
  return null;
}

module.exports = resolve;
