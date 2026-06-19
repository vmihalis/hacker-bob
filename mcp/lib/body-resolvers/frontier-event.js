"use strict";

// Plane X Cycle X.7 — body resolver for the `frontier_event` X-D12 prefix.
//
// Reads from `frontier-events.jsonl` and returns the full event object
// matching `event_id == refId`. Returns null when no event matches.
//
// The body is the canonical JSON of the matched event (pretty-printed
// for evaluator legibility) so the X.8 brief renderer / X.6 verifier can
// pass the body directly into JSONPath extraction without re-parsing.

const fs = require("fs");
const crypto = require("crypto");
const {
  frontierEventsJsonlPath,
} = require("../paths.js");

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function resolve(targetDomain, refId) {
  const filePath = frontierEventsJsonlPath(targetDomain);
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
    if (parsed && parsed.event_id === refId) {
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
