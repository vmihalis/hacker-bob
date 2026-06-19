"use strict";

// Plane X Cycle X.7 — body resolver for the `repo_check` X-D12 prefix.
//
// Reads from `repo-checks.jsonl` (O.5) and returns the full row whose
// `check_id` equals `refId`. Returns null when no row matches.
//
// The body carries the full matched_lines[] array plus file_hash and
// metadata. matched_lines[].excerpt is already redacted at write-time
// per O-P7 so the resolver returns the persisted form directly without
// re-redaction.

const fs = require("fs");
const crypto = require("crypto");
const {
  repoChecksJsonlPath,
} = require("../paths.js");

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function resolve(targetDomain, refId) {
  const filePath = repoChecksJsonlPath(targetDomain);
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
    if (parsed && parsed.check_id === refId) {
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
