"use strict";

// Plane X Cycle X.7 — body resolver for the `finding` X-D12 prefix.
//
// Reads from `claims.jsonl` and returns the claim record whose
// `finding_id` equals `refId`. Returns null when no finding matches.
//
// Findings are append-only and updated by emitting new rows; the
// resolver returns the MOST RECENT row matching the finding_id so a
// verifier comparing a finding's current state sees the latest version
// (matching the claim-projection reducer behavior).

const fs = require("fs");
const crypto = require("crypto");
const {
  claimsJsonlPath,
} = require("../paths.js");

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function resolve(targetDomain, refId) {
  const filePath = claimsJsonlPath(targetDomain);
  if (!fs.existsSync(filePath)) return null;
  const content = fs.readFileSync(filePath, "utf8");
  if (!content.trim()) return null;
  const lines = content.split("\n");
  let latest = null;
  for (const line of lines) {
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    if (parsed && parsed.finding_id === refId) {
      latest = parsed;
    }
  }
  if (latest == null) return null;
  const body = JSON.stringify(latest, null, 2);
  return {
    body,
    content_hash: sha256Hex(body),
    body_size_bytes: Buffer.byteLength(body, "utf8"),
  };
}

module.exports = resolve;
