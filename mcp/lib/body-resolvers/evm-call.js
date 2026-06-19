"use strict";

// Plane X Cycle X.7 — body resolver for the `evm_call` X-D12 prefix.
//
// Reads from `evm-calls.jsonl` (the per-session EVM call record store)
// and returns the record whose `call_id` equals `refId`. Returns null
// when the store does not exist OR no record matches.
//
// The store path is reserved in this cycle so the X-D12 closed prefix
// set has a registered resolver from day one. A future cycle wires
// `bob_evm_call` into the store; until then the resolver gracefully
// returns null for every lookup, which keeps the X.4 satisfiability
// gate honest (a Contract referencing `evm_call:foo` is structurally
// satisfiable but mechanically unresolvable at verify-time, surfacing
// `missing_artifact` in the X.6 failure payload exactly the same way a
// stale http_record ref would).

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  sessionDir,
} = require("../paths.js");

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function evmCallsJsonlPath(targetDomain) {
  return path.join(sessionDir(targetDomain), "evm-calls.jsonl");
}

function resolve(targetDomain, refId) {
  const filePath = evmCallsJsonlPath(targetDomain);
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
    if (parsed && parsed.call_id === refId) {
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
module.exports.evmCallsJsonlPath = evmCallsJsonlPath;
