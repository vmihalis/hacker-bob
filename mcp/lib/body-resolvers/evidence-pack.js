"use strict";

// Plane X Cycle X.7 — body resolver for the `evidence_pack` X-D12 prefix.
//
// Reads from `evidence-packs.json` and returns the evidence pack whose
// pack_id / finding_id / pack_hash matches `refId`. The match order
// is: pack_id → finding_id → pack_hash. Returns null when no pack
// matches under any of the three identifiers.
//
// evidence-packs.json is a single-document store (not append-only) so
// the resolver reads the file once and walks the `packs[]` array
// matching every shape. The returned body is the matched pack object as
// canonical JSON.

const fs = require("fs");
const crypto = require("crypto");
const {
  evidencePackPaths,
} = require("../paths.js");

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function matchPack(pack, refId) {
  if (pack == null || typeof pack !== "object") return false;
  if (typeof pack.pack_id === "string" && pack.pack_id === refId) return true;
  if (typeof pack.finding_id === "string" && pack.finding_id === refId) return true;
  if (typeof pack.pack_hash === "string" && pack.pack_hash === refId) return true;
  return false;
}

function resolve(targetDomain, refId) {
  const paths = evidencePackPaths(targetDomain);
  const filePath = paths.json;
  if (!fs.existsSync(filePath)) return null;
  const content = fs.readFileSync(filePath, "utf8");
  if (!content.trim()) return null;
  let document;
  try {
    document = JSON.parse(content);
  } catch {
    return null;
  }
  if (!document || typeof document !== "object") return null;
  const packs = Array.isArray(document.packs) ? document.packs : [];
  for (const pack of packs) {
    if (matchPack(pack, refId)) {
      const body = JSON.stringify(pack, null, 2);
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
