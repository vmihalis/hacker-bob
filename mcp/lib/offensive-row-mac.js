"use strict";

const crypto = require("crypto");
const {
  canonicalJson,
} = require("./verification-contracts.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");

// Distinct from HANDOFF_PROVENANCE_SIGNATURE_CONTEXT (wave-handoff-contracts.js) so a
// wave-handoff signature can never be replayed as an offensive row signature even though
// both reuse the same per-session signing key.
const OFFENSIVE_ROW_MAC_CONTEXT = "hacker-bob:offensive-run:row-hmac:v1";
const OFFENSIVE_ROW_MAC_ALGORITHM = "hmac-sha256";
const OFFENSIVE_ROW_MAC_VERSION = 1;

// Sign over the WHOLE row minus the row_mac envelope, so every trusted field
// (offensive_outcome, target_domain, target, all four hashes, exit_code, dry_run,
// timed_out, run_id, tool_id, version) is bound; flipping any of them invalidates the MAC.
function offensiveRowMacPayload(row) {
  const copy = { ...row };
  delete copy.row_mac;
  return canonicalJson(copy);
}

function computeOffensiveRowMacDigest(row, signingKey) {
  if (!Buffer.isBuffer(signingKey) || signingKey.length === 0) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "offensive row signing key is required");
  }
  return crypto
    .createHmac("sha256", signingKey)
    .update(OFFENSIVE_ROW_MAC_CONTEXT)
    .update("\n")
    .update(offensiveRowMacPayload(row))
    .digest("hex");
}

// Mints row.row_mac in place and returns the row. The trusted producer (offensive runner;
// simulated by tests in this PR) is the only caller — agents cannot read the key.
function signOffensiveRunRow(row, signingKey) {
  if (row == null || typeof row !== "object" || Array.isArray(row)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "offensive run row must be an object to sign");
  }
  if (row.row_mac != null) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "offensive run row_mac must be assigned by the signer");
  }
  row.row_mac = {
    version: OFFENSIVE_ROW_MAC_VERSION,
    algorithm: OFFENSIVE_ROW_MAC_ALGORITHM,
    digest: computeOffensiveRowMacDigest(row, signingKey),
  };
  return row;
}

// Returns a boolean (never throws) so the gate can fail-fast on any malformed/forged row.
function verifyOffensiveRunRowMac(row, signingKey) {
  if (!Buffer.isBuffer(signingKey) || signingKey.length === 0) return false;
  if (row == null || typeof row !== "object") return false;
  const env = row.row_mac;
  if (env == null || typeof env !== "object" || Array.isArray(env)) return false;
  if (env.version !== OFFENSIVE_ROW_MAC_VERSION) return false;
  if (env.algorithm !== OFFENSIVE_ROW_MAC_ALGORITHM) return false;
  if (typeof env.digest !== "string" || !/^[0-9a-f]{64}$/.test(env.digest)) return false;
  let expectedHex;
  try {
    expectedHex = computeOffensiveRowMacDigest(row, signingKey);
  } catch {
    return false;
  }
  const actual = Buffer.from(env.digest, "hex");
  const expected = Buffer.from(expectedHex, "hex");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

module.exports = {
  OFFENSIVE_ROW_MAC_CONTEXT,
  OFFENSIVE_ROW_MAC_ALGORITHM,
  OFFENSIVE_ROW_MAC_VERSION,
  computeOffensiveRowMacDigest,
  signOffensiveRunRow,
  verifyOffensiveRunRowMac,
};
