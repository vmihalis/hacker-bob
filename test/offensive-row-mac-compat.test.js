"use strict";

// CONSTRAINT 7 — backward compatibility. Two legacy corpora must keep verifying
// after the scheme-tagged envelope split:
//   (1) old offensive-runs.jsonl rows are {version:1, algorithm:"hmac-sha256", digest}
//       symmetric-HMAC rows — they must verify with the still-present symmetric key,
//       byte-identical to before (no re-sign, no migration);
//   (2) the retained compat facades (signOffensiveRunRow / verifyOffensiveRunRowMac)
//       must keep producing and accepting v1-verifiable rows so the 27 test files and
//       any in-flight producer keep working.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const { canonicalJson } = require("../mcp/lib/verification-contracts.js");
const {
  signRowWithMac,
  verifyRowWithMac,
  signOffensiveRunRow,
  verifyOffensiveRunRowMac,
  OFFENSIVE_ROW_MAC_CONTEXT,
  MAC_SCHEME_ED25519,
} = require("../mcp/lib/offensive-row-mac.js");

const CTX = OFFENSIVE_ROW_MAC_CONTEXT;

function baseRow() {
  return {
    version: 1,
    target_domain: "x.example.com",
    run_id: "run-legacy",
    tool_id: "bob_http_idor_confirm",
    target: "https://x.example.com/a",
    offensive_outcome: "exploited_safely",
    dry_run: false,
    timed_out: false,
    command_hash: "aa",
    exit_code: 0,
    stdout_hash: "bb",
    stderr_hash: "cc",
    demonstrated_severity: "high",
    surface_id: "s1",
  };
}

// Construct a legacy row EXACTLY as the pre-split code would have — independent of the
// helpers under test — so a true byte-for-byte on-disk legacy row is exercised.
function handBuiltLegacyRow(key) {
  const row = baseRow();
  const copy = { ...row };
  delete copy.row_mac;
  const payload = canonicalJson(copy);
  const digest = crypto.createHmac("sha256", key).update(CTX).update("\n").update(payload).digest("hex");
  row.row_mac = { version: 1, algorithm: "hmac-sha256", digest };
  return row;
}

test("a hand-built legacy v1 hmac row (as written before the split) still verifies", () => {
  const key = crypto.randomBytes(32);
  const row = handBuiltLegacyRow(key);
  // The new core verifier (bundle dispatch) accepts the legacy row.
  assert.equal(verifyRowWithMac(CTX, row, { publicKey: null, hmacKey: key }), true);
  // The retained facade accepts it too.
  assert.equal(verifyOffensiveRunRowMac(row, key), true);
  // A wrong symmetric key still fails.
  assert.equal(verifyOffensiveRunRowMac(row, crypto.randomBytes(32)), false);
});

test("signOffensiveRunRow facade still mints a v1-verifiable row", () => {
  const key = crypto.randomBytes(32);
  const row = baseRow();
  signOffensiveRunRow(row, key);
  assert.equal(row.row_mac.version, 1);
  assert.equal(row.row_mac.algorithm, "hmac-sha256");
  assert.equal(verifyOffensiveRunRowMac(row, key), true);
  // The facade-minted row is byte-identical to the hand-built legacy digest.
  assert.equal(row.row_mac.digest, handBuiltLegacyRow(key).row_mac.digest);
});

test("a v2 ed25519 row verifies with the public key only and FAILS with a symmetric/wrong key", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const key = crypto.randomBytes(32);
  const row = baseRow();
  signRowWithMac(CTX, row, { scheme: MAC_SCHEME_ED25519, privateKey });

  assert.equal(verifyRowWithMac(CTX, row, { publicKey, hmacKey: key }), true);
  // The legacy symmetric-only facade cannot verify an ed25519 row.
  assert.equal(verifyOffensiveRunRowMac(row, key), false);
  // A wrong public key fails.
  const other = crypto.generateKeyPairSync("ed25519");
  assert.equal(verifyRowWithMac(CTX, row, { publicKey: other.publicKey }), false);
});
