"use strict";

// The scheme-tagged offensive-row MAC: signRowWithMac / verifyRowWithMac.
// Asserts both schemes round-trip, that ed25519 verifies with the PUBLIC key only,
// and that every forgery vector (tamper, wrong key, cross-scheme replay, context
// separation) fails closed.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
  signRowWithMac,
  verifyRowWithMac,
  assertRowMacOrLegacy,
  OFFENSIVE_ROW_MAC_CONTEXT,
  CLAIM_FREEZE_MAC_CONTEXT,
  MAC_SCHEME_HMAC,
  MAC_SCHEME_ED25519,
} = require("../mcp/core/ledger-integrity/index.js");

const CTX = OFFENSIVE_ROW_MAC_CONTEXT;

function baseRow() {
  return {
    version: 1,
    target_domain: "x.example.com",
    run_id: "run-1",
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

test("ed25519 sign -> serialize -> verify round-trips with the PUBLIC key only", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const row = baseRow();
  signRowWithMac(CTX, row, { scheme: MAC_SCHEME_ED25519, privateKey });
  assert.equal(row.row_mac.version, 2);
  assert.equal(row.row_mac.scheme, MAC_SCHEME_ED25519);
  assert.equal(typeof row.row_mac.signature, "string");
  assert.equal(row.row_mac.digest, undefined, "ed25519 envelope carries a signature, not a digest");

  // Serialize the way the ledger does, then re-parse — verify survives JSON round-trip.
  const onDisk = JSON.parse(JSON.stringify(row));
  // A verifier holding ONLY the public key (no secret) verifies the row.
  assert.equal(verifyRowWithMac(CTX, onDisk, { scheme: MAC_SCHEME_ED25519, publicKey }), true);
  // The combined bundle (public key + a throwaway symmetric key) also verifies.
  assert.equal(verifyRowWithMac(CTX, onDisk, { publicKey, hmacKey: Buffer.alloc(32, 7) }), true);
});

test("ed25519: tampering any trusted field fails verification", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const row = baseRow();
  signRowWithMac(CTX, row, { scheme: MAC_SCHEME_ED25519, privateKey });
  for (const field of ["exit_code", "target_domain", "offensive_outcome", "stdout_hash", "surface_id", "dry_run"]) {
    const tampered = { ...row };
    tampered[field] = field === "exit_code" ? 1 : (field === "dry_run" ? true : "MUTATED");
    assert.equal(verifyRowWithMac(CTX, tampered, { publicKey }), false, `tamper(${field}) must fail`);
  }
});

test("ed25519: a row signed by one session key fails under another public key", () => {
  const a = crypto.generateKeyPairSync("ed25519");
  const b = crypto.generateKeyPairSync("ed25519");
  const row = baseRow();
  signRowWithMac(CTX, row, { scheme: MAC_SCHEME_ED25519, privateKey: a.privateKey });
  assert.equal(verifyRowWithMac(CTX, row, { publicKey: a.publicKey }), true);
  assert.equal(verifyRowWithMac(CTX, row, { publicKey: b.publicKey }), false);
});

test("context separation: a row signed under the offensive context fails under a different context", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const row = baseRow();
  signRowWithMac(CTX, row, { scheme: MAC_SCHEME_ED25519, privateKey });
  assert.equal(verifyRowWithMac("hacker-bob:some-other-context:v1", row, { publicKey }), false);
});

test("hmac sign -> verify round-trips (v1 envelope) with the symmetric key", () => {
  const key = crypto.randomBytes(32);
  const row = baseRow();
  signRowWithMac(CTX, row, { scheme: MAC_SCHEME_HMAC, key });
  assert.equal(row.row_mac.version, 1);
  assert.equal(row.row_mac.algorithm, MAC_SCHEME_HMAC);
  assert.match(row.row_mac.digest, /^[0-9a-f]{64}$/);
  assert.equal(verifyRowWithMac(CTX, row, { scheme: MAC_SCHEME_HMAC, key }), true);
  assert.equal(verifyRowWithMac(CTX, row, { publicKey: null, hmacKey: key }), true);
  assert.equal(verifyRowWithMac(CTX, row, { scheme: MAC_SCHEME_HMAC, key: crypto.randomBytes(32) }), false);
});

test("cross-scheme replay is rejected", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const key = crypto.randomBytes(32);

  // An ed25519 row presented to an hmac-only verifier fails (no public key in scope).
  const edRow = baseRow();
  signRowWithMac(CTX, edRow, { scheme: MAC_SCHEME_ED25519, privateKey });
  assert.equal(verifyRowWithMac(CTX, edRow, { scheme: MAC_SCHEME_HMAC, key }), false);

  // A legacy hmac row presented to an ed25519-only verifier fails (no hmac key in scope).
  const hmacRow = baseRow();
  signRowWithMac(CTX, hmacRow, { scheme: MAC_SCHEME_HMAC, key });
  assert.equal(verifyRowWithMac(CTX, hmacRow, { scheme: MAC_SCHEME_ED25519, publicKey }), false);

  // Forging an ed25519 envelope around hmac fields (mismatched scheme/material) fails.
  const forged = { ...baseRow(), row_mac: { version: 2, scheme: MAC_SCHEME_ED25519, signature: "AAAA" } };
  assert.equal(verifyRowWithMac(CTX, forged, { publicKey }), false);
});

test("malformed envelopes fail closed", () => {
  const { publicKey } = crypto.generateKeyPairSync("ed25519");
  const key = crypto.randomBytes(32);
  const verifier = { publicKey, hmacKey: key };
  for (const env of [
    null,
    {},
    { version: 3, scheme: MAC_SCHEME_ED25519, signature: "AA" },
    { version: 2, scheme: "rsa", signature: "AA" },
    { version: 2, scheme: MAC_SCHEME_ED25519, signature: "not base64url!!" },
    { version: 1, algorithm: "hmac-sha256", digest: "zz" },
    { version: 1, algorithm: "md5", digest: "a".repeat(64) },
  ]) {
    const row = { ...baseRow(), row_mac: env };
    assert.equal(verifyRowWithMac(CTX, row, verifier), false, `env ${JSON.stringify(env)} must fail`);
  }
});

// --- Cycle B: optional macField carrier (claim-freeze.json keys freeze_mac, not row_mac) ---

const FREEZE_CTX = CLAIM_FREEZE_MAC_CONTEXT;

function freezeDoc() {
  return {
    freeze_id: "CF-aaaaaaaaaaaaaaaaaaaaaaaa",
    version: 1,
    target_domain: "x.example.com",
    frozen_at: "2026-06-01T00:00:00.000Z",
    claim_count: 1,
    cluster_count: 0,
    source_event_count: 0,
    source_hashes: { claims_hash: "h1", claim_clusters_hash: "h2", frontier_events_hash: "h3" },
    claims: [{ claim_id: "C-1" }],
    clusters: [],
    cluster_ids: [],
    freeze_hash: "f".repeat(64),
  };
}

test("macField:'freeze_mac' round-trips with ed25519 and the same envelope/preimage", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const doc = freezeDoc();
  signRowWithMac(FREEZE_CTX, doc, { scheme: MAC_SCHEME_ED25519, privateKey }, { macField: "freeze_mac" });
  // The signature is carried under freeze_mac, NOT row_mac.
  assert.equal(doc.row_mac, undefined, "freeze_mac carrier must not write row_mac");
  assert.equal(doc.freeze_mac.scheme, MAC_SCHEME_ED25519);
  const onDisk = JSON.parse(JSON.stringify(doc));
  assert.equal(verifyRowWithMac(FREEZE_CTX, onDisk, { publicKey }, { macField: "freeze_mac" }), true);
});

test("freeze_mac covers freeze_hash: tampering any covered field (incl. freeze_hash) fails", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const doc = freezeDoc();
  signRowWithMac(FREEZE_CTX, doc, { scheme: MAC_SCHEME_ED25519, privateKey }, { macField: "freeze_mac" });
  for (const field of ["freeze_id", "claim_count", "freeze_hash"]) {
    const tampered = { ...doc };
    tampered[field] = field === "claim_count" ? 99 : "MUTATED";
    assert.equal(
      verifyRowWithMac(FREEZE_CTX, tampered, { publicKey }, { macField: "freeze_mac" }),
      false,
      `tamper(${field}) under freeze_mac must fail`,
    );
  }
});

test("field non-collision: a row_mac-signed row fails a freeze_mac verify and vice versa", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  // Sign under the DEFAULT field (row_mac) but verify expecting freeze_mac -> no envelope -> false.
  const rowSigned = baseRow();
  signRowWithMac(CTX, rowSigned, { scheme: MAC_SCHEME_ED25519, privateKey });
  assert.equal(rowSigned.freeze_mac, undefined);
  assert.equal(
    verifyRowWithMac(CTX, rowSigned, { publicKey }, { macField: "freeze_mac" }),
    false,
    "a row_mac-signed row has no freeze_mac envelope",
  );
  // Sign under freeze_mac but verify expecting the default row_mac -> no envelope -> false.
  const freezeSigned = freezeDoc();
  signRowWithMac(FREEZE_CTX, freezeSigned, { scheme: MAC_SCHEME_ED25519, privateKey }, { macField: "freeze_mac" });
  assert.equal(freezeSigned.row_mac, undefined);
  assert.equal(
    verifyRowWithMac(FREEZE_CTX, freezeSigned, { publicKey }),
    false,
    "a freeze_mac-signed doc has no row_mac envelope",
  );
});

test("assertRowMacOrLegacy two-state: absent mac => {legacy:true}, present-valid => {legacy:false}, present-invalid => throw", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const verifier = { publicKey };

  // Absent mac (legacy/old in-flight row) is accepted-with-warning (no throw).
  const legacy = baseRow();
  assert.deepEqual(assertRowMacOrLegacy(CTX, legacy, verifier), { legacy: true });

  // Present + valid is {legacy:false}.
  const signed = baseRow();
  signRowWithMac(CTX, signed, { scheme: MAC_SCHEME_ED25519, privateKey });
  assert.deepEqual(assertRowMacOrLegacy(CTX, signed, verifier), { legacy: false });

  // Present + invalid (tampered after signing) hard-fails (throws).
  const tampered = { ...signed, exit_code: 999 };
  assert.throws(() => assertRowMacOrLegacy(CTX, tampered, verifier), /does not verify/);

  // Present + valid signature but a NULL verifier hard-fails (a signed row with no key
  // to verify against fails closed, never silently accepts).
  assert.throws(() => assertRowMacOrLegacy(CTX, signed, null), /does not verify/);

  // The freeze_mac carrier flows through the same helper.
  const freezeSigned = freezeDoc();
  signRowWithMac(FREEZE_CTX, freezeSigned, { scheme: MAC_SCHEME_ED25519, privateKey }, { macField: "freeze_mac" });
  assert.deepEqual(
    assertRowMacOrLegacy(FREEZE_CTX, freezeSigned, verifier, { macField: "freeze_mac" }),
    { legacy: false },
  );
  assert.deepEqual(
    assertRowMacOrLegacy(FREEZE_CTX, freezeDoc(), verifier, { macField: "freeze_mac" }),
    { legacy: true },
  );
});
