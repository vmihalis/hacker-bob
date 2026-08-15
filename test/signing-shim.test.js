"use strict";

// The single signing seam every verdict-ledger producer signs through.
// Asserts:
//   * signRowViaIsolatedSignerOrLocal mints a MAC the public-key verifier accepts
//     (the legitimate signer is in-process — on the same-uid box this IS the local
//     degrade path, which still produces a valid signature so in-flight sessions
//     never stall);
//   * it backfills the keypair for a session that has only the symmetric key;
//   * it honors the macField option (claim-freeze uses freeze_mac);
//   * it covers BOTH signing surfaces behind one boundary: after a sign the
//     ed25519 private key AND the symmetric handoff-provenance key are both present
//     under the session dir (the custody boundary relocates the whole tree, so
//     hiding one key without the other is not the seam's job — both are covered).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  signRowViaIsolatedSignerOrLocal,
  ensureHandoffSigningKey,
  readHandoffSigningPublicKey,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  verifyRowWithMac,
  OFFENSIVE_ROW_MAC_CONTEXT,
  CLAIM_FREEZE_MAC_CONTEXT,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  handoffSigningKeyPath,
  handoffSigningPrivateKeyPath,
  handoffSigningPublicKeyPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-signshim-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function seedSessionDir(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

test("signing seam mints an ed25519 MAC the public-key verifier accepts", () => {
  withTempHome(() => {
    const domain = "shim.example.com";
    seedSessionDir(domain);
    const row = { version: 1, target_domain: domain, value: "alpha" };
    signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, row);
    assert.ok(row.row_mac, "the seam assigns row_mac in place");
    assert.equal(row.row_mac.scheme, "ed25519");
    const verifier = { publicKey: readHandoffSigningPublicKey(domain).publicKey };
    assert.equal(verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, verifier), true);
  });
});

test("signing seam backfills the keypair for a symmetric-only session", () => {
  withTempHome(() => {
    const domain = "shim-backfill.example.com";
    seedSessionDir(domain);
    // A session created before keypair provisioning existed: only the symmetric key.
    ensureHandoffSigningKey(domain);
    assert.equal(fs.existsSync(handoffSigningPrivateKeyPath(domain)), false);
    const row = { version: 1, target_domain: domain, value: "beta" };
    signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, row);
    assert.equal(fs.existsSync(handoffSigningPrivateKeyPath(domain)), true);
    assert.equal(fs.existsSync(handoffSigningPublicKeyPath(domain)), true);
    const verifier = { publicKey: readHandoffSigningPublicKey(domain).publicKey };
    assert.equal(verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, verifier), true);
  });
});

test("signing seam honors the macField option (claim-freeze freeze_mac)", () => {
  withTempHome(() => {
    const domain = "shim-freeze.example.com";
    seedSessionDir(domain);
    const freeze = { version: 1, target_domain: domain, freeze_id: "F-1" };
    signRowViaIsolatedSignerOrLocal(domain, CLAIM_FREEZE_MAC_CONTEXT, freeze, { macField: "freeze_mac" });
    assert.ok(freeze.freeze_mac, "the seam assigns the carrier field named by macField");
    assert.equal(freeze.row_mac, undefined, "row_mac is not assigned when macField is freeze_mac");
    const verifier = { publicKey: readHandoffSigningPublicKey(domain).publicKey };
    assert.equal(verifyRowWithMac(CLAIM_FREEZE_MAC_CONTEXT, freeze, verifier, { macField: "freeze_mac" }), true);
  });
});

test("signing seam custodies BOTH signing secrets under the session dir", () => {
  withTempHome(() => {
    const domain = "shim-both.example.com";
    seedSessionDir(domain);
    ensureHandoffSigningKey(domain);
    const row = { version: 1, target_domain: domain, value: "gamma" };
    signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, row);
    // Both signing surfaces live behind the same boundary: the ed25519 verdict
    // key AND the symmetric handoff-provenance key are present in the session dir.
    assert.equal(fs.existsSync(handoffSigningPrivateKeyPath(domain)), true);
    assert.equal(fs.existsSync(handoffSigningKeyPath(domain)), true);
  });
});
