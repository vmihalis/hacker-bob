"use strict";

// Cycle B domain separation: the four verdict-backing ledgers each sign under their OWN
// context string (bound into the preimage as context + "\n" + canonical(row minus mac)).
// A mac minted under one context MUST be rejected when presented under any other — so a
// row from one ledger cannot be replayed as a row for another even though all four reuse
// the same per-session signing key.
//
//   offensive-runs.jsonl     -> OFFENSIVE_ROW_MAC_CONTEXT
//   invariant-runs.jsonl     -> INVARIANT_RUN_MAC_CONTEXT
//   repo-command-runs.jsonl  -> REPO_COMMAND_RUN_MAC_CONTEXT
//   claim-freeze.json        -> CLAIM_FREEZE_MAC_CONTEXT  (carrier field freeze_mac)

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
  signRowWithMac,
  verifyRowWithMac,
  OFFENSIVE_ROW_MAC_CONTEXT,
  INVARIANT_RUN_MAC_CONTEXT,
  REPO_COMMAND_RUN_MAC_CONTEXT,
  CLAIM_FREEZE_MAC_CONTEXT,
  MAC_SCHEME_ED25519,
} = require("../mcp/core/ledger-integrity/offensive-row-mac.js");

const CONTEXTS = [
  OFFENSIVE_ROW_MAC_CONTEXT,
  INVARIANT_RUN_MAC_CONTEXT,
  REPO_COMMAND_RUN_MAC_CONTEXT,
  CLAIM_FREEZE_MAC_CONTEXT,
];

test("the four contexts are distinct strings", () => {
  assert.equal(new Set(CONTEXTS).size, 4, "all four ledger contexts must be unique");
});

test("each of the four contexts rejects a mac minted under any other context", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const verifier = { publicKey };
  // Use freeze_mac as the carrier so the claim-freeze context is exercised end-to-end
  // (the same envelope handles every context regardless of carrier field).
  const macField = "freeze_mac";

  for (const signCtx of CONTEXTS) {
    const row = {
      version: 1,
      target_domain: "x.example.com",
      run_id: "r-1",
      command_hash: "aa",
      stdout_hash: "bb",
      stderr_hash: "cc",
    };
    signRowWithMac(signCtx, row, { scheme: MAC_SCHEME_ED25519, privateKey }, { macField });
    // Round-trips under its OWN context.
    const onDisk = JSON.parse(JSON.stringify(row));
    assert.equal(
      verifyRowWithMac(signCtx, onDisk, verifier, { macField }),
      true,
      `${signCtx} must verify under its own context`,
    );
    // Rejected under every OTHER context.
    for (const verifyCtx of CONTEXTS) {
      if (verifyCtx === signCtx) continue;
      assert.equal(
        verifyRowWithMac(verifyCtx, onDisk, verifier, { macField }),
        false,
        `a ${signCtx} mac must NOT verify under ${verifyCtx} (domain separation)`,
      );
    }
  }
});
