"use strict";

// Cycle B: claim-freeze.json is KEYED with a domain-separated ed25519 signature carried
// in a freeze_mac field (bob.claim-freeze.v1, the SAME signRowWithMac envelope as the
// JSONL ledgers, only the carrier field differs). The signed preimage covers the freeze
// minus freeze_mac, which INCLUDES the keyless freeze_hash — so freeze_hash is transitively
// keyed WITHOUT a read-time re-hash (the re-hash forbidden at claim-freeze.js:120-130 is
// NOT added). Real KEYING; does NOT close F3 (the private key is still 0600 at the agent
// uid, so a same-uid actor can re-sign a tampered freeze — F2 collapses INTO F3).
//
// readCurrentClaimFreeze is the chokepoint BOTH consumers (exploitRunSkipReverifies +
// reclampSeveritiesAgainstFreeze) read through. THREE-STATE (MEDIUM-A): a present-but-
// INVALID freeze_mac (tampered/forged/cross-context) now THROWS STATE_CONFLICT (a hard
// fail up the stack — a tampered freeze must never silently relax a validation); an
// ABSENT freeze_mac (legacy in-flight freeze) returns the doc-with-warning; a genuinely
// absent file, or a corrupt/torn write, returns null. The deeper hard-fail behavior +
// consumer halt is covered in claim-freeze-tamper-hardfail.test.js.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/core/claims/claim-freeze.js");
const { appendCandidateClaim } = require("../mcp/core/claims/claims.js");
const { claimFreezePath } = require("../mcp/core/io/paths.js");
const { hashDocumentExcluding } = require("../mcp/lib/fabric-common.js");
const {
  signRowWithMac,
  OFFENSIVE_ROW_MAC_CONTEXT,
  CLAIM_FREEZE_MAC_CONTEXT,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  ensureHandoffKeypair,
  readHandoffSigningPrivateKey,
} = require("../mcp/core/ledger-integrity/index.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-freeze-mac-keying-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedClaim(domain, findingId = "F-1") {
  appendCandidateClaim({
    target_domain: domain,
    title: "Fixture finding",
    summary: "Fixture summary.",
    severity: "medium",
    status: "candidate",
    evidence_refs: [{ kind: "finding", finding_id: findingId, content_hash: "0".repeat(64) }],
    impact: "Fixture impact.",
  });
}

function writeRaw(domain, doc) {
  fs.writeFileSync(claimFreezePath(domain), `${JSON.stringify(doc, null, 2)}\n`);
}

test("(a) buildClaimFreeze({write:true}) writes a valid freeze_mac and reads back", () => withTempHome(() => {
  const domain = "freeze-keying-genuine.example.com";
  seedClaim(domain);
  const built = buildClaimFreeze(domain, { write: true, now: new Date("2026-06-01T00:00:00.000Z") });
  assert.ok(built.freeze_mac, "written freeze carries freeze_mac");
  assert.equal(built.freeze_mac.scheme, "ed25519");
  // freeze_hash is still minted (no read-time re-hash) and now transitively keyed.
  assert.match(built.freeze_hash, /^[0-9a-f]+$/);

  const read = readCurrentClaimFreeze(domain);
  assert.ok(read, "valid freeze reads back");
  assert.ok(Array.isArray(read.claims));
  assert.ok(read.freeze_mac, "read-back doc carries freeze_mac");
}));

test("(b) a present-but-INVALID freeze_mac HARD-FAILS (STATE_CONFLICT, never silent null)", () => withTempHome(() => {
  const domain = "freeze-keying-tamper.example.com";
  seedClaim(domain);
  const built = buildClaimFreeze(domain, { write: true, now: new Date("2026-06-01T00:00:00.000Z") });
  // Tamper a covered field on disk but KEEP the now-stale freeze_mac.
  const tampered = { ...built, claim_count: built.claim_count + 5 };
  writeRaw(domain, tampered);
  // MEDIUM-A: a tampered (present-but-invalid) freeze_mac now THROWS rather than returning
  // null — a tampered freeze must never silently relax the consumers (reclamp/gate).
  assert.throws(
    () => readCurrentClaimFreeze(domain),
    (err) => { assert.equal(err.code, "STATE_CONFLICT"); return true; },
    "tampered signed freeze => STATE_CONFLICT (hard fail, not silent null)",
  );
}));

test("(c) a recompute-freeze_hash-without-key attack HARD-FAILS freeze_mac (keying defeats the F2 forge)", () => withTempHome(() => {
  const domain = "freeze-keying-content-forge.example.com";
  seedClaim(domain);
  const built = buildClaimFreeze(domain, { write: true, now: new Date("2026-06-01T00:00:00.000Z") });
  // The old F2 forge: mutate the frozen claims, then RECOMPUTE the keyless freeze_hash so
  // a read-time re-hash check would pass. With keying, the stale freeze_mac no longer
  // covers the new content -> present-but-invalid mac -> hard fail (MEDIUM-A).
  const forged = { ...built };
  forged.claims = [{ claim_id: "C-INJECTED", note: "attacker content" }];
  forged.claim_count = 1;
  forged.freeze_hash = hashDocumentExcluding(forged, ["frozen_at", "freeze_hash"]); // recomputed, keyless
  writeRaw(domain, forged);
  assert.throws(
    () => readCurrentClaimFreeze(domain),
    (err) => { assert.equal(err.code, "STATE_CONFLICT"); return true; },
    "recomputed-freeze_hash forge still fails freeze_mac (hard fail)",
  );
}));

test("(d) an OLD unsigned legacy freeze is accepted-with-warning (doc returned)", () => withTempHome(() => {
  const domain = "freeze-keying-legacy.example.com";
  seedClaim(domain);
  const built = buildClaimFreeze(domain, { write: true, now: new Date("2026-06-01T00:00:00.000Z") });
  // An in-flight pre-Cycle-B freeze has no freeze_mac. Drop it and re-write the (still
  // freeze_hash-consistent) doc raw.
  const legacy = { ...built };
  delete legacy.freeze_mac;
  writeRaw(domain, legacy);
  const read = readCurrentClaimFreeze(domain);
  assert.ok(read, "unsigned legacy freeze is accepted-with-warning (still readable)");
  assert.equal(read.freeze_mac, undefined, "legacy freeze has no freeze_mac");
  assert.ok(Array.isArray(read.claims));
}));

test("(f) a CORRUPT/unparseable freeze file returns null (fail-closed wrap), never throws", () => withTempHome(() => {
  const domain = "freeze-keying-corrupt.example.com";
  seedClaim(domain);
  // A freeze file that is not valid JSON. readJsonFile throws on it; the read must be
  // wrapped fail-closed so the two consumers (exploitRunSkipReverifies +
  // reclampSeveritiesAgainstFreeze) see null, matching the absent-file and invalid-mac
  // two-state contract — NOT an uncaught throw past them.
  fs.writeFileSync(claimFreezePath(domain), "{ this is not valid json :::");
  let result;
  assert.doesNotThrow(() => { result = readCurrentClaimFreeze(domain); },
    "a corrupt freeze must fail closed to null, never throw");
  assert.equal(result, null, "corrupt/unparseable freeze => null");
}));

test("(e) cross-ledger replay: an OFFENSIVE-context mac written as freeze_mac fails", () => withTempHome(() => {
  const domain = "freeze-keying-crossledger.example.com";
  seedClaim(domain);
  const built = buildClaimFreeze(domain, { write: true, now: new Date("2026-06-01T00:00:00.000Z") });
  // Strip the genuine freeze_mac, then sign the freeze under the OFFENSIVE context but
  // store it in the freeze_mac field. A real signature, wrong domain -> rejected under
  // bob.claim-freeze.v1.
  const replayed = { ...built };
  delete replayed.freeze_mac;
  ensureHandoffKeypair(domain);
  signRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, replayed, readHandoffSigningPrivateKey(domain), { macField: "freeze_mac" });
  writeRaw(domain, replayed);
  // A present-but-cross-context freeze_mac is a present-but-invalid mac under
  // bob.claim-freeze.v1 -> hard fail (MEDIUM-A), not a silent null.
  assert.throws(
    () => readCurrentClaimFreeze(domain),
    (err) => { assert.equal(err.code, "STATE_CONFLICT"); return true; },
    "an offensive-context mac as freeze_mac fails domain separation (hard fail)",
  );

  // Sanity: the same bytes DO verify under the offensive context (proving the signature is
  // real, only the domain separation rejects it as a claim-freeze mac).
  const reread = JSON.parse(fs.readFileSync(claimFreezePath(domain), "utf8"));
  const { verifyRowWithMac } = require("../mcp/core/ledger-integrity/index.js");
  const { readHandoffSigningPublicKey } = require("../mcp/core/ledger-integrity/index.js");
  const publicKey = readHandoffSigningPublicKey(domain).publicKey;
  assert.equal(verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, reread, { publicKey }, { macField: "freeze_mac" }), true);
  assert.equal(verifyRowWithMac(CLAIM_FREEZE_MAC_CONTEXT, reread, { publicKey }, { macField: "freeze_mac" }), false);
}));
