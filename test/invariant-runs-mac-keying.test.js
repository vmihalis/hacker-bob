"use strict";

// Cycle B: invariant-runs.jsonl rows are KEYED with a domain-separated ed25519 signature
// (bob.invariant-run.v1). Forging an invariant-run source row now requires the signing
// key, not just a recomputable content hash (computeInvariantRunHash). This is real
// KEYING, NOT a read-time re-hash. It does NOT close F3: the private key is still 0600 at
// the agent uid, so a same-uid actor can mint a valid row_mac; F2 collapses INTO F3.
//
// The two read-time re-derivation sites both verify the keyed row_mac AFTER their content-
// hash re-derivation:
//   * invariant-runner.js readInvariantRunRowForVerification (verifyInvariantDifferential
//     + reverifyInvariantVerifiedRecord),
//   * proof-bundle.js readInvariantRunRow.
// Two-state backward compat: an OLD unsigned row is accepted-with-warning (still re-
// derived); a SIGNED-then-TAMPERED row hard-fails (fail-closed exclude at read).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  computeInvariantRunHash,
  verifyInvariantDifferential,
  reverifyInvariantVerifiedRecord,
  readInvariantVerifiedSummary,
} = require("../mcp/core/invariant-runner.js");
const { invariantRunsJsonlPath } = require("../mcp/core/io/paths.js");
const {
  signRowWithMac,
  OFFENSIVE_ROW_MAC_CONTEXT,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  ensureHandoffKeypair,
  readHandoffSigningPrivateKey,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  seedInvariantRunRow,
  seedInvariantRunPair,
} = require("./helpers/invariant-run-seed.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-inv-mac-keying-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function mintGenuineVerdict(domain, findingId, sign) {
  const { positive, control } = seedInvariantRunPair(domain, { findingId, sign });
  verifyInvariantDifferential({
    target_domain: domain,
    finding_id: findingId,
    positive_run_hash: positive.run_hash,
    control_run_hash: control.run_hash,
  });
  return { positive, control };
}

test("(a) NEW signed rows carry a valid bob.invariant-run.v1 mac and re-derive ok", () => withTempHome(() => {
  const domain = "inv-keying-genuine.example.com";
  const { positive, control } = mintGenuineVerdict(domain, "F-1", true);

  // The persisted positive row carries a v2 ed25519 row_mac (not just a content hash).
  const rows = fs.readFileSync(invariantRunsJsonlPath(domain), "utf8")
    .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  const onDiskPositive = rows.find((r) => r.run_hash === positive.run_hash);
  assert.ok(onDiskPositive.row_mac, "signed invariant row carries row_mac");
  assert.equal(onDiskPositive.row_mac.scheme, "ed25519");

  const summary = readInvariantVerifiedSummary(domain);
  assert.ok(summary.verified_by_finding["F-1"], "signed flipping pair re-derives ok at read");
  assert.equal(summary.verified_by_finding["F-1"].positive_run_hash, positive.run_hash);
  assert.equal(summary.verified_by_finding["F-1"].control_run_hash, control.run_hash);
}));

test("(b) a TAMPERED signed row (covered field mutated, stale mac kept) is fail-closed excluded", () => withTempHome(() => {
  const domain = "inv-keying-tamper.example.com";
  const { control } = mintGenuineVerdict(domain, "F-1", true);

  // Mutate a hash-bound field on the control row but KEEP its (now stale) row_mac, then
  // ALSO restore run_hash so the content-hash check alone could not catch it — the keyed
  // mac is what excludes it. We rewrite the row so computeInvariantRunHash still matches
  // (tree_ref is bound into run_hash, so mutating it AND recomputing run_hash keeps the
  // content layer consistent while the row_mac, signed over the original tree_ref, breaks).
  const runsPath = invariantRunsJsonlPath(domain);
  const rows = fs.readFileSync(runsPath, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  const rewritten = rows.map((row) => {
    if (row.run_hash !== control.run_hash) return JSON.stringify(row);
    const staleMac = row.row_mac;
    row.tree_ref = "attacker-relabeled";
    row.run_hash = computeInvariantRunHash(row); // re-bind content hash, keep stale mac
    row.row_mac = staleMac;
    return JSON.stringify(row);
  });
  fs.writeFileSync(runsPath, `${rewritten.join("\n")}\n`);

  // The verdict still cites the ORIGINAL control_run_hash, which no longer resolves; and
  // even resolving the relabeled row, its row_mac no longer verifies -> fail-closed.
  const summary = readInvariantVerifiedSummary(domain);
  assert.equal(summary.verified_by_finding["F-1"], undefined, "tampered signed row is excluded");
}));

test("(c) a forged row with a recomputed content-hash but NO valid mac is excluded (keying defeats the F2 forge)", () => withTempHome(() => {
  const domain = "inv-keying-content-forge.example.com";
  // Genuine SIGNED positive; the attacker then forges a control row with a perfectly
  // recomputed computeInvariantRunHash (the old F2 content-hash forge) but signs it under
  // the WRONG context (offensive-runs), i.e. without a valid invariant-run mac.
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  // Forge a content-valid control row, then attach a cross-context (offensive) signature.
  const forgedControl = {
    target_domain: domain,
    finding_id: "F-1",
    finding_hash: null,
    template_id: "INV-FIXTURE-001",
    slot_values: { a: "1" },
    contract_name: "BobInvariantTest_fixture",
    function_name: "testBobInvariant_fixture",
    execution_context_hash: "ctx-hash-shared",
    tree_ref: "fixed",
    checkout_kind: "upstream_fix",
    outcome: "test_passed",
    foundry_result_hash: require("../mcp/core/invariant-runner.js").invariantFoundryResultHash({ tests: [{ success: true }] }),
    foundry_result: { tests: [{ success: true }] },
    dry_run: false,
  };
  forgedControl.run_hash = computeInvariantRunHash(forgedControl); // content-hash is VALID
  ensureHandoffKeypair(domain);
  // Cross-context signature: a real ed25519 sig, but under the OFFENSIVE context, so it is
  // NOT a valid bob.invariant-run.v1 mac (domain separation).
  signRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, forgedControl, readHandoffSigningPrivateKey(domain));
  fs.appendFileSync(invariantRunsJsonlPath(domain), `${JSON.stringify(forgedControl)}\n`);

  // The differential verifier rejects the cross-context-signed control at read time.
  assert.throws(
    () => verifyInvariantDifferential({
      target_domain: domain,
      finding_id: "F-1",
      positive_run_hash: positive.run_hash,
      control_run_hash: forgedControl.run_hash,
    }),
    /does not verify|cross-context/,
    "a content-valid but invariant-mac-invalid row is rejected",
  );
}));

test("(d) an OLD unsigned legacy row is accepted-with-warning and still re-adjudicates", () => withTempHome(() => {
  const domain = "inv-keying-legacy.example.com";
  // sign:false => no row_mac (an in-flight pre-Cycle-B row).
  const { positive, control } = mintGenuineVerdict(domain, "F-1", false);
  const rows = fs.readFileSync(invariantRunsJsonlPath(domain), "utf8")
    .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  assert.equal(rows.find((r) => r.run_hash === positive.run_hash).row_mac, undefined, "legacy row has no mac");

  const summary = readInvariantVerifiedSummary(domain);
  assert.ok(summary.verified_by_finding["F-1"], "unsigned legacy flip still re-adjudicates (accept-with-warning)");
  assert.equal(summary.verified_by_finding["F-1"].control_run_hash, control.run_hash);
}));

test("(e) cross-ledger replay: an OFFENSIVE-context mac pasted on an invariant row fails", () => withTempHome(() => {
  const domain = "inv-keying-crossledger.example.com";
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: false,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "fixed", checkoutKind: "upstream_fix", sign: false,
  });
  // Sign the control under the OFFENSIVE context (a real signature, wrong domain) and
  // attach it. The read site must reject it under the invariant-run context.
  ensureHandoffKeypair(domain);
  signRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, control, readHandoffSigningPrivateKey(domain));
  const runsPath = invariantRunsJsonlPath(domain);
  const rows = fs.readFileSync(runsPath, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  const rewritten = rows.map((row) => (row.run_hash === control.run_hash ? JSON.stringify(control) : JSON.stringify(row)));
  fs.writeFileSync(runsPath, `${rewritten.join("\n")}\n`);

  assert.throws(
    () => verifyInvariantDifferential({
      target_domain: domain,
      finding_id: "F-1",
      positive_run_hash: positive.run_hash,
      control_run_hash: control.run_hash,
    }),
    /does not verify|cross-context/,
    "an offensive-context mac on an invariant row fails domain separation",
  );

  // And the reverify path (read summary) excludes a verdict citing it.
  const out = reverifyInvariantVerifiedRecord(domain, {
    finding_id: "F-1",
    positive_run_hash: positive.run_hash,
    control_run_hash: control.run_hash,
  });
  assert.equal(out.ok, false, "reverify fails closed on the cross-ledger-replayed row");
}));
