"use strict";

// HIGH-1 SIGNAL-PATH proof: container_isolated rides from the foundry result through
// the invariant-runs record WITHOUT perturbing run_hash, and is covered by row_mac.
//
//   (1) runInvariantForFinding lifts foundry_result.container_isolated into the
//       persisted record as a TOP-LEVEL field (sibling to recorded_at/run_id),
//       container route -> true, degrade route -> false.
//   (2) run_hash (computeInvariantRunHash) is BYTE-STABLE whether container_isolated
//       is true or false (proving the field is OUTSIDE the hash) — so a positive
//       /control pairing and every pre-existing fixture hash are unchanged.
//   (3) the persisted row's row_mac COVERS container_isolated: flipping the recorded
//       value invalidates the MAC (an agent cannot strip/flip it to launder a
//       degrade-host run into a containerized one).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  runInvariantForFinding,
  readInvariantRuns,
  computeInvariantRunHash,
  invariantFoundryResultHash,
} = require("../mcp/lib/invariant-runner.js");
const {
  verifyRowWithMac,
  INVARIANT_RUN_MAC_CONTEXT,
} = require("../mcp/lib/offensive-row-mac.js");
const { resolveOffensiveRowVerifier } = require("../mcp/lib/handoff-signing-key.js");

function uniqueDomain() {
  return `inv-ci-${Math.random().toString(36).slice(2)}.example.com`;
}

function makeHarness() {
  const harness = fs.mkdtempSync(path.join(os.homedir(), ".bob-foundry-ci-harness-"));
  fs.mkdirSync(path.join(harness, "test"), { recursive: true });
  return harness;
}

function cleanup(domain, harness) {
  const dir = path.join(os.homedir(), "hacker-bob-sessions", domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  if (harness && fs.existsSync(harness)) fs.rmSync(harness, { recursive: true, force: true });
}

const FINDING = Object.freeze({
  finding_id: "F-1",
  finding_hash: "h1",
  title: "Reentrancy in withdraw",
  vulnerability_class: "reentrancy",
  description: "external call before state update",
});

const SLOTS = { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" };

// A stub foundry_run that returns a normal forge envelope plus a TOP-LEVEL
// container_isolated marker — exactly what foundry-runner finalizeRun threads from
// the SC seam's child.container_isolated.
function stubFoundry(containerIsolated) {
  return async () => ({
    ok: true,
    tests: [{ name: "testX", success: true }],
    container_isolated: containerIsolated,
  });
}

test("(1) the invariant-runs record carries container_isolated:true on the container route", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  try {
    await runInvariantForFinding({
      target_domain: domain, finding: FINDING, slot_values: SLOTS,
      harness_path: harness, foundry_run: stubFoundry(true), run_id: "inv-ci-1",
    });
    const corpus = readInvariantRuns({ target_domain: domain });
    assert.equal(corpus.runs.length, 1);
    assert.equal(corpus.runs[0].container_isolated, true, "container route -> container_isolated:true");
  } finally {
    cleanup(domain, harness);
  }
});

test("(1) the invariant-runs record carries container_isolated:false on the degrade route", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  try {
    await runInvariantForFinding({
      target_domain: domain, finding: FINDING, slot_values: SLOTS,
      harness_path: harness, foundry_run: stubFoundry(false), run_id: "inv-ci-2",
    });
    const corpus = readInvariantRuns({ target_domain: domain });
    assert.equal(corpus.runs[0].container_isolated, false, "degrade route -> container_isolated:false");
  } finally {
    cleanup(domain, harness);
  }
});

test("(2) run_hash is BYTE-STABLE whether container_isolated is true or false (field is OUTSIDE the hash)", async () => {
  const domainTrue = uniqueDomain();
  const domainFalse = uniqueDomain();
  const harnessTrue = makeHarness();
  const harnessFalse = makeHarness();
  try {
    const resTrue = await runInvariantForFinding({
      target_domain: domainTrue, finding: FINDING, slot_values: SLOTS,
      harness_path: harnessTrue, foundry_run: stubFoundry(true), run_id: "inv-h-1",
    });
    const resFalse = await runInvariantForFinding({
      target_domain: domainFalse, finding: FINDING, slot_values: SLOTS,
      harness_path: harnessFalse, foundry_run: stubFoundry(false), run_id: "inv-h-2",
    });
    assert.equal(resTrue.run_hash, resFalse.run_hash,
      "container_isolated true vs false must produce the IDENTICAL run_hash");

    // Direct unit assertion: invariantFoundryResultHash ignores container_isolated.
    const base = { ok: true, tests: [{ success: true }] };
    assert.equal(
      invariantFoundryResultHash({ ...base, container_isolated: true }),
      invariantFoundryResultHash(base),
      "foundry_result_hash must exclude container_isolated (true)",
    );
    assert.equal(
      invariantFoundryResultHash({ ...base, container_isolated: false }),
      invariantFoundryResultHash(base),
      "foundry_result_hash must exclude container_isolated (false)",
    );
    // computeInvariantRunHash over a row carrying container_isolated must match a row
    // without it (the field is a sibling, not a hashed field).
    const row = {
      finding_id: "F-1", finding_hash: null, template_id: "INV-FIXTURE-001",
      slot_values: { a: "1" }, contract_name: "C", function_name: "f",
      execution_context_hash: "ctx", outcome: "test_failed",
      foundry_result: { tests: [{ success: false }] }, dry_run: false,
      tree_ref: "target", checkout_kind: "tree",
    };
    const hashWithout = computeInvariantRunHash(row);
    const hashWith = computeInvariantRunHash({ ...row, container_isolated: false });
    assert.equal(hashWith, hashWithout, "computeInvariantRunHash must ignore the container_isolated sibling field");
  } finally {
    cleanup(domainTrue, harnessTrue);
    cleanup(domainFalse, harnessFalse);
  }
});

test("(3) the row_mac COVERS container_isolated: a tamper-flip invalidates the MAC", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  try {
    await runInvariantForFinding({
      target_domain: domain, finding: FINDING, slot_values: SLOTS,
      harness_path: harness, foundry_run: stubFoundry(false), run_id: "inv-mac-1",
    });
    const corpus = readInvariantRuns({ target_domain: domain });
    const row = corpus.runs[0];
    assert.equal(row.container_isolated, false);
    assert.ok(row.row_mac, "the persisted row is signed");

    const verifier = resolveOffensiveRowVerifier(domain);
    // The genuine row verifies under its MAC.
    assert.equal(
      verifyRowWithMac(INVARIANT_RUN_MAC_CONTEXT, row, verifier),
      true,
      "the genuine row_mac verifies",
    );
    // Flipping container_isolated false -> true (the laundering an agent would want)
    // invalidates the MAC: it cannot strip/flip the field without re-signing, which
    // it cannot do on an isolated signer.
    const tampered = { ...row, container_isolated: true };
    assert.equal(
      verifyRowWithMac(INVARIANT_RUN_MAC_CONTEXT, tampered, verifier),
      false,
      "flipping container_isolated to true invalidates the row_mac",
    );
  } finally {
    cleanup(domain, harness);
  }
});
