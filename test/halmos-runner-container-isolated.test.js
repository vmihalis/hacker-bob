"use strict";

// LOAD-BEARING for halmos: a CONTAINERIZED halmos verdict must be TRUSTED, not over-gated.
//
// halmos runs feed the invariant-verified ledger (classifyHalmosViolation maps a run to
// violated/held), exactly like foundry. runInvariantForFinding lifts
// foundry_result.container_isolated TOOL-AGNOSTICALLY into the persisted invariant-runs
// row, so once halmos-runner lifts child.container_isolated into its result envelope, a
// containerized halmos verdict reaches the gate as container_isolated:true. Before the
// lift, halmos dropped the marker => the row read container_isolated:false => the gate's
// scBackingUnIsolatedFindingIds WRONGLY downgraded a legitimately-containerized halmos
// verdict (over-gating). This test proves the end-to-end TRUSTED path through the real
// runInvariantForFinding + verifyInvariantDifferential + the verdict gate, plus the
// degrade-host counterpart staying UN-trusted, plus run_hash byte-stability for a
// halmos-shaped result.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  runInvariantForFinding,
  verifyInvariantDifferential,
  readInvariantRuns,
  readInvariantVerifiedSummary,
  invariantFoundryResultHash,
} = require("../mcp/lib/invariant-runner.js");
const { appendCandidateClaim } = require("../mcp/lib/claims.js");
const { appendFrontierEvent } = require("../mcp/lib/frontier-events.js");
const { writeVerificationRound } = require("../mcp/lib/verification-round-store.js");
const { evaluateVerdictSandboxGate } = require("../mcp/lib/sandbox-isolation-gate.js");
const {
  handoffSigningPrivateKeyPath,
  sessionDir,
} = require("../mcp/lib/paths.js");
const {
  SANDBOX_ATTESTATION_MODE_ENV,
  SANDBOX_SIGNER_UID_ENV,
  SANDBOX_AGENT_UID_ENV,
} = require("../mcp/lib/sandbox-isolation-attest.js");

function uniqueDomain(tag) {
  return `halmos-ci-${tag}-${Math.random().toString(36).slice(2)}.example.com`;
}

function makeHarness() {
  const harness = fs.mkdtempSync(path.join(os.homedir(), ".bob-halmos-ci-"));
  fs.mkdirSync(path.join(harness, "test"), { recursive: true });
  return harness;
}

function cleanup(domain, ...harnesses) {
  const dir = sessionDir(domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  for (const h of harnesses) {
    if (h && fs.existsSync(h)) fs.rmSync(h, { recursive: true, force: true });
  }
}

const FINDING = Object.freeze({
  finding_id: "F-1",
  finding_hash: "h1",
  title: "Invariant violation in vault",
  vulnerability_class: "reentrancy",
  description: "external call before state update",
});
const SLOTS = { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" };

// A halmos-shaped adapter result — the EXACT shape runHalmos produces on the container
// route (top-level summary + tests + container_isolated), NOT a foundry envelope. A
// VIOLATED positive (summary.failed>0) carries container_isolated per the route; a HELD
// control passes.
function halmosViolatedResult(containerIsolated) {
  return async () => ({
    ok: false,
    summary: { total: 1, passed: 0, failed: 1 },
    tests: [{ test: "check_invariant", status: "Fail", counterexample: "cex" }],
    container_isolated: containerIsolated,
  });
}
function halmosHeldResult(containerIsolated) {
  return async () => ({
    ok: true,
    summary: { total: 1, passed: 1, failed: 0 },
    tests: [{ test: "check_invariant", status: "Pass", counterexample: null }],
    container_isolated: containerIsolated,
  });
}

// Mint a genuine positive(violated)/control(held) invariant-run pair via the REAL
// runInvariantForFinding using halmos-shaped adapters. The positive runs on the target
// tree (container_isolated as supplied); the control on a fixed tree.
async function seedHalmosBackedPair(domain, { positiveContainerIsolated }) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const surfaceId = "surface:vault-shares";
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-27T00:00:00.000Z",
    surface_id: surfaceId,
    payload: { kind: "smart_contract", language: "solidity" },
  });
  appendCandidateClaim({
    target_domain: domain,
    title: "Vault invariant violation",
    summary: "An attacker can break the share-accounting invariant.",
    severity: "high",
    status: "candidate",
    surface_ids: [surfaceId],
    evidence_refs: [{ kind: "finding", finding_id: "F-1", content_hash: "0".repeat(64) }],
    impact: "Share accounting can be drained.",
    payload: { finding: { id: "F-1" } },
  });
  const harnessPos = makeHarness();
  const harnessCtl = makeHarness();
  const positive = await runInvariantForFinding({
    target_domain: domain, finding: FINDING, slot_values: SLOTS,
    harness_path: harnessPos, foundry_run: halmosViolatedResult(positiveContainerIsolated),
    run_id: "halmos-pos", tree_ref: "target", checkout_kind: "tree",
  });
  const control = await runInvariantForFinding({
    target_domain: domain, finding: FINDING, slot_values: SLOTS,
    harness_path: harnessCtl, foundry_run: halmosHeldResult(true),
    run_id: "halmos-ctl", tree_ref: "fixed", checkout_kind: "upstream_fix",
  });
  verifyInvariantDifferential({
    target_domain: domain,
    finding_id: "F-1",
    positive_run_hash: positive.run_hash,
    control_run_hash: control.run_hash,
  });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain, round, notes: null,
      results: [{
        finding_id: "F-1", disposition: "confirmed", severity: "high", reportable: true,
        reasoning: "Fresh re-run confirmed the invariant violation against the current target.",
      }],
    });
  }
  return { positive, control, harnessPos, harnessCtl };
}

// Run with a resolved attestation mode but in the REAL $HOME — the session tree lives under
// ~/hacker-bob-sessions/<domain> (cleaned up after) so runInvariantForFinding's strict
// session-root guard (which rejects domain-directory symlinks under a temp /var home) is
// satisfied, exactly like foundry-runner-container-isolated-row.test.js. The isolated-signer
// stub overrides the key-path lstat + uids independently of $HOME, so the gate still sees a
// structurally-isolated signer.
async function withMode(mode, fn) {
  const previousMode = process.env[SANDBOX_ATTESTATION_MODE_ENV];
  if (mode != null) process.env[SANDBOX_ATTESTATION_MODE_ENV] = mode;
  else delete process.env[SANDBOX_ATTESTATION_MODE_ENV];
  try {
    return await fn();
  } finally {
    if (previousMode === undefined) delete process.env[SANDBOX_ATTESTATION_MODE_ENV];
    else process.env[SANDBOX_ATTESTATION_MODE_ENV] = previousMode;
  }
}

// Stub a STRUCTURAL Mechanism-A isolated signer so probe.isolated:true — the case where
// the live signer probe ALONE would wrongly allow a degrade-host SC run.
function withStructuralIsolatedKey(domain, signerUid, agentUid, fn) {
  const realLstat = fs.lstatSync;
  const realGetuid = process.getuid;
  const prevSigner = process.env[SANDBOX_SIGNER_UID_ENV];
  const prevAgent = process.env[SANDBOX_AGENT_UID_ENV];
  const keyPath = handoffSigningPrivateKeyPath(domain);
  fs.lstatSync = function stubLstat(p) {
    if (p === keyPath) return { uid: signerUid, mode: 0o400, isFile: () => true };
    return realLstat.apply(fs, arguments);
  };
  process.getuid = () => signerUid;
  process.env[SANDBOX_SIGNER_UID_ENV] = String(signerUid);
  process.env[SANDBOX_AGENT_UID_ENV] = String(agentUid);
  try {
    return fn();
  } finally {
    fs.lstatSync = realLstat;
    process.getuid = realGetuid;
    if (prevSigner === undefined) delete process.env[SANDBOX_SIGNER_UID_ENV];
    else process.env[SANDBOX_SIGNER_UID_ENV] = prevSigner;
    if (prevAgent === undefined) delete process.env[SANDBOX_AGENT_UID_ENV];
    else process.env[SANDBOX_AGENT_UID_ENV] = prevAgent;
  }
}

test("a CONTAINERIZED halmos verdict carries container_isolated:true through the invariant-runs row to the gate (TRUSTED, not over-gated)", async () => {
  await withMode("enforce", async () => {
    const domain = uniqueDomain("trust");
    let harnesses = [];
    try {
      const { harnessPos, harnessCtl } = await seedHalmosBackedPair(domain, { positiveContainerIsolated: true });
      harnesses = [harnessPos, harnessCtl];

      // The persisted positive row lifts container_isolated:true from the halmos adapter.
      const corpus = readInvariantRuns({ target_domain: domain });
      const positiveRow = corpus.runs.find((r) => r.tree_ref === "target");
      assert.equal(positiveRow.container_isolated, true,
        "the halmos-backed positive row must carry container_isolated:true (the lift reached the row)");

      // The re-derived verified summary carries container_isolated:true.
      const summary = readInvariantVerifiedSummary(domain);
      assert.equal(summary.verified_by_finding["F-1"].container_isolated, true,
        "readInvariantVerifiedSummary re-resolves container_isolated:true for the halmos verdict");

      // The gate TRUSTS it on an isolated signer (NOT over-gated).
      withStructuralIsolatedKey(domain, 424242, 1000, () => {
        const decision = evaluateVerdictSandboxGate(domain);
        assert.equal(decision.applies, true);
        assert.equal(decision.isolated, true);
        assert.equal(decision.sc_backing_not_containerized, false,
          "a containerized halmos verdict is NOT treated as un-isolated");
        assert.equal(decision.decision, "allow",
          "a CONTAINERIZED halmos verdict on an isolated signer is TRUSTED");
        assert.deepEqual([...decision.reportable_finding_ids], ["F-1"]);
      });
    } finally {
      cleanup(domain, ...harnesses);
    }
  });
});

for (const mode of ["enforce", "degrade"]) {
  test(`a DEGRADE-host halmos verdict (container_isolated:false) is NOT trusted on an isolated signer -> ${mode === "enforce" ? "block" : "downgrade"} (${mode})`, async () => {
    await withMode(mode, async () => {
      const domain = uniqueDomain(`degrade-${mode}`);
      let harnesses = [];
      try {
        const { harnessPos, harnessCtl } = await seedHalmosBackedPair(domain, { positiveContainerIsolated: false });
        harnesses = [harnessPos, harnessCtl];

        const corpus = readInvariantRuns({ target_domain: domain });
        const positiveRow = corpus.runs.find((r) => r.tree_ref === "target");
        assert.equal(positiveRow.container_isolated, false,
          "a degrade-host halmos positive row carries container_isolated:false");

        withStructuralIsolatedKey(domain, 424242, 1000, () => {
          const decision = evaluateVerdictSandboxGate(domain);
          assert.equal(decision.sc_backing_not_containerized, true,
            "a degrade-host halmos verdict is treated as un-isolated even though the live probe says isolated");
          assert.equal(decision.decision, mode === "enforce" ? "block" : "downgrade");
          assert.equal(decision.reason, "sc_backing_not_containerized");
        });
      } finally {
        cleanup(domain, ...harnesses);
      }
    });
  });
}

test("run_hash byte-stability: invariantFoundryResultHash strips container_isolated for a HALMOS-shaped result (no foundry_result keys)", () => {
  // A halmos-shaped result (summary/tests, no forge fork_attempts/raw_excerpt) must hash
  // IDENTICALLY with and without container_isolated, exactly as a foundry-shaped one does —
  // so a containerized halmos run's run_hash is byte-stable vs a degrade one and vs legacy.
  const halmosBase = { ok: false, summary: { total: 1, passed: 0, failed: 1 }, tests: [{ test: "t", status: "Fail" }] };
  assert.equal(
    invariantFoundryResultHash({ ...halmosBase, container_isolated: true }),
    invariantFoundryResultHash(halmosBase),
    "halmos-shaped foundry_result_hash must exclude container_isolated (true)",
  );
  assert.equal(
    invariantFoundryResultHash({ ...halmosBase, container_isolated: false }),
    invariantFoundryResultHash(halmosBase),
    "halmos-shaped foundry_result_hash must exclude container_isolated (false)",
  );
});

test("the two halmos invariant rows (container_isolated true vs false) produce IDENTICAL run_hash (field is OUTSIDE the hash)", async () => {
  const domainTrue = uniqueDomain("htrue");
  const domainFalse = uniqueDomain("hfalse");
  const h1 = makeHarness();
  const h2 = makeHarness();
  try {
    const resTrue = await runInvariantForFinding({
      target_domain: domainTrue, finding: FINDING, slot_values: SLOTS,
      harness_path: h1, foundry_run: halmosViolatedResult(true), run_id: "h-true",
      tree_ref: "target", checkout_kind: "tree",
    });
    const resFalse = await runInvariantForFinding({
      target_domain: domainFalse, finding: FINDING, slot_values: SLOTS,
      harness_path: h2, foundry_run: halmosViolatedResult(false), run_id: "h-false",
      tree_ref: "target", checkout_kind: "tree",
    });
    assert.equal(resTrue.run_hash, resFalse.run_hash,
      "a containerized vs degrade halmos run must produce the IDENTICAL run_hash");
  } finally {
    cleanup(domainTrue, h1);
    cleanup(domainFalse, h2);
  }
});
