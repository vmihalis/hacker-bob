"use strict";

// HIGH-1 PROOF: a degrade-host (non-containerized) smart-contract verdict can NEVER
// back a TRUSTED SC reportable, even on an otherwise-isolated signer.
//
// THE FORGERY VECTOR this closes: on an isolated-signer box with no SC-toolchain
// image, the SC seam DEGRADES to a host spawn AS THE SIGNER (byte-identical). So
// agent-authored Solidity in the foundry test/build runs as the signer and CAN read
// the 0400 ed25519 key to forge a MAC-valid invariant-runs row — while the live
// signer-key probe (probeVerdictLedgerKeyIsolation) stays isolated:true (the agent's
// OWN node processes still cannot read the key). probe.isolated ALONE would WRONGLY
// allow such a finding. The fix records container_isolated into the backing positive
// row (covered by row_mac, outside run_hash) and has the verdict gate refuse to trust
// an SC reportable whose backing positive run was NOT containerized.
//
// This test seeds a reportable medium+ smart_contract finding backed via the
// invariantVerified leg where the POSITIVE invariant-runs row is container_isolated
// :false, stubs a structurally-isolated SIGNER (probe.isolated:true), and asserts:
//   * under enforce  -> decision:block       (a degrade-host SC run is NOT trusted)
//   * under degrade  -> decision:downgrade
// Then flips the positive row to container_isolated:true and asserts decision:allow
// (a containerized SC run CAN back a trusted SC reportable).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { verifyInvariantDifferential } = require("../mcp/core/invariant-runner.js");
const { seedInvariantRunPair } = require("./helpers/invariant-run-seed.js");
const { appendCandidateClaim } = require("../mcp/core/claims/claims.js");
const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { writeVerificationRound } = require("../mcp/core/verification/verification-round-store.js");
const { evaluateVerdictSandboxGate } = require("../mcp/core/verdict-sandbox-gate.js");
const {
  handoffSigningPrivateKeyPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const {
  SANDBOX_ATTESTATION_MODE_ENV,
  SANDBOX_SIGNER_UID_ENV,
  SANDBOX_AGENT_UID_ENV,
} = require("../mcp/core/ledger-integrity/index.js");

function withTempHome(fn, mode) {
  const previousHome = process.env.HOME;
  const previousMode = process.env[SANDBOX_ATTESTATION_MODE_ENV];
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sc-trust-"));
  process.env.HOME = home;
  if (mode != null) process.env[SANDBOX_ATTESTATION_MODE_ENV] = mode;
  else delete process.env[SANDBOX_ATTESTATION_MODE_ENV];
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    if (previousMode === undefined) delete process.env[SANDBOX_ATTESTATION_MODE_ENV];
    else process.env[SANDBOX_ATTESTATION_MODE_ENV] = previousMode;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function verificationResult(findingId) {
  return {
    finding_id: findingId, disposition: "confirmed", severity: "high", reportable: true,
    reasoning: "Fresh re-run confirmed the invariant violation against the current target.",
  };
}

// Seed a reportable medium+ smart_contract finding backed via the invariantVerified
// leg, with the POSITIVE invariant-runs row carrying the supplied containerization.
// The verified_pass is minted by the real verifyInvariantDifferential so the gate's
// readInvariantVerifiedSummary re-adjudicates a genuine flip (the container_isolated
// signal rides on the re-resolved positive row).
function seedScBackedFinding(domain, { positiveContainerIsolated } = {}) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  // Register the smart_contract finding F-1 so findingIdSetForVerificationContext
  // admits it (the gate's reportable projection + verification-round writes both
  // address the finding by id).
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
  const { positive, control } = seedInvariantRunPair(domain, {
    findingId: "F-1", sign: true, positiveContainerIsolated,
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
      results: [verificationResult("F-1")],
    });
  }
  return { positive, control };
}

// Stub the STRUCTURAL Mechanism-A isolated signer the live probe reads (owner-only
// 0400 key owned by the signer uid, this process owns it AND declares as the signer,
// a DISTINCT non-root declared agent uid, not root) so probe.isolated:true. Without
// the HIGH-1 consult, probe.isolated ALONE would wrongly allow a degrade-host SC run.
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

for (const mode of ["enforce", "degrade"]) {
  test(`HIGH-1: a degrade-host (container_isolated:false) SC verdict is NOT trusted on an isolated signer -> ${mode === "enforce" ? "block" : "downgrade"} (${mode})`, () => withTempHome(() => {
    const domain = `sc-degrade-${mode}.example.com`;
    seedScBackedFinding(domain, { positiveContainerIsolated: false });
    withStructuralIsolatedKey(domain, 424242, 1000, () => {
      const decision = evaluateVerdictSandboxGate(domain);
      assert.equal(decision.applies, true, "a verdict-ledger-backed reportable medium+ SC finding makes the gate apply");
      assert.equal(decision.isolated, true, "the live signer-key probe says isolated (probe.isolated ALONE would wrongly allow)");
      assert.equal(decision.has_legacy_or_v1, false, "the backing invariant row is an ed25519 MAC, not a laundering-risk class");
      assert.equal(decision.sc_backing_not_containerized, true, "the backing positive run was a degrade-host spawn (not containerized)");
      assert.equal(decision.decision, mode === "enforce" ? "block" : "downgrade",
        `a degrade-host SC verdict can NOT back a trusted SC reportable (mode=${mode})`);
      assert.equal(decision.reason, "sc_backing_not_containerized");
      assert.deepEqual([...decision.reportable_finding_ids], ["F-1"]);
    });
  }, mode));

  test(`HIGH-1: a CONTAINERIZED (container_isolated:true) SC verdict IS trusted on an isolated signer -> allow (${mode})`, () => withTempHome(() => {
    const domain = `sc-container-${mode}.example.com`;
    seedScBackedFinding(domain, { positiveContainerIsolated: true });
    withStructuralIsolatedKey(domain, 424242, 1000, () => {
      const decision = evaluateVerdictSandboxGate(domain);
      assert.equal(decision.applies, true);
      assert.equal(decision.isolated, true);
      assert.equal(decision.sc_backing_not_containerized, false, "the backing positive run was containerized");
      assert.equal(decision.decision, "allow", "a containerized SC run on an isolated signer ALLOWS");
      assert.equal(decision.reason, "isolated_signer_ed25519_only");
      assert.deepEqual([...decision.reportable_finding_ids], ["F-1"]);
    });
  }, mode));

  test(`HIGH-1: a LEGACY (container_isolated absent) SC verdict fails closed un-isolated -> ${mode === "enforce" ? "block" : "downgrade"} (${mode})`, () => withTempHome(() => {
    const domain = `sc-legacy-${mode}.example.com`;
    // positiveContainerIsolated undefined => the field is OMITTED (a pre-cycle legacy row).
    seedScBackedFinding(domain, { positiveContainerIsolated: undefined });
    withStructuralIsolatedKey(domain, 424242, 1000, () => {
      const decision = evaluateVerdictSandboxGate(domain);
      assert.equal(decision.applies, true);
      assert.equal(decision.isolated, true);
      assert.equal(decision.sc_backing_not_containerized, true, "an absent container_isolated fails closed un-isolated");
      assert.equal(decision.decision, mode === "enforce" ? "block" : "downgrade");
      assert.equal(decision.reason, "sc_backing_not_containerized");
    });
  }, mode));
}
