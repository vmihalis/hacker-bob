"use strict";

// HIGH-1 BELT-AND-SUSPENDERS: a finding-differential-backed smart_contract reportable
// whose backing offensive run was NOT containerized can NEVER back a TRUSTED SC
// reportable, even on an otherwise-isolated signer.
//
// The invariant leg already gates SC verdicts on container_isolated. But an SC finding
// can ALSO reach the gate via the FINDING-DIFFERENTIAL leg (offensive positive/control
// flip). offensive-runs rows do not carry container_isolated today, so the re-resolved
// container_isolated is false (fail-closed) for every finding-differential row -- the
// correct posture: a finding-differential-backed SC reportable has NO containerization
// proof and must be treated un-isolated.
//
// SC-SCOPED: the finding-differential leg is predominantly HTTP (cors/idor/nuclei/reflect
// /xss). Gating EVERY differential-backed finding on container_isolated would wrongly
// downgrade legit HTTP reportables (RANK != BOUND). So the consult fires ONLY when the
// finding's bound surface resolves to kind smart_contract. This test seeds:
//   * an SC finding-differential-backed reportable -> enforce:block / degrade:downgrade
//     with reason sc_backing_not_containerized (the backing run was not containerized);
//   * an HTTP finding-differential-backed reportable on the SAME session -> UNAFFECTED
//     (decision:allow) -- proving the SC-scoping does not over-gate HTTP reportables.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { verifyFindingDifferential } = require("../mcp/core/differential/index.js");
const { appendCandidateClaim, canonicalizeExploitTarget } = require("../mcp/core/claims/claims.js");
const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { writeVerificationRound } = require("../mcp/core/verification/verification-round-store.js");
const { evaluateVerdictSandboxGate } = require("../mcp/core/ledger-integrity/index.js");
const { ensureHandoffSigningKey, signRowViaIsolatedSignerOrLocal } = require("../mcp/core/ledger-integrity/index.js");
const { OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/index.js");
const {
  offensiveRunsJsonlPath,
  handoffSigningPrivateKeyPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const {
  SANDBOX_ATTESTATION_MODE_ENV,
  SANDBOX_SIGNER_UID_ENV,
  SANDBOX_AGENT_UID_ENV,
} = require("../mcp/core/ledger-integrity/index.js");

function hex(char) {
  return char.repeat(64);
}

function withTempHome(fn, mode) {
  const previousHome = process.env.HOME;
  const previousMode = process.env[SANDBOX_ATTESTATION_MODE_ENV];
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fd-sc-trust-"));
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

// Build + sign a single offensive-runs row through the SINGLE sign shim => an ed25519
// (v2) MAC, so the verdict-ledger backing is asymmetric (NOT v1-HMAC). This keeps the
// gate's laundering-risk leg (has_legacy_or_v1) FALSE so the decision keys off the SC
// containerization consult (reason sc_backing_not_containerized), not the v1-HMAC path.
// The row carries NO container_isolated field -- offensive rows do not, which is exactly
// the fail-closed case this gate covers.
function buildSignedRow(domain, surfaceId, over = {}) {
  ensureHandoffSigningKey(domain);
  const row = {
    version: 1,
    target_domain: domain,
    run_id: over.run_id,
    tool_id: over.tool_id || "bob_http_idor_confirm",
    target: canonicalizeExploitTarget(over.target || `https://${domain}/api/x/1`),
    offensive_outcome: over.offensive_outcome || "exploited_safely",
    dry_run: false,
    timed_out: false,
    command_hash: over.command_hash || hex("a"),
    exit_code: 0,
    stdout_hash: hex("b"),
    stderr_hash: hex("c"),
    demonstrated_severity: over.demonstrated_severity || "high",
    surface_id: surfaceId,
  };
  signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, row);
  return row;
}

function appendRow(domain, row) {
  fs.mkdirSync(path.dirname(offensiveRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
}

function verificationResult(findingId) {
  return {
    finding_id: findingId, disposition: "confirmed", severity: "high", reportable: true,
    reasoning: "Fresh re-run confirmed the differential flip against the current target.",
  };
}

// Seed a reportable medium+ finding backed via the FINDING-DIFFERENTIAL leg on a surface
// of the given kind. The verified_pass is minted by the real verifyFindingDifferential so
// the gate's readFindingDifferentialVerifiedSummary re-adjudicates a genuine flip; the
// re-resolved container_isolated is false (offensive rows lack the field).
function seedDifferentialBackedFinding(domain, { findingId, surfaceId, surfaceKind, runSuffix }) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-27T00:00:00.000Z",
    surface_id: surfaceId,
    payload: { kind: surfaceKind },
  });
  appendCandidateClaim({
    target_domain: domain,
    title: `Differential ${surfaceKind} finding`,
    summary: "An attacker can flip the protected behavior.",
    severity: "high",
    status: "candidate",
    surface_ids: [surfaceId],
    // The gate's finding-differential leg keys off differentialVerified membership (the
    // verifyFindingDifferential verdict below), NOT the claim's evidence_refs -- a bare
    // finding ref is enough for the claim to resolve to the finding id.
    evidence_refs: [
      { kind: "finding", finding_id: findingId, content_hash: "0".repeat(64) },
    ],
    impact: "Protected behavior is bypassable.",
    payload: { finding: { id: findingId } },
  });
  appendRow(domain, buildSignedRow(domain, surfaceId, {
    run_id: `pos-${runSuffix}`, offensive_outcome: "exploited_safely", command_hash: hex("1"),
    target: `https://${domain}/api/${runSuffix}/1`,
  }));
  appendRow(domain, buildSignedRow(domain, surfaceId, {
    run_id: `ctl-${runSuffix}`, offensive_outcome: "blocked_by_defense", command_hash: hex("2"),
    target: `https://${domain}/api/${runSuffix}/1`,
  }));
  const out = verifyFindingDifferential({
    target_domain: domain, finding_id: findingId, surface_id: surfaceId,
    positive_run_ref: { ledger: "offensive_runs", row_id: `pos-${runSuffix}` },
    control_run_ref: { ledger: "offensive_runs", row_id: `ctl-${runSuffix}` },
  });
  assert.equal(out.result, "verified_pass", `${surfaceKind} finding-differential must mint verified_pass`);
}

// Stub the STRUCTURAL Mechanism-A isolated signer so probe.isolated:true. Without the
// finding-differential containerization consult, probe.isolated ALONE would wrongly allow
// a non-containerized SC finding-differential-backed reportable.
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
  test(`HIGH-1: a finding-differential-backed smart_contract reportable with a non-containerized backing run is NOT trusted -> ${mode === "enforce" ? "block" : "downgrade"} (${mode})`, () => withTempHome(() => {
    const domain = `fd-sc-${mode}.example.com`;
    seedDifferentialBackedFinding(domain, {
      findingId: "F-1", surfaceId: "surface:vault-shares", surfaceKind: "smart_contract", runSuffix: "sc",
    });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({ target_domain: domain, round, notes: null, results: [verificationResult("F-1")] });
    }
    withStructuralIsolatedKey(domain, 424242, 1000, () => {
      const decision = evaluateVerdictSandboxGate(domain);
      assert.equal(decision.applies, true, "a finding-differential-backed reportable medium+ SC finding makes the gate apply");
      assert.equal(decision.isolated, true, "the live signer-key probe says isolated (probe.isolated ALONE would wrongly allow)");
      assert.equal(decision.has_legacy_or_v1, false, "the backing offensive rows are ed25519-MAC, not a laundering-risk class");
      assert.equal(decision.sc_backing_not_containerized, true, "the finding-differential backing run was not containerized");
      assert.equal(decision.decision, mode === "enforce" ? "block" : "downgrade",
        `a non-containerized finding-differential SC verdict can NOT back a trusted SC reportable (mode=${mode})`);
      assert.equal(decision.reason, "sc_backing_not_containerized");
      assert.deepEqual([...decision.reportable_finding_ids], ["F-1"]);
    });
  }, mode));

  test(`HIGH-1: an HTTP finding-differential-backed reportable is UNAFFECTED by the SC consult -> allow (${mode})`, () => withTempHome(() => {
    const domain = `fd-http-${mode}.example.com`;
    seedDifferentialBackedFinding(domain, {
      findingId: "F-2", surfaceId: "surface:billing-http", surfaceKind: "http_endpoint", runSuffix: "http",
    });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({ target_domain: domain, round, notes: null, results: [verificationResult("F-2")] });
    }
    withStructuralIsolatedKey(domain, 424242, 1000, () => {
      const decision = evaluateVerdictSandboxGate(domain);
      assert.equal(decision.applies, true, "the HTTP finding-differential reportable is keyed-ledger-backed (gate applies)");
      assert.equal(decision.isolated, true);
      assert.equal(decision.sc_backing_not_containerized, false,
        "an HTTP differential surface is NOT smart_contract -> the SC containerization consult does not fire");
      assert.equal(decision.decision, "allow",
        "an HTTP finding-differential reportable on an isolated all-ed25519 session is allowed (no over-gating)");
      assert.equal(decision.reason, "isolated_signer_ed25519_only");
      assert.deepEqual([...decision.reportable_finding_ids], ["F-2"]);
    });
  }, mode));
}
