"use strict";

// The allow-path-REACHABLE proof (STRUCTURAL-LOGIC, NOT A SECURITY PROOF).
//
// HONESTY: withStructuralIsolatedKey stubs EVERY input the probe reads —
// fs.lstatSync (owner uid + 0400 mode), process.getuid, and both
// BOB_SANDBOX_SIGNER_UID / BOB_SANDBOX_AGENT_UID env vars. So isolated:true here
// is a tautology over those stubs: it proves the gate's allow BRANCH is REACHABLE
// and correctly wired (decision:allow / reason:isolated_signer_ed25519_only), it
// does NOT prove the OS actually excludes the agent from the key. The genuine
// OS/namespace-exclusion proof is a Docker-gated container integration test that
// reads a real key path that is not in the container namespace; that test (added
// in the container-routing build) is the only one that proves real exclusion.
//
// Why this branch-reachability regression IS worth keeping: Cycle C's inverted
// probe made the allow branch (probe.isolated && !hasLegacyOrV1) STATICALLY
// UNREACHABLE on any deployment where signing worked, so a verdict-ledger-backed
// reportable medium+ claim ALWAYS hard-blocked (enforce) or downgraded (degrade)
// — even on a box configured exactly per scripts/launch-bob-signer.sh. With the
// Mechanism-A structural probe (owner-only key + this process owns it + is the
// declared signer + a distinct declared agent uid + not root), isolated:true is
// REACHABLE. This test seeds a verdict-ledger-backed ed25519-only finding, stubs
// the structural isolated layout, and asserts evaluateVerdictSandboxGate returns
// decision:"allow"/reason:"isolated_signer_ed25519_only" — UNDER BOTH enforce AND
// default — so the unreachable-allow defect cannot recur invisibly.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const recordFindingTool = require("../mcp/tools/record-candidate-claim.js");
const { buildClaimFreeze } = require("../mcp/core/claims/claim-freeze.js");
const { writeVerificationRound } = require("../mcp/core/verification/verification-round-store.js");
const { writeEvidencePacks } = require("../mcp/core/evidence.js");
const { ensureHandoffSigningKey, signRowViaIsolatedSignerOrLocal } = require("../mcp/core/ledger-integrity/index.js");
const { OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/index.js");
const { evaluateVerdictSandboxGate } = require("../mcp/core/verdict-sandbox-gate.js");
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

function hex(char) { return char.repeat(64); }
const WEB_SURFACE = "surface:billing-profile";

function withTempHome(fn, mode) {
  const previousHome = process.env.HOME;
  const previousMode = process.env[SANDBOX_ATTESTATION_MODE_ENV];
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sandbox-allow-"));
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

function verificationResult(findingId, overrides = {}) {
  return {
    finding_id: findingId, disposition: "confirmed", severity: "high", reportable: true,
    reasoning: "Fresh replay confirmed the finding against the current target state.",
    ...overrides,
  };
}

function evidencePack(findingId) {
  return {
    finding_id: findingId, sample_type: "cross-account replay", sample_count: 1,
    aggregate_counts: { affected_objects_sampled: 1 },
    representative_samples: [{
      request_ref: "http-audit:1", endpoint: "/api/billing/1", auth_profile: "attacker",
      status: 200, observed_fields: ["billing_profile_id"], redacted_object_id: "acct_...002",
    }],
    sensitive_clusters: ["billing metadata"],
    replay_summary: "Fresh replay returned another tenant's private billing metadata.",
    redaction_notes: "Object IDs redacted.",
    report_snippet: "An attacker can retrieve another tenant's private billing metadata.",
  };
}

// A reportable MEDIUM web finding whose claim CITES an ed25519 (v2 asymmetric)
// offensive row via an exploit_run evidence_ref — so the finding is genuinely
// executed-verdict-backed (the per-finding keyed-ledger backing the gate intersects
// against), has_legacy_or_v1=false, and ONLY the isolation leg is at issue. The row is
// seeded FIRST so the claim can reference it; demonstrated_severity is MEDIUM (the
// bob_http_idor_confirm tool ceiling), matching the finding severity so the proof
// ceiling gate passes.
function seedVerdictBackedFinding(domain) {
  ensureHandoffSigningKey(domain);
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const row = {
    version: 1, target_domain: domain, run_id: "row-ed-1", tool_id: "bob_http_idor_confirm",
    target: `https://${domain}/api/billing/1`, offensive_outcome: "exploited_safely",
    dry_run: false, timed_out: false, command_hash: hex("1"), exit_code: 0,
    stdout_hash: hex("b"), stderr_hash: hex("c"), demonstrated_severity: "medium", surface_id: WEB_SURFACE,
  };
  signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, row);
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  recordFindingTool.handler({
    target_domain: domain, title: "IDOR on billing profile", severity: "medium", cwe: "CWE-639",
    endpoint: "https://victim.example/api/billing/1", description: "Tenant boundary allows cross-account view",
    proof_of_concept: "GET /api/billing/1 returns another tenant payload",
    response_evidence: "Cross-tenant billing payload", impact: "Cross-tenant billing disclosure",
    validated: true, auth_profile: "attacker", surface_id: WEB_SURFACE,
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
    evidence_refs: [{
      kind: "exploit_run", run_id: row.run_id, tool_id: row.tool_id, target: row.target,
      offensive_outcome: row.offensive_outcome, command_hash: row.command_hash,
      exit_code: row.exit_code, stdout_hash: row.stdout_hash, stderr_hash: row.stderr_hash,
    }],
  });
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({ target_domain: domain, round, notes: null, results: [verificationResult("F-1", { severity: "medium" })] });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
}

// SAME-UID MONKEYPATCH — proves the live probe is NOT same-uid-tamper-resistant.
// Stub the STRUCTURAL Mechanism-A isolated layout the live probe reads: an
// owner-only 0400 ed25519 private key owned by the signer uid, the running
// process owning it AND declaring as the signer (getuid===owner===declared
// signer), a DISTINCT declared agent uid, and not root.
//
// HONESTY: this stubs EVERY input the probe reads (lstat uid+mode, getuid, both
// uid env vars) from WITHIN THE SAME PROCESS at the SAME uid, so isolated:true is a
// tautology over the stubs — it exercises the allow BRANCH, not real OS-level uid
// exclusion (see the file header). That a same-uid test CAN rewrite these inputs is
// the demonstration that the gate's real boundary is the DISTINCT agent uid under
// Mechanism A, not in-process integrity. The stubs restore in a finally (leak-safe,
// scoped per test).
//
// DISTINCT-PER-LEG STUBS: the three signer-side inputs (key OWNER lstat.uid,
// RUNNING getuid, DECLARED signer env) are separate params so a refactor that
// conflates them is caught; they default to one value for the happy-path equality
// the probe legitimately requires.
function withStructuralIsolatedKey(
  domain,
  signerUid,
  agentUid,
  fn,
  { keyOwnerUid = signerUid, runningUid = signerUid, declaredSignerUid = signerUid } = {},
) {
  const realLstat = fs.lstatSync;
  const realGetuid = process.getuid;
  const prevSigner = process.env[SANDBOX_SIGNER_UID_ENV];
  const prevAgent = process.env[SANDBOX_AGENT_UID_ENV];
  const keyPath = handoffSigningPrivateKeyPath(domain);
  fs.lstatSync = function stubLstat(p) {
    if (p === keyPath) return { uid: keyOwnerUid, mode: 0o400, isFile: () => true };
    return realLstat.apply(fs, arguments);
  };
  process.getuid = () => runningUid;
  process.env[SANDBOX_SIGNER_UID_ENV] = String(declaredSignerUid);
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

// The gate's allow/inert outcomes are mode-INDEPENDENT (only block-vs-downgrade
// differs); the allow-path proof must hold identically under enforce AND default.
for (const mode of ["enforce", null]) {
  const label = mode === null ? "default" : mode;
  test(`(structural-logic, NOT a security proof) allow REACHABLE: structurally-isolated signer + ed25519-only backing -> decision:allow (${label})`, () => withTempHome(() => {
    const domain = `allow-${label}.example.com`;
    seedVerdictBackedFinding(domain);
    withStructuralIsolatedKey(domain, 424242, 1000, () => {
      const decision = evaluateVerdictSandboxGate(domain);
      assert.equal(decision.applies, true, "a verdict-ledger-backed reportable medium+ finding makes the gate apply");
      assert.equal(decision.isolated, true, "the structural Mechanism-A layout is isolated (allow is REACHABLE)");
      assert.equal(decision.has_legacy_or_v1, false, "the backing row is an ed25519 MAC");
      assert.equal(decision.decision, "allow", "an isolated signer over ed25519-only backing ALLOWS");
      assert.equal(decision.reason, "isolated_signer_ed25519_only");
      assert.deepEqual([...decision.reportable_finding_ids], ["F-1"]);
    });
  }, mode));

  test(`block on the same-uid box (agent==signer) -> ${mode === "enforce" ? "block" : "downgrade"} (${label})`, () => withTempHome(() => {
    const domain = `block-${label}.example.com`;
    seedVerdictBackedFinding(domain);
    // No structural stub: the real probe on a same-uid box reports isolated:false.
    const decision = evaluateVerdictSandboxGate(domain);
    assert.equal(decision.applies, true);
    assert.equal(decision.isolated, false, "the same-uid dev box is not isolated");
    assert.equal(decision.reason, "signer_not_isolated");
    // enforce -> block; degrade -> downgrade. The default now resolves to degrade on
    // EVERY platform (degrade-default, enforce opt-in), so the null-mode case is a
    // downgrade everywhere. Assert the resolved-mode outcome rather than a fixed
    // string so the test is mode/host-portable.
    const expected = decision.mode === "enforce" ? "block" : "downgrade";
    assert.equal(decision.decision, expected, `mode=${decision.mode} -> ${expected}`);
  }, mode));
}
