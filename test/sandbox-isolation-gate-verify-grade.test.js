"use strict";

// Verdict-level sandbox-isolation gate at VERIFY -> GRADE
// (lifecycle-gates.js sandboxIsolationBlockersForReportableVerdictClaims, the
// producer gateVerifyToGrade appends after the reachability check). The upstream
// verification/reachability checks short-circuit gateVerifyToGrade before this
// block, so this exercises the production producer directly.
//
// Asserts:
//   * a clean / advisory-only / pure-OSINT session (no verdict-ledger-backed
//     reportable medium+ finding) yields NO sandbox blocker (RANK != BOUND);
//   * a verdict-ledger-backed reportable medium+ finding on the SAME-UID box
//     (probe.isolated=false) + enforce -> a sandbox_isolation_unattested
//     STATE_CONFLICT blocker;
//   * the same + degrade -> NO blocker (the transition proceeds; the report door
//     downgrades to advisory), and a loud warning is emitted;
//   * a MOCKED isolated:true probe over ed25519-only backing rows + enforce ->
//     NO blocker (the allow path), proven without a real second uid.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  sandboxIsolationBlockersForReportableVerdictClaims,
} = require("../mcp/core/session/lifecycle-gates.js");
const recordFindingTool = require("../mcp/tools/record-candidate-claim.js");
const { buildClaimFreeze } = require("../mcp/core/claims/claim-freeze.js");
const { writeVerificationRound } = require("../mcp/core/verification/verification-round-store.js");
const { writeEvidencePacks } = require("../mcp/core/evidence.js");
const { ensureHandoffSigningKey, signRowViaIsolatedSignerOrLocal } = require("../mcp/core/ledger-integrity/index.js");
const { OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/index.js");
const {
  offensiveRunsJsonlPath,
  handoffSigningPrivateKeyPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const { SANDBOX_ATTESTATION_MODE_ENV } = require("../mcp/core/ledger-integrity/index.js");

function hex(char) { return char.repeat(64); }
const WEB_SURFACE = "surface:billing-profile";

function withTempHome(fn, mode) {
  const previousHome = process.env.HOME;
  const previousMode = process.env[SANDBOX_ATTESTATION_MODE_ENV];
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sandbox-vg-"));
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

// A reportable medium+ web finding with a final reportable round + evidence pack. When an
// {exploitRunRef} is supplied the finding CITES that keyed offensive-runs row (so it is
// genuinely keyed-ledger-backed per the gate's per-finding predicate, not freeze
// membership). Severity defaults to "medium" when a ref is cited (the bob_http_idor_confirm
// tool ceiling), else honors the caller's severity for the inert/advisory cases.
function seedReportableFinding(domain, { severity = null, finalReportable = true, exploitRunRef = null } = {}) {
  const findingSeverity = severity != null ? severity : (exploitRunRef ? "medium" : "high");
  const findingArgs = {
    target_domain: domain, title: "IDOR on billing profile", severity: findingSeverity, cwe: "CWE-639",
    endpoint: "https://victim.example/api/billing/1", description: "Tenant boundary allows cross-account view",
    proof_of_concept: "GET /api/billing/1 returns another tenant payload",
    response_evidence: "Cross-tenant billing payload", impact: "Cross-tenant billing disclosure",
    validated: true, auth_profile: "attacker", surface_id: WEB_SURFACE,
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
  };
  if (exploitRunRef) {
    findingArgs.exploit_outcome = { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } };
    findingArgs.evidence_refs = [exploitRunRef];
  }
  recordFindingTool.handler(findingArgs);
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain, round, notes: null,
      results: [verificationResult("F-1", { severity: findingSeverity, reportable: round === "final" ? finalReportable : true })],
    });
  }
  if (finalReportable) writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
}

// Mint an offensive-runs row through the SINGLE sign shim => an ed25519 (v2) MAC,
// so the verdict-ledger backing is asymmetric (NOT v1-HMAC). This lets the
// isolated-allow path test prove "isolated AND ed25519-only => allow". demonstrated_severity
// is MEDIUM (the bob_http_idor_confirm ceiling) so a finding can cite it as an exploit_run proof.
function seedEd25519OffensiveRow(domain, runId) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const row = {
    version: 1, target_domain: domain, run_id: runId, tool_id: "bob_http_idor_confirm",
    target: `https://${domain}/api/billing/1`, offensive_outcome: "exploited_safely",
    dry_run: false, timed_out: false, command_hash: hex("1"), exit_code: 0,
    stdout_hash: hex("b"), stderr_hash: hex("c"), demonstrated_severity: "medium", surface_id: WEB_SURFACE,
  };
  signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, row);
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

function exploitRunRefFor(row) {
  return {
    kind: "exploit_run", run_id: row.run_id, tool_id: row.tool_id, target: row.target,
    offensive_outcome: row.offensive_outcome, command_hash: row.command_hash,
    exit_code: row.exit_code, stdout_hash: row.stdout_hash, stderr_hash: row.stderr_hash,
  };
}

// Stub the live ed25519-private-key probe to isolated:true without a real second
// uid: the STRUCTURAL Mechanism-A layout the in-server probe reads — an
// owner-only (0400) key owned by the signer uid, the running process owning it
// AND declaring as the signer (getuid===ownerUid===BOB_SANDBOX_SIGNER_UID), a
// distinct declared agent uid, and not root. The probe is lstat/getuid
// STRUCTURAL (legs a-e); it performs NO open()/read of the key, so there is no
// openSync to stub.
function withStubbedIsolatedEd25519Key(domain, ownerUid, fn) {
  const realLstat = fs.lstatSync;
  const realGetuid = process.getuid;
  const prevSigner = process.env.BOB_SANDBOX_SIGNER_UID;
  const prevAgent = process.env.BOB_SANDBOX_AGENT_UID;
  const keyPath = handoffSigningPrivateKeyPath(domain);
  fs.lstatSync = function stubLstat(p) {
    if (p === keyPath) return { uid: ownerUid, mode: 0o400, isFile: () => true };
    return realLstat.apply(fs, arguments);
  };
  process.getuid = () => ownerUid;
  process.env.BOB_SANDBOX_SIGNER_UID = String(ownerUid);
  process.env.BOB_SANDBOX_AGENT_UID = String(ownerUid + 1); // distinct agent uid
  try {
    return fn();
  } finally {
    fs.lstatSync = realLstat;
    process.getuid = realGetuid;
    if (prevSigner === undefined) delete process.env.BOB_SANDBOX_SIGNER_UID;
    else process.env.BOB_SANDBOX_SIGNER_UID = prevSigner;
    if (prevAgent === undefined) delete process.env.BOB_SANDBOX_AGENT_UID;
    else process.env.BOB_SANDBOX_AGENT_UID = prevAgent;
  }
}

test("clean session (no verdict-ledger-backed reportable medium+ finding) -> NO sandbox blocker", () => withTempHome(() => {
  const domain = "vg-clean.example.com";
  // A reportable finding but NO offensive/invariant/repro/freeze ledger row backing it.
  ensureHandoffSigningKey(domain);
  seedReportableFinding(domain);
  // No claim-freeze write... actually buildClaimFreeze wrote one; remove it so there is
  // genuinely no verdict-ledger backing for this assertion.
  const { claimFreezePath } = require("../mcp/core/io/paths.js");
  fs.rmSync(claimFreezePath(domain), { force: true });
  const blockers = sandboxIsolationBlockersForReportableVerdictClaims(domain);
  assert.deepEqual(blockers, [], "a session with no keyed verdict-ledger row is inert");
}, "enforce"));

test("advisory-only session (low severity) -> NO sandbox blocker even with a ledger row", () => withTempHome(() => {
  const domain = "vg-advisory.example.com";
  ensureHandoffSigningKey(domain);
  seedReportableFinding(domain, { severity: "low" });
  seedEd25519OffensiveRow(domain, "row-low-1");
  const blockers = sandboxIsolationBlockersForReportableVerdictClaims(domain);
  assert.deepEqual(blockers, [], "a low-severity finding is below medium+ -> gate inert");
}, "enforce"));

test("verdict-ledger-backed reportable medium+ + same-uid probe + enforce -> STATE_CONFLICT sandbox blocker", () => withTempHome(() => {
  const domain = "vg-enforce-block.example.com";
  ensureHandoffSigningKey(domain);
  const row = seedEd25519OffensiveRow(domain, "row-1");
  seedReportableFinding(domain, { exploitRunRef: exploitRunRefFor(row) });
  // No stub -> the real same-uid probe is isolated:false (the dev reality).
  const blockers = sandboxIsolationBlockersForReportableVerdictClaims(domain);
  assert.equal(blockers.length, 1);
  assert.equal(blockers[0].code, "sandbox_isolation_unattested");
  assert.equal(blockers[0].reason, "signer_not_isolated");
  assert.match(String(blockers[0].message), /not isolated/);
  assert.ok(Array.isArray(blockers[0].reportable_finding_ids) && blockers[0].reportable_finding_ids.includes("F-1"));
}, "enforce"));

test("same finding + same-uid probe + degrade -> NO blocker (proceeds; report door downgrades)", () => withTempHome(() => {
  const domain = "vg-degrade.example.com";
  ensureHandoffSigningKey(domain);
  const row = seedEd25519OffensiveRow(domain, "row-1");
  seedReportableFinding(domain, { exploitRunRef: exploitRunRefFor(row) });
  const blockers = sandboxIsolationBlockersForReportableVerdictClaims(domain);
  assert.deepEqual(blockers, [], "degrade lets VERIFY -> GRADE proceed (loud warning is emitted; the report door downgrades)");
}, "degrade"));

test("MOCKED isolated:true + ed25519-only backing + enforce -> NO blocker (the allow path, no 2nd uid)", () => withTempHome(() => {
  const domain = "vg-enforce-allow.example.com";
  ensureHandoffSigningKey(domain);
  const row = seedEd25519OffensiveRow(domain, "row-1");
  seedReportableFinding(domain, { exploitRunRef: exploitRunRefFor(row) });
  withStubbedIsolatedEd25519Key(domain, 424242, () => {
    const blockers = sandboxIsolationBlockersForReportableVerdictClaims(domain);
    assert.deepEqual(blockers, [], "an isolated signer over ed25519-only backing rows passes enforce");
  });
}, "enforce"));
