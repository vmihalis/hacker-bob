"use strict";

// RANK != BOUND, applied PER FINDING. evaluateVerdictSandboxGate must gate ONLY the
// reportable medium+ findings whose OWN evidence cites a keyed verdict-ledger row
// (an exploit_run / repo_command_run ref, an invariant/finding-differential
// verified_pass, or the current keyed claim-freeze). A pure-OSINT reportable finding
// — its claim cites only finding/http_audit refs and is NOT in a keyed freeze — must
// be UNAFFECTED even when an UNRELATED finding wrote an offensive-runs row. The old
// gate keyed `applies` off (reportable.size>0 AND any-ledger-row-present), which
// over-bounded: an unrelated ledger row blocked/downgraded the whole reportable set.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const recordFindingTool = require("../mcp/tools/record-candidate-claim.js");
const { writeVerificationRound } = require("../mcp/core/verification/verification-round-store.js");
const { writeEvidencePacks } = require("../mcp/core/evidence.js");
const { buildClaimFreeze } = require("../mcp/core/claims/claim-freeze.js");
const {
  ensureHandoffSigningKey,
  signRowViaIsolatedSignerOrLocal,
} = require("../mcp/core/ledger-integrity/index.js");
const { OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/index.js");
const {
  evaluateVerdictSandboxGate,
  findingsBackedByKeyedLedger,
  sandboxDowngradeWarning,
  emitSandboxDowngradeWarning,
  SANDBOX_REMEDIATION,
} = require("../mcp/core/verdict-sandbox-gate.js");
const {
  offensiveRunsJsonlPath,
  claimsJsonlPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const { SANDBOX_ATTESTATION_MODE_ENV } = require("../mcp/core/ledger-integrity/index.js");

function hex(char) { return char.repeat(64); }
const KEYED_SURFACE = "surface:billing-profile";
const OSINT_SURFACE = "surface:public-exposure";

function withTempHome(fn, mode) {
  const previousHome = process.env.HOME;
  const previousMode = process.env[SANDBOX_ATTESTATION_MODE_ENV];
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sandbox-rank-"));
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
    finding_id: findingId, disposition: "confirmed", severity: "medium", reportable: true,
    reasoning: "Fresh replay confirmed the finding against the current target state.",
    ...overrides,
  };
}

function evidencePack(findingId, endpoint) {
  return {
    finding_id: findingId, sample_type: "cross-account replay", sample_count: 1,
    aggregate_counts: { affected_objects_sampled: 1 },
    representative_samples: [{
      request_ref: "http-audit:1", endpoint, auth_profile: "attacker",
      status: 200, observed_fields: ["object_id"], redacted_object_id: "acct_...002",
    }],
    sensitive_clusters: ["billing metadata"],
    replay_summary: "Fresh replay returned another tenant's private metadata.",
    redaction_notes: "Object IDs redacted.",
    report_snippet: "An attacker can retrieve another tenant's private metadata.",
  };
}

// Mint a MAC-valid ed25519 offensive-runs row and return the field bundle an
// exploit_run evidence_ref must mirror so offensiveRunRowSatisfiesEvidence matches.
function seedOffensiveRow(domain, runId) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const target = `https://${domain}/api/billing/1`;
  const row = {
    version: 1, target_domain: domain, run_id: runId, tool_id: "bob_http_idor_confirm",
    target, offensive_outcome: "exploited_safely",
    dry_run: false, timed_out: false, command_hash: hex("1"), exit_code: 0,
    stdout_hash: hex("b"), stderr_hash: hex("c"), demonstrated_severity: "medium", surface_id: KEYED_SURFACE,
  };
  signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, row);
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

// F-1: a reportable MEDIUM finding whose claim carries an exploit_run evidence_ref
// backed by the seeded offensive-runs row => keyed-ledger-backed.
function recordKeyedFinding(domain, row) {
  recordFindingTool.handler({
    target_domain: domain, title: "IDOR on billing profile", severity: "medium", cwe: "CWE-639",
    endpoint: row.target, description: "Tenant boundary allows cross-account view",
    proof_of_concept: "GET /api/billing/1 returns another tenant payload",
    response_evidence: "Cross-tenant billing payload", impact: "Cross-tenant billing disclosure",
    validated: true, auth_profile: "attacker", surface_id: KEYED_SURFACE,
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
    evidence_refs: [{
      kind: "exploit_run",
      run_id: row.run_id,
      tool_id: row.tool_id,
      target: row.target,
      offensive_outcome: "exploited_safely",
      command_hash: row.command_hash,
      exit_code: row.exit_code,
      stdout_hash: row.stdout_hash,
      stderr_hash: row.stderr_hash,
    }],
  });
}

// F-2: a reportable MEDIUM pure-OSINT finding. No exploit_run ref, no offensive row
// of its own, and (the test writes no claim-freeze) NOT freeze-backed => unbacked.
function recordOsintFinding(domain) {
  recordFindingTool.handler({
    target_domain: domain, title: "Sensitive endpoint indexed publicly", severity: "medium", cwe: "CWE-200",
    endpoint: `https://${domain}/exposed/config`, description: "A config endpoint is reachable without auth",
    proof_of_concept: "GET /exposed/config returns service metadata",
    response_evidence: "Public service metadata payload", impact: "Public information disclosure",
    validated: true, auth_profile: "anonymous", surface_id: OSINT_SURFACE,
    cvss_inputs: { attack_vector: "network", privileges_required: "none", confidentiality: "low" },
  });
}

function seedTwoFindings(domain) {
  ensureHandoffSigningKey(domain);
  const row = seedOffensiveRow(domain, "row-keyed-1");
  recordKeyedFinding(domain, row); // F-1 (keyed)
  recordOsintFinding(domain); // F-2 (OSINT)
  // Final-round reportable for BOTH (reportability comes from the verification round,
  // not the freeze). No claim-freeze is written, so the OSINT finding has no keyed
  // backing of any kind.
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain, round, notes: null,
      results: [verificationResult("F-1"), verificationResult("F-2")],
    });
  }
  writeEvidencePacks({
    target_domain: domain,
    packs: [
      evidencePack("F-1", `https://${domain}/api/billing/1`),
      evidencePack("F-2", `https://${domain}/exposed/config`),
    ],
  });
}

test("findingsBackedByKeyedLedger returns ONLY the exploit_run-backed finding", () => withTempHome(() => {
  const domain = "rank-helper.example.com";
  seedTwoFindings(domain);
  const backed = findingsBackedByKeyedLedger(domain, new Set(["F-1", "F-2"]));
  assert.deepEqual([...backed].sort(), ["F-1"], "only F-1 (exploit_run ref) is keyed-ledger-backed");
}));

for (const mode of ["enforce", "degrade"]) {
  test(`same-uid box: only the keyed-ledger-backed finding is gated; OSINT is untouched (${mode})`, () => withTempHome(() => {
    const domain = `rank-${mode}.example.com`;
    seedTwoFindings(domain);
    // No structural stub: the same-uid box probes isolated:false -> block/downgrade.
    const decision = evaluateVerdictSandboxGate(domain);
    assert.equal(decision.applies, true, "a keyed-ledger-backed reportable medium+ finding makes the gate apply");
    assert.equal(decision.isolated, false, "the same-uid dev box is not isolated");
    assert.equal(decision.decision, mode === "enforce" ? "block" : "downgrade");
    assert.deepEqual(
      [...decision.reportable_finding_ids].sort(),
      ["F-1"],
      "ONLY F-1 (keyed-ledger-backed) is gated; the pure-OSINT F-2 is NOT blocked/downgraded",
    );
  }, mode));
}

// MEDIUM B regression: the claim-freeze freezes EVERY candidate claim (buildClaimFreeze
// -> readCandidateClaims, no backing filter), so by grade/compose time the freeze contains
// BOTH F-1's and F-2's claims. The OLD gate counted freeze membership as backing, which
// collapsed the per-finding intersection -> the pure-OSINT F-2 leaked into the gated set.
// After removing the freeze-membership leg, F-2 must STILL be excluded from `backed` (and
// from reportable_finding_ids) even though the freeze contains its claim. This is the case
// the original test omitted (it wrote no freeze), so the leak was source-only.
function seedTwoFindingsWithFreeze(domain) {
  ensureHandoffSigningKey(domain);
  const row = seedOffensiveRow(domain, "row-keyed-frozen-1");
  recordKeyedFinding(domain, row); // F-1 (keyed exploit_run)
  recordOsintFinding(domain); // F-2 (pure OSINT)
  // KEY the freeze AFTER both claims are recorded, so the freeze contains BOTH claims —
  // reproducing the brutalist's collapse condition.
  buildClaimFreeze(domain, { write: true, now: new Date("2026-06-01T00:00:00.000Z") });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain, round, notes: null,
      results: [verificationResult("F-1"), verificationResult("F-2")],
    });
  }
  writeEvidencePacks({
    target_domain: domain,
    packs: [
      evidencePack("F-1", `https://${domain}/api/billing/1`),
      evidencePack("F-2", `https://${domain}/exposed/config`),
    ],
  });
}

test("freeze containing BOTH claims does NOT mark the pure-OSINT finding backed (RANK != BOUND holds)", () => withTempHome(() => {
  const domain = "rank-freeze-collapse.example.com";
  seedTwoFindingsWithFreeze(domain);
  const backed = findingsBackedByKeyedLedger(domain, new Set(["F-1", "F-2"]));
  assert.deepEqual(
    [...backed].sort(), ["F-1"],
    "F-2's claim is in the freeze, but freeze membership is NOT a backing leg -> only F-1 is backed",
  );
}));

for (const mode of ["enforce", "degrade"]) {
  test(`freeze containing BOTH claims: only the executed-backed finding is gated (${mode})`, () => withTempHome(() => {
    const domain = `rank-freeze-${mode}.example.com`;
    seedTwoFindingsWithFreeze(domain);
    const decision = evaluateVerdictSandboxGate(domain);
    assert.equal(decision.applies, true, "F-1 (executed-backed) makes the gate apply");
    assert.equal(decision.decision, mode === "enforce" ? "block" : "downgrade");
    assert.deepEqual(
      [...decision.reportable_finding_ids].sort(), ["F-1"],
      "ONLY F-1 is gated; the pure-OSINT F-2 is NOT gated even though its claim is frozen",
    );
  }, mode));
}

test("pure-OSINT-only session with an UNRELATED ledger row present -> gate INERT (applies:false)", () => withTempHome(() => {
  const domain = "rank-osint-only.example.com";
  ensureHandoffSigningKey(domain);
  // An offensive-runs row exists (an UNRELATED finding produced it), but the ONLY
  // reportable finding is pure-OSINT and cites no keyed-ledger row.
  seedOffensiveRow(domain, "row-unrelated-1");
  recordOsintFinding(domain); // F-1 (OSINT)
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain, round, notes: null, results: [verificationResult("F-1")],
    });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1", `https://${domain}/exposed/config`)] });
  const decision = evaluateVerdictSandboxGate(domain);
  assert.equal(decision.applies, false, "no reportable finding is keyed-ledger-backed -> gate inert");
  assert.equal(decision.reason, "no_verdict_ledger_backing");
  assert.deepEqual(decision.reportable_finding_ids, [], "nothing is gated");
}, "enforce"));

// M1: findingsBackedByKeyedLedger must FAIL CLOSED on INDETERMINATE backing. A
// reportable medium+ finding that reached the final-verification projection but
// whose claim cannot be resolved in EITHER claim index has UNKNOWN backing. Every
// other leg of the verdict gate fails closed (not-isolated, legacy/v1 laundering
// risk); the indeterminate case must too — it is GATED (added to `backed`), NOT
// silently allowed. The previous `if (!claim) continue;` let an unresolvable-claim
// finding escape the gate while everything around it failed closed.
//
// CONSTRUCTION: reportableMediumPlusFindingIds reads the final verification round
// JSON + the claim FREEZE (reclampSeveritiesAgainstFreeze reads readCurrentClaimFreeze,
// NOT claims.jsonl), while findingsBackedByKeyedLedger builds claimByFinding from
// readCandidateClaims (which reads claims.jsonl). Truncating claims.jsonl AFTER the
// freeze/rounds are written leaves F-1 REPORTABLE but makes its claim UNRESOLVABLE —
// the exact indeterminate-backing case. (The resolvable pure-OSINT exclusion proven
// above guarantees this fail-closed flip never over-gates a finding that DID resolve.)
function seedKeyedFindingThenStripClaim(domain) {
  ensureHandoffSigningKey(domain);
  const row = seedOffensiveRow(domain, "row-keyed-strip-1");
  recordKeyedFinding(domain, row); // F-1 (keyed exploit_run)
  buildClaimFreeze(domain, { write: true, now: new Date("2026-06-01T00:00:00.000Z") });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain, round, notes: null, results: [verificationResult("F-1")],
    });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1", row.target)] });
  // Make F-1's claim UNRESOLVABLE: truncate claims.jsonl. The freeze still resolves
  // F-1 for the reportable projection; readCandidateClaims returns []. No
  // differential/invariant summary was written, so backing is INDETERMINATE.
  fs.writeFileSync(claimsJsonlPath(domain), "");
}

test("M1: findingsBackedByKeyedLedger fails CLOSED on an unresolvable claim WHEN a keyed ledger is present", () => withTempHome(() => {
  const domain = "rank-indeterminate-helper.example.com";
  seedKeyedFindingThenStripClaim(domain); // seeds an offensive-runs row -> ledgerPresent
  const backedPresent = findingsBackedByKeyedLedger(domain, new Set(["F-1"]), { ledgerPresent: true });
  assert.deepEqual([...backedPresent], ["F-1"], "an unresolvable claim over a LIVE keyed ledger fails CLOSED into backed");
  // The other side of the conditional: with NO keyed ledger row in the session
  // (ledgerPresent false), an unresolvable-claim finding is verification-round-only
  // and stays UNGATED — nothing to launder. This is the clean-session inert case.
  const backedAbsent = findingsBackedByKeyedLedger(domain, new Set(["F-1"]), { ledgerPresent: false });
  assert.deepEqual([...backedAbsent], [], "with no keyed ledger present, an unresolvable claim is NOT gated (inert)");
}));

for (const mode of ["enforce", "degrade"]) {
  test(`M1: an indeterminate-backing reportable medium+ finding is GATED -> ${mode === "enforce" ? "block" : "downgrade"} (${mode})`, () => withTempHome(() => {
    const domain = `rank-indeterminate-${mode}.example.com`;
    seedKeyedFindingThenStripClaim(domain);
    const decision = evaluateVerdictSandboxGate(domain);
    assert.equal(decision.applies, true, "an indeterminate-backing reportable finding makes the gate apply (fail closed)");
    assert.equal(decision.isolated, false, "the same-uid dev box is not isolated");
    assert.equal(decision.reason, "signer_not_isolated");
    assert.equal(decision.decision, mode === "enforce" ? "block" : "downgrade");
    assert.deepEqual([...decision.reportable_finding_ids], ["F-1"], "the indeterminate finding is gated");
  }, mode));
}

// M3 (degrade is NEVER silent): the gate's degrade path must emit a LOUD, legible
// warning AND return it so a headless harness that discards stderr still sees the
// downgrade in the structured channel the caller folds into its artifact. Exercised
// directly against the warning builders, capturing process.stderr.write with a
// leak-safe stub (restored in finally, scoped per test).
function degradeDecision(overrides = {}) {
  return Object.freeze({
    applies: true, mode: "degrade", mode_defaulted: false, isolated: false, attested: false,
    has_legacy_or_v1: false, reportable_finding_ids: ["F-1", "F-2"],
    decision: "downgrade", reason: "signer_not_isolated", probe: null, ...overrides,
  });
}

function captureStderr(fn) {
  const realWrite = process.stderr.write;
  const lines = [];
  process.stderr.write = (chunk) => {
    lines.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    return true;
  };
  try {
    fn(lines);
  } finally {
    process.stderr.write = realWrite;
  }
  return lines;
}

test("M3: sandboxDowngradeWarning builds a loud warning naming count + reason + remediation", () => {
  const message = sandboxDowngradeWarning(degradeDecision(), "bob_compose_report:");
  assert.match(message, /SANDBOX ISOLATION UNATTESTED/, "names the unattested posture");
  assert.match(message, /bob_compose_report:/, "carries the caller context");
  assert.match(message, /downgrading 2 verdict-ledger-backed reportable medium\+ finding\(s\) to advisory/, "names the gated count");
  assert.match(message, /mode=degrade/);
  assert.match(message, /reason=signer_not_isolated/);
  assert.ok(message.includes(SANDBOX_REMEDIATION), "carries the remediation guidance");
});

test("M3: emitSandboxDowngradeWarning writes the warning to stderr AND returns it (never silent)", () => {
  let returned;
  const lines = captureStderr(() => {
    returned = emitSandboxDowngradeWarning(degradeDecision(), "bob_write_grade_verdict:");
  });
  assert.equal(lines.length, 1, "exactly one stderr line is emitted");
  assert.match(lines[0], /SANDBOX ISOLATION UNATTESTED/, "the stderr line is the loud warning");
  assert.match(lines[0], /bob_write_grade_verdict:/);
  assert.ok(lines[0].endsWith("\n"), "the stderr line is newline-terminated");
  assert.equal(`${returned}\n`, lines[0], "the returned message equals the stderr line (minus newline)");
});

test("M3: the legacy/v1-HMAC laundering reason renders DEGRADED (not UNATTESTED)", () => {
  const message = sandboxDowngradeWarning(
    degradeDecision({ has_legacy_or_v1: true, reason: "legacy_or_v1_hmac_row_backs_new_claim" }),
    "bob_compose_report:",
  );
  assert.match(message, /SANDBOX ISOLATION DEGRADED/, "the laundering-risk reason renders DEGRADED");
  assert.match(message, /reason=legacy_or_v1_hmac_row_backs_new_claim/);
});
