"use strict";

// The grade-verdict WRITE door is the authoritative ALL-sessions sandbox-isolation
// gate. The lifecycle gateVerifyToGrade sandbox blocker is repo-only AND only
// reached when reachability also fails; this write-level gate closes the web/SC
// uniformity gap by refusing (enforce) or downgrading (degrade) a SUBMIT-as-
// reportable grade whenever a reportable medium+ finding draws on a keyed verdict
// ledger and the LIVE re-probe cannot prove the signer key is isolated. It reuses
// the SAME evaluateVerdictSandboxGate decision both verdict seams consume (no logic
// fork) and the live probe inside it (never the stored sandbox-isolation.json flag).

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
const { signOffensiveRunRow, OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/index.js");
const { writeGradeVerdict, readGradeVerdict } = require("../mcp/core/grade-verdict-store.js");
const { seedInvariantRunPair } = require("./helpers/invariant-run-seed.js");
const { verifyInvariantDifferential } = require("../mcp/core/invariant-runner.js");
const { appendJsonlLine } = require("../mcp/core/io/storage.js");
const { canonicalizeExploitTarget } = require("../mcp/core/claims/claims.js");
const { offensiveRowHash } = require("../mcp/core/differential/index.js");
const {
  offensiveRunsJsonlPath,
  findingDifferentialVerifiedJsonlPath,
  handoffSigningPrivateKeyPath,
  gradeArtifactPaths,
  sandboxIsolationPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const {
  SANDBOX_ATTESTATION_MODE_ENV,
  SANDBOX_ISOLATION_SCHEMA_VERSION,
} = require("../mcp/core/ledger-integrity/index.js");

function hex(char) { return char.repeat(64); }
const WEB_SURFACE = "surface:billing-profile";

function withTempHome(fn, mode) {
  const previousHome = process.env.HOME;
  const previousMode = process.env[SANDBOX_ATTESTATION_MODE_ENV];
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-grade-sandbox-"));
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

function gradeFinding(findingId) {
  return {
    finding_id: findingId, impact: 25, proof_quality: 20, severity_accuracy: 10,
    chain_potential: 10, report_quality: 10, total_score: 75, feedback: "Reportable.",
  };
}

// Seed a final-reportable HIGH web (IDOR) finding through the full chain. When an
// {exploitRunRef} is supplied, the finding CITES that keyed offensive-runs row via an
// exploit_run evidence_ref, so the finding is genuinely executed-verdict-backed (the
// per-finding keyed-ledger backing the sandbox gate intersects against) rather than
// relying on claim-freeze membership (which is NOT a per-finding backing leg — a finding
// whose only "backing" is freeze membership must not be gated).
function seedReportableFinding(domain, { exploitRunRef = null, severity = "high" } = {}) {
  ensureHandoffSigningKey(domain);
  const findingArgs = {
    target_domain: domain, title: "IDOR on billing profile", severity, cwe: "CWE-639",
    endpoint: "https://victim.example/api/billing/1", request_method: "GET", injection_point: "path:billing_id", description: "Tenant boundary allows cross-account view",
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
    writeVerificationRound({ target_domain: domain, round, notes: null, results: [verificationResult("F-1", { severity })] });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
}

// The exploit_run evidence_ref shape mirroring a seeded offensive-runs row so
// findingsBackedByKeyedLedger counts the finding as keyed-ledger-backed via its OWN cite.
function exploitRunRefFor(row) {
  return {
    kind: "exploit_run", run_id: row.run_id, tool_id: row.tool_id, target: row.target,
    offensive_outcome: row.offensive_outcome, command_hash: row.command_hash,
    exit_code: row.exit_code, stdout_hash: row.stdout_hash, stderr_hash: row.stderr_hash,
  };
}

// An ed25519 offensive row (the post-split asymmetric MAC) so only the isolation
// leg — not the legacy/v1-HMAC leg — is at issue for the web cases. demonstrated_severity
// defaults to "medium" (the bob_http_idor_confirm tool's demonstrated-severity ceiling) so
// a finding citing it as an exploit_run proof passes the proof ceiling gate.
function seedEd25519OffensiveRow(domain, { demonstratedSeverity = "medium" } = {}) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const row = {
    version: 1, target_domain: domain, run_id: "row-ed-1", tool_id: "bob_http_idor_confirm",
    target: `https://${domain}/api/billing/1`, offensive_outcome: "exploited_safely",
    dry_run: false, timed_out: false, command_hash: hex("1"), exit_code: 0,
    stdout_hash: hex("b"), stderr_hash: hex("c"), demonstrated_severity: demonstratedSeverity, surface_id: WEB_SURFACE,
  };
  signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, row);
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

// Seed an ed25519-only finding-differential arm: a flipping positive/control pair
// signed through the post-split shim plus the verified_pass row binding them, so a
// reportable standalone web finding satisfies the executed-flip grade gate WITHOUT
// minting any v1-HMAC offensive row (which would trip the sandbox legacy leg).
function seedEd25519FindingDifferentialArm(domain, findingId) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const mkRow = (runId, outcome, commandHash) => {
    const row = {
      version: 1, target_domain: domain, run_id: runId, tool_id: "bob_http_idor_confirm",
      target: canonicalizeExploitTarget(`https://${domain}/api/billing/1`),
      offensive_outcome: outcome, dry_run: false, timed_out: false,
      command_hash: commandHash, exit_code: 0, stdout_hash: hex("b"), stderr_hash: hex("c"),
      demonstrated_severity: "high", surface_id: WEB_SURFACE,
    };
    signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, row);
    fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
    return row;
  };
  const positive = mkRow("fd-positive-1", "exploited_safely", hex("1"));
  const control = mkRow("fd-control-1", "blocked_by_defense", hex("2"));
  appendJsonlLine(findingDifferentialVerifiedJsonlPath(domain), {
    version: 1, target_domain: domain, finding_id: findingId, result: "verified_pass",
    reason: "executed_finding_differential_flip", surface_id: WEB_SURFACE, source: "offensive_runs",
    positive_run_id: "fd-positive-1", positive_row_hash: offensiveRowHash(positive),
    control_run_id: "fd-control-1", control_row_hash: offensiveRowHash(control),
  });
}

// A v1-HMAC (legacy symmetric) offensive row — the laundering-risk class.
function seedV1HmacOffensiveRow(domain, { demonstratedSeverity = "medium" } = {}) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const row = {
    version: 1, target_domain: domain, run_id: "row-v1-1", tool_id: "bob_http_idor_confirm",
    target: `https://${domain}/api/billing/1`, offensive_outcome: "exploited_safely",
    dry_run: false, timed_out: false, command_hash: hex("1"), exit_code: 0,
    stdout_hash: hex("b"), stderr_hash: hex("c"), demonstrated_severity: demonstratedSeverity, surface_id: WEB_SURFACE,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain)); // v1 hmac envelope
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

// Stub the STRUCTURAL Mechanism-A isolated layout on the ed25519 private key: an
// owner-only (0400) key owned by the signer uid, the running process owning it
// AND declaring as the signer, a distinct declared agent uid, and not root. No
// openSync stub (the readability test is gone — the server reads its own key).
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
  process.env.BOB_SANDBOX_AGENT_UID = String(ownerUid + 1);
  try { return fn(); } finally {
    fs.lstatSync = realLstat;
    process.getuid = realGetuid;
    if (prevSigner === undefined) delete process.env.BOB_SANDBOX_SIGNER_UID;
    else process.env.BOB_SANDBOX_SIGNER_UID = prevSigner;
    if (prevAgent === undefined) delete process.env.BOB_SANDBOX_AGENT_UID;
    else process.env.BOB_SANDBOX_AGENT_UID = prevAgent;
  }
}

// Forge sandbox-isolation.json{attested:true} directly. The gate must ignore it.
function forgeAttestedFlag(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const forged = {
    schema_version: SANDBOX_ISOLATION_SCHEMA_VERSION,
    target_domain: domain,
    attested: true,
    recorded_at: new Date().toISOString(),
    probe: {
      key_present: true, owner_only_mode: true, owner_uid: 424242, process_uid: 424242,
      process_owns_key: true, process_is_signer: true, declared_signer_uid: 424242,
      declared_agent_uid: 1000, agent_distinct: true, not_root: true, isolated: true,
    },
    operator: { ack_present: true, declared_signer_uid: 424242 },
    platform: process.platform,
  };
  fs.writeFileSync(sandboxIsolationPath(domain), `${JSON.stringify(forged, null, 2)}\n`);
}

const gateModule = require("../mcp/core/verdict-sandbox-gate.js");
const { withIsolatedSigner } = require("./helpers/sandbox-isolated-signer.js");

test("withIsolatedSigner forces evaluateVerdictSandboxGate to decision:allow and restores the real function in finally", () => {
  const realGate = gateModule.evaluateVerdictSandboxGate;
  const observed = withIsolatedSigner(() => {
    const decision = gateModule.evaluateVerdictSandboxGate("anything.example.com");
    assert.equal(decision.applies, false);
    assert.equal(decision.decision, "allow");
    assert.equal(decision.isolated, true);
    return gateModule.evaluateVerdictSandboxGate;
  });
  assert.notEqual(observed, realGate, "the stub is in place inside the wrap");
  assert.equal(gateModule.evaluateVerdictSandboxGate, realGate, "the real gate function is restored after the wrap");
  // It must restore even when the body throws.
  try {
    withIsolatedSigner(() => { throw new Error("boom"); });
  } catch { /* expected */ }
  assert.equal(gateModule.evaluateVerdictSandboxGate, realGate, "the real gate function is restored even on throw");
});

test("enforce + same-uid + a web verdict-ledger-backed reportable finding -> writeGradeVerdict BLOCKS (grade.json not written)", () => withTempHome(() => {
  const domain = "grade-sandbox-web-block.example.com";
  const row = seedEd25519OffensiveRow(domain);
  seedReportableFinding(domain, { exploitRunRef: exploitRunRefFor(row), severity: "medium" });
  let err;
  try {
    writeGradeVerdict({ target_domain: domain, verdict: "SUBMIT", total_score: 75, findings: [gradeFinding("F-1")] });
  } catch (e) { err = e; }
  assert.ok(err, "a non-isolated same-uid box must refuse a reportable SUBMIT grade");
  assert.equal(err.code, "STATE_CONFLICT");
  assert.equal(err.details && err.details.code, "grade_sandbox_isolation_unattested");
  assert.equal(err.details.reason, "signer_not_isolated");
  assert.deepEqual(err.details.reportable_finding_ids, ["F-1"]);
  assert.equal(typeof err.remediation, "string");
  assert.equal(fs.existsSync(gradeArtifactPaths(domain).json), false, "grade.json must not be written under enforce block");
}, "enforce"));

test("enforce + same-uid + an SC invariant-runs verdict-ledger-backed reportable finding -> BLOCKS (door is NOT repo-only)", () => withTempHome(() => {
  const domain = "grade-sandbox-sc-block.example.com";
  // A keyed invariant-runs differential pair + a re-derivable verified_pass record back
  // the finding via the invariant verified summary (readInvariantVerifiedSummary's
  // verified_by_finding) — the smart-contract verdict-ledger backing leg, proving the
  // write-level door fires for non-web/non-repo backings too. This is a genuine executed
  // backing the finding draws on, NOT freeze membership.
  const { positive, control } = seedInvariantRunPair(domain, { findingId: "F-1", sign: true });
  verifyInvariantDifferential({
    target_domain: domain, finding_id: "F-1",
    positive_run_hash: positive.run_hash, control_run_hash: control.run_hash,
  });
  seedReportableFinding(domain);
  let err;
  try {
    writeGradeVerdict({ target_domain: domain, verdict: "SUBMIT", total_score: 75, findings: [gradeFinding("F-1")] });
  } catch (e) { err = e; }
  assert.ok(err, "an SC invariant-ledger-backed reportable SUBMIT grade must refuse on a same-uid box");
  assert.equal(err.code, "STATE_CONFLICT");
  assert.equal(err.details.code, "grade_sandbox_isolation_unattested");
  assert.equal(fs.existsSync(gradeArtifactPaths(domain).json), false, "grade.json must not be written");
}, "enforce"));

test("enforce + MOCKED isolated signer + ed25519-only backing -> writeGradeVerdict SUBMITs (grade.json written)", () => withTempHome(() => {
  const domain = "grade-sandbox-isolated-allow.example.com";
  seedReportableFinding(domain);
  seedEd25519FindingDifferentialArm(domain, "F-1");
  withStubbedIsolatedEd25519Key(domain, 424242, () => {
    const written = JSON.parse(writeGradeVerdict({
      target_domain: domain, verdict: "SUBMIT", total_score: 75, findings: [gradeFinding("F-1")],
    }));
    assert.equal(written.verdict, "SUBMIT");
    assert.equal(written.findings_count, 1);
    assert.equal(written.sandbox_downgrade, undefined, "an isolated signer records no downgrade annotation");
  });
  assert.equal(fs.existsSync(gradeArtifactPaths(domain).json), true, "grade.json is written for an isolated signer");
}, "enforce"));

test("degrade + same-uid -> grade.json IS written but carries the sandbox_downgrade annotation + a loud warning", () => withTempHome(() => {
  const domain = "grade-sandbox-degrade.example.com";
  seedReportableFinding(domain);
  seedEd25519FindingDifferentialArm(domain, "F-1");
  const written = JSON.parse(writeGradeVerdict({
    target_domain: domain, verdict: "SUBMIT", total_score: 75, findings: [gradeFinding("F-1")],
  }));
  assert.equal(written.verdict, "SUBMIT");
  assert.ok(written.sandbox_downgrade, "degrade records a durable downgrade annotation, never silent");
  assert.equal(written.sandbox_downgrade.downgraded, true);
  assert.equal(written.sandbox_downgrade.reason, "signer_not_isolated");
  assert.deepEqual(written.sandbox_downgrade.reportable_finding_ids, ["F-1"]);
  assert.match(written.sandbox_downgrade.warning, /SANDBOX ISOLATION/);
  assert.equal(fs.existsSync(gradeArtifactPaths(domain).json), true, "grade.json IS written under degrade");
  // The annotation survives read-back so a downstream grader sees the advisory-trust stamp.
  const readBack = JSON.parse(readGradeVerdict({ target_domain: domain }));
  assert.ok(readBack.sandbox_downgrade, "the downgrade annotation survives normalizeGradeVerdictDocument read-back");
  assert.equal(readBack.sandbox_downgrade.downgraded, true);
  assert.equal(readBack.sandbox_downgrade.reason, "signer_not_isolated");
}, "degrade"));

test("clean grade (no reportable medium+ finding) on a same-uid box under enforce -> unaffected (RANK != BOUND)", () => withTempHome(() => {
  const domain = "grade-sandbox-clean-skip.example.com";
  // A LOW finding: not in the reportable medium+ set, so the gate is inert; the
  // grader correctly writes SKIP. No verdict-ledger row is even seeded.
  ensureHandoffSigningKey(domain);
  recordFindingTool.handler({
    target_domain: domain, title: "Low-signal info leak", severity: "low", cwe: "CWE-200",
    endpoint: "https://victim.example/api/info", description: "Low impact info disclosure",
    proof_of_concept: "GET /api/info", response_evidence: "Minor metadata", impact: "Low",
    validated: true, auth_profile: "attacker", surface_id: WEB_SURFACE,
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "low" },
  });
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain, round, notes: null,
      results: [verificationResult("F-1", { severity: "low", reportable: true })],
    });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
  const written = JSON.parse(writeGradeVerdict({
    target_domain: domain, verdict: "SKIP", total_score: 75, findings: [gradeFinding("F-1")],
  }));
  assert.equal(written.verdict, "SKIP");
  assert.equal(written.sandbox_downgrade, undefined, "a clean grade is byte-identical (no annotation)");
  assert.equal(fs.existsSync(gradeArtifactPaths(domain).json), true, "a clean grade is written untouched");
}, "enforce"));

test("live re-probe drives it: a forged sandbox-isolation.json{attested:true} on a same-uid box under enforce still BLOCKS", () => withTempHome(() => {
  const domain = "grade-sandbox-forged-flag.example.com";
  const row = seedEd25519OffensiveRow(domain);
  seedReportableFinding(domain, { exploitRunRef: exploitRunRefFor(row), severity: "medium" });
  forgeAttestedFlag(domain);
  let err;
  try {
    writeGradeVerdict({ target_domain: domain, verdict: "SUBMIT", total_score: 75, findings: [gradeFinding("F-1")] });
  } catch (e) { err = e; }
  assert.ok(err, "the forged file flag is ignored; the live openSync->EACCES probe is the truth");
  assert.equal(err.details.code, "grade_sandbox_isolation_unattested");
  assert.equal(err.details.reason, "signer_not_isolated");
  assert.equal(fs.existsSync(gradeArtifactPaths(domain).json), false, "grade.json must not be written despite the forged flag");
}, "enforce"));

test("enforce + MOCKED isolated signer but a v1-HMAC backing row -> BLOCK (legacy_or_v1_hmac_row_backs_new_claim) parity with the compose door", () => withTempHome(() => {
  const domain = "grade-sandbox-v1hmac-block.example.com";
  const row = seedV1HmacOffensiveRow(domain);
  seedReportableFinding(domain, { exploitRunRef: exploitRunRefFor(row), severity: "medium" });
  withStubbedIsolatedEd25519Key(domain, 424242, () => {
    let err;
    try {
      writeGradeVerdict({ target_domain: domain, verdict: "SUBMIT", total_score: 75, findings: [gradeFinding("F-1")] });
    } catch (e) { err = e; }
    assert.ok(err, "a v1-HMAC row cannot back a NEW reportable grade even on an isolated signer");
    assert.equal(err.details.code, "grade_sandbox_isolation_unattested");
    assert.equal(err.details.reason, "legacy_or_v1_hmac_row_backs_new_claim");
    assert.equal(fs.existsSync(gradeArtifactPaths(domain).json), false, "grade.json must not be written");
  });
}, "enforce"));
