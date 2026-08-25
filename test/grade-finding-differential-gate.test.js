"use strict";

// Grade-time standalone-finding differential gate. A final-reportable medium+ standalone
// web finding (auth-bypass/IDOR/SSRF/business-logic/info-disclosure/races) must be backed
// by a verified_pass in finding-differential-verified.jsonl bound to its finding_id, else
// writeGradeVerdict fails closed (MINT != CONFIRM). Findings already covered by an existing
// executed producer (native repro-verified, SC invariant-verified, exploit_run-backed
// exploited_safely) verify IDENTICALLY (skipped). A finding lowered below medium is inert.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  buildClaimFreeze,
} = require("../mcp/core/claims/claim-freeze.js");
const {
  appendJsonlLine,
} = require("../mcp/core/io/storage.js");
const {
  reproVerifiedJsonlPath,
  invariantVerifiedJsonlPath,
  invariantRunsJsonlPath,
  findingDifferentialVerifiedJsonlPath,
  offensiveRunsJsonlPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const {
  computeInvariantRunHash,
  invariantFoundryResultHash,
  verifyInvariantDifferential,
} = require("../mcp/core/invariant-runner.js");
const {
  appendCandidateClaim,
  canonicalizeExploitTarget,
} = require("../mcp/core/claims/claims.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");
const {
  appendFrontierEvent,
} = require("../mcp/core/frontier/frontier-events.js");
const {
  ensureHandoffSigningKey,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  signOffensiveRunRow,
} = require("../mcp/core/ledger-integrity/index.js");
const recordFindingTool = require("../mcp/tools/record-candidate-claim.js");
const {
  writeVerificationRound,
} = require("../mcp/core/verification/verification-round-store.js");
const {
  writeEvidencePacks,
} = require("../mcp/core/evidence.js");
const {
  writeGradeVerdict,
} = require("../mcp/core/grade-verdict-store.js");
const { withIsolatedSigner } = require("./helpers/sandbox-isolated-signer.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/core/frontier/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-grade-fd-gate-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function hex(char) {
  return char.repeat(64);
}

const WEB_SURFACE = "surface:billing-profile";

function verificationResult(findingId, overrides = {}) {
  return {
    finding_id: findingId,
    disposition: "confirmed",
    severity: "high",
    reportable: true,
    reasoning: "Fresh replay confirmed the finding against the current target state.",
    ...overrides,
  };
}

function evidencePack(findingId, overrides = {}) {
  return {
    finding_id: findingId,
    sample_type: "cross-account replay",
    sample_count: 1,
    aggregate_counts: { affected_objects_sampled: 1 },
    representative_samples: [{
      request_ref: "http-audit:1",
      endpoint: "/api/billing/1",
      auth_profile: "attacker",
      status: 200,
      observed_fields: ["billing_profile_id", "email"],
      redacted_object_id: "acct_...002",
    }],
    sensitive_clusters: ["billing metadata"],
    replay_summary: "Fresh replay returned another tenant's private billing metadata.",
    redaction_notes: "Object IDs and personal values redacted; auth material omitted.",
    report_snippet: "An attacker can retrieve another tenant's private billing metadata by changing the billing profile ID.",
    ...overrides,
  };
}

function gradeFinding(findingId, overrides = {}) {
  return {
    finding_id: findingId,
    impact: 25,
    proof_quality: 20,
    severity_accuracy: 10,
    chain_potential: 10,
    report_quality: 10,
    total_score: 75,
    feedback: "Clear, reproducible, and reportable.",
    ...overrides,
  };
}

// A standalone web finding (manual IDOR) recorded via the dual-write tool, frozen, with
// the V1 round chain + evidence pack so it reaches the grade gate as final-reportable high.
function seedStandaloneWebFinding(domain, { severity = "high", reportable = true } = {}) {
  recordFindingTool.handler({
    target_domain: domain,
    title: "IDOR on billing profile",
    severity,
    cwe: "CWE-639",
    endpoint: "https://victim.example/api/billing/1",
    description: "Tenant boundary allows cross-account view",
    proof_of_concept: "GET /api/billing/1 returns another tenant payload",
    response_evidence: "Cross-tenant billing payload",
    impact: "Cross-tenant billing disclosure",
    validated: true,
    auth_profile: "attacker",
    surface_id: WEB_SURFACE,
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
  });
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain,
      round,
      notes: null,
      results: [verificationResult("F-1", { severity, reportable })],
    });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
}

// Seed a real MAC-signed flipping pair (exploited_safely positive + blocked_by_defense
// control, same surface, distinct command_hash) AND the verified_pass verdict line that
// binds them. Post-A1 the grade gate RE-RESOLVES the verdict against these MAC-covered
// rows + re-adjudicates the flip, so a bare ledger line no longer suffices. The positive
// row's demonstrated_severity (default high) is what B1's severity ceiling reads off the
// MAC-covered row, so it must be >= the finding's severity.
function seedOffensiveRow(domain, over = {}) {
  const row = {
    version: 1,
    target_domain: domain,
    run_id: over.run_id,
    tool_id: over.tool_id || "bob_http_idor_confirm",
    target: canonicalizeExploitTarget(over.target || `https://${domain}/api/billing/1`),
    offensive_outcome: over.offensive_outcome,
    dry_run: false,
    timed_out: false,
    command_hash: over.command_hash,
    exit_code: 0,
    stdout_hash: over.stdout_hash || hex("b"),
    stderr_hash: over.stderr_hash || hex("c"),
    demonstrated_severity: over.demonstrated_severity || "high",
    surface_id: over.surface_id || WEB_SURFACE,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

function seedFindingDifferentialArm(domain, findingId, {
  surfaceId = WEB_SURFACE,
  positiveSeverity = "high",
  positiveRunId = "fd-positive-1",
  controlRunId = "fd-control-1",
} = {}) {
  const positive = seedOffensiveRow(domain, {
    run_id: positiveRunId, offensive_outcome: "exploited_safely", command_hash: hex("1"),
    surface_id: surfaceId, demonstrated_severity: positiveSeverity,
  });
  const control = seedOffensiveRow(domain, {
    run_id: controlRunId, offensive_outcome: "blocked_by_defense", command_hash: hex("2"),
    surface_id: surfaceId, demonstrated_severity: positiveSeverity,
  });
  const { offensiveRowHash } = require("../mcp/core/differential/index.js");
  appendJsonlLine(findingDifferentialVerifiedJsonlPath(domain), {
    version: 1,
    target_domain: domain,
    finding_id: findingId,
    result: "verified_pass",
    reason: "executed_finding_differential_flip",
    surface_id: surfaceId,
    source: "offensive_runs",
    positive_run_id: positiveRunId,
    positive_row_hash: offensiveRowHash(positive),
    control_run_id: controlRunId,
    control_row_hash: offensiveRowHash(control),
  });
}

test("a standalone web finding with NO arm row fails the grade gate (STATE_CONFLICT)", () => withTempHome(() => withIsolatedSigner(() => {
  const domain = "fd-gate-noarm.example.com";
  seedStandaloneWebFinding(domain);
  assert.throws(
    () => writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    }),
    (err) => {
      assert.match(String(err.message), /Finding-differential verified_pass is required/);
      assert.match(String(err.message), /no_finding_differential_verified_pass/);
      return true;
    },
  );
})));

test("a standalone web finding WITH a verified_pass arm row grades SUBMIT and stays reportable", () => withTempHome(() => withIsolatedSigner(() => {
  const domain = "fd-gate-arm.example.com";
  seedStandaloneWebFinding(domain);
  seedFindingDifferentialArm(domain, "F-1");
  const written = JSON.parse(writeGradeVerdict({
    target_domain: domain,
    verdict: "SUBMIT",
    total_score: 75,
    findings: [gradeFinding("F-1")],
  }));
  assert.equal(written.verdict, "SUBMIT");
  assert.equal(written.findings_count, 1, "the arm keeps the finding in the reportable grade set");
})));

test("B1 surface bind: a verified_pass arm minted for surface B does NOT satisfy a finding whose surface is A (finding_differential_surface_mismatch)", () => withTempHome(() => withIsolatedSigner(() => {
  const domain = "fd-gate-surfacebind.example.com";
  seedStandaloneWebFinding(domain); // finding F-1 carries WEB_SURFACE
  // A genuine, re-derivable flip — but minted on a DIFFERENT surface.
  seedFindingDifferentialArm(domain, "F-1", { surfaceId: "surface:OTHER" });
  assert.throws(
    () => writeGradeVerdict({
      target_domain: domain, verdict: "SUBMIT", total_score: 75, findings: [gradeFinding("F-1")],
    }),
    (err) => {
      assert.match(String(err.message), /Finding-differential verified_pass is required/);
      assert.match(String(err.message), /finding_differential_surface_mismatch/);
      return true;
    },
  );
})));

test("B1 severity ceiling: a low/medium flip does NOT back a HIGH finding (finding_differential_severity_below_finding)", () => withTempHome(() => withIsolatedSigner(() => {
  const domain = "fd-gate-sevbelow.example.com";
  seedStandaloneWebFinding(domain, { severity: "high" }); // finding is HIGH
  // Same surface, genuine flip, but the executed flip only demonstrated MEDIUM.
  seedFindingDifferentialArm(domain, "F-1", { positiveSeverity: "medium" });
  assert.throws(
    () => writeGradeVerdict({
      target_domain: domain, verdict: "SUBMIT", total_score: 75, findings: [gradeFinding("F-1")],
    }),
    (err) => {
      assert.match(String(err.message), /finding_differential_severity_below_finding/);
      return true;
    },
  );
})));

test("B1 severity ceiling: a HIGH flip DOES back a HIGH finding (grades SUBMIT)", () => withTempHome(() => withIsolatedSigner(() => {
  const domain = "fd-gate-sevok.example.com";
  seedStandaloneWebFinding(domain, { severity: "high" });
  seedFindingDifferentialArm(domain, "F-1", { positiveSeverity: "high" });
  const written = JSON.parse(writeGradeVerdict({
    target_domain: domain, verdict: "SUBMIT", total_score: 75, findings: [gradeFinding("F-1")],
  }));
  assert.equal(written.verdict, "SUBMIT");
  assert.equal(written.findings_count, 1);
})));

test("a finding lowered below medium is inert (not in the reportable medium+ set)", () => withTempHome(() => {
  const domain = "fd-gate-low.example.com";
  seedStandaloneWebFinding(domain, { severity: "low" });
  // Low severity -> not in the final-reportable medium+ set -> the gate never fires; the
  // grade verdict reflects the no-reportable-medium outcome (SKIP).
  const written = JSON.parse(writeGradeVerdict({
    target_domain: domain,
    verdict: "SKIP",
    total_score: 75,
    findings: [gradeFinding("F-1")],
  }));
  assert.equal(written.verdict, "SKIP");
}));

// ---- EXISTING-PRODUCER REGRESSION: these verify IDENTICALLY (skipped by the new gate) ----
//
// The skip logic is exercised at the gate-function boundary
// (findingDifferentialGapForStandaloneReportableFindings) so the regression is isolated
// from the unrelated repo-session reachability-inventory gate the full writeGradeVerdict
// path applies to native surfaces. The gate must report NO missing arm for any finding
// already covered by an existing executed producer.

const {
  findingDifferentialGapForStandaloneReportableFindings,
} = require("../mcp/core/claims/claims.js");
const REPRO_COMMAND_ARGV = ["sh", "-lc", "./harness crash-input.bin"];

function observeSurface(domain, surfaceId, payload) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-27T00:00:00.000Z",
    surface_id: surfaceId,
    payload,
  });
}

function reportableMediumPlus(findingIds) {
  return {
    reportableFindingIds: new Set(findingIds),
    finalSeverities: new Map(findingIds.map((id) => [id, "high"])),
  };
}

// Seed a GENUINE invariant-verified verified_pass via a consistent flipping pair of
// invariant-runs rows minted through verifyInvariantDifferential. readInvariantVerifiedSummary
// re-adjudicates the verdict from these rows, so a hand-forged verdict line whose run hashes
// point at nothing would be excluded — this fixture is honest by construction.
function seedVerifiedInvariantPass(domain, findingId) {
  const base = {
    target_domain: domain,
    finding_id: findingId,
    finding_hash: null,
    template_id: "vault-invariant",
    slot_values: { a: "1" },
    contract_name: "VaultInvariantTest",
    function_name: "testVaultInvariant",
    execution_context_hash: "ctx-hash-shared",
    dry_run: false,
  };
  const mkRow = (outcome, treeRef, checkoutKind) => {
    const foundryResult = outcome === "test_failed"
      ? { tests: [{ success: false }] }
      : { tests: [{ success: true }] };
    const row = {
      ...base,
      tree_ref: treeRef,
      checkout_kind: checkoutKind,
      outcome,
      foundry_result_hash: invariantFoundryResultHash(foundryResult),
      foundry_result: foundryResult,
    };
    row.run_hash = computeInvariantRunHash(row);
    appendJsonlLine(invariantRunsJsonlPath(domain), row);
    return row;
  };
  const positive = mkRow("test_failed", "target", "tree");
  const control = mkRow("test_passed", "fixed", "upstream_fix");
  verifyInvariantDifferential({
    target_domain: domain,
    finding_id: findingId,
    positive_run_hash: positive.run_hash,
    control_run_hash: control.run_hash,
  });
}

test("a native finding with a repro-verified verified_pass needs NO finding-differential arm (skipped, regression)", () => withTempHome(() => {
  const domain = "fd-gate-native.example.com";
  const surfaceId = "repo:module:src-parser.c";
  observeSurface(domain, surfaceId, { kind: "code_module", language: "c" });
  const { repoCommandRunsJsonlPath } = require("../mcp/core/io/paths.js");
  appendJsonlLine(repoCommandRunsJsonlPath(domain), {
    run_id: "grade-repro-run-1", command_hash: "b".repeat(64), exit_code: 134,
    stdout_hash: "c".repeat(64), stderr_hash: "d".repeat(64), dry_run: false,
  });
  appendCandidateClaim({
    target_domain: domain,
    title: "Native parser over-read",
    summary: "Local file parser reads past the available buffer.",
    severity: "high",
    status: "candidate",
    surface_ids: [surfaceId],
    evidence_refs: [
      { kind: "finding", finding_id: "F-1", content_hash: "0".repeat(64) },
      {
        kind: "repo_command_run", run_id: "grade-repro-run-1", command_hash: "b".repeat(64),
        exit_code: 134, stdout_hash: "c".repeat(64), stderr_hash: "d".repeat(64),
      },
    ],
    impact: "Parser crash on crafted input.",
    payload: { finding: { id: "F-1", capability_pack: "oss_native_code", repro_command_argv: REPRO_COMMAND_ARGV } },
  });
  // NO finding-differential arm row; the native surface is owned by O-P4 -> skipped.
  const gap = findingDifferentialGapForStandaloneReportableFindings(domain, reportableMediumPlus(["F-1"]));
  assert.deepEqual(gap.missing, [], "native finding must be skipped by the standalone gate");
}));

test("a smart_contract finding with an invariant-verified verified_pass needs NO arm (skipped, regression)", () => withTempHome(() => {
  const domain = "fd-gate-sc.example.com";
  const surfaceId = "surface:vault-contract";
  observeSurface(domain, surfaceId, { kind: "smart_contract", language: "solidity" });
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
  seedVerifiedInvariantPass(domain, "F-1");
  const gap = findingDifferentialGapForStandaloneReportableFindings(domain, reportableMediumPlus(["F-1"]));
  assert.deepEqual(gap.missing, [], "SC finding with invariant-verified must be skipped");
}));

test("an SC finding WITHOUT an FV invariant-verified falls through to the standalone arm (RANK != BOUND, APPENDED node)", () => withTempHome(() => {
  const domain = "fd-gate-sc-noinvariant.example.com";
  const surfaceId = "surface:vault-no-fv";
  observeSurface(domain, surfaceId, { kind: "smart_contract", language: "solidity" });
  appendCandidateClaim({
    target_domain: domain,
    title: "Vault logic flaw (no FV harness)",
    summary: "A logic flaw with no constructible on-chain executed differential.",
    severity: "high",
    status: "candidate",
    surface_ids: [surfaceId],
    evidence_refs: [{ kind: "finding", finding_id: "F-1", content_hash: "0".repeat(64) }],
    impact: "Logic flaw.",
    payload: { finding: { id: "F-1" } },
  });
  // No invariant-verified row, no finding-differential arm -> the gate reports the gap,
  // so the finding caps to advisory (it is not silently dropped).
  const gap = findingDifferentialGapForStandaloneReportableFindings(domain, reportableMediumPlus(["F-1"]));
  assert.deepEqual(gap.missing, [{ finding_id: "F-1", reason: "no_finding_differential_verified_pass" }]);
}));

test("an exploit_run-backed exploited_safely finding needs NO arm (its offensive row is the executed binding, regression)", () => withTempHome(() => {
  const domain = "fd-gate-exploitrun.example.com";
  const surfaceId = "surface:reflected";
  const target = canonicalizeExploitTarget(`https://${domain}/search?q=BOB_CANARY_1`);
  const row = {
    version: 1, target_domain: domain, run_id: "run-exploit-1", tool_id: "bob_http_idor_confirm",
    target, offensive_outcome: "exploited_safely", dry_run: false, timed_out: false,
    command_hash: hex("a"), exit_code: 0, stdout_hash: hex("b"), stderr_hash: hex("c"),
    demonstrated_severity: "medium", surface_id: surfaceId,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  appendCandidateClaim({
    target_domain: domain,
    title: "Reflected canary exploited safely",
    summary: "A benign canary was reflected in the target response.",
    severity: "medium",
    status: "candidate",
    surface_ids: [surfaceId],
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "reflected_canary" } },
    evidence_refs: [
      { kind: "finding", finding_id: "F-1", content_hash: "0".repeat(64) },
      {
        kind: "exploit_run", run_id: "run-exploit-1", tool_id: "bob_http_idor_confirm",
        target, offensive_outcome: "exploited_safely", command_hash: hex("a"),
        exit_code: 0, stdout_hash: hex("b"), stderr_hash: hex("c"),
      },
    ],
    impact: "Reflected content.",
    payload: { finding: { id: "F-1" } },
  });
  // FREEZE the claim so the read-time skip resolves its exploited_safely class from the
  // hash-bound, audit-graded snapshot (not live claims.jsonl) and re-MAC-verifies the
  // cited offensive-runs row on the frozen surface.
  buildClaimFreeze(domain, { write: true });
  const gap = findingDifferentialGapForStandaloneReportableFindings(domain, {
    reportableFindingIds: new Set(["F-1"]),
    finalSeverities: new Map([["F-1", "medium"]]),
  });
  assert.deepEqual(gap.missing, [], "exploit_run-backed finding must be skipped");
}));
