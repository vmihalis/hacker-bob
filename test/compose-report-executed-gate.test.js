"use strict";

// EXECUTED-FLIP gate at the report door. bob_compose_report must enforce the SAME
// non-forgeability spine as the grade gate: a final-reportable MEDIUM+ finding must carry
// an EXECUTED differential whose negative control flips, exactly as writeGradeVerdict
// decides. A forged reportable verification round (reportable:true is a forgeable boolean)
// can no longer launder a bob_verified medium+ vulnerability into the audit-graded
// report.md without a re-derivable verified_pass arm. Below-medium / non-vulnerability
// (operator_osint/external_research) sections render regardless (RANK != BOUND at the
// report layer), and native(O-P4)/SC-invariant/exploit_run-backed findings render
// identically (skip parity with the grade gate).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const composeReportTool = require("../mcp/tools/compose-report.js");
const recordFindingTool = require("../mcp/tools/record-candidate-claim.js");
const { buildClaimFreeze } = require("../mcp/core/claims/claim-freeze.js");
const { writeVerificationRound } = require("../mcp/core/verification/verification-round-store.js");
const { writeEvidencePacks } = require("../mcp/core/evidence.js");
const { appendJsonlLine } = require("../mcp/core/io/storage.js");
const { appendCandidateClaim, canonicalizeExploitTarget } = require("../mcp/core/claims/claims.js");
const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { ensureHandoffSigningKey } = require("../mcp/core/ledger-integrity/index.js");
const { signOffensiveRunRow } = require("../mcp/core/ledger-integrity/index.js");
const { offensiveRowHash } = require("../mcp/core/differential/index.js");
const {
  findingDifferentialVerifiedJsonlPath,
  invariantVerifiedJsonlPath,
  offensiveRunsJsonlPath,
  reportMarkdownPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/core/frontier/frontier-materialize-debounce.js");
const { withIsolatedSigner } = require("./helpers/sandbox-isolated-signer.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-compose-executed-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function hex(char) { return char.repeat(64); }
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

function evidencePack(findingId) {
  return {
    finding_id: findingId,
    sample_type: "cross-account replay",
    sample_count: 1,
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

// A standalone web finding (manual IDOR), frozen + V1 round chain + evidence pack so it
// reaches the report gate as final-reportable.
function seedStandaloneWebFinding(domain, { severity = "high", reportable = true, finalReportable = reportable, rounds = ["brutalist", "balanced", "final"] } = {}) {
  recordFindingTool.handler({
    target_domain: domain,
    title: "IDOR on billing profile",
    severity,
    cwe: "CWE-639",
    endpoint: "https://victim.example/api/billing/1",
    request_method: "GET",
    injection_point: "path:billing_id",
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
  for (const round of rounds) {
    writeVerificationRound({
      target_domain: domain, round, notes: null,
      results: [verificationResult("F-1", { severity, reportable: round === "final" ? finalReportable : reportable })],
    });
  }
  // The evidence-pack writer requires a reportable FINAL round; the laundering cases
  // (final reportable:false, or no final round at all) intentionally lack one.
  if (rounds.includes("final") && finalReportable) {
    writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
  }
}

function seedOffensiveRow(domain, over) {
  const row = {
    version: 1, target_domain: domain, run_id: over.run_id, tool_id: "bob_http_idor_confirm",
    target: canonicalizeExploitTarget(`https://${domain}/api/billing/1`),
    offensive_outcome: over.offensive_outcome, dry_run: false, timed_out: false,
    command_hash: over.command_hash, exit_code: 0, stdout_hash: hex("b"), stderr_hash: hex("c"),
    demonstrated_severity: over.demonstrated_severity || "high", surface_id: WEB_SURFACE,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

// A genuine, re-derivable finding-differential verified_pass arm (real MAC-signed
// flipping rows + the verdict line that binds them).
function seedFindingDifferentialArm(domain, findingId) {
  const positive = seedOffensiveRow(domain, { run_id: "fd-positive-1", offensive_outcome: "exploited_safely", command_hash: hex("1") });
  const control = seedOffensiveRow(domain, { run_id: "fd-control-1", offensive_outcome: "blocked_by_defense", command_hash: hex("2") });
  appendJsonlLine(findingDifferentialVerifiedJsonlPath(domain), {
    version: 1, target_domain: domain, finding_id: findingId, result: "verified_pass",
    reason: "executed_finding_differential_flip", surface_id: WEB_SURFACE, source: "offensive_runs",
    positive_run_id: "fd-positive-1", positive_row_hash: offensiveRowHash(positive),
    control_run_id: "fd-control-1", control_row_hash: offensiveRowHash(control),
  });
}

function verifiedSections() {
  return [{
    kind: "impact",
    heading: "Impact",
    prose: "An attacker can read another tenant's billing profile.",
    provenance: "bob_verified",
    evidence_refs: ["verification_round:final:F-1"],
  }];
}

function osintSections() {
  return [{
    kind: "impact", heading: "Background", prose: "Public OSINT note.",
    provenance: "operator_osint", evidence_refs: [],
  }];
}

test("a bob_verified MEDIUM+ section for a final-reportable finding with NO executed arm is REJECTED (even with reportable:true)", () => withTempHome(() => withIsolatedSigner(() => {
  const domain = "compose-exec-noarm.example.com";
  seedStandaloneWebFinding(domain);
  assert.throws(
    () => composeReportTool.handler({ target_domain: domain, sections: verifiedSections() }),
    (err) => {
      assert.equal(err.code, "STATE_CONFLICT");
      assert.match(String(err.message), /executed-flip binding/);
      assert.match(String(err.message), /no_finding_differential_verified_pass/);
      return true;
    },
  );
  assert.equal(fs.existsSync(reportMarkdownPath(domain)), false, "report.md must not be written on a rejected compose");
})));

test("the SAME finding WITH a genuine re-derivable verified_pass arm RENDERS", () => withTempHome(() => withIsolatedSigner(() => {
  const domain = "compose-exec-arm.example.com";
  seedStandaloneWebFinding(domain);
  seedFindingDifferentialArm(domain, "F-1");
  const out = JSON.parse(composeReportTool.handler({ target_domain: domain, sections: verifiedSections() }));
  assert.equal(out.sections_rendered, 1);
  assert.ok(fs.existsSync(reportMarkdownPath(domain)), "report.md is written when the executed flip is present");
})));

test("a low-severity finding renders regardless (RANK != BOUND at the report layer)", () => withTempHome(() => {
  const domain = "compose-exec-low.example.com";
  // Low severity -> not in the reportable medium+ set -> the executed gate never fires.
  seedStandaloneWebFinding(domain, { severity: "low" });
  const out = JSON.parse(composeReportTool.handler({ target_domain: domain, sections: osintSections() }));
  assert.equal(out.sections_rendered, 1);
}));

test("an operator_osint section renders regardless of any executed arm (non-vuln provenance untouched)", () => withTempHome(() => withIsolatedSigner(() => {
  const domain = "compose-exec-osint.example.com";
  seedStandaloneWebFinding(domain); // high + reportable, but NO arm...
  // ...yet the section is operator_osint (not bob_verified). The executed gate inspects
  // the reportable medium+ set independent of section provenance, so a session with an
  // unbacked medium+ finding is still refused — assert that explicitly, then prove an
  // osint-only session with NO reportable medium+ finding renders.
  assert.throws(() => composeReportTool.handler({ target_domain: domain, sections: osintSections() }), /executed-flip binding/);
})));

test("a native(O-P4) finding renders WITHOUT a finding-differential arm (skip parity with the grade gate)", () => withTempHome(() => withIsolatedSigner(() => {
  const domain = "compose-exec-native.example.com";
  const surfaceId = "repo:module:src-parser.c";
  appendFrontierEvent({
    target_domain: domain, kind: "surface.observed", ts: "2026-05-27T00:00:00.000Z",
    surface_id: surfaceId, payload: { kind: "code_module", language: "c" },
  });
  const { repoCommandRunsJsonlPath } = require("../mcp/core/io/paths.js");
  appendJsonlLine(repoCommandRunsJsonlPath(domain), {
    run_id: "grade-repro-run-1", command_hash: hex("b"), exit_code: 134,
    stdout_hash: hex("c"), stderr_hash: hex("d"), dry_run: false,
  });
  const REPRO_COMMAND_ARGV = ["sh", "-lc", "./harness crash-input.bin"];
  appendCandidateClaim({
    target_domain: domain, title: "Native parser over-read",
    summary: "Local file parser reads past the available buffer.", severity: "high",
    status: "candidate", surface_ids: [surfaceId],
    evidence_refs: [
      { kind: "finding", finding_id: "F-1", content_hash: hex("0") },
      { kind: "repo_command_run", run_id: "grade-repro-run-1", command_hash: hex("b"),
        exit_code: 134, stdout_hash: hex("c"), stderr_hash: hex("d") },
    ],
    impact: "Parser crash on crafted input.",
    payload: { finding: { id: "F-1", capability_pack: "oss_native_code", repro_command_argv: REPRO_COMMAND_ARGV } },
  });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({ target_domain: domain, round, notes: null, results: [verificationResult("F-1")] });
  }
  // The native O-P4 path owns this class: the standalone finding-differential gate SKIPS
  // it (no finding_differential_surface_mismatch). With NO repro-verified arm, the report
  // gate reports the native repro gap — i.e. the SAME class the grade gate enforces,
  // never the standalone finding-differential reason. Skip parity proven by the reason.
  try {
    composeReportTool.handler({ target_domain: domain, sections: osintSections() });
  } catch (err) {
    assert.doesNotMatch(String(err.message), /finding_differential/, "native finding is NOT routed through the standalone differential gate");
    assert.match(String(err.message), /no_verified_pass|no_repro_command_argv/, "it is owned by the O-P4 repro gate (skip parity)");
  }
})));

// The non-`final`-round laundering path. validateVerificationRoundRef first-matches over
// [brutalist, balanced, final], so a section citing a brutalist/balanced-reportable result
// would satisfy a "reportable=true" provenance check while the executed-flip gate keys off
// the FINAL round and never inspects that finding. The attack: record a catalog-CWE claim
// with no executed proof, hand-write a `brutalist` round marking it reportable:true, then
// compose a `bob_verified` section citing that brutalist result. Both the provenance check
// (final-round reportability) and the defense-in-depth gate (no bob_verified section without
// a final round) must REFUSE it.
test("a bob_verified section citing a finding reportable ONLY in the brutalist round (final reportable:false) is REJECTED", () => withTempHome(() => {
  const domain = "compose-exec-brutalist-launder.example.com";
  // brutalist + balanced reportable:true, but the FINAL round disposed it reportable:false.
  seedStandaloneWebFinding(domain, { finalReportable: false });
  const launderedSection = [{
    kind: "impact", heading: "Impact",
    prose: "An attacker can read another tenant's billing profile.",
    provenance: "bob_verified",
    evidence_refs: ["verification_round:brutalist:F-1"],
  }];
  assert.throws(
    () => composeReportTool.handler({ target_domain: domain, sections: launderedSection }),
    (err) => {
      assert.match(String(err.message), /reportable=true|final verification round/, "brutalist-only reportability cannot satisfy bob_verified provenance");
      return true;
    },
  );
  assert.equal(fs.existsSync(reportMarkdownPath(domain)), false, "report.md must not be written on a laundered bob_verified section");
}));

test("a bob_verified section with NO final verification round is REJECTED even WITH a genuine executed arm (fail-closed)", () => withTempHome(() => {
  const domain = "compose-exec-nofinal.example.com";
  // Only brutalist + balanced rounds exist; the session never produced a final round.
  seedStandaloneWebFinding(domain, { rounds: ["brutalist", "balanced"] });
  // A REAL re-derivable executed flip, so the executed-flip gate (which falls back to the
  // latest round) PASSES — isolating the no-final-round provenance requirement as the sole
  // closer: the bob_verified label demands the literal final adjudication round, not just
  // an executed differential.
  seedFindingDifferentialArm(domain, "F-1");
  const noFinalSection = [{
    kind: "impact", heading: "Impact",
    prose: "An attacker can read another tenant's billing profile.",
    provenance: "bob_verified",
    evidence_refs: ["verification_round:brutalist:F-1"],
  }];
  assert.throws(
    () => composeReportTool.handler({ target_domain: domain, sections: noFinalSection }),
    (err) => {
      assert.match(String(err.message), /reportable=true|final verification round/, "a bob_verified section cannot render without a final round even with a real executed arm");
      return true;
    },
  );
  assert.equal(fs.existsSync(reportMarkdownPath(domain)), false, "report.md must not be written when no final round grounds the bob_verified section");
}));
