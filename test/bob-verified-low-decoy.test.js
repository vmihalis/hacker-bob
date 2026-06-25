"use strict";

// LOW-DECOY / bob_verified PROVENANCE PARITY. The bob_verified stamp is gated on the SAME
// normalized medium+ final-round severity the executed-flip gate filters to. A LOW-severity
// reportable decoy + critical-impact prose used to wear bob_verified while the executed gate's
// reportable-medium+ set was empty (it returns early) — so no executed flip was ever required.
// Now a present-but-low bob_verified section is refused (X-P3) before the executed gate can
// vacuously pass it; a medium+ reportable citation with a real executed flip still renders.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const composeReportTool = require("../mcp/lib/tools/compose-report.js");
const { withIsolatedSigner } = require("./helpers/sandbox-isolated-signer.js");
const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
const { buildClaimFreeze } = require("../mcp/lib/claim-freeze.js");
const { writeVerificationRound } = require("../mcp/lib/verification-round-store.js");
const { writeEvidencePacks } = require("../mcp/lib/evidence.js");
const { appendJsonlLine } = require("../mcp/lib/storage.js");
const { canonicalizeExploitTarget } = require("../mcp/lib/claims.js");
const { ensureHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
const { signOffensiveRunRow } = require("../mcp/lib/offensive-row-mac.js");
const { offensiveRowHash } = require("../mcp/lib/finding-differential-verifier.js");
const {
  findingDifferentialVerifiedJsonlPath,
  offensiveRunsJsonlPath,
  reportMarkdownPath,
  sessionDir,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-verified-low-decoy-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
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

function seedStandaloneWebFinding(domain, { severity = "high" } = {}) {
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
      target_domain: domain, round, notes: null,
      results: [verificationResult("F-1", { severity, reportable: true })],
    });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
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
    // Critical-impact prose riding on a low-severity citation — the decoy shape.
    prose: "An attacker can fully take over another tenant's account and drain funds.",
    provenance: "bob_verified",
    evidence_refs: ["verification_round:final:F-1"],
  }];
}

test("a bob_verified section citing a LOW (reclamped) final-reportable finding is REFUSED (X-P3)", () => withTempHome(() => {
  const domain = "bob-verified-low.example.com";
  // reportable:true but severity LOW -> below the normalized medium+ floor.
  seedStandaloneWebFinding(domain, { severity: "low" });
  assert.throws(
    () => composeReportTool.handler({ target_domain: domain, sections: verifiedSections() }),
    (err) => {
      assert.equal(err.code, "INVALID_ARGUMENTS");
      assert.match(String(err.message), /provenance: bob_verified requires at least one verification_round ref whose reportable=true/);
      assert.match(String(err.message), /X-P3/);
      return true;
    },
  );
  assert.equal(fs.existsSync(reportMarkdownPath(domain)), false, "no report.md on a refused low-decoy compose");
}));

test("a bob_verified section citing a MEDIUM+ reportable finding WITH a real executed flip RENDERS", () => withTempHome(() => withIsolatedSigner(() => {
  const domain = "bob-verified-medium.example.com";
  seedStandaloneWebFinding(domain, { severity: "high" });
  seedFindingDifferentialArm(domain, "F-1");
  const out = JSON.parse(composeReportTool.handler({ target_domain: domain, sections: verifiedSections() }));
  assert.equal(out.sections_rendered, 1);
  assert.ok(fs.existsSync(reportMarkdownPath(domain)), "report.md is written for a medium+ bob_verified section with an executed flip");
})));

test("a MEDIUM+ bob_verified section WITHOUT an executed flip is still refused (the floor does not loosen the executed gate)", () => withTempHome(() => withIsolatedSigner(() => {
  const domain = "bob-verified-medium-noarm.example.com";
  seedStandaloneWebFinding(domain, { severity: "high" }); // medium+ + reportable, but NO arm
  assert.throws(
    () => composeReportTool.handler({ target_domain: domain, sections: verifiedSections() }),
    /executed-flip binding/,
  );
})));
