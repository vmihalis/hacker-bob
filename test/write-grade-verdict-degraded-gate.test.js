"use strict";

// Trust-degradation fail-closed gate for bob_write_grade_verdict. A finding
// whose source could not be signature-verified (signature_verification_status
// === "unsigned") must never be bound as reportable / SUBMIT-eligible in a
// grade verdict. The writer refuses to grade when a finding in the final
// reportable-severity set carries the unsigned marker, naming the offending
// finding id with a re-verify-or-exclude remediation. Signed / unmarked
// findings carry no marker, so the gate is inert and the normal grade write
// proceeds.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendCandidateClaim } = require("../mcp/lib/claims.js");
const { buildClaimFreeze } = require("../mcp/lib/claim-freeze.js");
const { writeVerificationRound } = require("../mcp/lib/verification-round-store.js");
const { writeEvidencePacks } = require("../mcp/lib/evidence.js");
const { writeGradeVerdict } = require("../mcp/lib/grade-verdict-store.js");
const { ERROR_CODES } = require("../mcp/lib/envelope.js");
const { gradeArtifactPaths } = require("../mcp/lib/paths.js");
const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-grade-degraded-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function verificationResult(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    disposition: "confirmed",
    severity: "high",
    reportable: true,
    reasoning: "Fresh replay confirmed the finding against the current target state.",
    ...overrides,
  };
}

function evidencePack(findingId = "F-1", overrides = {}) {
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
      observed_fields: ["billing_profile_id"],
      redacted_object_id: "acct_...002",
    }],
    sensitive_clusters: ["billing metadata"],
    replay_summary: "Fresh replay returned another tenant's private billing metadata.",
    redaction_notes: "Object IDs redacted; auth material omitted.",
    report_snippet: "An attacker can retrieve another tenant's private billing metadata by changing the billing profile ID.",
    ...overrides,
  };
}

function gradeFinding(findingId = "F-1", overrides = {}) {
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

function seedFinalChainForUnsigned(domain, findingId = "F-1") {
  appendCandidateClaim({
    target_domain: domain,
    claim_id: `claim-${findingId}`,
    title: "Cross-account export from an unsigned handoff",
    summary: "Merged finding from an unsigned-but-readable handoff.",
    severity: "high",
    status: "candidate",
    surface_ids: ["surface:billing-profile"],
    impact: "Cross-tenant billing disclosure.",
    evidence_refs: [{ kind: "finding", finding_id: findingId, content_hash: "0".repeat(64) }],
    payload: {
      finding: {
        id: findingId,
        target_domain: domain,
        title: "Cross-account export from an unsigned handoff",
        severity: "high",
        cwe: "CWE-639",
        endpoint: `https://${domain}/api/export/${findingId}`,
        description: "Merged finding from an unsigned-but-readable handoff.",
        proof_of_concept: `GET /api/export/${findingId} returns another tenant's data`,
        validated: true,
        signature_verification_status: "unsigned",
        signature_error_reason: "merged from a handoff without a signing key",
      },
    },
  });
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain,
      round,
      notes: null,
      results: [verificationResult(findingId)],
    });
  }
}

function seedFinalChainForSigned(domain) {
  recordFindingTool.handler({
    target_domain: domain,
    title: "IDOR on billing profile",
    severity: "high",
    cwe: "CWE-639",
    endpoint: "https://victim.example/api/billing/1",
    description: "Tenant boundary allows cross-account view",
    proof_of_concept: "GET /api/billing/1 returns another tenant payload",
    response_evidence: "Cross-tenant billing payload",
    impact: "Cross-tenant billing disclosure",
    validated: true,
    auth_profile: "attacker",
    surface_id: "surface:billing-profile",
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
  });
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain,
      round,
      notes: null,
      results: [verificationResult("F-1")],
    });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
}

test("bob_write_grade_verdict FAILS CLOSED when a reportable finding is unsigned", () => {
  withTempHome(() => {
    const domain = "grade-degraded.example.com";
    seedFinalChainForUnsigned(domain, "F-1");

    let err;
    try {
      writeGradeVerdict({
        target_domain: domain,
        verdict: "SUBMIT",
        total_score: 75,
        findings: [gradeFinding("F-1")],
      });
    } catch (e) { err = e; }
    assert.ok(err, "grading an unsigned reportable finding must refuse");
    assert.equal(err.code, ERROR_CODES.STATE_CONFLICT);
    assert.match(err.message, /F-1/);
    assert.equal(typeof err.remediation, "string");
    assert.match(err.remediation, /re-?verify/i);
    assert.equal(fs.existsSync(gradeArtifactPaths(domain).json), false, "grade.json must not be written");
  });
});

test("bob_write_grade_verdict FAILS CLOSED when a bound finding is unsigned even if it is not reportable", () => {
  withTempHome(() => {
    const domain = "grade-launder.example.com";
    // F-1: signed, reportable high — a legitimate SUBMIT enabler.
    recordFindingTool.handler({
      target_domain: domain,
      title: "IDOR on billing profile",
      severity: "high",
      cwe: "CWE-639",
      endpoint: "https://victim.example/api/billing/1",
      description: "Tenant boundary allows cross-account view",
      proof_of_concept: "GET /api/billing/1 returns another tenant payload",
      response_evidence: "Cross-tenant billing payload",
      impact: "Cross-tenant billing disclosure",
      validated: true,
      auth_profile: "attacker",
      surface_id: "surface:billing-profile",
      cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
    });
    // F-2: unsigned and NOT reportable — outside the reportable-severity set,
    // so it would slip a gate that keyed on that narrower set; it is still
    // bound into grade.json findings[] and can drive the verdict.
    appendCandidateClaim({
      target_domain: domain,
      claim_id: "claim-F-2",
      title: "Low-signal finding from an unsigned handoff",
      summary: "Merged finding from an unsigned-but-readable handoff.",
      severity: "low",
      status: "candidate",
      evidence_refs: [{ kind: "finding", finding_id: "F-2", content_hash: "0".repeat(64) }],
      payload: {
        finding: {
          id: "F-2",
          target_domain: domain,
          title: "Low-signal finding from an unsigned handoff",
          severity: "low",
          cwe: "CWE-639",
          endpoint: `https://${domain}/api/export/F-2`,
          description: "Merged finding from an unsigned-but-readable handoff.",
          proof_of_concept: "GET /api/export/F-2 returns another tenant's data",
          validated: true,
          signature_verification_status: "unsigned",
          signature_error_reason: "merged from a handoff without a signing key",
        },
      },
    });
    buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [
          verificationResult("F-1"),
          verificationResult("F-2", { reportable: false, severity: "low" }),
        ],
      });
    }

    let err;
    try {
      writeGradeVerdict({
        target_domain: domain,
        verdict: "SUBMIT",
        total_score: 75,
        findings: [gradeFinding("F-1"), gradeFinding("F-2")],
      });
    } catch (e) { err = e; }
    assert.ok(err, "binding an unsigned finding into the grade must refuse even when it is not reportable");
    assert.equal(err.code, ERROR_CODES.STATE_CONFLICT);
    assert.match(err.message, /F-2/);
    assert.equal(fs.existsSync(gradeArtifactPaths(domain).json), false, "grade.json must not be written");
  });
});

test("bob_write_grade_verdict flows through unaffected for an all-signed finding", () => {
  withTempHome(() => {
    const domain = "grade-signed.example.com";
    seedFinalChainForSigned(domain);

    const written = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    }));
    assert.equal(written.verdict, "SUBMIT");
    assert.equal(written.findings_count, 1);
    assert.equal(fs.existsSync(gradeArtifactPaths(domain).json), true, "grade.json must be written for signed findings");
  });
});
