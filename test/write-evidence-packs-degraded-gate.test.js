"use strict";

// Trust-degradation fail-closed gate for bob_write_evidence_packs. An evidence
// pack must never be written for a finding whose source could not be
// signature-verified (signature_verification_status === "unsigned"). The writer
// refuses to persist evidence-packs.json when any pack references a degraded
// finding, naming the offending finding id with a re-verify-or-exclude
// remediation. Signed / unmarked findings carry no marker, so the gate is inert
// and the normal evidence-pack write proceeds.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendCandidateClaim } = require("../mcp/lib/claims.js");
const { writeEvidencePacks } = require("../mcp/lib/evidence.js");
const { writeVerificationRound } = require("../mcp/lib/verification-round-store.js");
const { buildClaimFreeze } = require("../mcp/lib/claim-freeze.js");
const { ERROR_CODES } = require("../mcp/lib/envelope.js");
const { evidencePackPaths } = require("../mcp/lib/paths.js");
const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-evidence-degraded-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
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

function appendUnsignedFinding(domain, findingId = "F-1") {
  appendCandidateClaim({
    target_domain: domain,
    claim_id: `claim-${findingId}`,
    title: "Cross-account export from an unsigned handoff",
    summary: "Merged finding from an unsigned-but-readable handoff.",
    severity: "high",
    evidence_refs: [{ kind: "finding", finding_id: findingId }],
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
}

function recordSignedFinding(domain) {
  return JSON.parse(recordFindingTool.handler({
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
  }));
}

test("bob_write_evidence_packs FAILS CLOSED for a pack referencing an unsigned finding", () => {
  withTempHome(() => {
    const domain = "evidence-degraded.example.com";
    appendUnsignedFinding(domain, "F-1");
    buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [verificationResult("F-1")],
      });
    }

    let err;
    try {
      writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
    } catch (e) { err = e; }
    assert.ok(err, "evidence pack for an unsigned finding must refuse to write");
    assert.equal(err.code, ERROR_CODES.STATE_CONFLICT);
    assert.match(err.message, /F-1/);
    assert.equal(typeof err.remediation, "string");
    assert.match(err.remediation, /re-?verify/i);
    assert.equal(fs.existsSync(evidencePackPaths(domain).json), false, "evidence-packs.json must not be written");
  });
});

test("bob_write_evidence_packs flows through unaffected for an all-signed finding", () => {
  withTempHome(() => {
    const domain = "evidence-signed.example.com";
    recordSignedFinding(domain);
    buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [verificationResult("F-1")],
      });
    }
    const written = JSON.parse(writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] }));
    assert.equal(written.packs_count, 1);
    assert.equal(written.reportable_findings_covered, 1);
    assert.equal(fs.existsSync(evidencePackPaths(domain).json), true, "evidence-packs.json must be written for signed findings");
  });
});
