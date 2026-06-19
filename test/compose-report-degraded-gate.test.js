"use strict";

// Trust-degradation fail-closed gate for bob_compose_report. A finding whose
// source could not be signature-verified (signature_verification_status ===
// "unsigned") must never be laundered into report.md. The composer refuses to
// render when a final-reportable finding carries the unsigned marker, naming
// the offending finding id with a re-verify-or-exclude remediation. Signed /
// unmarked findings carry no marker, so the gate is inert and a normal report
// renders unaffected.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const composeReportTool = require("../mcp/lib/tools/compose-report.js");
const { appendCandidateClaim } = require("../mcp/lib/claims.js");
const { ERROR_CODES } = require("../mcp/lib/envelope.js");
const {
  reportMarkdownPath,
  sessionDir,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-compose-degraded-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function seedFinalRound(domain, results) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const paths = verificationRoundPaths(domain, "final");
  fs.writeFileSync(paths.json, JSON.stringify({
    target_domain: domain,
    round: "final",
    notes: null,
    results,
    written_at: new Date().toISOString(),
  }));
}

function appendFinding(domain, { findingId, signatureStatus = null }) {
  const finding = {
    id: findingId,
    target_domain: domain,
    title: `Cross-account export in /api/export/${findingId}`,
    severity: "high",
    cwe: "CWE-639",
    endpoint: `https://${domain}/api/export/${findingId}`,
    description: "Cross-account export.",
    proof_of_concept: `GET /api/export/${findingId} returns another tenant's data`,
    validated: true,
  };
  if (signatureStatus) {
    finding.signature_verification_status = signatureStatus;
    finding.signature_error_reason = "merged from a handoff without a signing key";
  }
  appendCandidateClaim({
    target_domain: domain,
    claim_id: `claim-${findingId}`,
    title: finding.title,
    summary: finding.description,
    severity: finding.severity,
    evidence_refs: [{ kind: "finding", finding_id: findingId }],
    payload: { finding },
  });
}

function sections() {
  return [{
    kind: "impact",
    heading: "Impact",
    prose: "An attacker can read another tenant's export.",
    provenance: "external_research",
    evidence_refs: [],
  }];
}

test("bob_compose_report FAILS CLOSED when a final-reportable finding is unsigned", () => {
  withTempHome(() => {
    const domain = "compose-degraded.example.com";
    appendFinding(domain, { findingId: "F-1", signatureStatus: "unsigned" });
    seedFinalRound(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed",
      repro_steps: ["step 1"],
      evidence_refs: ["frontier_event:e1"],
    }]);

    let err;
    try {
      composeReportTool.handler({ target_domain: domain, sections: sections() });
    } catch (e) { err = e; }
    assert.ok(err, "unsigned reportable finding must refuse report rendering");
    assert.equal(err.code, ERROR_CODES.STATE_CONFLICT);
    assert.match(err.message, /F-1/);
    assert.equal(typeof err.remediation, "string");
    assert.match(err.remediation, /re-?verify/i);
    assert.equal(fs.existsSync(reportMarkdownPath(domain)), false, "report.md must not be written");
  });
});

test("bob_compose_report does NOT gate an unsigned finding that is NOT final-reportable", () => {
  withTempHome(() => {
    const domain = "compose-degraded.example.com";
    // F-1 is unsigned but the final round marks it NOT reportable, so it never
    // binds into the report; the gate must stay inert.
    appendFinding(domain, { findingId: "F-1", signatureStatus: "unsigned" });
    seedFinalRound(domain, [{
      finding_id: "F-1",
      disposition: "denied",
      severity: "low",
      reportable: false,
      reasoning: "Not reportable",
      repro_steps: ["x"],
      evidence_refs: ["frontier_event:e1"],
    }]);

    const result = JSON.parse(composeReportTool.handler({ target_domain: domain, sections: sections() }));
    assert.equal(result.target_domain, domain);
    assert.match(result.report_content_hash, /^[a-f0-9]{64}$/);
  });
});

test("bob_compose_report flows through unaffected for an all-signed final-reportable finding", () => {
  withTempHome(() => {
    const domain = "compose-signed.example.com";
    appendFinding(domain, { findingId: "F-1" });
    seedFinalRound(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed",
      repro_steps: ["step 1"],
      evidence_refs: ["frontier_event:e1"],
    }]);

    const result = JSON.parse(composeReportTool.handler({ target_domain: domain, sections: sections() }));
    assert.equal(result.target_domain, domain);
    assert.match(result.report_content_hash, /^[a-f0-9]{64}$/);
    assert.equal(fs.existsSync(reportMarkdownPath(domain)), true, "report.md must render for signed findings");
  });
});
