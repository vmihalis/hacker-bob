"use strict";

// The grader reads findings through bob_read_candidate_claims. Each finding in
// that read response carries a server-derived CVSS v3.1 summary computed at read
// time from the finding's persisted cvss_inputs: a band/score when the inputs are
// sufficient, or the explicit insufficient marker when they are not. The derived
// summary is additive and read-only — it must equal deriveCvss31(finding.cvss_inputs)
// and must not be persisted onto the hashed finding.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
const readCandidateClaimsTool = require("../mcp/lib/tools/read-candidate-claims.js");
const { findingPayloadsFromClaims } = require("../mcp/lib/tools/record-candidate-claim.js");
const { deriveCvss31 } = require("../mcp/lib/cvss31.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-read-cvss-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function recordFinding(domain, overrides = {}) {
  const args = {
    target_domain: domain,
    title: overrides.title || "IDOR on billing profile",
    severity: overrides.severity || "high",
    cwe: overrides.cwe || "CWE-639",
    endpoint: overrides.endpoint || `https://${domain}/api/billing/1`,
    description: overrides.description || "Tenant boundary allows cross-account view of billing data",
    proof_of_concept: overrides.poc || "GET /api/billing/1 returns another tenant payload",
    response_evidence: overrides.response_evidence || "Cross-tenant billing payload",
    impact: overrides.impact || "Cross-tenant billing disclosure",
    validated: true,
    auth_profile: overrides.auth_profile || "attacker",
    surface_id: overrides.surface_id || "surface:billing-profile",
  };
  if (overrides.cvss_inputs !== undefined) {
    if (overrides.cvss_inputs !== null) args.cvss_inputs = overrides.cvss_inputs;
  } else {
    args.cvss_inputs = {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
    };
  }
  return JSON.parse(recordFindingTool.handler(args));
}

test("read-candidate-claims attaches the derived CVSS band for a finding WITH cvss_inputs", () => {
  withTempHome(() => {
    const domain = "read-cvss-present.example.com";
    recordFinding(domain);

    const response = JSON.parse(readCandidateClaimsTool.handler({ target_domain: domain }));
    assert.equal(response.findings.length, 1);
    const finding = response.findings[0];

    assert.ok(finding.cvss && typeof finding.cvss === "object", "finding must carry a derived cvss summary");
    assert.equal(finding.cvss.insufficient, undefined, "sufficient inputs must derive a band, not the insufficient marker");
    assert.equal(finding.cvss.version, "3.1");
    assert.equal(finding.cvss.severity_band, "medium");
    assert.equal(finding.cvss.base_score, 6.5);
    assert.equal(finding.cvss.vector, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

    // The derived band must be exactly what deriveCvss31 produces from the
    // finding's own persisted inputs.
    assert.deepEqual(finding.cvss, deriveCvss31(finding.cvss_inputs));
  });
});

test("read-candidate-claims attaches the insufficient marker for a finding WITHOUT cvss_inputs", () => {
  withTempHome(() => {
    const domain = "read-cvss-absent.example.com";
    // info-severity findings do not require cvss_inputs, so this records with none.
    recordFinding(domain, {
      severity: "info",
      title: "Server version disclosure",
      cwe: null,
      impact: "Discloses the backend version",
      cvss_inputs: null,
    });

    const response = JSON.parse(readCandidateClaimsTool.handler({ target_domain: domain }));
    assert.equal(response.findings.length, 1);
    const finding = response.findings[0];

    assert.ok(finding.cvss && typeof finding.cvss === "object", "finding must carry a derived cvss summary");
    assert.equal(finding.cvss.insufficient, true, "absent inputs must yield the explicit insufficient marker");
    assert.equal(finding.cvss.version, "3.1");
    assert.equal(typeof finding.cvss.reason, "string");
    assert.ok(finding.cvss.reason.length > 0);

    // The marker must match deriveCvss31 applied to the finding's (absent) inputs.
    assert.deepEqual(finding.cvss, deriveCvss31(finding.cvss_inputs));
  });
});

test("the derived CVSS band is additive and does not mutate the shared finding projection", () => {
  withTempHome(() => {
    const domain = "read-cvss-additive.example.com";
    recordFinding(domain);

    // The shared projection consumed by other readers must never carry the
    // read-time cvss field.
    const projected = findingPayloadsFromClaims(domain);
    assert.equal(projected.length, 1);
    assert.equal(
      Object.prototype.hasOwnProperty.call(projected[0], "cvss"),
      false,
      "findingPayloadsFromClaims must not gain the read-time cvss field",
    );

    // Reading via the tool a second time still re-derives a fresh band, proving
    // the projection was not mutated by the first read.
    const response = JSON.parse(readCandidateClaimsTool.handler({ target_domain: domain }));
    assert.ok(response.findings[0].cvss);
    const reprojected = findingPayloadsFromClaims(domain);
    assert.equal(
      Object.prototype.hasOwnProperty.call(reprojected[0], "cvss"),
      false,
      "findingPayloadsFromClaims must remain free of cvss after a read",
    );
  });
});
