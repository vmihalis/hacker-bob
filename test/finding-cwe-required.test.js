"use strict";

// CWE is required and catalog-validated on the fresh write path for reportable
// findings (severity critical/high/medium), optional for low/info, idempotently
// canonicalized so the dedupe key does not fork, and tolerant on legacy
// read-back projection (a row missing a CWE still projects).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const recordCandidateClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  findingPayloadsFromClaims,
} = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  readCandidateClaims,
} = require("../mcp/lib/claims.js");
const {
  claimsJsonlPath,
} = require("../mcp/lib/paths.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cwe-required-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function baseFinding(domain, overrides = {}) {
  return {
    target_domain: domain,
    title: "IDOR exposes another tenant record",
    severity: "medium",
    cwe: "CWE-639",
    endpoint: `https://${domain}/api/records/1`,
    description: "Changing the record identifier returns another tenant payload.",
    proof_of_concept: "GET /api/records/1 as the attacker tenant returns private fields.",
    response_evidence: "Response leaked another tenant identifier and email.",
    impact: "Cross-tenant record disclosure.",
    validated: true,
    auth_profile: "attacker",
    surface_id: "surface:record-1",
    // Cross-tenant IDOR: network-reachable, requires a low-privilege
    // authenticated tenant, discloses another tenant's record (confidentiality).
    cvss_inputs: {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
      integrity: "none",
      availability: "none",
    },
    ...overrides,
  };
}

test("write path requires a CWE for medium/high/critical findings", () => {
  for (const severity of ["medium", "high", "critical"]) {
    withTempHome(() => {
      const domain = `cwe-required-${severity}.example.com`;
      assert.throws(
        () => recordCandidateClaimTool.handler(baseFinding(domain, { severity, cwe: undefined })),
        (err) => {
          assert.match(err.message, /cwe is required/i);
          assert.match(err.message, /cwe-catalog\.js/);
          return true;
        },
        `${severity} without a CWE must be rejected`,
      );
    });
  }
});

test("write path rejects an empty-string CWE for reportable severities", () => {
  withTempHome(() => {
    const domain = "cwe-empty.example.com";
    assert.throws(
      () => recordCandidateClaimTool.handler(baseFinding(domain, { cwe: "   " })),
      /cwe is required/i,
    );
  });
});

test("write path rejects a well-formed but non-catalog CWE for reportable severities", () => {
  withTempHome(() => {
    const domain = "cwe-unknown.example.com";
    assert.throws(
      () => recordCandidateClaimTool.handler(baseFinding(domain, { cwe: "CWE-999999" })),
      /not in the curated CWE catalog/i,
    );
  });
});

test("write path allows a null/absent CWE for low and info findings", () => {
  for (const severity of ["low", "info"]) {
    withTempHome(() => {
      const domain = `cwe-optional-${severity}.example.com`;
      const response = JSON.parse(
        recordCandidateClaimTool.handler(baseFinding(domain, { severity, cwe: undefined })),
      );
      assert.equal(response.recorded, true, `${severity} without a CWE must be accepted`);

      const findings = findingPayloadsFromClaims(domain);
      assert.equal(findings.length, 1);
      assert.equal(findings[0].cwe, null, `${severity} finding must project a null CWE`);
    });
  }
});

test("a present CWE is canonicalized on write without forking the dedupe_key", () => {
  withTempHome(() => {
    const canonicalDomain = "cwe-canonical.example.com";
    const lowerDomain = "cwe-lower.example.com";

    // The dedupe key is computed from endpoint/title/auth/evidence (NOT the
    // target_domain), so use a fixed cross-domain endpoint and keep every field
    // identical except the CWE casing — canonical vs lowercase. Canonicalization
    // is idempotent, so both rows must land the SAME dedupe_key.
    const fixedEndpoint = "https://fixed.example/api/records/1";
    const canonicalResponse = JSON.parse(
      recordCandidateClaimTool.handler(
        baseFinding(canonicalDomain, { cwe: "CWE-639", endpoint: fixedEndpoint }),
      ),
    );
    const lowerResponse = JSON.parse(
      recordCandidateClaimTool.handler(
        baseFinding(lowerDomain, { cwe: "cwe-639", endpoint: fixedEndpoint }),
      ),
    );

    assert.equal(canonicalResponse.recorded, true);
    assert.equal(lowerResponse.recorded, true);

    const canonicalFinding = findingPayloadsFromClaims(canonicalDomain)[0];
    const lowerFinding = findingPayloadsFromClaims(lowerDomain)[0];

    assert.equal(canonicalFinding.cwe, "CWE-639", "canonical input stays canonical");
    assert.equal(lowerFinding.cwe, "CWE-639", "lowercase input canonicalizes to CWE-639");

    assert.equal(
      canonicalFinding.dedupe_key,
      lowerFinding.dedupe_key,
      "idempotent canonicalization must keep the dedupe_key stable across CWE casing",
    );
  });
});

test("legacy read-back projects a claim row whose CWE is present but non-catalog", () => {
  // A persisted claim whose recorded CWE is out-of-catalog or free-text must
  // still project on read-back (degraded to null), not be silently dropped by
  // the projection's catch. Strict catalog validation stays on the write path only.
  for (const legacyCwe of ["IDOR", "CWE-602", "CWE-79 (XSS)"]) {
    withTempHome(() => {
      const domain = "cwe-legacy-present.example.com";
      const response = JSON.parse(
        recordCandidateClaimTool.handler(baseFinding(domain, { cwe: "CWE-639" })),
      );
      assert.equal(response.recorded, true);

      const file = claimsJsonlPath(domain);
      const lines = fs.readFileSync(file, "utf8").split("\n").filter((l) => l.trim());
      assert.equal(lines.length, 1);
      const claim = JSON.parse(lines[0]);
      claim.payload.finding.cwe = legacyCwe;
      fs.writeFileSync(file, `${JSON.stringify(claim)}\n`);

      const reread = readCandidateClaims(domain);
      assert.equal(reread[0].payload.finding.cwe, legacyCwe, "row truly carries the legacy CWE");

      const findings = findingPayloadsFromClaims(domain);
      assert.equal(findings.length, 1, `legacy row with cwe ${legacyCwe} must still project`);
      assert.equal(findings[0].cwe, null, `non-catalog cwe ${legacyCwe} degrades to null on read-back`);
      assert.equal(findings[0].severity, "medium");
    });
  }
});

test("legacy read-back projects a claim row that lacks a CWE without throwing", () => {
  withTempHome(() => {
    const domain = "cwe-legacy.example.com";
    const response = JSON.parse(
      recordCandidateClaimTool.handler(baseFinding(domain, { cwe: "CWE-639" })),
    );
    assert.equal(response.recorded, true);

    // Simulate a legacy claim row written before the CWE requirement existed:
    // strip the embedded finding.cwe and the derived attack_class from the
    // persisted claim, then confirm the projection still surfaces the finding.
    const file = claimsJsonlPath(domain);
    const lines = fs.readFileSync(file, "utf8").split("\n").filter((l) => l.trim());
    assert.equal(lines.length, 1);
    const claim = JSON.parse(lines[0]);
    delete claim.payload.finding.cwe;
    delete claim.payload.attack_class;
    fs.writeFileSync(file, `${JSON.stringify(claim)}\n`);

    // Sanity: the row truly lacks a CWE now.
    const reread = readCandidateClaims(domain);
    assert.equal(reread.length, 1);
    assert.equal(reread[0].payload.finding.cwe, undefined);

    const findings = findingPayloadsFromClaims(domain);
    assert.equal(findings.length, 1, "legacy CWE-less row must still project");
    assert.equal(findings[0].cwe, null, "legacy projection normalizes a missing CWE to null");
    assert.equal(findings[0].severity, "medium");
  });
});
