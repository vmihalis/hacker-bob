"use strict";

// CWE is required and labelled on the fresh write path for reportable findings
// (severity critical/high/medium), optional for low/info, idempotently
// canonicalized so the dedupe key does not fork, and tolerant on legacy
// read-back projection (a row missing a CWE still projects).
//
// Catalog membership is an ANNOTATION, not a drop-gate: a curated catalog CWE
// records as before; a novel (CWE-shaped but non-catalog) mechanism records at
// its demonstrated severity ONLY when an executed differential backs it, and is
// stamped cwe_in_catalog:false. The executed-proof floor is preserved — a
// medium+ novel-mechanism finding with no executed proof cannot reach reportable
// severity. The label requirement and the CWE-shape floor still hold.

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
  canonicalizeExploitTarget,
  readCandidateClaims,
} = require("../mcp/lib/claims.js");
const {
  claimsJsonlPath,
  offensiveRunsJsonlPath,
} = require("../mcp/lib/paths.js");
const {
  ensureHandoffSigningKey,
} = require("../mcp/lib/handoff-signing-key.js");
const {
  signOffensiveRunRow,
} = require("../mcp/lib/offensive-row-mac.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

// A novel-mechanism reportable finding records only when an executed
// differential backs it. The most direct executed-proof channel at the claim
// layer is a MAC-signed, non-dry-run offensive-runs.jsonl row cited via an
// exploit_run evidence ref. bob_http_idor_confirm caps at medium, so seed a
// medium row and cite it on a medium claim.
const EXECUTED_SURFACE_ID = "surface:executed-idor";

function executedExploitRef(domain) {
  return {
    kind: "exploit_run",
    run_id: "run-novel-finding-01",
    tool_id: "bob_http_idor_confirm",
    target: `https://${domain}/api/records/1`,
    offensive_outcome: "exploited_safely",
    command_hash: "a".repeat(64),
    exit_code: 0,
    stdout_hash: "b".repeat(64),
    stderr_hash: "c".repeat(64),
  };
}

function seedExecutedDifferential(domain) {
  const ref = executedExploitRef(domain);
  const row = {
    version: 1,
    target_domain: domain,
    run_id: ref.run_id,
    tool_id: ref.tool_id,
    target: canonicalizeExploitTarget(ref.target),
    offensive_outcome: "exploited_safely",
    dry_run: false,
    timed_out: false,
    command_hash: ref.command_hash,
    exit_code: ref.exit_code,
    stdout_hash: ref.stdout_hash,
    stderr_hash: ref.stderr_hash,
    demonstrated_severity: "medium",
    surface_id: EXECUTED_SURFACE_ID,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  fs.mkdirSync(path.dirname(offensiveRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
}

// A medium finding that cites the seeded executed differential and pins the same
// surface_id the row stamped (the cross-finding severity-laundering gate requires
// the citing claim's single surface_id to equal the backed row's).
function executedProofOverrides(domain) {
  return {
    severity: "medium",
    surface_id: EXECUTED_SURFACE_ID,
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
    evidence_refs: [executedExploitRef(domain)],
  };
}

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

test("write path rejects a well-formed non-catalog CWE for reportable severities WITHOUT executed proof", () => {
  // Catalog membership is now annotate-not-gate, but the executed-proof floor
  // stays: a medium+ novel-mechanism finding with no executed differential
  // cannot reach reportable severity. It is rejected with guidance, not silently
  // recorded.
  withTempHome(() => {
    const domain = "cwe-unknown.example.com";
    assert.throws(
      () => recordCandidateClaimTool.handler(baseFinding(domain, { cwe: "CWE-999999" })),
      (err) => {
        assert.match(err.message, /outside the curated CWE catalog/i);
        assert.match(err.message, /executed differential/i);
        return true;
      },
    );
  });
});

test("write path records a novel-mechanism medium finding WITH an executed differential at its demonstrated severity", () => {
  withTempHome(() => {
    const domain = "cwe-novel-executed.example.com";
    seedExecutedDifferential(domain);
    const response = JSON.parse(
      recordCandidateClaimTool.handler(
        baseFinding(domain, { cwe: "CWE-999999", ...executedProofOverrides(domain) }),
      ),
    );
    assert.equal(response.recorded, true, "a novel CWE backed by an executed differential records");

    const claim = readCandidateClaims(domain)[0];
    assert.equal(claim.payload.finding.cwe, "CWE-999999", "the canonical free-form label is persisted");
    assert.equal(claim.payload.finding.cwe_in_catalog, false, "non-catalog membership is annotated, not gated");
    assert.equal(claim.payload.finding.severity, "medium", "records at the demonstrated severity");
  });
});

test("write path accepts a free-form lowercase novel CWE id WITH executed proof and canonicalizes the label", () => {
  withTempHome(() => {
    const domain = "cwe-novel-freeform.example.com";
    seedExecutedDifferential(domain);
    const response = JSON.parse(
      recordCandidateClaimTool.handler(
        baseFinding(domain, { cwe: "cwe-602", ...executedProofOverrides(domain) }),
      ),
    );
    assert.equal(response.recorded, true);

    const claim = readCandidateClaims(domain)[0];
    assert.equal(claim.payload.finding.cwe, "CWE-602", "the novel label canonicalizes to CWE-602");
    assert.equal(claim.payload.finding.cwe_in_catalog, false);
  });
});

test("write path rejects a non-CWE-shaped label even with executed proof (shape floor)", () => {
  // The shape floor survives the annotate-not-gate relaxation: only
  // catalog-MEMBERSHIP is relaxed, not the requirement to name a CWE-shaped
  // mechanism. A free-text label like "IDOR" is not a CWE id.
  withTempHome(() => {
    const domain = "cwe-nonshaped.example.com";
    seedExecutedDifferential(domain);
    assert.throws(
      () => recordCandidateClaimTool.handler(
        baseFinding(domain, { cwe: "IDOR", ...executedProofOverrides(domain) }),
      ),
      /must be a CWE identifier/i,
    );
  });
});

test("a catalog CWE is annotated cwe_in_catalog:true and records unchanged", () => {
  withTempHome(() => {
    const domain = "cwe-catalog-annotated.example.com";
    const response = JSON.parse(
      recordCandidateClaimTool.handler(baseFinding(domain)),
    );
    assert.equal(response.recorded, true);

    const claim = readCandidateClaims(domain)[0];
    assert.equal(claim.payload.finding.cwe, "CWE-639");
    assert.equal(claim.payload.finding.cwe_in_catalog, true, "catalog membership is annotated true");
    assert.equal(claim.payload.finding.severity, "medium");
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
