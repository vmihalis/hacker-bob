"use strict";

// Cycle D.2 invariant: every record-candidate-claim call lands a single
// CandidateClaim row in claims.jsonl with an embedded finding-shaped payload,
// emits exactly one claim.candidate.linked frontier event, and exposes the
// finding_id through the claim-projection helpers. The legacy findings.jsonl
// dual-write was removed; claims are the sole authoritative ledger.

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
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const {
  claimsForFinding,
  findingForClaim,
} = require("../mcp/lib/claim-projections.js");
const {
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-claim-write-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function findingInput(domain, index) {
  return {
    target_domain: domain,
    title: `IDOR exposes record ${index}`,
    severity: index % 2 === 0 ? "high" : "medium",
    cwe: "CWE-639",
    endpoint: `https://victim.example/api/records/${index}`,
    description: `Changing record ${index} identifier returns another tenant payload.`,
    proof_of_concept: `GET /api/records/${index} as the attacker tenant returns private fields.`,
    response_evidence: `Response leaked tenant identifier and email for record ${index}.`,
    impact: `Cross-tenant record ${index} disclosure.`,
    validated: true,
    auth_profile: `attacker-${index}`,
    surface_id: `surface:record-${index}`,
    // Cross-tenant IDOR disclosure: network-reachable, low-privilege attacker
    // tenant, confidentiality impact.
    cvss_inputs: {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
    },
  };
}

test("recording 5 candidate claims writes 5 claims plus 5 claim.candidate.linked events", () => {
  withTempHome(() => {
    const domain = "claim-write.example.com";
    const findingIds = [];
    const claimIds = [];
    for (let i = 1; i <= 5; i += 1) {
      const response = JSON.parse(recordCandidateClaimTool.handler(findingInput(domain, i)));
      assert.equal(response.recorded, true, `claim ${i} must be recorded`);
      findingIds.push(response.finding_id);
      assert.equal(typeof response.claim_id, "string");
      assert.match(response.claim_id, /^CL-/);
      claimIds.push(response.claim_id);
      assert.equal(response.written_jsonl.endsWith("claims.jsonl"), true);
    }
    assert.equal(new Set(findingIds).size, 5, "each candidate must mint a distinct finding_id");
    assert.equal(new Set(claimIds).size, 5, "each candidate must mint a distinct claim_id");

    const claims = readCandidateClaims(domain);
    assert.equal(claims.length, 5, "claims.jsonl should carry exactly 5 rows");

    const findings = findingPayloadsFromClaims(domain);
    assert.equal(findings.length, 5, "claim payload projection should yield 5 finding-shaped rows");

    const claimsByFindingId = new Map();
    for (const claim of claims) {
      assert.equal(typeof claim.claim_id, "string");
      assert.equal(typeof claim.claim_hash, "string");
      assert.equal(claim.claim_hash.length, 64);
      assert.ok(Array.isArray(claim.evidence_refs), "claim must carry evidence_refs[]");
      assert.equal(claim.evidence_refs.length, 1, "claim must carry exactly one evidence ref to its embedded finding payload");
      const ref = claim.evidence_refs[0];
      assert.equal(ref.kind, "finding");
      assert.equal(typeof ref.finding_id, "string");
      assert.equal(typeof ref.content_hash, "string");
      assert.equal(ref.content_hash.length, 64);
      claimsByFindingId.set(ref.finding_id, claim);
    }

    for (const finding of findings) {
      const claim = claimsByFindingId.get(finding.id);
      assert.ok(claim, `every projected finding must have a CandidateClaim (missing for ${finding.id})`);
      // CVSS round-trip: the cvss_inputs written on the fixture must survive the
      // write -> findingPayloadsFromClaims read-back projection intact, so a
      // regression that strips or mis-normalizes CVSS in either path is caught
      // here rather than passing silently.
      assert.ok(
        finding.cvss_inputs && typeof finding.cvss_inputs === "object",
        `projected finding ${finding.id} must carry cvss_inputs`,
      );
      assert.equal(finding.cvss_inputs.attack_vector, "network");
      assert.equal(finding.cvss_inputs.privileges_required, "low");
      assert.equal(finding.cvss_inputs.confidentiality, "high");
      assert.equal(
        claim.evidence_refs[0].content_hash,
        hashCanonicalJson(finding),
        "claim evidence ref content_hash must match hashCanonicalJson(finding)",
      );
      assert.equal(claim.severity, finding.severity);
      assert.deepEqual(claim.surface_ids, [finding.surface_id]);
      assert.ok(claim.payload && typeof claim.payload === "object", "claim payload must carry the embedded finding shape");
      assert.equal(claim.payload.auth_profile_ref, finding.auth_profile);
      assert.equal(claim.payload.subject_id, finding.endpoint);
      assert.equal(claim.payload.surface_ref, finding.surface_id);
      assert.equal(claim.payload.attack_class, finding.cwe);
      assert.ok(claim.payload.finding && typeof claim.payload.finding === "object", "claim payload must inline the finding payload");
      assert.equal(claim.payload.finding.id, finding.id);
    }

    const events = readFrontierEvents(domain).filter((event) => event.kind === "claim.candidate.linked");
    assert.equal(events.length, 5, "frontier-events.jsonl should carry 5 claim.candidate.linked events");
    const eventLinks = new Map();
    for (const event of events) {
      assert.equal(typeof event.event_id, "string");
      assert.equal(typeof event.event_hash, "string");
      assert.equal(event.event_hash.length, 64);
      assert.equal(event.plane, "frontier");
      const payload = event.payload || {};
      assert.equal(typeof payload.claim_id, "string");
      assert.equal(typeof payload.finding_id, "string");
      eventLinks.set(payload.finding_id, payload.claim_id);
    }
    for (const finding of findings) {
      const linkedClaimId = eventLinks.get(finding.id);
      assert.ok(linkedClaimId, `frontier event must reference finding ${finding.id}`);
      assert.equal(linkedClaimId, claimsByFindingId.get(finding.id).claim_id);
    }

    for (const finding of findings) {
      const projected = claimsForFinding(domain, finding.id);
      assert.equal(projected.length, 1, `claimsForFinding(${finding.id}) must return exactly one claim`);
      assert.equal(projected[0].claim_id, claimsByFindingId.get(finding.id).claim_id);
      const inverse = findingForClaim(domain, projected[0].claim_id);
      assert.equal(inverse, finding.id, "findingForClaim should round-trip back to the source finding_id");
    }
  });
});
