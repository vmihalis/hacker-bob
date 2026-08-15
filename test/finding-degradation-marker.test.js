"use strict";

// Trust-degradation marker on a finding (signature_verification_status).
// Asserts:
//   * the marker round-trips through normalizeFindingRecord (strict write +
//     tolerant read-back) and projects through findingPayloadsFromClaims
//   * a finding with no marker reads as signed (no back-fill, field absent)
//   * an invalid marker throws on the strict write path and degrades to absent
//     on tolerant read-back (so a legacy row still projects)
//   * the marker is excluded from the finding dedupe key (ids stay byte-stable)

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const recordClaimTool = require("../mcp/tools/record-candidate-claim.js");
const { appendCandidateClaim } = require("../mcp/core/claims/claims.js");
const {
  computeFindingDedupeKey,
  normalizeFindingRecord,
  normalizeSignatureVerificationStatus,
} = require("../mcp/core/finding-contracts.js");
const { SIGNATURE_VERIFICATION_STATUS_VALUES } = require("../mcp/lib/constants.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sig-marker-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

const DOMAIN = "audit.example.com";
const BASE_FINDING = Object.freeze({
  id: "F-1",
  target_domain: DOMAIN,
  title: "IDOR in /api/orders",
  severity: "medium",
  cwe: "CWE-639",
  endpoint: "https://audit.example.com/api/orders/1",
  description: "An attacker can read other users' orders.",
  proof_of_concept: "curl https://audit.example.com/api/orders/2",
  validated: true,
});

test("the marker round-trips through normalizeFindingRecord (strict write + tolerant read-back)", () => {
  const written = normalizeFindingRecord({
    ...BASE_FINDING,
    signature_verification_status: "unsigned",
    signature_error_reason: "merged from a handoff without a signing key",
    degradation_marked_at: "2026-06-14T00:00:00.000Z",
  }, { expectedDomain: DOMAIN, requireCwe: true });
  assert.equal(written.signature_verification_status, "unsigned");
  assert.equal(written.signature_error_reason, "merged from a handoff without a signing key");
  assert.equal(written.degradation_marked_at, "2026-06-14T00:00:00.000Z");

  // findingPayloadsFromClaims re-normalizes payload.finding with requireCwe
  // omitted (tolerant); the marker must survive that projection.
  const readBack = normalizeFindingRecord(written, { expectedDomain: DOMAIN });
  assert.equal(readBack.signature_verification_status, "unsigned");
  assert.equal(readBack.signature_error_reason, "merged from a handoff without a signing key");
});

test("a finding with no marker reads as signed (no back-fill)", () => {
  const finding = normalizeFindingRecord({ ...BASE_FINDING }, { expectedDomain: DOMAIN, requireCwe: true });
  assert.equal("signature_verification_status" in finding, false);
  assert.equal("signature_error_reason" in finding, false);
  assert.equal("degradation_marked_at" in finding, false);
});

test("an invalid marker throws on the strict write path and degrades to absent on tolerant read-back", () => {
  assert.throws(
    () => normalizeFindingRecord(
      { ...BASE_FINDING, signature_verification_status: "tampered" },
      { expectedDomain: DOMAIN, requireCwe: true },
    ),
    /signature_verification_status/,
  );
  const tolerant = normalizeFindingRecord(
    { ...BASE_FINDING, signature_verification_status: "tampered" },
    { expectedDomain: DOMAIN },
  );
  assert.equal("signature_verification_status" in tolerant, false);

  assert.equal(normalizeSignatureVerificationStatus(null), null);
  assert.equal(normalizeSignatureVerificationStatus("tampered"), null);
  for (const value of SIGNATURE_VERIFICATION_STATUS_VALUES) {
    assert.equal(normalizeSignatureVerificationStatus(value, { strict: true }), value);
  }
});

test("the marker is excluded from the finding dedupe key (ids stay byte-stable)", () => {
  const withoutMarker = computeFindingDedupeKey({ ...BASE_FINDING });
  const withMarker = computeFindingDedupeKey({
    ...BASE_FINDING,
    signature_verification_status: "unsigned",
    signature_error_reason: "x",
    degradation_marked_at: "2026-06-14T00:00:00.000Z",
  });
  assert.equal(withMarker, withoutMarker);
});

test("a producer-marked finding projects the marker through findingPayloadsFromClaims; an unmarked claim does not", () => {
  withTempHome(() => {
    // Unmarked claim recorded through the agent tool: no marker (agents cannot
    // self-declare signature status — it is producer-only).
    recordClaimTool.handler({
      target_domain: DOMAIN,
      title: BASE_FINDING.title,
      severity: "medium",
      cwe: "CWE-639",
      endpoint: BASE_FINDING.endpoint,
      description: BASE_FINDING.description,
      proof_of_concept: BASE_FINDING.proof_of_concept,
      response_evidence: "Cross-account order returned in attacker session",
      impact: "Cross-account data disclosure",
      validated: true,
      cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
    });

    // A producer (e.g. the wave-merge settler) persists a finding whose source
    // handoff could not be signature-verified, marking payload.finding directly.
    appendCandidateClaim({
      target_domain: DOMAIN,
      claim_id: "claim-merged-unsigned",
      title: "Cross-account export in /api/export",
      summary: "Merged finding from an unsigned-but-readable handoff.",
      severity: "medium",
      evidence_refs: [{ kind: "finding", finding_id: "F-2" }],
      payload: {
        finding: {
          id: "F-2",
          target_domain: DOMAIN,
          title: "Cross-account export in /api/export",
          severity: "medium",
          cwe: "CWE-639",
          endpoint: "https://audit.example.com/api/export/1",
          description: "Merged finding from an unsigned-but-readable handoff.",
          proof_of_concept: "GET /api/export/2 returns another tenant's data",
          validated: true,
          signature_verification_status: "unsigned",
          signature_error_reason: "merged from a handoff without a signing key",
          degradation_marked_at: "2026-06-14T00:00:00.000Z",
        },
      },
    });

    const findings = recordClaimTool.findingPayloadsFromClaims(DOMAIN);
    const marked = findings.filter((f) => f.signature_verification_status === "unsigned");
    const unmarked = findings.filter((f) => f.signature_verification_status == null);
    assert.equal(marked.length, 1);
    assert.equal(marked[0].signature_error_reason, "merged from a handoff without a signing key");
    assert.equal(unmarked.length, 1);
  });
});

test("a persisted finding whose marker is corrupt still projects, with the marker dropped to absent", () => {
  withTempHome(() => {
    appendCandidateClaim({
      target_domain: DOMAIN,
      claim_id: "claim-corrupt-marker",
      title: "Cross-account export in /api/export",
      summary: "Finding whose persisted signature marker is unparseable.",
      severity: "medium",
      evidence_refs: [{ kind: "finding", finding_id: "F-3" }],
      payload: {
        finding: {
          id: "F-3",
          target_domain: DOMAIN,
          title: "Cross-account export in /api/export",
          severity: "medium",
          cwe: "CWE-639",
          endpoint: "https://audit.example.com/api/export/3",
          description: "Finding whose persisted signature marker is unparseable.",
          proof_of_concept: "GET /api/export/4 returns another tenant's data",
          validated: true,
          signature_verification_status: "tampered",
        },
      },
    });
    const findings = recordClaimTool.findingPayloadsFromClaims(DOMAIN);
    assert.equal(findings.length, 1);
    assert.equal("signature_verification_status" in findings[0], false);
  });
});
