"use strict";

// The candidate-claim readers surface the trust-degradation marker and a
// degraded_count aggregate so a reader can see which findings came from a
// source that could not be signature-verified. Signed findings carry no marker
// and their list rows stay byte-stable.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const readClaimsTool = require("../mcp/lib/tools/read-candidate-claims.js");
const listClaimsTool = require("../mcp/lib/tools/list-candidate-claims.js");
const recordClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const { appendCandidateClaim } = require("../mcp/lib/claims.js");

const DOMAIN = "degraded-reader.example.com";

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-degraded-reader-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function recordSignedFinding() {
  recordClaimTool.handler({
    target_domain: DOMAIN,
    title: "Signed IDOR in /api/orders",
    severity: "medium",
    cwe: "CWE-639",
    endpoint: `https://${DOMAIN}/api/orders/1`,
    description: "An attacker can read other users' orders.",
    proof_of_concept: `curl https://${DOMAIN}/api/orders/2`,
    response_evidence: "Cross-account order returned in attacker session",
    impact: "Cross-account data disclosure",
    validated: true,
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
  });
}

function persistDegradedFinding() {
  appendCandidateClaim({
    target_domain: DOMAIN,
    claim_id: "claim-unsigned",
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
        endpoint: `https://${DOMAIN}/api/export/2`,
        description: "Merged finding from an unsigned-but-readable handoff.",
        proof_of_concept: "GET /api/export/3 returns another tenant's data",
        validated: true,
        signature_verification_status: "unsigned",
        signature_error_reason: "merged from a handoff without a signing key",
      },
    },
  });
}

test("read-candidate-claims surfaces the marker and a degraded_count", () => {
  withTempHome(() => {
    recordSignedFinding();
    persistDegradedFinding();
    const out = JSON.parse(readClaimsTool.handler({ target_domain: DOMAIN }));
    assert.equal(out.degraded_count, 1);
    assert.equal(out.findings.filter((f) => f.signature_verification_status === "unsigned").length, 1);
    assert.equal(out.findings.filter((f) => f.signature_verification_status == null).length, 1);
  });
});

test("list-candidate-claims surfaces the marker on degraded rows only, plus a degraded_count", () => {
  withTempHome(() => {
    recordSignedFinding();
    persistDegradedFinding();
    const out = JSON.parse(listClaimsTool.handler({ target_domain: DOMAIN }));
    assert.equal(out.degraded_count, 1);
    assert.equal(out.findings.filter((r) => r.signature_verification_status === "unsigned").length, 1);
    assert.equal(out.findings.filter((r) => !("signature_verification_status" in r)).length, 1);
  });
});

test("an explicit signed marker is not surfaced as degradation (only unsigned counts)", () => {
  withTempHome(() => {
    appendCandidateClaim({
      target_domain: DOMAIN,
      claim_id: "claim-explicit-signed",
      title: "Explicitly-signed finding",
      summary: "A finding carrying an explicit signed marker.",
      severity: "medium",
      evidence_refs: [{ kind: "finding", finding_id: "F-9" }],
      payload: {
        finding: {
          id: "F-9",
          target_domain: DOMAIN,
          title: "Explicitly-signed finding",
          severity: "medium",
          cwe: "CWE-639",
          endpoint: `https://${DOMAIN}/api/orders/9`,
          description: "A finding carrying an explicit signed marker.",
          proof_of_concept: "curl https://degraded-reader.example.com/api/orders/9",
          validated: true,
          signature_verification_status: "signed",
        },
      },
    });
    const list = JSON.parse(listClaimsTool.handler({ target_domain: DOMAIN }));
    assert.equal("degraded_count" in list, false);
    assert.equal(list.findings.every((r) => !("signature_verification_status" in r)), true);
    const read = JSON.parse(readClaimsTool.handler({ target_domain: DOMAIN }));
    assert.equal("degraded_count" in read, false);
  });
});

test("a fully signed session omits degraded_count and carries no marker fields (byte-stable)", () => {
  withTempHome(() => {
    recordSignedFinding();
    const read = JSON.parse(readClaimsTool.handler({ target_domain: DOMAIN }));
    assert.equal("degraded_count" in read, false);
    assert.equal(read.findings.every((f) => f.signature_verification_status == null), true);
    const list = JSON.parse(listClaimsTool.handler({ target_domain: DOMAIN }));
    assert.equal("degraded_count" in list, false);
    assert.equal(list.findings.every((r) => !("signature_verification_status" in r)), true);
  });
});
