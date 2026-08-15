"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  CANDIDATE_TIER,
  normalizeCweEntry,
  normalizeAuditFinding,
  normalizeSchemaContract,
  normalizeKnowledgeRecord,
  normalizeKnowledgeBatch,
  candidateDedupKey,
  buildAdvisoryEvidence,
} = require("../mcp/core/mechanism/index.js");

const {
  loadMechanismTemplates,
} = require("../mcp/core/mechanism/index.js");

// The validated target shape: a candidate must satisfy the same loader the live
// corpus uses, so the abstraction is real and not a parallel format.
function assertValidatesAsMechanismTemplate(template) {
  const { templates, warnings } = loadMechanismTemplates([template]);
  assert.equal(warnings.length, 0, `template should load cleanly, got warnings: ${JSON.stringify(warnings)}`);
  assert.equal(templates.length, 1, "exactly one template should load");
  const loaded = templates[0];
  assert.ok(Array.isArray(loaded.required_entities) && loaded.required_entities.length > 0);
  assert.ok(Array.isArray(loaded.interventions) && loaded.interventions.length > 0);
  assert.ok(Array.isArray(loaded.positive_controls) && loaded.positive_controls.length > 0);
  assert.ok(Array.isArray(loaded.negative_controls) && loaded.negative_controls.length > 0);
  assert.ok(loaded.evidence_predicate && typeof loaded.evidence_predicate === "object");
}

// A candidate must validate yet stay merely-believed: tier-3, advisory, no
// claim authority, no executed proof, not verified.
function assertTier3Advisory(template) {
  assert.equal(template.tier, CANDIDATE_TIER, "candidate is tier-3");
  assert.equal(template.candidate, true, "carries the candidate marker");
  assert.equal(template.claim_authority, false, "no claim authority");
  assert.equal(template.advisory_evidence.executed_proof, false, "no executed proof");
  assert.equal(template.advisory_evidence.verified, false, "not verified");
  assert.equal(template.advisory_evidence.claim_authority, false, "evidence carries no claim authority");
}

test("CWE-catalog entry normalizes to a candidate that validates as a mechanism template", () => {
  const { template, warnings } = normalizeCweEntry({ id: "CWE-639", title: "Authorization Bypass Through User-Controlled Key (IDOR)" });
  assert.equal(warnings.length, 0);
  assert.ok(template);
  assert.equal(template.mechanism_id, "CWE-639");
  assertValidatesAsMechanismTemplate(template);
  assertTier3Advisory(template);
});

test("CWE-catalog entry accepts a bare id and canonicalizes loose forms", () => {
  const fromBare = normalizeCweEntry("cwe_639").template;
  assert.ok(fromBare);
  assert.equal(fromBare.mechanism_id, "CWE-639");
  assert.equal(fromBare.tier, CANDIDATE_TIER);
});

test("CWE-catalog entry with no resolvable id is held back, not confirmed", () => {
  const { template, warnings } = normalizeCweEntry({ id: "not-a-cwe" });
  assert.equal(template, null);
  assert.ok(warnings.length > 0);
});

test("audit finding with a PoC captures the PoC as advisory, never as confirmation", () => {
  const finding = {
    title: "Admin endpoint reachable without role",
    description: "GET /admin returns 200 for any session.",
    vulnerability_class: "access_control",
    finding_hash: "abc123def456",
    poc: "curl -H 'Cookie: session=user' https://target/admin -> 200",
    not_a_false_positive: "The endpoint mutates global config; confirmed in staging.",
  };
  const { template, warnings } = normalizeAuditFinding(finding, { cwe: "CWE-862" });
  assert.equal(warnings.length, 0);
  assert.ok(template);
  assertValidatesAsMechanismTemplate(template);
  assertTier3Advisory(template);
  // The bundled PoC + rationale are captured, but flagged unverified.
  assert.equal(template.advisory_evidence.advisory_poc_present, true);
  assert.ok(template.advisory_evidence.advisory_poc.includes("curl"));
  assert.ok(template.advisory_evidence.advisory_not_a_false_positive.includes("staging"));
  assert.equal(template.advisory_evidence.verified, false, "a PoC does not mint verified");
  assert.equal(template.advisory_evidence.executed_proof, false, "a PoC is not an executed differential");
});

test("audit finding without a catalog CWE is held back (CWE shapes mechanism_id, never drops the lead)", () => {
  const { template, warnings } = normalizeAuditFinding({ title: "Some bug" });
  assert.equal(template, null);
  assert.ok(warnings.some((w) => /catalog CWE/.test(w)));
});

test("schema contract normalizes to a doc-vs-behavior candidate with a refuting control", () => {
  const contract = {
    endpoint: "/api/orders/{id}",
    method: "get",
    contract_hash: "deadbeefcafe0001",
    claimed_auth: { schemes: ["bearer"] },
  };
  const { template, warnings } = normalizeSchemaContract(contract);
  assert.equal(warnings.length, 0);
  assert.ok(template);
  assert.equal(template.mechanism_id, "CWE-345");
  assertValidatesAsMechanismTemplate(template);
  assertTier3Advisory(template);
  assert.ok(
    template.negative_controls.some((c) => /documented_request_behaves_as_documented/.test(c)),
    "carries a control that must flip",
  );
});

test("every candidate carries a refuting negative control (no single-run pass mints verified)", () => {
  const cwe = normalizeCweEntry({ id: "CWE-284" }).template;
  const audit = normalizeAuditFinding({ title: "x", vulnerability_class: "access_control" }, { cwe: "CWE-862" }).template;
  const schema = normalizeSchemaContract({ endpoint: "/x", method: "post" }).template;
  for (const template of [cwe, audit, schema]) {
    assert.ok(template.negative_controls.includes("benign_baseline_must_hold"));
    assert.ok(template.negative_controls.includes("non_discriminating_control_refused"));
    assert.ok(template.positive_controls.length > 0, "has a positive control to flip against");
  }
});

test("dedup collapses two near-identical inputs to one candidate", () => {
  const batch = normalizeKnowledgeBatch(
    [
      { kind: "cwe_catalog", record: { id: "CWE-639" } },
      { kind: "cwe_catalog", record: { id: "cwe-639" } },
      { kind: "cwe_catalog", record: { id: "CWE-284" } },
    ],
  );
  assert.equal(batch.candidates.length, 2, "the two CWE-639 variants collapse; CWE-284 survives");
  assert.ok(batch.warnings.some((w) => Array.isArray(w.warnings) && w.warnings.some((m) => /duplicate candidate dedup_key/.test(m))));
});

test("dedup keys differ across source tiers for the same underlying class", () => {
  const cwe = normalizeCweEntry({ id: "CWE-862" }).template;
  const audit = normalizeAuditFinding({ title: "missing authz", vulnerability_class: "access_control" }, { cwe: "CWE-862" }).template;
  assert.notEqual(candidateDedupKey(cwe), candidateDedupKey(audit));
});

test("dedup ranks rather than bounds: distinct keys all survive", () => {
  const records = [];
  for (const id of ["CWE-639", "CWE-284", "CWE-862", "CWE-345", "CWE-918"]) {
    records.push({ kind: "cwe_catalog", record: { id } });
  }
  const batch = normalizeKnowledgeBatch(records);
  assert.equal(batch.candidates.length, 5, "no distinct candidate is truncated");
});

test("a loaded candidate still reads as advisory, not confirmed (validation does not promote)", () => {
  // The risk this guards: a candidate that VALIDATES could be mistaken for a
  // confirmed corpus template. After loading through the live loader, the
  // advisory markers must still be present on the produced candidate object.
  const candidate = normalizeCweEntry({ id: "CWE-639" }).template;
  assertValidatesAsMechanismTemplate(candidate);
  // The candidate object itself never loses its tier-3 advisory framing.
  assert.equal(candidate.claim_authority, false);
  assert.equal(candidate.tier, CANDIDATE_TIER);
  assert.equal(candidate.candidate, true);
});

test("buildAdvisoryEvidence defaults to unverified with no proof", () => {
  const ev = buildAdvisoryEvidence(null, "cwe_catalog");
  assert.equal(ev.verified, false);
  assert.equal(ev.executed_proof, false);
  assert.equal(ev.claim_authority, false);
  assert.equal(ev.tier, CANDIDATE_TIER);
});

test("normalizeKnowledgeRecord rejects an unknown kind", () => {
  const { template, warnings } = normalizeKnowledgeRecord({}, "mystery");
  assert.equal(template, null);
  assert.ok(warnings.some((w) => /unknown knowledge record kind/.test(w)));
});

test("batch normalize honors a single kind via options without per-item envelopes", () => {
  const batch = normalizeKnowledgeBatch(
    [{ id: "CWE-639" }, { id: "CWE-284" }],
    { kind: "cwe_catalog" },
  );
  assert.equal(batch.candidates.length, 2);
  for (const c of batch.candidates) {
    assert.equal(c.tier, CANDIDATE_TIER);
    assert.equal(c.claim_authority, false);
  }
});
