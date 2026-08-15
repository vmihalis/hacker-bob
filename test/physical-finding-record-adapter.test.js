"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  derivePhysicalAssignmentContextDigest,
  derivePhysicalFindingDedupeKey,
} = require("../mcp/domains/physical/physical-capability-consumers.js");
const {
  buildPersistedPhysicalFindingRecord,
  normalizePhysicalFindingRecord,
} = require("../mcp/domains/physical/physical-finding-record-adapter.js");
const {
  declaredFindingRecordAdapter,
  normalizeFindingRecord,
} = require("../mcp/core/finding-contracts.js");

const NUCLEUS = "d".repeat(64);
const PROJECTION = "b".repeat(64);

function assignmentFixture(overrides = {}) {
  const assignment = {
    version: 1,
    capability_pack: "physical",
    capability_pack_version: 1,
    evaluator_agent: "evaluator-physical-agent",
    brief_profile: "physical",
    surface_id: "surface:door-reader",
    surface_type: "control_point",
    surface_class: "physical",
    session_nucleus_hash: NUCLEUS,
    asset_locator: "physical-asset:door-reader",
    campaign_ref: "physical-campaign:campaign-1",
    physical_resource_bundle_ref: "physical-resource-bundle:bundle-1",
    lifecycle_precondition: "no_active_effects",
    effect_authority: "broker_admission_required",
    ...overrides,
  };
  if (!Object.prototype.hasOwnProperty.call(overrides, "assignment_context_digest")) {
    assignment.assignment_context_digest = derivePhysicalAssignmentContextDigest(assignment);
  }
  return assignment;
}

function recordFixture(overrides = {}) {
  const assignment = assignmentFixture();
  const record = {
    id: "F-1",
    target_domain: "physical-session-1",
    ...assignment,
    finding_kind: "physical_verified_transition",
    verified_verdict_ref: "physical-claim-verdict:verdict-1",
    verification_projection_digest: PROJECTION,
    title: "Credential representation crosses the restricted-zone control",
    severity: "high",
    cwe: "CWE-284",
    description: "An independently observed differential shows the representation crossing the control boundary.",
    impact: "An unauthorized bearer could reach the bounded restricted zone.",
    validity_kind: "historical_event",
    decided_at: "2026-07-20T00:01:00.000Z",
    validated: true,
    ...overrides,
  };
  if (!Object.prototype.hasOwnProperty.call(overrides, "finding_dedupe_key")) {
    record.finding_dedupe_key = derivePhysicalFindingDedupeKey({
      asset_locator: record.asset_locator,
      verified_verdict_ref: record.verified_verdict_ref,
      verification_projection_digest: record.verification_projection_digest,
      title: record.title,
    });
  }
  if (!Object.prototype.hasOwnProperty.call(overrides, "dedupe_key")) {
    record.dedupe_key = record.finding_dedupe_key;
  }
  return record;
}

test("physical finding records dispatch through the pack-declared adapter", () => {
  const raw = recordFixture();
  const declared = declaredFindingRecordAdapter(raw);
  assert.equal(declared.adapter_id, "physical_verified_transition_finding_v1");

  const direct = normalizePhysicalFindingRecord(raw, {
    expectedDomain: raw.target_domain,
  });
  const generic = normalizeFindingRecord(raw, {
    expectedDomain: raw.target_domain,
  });
  assert.deepEqual(generic, direct);
  assert.ok(Object.isFrozen(generic));
  assert.equal(generic.asset_locator, "physical-asset:door-reader");
  assert.equal(generic.verified_verdict_ref, "physical-claim-verdict:verdict-1");
  assert.equal(Object.prototype.hasOwnProperty.call(generic, "endpoint"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(generic, "proof_of_concept"), false);
});

test("physical finding records reject web shims and every authority/dedupe drift", () => {
  for (const [field, value] of [
    ["endpoint", "https://invalid.example/door"],
    ["proof_of_concept", "raw command bytes"],
    ["base_url", "https://invalid.example"],
    ["response_evidence", "raw card data"],
    ["sc_evidence", {}],
  ]) {
    assert.throws(
      () => normalizeFindingRecord({ ...recordFixture(), [field]: value }),
      /fields are not exact|cannot carry/,
      field,
    );
  }

  assert.throws(
    () => normalizeFindingRecord(recordFixture({ dedupe_key: "0".repeat(24) })),
    /dedupe binding drifted/,
  );
  assert.throws(
    () => normalizeFindingRecord(recordFixture({
      asset_locator: "physical-asset:other-reader",
    })),
    /assignment_context_digest does not bind/,
  );
  assert.throws(
    () => normalizeFindingRecord(recordFixture({ validated: false })),
    /must be ledger-validated/,
  );
  assert.throws(
    () => normalizeFindingRecord(recordFixture(), { expectedDomain: "other-session" }),
    /target_domain mismatch/,
  );
});

test("physical persistence builder accepts only a live branded finding", () => {
  assert.throws(
    () => buildPersistedPhysicalFindingRecord({
      finding: {},
      id: "F-1",
      target_domain: "physical-session-1",
      assignment: assignmentFixture(),
    }),
    /physical finding adapter/,
  );
});

test("physical finding line diagnostics remain bounded and identify the malformed row", () => {
  assert.throws(
    () => normalizePhysicalFindingRecord(
      recordFixture({
        verification_projection_digest: "not-a-digest",
        finding_dedupe_key: "0".repeat(24),
        dedupe_key: "0".repeat(24),
      }),
      { lineNumber: 9 },
    ),
    /Malformed findings\.jsonl at line 9:/,
  );
});
