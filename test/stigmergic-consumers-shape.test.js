"use strict";

// Cycle Y.9 (rev 4.1) — Stigmergic consumers manifest shape test.
//
// Asserts:
//   * STIGMERGIC_CONSUMERS is Object.freeze'd (closed list).
//   * Exactly 10 canonical consumer entries per Y-D19 rev 4.1 + Plane-Delta S12/C9/I12/I10.
//   * Every entry carries the required keys (consumer_id,
//     source_location: {file, token_or_regex}, producer_id,
//     decision_boundary, rationale).
//   * consumer_id values are unique within the registry.
//   * Every consumer's producer_id matches a producer entry in
//     mcp/lib/stigmergic-producers.js (no orphans, Y-P14 closed manifest
//     pact).
//   * decision_boundary is one of the closed DECISION_BOUNDARY_VALUES.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  DECISION_BOUNDARY_VALUES,
  STIGMERGIC_CONSUMERS,
  CONSUMER_IDS,
  getConsumer,
  isKnownConsumerId,
  getConsumersForProducer,
} = require("../mcp/lib/stigmergic-consumers.js");
const {
  STIGMERGIC_PRODUCERS,
  isKnownProducerId,
} = require("../mcp/lib/stigmergic-producers.js");

const CANONICAL_CONSUMER_IDS = [
  "assignment_brief_technique_section_renderer",
  "orchestrator_handoff_receipt_record_surface_leads",
  "chain_builder_prompt_body_read_before_propose",
  "compose_report_provenance_gate",
  "write_chain_rollup_evidence_refs_validator",
  "evaluator_spawn_friction_log_on_internal_error",
  "assignment_brief_reachability_triage_renderer",
  "grade_verdict_reachability_ceiling_reconciler",
  "assignment_brief_oss_technique_pack_renderer",
  "c11_static_analysis_brief_slice",
];

test("STIGMERGIC_CONSUMERS is Object.freeze'd and elements are frozen", () => {
  assert.equal(Object.isFrozen(STIGMERGIC_CONSUMERS), true);
  for (const entry of STIGMERGIC_CONSUMERS) {
    assert.equal(
      Object.isFrozen(entry),
      true,
      `${entry.consumer_id} must be frozen`,
    );
    assert.equal(
      Object.isFrozen(entry.source_location),
      true,
      `${entry.consumer_id}.source_location must be frozen`,
    );
  }
  assert.equal(Object.isFrozen(CONSUMER_IDS), true);
  assert.equal(Object.isFrozen(DECISION_BOUNDARY_VALUES), true);
});

test("STIGMERGIC_CONSUMERS contains exactly the 10 canonical Y-D19/Plane-Delta entries", () => {
  assert.equal(STIGMERGIC_CONSUMERS.length, 10);
  const actualIds = STIGMERGIC_CONSUMERS.map((c) => c.consumer_id).sort();
  const expectedIds = [...CANONICAL_CONSUMER_IDS].sort();
  assert.deepEqual(
    actualIds,
    expectedIds,
    "consumer_id vocabulary MUST match canonical Y-D19/Plane-Delta set exactly",
  );
});

test("every consumer entry carries the required keys with correct shape", () => {
  for (const entry of STIGMERGIC_CONSUMERS) {
    assert.equal(typeof entry.consumer_id, "string");
    assert.ok(entry.consumer_id.length > 0);
    assert.equal(typeof entry.source_location, "object");
    assert.equal(typeof entry.source_location.file, "string");
    assert.ok(entry.source_location.file.length > 0);
    const tor = entry.source_location.token_or_regex;
    assert.ok(
      typeof tor === "string" || tor instanceof RegExp,
      `${entry.consumer_id}.source_location.token_or_regex must be string or RegExp`,
    );
    assert.equal(typeof entry.producer_id, "string");
    assert.ok(entry.producer_id.length > 0);
    assert.ok(
      DECISION_BOUNDARY_VALUES.includes(entry.decision_boundary),
      `${entry.consumer_id}.decision_boundary "${entry.decision_boundary}" must be in DECISION_BOUNDARY_VALUES`,
    );
    assert.equal(typeof entry.rationale, "string");
    assert.ok(entry.rationale.length > 0);
  }
});

test("consumer_id values are unique within the registry", () => {
  const seen = new Set();
  for (const entry of STIGMERGIC_CONSUMERS) {
    assert.equal(
      seen.has(entry.consumer_id),
      false,
      `duplicate consumer_id ${entry.consumer_id}`,
    );
    seen.add(entry.consumer_id);
  }
});

test("every consumer's producer_id matches a producer entry in STIGMERGIC_PRODUCERS", () => {
  // Y-P14 closed manifest pact: no orphans, no fabricated producer names.
  const producerIds = new Set(STIGMERGIC_PRODUCERS.map((p) => p.producer_id));
  for (const consumer of STIGMERGIC_CONSUMERS) {
    assert.equal(
      producerIds.has(consumer.producer_id),
      true,
      `consumer ${consumer.consumer_id} references producer_id "${consumer.producer_id}" not in STIGMERGIC_PRODUCERS`,
    );
    assert.equal(isKnownProducerId(consumer.producer_id), true);
  }
});

test("lookup helpers resolve canonical ids and return null for unknown", () => {
  assert.equal(
    getConsumer("compose_report_provenance_gate").consumer_id,
    "compose_report_provenance_gate",
  );
  assert.equal(getConsumer("not_a_real_consumer"), null);
  assert.equal(
    isKnownConsumerId("write_chain_rollup_evidence_refs_validator"),
    true,
  );
  assert.equal(isKnownConsumerId(""), false);
});

test("getConsumersForProducer returns consumers indexed by producer_id", () => {
  const chainConsumers = getConsumersForProducer("chain_attempts_ledger");
  assert.equal(chainConsumers.length, 1);
  assert.equal(
    chainConsumers[0].consumer_id,
    "chain_builder_prompt_body_read_before_propose",
  );
  assert.equal(getConsumersForProducer("not_a_real_producer").length, 0);
});

test("producers' registered_consumers overlap STIGMERGIC_CONSUMERS (bidirectional pact)", () => {
  const consumerIds = new Set(STIGMERGIC_CONSUMERS.map((c) => c.consumer_id));
  for (const producer of STIGMERGIC_PRODUCERS) {
    const overlap = (producer.registered_consumers || []).filter((id) =>
      consumerIds.has(id),
    );
    assert.ok(
      overlap.length >= 1,
      `producer ${producer.producer_id} registered_consumers ${JSON.stringify(producer.registered_consumers)} has no overlap with STIGMERGIC_CONSUMERS`,
    );
  }
});
