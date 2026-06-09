"use strict";

// Cycle Y.6 (rev 4.1) — Stigmergic producers manifest shape test.
//
// Asserts:
//   * STIGMERGIC_PRODUCERS is Object.freeze'd (closed list).
//   * Exactly 9 canonical producer entries per Y-D19 rev 4.1 + Plane-Delta S12/PR4/I10.
//   * Every entry carries the required keys (producer_id,
//     mcp_tool_or_artifact, trace_shape_ref, registered_consumers).
//   * registered_consumers[] is non-empty for every entry (every
//     manifested producer has at least one consumer reference).
//   * producer_id values are unique within the registry.
//   * producer_id values match the canonical rev-4.1 vocabulary exactly
//     (no rev-4 renames like surface_leads_ledger /
//     capability_friction_observed_kind / hypothesis_ledger /
//     static_artifact_handles survive).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const {
  STIGMERGIC_PRODUCERS,
  PRODUCER_IDS,
  getProducer,
  isKnownProducerId,
} = require("../mcp/lib/stigmergic-producers.js");

const REPO_ROOT = path.join(__dirname, "..");

const CANONICAL_PRODUCER_IDS = [
  "technique_pack_scorer",
  "surface_discovery_ranked_leads",
  "chain_attempts_ledger",
  "verification_round_ledger",
  "mcp_owned_body_binding_handles",
  "capability_friction_ledger",
  "repo_inventory_reachability_stamp",
  "oss_technique_pack_registry",
  "static_analysis_index",
];

test("STIGMERGIC_PRODUCERS is Object.freeze'd and elements are frozen", () => {
  assert.equal(Object.isFrozen(STIGMERGIC_PRODUCERS), true);
  for (const entry of STIGMERGIC_PRODUCERS) {
    assert.equal(Object.isFrozen(entry), true, `${entry.producer_id} must be frozen`);
    assert.equal(
      Object.isFrozen(entry.registered_consumers),
      true,
      `${entry.producer_id}.registered_consumers must be frozen`,
    );
  }
  assert.equal(Object.isFrozen(PRODUCER_IDS), true);
});

test("STIGMERGIC_PRODUCERS contains exactly the 9 canonical Y-D19 + Plane-Delta S12/PR4/I10 entries", () => {
  assert.equal(STIGMERGIC_PRODUCERS.length, 9);
  const actualIds = STIGMERGIC_PRODUCERS.map((p) => p.producer_id).sort();
  const expectedIds = [...CANONICAL_PRODUCER_IDS].sort();
  assert.deepEqual(
    actualIds,
    expectedIds,
    "producer_id vocabulary MUST match canonical Y-D19 (rev 4.1) set exactly",
  );
});

test("every producer entry carries the required keys with correct shape", () => {
  for (const entry of STIGMERGIC_PRODUCERS) {
    assert.equal(typeof entry.producer_id, "string");
    assert.ok(entry.producer_id.length > 0);
    assert.equal(typeof entry.mcp_tool_or_artifact, "string");
    assert.ok(entry.mcp_tool_or_artifact.length > 0);
    assert.equal(typeof entry.trace_shape_ref, "string");
    assert.ok(entry.trace_shape_ref.length > 0);
    assert.ok(
      Array.isArray(entry.registered_consumers),
      `${entry.producer_id}.registered_consumers must be an array`,
    );
    assert.ok(
      entry.registered_consumers.length >= 1,
      `${entry.producer_id} must have at least one registered consumer`,
    );
    for (const consumerId of entry.registered_consumers) {
      assert.equal(typeof consumerId, "string");
      assert.ok(consumerId.length > 0);
    }
  }
});

test("producer_id values are unique within the registry", () => {
  const seen = new Set();
  for (const entry of STIGMERGIC_PRODUCERS) {
    assert.equal(
      seen.has(entry.producer_id),
      false,
      `duplicate producer_id ${entry.producer_id}`,
    );
    seen.add(entry.producer_id);
  }
});

test("rev-4 renamed strings do NOT survive in the rev-4.1 manifest", () => {
  // Defect 5 reconciliation: the rev-4 draft used these strings; rev 4.1
  // commits the canonical vocabulary so the cross-reference tests resolve.
  const REV4_REMOVED = new Set([
    "surface_leads_ledger",
    "hypothesis_ledger",
    "capability_friction_observed_kind",
    "static_artifact_handles",
  ]);
  for (const removedId of REV4_REMOVED) {
    assert.equal(
      isKnownProducerId(removedId),
      false,
      `rev-4 removed producer_id "${removedId}" must NOT appear in rev-4.1 manifest`,
    );
  }
});

test("lookup helpers resolve canonical ids and return null for unknown", () => {
  assert.equal(getProducer("chain_attempts_ledger").producer_id, "chain_attempts_ledger");
  assert.equal(getProducer("not_a_real_producer"), null);
  assert.equal(isKnownProducerId("verification_round_ledger"), true);
  assert.equal(isKnownProducerId(""), false);
});

// Rev 4.1 closure — brutalist Y.6 defect: trace_shape_ref strings pointed at
// phantom symbols (`mcp/lib/capability-packs.js#selectTechniquePacksForSurface`,
// `mcp/lib/wave-handoff-contracts.js#ranked_leads`). The shape test asserted
// `typeof trace_shape_ref === "string"` but never verified the path or the
// symbol resolved on disk. Add the mechanical ground-truth assertion here so
// any future drift between the manifest and the implementation is caught at
// CI rather than at runtime.
test("every trace_shape_ref `path#symbol` resolves on disk (mechanical ground-truth)", () => {
  for (const entry of STIGMERGIC_PRODUCERS) {
    const ref = entry.trace_shape_ref;
    // Accept either "path#symbol" or "path" (path-only refs are valid for
    // artifact-level producers whose shape is the whole file).
    const hashIndex = ref.indexOf("#");
    const filePath = hashIndex === -1 ? ref : ref.slice(0, hashIndex);
    const symbol = hashIndex === -1 ? null : ref.slice(hashIndex + 1);

    const absPath = path.join(REPO_ROOT, filePath);
    assert.ok(
      fs.existsSync(absPath),
      `${entry.producer_id}: trace_shape_ref path "${filePath}" does not exist on disk`,
    );

    if (symbol) {
      const content = fs.readFileSync(absPath, "utf8");
      assert.ok(
        content.includes(symbol),
        `${entry.producer_id}: trace_shape_ref symbol "${symbol}" not found in ${filePath}`,
      );
    }
  }
});
