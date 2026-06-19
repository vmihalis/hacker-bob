"use strict";

// Cycle Y.6 (rev 4.1) — Role-trace-expectations shape test.
//
// Asserts:
//   * ROLE_TRACE_EXPECTATIONS is Object.freeze'd (closed map).
//   * Every entry references a fragment_id present in
//     FRICTION_PROMPT_FRAGMENTS (Y.2) — direction A of the cross-reference
//     (no role consumer references a non-manifested fragment).
//   * Every entry references a producer_id present in STIGMERGIC_PRODUCERS
//     (Y.6) — direction B of the cross-reference (no role consumer
//     references a non-manifested producer).
//   * Every entry's decision_boundary is in the closed Y-P14a enum.
//   * No escape-hatch wording: the tests use strict set membership, NOT
//     "OR future role-specific fragment module".

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  ROLE_TRACE_EXPECTATIONS,
  DECISION_BOUNDARY_VALUES,
  ROLE_IDS,
  getExpectationsForRole,
  getExpectationsForRoleByBoundary,
} = require("../mcp/lib/role-trace-expectations.js");
const {
  FRICTION_PROMPT_FRAGMENTS,
  isKnownFragmentId,
} = require("../mcp/lib/friction-prompt-fragments.js");
const {
  STIGMERGIC_PRODUCERS,
  isKnownProducerId,
} = require("../mcp/lib/stigmergic-producers.js");

test("ROLE_TRACE_EXPECTATIONS is Object.freeze'd at every level", () => {
  assert.equal(Object.isFrozen(ROLE_TRACE_EXPECTATIONS), true);
  for (const role of Object.keys(ROLE_TRACE_EXPECTATIONS)) {
    const entries = ROLE_TRACE_EXPECTATIONS[role];
    assert.ok(Array.isArray(entries), `${role} expectations must be an array`);
    assert.equal(Object.isFrozen(entries), true, `${role} entries must be frozen`);
    for (const entry of entries) {
      assert.equal(Object.isFrozen(entry), true, `${role} entry must be frozen`);
    }
  }
  assert.equal(Object.isFrozen(DECISION_BOUNDARY_VALUES), true);
  assert.equal(Object.isFrozen(ROLE_IDS), true);
});

test("every entry has the required keys with correct shape", () => {
  for (const role of Object.keys(ROLE_TRACE_EXPECTATIONS)) {
    for (const entry of ROLE_TRACE_EXPECTATIONS[role]) {
      assert.equal(typeof entry.fragment_id, "string", `${role} entry fragment_id`);
      assert.ok(entry.fragment_id.length > 0);
      assert.equal(typeof entry.decision_boundary, "string", `${role} entry decision_boundary`);
      assert.equal(typeof entry.producer_id, "string", `${role} entry producer_id`);
      assert.ok(entry.producer_id.length > 0);
    }
  }
});

test("every fragment_id matches a FRICTION_PROMPT_FRAGMENTS entry (direction A — no escape hatch)", () => {
  for (const role of Object.keys(ROLE_TRACE_EXPECTATIONS)) {
    for (const entry of ROLE_TRACE_EXPECTATIONS[role]) {
      assert.equal(
        isKnownFragmentId(entry.fragment_id),
        true,
        `${role} references fragment_id "${entry.fragment_id}" that is NOT in FRICTION_PROMPT_FRAGMENTS`,
      );
    }
  }
});

test("every producer_id matches a STIGMERGIC_PRODUCERS entry (direction B — no escape hatch)", () => {
  for (const role of Object.keys(ROLE_TRACE_EXPECTATIONS)) {
    for (const entry of ROLE_TRACE_EXPECTATIONS[role]) {
      assert.equal(
        isKnownProducerId(entry.producer_id),
        true,
        `${role} references producer_id "${entry.producer_id}" that is NOT in STIGMERGIC_PRODUCERS`,
      );
    }
  }
});

test("every decision_boundary is in the closed Y-P14a enum", () => {
  for (const role of Object.keys(ROLE_TRACE_EXPECTATIONS)) {
    for (const entry of ROLE_TRACE_EXPECTATIONS[role]) {
      assert.ok(
        DECISION_BOUNDARY_VALUES.includes(entry.decision_boundary),
        `${role} decision_boundary "${entry.decision_boundary}" is not in the closed enum`,
      );
    }
  }
});

test("the 4 canonical roles are present (chain-builder, surface-discovery, report-writer, evaluator-spawn)", () => {
  const expectedRoles = ["chain-builder", "surface-discovery", "report-writer", "evaluator-spawn"];
  for (const role of expectedRoles) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(ROLE_TRACE_EXPECTATIONS, role),
      `role "${role}" must be present in ROLE_TRACE_EXPECTATIONS`,
    );
  }
});

test("chain-builder maps to chain_attempts_ledger producer at chain_attempt_proposal boundary", () => {
  // Defect 5 (rev 4.1) reconciliation: rev 4 invented hypothesis_ledger.
  // The canonical producer for both chain-builder fragments is
  // chain_attempts_ledger (the actual trace consumed before proposing).
  const cb = getExpectationsForRoleByBoundary("chain-builder", "chain_attempt_proposal");
  assert.equal(cb.length, 2);
  for (const entry of cb) {
    assert.equal(entry.producer_id, "chain_attempts_ledger");
  }
});

test("evaluator-spawn maps to capability_friction_ledger (NOT the rev-4 invented capability_friction_observed_kind)", () => {
  const ev = getExpectationsForRole("evaluator-spawn");
  assert.ok(ev && ev.length >= 1);
  for (const entry of ev) {
    // Rev 4 used capability_friction_observed_kind (an event_kind, not a
    // producer). Rev 4.1 added capability_friction_ledger as producer #6
    // so this assertion resolves mechanically.
    assert.equal(entry.producer_id, "capability_friction_ledger");
  }
});

test("FRICTION_PROMPT_FRAGMENTS contains every fragment_id referenced by ROLE_TRACE_EXPECTATIONS (no orphans)", () => {
  // This guards against a Y.2 fragment removal silently orphaning a Y.6
  // consumer. Y.6 is the authoritative reference, so the assertion lives
  // here too (Y.2's cross-reference test asserts the inverse direction).
  const referenced = new Set();
  for (const role of Object.keys(ROLE_TRACE_EXPECTATIONS)) {
    for (const entry of ROLE_TRACE_EXPECTATIONS[role]) {
      referenced.add(entry.fragment_id);
    }
  }
  for (const fragmentId of referenced) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(FRICTION_PROMPT_FRAGMENTS, fragmentId),
      `fragment_id "${fragmentId}" referenced by ROLE_TRACE_EXPECTATIONS is not in FRICTION_PROMPT_FRAGMENTS`,
    );
  }
});

test("STIGMERGIC_PRODUCERS contains every producer_id referenced by ROLE_TRACE_EXPECTATIONS (no orphans)", () => {
  const referenced = new Set();
  for (const role of Object.keys(ROLE_TRACE_EXPECTATIONS)) {
    for (const entry of ROLE_TRACE_EXPECTATIONS[role]) {
      referenced.add(entry.producer_id);
    }
  }
  const manifested = new Set(STIGMERGIC_PRODUCERS.map((p) => p.producer_id));
  for (const producerId of referenced) {
    assert.ok(
      manifested.has(producerId),
      `producer_id "${producerId}" referenced by ROLE_TRACE_EXPECTATIONS is not in STIGMERGIC_PRODUCERS`,
    );
  }
});

test("getExpectationsForRole returns null for unknown roles", () => {
  assert.equal(getExpectationsForRole("not-a-real-role"), null);
});
