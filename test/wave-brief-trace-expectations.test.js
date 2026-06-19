"use strict";

// Plane Y Cycle Y.5 (rev 4 W1 — Y-P14d) — Trace-reading expectations composer.
//
// Y.5 ships mcp/lib/trace-reading-composer.js exporting
// composeTraceReadingExpectationsForRole(roleId), which joins:
//   - Y.2 mcp/lib/friction-prompt-fragments.js (canonical 9-id ledger)
//   - Y.6 mcp/lib/role-trace-expectations.js (per-role mapping, lands in
//     Y.6 per rev-4.1 defect 4 reframing)
// and returns a structured slice the brief renderer drops into the
// assignment brief when present.
//
// Per the rev-4.1 DAG (Part IV) Y.5 lands BEFORE Y.6, so the composer
// MUST degrade gracefully when role-trace-expectations.js is absent:
//   - Returns null
//   - readAssignmentBrief drops the slice entirely (no empty key in the
//     brief JSON)
//
// Once Y.6 lands the registry, the composer surfaces fragment text for
// every (role, decision_boundary, producer_id, fragment_id) entry; the
// chain-builder role's `read_chain_attempts_before_propose` fragment is
// the canonical assertion (per rev-4.1 Y-D19 vocabulary).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  composeTraceReadingExpectationsForRole,
  ROLE_TRACE_EXPECTATIONS_PATH,
} = require("../mcp/lib/trace-reading-composer.js");
const {
  FRICTION_PROMPT_FRAGMENTS,
} = require("../mcp/lib/friction-prompt-fragments.js");

test("composeTraceReadingExpectationsForRole returns null for unknown / empty role id", () => {
  assert.equal(composeTraceReadingExpectationsForRole(""), null);
  assert.equal(composeTraceReadingExpectationsForRole(null), null);
  assert.equal(composeTraceReadingExpectationsForRole(undefined), null);
  assert.equal(composeTraceReadingExpectationsForRole(42), null);
});

test("composer returns null when role-trace-expectations.js (Y.6) is absent — forward-compat with Y.5 → Y.6 DAG edge", () => {
  // The Y.5 → Y.6 dependency means Y.5 ships BEFORE Y.6 lands the
  // registry. Until then any role id MUST resolve to null and the brief
  // renderer MUST drop the trace_reading_expectations slice entirely.
  if (fs.existsSync(ROLE_TRACE_EXPECTATIONS_PATH)) {
    // Y.6 has landed; this test is now a no-op because the composer
    // resolves real entries. The chain-builder assertion below picks up.
    return;
  }
  assert.equal(composeTraceReadingExpectationsForRole("chain-builder"), null);
  assert.equal(composeTraceReadingExpectationsForRole("surface-discovery"), null);
});

test("composer surfaces chain-builder read_chain_attempts_before_propose fragment text once Y.6 lands the registry (rev 4.1 canonical vocabulary)", () => {
  // Activated automatically once Y.6 ships mcp/lib/role-trace-expectations.js.
  // Until then the test is a no-op so Y.5 can ship per the DAG.
  if (!fs.existsSync(ROLE_TRACE_EXPECTATIONS_PATH)) {
    return;
  }
  const composed = composeTraceReadingExpectationsForRole("chain-builder");
  assert.ok(composed, "composer MUST return a slice once Y.6 has landed the chain-builder mapping");
  assert.equal(composed.role, "chain-builder");
  assert.ok(Array.isArray(composed.fragments) && composed.fragments.length > 0);

  const readChainAttempts = composed.fragments.find(
    (entry) => entry.fragment_id === "read_chain_attempts_before_propose",
  );
  assert.ok(
    readChainAttempts,
    "chain-builder MUST include the read_chain_attempts_before_propose fragment (Y-D19 chain_attempts_ledger consumer)",
  );
  assert.equal(readChainAttempts.decision_boundary, "chain_attempt_proposal");
  assert.equal(readChainAttempts.producer_id, "chain_attempts_ledger");
  assert.equal(
    readChainAttempts.fragment_text,
    FRICTION_PROMPT_FRAGMENTS.read_chain_attempts_before_propose,
    "fragment_text MUST be the live FRICTION_PROMPT_FRAGMENTS body (no duplicated literal)",
  );
});

test("composed slice is Object.freeze'd end-to-end (no consumer mutation)", () => {
  if (!fs.existsSync(ROLE_TRACE_EXPECTATIONS_PATH)) {
    return;
  }
  const composed = composeTraceReadingExpectationsForRole("chain-builder");
  if (composed == null) return;
  assert.equal(Object.isFrozen(composed), true);
  assert.equal(Object.isFrozen(composed.fragments), true);
  for (const fragment of composed.fragments) {
    assert.equal(Object.isFrozen(fragment), true);
  }
});
