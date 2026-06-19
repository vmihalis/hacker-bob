"use strict";

// Cycle Y.6 (rev 4.1) — Role trace expectations registry (Y-P14d).
//
// Closed map of role-id -> ordered list of trace-reading expectations a
// subagent is expected to honor at recognized decision boundaries. Each
// entry references:
//   * fragment_id (must exist in mcp/lib/friction-prompt-fragments.js)
//   * decision_boundary (closed enum per Y-P14a)
//   * producer_id (must exist in mcp/lib/stigmergic-producers.js)
//
// The Y.5 assignment-brief renderer (W1) composes the brief's per-role
// "trace-reading expectations" section by reading this registry and
// injecting the matching fragment text from FRICTION_PROMPT_FRAGMENTS.
// fragment_id is preserved on the brief for telemetry attribution.
//
// Rev 4.1 (defect 5) — canonical fragment_id and producer_id strings are
// committed in mcp/lib/friction-prompt-fragments.js (Y.2) and
// mcp/lib/stigmergic-producers.js (Y.6). The Y.6 shape test asserts every
// entry here resolves to a real fragment + real producer (no escape
// hatch, no orphan).
//
// Adding a new role expectation requires:
//   1. The fragment_id must already exist in FRICTION_PROMPT_FRAGMENTS,
//      OR be added in a paired Y.2-EXTEND commit.
//   2. The producer_id must already exist in STIGMERGIC_PRODUCERS, OR be
//      added in a paired Y.6-EXTEND commit.
//   3. A matching consumer entry should land in STIGMERGIC_CONSUMERS
//      (Y.9) so check:stigmergy-coherence resolves the pair.

const DECISION_BOUNDARY_VALUES = Object.freeze([
  "brief_composition",
  "handoff_receipt",
  "chain_attempt_proposal",
  "claim_recording",
  "validator_invocation",
]);

const ROLE_TRACE_EXPECTATIONS = Object.freeze({
  "chain-builder": Object.freeze([
    Object.freeze({
      fragment_id: "read_chain_attempts_before_propose",
      decision_boundary: "chain_attempt_proposal",
      producer_id: "chain_attempts_ledger",
    }),
    Object.freeze({
      fragment_id: "propose_hypothesis_for_new_chain",
      decision_boundary: "chain_attempt_proposal",
      producer_id: "chain_attempts_ledger",
    }),
  ]),
  "surface-discovery": Object.freeze([
    Object.freeze({
      fragment_id: "emit_structured_ranked_leads",
      decision_boundary: "handoff_receipt",
      producer_id: "surface_discovery_ranked_leads",
    }),
  ]),
  "report-writer": Object.freeze([
    Object.freeze({
      fragment_id: "cite_verification_round_for_bob_verified",
      decision_boundary: "validator_invocation",
      producer_id: "verification_round_ledger",
    }),
  ]),
  "evaluator-spawn": Object.freeze([
    Object.freeze({
      fragment_id: "log_friction_on_internal_error",
      decision_boundary: "validator_invocation",
      producer_id: "capability_friction_ledger",
    }),
  ]),
});

const ROLE_IDS = Object.freeze(Object.keys(ROLE_TRACE_EXPECTATIONS));

function getExpectationsForRole(roleId) {
  if (
    !Object.prototype.hasOwnProperty.call(ROLE_TRACE_EXPECTATIONS, roleId)
  ) {
    return null;
  }
  return ROLE_TRACE_EXPECTATIONS[roleId];
}

function getExpectationsForRoleByBoundary(roleId, decisionBoundary) {
  const all = getExpectationsForRole(roleId);
  if (!all) return null;
  return all.filter((e) => e.decision_boundary === decisionBoundary);
}

module.exports = {
  DECISION_BOUNDARY_VALUES,
  ROLE_TRACE_EXPECTATIONS,
  ROLE_IDS,
  getExpectationsForRole,
  getExpectationsForRoleByBoundary,
};
