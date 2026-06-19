"use strict";

// Cycle Y.2 EXTEND (rev 4.1 W1) — Friction prompt fragments registry.
//
// Closed map of fragment_id -> fragment text injected into subagent briefs
// at recognized friction points. Composed by assignment-brief.js (Y.5) via
// the role-trace-expectations registry (Y.6). The fragment_id vocabulary is
// the canonical Y-D19 (rev 4.1) set — 9 entries — and is referenced by
// mcp/lib/role-trace-expectations.js (Y.6) for stigmergic producer/consumer
// pairing. Adding a fragment requires a paired entry in
// role-trace-expectations.js for at least one role.
//
// Y-P14d (rev 4) — Brief-renderer discipline. Each fragment makes the
// runtime-expected action explicit at a recognized decision boundary
// (chain_attempt_proposal, handoff_receipt, validator_invocation,
// brief_composition). The text MUST be operationally actionable — naming
// the specific bob_* tool to call and the payload field that carries the
// trace — so the receiving subagent has a mechanical path through the
// friction without reaching for Bash.

const FRICTION_PROMPT_FRAGMENTS = Object.freeze({
  internal_error_retry:
    "on INTERNAL_ERROR from any bob_record_* or bob_write_*, call bob_log_capability_friction with friction_kind: tool_inadequate, inadequacy_mode: output_format_unsuitable, and reference the failed invocation via inadequate_invocation_ref.",
  invalid_arguments_retry:
    "on INVALID_ARGUMENTS retry success, the MCP server auto-emits protocol_drift — do not also log manually.",
  bash_curl_on_target_detected:
    "if you need to curl in-scope target_domain, call bob_log_capability_friction with wanted_tool: bob_http_scan and reason BEFORE using Bash.",
  setup_setup_rejection:
    "if to_state: SETUP is rejected after SETUP context, call bob_log_protocol_drift with drift_signature: lifecycle_transition_invalid.",
  read_chain_attempts_before_propose:
    "before proposing a new chain-attempt with bob_propose_hypothesis or bob_write_chain_attempt, call bob_read_chain_attempts and cite the prior chain_id in the new attempt's prior_attempt_ref field.",
  propose_hypothesis_for_new_chain:
    "for a NEW chain proposal (no prior_attempt_ref), call bob_propose_hypothesis with hypothesis_kind: chain_extension and let the graph apparatus record the proposal; do NOT write chain-attempts.jsonl by hand.",
  emit_structured_ranked_leads:
    "emit ranked_leads as structured surface-leads via bob_record_surface_leads with full rationale per lead; do NOT only summarize them in handoff free-text.",
  cite_verification_round_for_bob_verified:
    "every section marked sections[].provenance: bob_verified MUST cite at least one verification_round result_id whose reportable === true in sections[].evidence_refs[].",
  log_friction_on_internal_error:
    "on any unexpected MCP INTERNAL_ERROR, call bob_log_capability_friction with friction_kind: tool_inadequate, inadequacy_mode: output_format_unsuitable, inadequate_invocation_ref pointing at the failed event_id.",
});

const FRAGMENT_IDS = Object.freeze(Object.keys(FRICTION_PROMPT_FRAGMENTS));

function isKnownFragmentId(fragmentId) {
  return Object.prototype.hasOwnProperty.call(
    FRICTION_PROMPT_FRAGMENTS,
    fragmentId,
  );
}

function getFragmentText(fragmentId) {
  if (!isKnownFragmentId(fragmentId)) {
    return null;
  }
  return FRICTION_PROMPT_FRAGMENTS[fragmentId];
}

module.exports = {
  FRICTION_PROMPT_FRAGMENTS,
  FRAGMENT_IDS,
  isKnownFragmentId,
  getFragmentText,
};
