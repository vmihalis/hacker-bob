"use strict";

const { advanceSession } = require("../session-state.js");
const {
  LIFECYCLE_STATE_VALUES,
} = require("../governance-contracts.js");

// Maps each legacy phase string to the lifecycle state it collapsed into.
// The old eight-phase FSM modeled per-claim frontier work as four sequential
// phases (SURFACE_DISCOVERY, AUTH, EVALUATE, CHAIN) plus an EXPLORE re-entry;
// all five collapse to OPEN_FRONTIER because the topology now treats them as
// one lifecycle state with task lenses. VERIFY/GRADE/REPORT keep their names.
// SETUP is the init-session bootstrap state and was never a phase destination.
const LEGACY_PHASE_TO_LIFECYCLE_STATE = Object.freeze({
  SURFACE_DISCOVERY: "OPEN_FRONTIER",
  AUTH: "OPEN_FRONTIER",
  EVALUATE: "OPEN_FRONTIER",
  CHAIN: "OPEN_FRONTIER",
  EXPLORE: "OPEN_FRONTIER",
  VERIFY: "VERIFY",
  GRADE: "GRADE",
  REPORT: "REPORT",
});

// Arg adapter for the `bounty_transition_phase` alias. Translates the legacy
// `to_phase` enum to the canonical `to_state` enum and treats a populated
// `override_reason` as an `operator_force` override (the legacy tool used
// `override_reason` as both the opt-out flag and the audit string). The
// `auth_status` argument is dropped: auth context is governance-plane scope
// in the new topology and moves through bob_init_session / governance events.
function adaptLegacyTransitionPhaseArgs(args) {
  const safe = (args && typeof args === "object" && !Array.isArray(args)) ? args : {};
  const result = {};
  if (typeof safe.target_domain === "string") {
    result.target_domain = safe.target_domain;
  }
  if (typeof safe.to_phase === "string"
    && Object.prototype.hasOwnProperty.call(LEGACY_PHASE_TO_LIFECYCLE_STATE, safe.to_phase)) {
    result.to_state = LEGACY_PHASE_TO_LIFECYCLE_STATE[safe.to_phase];
  } else if (typeof safe.to_phase === "string") {
    // Pass the unknown legacy phase through so the lifecycle normalizer can
    // produce the canonical INVALID_ARGUMENTS error referencing the supported
    // enum, rather than silently downgrading to a default state.
    result.to_state = safe.to_phase;
  }
  if (typeof safe.override_reason === "string" && safe.override_reason.trim()) {
    result.override = "operator_force";
    result.override_reason = safe.override_reason;
  }
  return result;
}

const LEGACY_TRANSITION_PHASE_INPUT_SCHEMA = Object.freeze({
  type: "object",
  properties: {
    target_domain: { type: "string" },
    to_phase: {
      type: "string",
      enum: Object.keys(LEGACY_PHASE_TO_LIFECYCLE_STATE),
    },
    auth_status: {
      type: "string",
      enum: ["authenticated", "unauthenticated"],
      description:
        "Ignored by the bob_advance_session redirect; auth context is governance scope.",
    },
    override_reason: {
      type: "string",
      description:
        "Optional human-auditable reason; presence triggers operator_force override.",
    },
  },
  required: ["target_domain", "to_phase"],
});

module.exports = Object.freeze({
  name: "bob_advance_session",
  description:
    "Advance the persisted SessionNucleus to a new lifecycle_state. " +
    "Enforces the allowedTransitions table from lifecycle-gates.js. " +
    "Pass override: \"operator_force\" to bypass blockers; the override is " +
    "recorded as a governance.lifecycle.override event in session-events.jsonl.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
      to_state: {
        type: "string",
        enum: [...LIFECYCLE_STATE_VALUES],
      },
      override: {
        type: "string",
        enum: ["operator_force"],
        description:
          "Operator opt-out used to advance despite structured blockers. " +
          "Each override is recorded in session-events.jsonl as a " +
          "governance.lifecycle.override event with the blocker list.",
      },
      override_reason: {
        type: "string",
        description:
          "Optional human-auditable reason recorded with the override event.",
      },
    },
    required: ["target_domain", "to_state"],
  },
  handler: advanceSession,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [
    "session-nucleus.json",
    "session-events.jsonl",
  ],
  // Cycle D.1 redirects the legacy bounty_transition_phase shim into this tool.
  // The alias adopts the legacy to_phase enum and remaps each value to the
  // matching lifecycle state via the adapter above.
  aliases: [{
    name: "bounty_transition_phase",
    description:
      "Deprecated alias for bob_advance_session. Accepts the legacy to_phase " +
      "enum {SURFACE_DISCOVERY, AUTH, EVALUATE, CHAIN, VERIFY, GRADE, REPORT, " +
      "EXPLORE}, maps each value to its lifecycle state, and forwards to " +
      "bob_advance_session. The auth_status argument is ignored; override_reason " +
      "implies operator_force. Removed in v2.1.0; prefer bob_advance_session " +
      "with the six-state lifecycle enum directly.",
    inputSchema: LEGACY_TRANSITION_PHASE_INPUT_SCHEMA,
    arg_adapter: adaptLegacyTransitionPhaseArgs,
  }],
});
