"use strict";

const { advanceSession } = require("../session-state.js");
const {
  LIFECYCLE_STATE_VALUES,
} = require("../governance-contracts.js");
const {
  AUTH_STATUS_VALUES,
} = require("../constants.js");

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
      auth_status: {
        type: "string",
        enum: [...AUTH_STATUS_VALUES],
        description:
          "Optional governance auth-context update applied during this advance. When " +
          "omitted, auth_status is derived: 'authenticated' if a usable auth profile is " +
          "stored, else the prior value carries forward. An explicit value wins (e.g. " +
          "--no-auth advances with 'unauthenticated'). Any CHANGE to auth_status is recorded " +
          "in session-events.jsonl as a governance.auth_context.replaced event.",
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
});
