"use strict";

const { transitionPhase } = require("../session-state.js");

module.exports = Object.freeze({
  name: "bounty_transition_phase",
  description:
    "Apply one validated FSM phase transition to the persisted session state.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "to_phase": {
        "type": "string",
        "enum": [
          "RECON",
          "AUTH",
          "HUNT",
          "CHAIN",
          "VERIFY",
          "GRADE",
          "REPORT",
          "EXPLORE"
        ]
      },
      "auth_status": {
        "type": "string",
        "enum": [
          "authenticated",
          "unauthenticated"
        ]
      },
      "override_reason": {
        "type": "string",
        "description": "Auditable HUNT -> CHAIN override reason. Only allowed for HUNT -> CHAIN and must be at least 20 characters."
      }
    },
    "required": [
      "target_domain",
      "to_phase"
    ]
  },
  handler: transitionPhase,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["state.json"],
  hook_required: false,
});
