"use strict";

const { readVerificationRound } = require("../findings.js");

module.exports = Object.freeze({
  name: "bounty_read_verification_round",
  description:
    "Read one verification round JSON document.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "round": {
        "type": "string",
        "enum": [
          "brutalist",
          "balanced",
          "final"
        ]
      }
    },
    "required": [
      "target_domain",
      "round"
    ]
  },
  handler: readVerificationRound,
  role_bundles: ["verifier","grader","reporter","orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  hook_required: false,
});
