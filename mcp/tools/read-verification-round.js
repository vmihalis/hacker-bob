"use strict";

const { defineReadTool } = require("./_archetypes.js");

const { readVerificationRound } = require("../core/verification/verification-round-store.js");

module.exports = defineReadTool({
  name: "bob_read_verification_round",
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
  role_bundles: ["verifier","grader","reporter","orchestrator","evidence"],
});
