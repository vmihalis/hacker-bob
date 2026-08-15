"use strict";

const { defineReadTool } = require("./_archetypes.js");

const { readVerificationContext } = require("../core/verification/verification.js");

module.exports = defineReadTool({
  name: "bob_read_verification_context",
  description:
    "Read schema-aware verification attempt context, round/adjudication/evidence freshness, replay policy, and next action.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler: readVerificationContext,
  role_bundles: ["orchestrator", "verifier", "evidence", "grader", "reporter"],
});
