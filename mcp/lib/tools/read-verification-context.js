"use strict";

const { readVerificationContext } = require("../verification.js");

module.exports = Object.freeze({
  name: "bob_read_verification_context",
  aliases: ["bounty_read_verification_context"],
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
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
