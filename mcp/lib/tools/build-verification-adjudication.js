"use strict";

const { buildVerificationAdjudication } = require("../verification.js");

module.exports = Object.freeze({
  name: "bob_build_verification_adjudication",
  aliases: ["bounty_build_verification_adjudication"],
  description:
    "Build the deterministic v2 verification adjudication plan from current brutalist and balanced rounds.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler: buildVerificationAdjudication,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["verification-adjudication.json", "verification-manifest.json"],
});
