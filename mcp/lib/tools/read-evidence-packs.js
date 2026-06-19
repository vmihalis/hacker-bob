"use strict";

const { readEvidencePacks } = require("../evidence.js");

module.exports = Object.freeze({
  name: "bob_read_evidence_packs",
  aliases: ["bounty_read_evidence_packs"],
  description:
    "Read and validate the evidence packs document for final reportable findings.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler: readEvidencePacks,
  role_bundles: ["evidence", "grader", "reporter", "orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
