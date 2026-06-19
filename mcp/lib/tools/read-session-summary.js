"use strict";

const { readSessionSummary } = require("../session-summary.js");

module.exports = Object.freeze({
  name: "bob_read_session_summary",
  aliases: ["bounty_read_session_summary"],
  description:
    "Read a compact derived session summary for handoff and report presentation. Returns phase, auth status, wave/finding counts, final reportable/evidence/grade/report status, blockers, and next action without raw PoCs, request bodies, tokens, or report text.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
    },
    required: [
      "target_domain",
    ],
  },
  handler: readSessionSummary,
  role_bundles: ["orchestrator", "reporter"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
