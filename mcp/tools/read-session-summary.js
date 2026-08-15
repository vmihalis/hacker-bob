"use strict";

const { defineReadTool } = require("./_archetypes.js");

const { readSessionSummary } = require("../core/session/session-summary.js");

module.exports = defineReadTool({
  name: "bob_read_session_summary",
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
});
