"use strict";

const { defineReadTool } = require("./_archetypes.js");

const { readStateSummary } = require("../core/session/session-state.js");

module.exports = defineReadTool({
  name: "bob_read_state_summary",
  description:
    "Lightweight session state view (~500 tokens). Returns phase, wave, finding count, operator note, coverage, and array sizes without the full dead_ends/waf arrays. Use this instead of bob_read_session_state when you only need to check progress.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      }
    },
    "required": [
      "target_domain"
    ]
  },
  handler: readStateSummary,
  role_bundles: ["orchestrator"],
});
