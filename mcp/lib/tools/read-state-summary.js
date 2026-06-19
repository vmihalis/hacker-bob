"use strict";

const { readStateSummary } = require("../session-state.js");

module.exports = Object.freeze({
  name: "bob_read_state_summary",
  aliases: ["bounty_read_state_summary"],
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
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
