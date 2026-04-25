"use strict";

const { readSessionState } = require("../session-state.js");

module.exports = Object.freeze({
  name: "bounty_read_session_state",
  description:
    "Read normalized orchestrator session state from authoritative storage.",
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
  handler: readSessionState,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  hook_required: false,
});
