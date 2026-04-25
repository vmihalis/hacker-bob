"use strict";

const { initSession } = require("../session-state.js");

module.exports = Object.freeze({
  name: "bounty_init_session",
  description:
    "Initialize a new session state.json for a target domain.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "target_url": {
        "type": "string"
      }
    },
    "required": [
      "target_domain",
      "target_url"
    ]
  },
  handler: initSession,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["state.json"],
  hook_required: false,
});
