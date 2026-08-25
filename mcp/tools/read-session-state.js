"use strict";

const { defineReadTool } = require("./_archetypes.js");

const { readSessionState } = require("../core/session/session-state.js");

module.exports = defineReadTool({
  name: "bob_read_session_state",
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
});
