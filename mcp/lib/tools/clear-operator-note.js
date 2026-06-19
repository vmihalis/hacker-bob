"use strict";

const { clearOperatorNote } = require("../session-state.js");

module.exports = Object.freeze({
  name: "bob_clear_operator_note",
  aliases: ["bounty_clear_operator_note"],
  description:
    "Clear the compact operator note from session state.",
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
  handler: clearOperatorNote,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["state.json", "session-nucleus.json", "session-events.jsonl"],
});
