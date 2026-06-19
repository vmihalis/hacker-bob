"use strict";

const { setOperatorNote } = require("../session-state.js");

module.exports = Object.freeze({
  name: "bob_set_operator_note",
  aliases: ["bounty_set_operator_note"],
  description:
    "Set a compact non-secret operator note on session state. Use only for bounded human instructions needed across resume turns; rejects secret-looking values.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
      operator_note: {
        type: "string",
        maxLength: 1000,
      },
    },
    required: [
      "target_domain",
      "operator_note",
    ],
  },
  handler: setOperatorNote,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["state.json", "session-nucleus.json", "session-events.jsonl"],
});
