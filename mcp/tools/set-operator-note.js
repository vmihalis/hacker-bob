"use strict";

const { defineSetTool } = require("./_archetypes.js");

const { setOperatorNote } = require("../core/session/session-state.js");

module.exports = defineSetTool({
  name: "bob_set_operator_note",
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
  session_artifacts_written: ["state.json", "session-nucleus.json", "session-events.jsonl"],
});
