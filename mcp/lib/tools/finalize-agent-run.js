"use strict";

const { finalizeAgentRun } = require("../agent-run-completion.js");

module.exports = Object.freeze({
  name: "bob_finalize_agent_run",
  aliases: ["bounty_finalize_agent_run"],
  description:
    "Evaluator-final completion check that validates the structured wave handoff and records metadata-only completion telemetry.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "wave": {
        "type": "string",
        "pattern": "^w[1-9][0-9]*$"
      },
      "agent": {
        "type": "string",
        "pattern": "^a[1-9][0-9]*$"
      },
      "surface_id": {
        "type": "string"
      }
    },
    "required": [
      "target_domain",
      "wave",
      "agent",
      "surface_id"
    ]
  },
  handler: finalizeAgentRun,
  role_bundles: ["evaluator-shared"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [
    "tool-telemetry.jsonl",
    "pipeline-events.jsonl"
  ],
});
