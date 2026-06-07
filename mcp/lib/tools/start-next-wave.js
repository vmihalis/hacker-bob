"use strict";

const { startNextWave } = require("../waves.js");

module.exports = Object.freeze({
  name: "bob_start_next_wave",
  aliases: ["bounty_start_next_wave"],
  description:
    "Plan and start the next standard EVALUATE/EXPLORE wave using MCP-owned wave policy and deep lead promotion.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string", minLength: 1 },
      dry_run: { type: "boolean" },
    },
    required: ["target_domain"],
    additionalProperties: false,
  },
  handler: startNextWave,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [
    "surface-routes.json",
    "wave-N-assignments.json",
    "state.json",
    "surface-leads.json",
    "frontier-events.jsonl",
    "surface-index.json",
    "task-queue.json",
    "task-graph.json",
  ],
});
