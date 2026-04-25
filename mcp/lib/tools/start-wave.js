"use strict";

const { startWave } = require("../waves.js");

module.exports = Object.freeze({
  name: "bounty_start_wave",
  description: "Persist a new wave assignment file and set pending_wave in session state.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      wave_number: { type: "number" },
      assignments: {
        type: "array",
        items: {
          type: "object",
          properties: {
            agent: { type: "string", pattern: "^a[1-9][0-9]*$" },
            surface_id: { type: "string" },
          },
          required: ["agent", "surface_id"],
        },
      },
    },
    required: ["target_domain", "wave_number", "assignments"],
  },
  handler: startWave,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["wave-N-assignments.json", "state.json"],
  hook_required: false,
});
