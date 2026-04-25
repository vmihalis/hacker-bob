"use strict";

const { waveStatus } = require("../waves.js");

module.exports = Object.freeze({
  name: "bounty_wave_status",
  description:
    "Read-only hunt status summary for wave decisions. Returns finding counts, severity breakdown, and per-finding metadata.",
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
  handler: waveStatus,
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
