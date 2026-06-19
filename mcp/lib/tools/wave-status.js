"use strict";

const { waveStatus } = require("../waves.js");

module.exports = Object.freeze({
  name: "bob_wave_status",
  aliases: ["bounty_wave_status"],
  description:
    "Read-only evaluate status summary for wave decisions. Returns finding counts, coverage gate inputs, transition blockers, and per-finding metadata.",
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
});
