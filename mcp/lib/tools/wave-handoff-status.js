"use strict";

const { waveHandoffStatus } = require("../waves.js");

module.exports = Object.freeze({
  name: "bounty_wave_handoff_status",
  description:
    "Read-only readiness check for one wave. Compares expected assignments to present handoff JSON files without validating payload contents.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "wave_number": {
        "type": "number"
      }
    },
    "required": [
      "target_domain",
      "wave_number"
    ]
  },
  handler: waveHandoffStatus,
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
