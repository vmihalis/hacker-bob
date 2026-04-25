"use strict";

const { readWaveHandoffs } = require("../waves.js");

module.exports = Object.freeze({
  name: "bounty_read_wave_handoffs",
  description:
    "Read validated structured wave handoff summaries from handoff-wN-aN.json files only. Markdown handoffs are ignored.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "wave_number": {
        "type": "number",
        "description": "Optional wave number. When omitted, all assignment files are scanned."
      }
    },
    "required": [
      "target_domain"
    ]
  },
  handler: readWaveHandoffs,
  role_bundles: ["chain","orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  hook_required: false,
});
