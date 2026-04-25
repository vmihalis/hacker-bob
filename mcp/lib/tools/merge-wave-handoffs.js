"use strict";

const { mergeWaveHandoffs } = require("../waves.js");

module.exports = Object.freeze({
  name: "bounty_merge_wave_handoffs",
  description:
    "Merge structured wave handoffs for one wave using the persisted assignment file.",
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
  handler: mergeWaveHandoffs,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  hook_required: false,
});
