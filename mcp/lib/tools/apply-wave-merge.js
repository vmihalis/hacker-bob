"use strict";

const { applyWaveMerge } = require("../waves.js");

module.exports = Object.freeze({
  name: "bob_apply_wave_merge",
  aliases: ["bounty_apply_wave_merge"],
  description:
    "Apply one wave merge to session state from authoritative structured handoff JSON, including exclusions, leads, and findings summary.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "wave_number": {
        "type": "number"
      },
      "force_merge": {
        "type": "boolean"
      },
      "force_merge_reason": {
        "type": "string",
        "description": "Required when force_merge is true. Explain missing/invalid handoffs and why settlement is safe."
      }
    },
    "required": [
      "target_domain",
      "wave_number",
      "force_merge"
    ]
  },
  handler: applyWaveMerge,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["state.json"],
});
