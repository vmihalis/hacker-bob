"use strict";

const { defineReadTool } = require("./_archetypes.js");

const { readWaveHandoffs } = require("../core/waves/wave-handoff-store.js");

module.exports = defineReadTool({
  name: "bob_read_wave_handoffs",
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
});
