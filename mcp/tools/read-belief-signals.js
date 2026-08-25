"use strict";

const { defineReadTool } = require("./_archetypes.js");

const { readBeliefSignals } = require("../core/belief/authority.js");

module.exports = defineReadTool({
  name: "bob_read_belief_signals",
  capability_id: "CB-S1_belief_authority",
  description:
    "Read advisory belief scratch signals for a session. Belief signals are derived, recomputable scratch and are not claim, verification, grade, report, or governance authority.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      limit: { type: "integer", minimum: 1, maximum: 1000 },
    },
    required: ["target_domain"],
  },
  handler: readBeliefSignals,
  role_bundles: ["orchestrator"],
  global_preapproval: false,
});
