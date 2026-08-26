"use strict";

const {
  planBeliefExperiment,
} = require("../core/belief/experiment-loop.js");

module.exports = Object.freeze({
  name: "bob_plan_belief_experiment",
  capability_id: "CB-B3_experiment_loop",
  description:
    "Plan bounded active belief experiments and optionally append them through the existing bob_propose_hypothesis frontier-event path. Does not spawn agents or record claims.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      seed: { type: "string" },
      rank_limit: { type: "integer", minimum: 1, maximum: 100 },
      max_iterations: { type: "integer", minimum: 1, maximum: 5 },
      dry_run: { type: "boolean" },
    },
    required: ["target_domain"],
  },
  handler: planBeliefExperiment,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
});
