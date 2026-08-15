"use strict";

const { runBeliefSampler } = require("../core/belief/factor-graph.js");

module.exports = Object.freeze({
  name: "bob_run_belief_sampler",
  capability_id: "CB-B4_factor_graph_sampler",
  description:
    "Run the deterministic advisory factor-graph sampler over the current belief window and persist aggregate belief samples under belief-scratch. Does not record claims, schedule work, or perform network actions.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      seed: { type: "string" },
      sample_count: { type: "integer", minimum: 1, maximum: 4096 },
      rank_limit: { type: "integer", minimum: 1, maximum: 100 },
      chain_depth: { type: "integer", minimum: 1, maximum: 4 },
    },
    required: ["target_domain"],
  },
  handler: runBeliefSampler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["belief-scratch/belief-samples.jsonl"],
});
