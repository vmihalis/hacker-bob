"use strict";

const {
  runBeliefResidual,
} = require("../belief/residual.js");

module.exports = Object.freeze({
  name: "bob_run_belief_residual",
  capability_id: "CB-B6_residual_anomaly",
  description:
    "Compute a deterministic residual_anomaly diagnostic from belief sampler marginals and persist it as advisory belief scratch. Non-gating; cannot record claims, schedule work, or promote templates.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      seed: { type: "string" },
      sample_count: { type: "integer", minimum: 1, maximum: 4096 },
      rank_limit: { type: "integer", minimum: 1, maximum: 100 },
      chain_depth: { type: "integer", minimum: 1, maximum: 4 },
      decomposition_limit: { type: "integer", minimum: 1, maximum: 100 },
    },
    required: ["target_domain"],
  },
  handler: runBeliefResidual,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["belief-scratch/belief-signals.jsonl"],
});
