"use strict";

const {
  trainBeliefModel,
} = require("../belief/model.js");

module.exports = Object.freeze({
  name: "bob_train_belief_model",
  capability_id: "CB-B5_calibrated_factor_model",
  description:
    "Train an offline calibrated belief factor model from explicit local session domains using sanitized claim, verification, and grade outcomes. Writes inspectable model metadata under belief-scratch; never default-enables learned weights.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      training_domains: {
        type: "array",
        items: { type: "string" },
        minItems: 1,
      },
      holdout_domains: {
        type: "array",
        items: { type: "string" },
      },
      model_id: { type: "string" },
    },
    required: ["target_domain", "training_domains"],
  },
  handler: trainBeliefModel,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["belief-scratch/belief-model-info.json"],
});
