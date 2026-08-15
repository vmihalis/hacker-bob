"use strict";

const {
  readBeliefModelInfo,
} = require("../core/belief/model.js");

module.exports = Object.freeze({
  name: "bob_read_belief_model_info",
  capability_id: "CB-B5_calibrated_factor_model",
  description:
    "Read the inspectable offline belief model metadata for a session. Returns calibration metrics and feature weights only; no raw reports, evidence bodies, or secrets.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler: readBeliefModelInfo,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
