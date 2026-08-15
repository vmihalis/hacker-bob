"use strict";

const {
  rankInterventions,
} = require("../core/belief/intervention-calculus.js");

module.exports = Object.freeze({
  name: "bob_query_intervention_calculus",
  capability_id: "CB-B2_intervention_calculus",
  description:
    "Compute deterministic advisory do-operation and expected-information-gain rankings over the belief window. Read-only; does not write artifacts, schedule work, or record claims.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      template_id: { type: "string" },
      seed: { type: "string" },
      rank_limit: { type: "integer", minimum: 1, maximum: 100 },
    },
    required: ["target_domain"],
  },
  handler: rankInterventions,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
