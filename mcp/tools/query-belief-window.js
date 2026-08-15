"use strict";

const {
  buildBeliefWindow,
} = require("../core/belief/belief-window.js");

module.exports = Object.freeze({
  name: "bob_query_belief_window",
  capability_id: "CB-B1_belief_window",
  description:
    "Build a bounded advisory belief window over mechanism variables from surface-graph mechanism edges and frontier observation typed facts. Read-only and offline; does not write claims or session artifacts.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      template_id: { type: "string" },
      variable_limit: { type: "integer", minimum: 1, maximum: 64 },
      factor_limit: { type: "integer", minimum: 1, maximum: 128 },
      fact_limit: { type: "integer", minimum: 1, maximum: 200 },
      size_limit_bytes: { type: "integer", minimum: 1024, maximum: 65536 },
    },
    required: ["target_domain"],
  },
  handler: buildBeliefWindow,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
