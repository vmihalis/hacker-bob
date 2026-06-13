"use strict";

const {
  BELIEF_SIGNAL_KIND_VALUES,
  queryBeliefSignals,
} = require("../belief/authority.js");

module.exports = Object.freeze({
  name: "bob_query_belief_signals",
  capability_id: "CB-S1_belief_authority",
  description:
    "Query advisory belief scratch signals by kind or source. This tool is read-only, offline, and cannot mutate claim, verification, grade, report, or governance artifacts.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      kind: { type: "string", enum: BELIEF_SIGNAL_KIND_VALUES },
      source: { type: "string" },
      limit: { type: "integer", minimum: 1, maximum: 1000 },
    },
    required: ["target_domain"],
  },
  handler: queryBeliefSignals,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
