"use strict";

function readCapabilityMetricsHandler(args) {
  const { readCapabilityMetrics } = require("../capability-metrics.js");
  return readCapabilityMetrics({
    target_domain: args && args.target_domain,
  });
}

module.exports = Object.freeze({
  name: "bob_read_capability_metrics",
  aliases: ["bounty_read_capability_metrics"],
  description:
    "Aggregate tool telemetry by capability (C2 doc-vs-behavior, C4 multi-account, I6 findings index, I1 surface graph, I7 chain state tree, X2 verification attempt diff). Returns per-capability call counts, success rate, average latency, last-called timestamp, plus per-tool breakdown. Pass target_domain to scope to one session; omit for cross-target.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string", description: "Optional. When omitted, aggregates across every session under the telemetry directory." },
    },
  },
  handler: readCapabilityMetricsHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
