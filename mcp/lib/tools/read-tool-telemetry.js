"use strict";

const {
  readToolTelemetry,
} = require("../tool-telemetry.js");

module.exports = Object.freeze({
  name: "bounty_read_tool_telemetry",
  description:
    "Read diagnostic MCP tool-call telemetry summaries. Returns counts, success rates, latency percentiles, error histograms, last calls, and recent failures without raw tool arguments or payloads.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      tool: { type: "string" },
      limit: {
        type: "number",
        minimum: 1,
        maximum: 100,
        description: "Maximum recent failures to include per summary. Defaults to 10.",
      },
      include_agent_runs: {
        type: "boolean",
        description: "When true, include hunter SubagentStop run telemetry summaries.",
      },
      agent_run_type: { type: "string" },
      wave: { type: "string" },
      agent: { type: "string" },
      surface_id: { type: "string" },
    },
  },
  handler: readToolTelemetry,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  hook_required: false,
  readToolTelemetry,
});
