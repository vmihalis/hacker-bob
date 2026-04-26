"use strict";

const {
  readPipelineAnalytics,
} = require("../pipeline-analytics.js");

module.exports = Object.freeze({
  name: "bounty_read_pipeline_analytics",
  description:
    "Read local metadata-only pipeline analytics for one session or recent sessions. Summarizes phase progress, wave health, findings, verification, grade/report status, bottlenecks, and safe telemetry-derived tool and hunter health.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
        description: "When present, return detailed analytics for this target session.",
      },
      window_days: {
        type: "number",
        minimum: 1,
        maximum: 365,
        description: "Cross-session lookback window. Defaults to 30 days, capped at 365.",
      },
      limit: {
        type: "number",
        minimum: 1,
        maximum: 100,
        description: "Maximum recent events, bottlenecks, and examples to include. Defaults to 20.",
      },
      include_events: {
        type: "boolean",
        description: "When true, include a capped metadata-only pipeline event timeline.",
      },
    },
  },
  handler: readPipelineAnalytics,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  hook_required: false,
  readPipelineAnalytics,
});
