"use strict";

const { readStaticAnalysisIndexTool } = require("../static-analysis-index.js");

module.exports = Object.freeze({
  name: "bob_read_static_analysis_index",
  aliases: ["bounty_read_static_analysis_index"],
  description:
    "Read the bounded, scrubbed static-analysis index for a repo session. Returns unverified lead seeds only; never records findings, skips, or promotions.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      top_k: {
        type: "integer",
        minimum: 1,
        maximum: 20,
        description: "Maximum ranked rows to return. Defaults to 20.",
      },
      min_severity: {
        type: "string",
        enum: ["error", "warning", "note"],
        description: "Minimum severity to include. Defaults to note.",
      },
      rule_id: {
        type: "string",
        description: "Optional exact rule id filter.",
      },
      surface_id: {
        type: "string",
        description: "Optional exact repo surface id filter.",
      },
    },
    required: ["target_domain"],
  },
  handler: readStaticAnalysisIndexTool,
  role_bundles: ["evaluator-shared", "orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
