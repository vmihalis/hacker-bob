"use strict";

const { listFindings } = require("../findings.js");

module.exports = Object.freeze({
  name: "bounty_list_findings",
  description:
    "List all recorded findings for a target.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      }
    },
    "required": [
      "target_domain"
    ]
  },
  handler: listFindings,
  role_bundles: ["hunter","orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  hook_required: false,
});
