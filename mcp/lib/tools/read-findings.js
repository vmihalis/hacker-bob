"use strict";

const { readFindings } = require("../findings.js");

module.exports = Object.freeze({
  name: "bounty_read_findings",
  description:
    "Read all recorded findings for a target from authoritative structured storage.",
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
  handler: readFindings,
  role_bundles: ["chain","verifier","grader","reporter"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  hook_required: false,
});
