"use strict";

const { recordFinding } = require("../findings.js");

module.exports = Object.freeze({
  name: "bounty_record_finding",
  description:
    "Record a validated security finding to structured disk artifacts. Survives context rotation.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "title": {
        "type": "string"
      },
      "severity": {
        "type": "string",
        "enum": [
          "critical",
          "high",
          "medium",
          "low",
          "info"
        ]
      },
      "cwe": {
        "type": "string"
      },
      "endpoint": {
        "type": "string"
      },
      "description": {
        "type": "string"
      },
      "proof_of_concept": {
        "type": "string"
      },
      "response_evidence": {
        "type": "string"
      },
      "impact": {
        "type": "string"
      },
      "auth_profile": {
        "type": "string"
      },
      "surface_id": {
        "type": "string"
      },
      "validated": {
        "type": "boolean"
      },
      "wave": {
        "type": "string",
        "pattern": "^w[1-9][0-9]*$"
      },
      "agent": {
        "type": "string",
        "pattern": "^a[1-9][0-9]*$"
      },
      "force_record": {
        "type": "boolean",
        "description": "Intentionally record a duplicate finding instead of returning the existing finding ID."
      }
    },
    "required": [
      "target_domain",
      "title",
      "severity",
      "endpoint",
      "description",
      "proof_of_concept",
      "validated"
    ]
  },
  handler: recordFinding,
  role_bundles: ["hunter"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["findings.jsonl","findings.md"],
  hook_required: false,
});
