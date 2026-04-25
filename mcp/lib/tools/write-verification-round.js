"use strict";

const { writeVerificationRound } = require("../findings.js");

module.exports = Object.freeze({
  name: "bounty_write_verification_round",
  description:
    "Write one verifier round to authoritative JSON plus a markdown mirror.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "round": {
        "type": "string",
        "enum": [
          "brutalist",
          "balanced",
          "final"
        ]
      },
      "notes": {
        "type": [
          "string",
          "null"
        ]
      },
      "results": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "finding_id": {
              "type": "string"
            },
            "disposition": {
              "type": "string",
              "enum": [
                "confirmed",
                "denied",
                "downgraded"
              ]
            },
            "severity": {
              "enum": [
                "critical",
                "high",
                "medium",
                "low",
                "info",
                null
              ]
            },
            "reportable": {
              "type": "boolean"
            },
            "reasoning": {
              "type": "string"
            }
          },
          "required": [
            "finding_id",
            "disposition",
            "severity",
            "reportable",
            "reasoning"
          ]
        }
      }
    },
    "required": [
      "target_domain",
      "round",
      "notes",
      "results"
    ]
  },
  handler: writeVerificationRound,
  role_bundles: ["verifier"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["brutalist.json","balanced.json","verified-final.json"],
  hook_required: false,
});
