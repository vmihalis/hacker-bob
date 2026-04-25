"use strict";

const { logCoverage } = require("../coverage.js");

module.exports = Object.freeze({
  name: "bounty_log_coverage",
  description:
    "Append concise endpoint/bug-class/auth-profile coverage records for the assigned surface. Call after meaningful tests and before long pivots so coverage survives maxTurns. Validated against wave assignments.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "wave": {
        "type": "string",
        "pattern": "^w[0-9]+$"
      },
      "agent": {
        "type": "string",
        "pattern": "^a[0-9]+$"
      },
      "surface_id": {
        "type": "string"
      },
      "entries": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "endpoint": {
              "type": "string"
            },
            "method": {
              "type": "string"
            },
            "bug_class": {
              "type": "string"
            },
            "auth_profile": {
              "type": "string"
            },
            "status": {
              "type": "string",
              "enum": [
                "tested",
                "blocked",
                "promising",
                "needs_auth",
                "requeue"
              ]
            },
            "evidence_summary": {
              "type": "string"
            },
            "next_step": {
              "type": "string"
            }
          },
          "required": [
            "endpoint",
            "bug_class",
            "status",
            "evidence_summary"
          ]
        }
      }
    },
    "required": [
      "target_domain",
      "wave",
      "agent",
      "surface_id",
      "entries"
    ]
  },
  handler: logCoverage,
  role_bundles: ["hunter"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["coverage.jsonl"],
  hook_required: false,
});
