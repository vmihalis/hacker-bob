"use strict";

const { writeVerificationRound } = require("../verification-round-store.js");
const { wrapWriteTool } = require("./_write-base.js");

module.exports = wrapWriteTool({
  name: "bob_write_verification_round",
  aliases: ["bounty_write_verification_round"],
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
      "verification_attempt_id": {
        "type": "string"
      },
      "verification_snapshot_hash": {
        "type": "string"
      },
      "round_profile": {
        "type": "string"
      },
      "adjudication_plan_hash": {
        "type": "string"
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
              "type": "string",
              "enum": [
                "critical",
                "high",
                "medium",
                "low",
                "info"
              ]
            },
            "reportable": {
              "type": "boolean"
            },
            "reasoning": {
              "type": "string"
            },
            "repro_steps": {
              "type": "array",
              "maxItems": 64,
              "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": 2048
              }
            },
            "evidence_refs": {
              "type": "array",
              "maxItems": 64,
              "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1024
              }
            },
            "confidence": {
              "type": "string",
              "enum": [
                "high",
                "medium",
                "low"
              ]
            },
            "confidence_reasons": {
              "type": "array",
              "items": {
                "type": "string",
                "enum": [
                  "fresh_replay_passed",
                  "auth_expired",
                  "tooling_blocked",
                  "state_changed",
                  "manual_inference",
                  "roast_disagreement",
                  "disambiguation_failed",
                  "agreement_not_replayed",
                  "unruled_confounder",
                  "missing_control"
                ]
              }
            },
            "state_sensitive": {
              "type": "boolean"
            },
            "artifact_hashes": {
              "type": "object",
              "maxProperties": 20,
              "additionalProperties": {
                "type": "string",
                "description": "Y.0 hotfix 2 (O3): lower-case md5 (32 hex) OR sha256 (64 hex). md5 acceptance is additive for back-compat with third-party tooling whose only emitted hash is md5; sha256 remains the canonical default.",
                "pattern": "^(?:[a-f0-9]{32}|[a-f0-9]{64})$"
              }
            },
            "inherited_confidence_reasons": {
              "type": "array",
              "items": {
                "type": "string",
                "enum": [
                  "fresh_replay_passed",
                  "auth_expired",
                  "tooling_blocked",
                  "state_changed",
                  "manual_inference",
                  "roast_disagreement",
                  "disambiguation_failed",
                  "agreement_not_replayed",
                  "unruled_confounder",
                  "missing_control"
                ]
              }
            },
            "resolved_confidence_reasons": {
              "type": "array",
              "items": {
                "type": "string",
                "enum": [
                  "fresh_replay_passed",
                  "auth_expired",
                  "tooling_blocked",
                  "state_changed",
                  "manual_inference",
                  "roast_disagreement",
                  "disambiguation_failed",
                  "agreement_not_replayed",
                  "unruled_confounder",
                  "missing_control"
                ]
              }
            }
          },
          "required": [
            "finding_id",
            "disposition",
            "severity",
            "reportable",
            "reasoning",
            "repro_steps",
            "evidence_refs"
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
  session_artifacts_written: ["brutalist.json","balanced.json","verified-final.json","verification-manifest.json"],
});
