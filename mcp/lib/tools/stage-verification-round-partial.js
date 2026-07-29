"use strict";

const { stageVerificationRoundPartial } = require("../verification-round-store.js");
const { wrapWriteTool } = require("./_write-base.js");

const CONFIDENCE_REASON_ENUM = [
  "fresh_replay_passed",
  "auth_expired",
  "tooling_blocked",
  "state_changed",
  "manual_inference",
  "roast_disagreement",
  "disambiguation_failed",
  "agreement_not_replayed",
  "unruled_confounder",
  "missing_control",
  "exploit_replay_confirmed",
];

module.exports = wrapWriteTool({
  name: "bob_stage_verification_round_partial",
  // The committed round artifact is the only audit-graded surface; a staged
  // partial is a validated, attempt/snapshot-bound submission for ONE finding
  // that the server unions at commit. Staging never writes a round document.
  writes_audit_graded: false,
  description:
    "Stage one finding's verification result for a round. A per-finding verifier worker submits the validated, attempt/snapshot-bound result for ONE finding_id; the server unions the staged partials into the single round document at commit (an empty bob_write_verification_round invocation triggers the union). Requires a v2 VERIFY attempt. Re-staging the same finding overwrites the prior submission.",
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
      "verification_attempt_id": {
        "type": "string"
      },
      "verification_snapshot_hash": {
        "type": "string"
      },
      "notes": {
        "type": [
          "string",
          "null"
        ]
      },
      "result": {
        "type": "object",
        "description": "The verification result for the single finding this worker executed.",
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
              "enum": CONFIDENCE_REASON_ENUM
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
              "pattern": "^(?:[a-f0-9]{32}|[a-f0-9]{64})$"
            }
          },
          "inherited_confidence_reasons": {
            "type": "array",
            "items": {
              "type": "string",
              "enum": CONFIDENCE_REASON_ENUM
            }
          },
          "resolved_confidence_reasons": {
            "type": "array",
            "items": {
              "type": "string",
              "enum": CONFIDENCE_REASON_ENUM
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
    },
    "required": [
      "target_domain",
      "round",
      "verification_attempt_id",
      "verification_snapshot_hash",
      "result"
    ]
  },
  handler: stageVerificationRoundPartial,
  role_bundles: ["verifier"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["verification-round-partials"],
});
