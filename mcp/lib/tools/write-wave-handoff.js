"use strict";

const { writeWaveHandoff } = require("../waves.js");
const {
  BLOCKED_PREREQ_IDENTIFIER_HINT_LONG_HEX_PATTERN,
  BLOCKED_PREREQ_IDENTIFIER_HINT_PATTERN,
  BYPASS_ATTEMPT_CONDITION_MIN_CHARS,
  BYPASS_ATTEMPT_SUMMARY_MIN_CHARS,
  WAVE_HANDOFF_CONTENT_MAX_CHARS,
} = require("../wave-handoff-contracts.js");
const { wrapWriteTool } = require("./_write-base.js");

module.exports = wrapWriteTool({
  name: "bob_write_wave_handoff",
  writes_audit_graded: true,
  description:
    "Evaluator-final writer for one structured wave handoff as markdown plus authoritative JSON.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "wave": {
        "type": "string",
        "pattern": "^w[1-9][0-9]*$"
      },
      "agent": {
        "type": "string",
        "pattern": "^a[1-9][0-9]*$"
      },
      "surface_id": {
        "type": "string"
      },
      "surface_status": {
        "type": "string",
        "enum": [
          "complete",
          "partial"
        ]
      },
      "handoff_token": {
        "type": "string",
        "minLength": 32
      },
      "summary": {
        "type": "string",
        "minLength": 1,
        "maxLength": 2000
      },
      "chain_notes": {
        "type": "array",
        "maxItems": 20,
        "items": {
          "type": "string",
          "minLength": 1,
          "maxLength": 300,
          "x-autoTruncate": true
        }
      },
      "discovered_pivots": {
        "type": "array",
        "maxItems": 20,
        "items": {
          "type": "object",
          "required": ["from_surface", "to_surface", "kind", "trust_assumption"],
          "properties": {
            "from_surface": { "type": "string", "minLength": 1, "maxLength": 200 },
            "to_surface": { "type": "string", "minLength": 1, "maxLength": 200 },
            "kind": { "type": "string", "minLength": 1, "maxLength": 100 },
            "trust_assumption": { "type": "string", "minLength": 1, "maxLength": 500 },
            "evidence_refs": {
              "type": "array",
              "maxItems": 10,
              "items": { "type": "string", "maxLength": 300 }
            }
          }
        }
      },
      "spawned_children": {
        "type": "array",
        "maxItems": 64,
        "items": {
          "type": "object",
          "required": ["subagent_type", "cell_key"],
          "properties": {
            "subagent_type": { "type": "string", "minLength": 1, "maxLength": 100 },
            "cell_key": { "type": "string", "minLength": 1, "maxLength": 300 }
          }
        }
      },
      "blocked_harness_runs": {
        "type": "array",
        "maxItems": 20,
        "items": {
          "type": "object",
          "required": ["kind", "harness", "reason"],
          "properties": {
            "kind": {
              "type": "string",
              "enum": [
                "foundry_fork",
                "anchor_fork",
                "aptos_fork",
                "sui_fork",
                "substrate_fork",
                "cosmwasm_fork",
                "rpc_endpoint",
                "fuzzer",
                "symbolic_solver",
                "mock_dependency",
                "external_api",
                "docker_unavailable",
                "sanitizer_unavailable",
                "static_analyzer_unavailable",
                "cve_feed_stale",
                "other"
              ]
            },
            "harness": { "type": "string", "minLength": 1, "maxLength": 120 },
            "reason": { "type": "string", "minLength": 1, "maxLength": 240 },
            "needed_for": { "type": "string", "minLength": 1, "maxLength": 200 }
          },
          "additionalProperties": false
        }
      },
      "blocked_prereqs": {
        "type": "array",
        "maxItems": 20,
        "description": "Prerequisites the evaluator could not satisfy from registered material (auth profile, egress profile, funded wallet, etc.). Pair with surface_status: partial. Free-text fields (reason, evidence_summary) are screened for secrets at write time; identifier_hint must be a lowercase handle when present.",
        "items": {
          "type": "object",
          "required": ["kind", "reason"],
          "properties": {
            "kind": {
              "type": "string",
              "enum": [
                "auth_missing",
                "egress_unreachable",
                "funded_wallet_missing",
                "key_material_missing",
                "external_credential_missing"
              ]
            },
            "identifier_hint": {
              "type": "string",
              "minLength": 1,
              "maxLength": 64,
              "pattern": BLOCKED_PREREQ_IDENTIFIER_HINT_PATTERN.source,
              "not": { "pattern": BLOCKED_PREREQ_IDENTIFIER_HINT_LONG_HEX_PATTERN.source },
              "description": "Optional. Registry handle (e.g., auth profile name 'attacker', egress profile name 'us-west-egress') that would resolve this prereq when added. Omit when no specific registry handle is identified. Restricted to lowercase alphanumerics + ._- and screened for long-hex / secret-shaped values."
            },
            "reason": { "type": "string", "minLength": 1, "maxLength": 240 },
            "evidence_summary": { "type": "string", "minLength": 1, "maxLength": 300 },
            "needed_for": { "type": "string", "minLength": 1, "maxLength": 200 }
          },
          "additionalProperties": false
        }
      },
      "bypass_attempts": {
        "type": "array",
        "maxItems": 30,
        "items": {
          "type": "object",
          "required": ["condition", "attempt_summary", "outcome"],
          "properties": {
            "condition": { "type": "string", "minLength": BYPASS_ATTEMPT_CONDITION_MIN_CHARS, "maxLength": 120, "x-autoTruncate": true },
            "attempt_summary": { "type": "string", "minLength": BYPASS_ATTEMPT_SUMMARY_MIN_CHARS, "maxLength": 500, "x-autoTruncate": true },
            "outcome": {
              "type": "string",
              "enum": ["no_finding", "partial_evidence", "finding_recorded", "blocked"]
            },
            "finding_id": { "type": "string", "pattern": "^F-[1-9][0-9]*$" }
          },
          "additionalProperties": false
        }
      },
      "content": {
        "type": "string",
        "maxLength": WAVE_HANDOFF_CONTENT_MAX_CHARS
      },
      "dead_ends": {
        "type": "array",
        "items": {
          "type": "string"
        }
      },
      "waf_blocked_endpoints": {
        "type": "array",
        "items": {
          "type": "string"
        }
      },
      "lead_surface_ids": {
        "type": "array",
        "items": {
          "type": "string"
        }
      },
      "surface_leads": {
        "type": "array",
        "maxItems": 15,
        "items": {
          "type": "object",
          "properties": {
            "title": { "type": "string" },
            "hosts": { "type": "array", "items": { "type": "string" } },
            "endpoints": { "type": "array", "items": { "type": "string" } },
            "interesting_params": { "type": "array", "items": { "type": "string" } },
            "tech_stack": { "type": "array", "items": { "type": "string" } },
            "nuclei_hits": { "type": "array", "items": { "type": "string" } },
            "priority": { "type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
            "surface_type": { "type": "string" },
            "bug_class_hints": { "type": "array", "items": { "type": "string" } },
            "high_value_flows": { "type": "array", "items": { "type": "string" } },
            "evidence": { "type": "array", "items": { "type": "string" } },
            "confidence": { "type": "string", "enum": ["high", "medium", "low"] },
            "score": { "type": "number", "minimum": 0, "maximum": 100 },
            "promote": { "type": "boolean" }
          }
        }
      }
    },
    "required": [
      "target_domain",
      "wave",
      "agent",
      "surface_id",
      "surface_status",
      "summary",
      "content",
      "handoff_token"
    ]
  },
  handler: writeWaveHandoff,
  role_bundles: ["evaluator-shared"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["handoff-wN-aN.json","handoff-wN-aN.md"],
});
