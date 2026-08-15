"use strict";

const { readAssignmentBrief } = require("../core/session/assignment-brief.js");

module.exports = Object.freeze({
  name: "bob_read_assignment_brief",
  description:
    "Return everything a evaluator needs to start testing: assigned surface, exclusions, valid surface IDs, coverage summary, ranking summary, run context budget, plus profile-specific context. Web evaluators get bypass tables, bounded technique_packs.selected with registry warnings, small legacy technique/payload hint summaries, traffic/audit/circuit-breaker summaries, public intel, and static scan hints. Smart-contract evaluators get bob_spec_status (filtered to their surface) and the chain rpc_pool. Evaluators call this once on startup instead of receiving everything via spawn prompt.",
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
      "egress_profile": {
        "type": "string"
      },
      "block_internal_hosts": {
        "type": "boolean",
        "description": "Optional one-way strict override for the brief context. When omitted, Bob reports the session's persisted effective internal-host policy."
      },
      "remaining_depth": {
        "type": "integer",
        "minimum": 0,
        "maximum": 5,
        "description": "For a NESTED child sub-evaluator ONLY: pass the remaining_depth you were injected with (from your parent's child_fanout_plan.children[].remaining_depth) so your brief's child_fanout_plan decrements and leafs out. Omit it at the wave root."
      }
    },
    "required": [
      "target_domain",
      "wave",
      "agent"
    ]
  },
  handler: readAssignmentBrief,
  role_bundles: ["evaluator-shared", "evaluator-physical"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  // The brief read records a best-effort idempotent `running` marker into the
  // MCP-owned agent-runs.jsonl ledger (the universal first surface-scoped tool
  // call — see assignment-brief.js readAssignmentBrief). That write is declared
  // here so the session-authority kernel's canShadowMissingSession guard
  // (which lets an initialized_session_read tool shadow a MISSING session only
  // when it declares no session artifacts) refuses to shadow this tool — a
  // missing session gets the loud no_session block, never a silent ledger write.
  // mutating stays false: the marker is non-contractual and swallowed on error,
  // so the brief must still read in degraded-unacked enforce posture.
  session_artifacts_written: ["agent-runs.jsonl"],
});
