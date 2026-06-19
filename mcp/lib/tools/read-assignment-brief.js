"use strict";

const { readAssignmentBrief } = require("../assignment-brief.js");

module.exports = Object.freeze({
  name: "bob_read_assignment_brief",
  aliases: ["bounty_read_assignment_brief"],
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
      }
    },
    "required": [
      "target_domain",
      "wave",
      "agent"
    ]
  },
  handler: readAssignmentBrief,
  role_bundles: ["evaluator-shared"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
