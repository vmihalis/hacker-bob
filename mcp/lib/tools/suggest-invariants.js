"use strict";

const { suggestInvariantsForFinding } = require("../invariant-template-corpus.js");

function suggestInvariantsHandler(args) {
  return suggestInvariantsForFinding(args.finding, {
    slot_values: args.slot_values,
    limit: args.limit,
  });
}

module.exports = Object.freeze({
  name: "bob_suggest_invariants",
  aliases: ["bounty_suggest_invariants"],
  description:
    "Suggest Foundry invariant test templates for a given finding's vulnerability_class. Pass a parsed audit finding (from bob_query_audit_reports). Optionally pass slot_values to fill template parameter slots (target_contract, vulnerable_function, etc.). Returns one suggestion per template in the corpus for that class with the parameter slots either filled or listed under unfilled_slots.",
  inputSchema: {
    type: "object",
    properties: {
      finding: {
        type: "object",
        description: "A parsed audit finding with at least vulnerability_class.",
      },
      slot_values: {
        type: "object",
        description: "Optional map of parameter_slot name -> value. Common slots: target_contract, vulnerable_function, admin_function, swap_pool, callee_contract, oracle_contract, victim_function, withdraw_amount.",
      },
      limit: { type: "integer", minimum: 1, maximum: 25 },
    },
    required: ["finding"],
  },
  handler: suggestInvariantsHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
