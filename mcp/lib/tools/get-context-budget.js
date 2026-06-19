"use strict";

const { getContextBudget } = require("../context-budget.js");

module.exports = Object.freeze({
  name: "bob_get_context_budget",
  aliases: ["bounty_get_context_budget"],
  description: "Return the versioned context budget for a capability pack. If surface_id is supplied, target_domain is required so the routed surface can be validated.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string", description: "Required when surface_id is supplied." },
      capability_pack: { type: "string" },
      brief_profile: { type: "string" },
      surface_id: { type: "string", description: "Optional routed surface to validate; requires target_domain." },
    },
    required: ["capability_pack"],
  },
  handler: getContextBudget,
  role_bundles: ["evaluator-shared", "orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
