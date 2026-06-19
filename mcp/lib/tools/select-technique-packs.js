"use strict";

const { selectTechniquePacks } = require("../technique-packs.js");

module.exports = Object.freeze({
  name: "bob_select_technique_packs",
  aliases: ["bounty_select_technique_packs"],
  description:
    "Select bounded candidate technique packs for one routed attack surface using deterministic metadata and prior attempt logs.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      surface_id: { type: "string" },
      capability_pack: { type: "string" },
      max_packs: { type: "number", minimum: 1, maximum: 50 },
      include_attempted: { type: "boolean" },
    },
    required: ["target_domain", "surface_id"],
  },
  handler: selectTechniquePacks,
  role_bundles: ["evaluator-web", "orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
