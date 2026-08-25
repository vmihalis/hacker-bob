"use strict";

const {
  compileAndRouteContractBinding,
} = require("../core/belief/contract-compiler.js");

function handler(args) {
  return compileAndRouteContractBinding(args || {});
}

module.exports = Object.freeze({
  name: "bob_compile_contract_binding",
  capability_id: "CB-B8_contract_compiler",
  description:
    "Compile a grounded schema-contract x inert product-model binding into a routed ProofObligation. "
    + "The tool appends only through the existing hypothesis proposal and contract attachment path. "
    + "Unknown classes, soft/generated authority, or unbound schema/model inputs return HOLD and append nothing.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      schema_contract: {
        type: "object",
        description:
          "Concrete schema-contract record with endpoint, method, and 64-hex contract_hash.",
      },
      product_model: {
        type: "object",
        description:
          "Inert product-model signal. Must carry inert:true and closure/evidence/dispatch authority all false.",
      },
      binding: {
        type: "object",
        description:
          "Grounded binding with surface_id, operation_id or endpoint/method, schema_contract_hash, and class_id/validity_class_id.",
      },
      generated_hypothesis: {
        oneOf: [{ type: "string" }, { type: "object" }],
        description:
          "Optional generated nomination. It is treated as inert text only and is refused if it claims closure, evidence, dispatch, or verification authority.",
      },
      proposal_id: {
        type: "string",
        description: "Optional stable proposal id. Defaults to a digest of the binding.",
      },
      dry_run: {
        type: "boolean",
        description: "When true, compile and return the route without appending frontier events.",
      },
      actor: { type: "string" },
    },
    required: ["target_domain", "schema_contract", "product_model", "binding"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
});
