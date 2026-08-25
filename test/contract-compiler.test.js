"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  OBJECT_AUTH_MANDATORY_CONTROLS,
  compileAndRouteContractBinding,
  compileContractBinding,
} = require("../mcp/core/belief/contract-compiler.js");
const {
  materializeTaskGraph,
} = require("../mcp/core/waves/task-graph-materializer.js");
const {
  TOOL_HANDLERS,
} = require("../mcp/tools/tool-registry.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-contract-compiler-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

const schemaContract = Object.freeze({
  contract_hash: hashCanonicalJson({
    endpoint: "/api/accounts/{accountId}",
    method: "GET",
    params: ["accountId"],
  }),
  endpoint: "/api/accounts/{accountId}",
  method: "GET",
  claimed_auth: { schemes: ["bearer"] },
  claimed_params: [{ name: "accountId", in: "path" }],
});

const productModel = Object.freeze({
  schema_version: "product-model.v1",
  model_hash: hashCanonicalJson({
    operations: ["op-account-read"],
    product: "accounts",
  }),
  inert: true,
  closure_authority: false,
  evidence_authority: false,
  dispatch_authority: false,
  operations: [
    {
      operation_id: "op-account-read",
      surface_id: "surface:account-read",
      endpoint: "/api/accounts/{accountId}",
      method: "GET",
    },
  ],
});

function baseInput(overrides = {}) {
  return {
    target_domain: "contract-compiler.local",
    schema_contract: schemaContract,
    product_model: productModel,
    binding: {
      class_id: "object_authorization",
      schema_contract_hash: schemaContract.contract_hash,
      operation_id: "op-account-read",
      surface_id: "surface:account-read",
    },
    generated_hypothesis: "Attacker can read another account by changing accountId.",
    proposal_id: "cc-account-read",
    ...overrides,
  };
}

test("compileContractBinding enriches a routed ProofObligation with hard DesignAdmission", () => {
  const compiled = compileContractBinding(baseInput({ dry_run: true }));
  assert.equal(compiled.status, "compiled");
  assert.equal(compiled.routed, true);
  assert.equal(compiled.appended, false);
  assert.equal(compiled.proof_obligation.route.propose_tool, "bob_propose_hypothesis");
  assert.equal(compiled.proof_obligation.route.attach_tool, "bob_attach_contract");
  assert.equal(compiled.generated_hypothesis.inert, true);
  assert.equal(compiled.generated_hypothesis.closure_authority, false);
  assert.equal(compiled.contract.design_admission.hard_plane, true);
  assert.equal(compiled.contract.design_admission.no_generic_web_fallback, true);
  assert.equal(compiled.contract.design_admission.unknown_class_disposition, "HOLD");
  assert.deepEqual(
    compiled.contract.design_admission.mandatory_controls,
    OBJECT_AUTH_MANDATORY_CONTROLS,
  );
  assert.ok(compiled.contract.contract_hash);
  assert.equal(compiled.proposal_args.suggested_contract.contract_hash, compiled.contract_hash);
});

test("bob_compile_contract_binding routes via hypothesis proposal and attach-contract state", () => {
  withTempHome(() => {
    const routed = TOOL_HANDLERS.bob_compile_contract_binding(baseInput());
    assert.equal(routed.status, "compiled");
    assert.equal(routed.appended, true);
    assert.equal(routed.node_id, "TG-H-cc-account-read");
    assert.ok(routed.proposal_event_id);
    assert.ok(routed.contract_event_id);
    const graph = materializeTaskGraph("contract-compiler.local", { write: true });
    const node = graph.document.nodes.find((entry) => entry.node_id === routed.node_id);
    assert.ok(node, "compiled node materialized");
    assert.equal(node.state, "contracted");
    assert.equal(node.contract_hash, routed.contract_hash);
    assert.equal(routed.contract.design_admission.cvk.required, true);
    assert.equal(routed.contract.design_admission.generated_hypothesis_closure_authority, false);
  });
});

test("forged, soft, and unknown compiler inputs hold and append no closure route", () => {
  withTempHome(() => {
    const forged = compileAndRouteContractBinding(baseInput({
      proposal_id: "cc-forged",
      binding: {
        class_id: "object_authorization",
        schema_contract_hash: "0".repeat(64),
        operation_id: "op-account-read",
        surface_id: "surface:account-read",
      },
    }));
    assert.equal(forged.status, "HOLD");
    assert.equal(forged.routed, false);
    assert.equal(forged.appended, false);
    assert.equal(forged.reason, "schema_contract_hash_mismatch");

    const soft = compileAndRouteContractBinding(baseInput({
      proposal_id: "cc-soft",
      generated_hypothesis: {
        statement: "I should be inert but claim closure.",
        closure_authority: true,
      },
    }));
    assert.equal(soft.status, "HOLD");
    assert.equal(soft.routed, false);
    assert.equal(soft.appended, false);
    assert.equal(soft.reason, "generated_hypothesis_claimed_authority_refused");

    const unknown = TOOL_HANDLERS.bob_compile_contract_binding(baseInput({
      proposal_id: "cc-unknown",
      binding: {
        class_id: "new-autonomy-class",
        schema_contract_hash: schemaContract.contract_hash,
        operation_id: "op-account-read",
        surface_id: "surface:account-read",
      },
    }));
    assert.equal(unknown.status, "HOLD");
    assert.equal(unknown.routed, false);
    assert.equal(unknown.appended, false);
    assert.equal(unknown.reason, "unknown_control_validity_class");
    assert.equal(unknown.unknown_class_disposition, "HOLD");
    assert.equal(unknown.no_generic_web_fallback, true);

    const graph = materializeTaskGraph("contract-compiler.local", { write: false });
    assert.deepEqual(graph.document.nodes, []);
  });
});
