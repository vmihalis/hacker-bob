"use strict";

const {
  normalizeContract,
  assertContractSatisfiable,
} = require("../contract/index.js");
const {
  scheduleMaterialization,
} = require("../frontier/frontier-materialize-debounce.js");
const {
  assertNonEmptyString,
  normalizeOptionalText,
  normalizeStringArray,
} = require("../io/validation.js");
const {
  CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  OBJECT_AUTH_CLASS_ALIASES,
} = require("../validity/index.js");
const {
  appendContract,
} = require("../contract/index.js");
const {
  appendHypothesisProposal,
} = require("../waves/task-graph-events.js");
const {
  materializeTaskGraph,
} = require("../waves/task-graph-materializer.js");
const {
  hypothesisNodeId,
} = require("../waves/task-graph-state-machine.js");
const {
  cloneJson,
  hashCanonicalJson,
  isPlainObject,
} = require("../verification/verification-contracts.js");

const CONTRACT_COMPILER_VERSION = 1;
const CONTRACT_COMPILER_SOURCE = "contract_compiler";
const CONTRACT_COMPILER_PROOF_MODE = "executed_differential_v1";
const CONTRACT_COMPILER_CLOSURE_REGIME = "deterministic_signed_rows";
const CONTRACT_COMPILER_DISPOSITION_HOLD = "HOLD";

const OBJECT_AUTH_MANDATORY_CONTROLS = Object.freeze([
  "attacker_owned_control",
  "victim_auth_same_object",
  "no_auth_same_object",
  "public_object_check",
  "nonexistent_object",
  "stale_session_check",
  "cache_nonce_check",
]);

const REQUIRED_PRODUCTION_TOOLS = Object.freeze([
  "bob_run_auth_differential",
  "bob_verify_finding_differential",
]);

function hold(reason, details = {}) {
  return Object.freeze({
    version: CONTRACT_COMPILER_VERSION,
    status: "HOLD",
    routed: false,
    appended: false,
    reason,
    unknown_class_disposition: CONTRACT_COMPILER_DISPOSITION_HOLD,
    no_generic_web_fallback: true,
    closure_authority: false,
    evidence_authority: false,
    dispatch_authority: false,
    details: Object.freeze(cloneJson(details)),
  });
}

function sha(value) {
  return hashCanonicalJson(value);
}

function isDigest(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function normalizeMethod(value) {
  return assertNonEmptyString(value || "GET", "method").toUpperCase();
}

function normalizeClassId(value) {
  if (value === CONTROL_VALIDITY_CLASS_OBJECT_AUTH) return CONTROL_VALIDITY_CLASS_OBJECT_AUTH;
  if (typeof value === "string" && OBJECT_AUTH_CLASS_ALIASES.has(value)) {
    return CONTROL_VALIDITY_CLASS_OBJECT_AUTH;
  }
  return null;
}

function generatedClaimsAuthority(candidate) {
  if (!isPlainObject(candidate)) return false;
  return candidate.closure_authority === true
    || candidate.evidence_authority === true
    || candidate.dispatch_authority === true
    || candidate.claim_authority === true
    || candidate.closes === true
    || candidate.verified === true
    || candidate.disposition === "verified_pass";
}

function normalizeSchemaContract(raw) {
  if (!isPlainObject(raw)) return null;
  const contractHash = raw.contract_hash;
  if (!isDigest(contractHash)) return null;
  return Object.freeze({
    contract_hash: contractHash,
    endpoint: assertNonEmptyString(raw.endpoint, "schema_contract.endpoint"),
    method: normalizeMethod(raw.method),
    claimed_auth: isPlainObject(raw.claimed_auth) ? cloneJson(raw.claimed_auth) : {},
    claimed_params: Array.isArray(raw.claimed_params) ? cloneJson(raw.claimed_params) : [],
  });
}

function operationEndpoint(operation) {
  if (!isPlainObject(operation)) return null;
  return operation.endpoint || operation.path || operation.route || null;
}

function operationMethod(operation) {
  if (!isPlainObject(operation)) return null;
  return operation.method || operation.http_method || null;
}

function findBoundOperation(productModel, binding, schemaContract) {
  const operations = Array.isArray(productModel.operations) ? productModel.operations : [];
  const desiredOperationId = normalizeOptionalText(binding.operation_id, "binding.operation_id");
  const desiredSurfaceId = normalizeOptionalText(binding.surface_id, "binding.surface_id");
  const desiredEndpoint = normalizeOptionalText(binding.endpoint, "binding.endpoint")
    || schemaContract.endpoint;
  const desiredMethod = normalizeMethod(binding.method || schemaContract.method);
  for (const operation of operations) {
    if (!isPlainObject(operation)) continue;
    if (desiredOperationId && operation.operation_id !== desiredOperationId) continue;
    if (desiredSurfaceId && operation.surface_id !== desiredSurfaceId) continue;
    if (operationEndpoint(operation) !== desiredEndpoint) continue;
    if (normalizeMethod(operationMethod(operation) || desiredMethod) !== desiredMethod) continue;
    return operation;
  }
  return null;
}

function normalizeProductModel(raw) {
  if (!isPlainObject(raw)) return null;
  if (raw.inert !== true) return null;
  if (raw.closure_authority !== false) return null;
  if (raw.evidence_authority !== false) return null;
  if (raw.dispatch_authority !== false) return null;
  if (!isDigest(raw.model_hash)) return null;
  return raw;
}

function hypothesisStatementFor({ generatedHypothesis, schemaContract, classId }) {
  let statement = null;
  if (typeof generatedHypothesis === "string") {
    statement = generatedHypothesis.trim();
  } else if (isPlainObject(generatedHypothesis)) {
    statement = normalizeOptionalText(
      generatedHypothesis.hypothesis_statement || generatedHypothesis.statement,
      "generated_hypothesis.statement",
    );
  }
  if (!statement) {
    statement = `${classId} obligation for ${schemaContract.method} ${schemaContract.endpoint}`;
  }
  return statement.length <= 512 ? statement : statement.slice(0, 512);
}

function buildDesignAdmission({ classId, schemaContract, productModel, bindingHash }) {
  return Object.freeze({
    version: "design-admission.v1",
    status: "required",
    hard_plane: true,
    source: CONTRACT_COMPILER_SOURCE,
    class_id: classId,
    proof_mode: CONTRACT_COMPILER_PROOF_MODE,
    closure_regime: CONTRACT_COMPILER_CLOSURE_REGIME,
    unknown_class_disposition: CONTRACT_COMPILER_DISPOSITION_HOLD,
    no_generic_web_fallback: true,
    mandatory_controls: OBJECT_AUTH_MANDATORY_CONTROLS.slice(),
    cvk: Object.freeze({
      required: true,
      validity_class_id: classId,
      certificate_required: true,
    }),
    generated_hypothesis_inert: true,
    generated_hypothesis_closure_authority: false,
    schema_contract_hash: schemaContract.contract_hash,
    product_model_hash: productModel.model_hash,
    binding_hash: bindingHash,
  });
}

function buildContract({ classId, schemaContract, surfaceId, designAdmission, proposalId }) {
  return normalizeContract({
    contract_id: `CC-${sha({
      class_id: classId,
      schema_contract_hash: schemaContract.contract_hash,
      surface_id: surfaceId,
      proposal_id: proposalId,
    }).slice(0, 24)}`,
    severity_floor: "medium",
    invariants: [
      {
        id: "schema-model-binding",
        statement:
          "Schema endpoint and product-model operation stay bound to the same surface and class.",
      },
      {
        id: "signed-differential-required",
        statement:
          "Closure requires signed executed differential rows and a CVK certificate for this class.",
      },
      {
        id: "generated-hypothesis-inert",
        statement:
          "Generated hypotheses nominate work only; they never supply evidence, dispatch, or closure.",
      },
    ],
    witnesses: [
      {
        id: "executed-differential-flip",
        kind: "tool_output_match",
        predicate: {
          tool: "bob_verify_finding_differential",
          match: { path: "$.disposition", equals: "verified_pass" },
        },
      },
      {
        id: "control-validity-certificate",
        kind: "evidence_ref_kind_present",
        predicate: { kind: "control_validity_certificate" },
      },
    ],
    production_paths: [
      {
        description:
          "Run the signed auth differential, then bind positive and control rows through the verifier.",
        tool_call_pattern: [
          {
            tool: "bob_run_auth_differential",
            args_match: {
              surface_id: surfaceId,
              endpoints: [{ endpoint: schemaContract.endpoint, method: schemaContract.method }],
            },
          },
          { tool: "bob_verify_finding_differential" },
        ],
      },
    ],
    design_admission: designAdmission,
  });
}

function compileContractBinding(input) {
  if (!isPlainObject(input)) return hold("input_not_object");
  const targetDomain = assertNonEmptyString(input.target_domain, "target_domain");
  const schemaContract = normalizeSchemaContract(input.schema_contract);
  if (!schemaContract) return hold("schema_contract_unbound_or_invalid");
  const productModel = normalizeProductModel(input.product_model);
  if (!productModel) return hold("product_model_not_inert_or_invalid");
  if (!isPlainObject(input.binding)) return hold("binding_not_object");
  if (input.binding.soft === true || input.binding.generated === true) {
    return hold("binding_soft_or_generated_authority_refused");
  }
  if (generatedClaimsAuthority(input.generated_hypothesis)) {
    return hold("generated_hypothesis_claimed_authority_refused");
  }
  const bindingClass = input.binding.class_id
    || input.binding.validity_class_id
    || input.binding.bug_class
    || input.class_id
    || input.validity_class_id;
  const classId = normalizeClassId(bindingClass);
  if (!classId) {
    return hold("unknown_control_validity_class", {
      class_id: bindingClass || null,
    });
  }
  const bindingSchemaHash = input.binding.schema_contract_hash || schemaContract.contract_hash;
  if (bindingSchemaHash !== schemaContract.contract_hash) {
    return hold("schema_contract_hash_mismatch", {
      binding_schema_contract_hash: bindingSchemaHash,
      schema_contract_hash: schemaContract.contract_hash,
    });
  }
  const operation = findBoundOperation(productModel, input.binding, schemaContract);
  if (!operation) {
    return hold("unbound_schema_model_binding", {
      schema_contract_hash: schemaContract.contract_hash,
      endpoint: schemaContract.endpoint,
      method: schemaContract.method,
    });
  }
  const surfaceId = normalizeOptionalText(input.binding.surface_id, "binding.surface_id")
    || normalizeOptionalText(operation.surface_id, "operation.surface_id");
  if (!surfaceId) return hold("surface_unbound");
  const bindingHash = sha({
    class_id: classId,
    schema_contract_hash: schemaContract.contract_hash,
    product_model_hash: productModel.model_hash,
    surface_id: surfaceId,
    endpoint: schemaContract.endpoint,
    method: schemaContract.method,
    operation_id: operation.operation_id || null,
  });
  const designAdmission = buildDesignAdmission({
    classId,
    schemaContract,
    productModel,
    bindingHash,
  });
  const proposalId = normalizeOptionalText(input.proposal_id, "proposal_id")
    || `cc-${bindingHash.slice(0, 24)}`;
  const contract = buildContract({
    classId,
    schemaContract,
    surfaceId,
    designAdmission,
    proposalId,
  });
  assertContractSatisfiable(contract, {
    allowed_tools_for_node: REQUIRED_PRODUCTION_TOOLS.slice(),
  });
  const hypothesisStatement = hypothesisStatementFor({
    generatedHypothesis: input.generated_hypothesis,
    schemaContract,
    classId,
  });
  const proposalArgs = {
    target_domain: targetDomain,
    hypothesis_statement: hypothesisStatement,
    surface_refs: normalizeStringArray([surfaceId], "surface_refs"),
    suggested_contract: contract,
    proposal_id: proposalId,
    source: {
      tool: "bob_compile_contract_binding",
      compiler: CONTRACT_COMPILER_SOURCE,
      schema_contract_hash: schemaContract.contract_hash,
      product_model_hash: productModel.model_hash,
    },
    actor: input.actor,
  };
  const nodeId = hypothesisNodeId({ proposalId, eventId: bindingHash });
  const proofObligation = Object.freeze({
    obligation_id: `PO-${bindingHash.slice(0, 24)}`,
    class_id: classId,
    target_domain: targetDomain,
    surface_id: surfaceId,
    endpoint: schemaContract.endpoint,
    method: schemaContract.method,
    schema_contract_hash: schemaContract.contract_hash,
    product_model_hash: productModel.model_hash,
    binding_hash: bindingHash,
    route: Object.freeze({
      propose_tool: "bob_propose_hypothesis",
      attach_tool: "bob_attach_contract",
      node_id: nodeId,
    }),
    closure_authority: false,
    evidence_authority: false,
  });
  return Object.freeze({
    version: CONTRACT_COMPILER_VERSION,
    status: "compiled",
    routed: true,
    appended: false,
    target_domain: targetDomain,
    node_id: nodeId,
    proposal_id: proposalId,
    contract_hash: contract.contract_hash,
    contract,
    design_admission: designAdmission,
    proof_obligation: proofObligation,
    proposal_args: Object.freeze(proposalArgs),
    attach_args: Object.freeze({
      target_domain: targetDomain,
      node_id: nodeId,
      contract,
      allowed_tools_for_node: REQUIRED_PRODUCTION_TOOLS.slice(),
      source: {
        tool: "bob_compile_contract_binding",
        compiler: CONTRACT_COMPILER_SOURCE,
        binding_hash: bindingHash,
      },
      actor: input.actor,
    }),
    generated_hypothesis: Object.freeze({
      inert: true,
      closure_authority: false,
      evidence_authority: false,
      dispatch_authority: false,
      statement: hypothesisStatement,
    }),
  });
}

function compileAndRouteContractBinding(input) {
  const compiled = compileContractBinding(input);
  if (compiled.status !== "compiled") return compiled;
  if (input && input.dry_run === true) return compiled;
  const proposalEvent = appendHypothesisProposal(compiled.proposal_args);
  materializeTaskGraph(compiled.target_domain, { write: true });
  const attached = appendContract(compiled.attach_args);
  try {
    scheduleMaterialization(compiled.target_domain);
  } catch {
    // Debounce is best effort; the ledger append is the authority.
  }
  return Object.freeze({
    ...compiled,
    appended: true,
    proposal_event_id: proposalEvent.event_id,
    proposal_event_hash: proposalEvent.event_hash,
    contract_event_id: attached.event.event_id,
    contract_event_hash: attached.event.event_hash,
    from_state: attached.from_state,
    contract_hash: attached.contract.contract_hash,
    contract: attached.contract,
  });
}

module.exports = Object.freeze({
  CONTRACT_COMPILER_CLOSURE_REGIME,
  CONTRACT_COMPILER_DISPOSITION_HOLD,
  CONTRACT_COMPILER_PROOF_MODE,
  CONTRACT_COMPILER_SOURCE,
  CONTRACT_COMPILER_VERSION,
  OBJECT_AUTH_MANDATORY_CONTROLS,
  REQUIRED_PRODUCTION_TOOLS,
  compileAndRouteContractBinding,
  compileContractBinding,
});
