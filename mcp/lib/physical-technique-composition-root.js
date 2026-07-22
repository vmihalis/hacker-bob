"use strict";

// Closed Plane-PH technique composition owner.
//
// A production root can be created only from the broker's privately branded,
// live signed-admission bridge and the provider-worker-vault module's privately
// branded production root/capability.  Runtime identity is registry enrollment
// data joined to those brands and their exact signed admission digests.  No
// provider identifier, operation/command selector, byte surface, callback,
// module path, or caller-authored readiness value is accepted by the production
// constructor.
//
// The current broker and worker/vault implementations intentionally report
// concrete production blockers.  Consequently this module defines the closed
// composition contract, but it does not promote conformance fixtures or the
// fixed non-authorizing completion adapter into a production root.  Even after
// those component blockers are cleared, execution remains fail-closed until one
// private owner can atomically consume both the signed dispatch admission and
// the worker/vault transaction and project its durable terminal evidence.

const { types: utilTypes } = require("node:util");

const {
  hashCanonicalJson,
} = require("./verification-contracts.js");

const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const utilIsProxy = utilTypes.isProxy;

const PHYSICAL_TECHNIQUE_COMPOSITION_ROOT_VERSION = 1;
const ENROLLMENT_BINDING_DOMAIN =
  "hacker-bob/production-physical-technique-composition-enrollment/v1";
const TEST_ENROLLMENT_BINDING_DOMAIN =
  "hacker-bob/test-only-physical-technique-composition-enrollment/v1";
const ROOT_BINDING_DOMAIN =
  "hacker-bob/physical-technique-composition-root/v1";
const PRODUCTION_EXECUTION_SPINE_BLOCKERS = objectFreeze([
  "provider_worker_vault_dispatch_transaction_owner_missing",
  "provider_worker_vault_terminal_projection_owner_missing",
]);

const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const REF_PATTERN = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const TECHNIQUE_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const PHYSICAL_TECHNIQUE_FAMILIES = objectFreeze([
  "credential_acquire",
  "credential_emulate",
  "credential_recover",
  "credential_write",
  "physical_observe",
  "protocol_transceive",
  "rf_trace",
]);
const EXECUTION_DISPOSITIONS = objectFreeze([
  "blocked",
  "denied",
  "inconclusive",
  "not_applicable",
  "stimulus_recorded",
]);
const RESIDUAL_EFFECT_STATES = objectFreeze([
  "none",
  "quarantined",
  "restored",
  "unknown",
]);
const IDENTITY_FIELDS = objectFreeze([
  "target_domain",
  "family",
  "execution_ref",
  "cell_ref",
  "assignment_context_digest",
  "session_nucleus_hash",
  "physical_scope_axis_digest",
]);
const ENROLLMENT_FIELDS = objectFreeze([
  "version",
  "kind",
  ...IDENTITY_FIELDS,
  "technique_cell_id",
  "signed_attempt_ref",
  "attempt_ref",
  "technique_id",
  "signed_grant_digest",
  "execution_request_digest",
  "execution_lineage_digest",
  "composition_binding_digest",
  "admission_binding_digest",
]);
const EXECUTION_REQUEST_FIELDS = IDENTITY_FIELDS;
const TEST_OUTCOME_FIELDS = objectFreeze([
  "version",
  "kind",
  ...IDENTITY_FIELDS,
  "signed_grant_digest",
  "execution_request_digest",
  "execution_lineage_digest",
  "attempt_ref",
  "technique_id",
  "execution_disposition",
  "residual_effect_state",
  "instrument_receipt_ref",
  "observation_refs",
  "artifact_refs",
  "verification_input_ref",
  "completion_evidence_digest",
  "cleanup_evidence_digest",
  "terminal_state",
  "evidence_commit_state",
  "cleanup_state",
]);
const ROOT_PUBLIC_FIELDS = objectFreeze([
  "version",
  "kind",
  "root_binding_digest",
]);

const PRODUCTION_ROOTS = new WeakSet();
const TEST_ROOTS = new WeakSet();
const ROOT_STATE = new WeakMap();
const TEST_ENROLLMENT_CLAIMS = new Set();

function compositionError(code, message = code, cause = null, blockers = null) {
  const error = new Error(`${code}: ${message}`);
  error.code = code;
  if (cause != null) Object.defineProperty(error, "cause", { value: cause });
  if (blockers != null) {
    Object.defineProperty(error, "production_blockers", {
      value: objectFreeze([...blockers]),
    });
  }
  return error;
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilIsProxy(value) || utilTypes.isPromise(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertExactDataObject(value, fields, label) {
  if (!isPlainDataObject(value)) {
    throw compositionError(
      "physical_technique_composition_contract_invalid",
      `${label} must be a non-Proxy plain data object`,
    );
  }
  const descriptors = objectGetOwnPropertyDescriptors(value);
  const keys = reflectOwnKeys(descriptors);
  if (keys.some((key) => typeof key !== "string")) {
    throw compositionError(
      "physical_technique_composition_contract_invalid",
      `${label} cannot contain symbol fields`,
    );
  }
  const expected = [...fields].sort();
  const actual = [...keys].sort();
  if (actual.length !== expected.length
      || actual.some((field, index) => field !== expected[index])) {
    throw compositionError(
      "physical_technique_composition_contract_invalid",
      `${label} must carry exactly ${fields.join(", ")}`,
    );
  }
  const result = Object.create(null);
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !objectHasOwn(descriptor, "value")) {
      throw compositionError(
        "physical_technique_composition_contract_invalid",
        `${label}.${field} must be an enumerable data property`,
      );
    }
    result[field] = descriptor.value;
  }
  return result;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw compositionError(
      "physical_technique_composition_contract_invalid",
      `${label} must be a lowercase SHA-256 digest`,
    );
  }
  return value;
}

function assertRef(value, label, prefix = null) {
  if (typeof value !== "string" || !REF_PATTERN.test(value) || value.includes("..")
      || (prefix != null && !value.startsWith(`${prefix}:`))) {
    throw compositionError(
      "physical_technique_composition_contract_invalid",
      `${label} must be an opaque ${prefix || "namespaced"} reference`,
    );
  }
  return value;
}

function assertToken(value, label) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)) {
    throw compositionError(
      "physical_technique_composition_contract_invalid",
      `${label} must be a bounded token`,
    );
  }
  return value;
}

function assertTargetDomain(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 253
      || value !== value.trim() || /[\\/\u0000-\u001f\u007f]/u.test(value)) {
    throw compositionError(
      "physical_technique_composition_contract_invalid",
      `${label} is invalid`,
    );
  }
  return value;
}

function assertFamily(value, label) {
  if (!PHYSICAL_TECHNIQUE_FAMILIES.includes(value)) {
    throw compositionError(
      "physical_technique_composition_contract_invalid",
      `${label} is not a registered physical technique family`,
    );
  }
  return value;
}

function normalizeEnrollment(input, expectedKind, expectedCompositionBindingDigest = null) {
  const value = assertExactDataObject(input, ENROLLMENT_FIELDS, "physical technique enrollment");
  if (value.version !== PHYSICAL_TECHNIQUE_COMPOSITION_ROOT_VERSION
      || value.kind !== expectedKind) {
    throw compositionError(
      "physical_technique_composition_contract_invalid",
      "physical technique enrollment version or kind is invalid",
    );
  }
  const normalized = {
    version: PHYSICAL_TECHNIQUE_COMPOSITION_ROOT_VERSION,
    kind: expectedKind,
    target_domain: assertTargetDomain(value.target_domain, "enrollment.target_domain"),
    family: assertFamily(value.family, "enrollment.family"),
    execution_ref: assertRef(
      value.execution_ref,
      "enrollment.execution_ref",
      "physical-execution",
    ),
    cell_ref: assertRef(value.cell_ref, "enrollment.cell_ref", "physical-cell"),
    assignment_context_digest: assertDigest(
      value.assignment_context_digest,
      "enrollment.assignment_context_digest",
    ),
    session_nucleus_hash: assertDigest(
      value.session_nucleus_hash,
      "enrollment.session_nucleus_hash",
    ),
    physical_scope_axis_digest: assertDigest(
      value.physical_scope_axis_digest,
      "enrollment.physical_scope_axis_digest",
    ),
    technique_cell_id: assertToken(value.technique_cell_id, "enrollment.technique_cell_id"),
    signed_attempt_ref: assertRef(
      value.signed_attempt_ref,
      "enrollment.signed_attempt_ref",
      "attempt",
    ),
    attempt_ref: assertRef(value.attempt_ref, "enrollment.attempt_ref", "physical-attempt"),
    technique_id: typeof value.technique_id === "string"
        && TECHNIQUE_PATTERN.test(value.technique_id)
      ? value.technique_id
      : null,
    signed_grant_digest: assertDigest(
      value.signed_grant_digest,
      "enrollment.signed_grant_digest",
    ),
    execution_request_digest: assertDigest(
      value.execution_request_digest,
      "enrollment.execution_request_digest",
    ),
    execution_lineage_digest: assertDigest(
      value.execution_lineage_digest,
      "enrollment.execution_lineage_digest",
    ),
    composition_binding_digest: assertDigest(
      value.composition_binding_digest,
      "enrollment.composition_binding_digest",
    ),
  };
  if (normalized.technique_id == null) {
    throw compositionError(
      "physical_technique_composition_contract_invalid",
      "enrollment.technique_id is invalid",
    );
  }
  if (expectedCompositionBindingDigest != null
      && normalized.composition_binding_digest !== expectedCompositionBindingDigest) {
    throw compositionError(
      "physical_technique_composition_binding_drift",
      "enrollment belongs to another broker composition binding",
    );
  }
  const domain = expectedKind === "production_physical_technique_enrollment"
    ? ENROLLMENT_BINDING_DOMAIN : TEST_ENROLLMENT_BINDING_DOMAIN;
  const admissionBindingDigest = hashCanonicalJson({ domain, ...normalized });
  if (assertDigest(
    value.admission_binding_digest,
    "enrollment.admission_binding_digest",
  ) !== admissionBindingDigest) {
    throw compositionError(
      "physical_technique_composition_binding_drift",
      "enrollment digest does not bind the exact runtime identity and admission",
    );
  }
  return objectFreeze({ ...normalized, admission_binding_digest: admissionBindingDigest });
}

function identityProjection(enrollment) {
  return objectFreeze(Object.fromEntries(
    IDENTITY_FIELDS.map((field) => [field, enrollment[field]]),
  ));
}

function normalizeExecutionRequest(input) {
  const value = assertExactDataObject(
    input,
    EXECUTION_REQUEST_FIELDS,
    "physical technique composition execution request",
  );
  return objectFreeze({
    target_domain: assertTargetDomain(value.target_domain, "request.target_domain"),
    family: assertFamily(value.family, "request.family"),
    execution_ref: assertRef(value.execution_ref, "request.execution_ref", "physical-execution"),
    cell_ref: assertRef(value.cell_ref, "request.cell_ref", "physical-cell"),
    assignment_context_digest: assertDigest(
      value.assignment_context_digest,
      "request.assignment_context_digest",
    ),
    session_nucleus_hash: assertDigest(
      value.session_nucleus_hash,
      "request.session_nucleus_hash",
    ),
    physical_scope_axis_digest: assertDigest(
      value.physical_scope_axis_digest,
      "request.physical_scope_axis_digest",
    ),
  });
}

function assertExactIdentity(actual, expected, label) {
  for (const field of IDENTITY_FIELDS) {
    if (actual[field] !== expected[field]) {
      throw compositionError(
        "physical_technique_composition_binding_drift",
        `${label}.${field} does not match the enrolled runtime identity`,
      );
    }
  }
  return actual;
}

function normalizeRefArray(input, label) {
  if (!Array.isArray(input) || utilIsProxy(input) || input.length > 16) {
    throw compositionError(
      "physical_technique_composition_evidence_invalid",
      `${label} must be a bounded dense reference array`,
    );
  }
  const descriptors = objectGetOwnPropertyDescriptors(input);
  const values = [];
  for (let index = 0; index < input.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || descriptor.enumerable !== true || !objectHasOwn(descriptor, "value")) {
      throw compositionError(
        "physical_technique_composition_evidence_invalid",
        `${label} must contain only dense data properties`,
      );
    }
    values.push(assertRef(descriptor.value, `${label}[${index}]`));
  }
  const extra = reflectOwnKeys(descriptors).filter((key) => (
    key !== "length" && (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key))
  ));
  if (extra.length > 0 || new Set(values).size !== values.length) {
    throw compositionError(
      "physical_technique_composition_evidence_invalid",
      `${label} contains an extra field or duplicate reference`,
    );
  }
  return objectFreeze([...values].sort());
}

function nullableRef(value, label, prefix = null) {
  return value == null ? null : assertRef(value, label, prefix);
}

function buildRuntimeResult(enrollment, outcome) {
  const basis = {
    version: PHYSICAL_TECHNIQUE_COMPOSITION_ROOT_VERSION,
    family: enrollment.family,
    execution_ref: enrollment.execution_ref,
    cell_ref: enrollment.cell_ref,
    assignment_context_digest: enrollment.assignment_context_digest,
    session_nucleus_hash: enrollment.session_nucleus_hash,
    attempt_ref: outcome.attempt_ref,
    technique_id: outcome.technique_id,
    execution_disposition: outcome.execution_disposition,
    residual_effect_state: outcome.residual_effect_state,
    instrument_receipt_ref: outcome.instrument_receipt_ref,
    observation_refs: outcome.observation_refs,
    artifact_refs: outcome.artifact_refs,
    verification_input_ref: outcome.verification_input_ref,
  };
  return objectFreeze({
    ...basis,
    execution_projection_digest: hashCanonicalJson(basis),
  });
}

function normalizeTestOutcome(input, state) {
  const value = assertExactDataObject(
    input,
    TEST_OUTCOME_FIELDS,
    "test physical technique composition outcome",
  );
  if (value.version !== PHYSICAL_TECHNIQUE_COMPOSITION_ROOT_VERSION
      || value.kind !== "test_physical_technique_composition_outcome") {
    throw compositionError(
      "physical_technique_composition_evidence_invalid",
      "test composition outcome version or kind is invalid",
    );
  }
  const identity = normalizeExecutionRequest(Object.fromEntries(
    IDENTITY_FIELDS.map((field) => [field, value[field]]),
  ));
  assertExactIdentity(identity, state.identity, "test composition outcome");
  for (const field of [
    "signed_grant_digest",
    "execution_request_digest",
    "execution_lineage_digest",
  ]) {
    if (assertDigest(value[field], `test outcome.${field}`) !== state.enrollment[field]) {
      throw compositionError(
        "physical_technique_composition_binding_drift",
        `test composition outcome.${field} belongs to another admission`,
      );
    }
  }
  if (value.attempt_ref !== state.enrollment.attempt_ref
      || value.technique_id !== state.enrollment.technique_id) {
    throw compositionError(
      "physical_technique_composition_binding_drift",
      "test composition outcome attempt or technique binding drifted",
    );
  }
  if (!EXECUTION_DISPOSITIONS.includes(value.execution_disposition)
      || !RESIDUAL_EFFECT_STATES.includes(value.residual_effect_state)) {
    throw compositionError(
      "physical_technique_composition_evidence_invalid",
      "test composition outcome disposition is invalid",
    );
  }
  if (value.terminal_state !== "closed" || value.evidence_commit_state !== "durable"
      || !["not_required", "restored"].includes(value.cleanup_state)) {
    throw compositionError(
      "physical_technique_composition_cleanup_missing",
      "composition outcome lacks a closed durable evidence and cleanup terminal state",
    );
  }
  assertDigest(value.completion_evidence_digest, "test outcome.completion_evidence_digest");
  assertDigest(value.cleanup_evidence_digest, "test outcome.cleanup_evidence_digest");
  const normalized = {
    attempt_ref: assertRef(value.attempt_ref, "test outcome.attempt_ref", "physical-attempt"),
    technique_id: value.technique_id,
    execution_disposition: value.execution_disposition,
    residual_effect_state: value.residual_effect_state,
    instrument_receipt_ref: nullableRef(
      value.instrument_receipt_ref,
      "test outcome.instrument_receipt_ref",
      "physical-execution-receipt",
    ),
    observation_refs: normalizeRefArray(value.observation_refs, "test outcome.observation_refs"),
    artifact_refs: normalizeRefArray(value.artifact_refs, "test outcome.artifact_refs"),
    verification_input_ref: nullableRef(
      value.verification_input_ref,
      "test outcome.verification_input_ref",
      "physical-verification-input",
    ),
  };
  if (normalized.execution_disposition === "stimulus_recorded") {
    if (normalized.instrument_receipt_ref == null || normalized.verification_input_ref == null
        || !["none", "restored"].includes(normalized.residual_effect_state)) {
      throw compositionError(
        "physical_technique_composition_evidence_missing",
        "recorded stimulus lacks durable receipt/verifier input or resolved cleanup",
      );
    }
  } else if (normalized.instrument_receipt_ref != null) {
    throw compositionError(
      "physical_technique_composition_evidence_invalid",
      "a non-recorded outcome cannot carry an instrument execution receipt",
    );
  }
  if (normalized.residual_effect_state === "unknown"
      && normalized.execution_disposition !== "inconclusive") {
    throw compositionError(
      "physical_technique_composition_cleanup_missing",
      "unknown residual effect must remain inconclusive",
    );
  }
  return objectFreeze(normalized);
}

function createRoot(kind, enrollment, stateInput, rootSet) {
  const identity = identityProjection(enrollment);
  const rootBasis = {
    domain: ROOT_BINDING_DOMAIN,
    version: PHYSICAL_TECHNIQUE_COMPOSITION_ROOT_VERSION,
    kind,
    admission_binding_digest: enrollment.admission_binding_digest,
  };
  const root = objectFreeze({
    version: PHYSICAL_TECHNIQUE_COMPOSITION_ROOT_VERSION,
    kind,
    root_binding_digest: hashCanonicalJson(rootBasis),
  });
  const state = {
    ...stateInput,
    enrollment,
    identity,
    phase: "ready",
  };
  rootSet.add(root);
  ROOT_STATE.set(root, state);
  return root;
}

function validateRoot(input, rootSet, expectedKind, label) {
  const state = input == null ? null : ROOT_STATE.get(input);
  if (!input || !state || !rootSet.has(input) || !objectIsFrozen(input)
      || utilIsProxy(input)) {
    throw compositionError(
      "physical_technique_composition_root_untrusted",
      `${label} must be created by Bob's private composition factory`,
    );
  }
  const value = assertExactDataObject(input, ROOT_PUBLIC_FIELDS, label);
  const expectedDigest = hashCanonicalJson({
    domain: ROOT_BINDING_DOMAIN,
    version: PHYSICAL_TECHNIQUE_COMPOSITION_ROOT_VERSION,
    kind: expectedKind,
    admission_binding_digest: state.enrollment.admission_binding_digest,
  });
  if (value.version !== PHYSICAL_TECHNIQUE_COMPOSITION_ROOT_VERSION
      || value.kind !== expectedKind || value.root_binding_digest !== expectedDigest) {
    throw compositionError(
      "physical_technique_composition_root_untrusted",
      `${label} public binding drifted from private state`,
    );
  }
  return { root: input, state };
}

function assertProductionPhysicalTechniqueCompositionRoot(input) {
  return validateRoot(
    input,
    PRODUCTION_ROOTS,
    "production_physical_technique_composition_root",
    "production physical technique composition root",
  ).root;
}

function describeProductionPhysicalTechniqueCompositionRoot(input) {
  const { state } = validateRoot(
    input,
    PRODUCTION_ROOTS,
    "production_physical_technique_composition_root",
    "production physical technique composition root",
  );
  revalidateProductionState(state);
  return state.identity;
}

function assertTestPhysicalTechniqueCompositionRoot(input) {
  return validateRoot(
    input,
    TEST_ROOTS,
    "test_physical_technique_composition_root",
    "test physical technique composition root",
  ).root;
}

function describeTestPhysicalTechniqueCompositionRoot(input) {
  return validateRoot(
    input,
    TEST_ROOTS,
    "test_physical_technique_composition_root",
    "test physical technique composition root",
  ).state.identity;
}

function assertWorkerVaultProduction(root, expectedLineageDigest) {
  const workerVault = require(
    "../../packages/bob-instrument-broker/lib/provider-worker-vault-composition.js"
  );
  let workerRoot;
  try {
    workerRoot = workerVault.assertProviderWorkerVaultCompositionRoot(root);
  } catch (cause) {
    throw compositionError(
      "physical_technique_worker_vault_untrusted",
      "provider-worker-vault root is not privately branded",
      cause,
    );
  }
  let readiness;
  try {
    readiness = workerRoot.readiness();
  } catch (cause) {
    throw compositionError(
      "physical_technique_worker_vault_untrusted",
      "provider-worker-vault readiness could not be revalidated",
      cause,
    );
  }
  const blockers = Array.isArray(readiness && readiness.requirements)
    ? readiness.requirements
      .filter((entry) => entry && entry.status !== "satisfied")
      .map((entry) => entry.blocker_code)
      .filter((entry) => typeof entry === "string")
    : ["provider_worker_vault_requirements_unavailable"];
  if (workerRoot.production_ready !== true
      || workerRoot.hardware_access_authorized !== true
      || workerRoot.execution_authority !== true
      || readiness.production_ready !== true
      || readiness.hardware_access_authorized !== true
      || readiness.execution_authority !== true) {
    throw compositionError(
      "physical_technique_worker_vault_not_production",
      "provider-worker-vault root has no independent production authority",
      null,
      blockers,
    );
  }
  if (workerRoot.execution_lineage_digest !== expectedLineageDigest) {
    throw compositionError(
      "physical_technique_composition_binding_drift",
      "provider-worker-vault lineage belongs to another signed admission",
    );
  }
  return { workerVault, workerRoot };
}

function readDispatchBinding(bridge) {
  const dispatch = require(
    "../../packages/bob-instrument-broker/lib/physical-provider-dispatch.js"
  );
  try {
    dispatch.assertPhysicalProviderDispatchBridge(bridge);
    return {
      dispatch,
      binding: dispatch.projectPhysicalProviderDispatchCompositionBinding(bridge),
    };
  } catch (cause) {
    throw compositionError(
      "physical_technique_provider_dispatch_untrusted",
      "provider dispatch bridge is not a live privately branded bridge",
      cause,
    );
  }
}

function assertDispatchBindingMatchesEnrollment(binding, enrollment) {
  const exact = {
    session_nucleus_hash: enrollment.session_nucleus_hash,
    physical_scope_axis_digest: enrollment.physical_scope_axis_digest,
    technique_cell_id: enrollment.technique_cell_id,
    attempt_ref: enrollment.signed_attempt_ref,
    signed_grant_digest: enrollment.signed_grant_digest,
    execution_request_digest: enrollment.execution_request_digest,
    execution_lineage_digest: enrollment.execution_lineage_digest,
    composition_binding_digest: enrollment.composition_binding_digest,
  };
  for (const [field, expected] of Object.entries(exact)) {
    if (binding[field] !== expected) {
      throw compositionError(
        "physical_technique_composition_binding_drift",
        `provider dispatch ${field} belongs to another runtime enrollment`,
      );
    }
  }
  if (binding.dispatch_phase !== "held") {
    throw compositionError(
      "physical_technique_composition_replay",
      "provider dispatch admission is no longer an unused held execution",
    );
  }
}

function revalidateProductionState(state) {
  const observed = readDispatchBinding(state.dispatch_bridge);
  assertDispatchBindingMatchesEnrollment(observed.binding, state.enrollment);
  if (observed.binding.production_qualification !== "qualified") {
    throw compositionError(
      "physical_technique_provider_dispatch_not_production",
      "provider dispatch still lacks independent completion, cleanup, worker, or HIL owners",
      null,
      observed.binding.production_blockers || [],
    );
  }
  const worker = assertWorkerVaultProduction(
    state.worker_vault_root,
    state.enrollment.execution_lineage_digest,
  );
  try {
    worker.workerVault.assertProviderWorkerVaultProductionTransactionCapability(
      worker.workerRoot,
      state.transaction_capability,
    );
  } catch (cause) {
    throw compositionError(
      "physical_technique_worker_vault_capability_untrusted",
      "worker-vault transaction capability is not exact, live, and privately branded",
      cause,
    );
  }
  return { worker };
}

function createProductionPhysicalTechniqueCompositionRoot(input) {
  const value = assertExactDataObject(input, [
    "version",
    "enrollment",
    "provider_dispatch_bridge",
    "provider_worker_vault_root",
    "transaction_capability",
  ], "production physical technique composition root request");
  if (value.version !== PHYSICAL_TECHNIQUE_COMPOSITION_ROOT_VERSION) {
    throw compositionError(
      "physical_technique_composition_contract_invalid",
      "production composition request.version must be 1",
    );
  }
  // Normalize the caller-visible registry record before invoking any branded
  // component. Accessors, Proxies, unknown fields, public provider selectors,
  // callbacks, paths, and readiness booleans therefore fail first.
  const initialEnrollment = normalizeEnrollment(
    value.enrollment,
    "production_physical_technique_enrollment",
  );
  const observed = readDispatchBinding(value.provider_dispatch_bridge);
  const enrollment = normalizeEnrollment(
    value.enrollment,
    "production_physical_technique_enrollment",
    observed.binding.composition_binding_digest,
  );
  assertDispatchBindingMatchesEnrollment(observed.binding, enrollment);
  if (observed.binding.production_qualification !== "qualified") {
    throw compositionError(
      "physical_technique_provider_dispatch_not_production",
      "provider dispatch still lacks independent completion, cleanup, worker, or HIL owners",
      null,
      observed.binding.production_blockers || [],
    );
  }
  const worker = assertWorkerVaultProduction(
    value.provider_worker_vault_root,
    initialEnrollment.execution_lineage_digest,
  );
  try {
    worker.workerVault.assertProviderWorkerVaultProductionTransactionCapability(
      worker.workerRoot,
      value.transaction_capability,
    );
  } catch (cause) {
    throw compositionError(
      "physical_technique_worker_vault_capability_untrusted",
      "worker-vault transaction capability is not exact, live, and privately branded",
      cause,
    );
  }
  return createRoot(
    "production_physical_technique_composition_root",
    enrollment,
    {
      dispatch_bridge: value.provider_dispatch_bridge,
      worker_vault_root: worker.workerRoot,
      transaction_capability: value.transaction_capability,
    },
    PRODUCTION_ROOTS,
  );
}

function createTestPhysicalTechniqueCompositionRoot(input) {
  const value = assertExactDataObject(input, [
    "version",
    "enrollment",
    "execute",
  ], "test physical technique composition root request");
  if (value.version !== PHYSICAL_TECHNIQUE_COMPOSITION_ROOT_VERSION
      || typeof value.execute !== "function" || utilIsProxy(value.execute)) {
    throw compositionError(
      "physical_technique_composition_contract_invalid",
      "test composition requires version 1 and a non-Proxy executor",
    );
  }
  const enrollment = normalizeEnrollment(
    value.enrollment,
    "test_physical_technique_enrollment",
  );
  if (TEST_ENROLLMENT_CLAIMS.has(enrollment.admission_binding_digest)) {
    throw compositionError(
      "physical_technique_composition_replay",
      "test enrollment was already claimed by another root",
    );
  }
  TEST_ENROLLMENT_CLAIMS.add(enrollment.admission_binding_digest);
  return createRoot(
    "test_physical_technique_composition_root",
    enrollment,
    { test_execute: value.execute },
    TEST_ROOTS,
  );
}

function claimExecution(state, request) {
  if (state.phase !== "ready") {
    throw compositionError(
      "physical_technique_composition_replay",
      `physical technique composition root is ${state.phase}`,
    );
  }
  assertExactIdentity(request, state.identity, "composition execution request");
  // Claim before the first callback/Promise turn. Any rejected or malformed
  // outcome stays failed-closed and cannot be retried under the same grant.
  state.phase = "executing";
}

async function executeProductionPhysicalTechniqueCompositionRoot(rootInput, requestInput) {
  const { state } = validateRoot(
    rootInput,
    PRODUCTION_ROOTS,
    "production_physical_technique_composition_root",
    "production physical technique composition root",
  );
  const request = normalizeExecutionRequest(requestInput);
  claimExecution(state, request);
  try {
    revalidateProductionState(state);
    // Do not fall back to the legacy provider-dispatch callback registry after
    // authenticating a worker/vault transaction. Calling that path would leave
    // the validated transaction unused and let production bypass the only
    // topology intended to own worker isolation, response custody, durable
    // terminal commit, and restoration. Calling both paths is also forbidden:
    // it could duplicate a physical effect. A later concrete owner must consume
    // both admissions as one durable transaction and return real evidence
    // handles before this gate can be removed.
    throw compositionError(
      "physical_technique_production_execution_spine_unavailable",
      "no private owner atomically binds dispatch admission to worker-vault execution",
      null,
      PRODUCTION_EXECUTION_SPINE_BLOCKERS,
    );
  } catch (cause) {
    state.phase = "failed_closed";
    if (cause && typeof cause.code === "string"
        && cause.code.startsWith("physical_technique_")) throw cause;
    throw compositionError(
      "physical_technique_composition_execution_failed",
      "production physical technique composition failed closed",
      cause,
    );
  }
}

async function executeTestPhysicalTechniqueCompositionRoot(rootInput, requestInput) {
  const { state } = validateRoot(
    rootInput,
    TEST_ROOTS,
    "test_physical_technique_composition_root",
    "test physical technique composition root",
  );
  const request = normalizeExecutionRequest(requestInput);
  claimExecution(state, request);
  try {
    const raw = reflectApply(state.test_execute, undefined, [request]);
    const settled = utilTypes.isPromise(raw) ? await raw : raw;
    const outcome = normalizeTestOutcome(settled, state);
    const result = buildRuntimeResult(state.enrollment, outcome);
    state.phase = "completed";
    return result;
  } catch (cause) {
    state.phase = "failed_closed";
    if (cause && typeof cause.code === "string"
        && cause.code.startsWith("physical_technique_")) throw cause;
    throw compositionError(
      "physical_technique_composition_execution_failed",
      "test physical technique composition failed closed",
      cause,
    );
  }
}

module.exports = objectFreeze({
  PHYSICAL_TECHNIQUE_COMPOSITION_ROOT_VERSION,
  assertProductionPhysicalTechniqueCompositionRoot,
  assertTestPhysicalTechniqueCompositionRoot,
  createProductionPhysicalTechniqueCompositionRoot,
  createTestPhysicalTechniqueCompositionRoot,
  describeProductionPhysicalTechniqueCompositionRoot,
  describeTestPhysicalTechniqueCompositionRoot,
  executeProductionPhysicalTechniqueCompositionRoot,
  executeTestPhysicalTechniqueCompositionRoot,
});
