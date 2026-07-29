"use strict";

const { normalizeOpaqueRef } = require("./physical-quantities.js");
const {
  normalizeRequestedEffects,
} = require("./requested-effects.js");
const { hashCanonicalJson } = require("./verification-contracts.js");

const PROVIDER_ABI_VERSION = 3;
const SUPPORTED_PROVIDER_ABI_VERSIONS = Object.freeze([2, 3]);
const PROVIDER_BOOTSTRAP_ABI_VERSION = 3;
const PROVIDER_BOOTSTRAP_CALL_VERSION = 1;
const NORMALIZED_OPERATION_VERSION = 1;
const PROVIDER_DESCRIPTOR_VERSION = 1;
const PROVIDER_CAPABILITIES_VERSION = 1;
const PROVIDER_CALL_VERSION = 1;
const PUBLIC_RESULT_VERSION = 1;
const MAX_PUBLIC_RESULT_GRAPH_NODES = 4_096;
const MAX_PUBLIC_RESULT_GRAPH_DEPTH = 64;

const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const SEMVER_PATTERN = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const OPERATION_REGISTRIES = new WeakSet();
const PROVIDER_CAPABILITIES = new WeakSet();
const PROVIDER_DESCRIPTORS = new WeakSet();

const PARAMETER_KINDS = Object.freeze([
  "boolean",
  "digest",
  "enum",
  "identifier",
  "integer",
  "number",
  "reference",
  "timestamp",
]);
const IDEMPOTENCY_VALUES = Object.freeze([
  "read_only_idempotent",
  "attempt_idempotent",
  "non_idempotent",
]);
const RETRY_POLICY_VALUES = Object.freeze([
  "never",
  "new_attempt_after_confirmed_no_effect",
]);
const STOP_SEMANTICS_VALUES = Object.freeze([
  "not_applicable",
  "cooperative",
  "bounded",
]);
const RESTORE_POLICY_VALUES = Object.freeze([
  "not_required",
  "best_effort",
  "required",
  "irreversible_authorized",
]);
const ATTEMPT_STATE_VALUES = Object.freeze([
  "created",
  "prepared",
  "dispatched",
  "acknowledged",
  "refused",
  "stop_requested",
  "stopped",
  "ambiguous_effect",
  "reconciled_no_effect",
  "restored",
  "quarantined",
  "irreversible_authorized",
  "unknown_effect",
]);
const EFFECT_DISPOSITION_VALUES = Object.freeze([
  "not_dispatched",
  "confirmed_no_effect",
  "confirmed_effect",
  "ambiguous",
  "unknown",
]);
const PUBLIC_OUTCOME_VALUES = Object.freeze([
  "succeeded",
  "refused",
  "failed",
  "stopped",
  "inconclusive",
]);
const PROVIDER_HEALTH_VALUES = Object.freeze([
  "healthy",
  "degraded",
  "unavailable",
]);
const PROVIDER_BOOTSTRAP_OPERATION_IDS = Object.freeze([
  "instrument.inventory",
  "instrument.capabilities",
  "instrument.health",
]);
const PROVIDER_BOOTSTRAP_OUTCOME_VALUES = Object.freeze([
  "succeeded",
  "refused_no_effect",
  "ambiguous",
]);
// Bootstrap is deliberately independent of active execution. These fields are
// called out separately from the closed schemas so a caller gets an explicit
// refusal instead of being able to suggest that a bootstrap observation was
// backed by a fabricated lease, fence, resource reservation, or snapshot.
const PROVIDER_BOOTSTRAP_ACTIVE_PLANE_FORBIDDEN_FIELDS = Object.freeze([
  "capability_id",
  "cleanup_plan_digest",
  "dispatch_journal_ref",
  "effect_disposition",
  "expected_sequence",
  "expected_state",
  "expected_workspace_state_digest",
  "fencing_generation",
  "fencing_token",
  "journal_entry_ref",
  "lease_digest",
  "lease_id",
  "lease_ref",
  "parameters",
  "preparation_plan_digest",
  "prepare_request",
  "provider_request_digest",
  "requested_effects",
  "resource_bundle_digest",
  "resource_reservation_digest",
  "resource_reservation_ref",
  "restore_plan_digest",
  "snapshot_artifact_ref",
  "snapshot_plan_digest",
  "state",
  "stop_contract_digest",
  "workspace_snapshot_digest",
  "workspace_snapshot_ref",
  "workspace_state_digest",
]);
const PROVIDER_BOOTSTRAP_INTENT_FIELDS = Object.freeze([
  "version",
  "call_kind",
  "attempt_ref",
  "session_nucleus_hash",
  "physical_scope_axis_digest",
  "execution_principal_id",
  "instrument_ref",
  "enrollment_candidate_ref",
  "provider_id",
  "provider_descriptor_digest",
  "provider_binary_digest",
  "transport_digest",
  "bootstrap_manifest_digest",
  "bootstrap_invariants_digest",
  "operation_id",
  "operation_digest",
  "execution_request_digest",
  "authority_resolution_digest",
  "signed_grant_digest",
  "replay_claim_digest",
  "replay_reservation_receipt_digest",
  "connection_ref",
  "connection_generation",
  "grant_not_before",
  "grant_expires_at",
]);
const PROVIDER_BOOTSTRAP_REQUEST_FIELDS = Object.freeze([
  ...PROVIDER_BOOTSTRAP_INTENT_FIELDS,
  "bootstrap_intent_digest",
  "dispatch_record_digest",
  "dispatch_credential",
]);
const PROVIDER_BOOTSTRAP_REPORT_FIELDS = Object.freeze([
  "version",
  "attempt_ref",
  "operation_id",
  "bootstrap_intent_digest",
  "bootstrap_request_digest",
  "signed_grant_digest",
  "replay_reservation_receipt_digest",
  "dispatch_record_digest",
  "dispatch_redemption_digest",
  "connection_generation",
  "outcome",
  "observation_ref",
  "observation_digest",
  "receipt_ref",
  "receipt_digest",
  "response_digest",
  "observed_at",
  "assurance_claims_digest",
  "invariant_witness_digest",
]);
const PROVIDER_METHODS = Object.freeze([
  "describe",
  "inventory",
  "capabilities",
  "prepare",
  "snapshot",
  "execute",
  "status",
  "stop",
  "reconcile",
  "restore",
  "health",
]);

const ATTEMPT_TRANSITIONS = Object.freeze({
  created: Object.freeze(["prepared", "refused"]),
  prepared: Object.freeze(["dispatched", "refused", "stop_requested"]),
  dispatched: Object.freeze(["acknowledged", "ambiguous_effect", "unknown_effect", "stop_requested"]),
  acknowledged: Object.freeze(["restored", "quarantined", "irreversible_authorized"]),
  refused: Object.freeze([]),
  stop_requested: Object.freeze(["stopped", "ambiguous_effect", "unknown_effect", "quarantined"]),
  stopped: Object.freeze(["restored", "quarantined"]),
  ambiguous_effect: Object.freeze([
    "acknowledged",
    "reconciled_no_effect",
    "quarantined",
    "unknown_effect",
  ]),
  reconciled_no_effect: Object.freeze([]),
  restored: Object.freeze([]),
  quarantined: Object.freeze([]),
  irreversible_authorized: Object.freeze([]),
  unknown_effect: Object.freeze([]),
});

const TERMINAL_ATTEMPT_STATES = Object.freeze([
  "refused",
  "reconciled_no_effect",
  "restored",
  "quarantined",
  "irreversible_authorized",
  "unknown_effect",
]);
const PROVIDER_BOOTSTRAP_REQUESTS = new WeakSet();

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, requiredFields, optionalFields = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...requiredFields, ...optionalFields]);
  const unknown = keys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = requiredFields.filter((field) => !keys.includes(field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const field of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || !descriptor.enumerable) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
  }
  return value;
}

function assertNoBootstrapActivePlaneFields(value, label) {
  if (!isPlainObject(value)) return value;
  const fields = new Set(Reflect.ownKeys(value).filter((field) => typeof field === "string"));
  const forbidden = PROVIDER_BOOTSTRAP_ACTIVE_PLANE_FORBIDDEN_FIELDS
    .filter((field) => fields.has(field));
  if (forbidden.length > 0) {
    throw new Error(
      `${label} cannot contain active-plane fields: ${forbidden.join(", ")}`,
    );
  }
  return value;
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertHash(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertInteger(value, label, { min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${label} must be a safe integer between ${min} and ${max}`);
  }
  return value;
}

function assertFiniteNumber(value, label, { min = -Number.MAX_VALUE, max = Number.MAX_VALUE } = {}) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max) {
    throw new Error(`${label} must be a finite number between ${min} and ${max}`);
  }
  return value;
}

function assertCanonicalTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be an ISO-8601 timestamp`);
  }
  if (new Date(value).toISOString() !== value) {
    throw new Error(`${label} must use canonical UTC ISO-8601 form`);
  }
  return value;
}

function normalizeIdentifierArray(value, label, { min = 0, max = 128 } = {}) {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    throw new Error(`${label} must be an array with ${min}-${max} entries`);
  }
  const normalized = value.map((entry, index) => assertIdentifier(entry, `${label}[${index}]`));
  const sorted = [...new Set(normalized)].sort();
  if (sorted.length !== normalized.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze(sorted);
}

function normalizeParameterContract(input, label) {
  assertClosedObject(input, label, ["kind", "required"], ["values", "ref_prefix", "min", "max"]);
  const kind = assertEnum(input.kind, PARAMETER_KINDS, `${label}.kind`);
  if (typeof input.required !== "boolean") throw new Error(`${label}.required must be a boolean`);
  const normalized = { kind, required: input.required };
  if (kind === "enum") {
    const invalid = Object.keys(input).filter((field) => !["kind", "required", "values"].includes(field));
    if (invalid.length > 0) throw new Error(`${label} has fields invalid for enum: ${invalid.sort().join(", ")}`);
    normalized.values = normalizeIdentifierArray(input.values, `${label}.values`, { min: 1, max: 128 });
  } else if (kind === "reference") {
    const invalid = Object.keys(input).filter((field) => !["kind", "required", "ref_prefix"].includes(field));
    if (invalid.length > 0) throw new Error(`${label} has fields invalid for reference: ${invalid.sort().join(", ")}`);
    if (input.ref_prefix != null) normalized.ref_prefix = assertIdentifier(input.ref_prefix, `${label}.ref_prefix`);
  } else if (kind === "integer" || kind === "number") {
    const invalid = Object.keys(input).filter((field) => !["kind", "required", "min", "max"].includes(field));
    if (invalid.length > 0) throw new Error(`${label} has fields invalid for ${kind}: ${invalid.sort().join(", ")}`);
    if (input.min != null) {
      normalized.min = kind === "integer"
        ? assertInteger(input.min, `${label}.min`)
        : assertFiniteNumber(input.min, `${label}.min`);
    }
    if (input.max != null) {
      normalized.max = kind === "integer"
        ? assertInteger(input.max, `${label}.max`)
        : assertFiniteNumber(input.max, `${label}.max`);
    }
    if (normalized.min != null && normalized.max != null && normalized.min > normalized.max) {
      throw new Error(`${label}.min must be <= ${label}.max`);
    }
  } else {
    const invalid = Object.keys(input).filter((field) => !["kind", "required"].includes(field));
    if (invalid.length > 0) throw new Error(`${label} has fields invalid for ${kind}: ${invalid.sort().join(", ")}`);
  }
  return deepFreeze(normalized);
}

function normalizeParameterValue(value, contract, label) {
  if (contract.kind === "boolean") {
    if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
    return value;
  }
  if (contract.kind === "digest") return assertHash(value, label);
  if (contract.kind === "enum") return assertEnum(value, contract.values, label);
  if (contract.kind === "identifier") return assertIdentifier(value, label);
  if (contract.kind === "integer") {
    return assertInteger(value, label, { min: contract.min, max: contract.max });
  }
  if (contract.kind === "number") {
    return assertFiniteNumber(value, label, { min: contract.min, max: contract.max });
  }
  if (contract.kind === "reference") {
    return normalizeOpaqueRef(value, label, { prefix: contract.ref_prefix || null });
  }
  if (contract.kind === "timestamp") return assertCanonicalTimestamp(value, label);
  throw new Error(`${label} uses an unsupported parameter kind`);
}

function normalizeOperationParameters(input, operation, label = "parameters") {
  if (!isPlainObject(input)) throw new Error(`${label} must be an object`);
  const unknown = Object.keys(input).filter((field) => !operation.parameters[field]).sort();
  if (unknown.length > 0) throw new Error(`${label} has undeclared fields: ${unknown.join(", ")}`);
  const missing = Object.entries(operation.parameters)
    .filter(([, contract]) => contract.required)
    .map(([field]) => field)
    .filter((field) => !Object.prototype.hasOwnProperty.call(input, field))
    .sort();
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  const normalized = {};
  for (const field of Object.keys(input).sort()) {
    normalized[field] = normalizeParameterValue(input[field], operation.parameters[field], `${label}.${field}`);
  }
  return deepFreeze(normalized);
}

function defineNormalizedOperation(input, label = "normalized_operation") {
  assertClosedObject(
    input,
    label,
    ["version", "operation_id", "semantic_version", "parameters", "public_summary_codes"],
  );
  if (input.version !== NORMALIZED_OPERATION_VERSION) {
    throw new Error(`${label}.version must be ${NORMALIZED_OPERATION_VERSION}`);
  }
  const operationId = assertIdentifier(input.operation_id, `${label}.operation_id`);
  const semanticVersion = assertInteger(input.semantic_version, `${label}.semantic_version`, { min: 1, max: 65535 });
  if (!isPlainObject(input.parameters)) throw new Error(`${label}.parameters must be an object`);
  const parameters = {};
  for (const field of Object.keys(input.parameters).sort()) {
    assertIdentifier(field, `${label}.parameters field`);
    parameters[field] = normalizeParameterContract(input.parameters[field], `${label}.parameters.${field}`);
  }
  const contract = {
    version: NORMALIZED_OPERATION_VERSION,
    operation_id: operationId,
    semantic_version: semanticVersion,
    parameters: deepFreeze(parameters),
    public_summary_codes: normalizeIdentifierArray(
      input.public_summary_codes,
      `${label}.public_summary_codes`,
      { min: 1, max: 128 },
    ),
  };
  return deepFreeze({ ...contract, operation_digest: hashCanonicalJson(contract) });
}

function buildNormalizedOperationRegistry(definitions) {
  if (!Array.isArray(definitions) || definitions.length === 0 || definitions.length > 1024) {
    throw new Error("normalized operation definitions must contain 1-1024 entries");
  }
  const operations = new Map();
  for (let index = 0; index < definitions.length; index += 1) {
    const operation = defineNormalizedOperation(definitions[index], `normalized_operations[${index}]`);
    if (operations.has(operation.operation_id)) {
      throw new Error(`duplicate normalized operation ID ${operation.operation_id}`);
    }
    operations.set(operation.operation_id, operation);
  }
  const ordered = [...operations.values()].sort((left, right) => left.operation_id.localeCompare(right.operation_id));
  const ids = Object.freeze(ordered.map((operation) => operation.operation_id));
  const registry = Object.freeze({
    version: NORMALIZED_OPERATION_VERSION,
    registry_digest: hashCanonicalJson({ version: NORMALIZED_OPERATION_VERSION, operations: ordered }),
    get(operationId) {
      return operations.get(operationId) || null;
    },
    has(operationId) {
      return operations.has(operationId);
    },
    ids() {
      return ids;
    },
  });
  OPERATION_REGISTRIES.add(registry);
  return registry;
}

function assertOperationRegistry(registry) {
  if (!registry || !OPERATION_REGISTRIES.has(registry)) {
    throw new Error("operation registry must be a closed Bob normalized-operation registry");
  }
  return registry;
}

function assertEffectRegistry(registry) {
  // The requested-effects module deliberately keeps its brand private. An
  // empty normalization is the public, non-widening way to prove provenance.
  normalizeRequestedEffects([], registry, "effect_registry_probe");
  return registry;
}

function normalizeWorstCaseEffect(input, effectRegistry, label) {
  assertClosedObject(
    input,
    label,
    ["template_id", "template_digest", "subject_kind", "action", "channel", "persistence"],
  );
  const template = effectRegistry.get(input.template_id);
  if (!template) throw new Error(`${label}.template_id is not registered: ${input.template_id}`);
  for (const field of ["template_digest", "subject_kind", "action", "channel", "persistence"]) {
    if (input[field] !== template[field]) {
      throw new Error(`${label}.${field} does not match the registered effect template`);
    }
  }
  return deepFreeze({
    template_id: template.template_id,
    template_digest: template.template_digest,
    subject_kind: template.subject_kind,
    action: template.action,
    channel: template.channel,
    persistence: template.persistence,
  });
}

function normalizeProviderCapability(input, operationRegistry, effectRegistry, label = "capability") {
  assertClosedObject(
    input,
    label,
    [
      "capability_id",
      "operation_id",
      "operation_digest",
      "worst_case_effects",
      "idempotency",
      "retry_policy",
      "stop_semantics",
      "restore_policy",
    ],
  );
  const capabilityId = assertIdentifier(input.capability_id, `${label}.capability_id`);
  const operationId = assertIdentifier(input.operation_id, `${label}.operation_id`);
  const operation = operationRegistry.get(operationId);
  if (!operation) throw new Error(`${label}.operation_id is not registered: ${operationId}`);
  if (input.operation_digest !== operation.operation_digest) {
    throw new Error(`${label}.operation_digest does not match the normalized operation`);
  }
  if (!Array.isArray(input.worst_case_effects) || input.worst_case_effects.length > 64) {
    throw new Error(`${label}.worst_case_effects must be an array with at most 64 entries`);
  }
  const worstCaseEffects = input.worst_case_effects.map((effect, index) => (
    normalizeWorstCaseEffect(effect, effectRegistry, `${label}.worst_case_effects[${index}]`)
  ));
  const effectIds = worstCaseEffects.map((effect) => effect.template_id);
  if (new Set(effectIds).size !== effectIds.length) {
    throw new Error(`${label}.worst_case_effects must not contain duplicate templates`);
  }
  worstCaseEffects.sort((left, right) => left.template_id.localeCompare(right.template_id));
  const idempotency = assertEnum(input.idempotency, IDEMPOTENCY_VALUES, `${label}.idempotency`);
  const retryPolicy = assertEnum(input.retry_policy, RETRY_POLICY_VALUES, `${label}.retry_policy`);
  const stopSemantics = assertEnum(input.stop_semantics, STOP_SEMANTICS_VALUES, `${label}.stop_semantics`);
  const restorePolicy = assertEnum(input.restore_policy, RESTORE_POLICY_VALUES, `${label}.restore_policy`);

  const readOnly = worstCaseEffects.every((effect) => effect.action === "observe" && effect.persistence === "none");
  const irreversible = worstCaseEffects.some((effect) => effect.persistence === "irreversible" || effect.action === "destroy");
  const persistent = worstCaseEffects.some((effect) => effect.persistence === "persistent");
  if (!readOnly && idempotency === "read_only_idempotent") {
    throw new Error(`${label} cannot declare effectful work read_only_idempotent`);
  }
  if (retryPolicy === "new_attempt_after_confirmed_no_effect"
      && (!readOnly || idempotency !== "read_only_idempotent")) {
    throw new Error(`${label} permits automatic retry only for read-only idempotent work`);
  }
  if (!readOnly && retryPolicy !== "never") {
    throw new Error(`${label} effectful work must use retry_policy never`);
  }
  if (irreversible && restorePolicy !== "irreversible_authorized") {
    throw new Error(`${label} irreversible effects require restore_policy irreversible_authorized`);
  }
  if (!irreversible && persistent && restorePolicy !== "required") {
    throw new Error(`${label} persistent effects require restore_policy required`);
  }
  if (restorePolicy === "irreversible_authorized" && !irreversible) {
    throw new Error(`${label} restore_policy irreversible_authorized requires an irreversible worst-case effect`);
  }
  const normalized = {
    capability_id: capabilityId,
    operation_id: operationId,
    operation_digest: operation.operation_digest,
    worst_case_effects: Object.freeze(worstCaseEffects),
    idempotency,
    retry_policy: retryPolicy,
    stop_semantics: stopSemantics,
    restore_policy: restorePolicy,
  };
  const capability = deepFreeze(normalized);
  PROVIDER_CAPABILITIES.add(capability);
  return capability;
}

function defineProviderDescriptor(input, operationRegistry, effectRegistry, label = "provider_descriptor") {
  assertOperationRegistry(operationRegistry);
  assertEffectRegistry(effectRegistry);
  assertClosedObject(
    input,
    label,
    [
      "version",
      "abi_version",
      "provider_id",
      "provider_version",
      "implementation_digest",
      "operation_registry_digest",
      "capabilities",
    ],
  );
  if (input.version !== PROVIDER_DESCRIPTOR_VERSION) {
    throw new Error(`${label}.version must be ${PROVIDER_DESCRIPTOR_VERSION}`);
  }
  const abiVersion = assertEnum(
    input.abi_version,
    SUPPORTED_PROVIDER_ABI_VERSIONS,
    `${label}.abi_version`,
  );
  const providerId = assertIdentifier(input.provider_id, `${label}.provider_id`);
  if (typeof input.provider_version !== "string" || !SEMVER_PATTERN.test(input.provider_version)) {
    throw new Error(`${label}.provider_version must be semantic version text`);
  }
  const implementationDigest = assertHash(input.implementation_digest, `${label}.implementation_digest`);
  if (input.operation_registry_digest !== operationRegistry.registry_digest) {
    throw new Error(`${label}.operation_registry_digest does not match the operation registry`);
  }
  if (!Array.isArray(input.capabilities) || input.capabilities.length === 0 || input.capabilities.length > 1024) {
    throw new Error(`${label}.capabilities must contain 1-1024 entries`);
  }
  const capabilities = input.capabilities.map((capability, index) => normalizeProviderCapability(
    capability,
    operationRegistry,
    effectRegistry,
    `${label}.capabilities[${index}]`,
  ));
  const capabilityIds = capabilities.map((capability) => capability.capability_id);
  if (new Set(capabilityIds).size !== capabilityIds.length) {
    throw new Error(`${label}.capabilities must have unique capability_id values`);
  }
  capabilities.sort((left, right) => left.capability_id.localeCompare(right.capability_id));
  const capabilitiesDigest = hashCanonicalJson(capabilities);
  const descriptor = {
    version: PROVIDER_DESCRIPTOR_VERSION,
    abi_version: abiVersion,
    provider_id: providerId,
    provider_version: input.provider_version,
    implementation_digest: implementationDigest,
    operation_registry_digest: operationRegistry.registry_digest,
    capabilities_digest: capabilitiesDigest,
    capabilities: Object.freeze(capabilities),
  };
  const normalized = {
    ...descriptor,
    descriptor_digest: hashCanonicalJson(descriptor),
  };
  const providerDescriptor = deepFreeze(normalized);
  PROVIDER_DESCRIPTORS.add(providerDescriptor);
  return providerDescriptor;
}

function normalizeProviderDescriptor(input, operationRegistry, effectRegistry, label = "provider_descriptor") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "abi_version",
      "provider_id",
      "provider_version",
      "implementation_digest",
      "operation_registry_digest",
      "capabilities_digest",
      "capabilities",
      "descriptor_digest",
    ],
  );
  const descriptor = defineProviderDescriptor({
    version: input.version,
    abi_version: input.abi_version,
    provider_id: input.provider_id,
    provider_version: input.provider_version,
    implementation_digest: input.implementation_digest,
    operation_registry_digest: input.operation_registry_digest,
    capabilities: input.capabilities,
  }, operationRegistry, effectRegistry, label);
  if (input.capabilities_digest !== descriptor.capabilities_digest) {
    throw new Error(`${label}.capabilities_digest does not match the declared capabilities`);
  }
  if (input.descriptor_digest !== descriptor.descriptor_digest) {
    throw new Error(`${label}.descriptor_digest does not match the descriptor`);
  }
  return descriptor;
}

function assertNormalizedProviderDescriptor(descriptor) {
  if (!descriptor || !PROVIDER_DESCRIPTORS.has(descriptor)) {
    throw new Error("provider descriptor must be normalized before compatibility checks");
  }
  return descriptor;
}

function assertProviderActiveAbiCompatible(descriptor) {
  assertNormalizedProviderDescriptor(descriptor);
  if (!SUPPORTED_PROVIDER_ABI_VERSIONS.includes(descriptor.abi_version)) {
    throw new Error(
      `provider ABI ${descriptor.abi_version} is incompatible with the active provider ABI`,
    );
  }
  return true;
}

function assertProviderBootstrapAbiCompatible(descriptor) {
  assertNormalizedProviderDescriptor(descriptor);
  if (descriptor.abi_version !== PROVIDER_BOOTSTRAP_ABI_VERSION) {
    throw new Error(
      `bootstrap provider calls require provider ABI ${PROVIDER_BOOTSTRAP_ABI_VERSION}; `
        + `received ABI ${descriptor.abi_version}`,
    );
  }
  return true;
}

function assertProviderAbiCompatible(descriptor, supportedAbiVersion = null) {
  if (supportedAbiVersion == null) return assertProviderActiveAbiCompatible(descriptor);
  assertNormalizedProviderDescriptor(descriptor);
  assertInteger(supportedAbiVersion, "supported_abi_version", { min: 1, max: 65535 });
  if (descriptor.abi_version !== supportedAbiVersion) {
    throw new Error(`provider ABI ${descriptor.abi_version} is incompatible with supported ABI ${supportedAbiVersion}`);
  }
  return true;
}

function normalizeCapabilitiesResponse(input, descriptor, label = "provider_capabilities") {
  assertClosedObject(
    input,
    label,
    ["version", "provider_id", "descriptor_digest", "capabilities_digest", "capabilities"],
  );
  if (!descriptor || !PROVIDER_DESCRIPTORS.has(descriptor)) {
    throw new Error("provider descriptor must be normalized before capabilities");
  }
  if (input.version !== PROVIDER_CAPABILITIES_VERSION) {
    throw new Error(`${label}.version must be ${PROVIDER_CAPABILITIES_VERSION}`);
  }
  if (input.provider_id !== descriptor.provider_id) throw new Error(`${label}.provider_id drifted`);
  if (input.descriptor_digest !== descriptor.descriptor_digest) throw new Error(`${label}.descriptor_digest drifted`);
  if (input.capabilities_digest !== descriptor.capabilities_digest) throw new Error(`${label}.capabilities_digest drifted`);
  if (hashCanonicalJson(input.capabilities) !== descriptor.capabilities_digest) {
    throw new Error(`${label}.capabilities do not match the descriptor`);
  }
  return deepFreeze({
    version: PROVIDER_CAPABILITIES_VERSION,
    provider_id: descriptor.provider_id,
    descriptor_digest: descriptor.descriptor_digest,
    capabilities_digest: descriptor.capabilities_digest,
    capabilities: descriptor.capabilities,
  });
}

function normalizeInventoryResponse(input, descriptor, label = "provider_inventory") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "provider_id",
      "instrument_ref",
      "inventory_ref",
      "descriptor_digest",
      "capabilities_digest",
      "assurance_claims_digest",
      "observed_at",
      "receipt_ref",
    ],
  );
  if (input.version !== PROVIDER_CALL_VERSION) throw new Error(`${label}.version must be ${PROVIDER_CALL_VERSION}`);
  if (input.provider_id !== descriptor.provider_id) throw new Error(`${label}.provider_id drifted`);
  if (input.descriptor_digest !== descriptor.descriptor_digest) throw new Error(`${label}.descriptor_digest drifted`);
  if (input.capabilities_digest !== descriptor.capabilities_digest) throw new Error(`${label}.capabilities_digest drifted`);
  return deepFreeze({
    version: PROVIDER_CALL_VERSION,
    provider_id: descriptor.provider_id,
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, { prefix: "instrument" }),
    inventory_ref: normalizeOpaqueRef(input.inventory_ref, `${label}.inventory_ref`, { prefix: "inventory" }),
    descriptor_digest: descriptor.descriptor_digest,
    capabilities_digest: descriptor.capabilities_digest,
    assurance_claims_digest: assertHash(input.assurance_claims_digest, `${label}.assurance_claims_digest`),
    observed_at: assertCanonicalTimestamp(input.observed_at, `${label}.observed_at`),
    receipt_ref: normalizeOpaqueRef(input.receipt_ref, `${label}.receipt_ref`, { prefix: "receipt" }),
  });
}

function findCapability(descriptor, capabilityId, operationId, label) {
  const capability = descriptor.capabilities.find((entry) => entry.capability_id === capabilityId) || null;
  if (!capability) throw new Error(`${label}.capability_id is not declared by the provider`);
  if (capability.operation_id !== operationId) {
    throw new Error(`${label}.operation_id does not match the selected capability`);
  }
  return capability;
}

function normalizePrepareRequest(input, context, label = "prepare_request") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "attempt_ref",
      "instrument_ref",
      "capability_id",
      "operation_id",
      "operation_digest",
      "parameters",
      "requested_effects",
      "execution_deadline",
      "journal_entry_ref",
    ],
  );
  assertClosedObject(context, "prepare_context", ["descriptor", "operation_registry", "effect_registry"]);
  const { descriptor, operation_registry: operationRegistry, effect_registry: effectRegistry } = context;
  assertOperationRegistry(operationRegistry);
  assertEffectRegistry(effectRegistry);
  if (!descriptor || !PROVIDER_DESCRIPTORS.has(descriptor)) {
    throw new Error("prepare_context.descriptor must be normalized");
  }
  if (input.version !== PROVIDER_CALL_VERSION) throw new Error(`${label}.version must be ${PROVIDER_CALL_VERSION}`);
  const operationId = assertIdentifier(input.operation_id, `${label}.operation_id`);
  const operation = operationRegistry.get(operationId);
  if (!operation) throw new Error(`${label}.operation_id is not registered`);
  if (input.operation_digest !== operation.operation_digest) {
    throw new Error(`${label}.operation_digest does not match the operation registry`);
  }
  const capability = findCapability(descriptor, input.capability_id, operationId, label);
  const requestedEffects = normalizeRequestedEffects(input.requested_effects, effectRegistry, `${label}.requested_effects`);
  const allowedEffects = new Map(capability.worst_case_effects.map((effect) => [effect.template_id, effect.template_digest]));
  for (const effect of requestedEffects) {
    if (allowedEffects.get(effect.template_id) !== effect.template_digest) {
      throw new Error(`${label}.requested_effects exceeds the capability worst-case declaration`);
    }
  }
  if (capability.worst_case_effects.length > 0 && requestedEffects.length === 0) {
    throw new Error(`${label}.requested_effects cannot omit every declared effect`);
  }
  if (capability.worst_case_effects.length === 0 && requestedEffects.length > 0) {
    throw new Error(`${label}.requested_effects is not allowed for an effect-free capability`);
  }
  const request = {
    version: PROVIDER_CALL_VERSION,
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, { prefix: "instrument" }),
    capability_id: capability.capability_id,
    operation_id: operation.operation_id,
    operation_digest: operation.operation_digest,
    parameters: normalizeOperationParameters(input.parameters, operation, `${label}.parameters`),
    requested_effects: requestedEffects,
    execution_deadline: assertCanonicalTimestamp(input.execution_deadline, `${label}.execution_deadline`),
    journal_entry_ref: normalizeOpaqueRef(
      input.journal_entry_ref,
      `${label}.journal_entry_ref`,
      { prefix: "journal-entry" },
    ),
  };
  return deepFreeze({ ...request, request_digest: hashCanonicalJson(request) });
}

function normalizeAttemptCall(input, label, requiredExtraFields, normalizeExtra) {
  assertClosedObject(
    input,
    label,
    ["version", "attempt_ref", "operation_id", "request_digest", ...requiredExtraFields],
  );
  if (input.version !== PROVIDER_CALL_VERSION) throw new Error(`${label}.version must be ${PROVIDER_CALL_VERSION}`);
  const normalized = {
    version: PROVIDER_CALL_VERSION,
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    operation_id: assertIdentifier(input.operation_id, `${label}.operation_id`),
    request_digest: assertHash(input.request_digest, `${label}.request_digest`),
  };
  normalizeExtra(normalized, input, label);
  return deepFreeze(normalized);
}

function normalizeExecuteRequest(input, label = "execute_request") {
  return normalizeAttemptCall(
    input,
    label,
    ["expected_state", "expected_sequence", "dispatch_journal_ref", "dispatch_credential"],
    (normalized, raw) => {
    if (raw.expected_state !== "prepared") throw new Error(`${label}.expected_state must be prepared`);
    normalized.expected_state = "prepared";
    normalized.expected_sequence = assertInteger(
      raw.expected_sequence,
      `${label}.expected_sequence`,
      { min: 0 },
    );
    normalized.dispatch_journal_ref = normalizeOpaqueRef(
      raw.dispatch_journal_ref,
      `${label}.dispatch_journal_ref`,
      { prefix: "journal-entry" },
    );
    if (!isPlainObject(raw.dispatch_credential) || !Object.isFrozen(raw.dispatch_credential)) {
      throw new Error(`${label}.dispatch_credential must be a frozen opaque credential object`);
    }
    // Provenance and every durable binding are checked by the store-enrolled
    // provider redemption port at the effect seam. Preserve exact identity;
    // cloning or structurally trusting the projection here would destroy that
    // private-brand boundary.
    normalized.dispatch_credential = raw.dispatch_credential;
    },
  );
}

function normalizeSnapshotRequest(input, label = "snapshot_request") {
  return normalizeAttemptCall(
    input,
    label,
    ["instrument_ref", "expected_state", "expected_sequence", "snapshot_plan_digest"],
    (normalized, raw) => {
      normalized.instrument_ref = normalizeOpaqueRef(
        raw.instrument_ref,
        `${label}.instrument_ref`,
        { prefix: "instrument" },
      );
      if (raw.expected_state !== "prepared") throw new Error(`${label}.expected_state must be prepared`);
      normalized.expected_state = "prepared";
      normalized.expected_sequence = assertInteger(raw.expected_sequence, `${label}.expected_sequence`, { min: 0 });
      normalized.snapshot_plan_digest = assertHash(raw.snapshot_plan_digest, `${label}.snapshot_plan_digest`);
    },
  );
}

function normalizeSnapshotResponse(input, snapshotRequest, label = "snapshot_response") {
  assertNoPublicByteMaterial(input, label);
  assertClosedObject(
    input,
    label,
    [
      "version",
      "attempt_ref",
      "instrument_ref",
      "operation_id",
      "request_digest",
      "prepared_sequence",
      "snapshot_plan_digest",
      "snapshot_artifact_ref",
      "workspace_state_digest",
      "receipt_ref",
    ],
  );
  const request = normalizeSnapshotRequest(snapshotRequest, `${label}.request`);
  if (input.version !== PROVIDER_CALL_VERSION) throw new Error(`${label}.version must be ${PROVIDER_CALL_VERSION}`);
  for (const field of [
    "attempt_ref",
    "instrument_ref",
    "operation_id",
    "request_digest",
    "snapshot_plan_digest",
  ]) {
    if (input[field] !== request[field]) throw new Error(`${label}.${field} drifted from the snapshot request`);
  }
  if (input.prepared_sequence !== request.expected_sequence) {
    throw new Error(`${label}.prepared_sequence drifted from the snapshot request`);
  }
  return deepFreeze({
    version: PROVIDER_CALL_VERSION,
    attempt_ref: request.attempt_ref,
    instrument_ref: request.instrument_ref,
    operation_id: request.operation_id,
    request_digest: request.request_digest,
    prepared_sequence: request.expected_sequence,
    snapshot_plan_digest: request.snapshot_plan_digest,
    snapshot_artifact_ref: normalizeOpaqueRef(
      input.snapshot_artifact_ref,
      `${label}.snapshot_artifact_ref`,
      { prefix: "artifact" },
    ),
    workspace_state_digest: assertHash(input.workspace_state_digest, `${label}.workspace_state_digest`),
    receipt_ref: normalizeOpaqueRef(input.receipt_ref, `${label}.receipt_ref`, { prefix: "receipt" }),
  });
}

function normalizeStatusRequest(input, label = "status_request") {
  return normalizeAttemptCall(input, label, [], () => {});
}

function normalizeStopRequest(input, label = "stop_request") {
  return normalizeAttemptCall(input, label, ["expected_sequence", "stop_request_ref"], (normalized, raw) => {
    normalized.expected_sequence = assertInteger(raw.expected_sequence, `${label}.expected_sequence`, { min: 0 });
    normalized.stop_request_ref = normalizeOpaqueRef(
      raw.stop_request_ref,
      `${label}.stop_request_ref`,
      { prefix: "stop-request" },
    );
  });
}

function normalizeReconcileRequest(input, label = "reconcile_request") {
  return normalizeAttemptCall(input, label, ["expected_sequence", "observation_ref"], (normalized, raw) => {
    normalized.expected_sequence = assertInteger(raw.expected_sequence, `${label}.expected_sequence`, { min: 0 });
    normalized.observation_ref = normalizeOpaqueRef(
      raw.observation_ref,
      `${label}.observation_ref`,
      { prefix: "observation" },
    );
  });
}

function normalizeRestoreRequest(input, label = "restore_request") {
  return normalizeAttemptCall(
    input,
    label,
    [
      "expected_sequence",
      "snapshot_artifact_ref",
      "expected_workspace_state_digest",
      "restore_plan_digest",
    ],
    (normalized, raw) => {
      normalized.expected_sequence = assertInteger(raw.expected_sequence, `${label}.expected_sequence`, { min: 0 });
      normalized.snapshot_artifact_ref = normalizeOpaqueRef(
        raw.snapshot_artifact_ref,
        `${label}.snapshot_artifact_ref`,
        { prefix: "artifact" },
      );
      normalized.expected_workspace_state_digest = assertHash(
        raw.expected_workspace_state_digest,
        `${label}.expected_workspace_state_digest`,
      );
      normalized.restore_plan_digest = assertHash(raw.restore_plan_digest, `${label}.restore_plan_digest`);
    },
  );
}

function normalizeHealthRequest(input, label = "health_request") {
  assertClosedObject(input, label, ["version", "provider_id", "descriptor_digest"]);
  if (input.version !== PROVIDER_CALL_VERSION) throw new Error(`${label}.version must be ${PROVIDER_CALL_VERSION}`);
  return deepFreeze({
    version: PROVIDER_CALL_VERSION,
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    descriptor_digest: assertHash(input.descriptor_digest, `${label}.descriptor_digest`),
  });
}

function normalizeProviderBootstrapIntent(
  input,
  descriptor,
  label = "provider_bootstrap_intent",
) {
  // Compatibility is checked before inspecting the request. An ABI-v2
  // provider therefore cannot receive a partially parsed bootstrap call.
  assertProviderBootstrapAbiCompatible(descriptor);
  assertNoBootstrapActivePlaneFields(input, label);
  assertClosedObject(input, label, PROVIDER_BOOTSTRAP_INTENT_FIELDS);
  if (input.version !== PROVIDER_BOOTSTRAP_CALL_VERSION) {
    throw new Error(`${label}.version must be ${PROVIDER_BOOTSTRAP_CALL_VERSION}`);
  }
  if (input.call_kind !== "bootstrap") throw new Error(`${label}.call_kind must be bootstrap`);

  const providerId = assertIdentifier(input.provider_id, `${label}.provider_id`);
  if (providerId !== descriptor.provider_id) throw new Error(`${label}.provider_id drifted`);
  const providerDescriptorDigest = assertHash(
    input.provider_descriptor_digest,
    `${label}.provider_descriptor_digest`,
  );
  if (providerDescriptorDigest !== descriptor.descriptor_digest) {
    throw new Error(`${label}.provider_descriptor_digest drifted`);
  }
  const operationId = assertEnum(
    input.operation_id,
    PROVIDER_BOOTSTRAP_OPERATION_IDS,
    `${label}.operation_id`,
  );
  const declaredCapabilities = descriptor.capabilities.filter(
    (capability) => capability.operation_id === operationId,
  );
  if (declaredCapabilities.length === 0) {
    throw new Error(`${label}.operation_id is not declared by the provider`);
  }
  const operationDigest = assertHash(input.operation_digest, `${label}.operation_digest`);
  if (!declaredCapabilities.some((capability) => capability.operation_digest === operationDigest)) {
    throw new Error(`${label}.operation_digest does not match the provider declaration`);
  }
  const grantNotBefore = assertCanonicalTimestamp(
    input.grant_not_before,
    `${label}.grant_not_before`,
  );
  const grantExpiresAt = assertCanonicalTimestamp(
    input.grant_expires_at,
    `${label}.grant_expires_at`,
  );
  if (Date.parse(grantExpiresAt) <= Date.parse(grantNotBefore)) {
    throw new Error(`${label}.grant_expires_at must be after ${label}.grant_not_before`);
  }

  const basis = {
    version: PROVIDER_BOOTSTRAP_CALL_VERSION,
    call_kind: "bootstrap",
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, {
      prefix: "bootstrap-attempt",
    }),
    session_nucleus_hash: assertHash(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    physical_scope_axis_digest: assertHash(
      input.physical_scope_axis_digest,
      `${label}.physical_scope_axis_digest`,
    ),
    execution_principal_id: normalizeOpaqueRef(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      { prefix: "principal" },
    ),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    enrollment_candidate_ref: normalizeOpaqueRef(
      input.enrollment_candidate_ref,
      `${label}.enrollment_candidate_ref`,
      { prefix: "enrollment-candidate" },
    ),
    provider_id: descriptor.provider_id,
    provider_descriptor_digest: descriptor.descriptor_digest,
    provider_binary_digest: assertHash(
      input.provider_binary_digest,
      `${label}.provider_binary_digest`,
    ),
    transport_digest: assertHash(input.transport_digest, `${label}.transport_digest`),
    bootstrap_manifest_digest: assertHash(
      input.bootstrap_manifest_digest,
      `${label}.bootstrap_manifest_digest`,
    ),
    bootstrap_invariants_digest: assertHash(
      input.bootstrap_invariants_digest,
      `${label}.bootstrap_invariants_digest`,
    ),
    operation_id: operationId,
    operation_digest: operationDigest,
    execution_request_digest: assertHash(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    authority_resolution_digest: assertHash(
      input.authority_resolution_digest,
      `${label}.authority_resolution_digest`,
    ),
    signed_grant_digest: assertHash(input.signed_grant_digest, `${label}.signed_grant_digest`),
    replay_claim_digest: assertHash(input.replay_claim_digest, `${label}.replay_claim_digest`),
    replay_reservation_receipt_digest: assertHash(
      input.replay_reservation_receipt_digest,
      `${label}.replay_reservation_receipt_digest`,
    ),
    connection_ref: normalizeOpaqueRef(
      input.connection_ref,
      `${label}.connection_ref`,
      { prefix: "instrument-connection" },
    ),
    connection_generation: assertInteger(
      input.connection_generation,
      `${label}.connection_generation`,
      { min: 1 },
    ),
    grant_not_before: grantNotBefore,
    grant_expires_at: grantExpiresAt,
  };
  return deepFreeze({
    ...basis,
    bootstrap_intent_digest: hashCanonicalJson(basis),
  });
}

function normalizeProviderBootstrapRequest(
  input,
  descriptor,
  label = "provider_bootstrap_request",
) {
  // Keep this check first for the same fail-before-invocation property as the
  // intent normalizer, including when input is malformed or accessor-backed.
  assertProviderBootstrapAbiCompatible(descriptor);
  if (input && PROVIDER_BOOTSTRAP_REQUESTS.has(input)) {
    if (input.provider_id !== descriptor.provider_id
        || input.provider_descriptor_digest !== descriptor.descriptor_digest) {
      throw new Error(`${label} is bound to a different provider descriptor`);
    }
    return input;
  }
  assertNoBootstrapActivePlaneFields(input, label);
  assertClosedObject(input, label, PROVIDER_BOOTSTRAP_REQUEST_FIELDS);
  const intentInput = {};
  for (const field of PROVIDER_BOOTSTRAP_INTENT_FIELDS) intentInput[field] = input[field];
  const intent = normalizeProviderBootstrapIntent(intentInput, descriptor, `${label}.intent`);
  const suppliedIntentDigest = assertHash(
    input.bootstrap_intent_digest,
    `${label}.bootstrap_intent_digest`,
  );
  if (suppliedIntentDigest !== intent.bootstrap_intent_digest) {
    throw new Error(`${label}.bootstrap_intent_digest does not match the normalized intent`);
  }
  const dispatchRecordDigest = assertHash(
    input.dispatch_record_digest,
    `${label}.dispatch_record_digest`,
  );
  const dispatchCredential = input.dispatch_credential;
  if (!isPlainObject(dispatchCredential) || !Object.isFrozen(dispatchCredential)) {
    throw new Error(`${label}.dispatch_credential must be a frozen opaque credential object`);
  }

  const requestBasis = {
    ...intent,
    dispatch_record_digest: dispatchRecordDigest,
  };
  const request = {
    ...requestBasis,
    bootstrap_request_digest: hashCanonicalJson(requestBasis),
  };
  // Authority is deliberately not serializable. The provider redemption port
  // receives this exact object identity; JSON, structured-clone, and object
  // spread projections lose the credential and cannot recreate a valid call.
  Object.defineProperty(request, "dispatch_credential", {
    value: dispatchCredential,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  Object.freeze(request);
  PROVIDER_BOOTSTRAP_REQUESTS.add(request);
  return request;
}

function normalizeProviderBootstrapReport(
  input,
  bootstrapRequest,
  label = "provider_bootstrap_report",
) {
  if (!bootstrapRequest || !PROVIDER_BOOTSTRAP_REQUESTS.has(bootstrapRequest)) {
    throw new Error(`${label}.request must be a normalized provider bootstrap request`);
  }
  assertNoBootstrapActivePlaneFields(input, label);
  assertNoPublicByteMaterial(input, label);
  assertClosedObject(input, label, PROVIDER_BOOTSTRAP_REPORT_FIELDS);
  if (input.version !== PROVIDER_BOOTSTRAP_CALL_VERSION) {
    throw new Error(`${label}.version must be ${PROVIDER_BOOTSTRAP_CALL_VERSION}`);
  }
  for (const field of [
    "attempt_ref",
    "operation_id",
    "bootstrap_intent_digest",
    "bootstrap_request_digest",
    "signed_grant_digest",
    "replay_reservation_receipt_digest",
    "dispatch_record_digest",
    "connection_generation",
  ]) {
    if (input[field] !== bootstrapRequest[field]) {
      throw new Error(`${label}.${field} drifted from the bootstrap request`);
    }
  }
  const outcome = assertEnum(
    input.outcome,
    PROVIDER_BOOTSTRAP_OUTCOME_VALUES,
    `${label}.outcome`,
  );
  const observedAt = assertCanonicalTimestamp(input.observed_at, `${label}.observed_at`);
  const evidenceFields = [
    "observation_ref",
    "observation_digest",
    "response_digest",
    "assurance_claims_digest",
    "invariant_witness_digest",
  ];
  if (outcome === "succeeded") {
    const missingEvidence = evidenceFields.filter((field) => input[field] == null);
    if (missingEvidence.length > 0) {
      throw new Error(`${label} succeeded without evidence fields: ${missingEvidence.join(", ")}`);
    }
    if (Date.parse(observedAt) < Date.parse(bootstrapRequest.grant_not_before)
        || Date.parse(observedAt) >= Date.parse(bootstrapRequest.grant_expires_at)) {
      throw new Error(`${label}.observed_at is outside the bootstrap grant window`);
    }
  } else {
    const fabricatedEvidence = evidenceFields.filter((field) => input[field] !== null);
    if (fabricatedEvidence.length > 0) {
      throw new Error(
        `${label} ${outcome} must not fabricate evidence fields: ${fabricatedEvidence.join(", ")}`,
      );
    }
  }

  return deepFreeze({
    version: PROVIDER_BOOTSTRAP_CALL_VERSION,
    attempt_ref: bootstrapRequest.attempt_ref,
    operation_id: bootstrapRequest.operation_id,
    bootstrap_intent_digest: bootstrapRequest.bootstrap_intent_digest,
    bootstrap_request_digest: bootstrapRequest.bootstrap_request_digest,
    signed_grant_digest: bootstrapRequest.signed_grant_digest,
    replay_reservation_receipt_digest: bootstrapRequest.replay_reservation_receipt_digest,
    dispatch_record_digest: bootstrapRequest.dispatch_record_digest,
    dispatch_redemption_digest: assertHash(
      input.dispatch_redemption_digest,
      `${label}.dispatch_redemption_digest`,
    ),
    connection_generation: bootstrapRequest.connection_generation,
    outcome,
    observation_ref: input.observation_ref == null
      ? null
      : normalizeOpaqueRef(input.observation_ref, `${label}.observation_ref`),
    observation_digest: input.observation_digest == null
      ? null
      : assertHash(input.observation_digest, `${label}.observation_digest`),
    receipt_ref: normalizeOpaqueRef(input.receipt_ref, `${label}.receipt_ref`),
    receipt_digest: assertHash(input.receipt_digest, `${label}.receipt_digest`),
    response_digest: input.response_digest == null
      ? null
      : assertHash(input.response_digest, `${label}.response_digest`),
    observed_at: observedAt,
    assurance_claims_digest: input.assurance_claims_digest == null
      ? null
      : assertHash(input.assurance_claims_digest, `${label}.assurance_claims_digest`),
    invariant_witness_digest: input.invariant_witness_digest == null
      ? null
      : assertHash(input.invariant_witness_digest, `${label}.invariant_witness_digest`),
  });
}

function assertNoPublicByteMaterial(value, label = "public_result") {
  const seen = new Set();
  const stack = [{ item: value, path: label, depth: 0 }];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    const item = current.item;
    if (item == null || typeof item !== "object") continue;
    if (seen.has(item)) throw new Error(`${current.path} must not contain repeated objects or cycles`);
    seen.add(item);
    nodes += 1;
    if (nodes > MAX_PUBLIC_RESULT_GRAPH_NODES
        || current.depth > MAX_PUBLIC_RESULT_GRAPH_DEPTH) {
      throw new Error(`${label} exceeds the bounded public result graph`);
    }
    if (Buffer.isBuffer(item)
        || item instanceof ArrayBuffer
        || ArrayBuffer.isView(item)) {
      throw new Error(`${current.path} must not contain raw byte material`);
    }
    const keys = Reflect.ownKeys(item);
    if (keys.some((field) => typeof field !== "string")) {
      throw new Error(`${current.path} cannot contain symbol fields`);
    }
    if (Array.isArray(item)) {
      const expected = new Set([
        "length",
        ...Array.from({ length: item.length }, (_, index) => String(index)),
      ]);
      if (keys.some((field) => !expected.has(field)) || keys.length !== expected.size) {
        throw new Error(`${current.path} must be a dense array without extra fields`);
      }
    }
    for (const field of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(item, field);
      const arrayLength = Array.isArray(item) && field === "length";
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
          || (!descriptor.enumerable && !arrayLength)) {
        throw new Error(`${current.path}.${field} must be an enumerable data field`);
      }
      if (!arrayLength) {
        stack.push({
          item: descriptor.value,
          path: Array.isArray(item) ? `${current.path}[${field}]` : `${current.path}.${field}`,
          depth: current.depth + 1,
        });
      }
    }
  }
  return true;
}

function normalizePublicResult(input, operation, label = "public_result") {
  assertNoPublicByteMaterial(input, label);
  assertClosedObject(
    input,
    label,
    ["version", "outcome", "summary_code", "artifact_refs", "metric_counts"],
  );
  if (input.version !== PUBLIC_RESULT_VERSION) throw new Error(`${label}.version must be ${PUBLIC_RESULT_VERSION}`);
  const outcome = assertEnum(input.outcome, PUBLIC_OUTCOME_VALUES, `${label}.outcome`);
  const summaryCode = assertIdentifier(input.summary_code, `${label}.summary_code`);
  if (!operation.public_summary_codes.includes(summaryCode)) {
    throw new Error(`${label}.summary_code is not declared by operation ${operation.operation_id}`);
  }
  if (!Array.isArray(input.artifact_refs) || input.artifact_refs.length > 64) {
    throw new Error(`${label}.artifact_refs must be an array with at most 64 entries`);
  }
  const artifactRefs = input.artifact_refs.map((ref, index) => normalizeOpaqueRef(
    ref,
    `${label}.artifact_refs[${index}]`,
    { prefix: "artifact" },
  ));
  const sortedArtifactRefs = [...new Set(artifactRefs)].sort();
  if (sortedArtifactRefs.length !== artifactRefs.length) {
    throw new Error(`${label}.artifact_refs must not contain duplicates`);
  }
  if (!isPlainObject(input.metric_counts) || Object.keys(input.metric_counts).length > 128) {
    throw new Error(`${label}.metric_counts must be an object with at most 128 entries`);
  }
  const metricCounts = {};
  for (const metricId of Object.keys(input.metric_counts).sort()) {
    assertIdentifier(metricId, `${label}.metric_counts field`);
    if (/(?:^|[._-])(secret|credential|password|key|raw|byte|payload|content|value)(?:$|[._-])/i.test(metricId)) {
      throw new Error(`${label}.metric_counts.${metricId} is not safe public metadata`);
    }
    metricCounts[metricId] = assertInteger(
      input.metric_counts[metricId],
      `${label}.metric_counts.${metricId}`,
      { min: 0 },
    );
  }
  return deepFreeze({
    version: PUBLIC_RESULT_VERSION,
    outcome,
    summary_code: summaryCode,
    artifact_refs: Object.freeze(sortedArtifactRefs),
    metric_counts: deepFreeze(metricCounts),
  });
}

const DISPOSITIONS_BY_STATE = Object.freeze({
  created: Object.freeze(["not_dispatched"]),
  prepared: Object.freeze(["not_dispatched"]),
  dispatched: Object.freeze(["ambiguous"]),
  acknowledged: Object.freeze(["confirmed_effect"]),
  refused: Object.freeze(["confirmed_no_effect"]),
  stop_requested: Object.freeze(["ambiguous"]),
  stopped: Object.freeze(["confirmed_no_effect", "confirmed_effect"]),
  ambiguous_effect: Object.freeze(["ambiguous"]),
  reconciled_no_effect: Object.freeze(["confirmed_no_effect"]),
  restored: Object.freeze(["confirmed_effect"]),
  quarantined: Object.freeze(["ambiguous", "confirmed_effect", "unknown"]),
  irreversible_authorized: Object.freeze(["confirmed_effect"]),
  unknown_effect: Object.freeze(["unknown"]),
});

function normalizeAttemptReport(input, operationRegistry, label = "attempt_report") {
  assertOperationRegistry(operationRegistry);
  assertClosedObject(
    input,
    label,
    [
      "version",
      "attempt_ref",
      "operation_id",
      "request_digest",
      "state",
      "sequence",
      "effect_disposition",
      "receipt_ref",
      "public_result",
    ],
  );
  if (input.version !== PROVIDER_CALL_VERSION) throw new Error(`${label}.version must be ${PROVIDER_CALL_VERSION}`);
  const operationId = assertIdentifier(input.operation_id, `${label}.operation_id`);
  const operation = operationRegistry.get(operationId);
  if (!operation) throw new Error(`${label}.operation_id is not registered`);
  const state = assertEnum(input.state, ATTEMPT_STATE_VALUES, `${label}.state`);
  const effectDisposition = assertEnum(
    input.effect_disposition,
    EFFECT_DISPOSITION_VALUES,
    `${label}.effect_disposition`,
  );
  if (!DISPOSITIONS_BY_STATE[state].includes(effectDisposition)) {
    throw new Error(`${label}.effect_disposition is inconsistent with state ${state}`);
  }
  const receiptRef = input.receipt_ref == null
    ? null
    : normalizeOpaqueRef(input.receipt_ref, `${label}.receipt_ref`, { prefix: "receipt" });
  if (state === "created" && receiptRef != null) throw new Error(`${label}.created state cannot carry a receipt_ref`);
  if (state !== "created" && receiptRef == null) throw new Error(`${label}.${state} state requires a receipt_ref`);
  const publicResult = input.public_result == null
    ? null
    : normalizePublicResult(input.public_result, operation, `${label}.public_result`);
  if (["created", "prepared", "dispatched", "stop_requested", "ambiguous_effect", "unknown_effect"].includes(state)
      && publicResult != null) {
    throw new Error(`${label}.${state} state cannot carry a public_result`);
  }
  if (["acknowledged", "refused"].includes(state) && publicResult == null) {
    throw new Error(`${label}.${state} state requires a public_result`);
  }
  if (state === "acknowledged" && publicResult.outcome !== "succeeded") {
    throw new Error(`${label}.acknowledged public_result must be succeeded`);
  }
  if (state === "refused" && publicResult.outcome !== "refused") {
    throw new Error(`${label}.refused public_result must be refused`);
  }
  return deepFreeze({
    version: PROVIDER_CALL_VERSION,
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    operation_id: operation.operation_id,
    request_digest: assertHash(input.request_digest, `${label}.request_digest`),
    state,
    sequence: assertInteger(input.sequence, `${label}.sequence`, { min: 0 }),
    effect_disposition: effectDisposition,
    receipt_ref: receiptRef,
    public_result: publicResult,
  });
}

function assertAttemptTransition(previousInput, nextInput, operationRegistry) {
  const previous = normalizeAttemptReport(previousInput, operationRegistry, "previous_attempt_report");
  const next = normalizeAttemptReport(nextInput, operationRegistry, "next_attempt_report");
  for (const field of ["attempt_ref", "operation_id", "request_digest"]) {
    if (next[field] !== previous[field]) throw new Error(`attempt transition changed ${field}`);
  }
  if (next.sequence !== previous.sequence + 1) {
    throw new Error("attempt transition sequence must increment by exactly one");
  }
  if (!ATTEMPT_TRANSITIONS[previous.state].includes(next.state)) {
    throw new Error(`attempt transition ${previous.state} -> ${next.state} is not allowed`);
  }
  return next;
}

function isTerminalAttemptState(state) {
  assertEnum(state, ATTEMPT_STATE_VALUES, "attempt_state");
  return TERMINAL_ATTEMPT_STATES.includes(state);
}

function assertAutomaticRetryAllowed(input, operationRegistry, label = "automatic_retry") {
  assertClosedObject(input, label, ["prior_report", "capability", "new_attempt_ref"]);
  const prior = normalizeAttemptReport(input.prior_report, operationRegistry, `${label}.prior_report`);
  const capability = input.capability;
  if (!isPlainObject(capability) || !PROVIDER_CAPABILITIES.has(capability)) {
    throw new Error(`${label}.capability must be normalized`);
  }
  if (capability.operation_id !== prior.operation_id) {
    throw new Error(`${label}.capability does not match the prior operation`);
  }
  if (["dispatched", "stop_requested", "ambiguous_effect", "unknown_effect"].includes(prior.state)
      || ["ambiguous", "unknown"].includes(prior.effect_disposition)) {
    throw new Error(`${label} is forbidden from an ambiguous or unknown effect state`);
  }
  if (capability.retry_policy !== "new_attempt_after_confirmed_no_effect") {
    throw new Error(`${label} is forbidden by capability retry_policy`);
  }
  if (capability.idempotency !== "read_only_idempotent"
      || capability.worst_case_effects.some((effect) => effect.action !== "observe" || effect.persistence !== "none")) {
    throw new Error(`${label} is permitted only for read-only idempotent capabilities`);
  }
  if (!["refused", "reconciled_no_effect"].includes(prior.state)) {
    throw new Error(`${label} requires a reconciled confirmed-no-effect terminal`);
  }
  const newAttemptRef = normalizeOpaqueRef(
    input.new_attempt_ref,
    `${label}.new_attempt_ref`,
    { prefix: "attempt" },
  );
  if (newAttemptRef === prior.attempt_ref) {
    throw new Error(`${label}.new_attempt_ref must differ from the prior attempt`);
  }
  return deepFreeze({
    prior_attempt_ref: prior.attempt_ref,
    new_attempt_ref: newAttemptRef,
    retry_basis: "confirmed_no_effect",
  });
}

function normalizeHealthResponse(input, descriptor, label = "health_response") {
  assertClosedObject(
    input,
    label,
    ["version", "provider_id", "descriptor_digest", "status", "summary_codes", "checked_at", "receipt_ref"],
  );
  if (input.version !== PROVIDER_CALL_VERSION) throw new Error(`${label}.version must be ${PROVIDER_CALL_VERSION}`);
  if (input.provider_id !== descriptor.provider_id) throw new Error(`${label}.provider_id drifted`);
  if (input.descriptor_digest !== descriptor.descriptor_digest) throw new Error(`${label}.descriptor_digest drifted`);
  return deepFreeze({
    version: PROVIDER_CALL_VERSION,
    provider_id: descriptor.provider_id,
    descriptor_digest: descriptor.descriptor_digest,
    status: assertEnum(input.status, PROVIDER_HEALTH_VALUES, `${label}.status`),
    summary_codes: normalizeIdentifierArray(input.summary_codes, `${label}.summary_codes`, { min: 1, max: 64 }),
    checked_at: assertCanonicalTimestamp(input.checked_at, `${label}.checked_at`),
    receipt_ref: normalizeOpaqueRef(input.receipt_ref, `${label}.receipt_ref`, { prefix: "receipt" }),
  });
}

function assertProviderInterface(provider) {
  if (provider == null || (typeof provider !== "object" && typeof provider !== "function")) {
    throw new Error("provider must be an object");
  }
  const missing = PROVIDER_METHODS.filter((method) => typeof provider[method] !== "function");
  if (missing.length > 0) throw new Error(`provider is missing ABI methods: ${missing.join(", ")}`);
  return provider;
}

// Provider-neutral shape for a completion-evidence adapter injected at the
// composition root. It carries a stable port identity, an evidence-domain
// digest, a durability-assurance label, and two synchronous read/commit
// methods — never a provider name, callback surface, module path, or a
// self-asserted production/hardware/execution claim. The concrete Chameleon
// adapter lives in the provider package; the broker dispatch validates it only
// against this data-and-method shape.
function assertProviderCompletionEvidenceAdapter(adapter) {
  if (adapter == null || typeof adapter !== "object") {
    throw new Error("provider completion evidence adapter must be an object");
  }
  if (typeof adapter.port_id !== "string" || !IDENTIFIER_PATTERN.test(adapter.port_id)) {
    throw new Error("provider completion evidence adapter port_id is invalid");
  }
  if (typeof adapter.evidence_domain_digest !== "string"
      || !HASH_PATTERN.test(adapter.evidence_domain_digest)) {
    throw new Error("provider completion evidence adapter evidence_domain_digest is invalid");
  }
  if (typeof adapter.durability_assurance !== "string"
      || adapter.durability_assurance.length === 0) {
    throw new Error("provider completion evidence adapter durability_assurance is invalid");
  }
  if (typeof adapter.read_committed !== "function"
      || typeof adapter.verify_and_commit !== "function") {
    throw new Error(
      "provider completion evidence adapter requires read_committed and verify_and_commit methods",
    );
  }
  if (adapter.production_ready !== false
      || adapter.hardware_access_authorized !== false
      || adapter.execution_authority !== false) {
    throw new Error(
      "provider completion evidence adapter cannot self-assert production authority",
    );
  }
  return adapter;
}

module.exports = {
  ATTEMPT_STATE_VALUES,
  ATTEMPT_TRANSITIONS,
  EFFECT_DISPOSITION_VALUES,
  IDEMPOTENCY_VALUES,
  NORMALIZED_OPERATION_VERSION,
  PARAMETER_KINDS,
  PROVIDER_ABI_VERSION,
  PROVIDER_BOOTSTRAP_ABI_VERSION,
  PROVIDER_BOOTSTRAP_ACTIVE_PLANE_FORBIDDEN_FIELDS,
  PROVIDER_BOOTSTRAP_CALL_VERSION,
  PROVIDER_BOOTSTRAP_INTENT_FIELDS,
  PROVIDER_BOOTSTRAP_OPERATION_IDS,
  PROVIDER_BOOTSTRAP_OUTCOME_VALUES,
  PROVIDER_BOOTSTRAP_REPORT_FIELDS,
  PROVIDER_BOOTSTRAP_REQUEST_FIELDS,
  PROVIDER_CALL_VERSION,
  PROVIDER_CAPABILITIES_VERSION,
  PROVIDER_DESCRIPTOR_VERSION,
  PROVIDER_HEALTH_VALUES,
  PROVIDER_METHODS,
  PUBLIC_OUTCOME_VALUES,
  PUBLIC_RESULT_VERSION,
  RESTORE_POLICY_VALUES,
  RETRY_POLICY_VALUES,
  STOP_SEMANTICS_VALUES,
  SUPPORTED_PROVIDER_ABI_VERSIONS,
  TERMINAL_ATTEMPT_STATES,
  assertAutomaticRetryAllowed,
  assertAttemptTransition,
  assertNoPublicByteMaterial,
  assertProviderCompletionEvidenceAdapter,
  assertProviderActiveAbiCompatible,
  assertProviderAbiCompatible,
  assertProviderBootstrapAbiCompatible,
  assertProviderInterface,
  buildNormalizedOperationRegistry,
  defineNormalizedOperation,
  defineProviderDescriptor,
  isTerminalAttemptState,
  normalizeAttemptReport,
  normalizeCapabilitiesResponse,
  normalizeExecuteRequest,
  normalizeHealthRequest,
  normalizeHealthResponse,
  normalizeInventoryResponse,
  normalizeOperationParameters,
  normalizePrepareRequest,
  normalizeProviderBootstrapIntent,
  normalizeProviderBootstrapReport,
  normalizeProviderBootstrapRequest,
  normalizeProviderCapability,
  normalizeProviderDescriptor,
  normalizePublicResult,
  normalizeReconcileRequest,
  normalizeRestoreRequest,
  normalizeSnapshotRequest,
  normalizeSnapshotResponse,
  normalizeStatusRequest,
  normalizeStopRequest,
};
