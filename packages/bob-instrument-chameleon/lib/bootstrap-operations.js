"use strict";

// PH-P8 is a pure, transport-independent bootstrap contract. It contains no
// device opening, framing, serial, USB, or firmware implementation. A single
// normalized MCP bootstrap request authorizes one provider-internal operation;
// that operation deterministically compiles to a fixed zero-payload command
// subset. There is deliberately no raw-command or passthrough API.

const {
  assertNoPublicByteMaterial,
  buildNormalizedOperationRegistry,
  normalizeOperationParameters,
} = require("../../bob-instrument-contracts/lib/instrument-provider-contract.js");
const {
  assertVerifiedPhysicalBootstrapGrant,
  normalizeMcpPhysicalExecutionRequest,
} = require("../../../mcp/lib/physical-authority.js");
const {
  normalizeOpaqueRef,
} = require("../../bob-instrument-contracts/lib/physical-quantities.js");
const {
  hashCanonicalJson,
} = require("../../bob-instrument-contracts/lib/verification-contracts.js");
const {
  assertPhysicalTrustedClockPort,
  assertPhysicalTrustedClockTimestampNonFuture,
  assertPhysicalTrustedClockValidityWindow,
  samplePhysicalTrustedClock,
} = require("../../../mcp/lib/physical-trusted-clock.js");

const BOOTSTRAP_SCHEMA_VERSION = 1;
const PROVIDER_ID = "chameleon_ultra";
const BOOTSTRAP_ASSURANCE_PROFILE_ID = "bootstrap_read_only";
const PRODUCTION_TRUSTED_CLOCK_MODE = "signed_monotonic_wall_mapping";
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const ED25519_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const BOOTSTRAP_INVARIANT_WITNESS_DOMAIN =
  "hacker-bob/chameleon-bootstrap-invariant-witness/v1";
const BOOTSTRAP_INVARIANT_WITNESS_KEY_USAGE =
  "hacker-bob/chameleon-bootstrap-invariant-witness-signing/v1";
const BOOTSTRAP_GRANT_PROJECTIONS = new WeakSet();
const BOOTSTRAP_GRANT_PROJECTION_STATE = new WeakMap();
const CHAMELEON_BOOTSTRAP_ATTENUATORS = new WeakSet();
const CHAMELEON_BOOTSTRAP_ATTENUATOR_STATE = new WeakMap();
const ATTENUATED_CORE_BOOTSTRAP_GRANTS = new WeakSet();
const COMPILED_BOOTSTRAP_OPERATIONS = new WeakSet();
const BOOTSTRAP_INVARIANT_WITNESS_VERIFIERS = new WeakSet();
const BOOTSTRAP_INVARIANT_WITNESS_VERIFIER_STATE = new WeakMap();
const BOOTSTRAP_INVARIANT_WITNESSES = new WeakSet();
const BOOTSTRAP_RECEIPT_ALLOCATORS = new WeakSet();
const BOOTSTRAP_RECEIPT_ALLOCATOR_STATE = new WeakMap();
const COMMITTED_BOOTSTRAP_RECEIPT_ALLOCATIONS = new WeakSet();
const ALLOCATED_BOOTSTRAP_DECODED_PAYLOADS = new WeakSet();

const CHAMELEON_BOOTSTRAP_FORBIDDEN_REQUEST_FIELDS = Object.freeze([
  "assurance_claims_digest",
  "assurance_invalidation_plan_digest",
  "assurance_profile_id",
  "attempt_id",
  "availability_variant_digest",
  "availability_variant_id",
  "bootstrap_execution_request_digest",
  "bootstrap_inventory_digest",
  "bootstrap_inventory_observation_ref",
  "bootstrap_receipt_ref",
  "capability_pack_digest",
  "capability_pack_id",
  "capability_pack_version",
  "cleanup_plan_digest",
  "contract_hash",
  "control_plan_digest",
  "dispatch_event_id",
  "environment_alias",
  "environment_ref",
  "exact_state_delta_digest",
  "experiment_plan_hash",
  "fencing_token",
  "graph_context_hash",
  "hil_plan_digest",
  "inventory_observation_digest",
  "inventory_observation_ref",
  "lease_id",
  "node_id",
  "observer_plan_digest",
  "owned_fixture_ref",
  "preparation_plan_digest",
  "prep_token_hash",
  "provider_manifest_digest",
  "recovery_or_quarantine_plan_digest",
  "resource_bundle_digest",
  "snapshot_plan_digest",
  "target_alias",
  "target_ref",
  "technique_cell_id",
  "workspace_snapshot_digest",
  "workspace_snapshot_ref",
]);

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

function assertEnumerableDataObject(value, label) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  for (const field of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || !descriptor.enumerable) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
  }
  return keys;
}

function assertClosedObject(value, label, requiredFields, optionalFields = []) {
  const keys = assertEnumerableDataObject(value, label);
  const allowed = new Set([...requiredFields, ...optionalFields]);
  const unknown = keys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = requiredFields.filter((field) => !keys.includes(field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertInteger(value, label, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${label} must be a safe integer between ${min} and ${max}`);
  }
  return value;
}

function assertCanonicalTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  return value;
}

function assertCanonicalEd25519Signature(value, label) {
  if (typeof value !== "string" || !ED25519_SIGNATURE_PATTERN.test(value)) {
    throw new Error(`${label} must be a canonical Ed25519 base64url signature`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    throw new Error(`${label} must use canonical Ed25519 base64url encoding`);
  }
  return value;
}

function callSynchronous(callback, label, ...args) {
  let value;
  try {
    value = callback(...args);
  } catch {
    throw new Error(`${label} failed`);
  }
  if (value && typeof value.then === "function") {
    throw new Error(`${label} must be synchronous`);
  }
  return value;
}

function assertDerivedDigest(input, field, expected, label) {
  if (input[field] != null && input[field] !== expected) {
    throw new Error(`${label}.${field} does not match its canonical content`);
  }
}

function assertSelfReportedText(value, label, maxLength = 128) {
  if (typeof value !== "string" || value.length < 1 || value.length > maxLength
      || value.trim() !== value || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`${label} must be bounded printable self-reported metadata`);
  }
  return value;
}

function normalizeCommandIds(value, label, { minEntries = 0, maxEntries = 4096 } = {}) {
  if (!Array.isArray(value) || value.length < minEntries || value.length > maxEntries) {
    throw new Error(`${label} must contain ${minEntries}-${maxEntries} command IDs`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || !descriptor.enumerable) {
      throw new Error(`${label} must be a dense enumerable data array`);
    }
  }
  const extra = Reflect.ownKeys(descriptors).filter((field) => (
    field !== "length" && (typeof field !== "string" || !/^\d+$/u.test(field))
  ));
  if (extra.length > 0) throw new Error(`${label} cannot contain extra or symbol fields`);
  const ids = Array.from({ length: value.length }, (_, index) => assertInteger(
    descriptors[String(index)].value,
    `${label}[${index}]`,
    { min: 0, max: 65535 },
  ));
  const normalized = [...new Set(ids)].sort((left, right) => left - right);
  if (normalized.length !== ids.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze(normalized);
}

function assertExactArray(actual, expected, label) {
  if (actual.length !== expected.length
      || actual.some((value, index) => value !== expected[index])) {
    throw new Error(`${label} does not match the closed bootstrap manifest`);
  }
}

const OPERATION_DEFINITIONS = Object.freeze([
  Object.freeze({
    version: 1,
    operation_id: "instrument.inventory",
    semantic_version: 1,
    parameters: Object.freeze({}),
    public_summary_codes: Object.freeze(["inventory_observed"]),
  }),
  Object.freeze({
    version: 1,
    operation_id: "instrument.capabilities",
    semantic_version: 1,
    parameters: Object.freeze({}),
    public_summary_codes: Object.freeze(["capabilities_observed"]),
  }),
  Object.freeze({
    version: 1,
    operation_id: "instrument.health",
    semantic_version: 1,
    parameters: Object.freeze({}),
    public_summary_codes: Object.freeze(["health_observed"]),
  }),
]);

const CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY = buildNormalizedOperationRegistry(
  OPERATION_DEFINITIONS,
);

const COMMAND_IDS_BY_OPERATION = deepFreeze({
  "instrument.inventory": [1000, 1017, 1033],
  "instrument.capabilities": [1035],
  "instrument.health": [1025],
});

const CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST = Object.freeze(
  [...new Set(Object.values(COMMAND_IDS_BY_OPERATION).flat())].sort((left, right) => left - right),
);

const BOOTSTRAP_EFFECT = deepFreeze({
  subject_kind: "instrument",
  action: "observe",
  channel: "usb",
  persistence: "none",
});

const BOOTSTRAP_INVARIANTS = deepFreeze({
  request_payload_bytes: 0,
  rf_state: "off",
  mode_change: "forbidden",
  slot_access: "forbidden",
  workspace_write: "forbidden",
});
const BOOTSTRAP_INVARIANTS_DIGEST = hashCanonicalJson(BOOTSTRAP_INVARIANTS);

const assuranceClaims = {
  profile_id: BOOTSTRAP_ASSURANCE_PROFILE_ID,
  identity_enrollment: "unverified",
  firmware_provenance: "self_reported",
  command_surface_conformance: "bootstrap_allowlisted",
  transport_trust: "local_observed",
  rf_invariant_assurance: "pending_independent_observation_hil",
  mode_invariant_assurance: "not_observed_get_device_mode_not_allowlisted",
  workspace_invariant_assurance: "closed_command_effect_manifest_only",
  production_ready: false,
  execution_authority: false,
  lifecycle_authority: false,
};
const CHAMELEON_BOOTSTRAP_ASSURANCE_CLAIMS = deepFreeze({
  ...assuranceClaims,
  assurance_claims_digest: hashCanonicalJson(assuranceClaims),
});

const manifestOperations = CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.ids().map((operationId) => {
  const operation = CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.get(operationId);
  const commandIds = COMMAND_IDS_BY_OPERATION[operationId];
  return deepFreeze({
    operation_id: operation.operation_id,
    operation_digest: operation.operation_digest,
    exposure: "provider_private",
    disposition: "provider_internal",
    parameters: {},
    command_ids: commandIds,
    command_set_digest: hashCanonicalJson(commandIds),
    effect: BOOTSTRAP_EFFECT,
    invariants: BOOTSTRAP_INVARIANTS,
  });
});
const manifestBasis = {
  version: BOOTSTRAP_SCHEMA_VERSION,
  provider_id: PROVIDER_ID,
  exposure: "provider_private",
  disposition: "provider_internal",
  assurance_ceiling_profile_id: BOOTSTRAP_ASSURANCE_PROFILE_ID,
  operation_registry_digest: CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.registry_digest,
  command_allowlist: CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST,
  operations: manifestOperations,
  invariants: BOOTSTRAP_INVARIANTS,
};
const CHAMELEON_BOOTSTRAP_MANIFEST = deepFreeze({
  ...manifestBasis,
  manifest_digest: hashCanonicalJson(manifestBasis),
});

const EMPTY_PARAMETERS_DIGEST = hashCanonicalJson({});

function requireManifestOperation(operationId, label) {
  const operation = CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.get(operationId);
  if (!operation) {
    throw new Error(
      `${label} is not a provider-internal Chameleon bootstrap operation; raw, RF, mode, and slot operations are unavailable`,
    );
  }
  return operation;
}

function normalizeChameleonBootstrapRequest(
  input,
  effectRegistry,
  label = "chameleon_bootstrap_request",
) {
  assertEnumerableDataObject(input, label);
  const forbidden = CHAMELEON_BOOTSTRAP_FORBIDDEN_REQUEST_FIELDS
    .filter((field) => Object.prototype.hasOwnProperty.call(input, field));
  if (forbidden.length > 0) {
    throw new Error(
      `${label} cannot presuppose inventory, snapshot, task, plan, experiment, resource, target, or environment state: ${forbidden.sort().join(", ")}`,
    );
  }
  const request = normalizeMcpPhysicalExecutionRequest(input, effectRegistry, { label });
  if (request.grant_kind !== "bootstrap") {
    throw new Error(`${label}.grant_kind must be bootstrap`);
  }
  if (request.bootstrap_manifest_digest !== CHAMELEON_BOOTSTRAP_MANIFEST.manifest_digest) {
    throw new Error(`${label}.bootstrap_manifest_digest does not match the closed Chameleon manifest`);
  }
  requireManifestOperation(request.operation_id, `${label}.operation_id`);
  if (request.parameter_digest !== EMPTY_PARAMETERS_DIGEST) {
    throw new Error(`${label}.parameter_digest must bind the empty zero-payload parameter object`);
  }
  if (request.requested_effects.length !== 1) {
    throw new Error(`${label}.requested_effects must contain exactly one instrument.observe/usb/none effect`);
  }
  const [effect] = request.requested_effects;
  for (const [field, expected] of Object.entries(BOOTSTRAP_EFFECT)) {
    if (effect[field] !== expected) {
      throw new Error(`${label}.requested_effects[0] must be exactly instrument.observe/usb/none`);
    }
  }
  if (effect.subject_ref !== request.instrument_ref || Object.keys(effect.bounds).length !== 0) {
    throw new Error(`${label}.requested_effects[0] must be unbounded and bind only the instrument alias`);
  }
  return request;
}

function createChameleonBootstrapGrantAttenuator(input) {
  assertClosedObject(input, "chameleon_bootstrap_grant_attenuator", [
    "attenuator_id",
    "bootstrap_grant_verifier",
    "provider_descriptor_digest",
    "provider_binary_digest",
    "transport_digest",
  ]);
  if (!input.bootstrap_grant_verifier || typeof input.bootstrap_grant_verifier !== "object") {
    throw new Error("chameleon_bootstrap_grant_attenuator.bootstrap_grant_verifier must be a configured verifier");
  }
  if (input.bootstrap_grant_verifier.trusted_clock_mode !== PRODUCTION_TRUSTED_CLOCK_MODE) {
    throw new Error(
      "Chameleon bootstrap attenuation requires a signed monotonic wall-clock mapping",
    );
  }
  const attenuator = Object.freeze({
    version: BOOTSTRAP_SCHEMA_VERSION,
    attenuator_id: assertIdentifier(
      input.attenuator_id,
      "chameleon_bootstrap_grant_attenuator.attenuator_id",
    ),
    provider_id: PROVIDER_ID,
  });
  CHAMELEON_BOOTSTRAP_ATTENUATORS.add(attenuator);
  CHAMELEON_BOOTSTRAP_ATTENUATOR_STATE.set(attenuator, Object.freeze({
    bootstrap_grant_verifier: input.bootstrap_grant_verifier,
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      "chameleon_bootstrap_grant_attenuator.provider_descriptor_digest",
    ),
    provider_binary_digest: assertDigest(
      input.provider_binary_digest,
      "chameleon_bootstrap_grant_attenuator.provider_binary_digest",
    ),
    transport_digest: assertDigest(
      input.transport_digest,
      "chameleon_bootstrap_grant_attenuator.transport_digest",
    ),
  }));
  return attenuator;
}

function assertChameleonBootstrapGrantAttenuator(input) {
  const state = input == null ? null : CHAMELEON_BOOTSTRAP_ATTENUATOR_STATE.get(input);
  if (!input || !CHAMELEON_BOOTSTRAP_ATTENUATORS.has(input) || !state) {
    throw new Error("Chameleon bootstrap grant attenuator must be configured by the provider runtime");
  }
  return { attenuator: input, state };
}

function assertCoreBootstrapRequestCeiling(coreGrant) {
  if (coreGrant.trusted_clock_mode !== PRODUCTION_TRUSTED_CLOCK_MODE) {
    throw new Error(
      "Chameleon bootstrap authority requires a signed monotonic wall-clock mapping",
    );
  }
  if (coreGrant.request_path !== "mcp" || coreGrant.grant_kind !== "bootstrap") {
    throw new Error("Chameleon bootstrap authority must originate from the MCP bootstrap path");
  }
  if (coreGrant.parameter_digest !== EMPTY_PARAMETERS_DIGEST || coreGrant.rf_state !== "off") {
    throw new Error("Chameleon bootstrap authority must bind empty parameters and RF off");
  }
  if (!Array.isArray(coreGrant.requested_effects) || coreGrant.requested_effects.length !== 1) {
    throw new Error("Chameleon bootstrap authority must bind exactly one requested effect");
  }
  const [effect] = coreGrant.requested_effects;
  for (const [field, expected] of Object.entries(BOOTSTRAP_EFFECT)) {
    if (effect[field] !== expected) {
      throw new Error("Chameleon bootstrap authority must be exactly instrument.observe/usb/none");
    }
  }
  if (effect.subject_ref !== coreGrant.instrument_ref || Object.keys(effect.bounds).length !== 0) {
    throw new Error("Chameleon bootstrap authority must bind only the unbounded instrument alias");
  }
}

function projectChameleonBootstrapGrant(coreGrantProjection, attenuatorInput) {
  if (arguments.length !== 2) {
    throw new Error(
      "projectChameleonBootstrapGrant accepts only a verified core grant and configured attenuator",
    );
  }
  const { attenuator, state: attenuatorState } = assertChameleonBootstrapGrantAttenuator(attenuatorInput);
  const operation = requireManifestOperation(
    coreGrantProjection && coreGrantProjection.operation_id,
    "chameleon bootstrap operation",
  );
  const commandIds = COMMAND_IDS_BY_OPERATION[operation.operation_id];
  const expectedCoreBindings = deepFreeze({
    execution_request_digest: coreGrantProjection.execution_request_digest,
    provider_id: PROVIDER_ID,
    provider_descriptor_digest: attenuatorState.provider_descriptor_digest,
    bootstrap_manifest_digest: CHAMELEON_BOOTSTRAP_MANIFEST.manifest_digest,
    provider_binary_digest: attenuatorState.provider_binary_digest,
    transport_digest: attenuatorState.transport_digest,
    operation_id: operation.operation_id,
    operation_digest: operation.operation_digest,
    bootstrap_invariants_digest: BOOTSTRAP_INVARIANTS_DIGEST,
  });
  const coreGrant = assertVerifiedPhysicalBootstrapGrant(
    coreGrantProjection,
    attenuatorState.bootstrap_grant_verifier,
    expectedCoreBindings,
  );
  assertCoreBootstrapRequestCeiling(coreGrant);
  if (ATTENUATED_CORE_BOOTSTRAP_GRANTS.has(coreGrant)) {
    throw new Error("physical bootstrap grant has already been attenuated for provider use");
  }
  const projectionBasis = {
    version: BOOTSTRAP_SCHEMA_VERSION,
    projection_kind: "chameleon_bootstrap_read_only",
    provider_id: PROVIDER_ID,
    provider_descriptor_digest: coreGrant.provider_descriptor_digest,
    exposure: "provider_private",
    grant_kind: "bootstrap",
    request_path: coreGrant.request_path,
    session_id: coreGrant.session_id,
    session_nucleus_hash: coreGrant.session_nucleus_hash,
    caller_role_id: coreGrant.caller_role_id,
    requester_principal_id: coreGrant.requester_principal_id,
    ipc_peer_principal_id: coreGrant.ipc_peer_principal_id,
    execution_principal_id: coreGrant.execution_principal_id,
    instrument_ref: coreGrant.instrument_ref,
    enrollment_candidate_ref: coreGrant.enrollment_candidate_ref,
    bootstrap_manifest_digest: coreGrant.bootstrap_manifest_digest,
    provider_binary_digest: coreGrant.provider_binary_digest,
    transport_digest: coreGrant.transport_digest,
    operation_id: operation.operation_id,
    operation_digest: operation.operation_digest,
    command_ids: commandIds,
    command_set_digest: hashCanonicalJson(commandIds),
    parameter_digest: coreGrant.parameter_digest,
    requested_effects_digest: coreGrant.requested_effects_digest,
    authority_epoch: coreGrant.authority_epoch,
    revocation_generation: coreGrant.revocation_generation,
    nonce: coreGrant.request_nonce,
    sequence: coreGrant.request_sequence,
    not_before: coreGrant.not_before,
    expires_at: coreGrant.expires_at,
    execution_request_digest: coreGrant.execution_request_digest,
    signed_grant_digest: coreGrant.signed_grant_digest,
    core_grant_projection_digest: coreGrant.projection_digest,
    authority_resolution_digest: coreGrant.authority_resolution_digest,
    replay_reservation_receipt_digest: coreGrant.replay_reservation_receipt_digest,
    trusted_clock_mode: coreGrant.trusted_clock_mode,
    assurance_ceiling_profile_id: BOOTSTRAP_ASSURANCE_PROFILE_ID,
    bootstrap_invariants_digest: BOOTSTRAP_INVARIANTS_DIGEST,
    invariants: BOOTSTRAP_INVARIANTS,
  };
  const projection = deepFreeze({
    ...projectionBasis,
    bootstrap_grant_projection_digest: hashCanonicalJson(projectionBasis),
  });
  ATTENUATED_CORE_BOOTSTRAP_GRANTS.add(coreGrant);
  BOOTSTRAP_GRANT_PROJECTIONS.add(projection);
  BOOTSTRAP_GRANT_PROJECTION_STATE.set(projection, Object.freeze({
    core_grant_projection: coreGrant,
    attenuator,
    verifier: attenuatorState.bootstrap_grant_verifier,
    expected_core_bindings: expectedCoreBindings,
  }));
  return projection;
}

function assertBootstrapGrantProjection(value, options = {}) {
  const state = value == null ? null : BOOTSTRAP_GRANT_PROJECTION_STATE.get(value);
  if (!value || !BOOTSTRAP_GRANT_PROJECTIONS.has(value) || !state) {
    throw new Error(
      "bootstrap grant projection must be issued by the signed core authority and closed Chameleon attenuator",
    );
  }
  if (options.live !== false) {
    assertVerifiedPhysicalBootstrapGrant(
      state.core_grant_projection,
      state.verifier,
      state.expected_core_bindings,
    );
  }
  return value;
}

function compileChameleonBootstrapOperation(grantProjection) {
  if (arguments.length !== 1) {
    throw new Error("bootstrap compilation accepts one grant projection and no raw command or payload input");
  }
  const grant = assertBootstrapGrantProjection(grantProjection);
  const operation = requireManifestOperation(grant.operation_id, "bootstrap grant operation_id");
  normalizeOperationParameters({}, operation, "chameleon bootstrap parameters");
  const commands = COMMAND_IDS_BY_OPERATION[operation.operation_id].map((commandId) => deepFreeze({
    version: BOOTSTRAP_SCHEMA_VERSION,
    command_id: commandId,
    payload_kind: "none",
    payload_byte_length: 0,
  }));
  const compiledBasis = {
    version: BOOTSTRAP_SCHEMA_VERSION,
    provider_id: PROVIDER_ID,
    bootstrap_grant_projection_digest: grant.bootstrap_grant_projection_digest,
    signed_grant_digest: grant.signed_grant_digest,
    core_grant_projection_digest: grant.core_grant_projection_digest,
    replay_reservation_receipt_digest: grant.replay_reservation_receipt_digest,
    execution_request_digest: grant.execution_request_digest,
    operation_id: operation.operation_id,
    operation_digest: operation.operation_digest,
    trusted_clock_mode: grant.trusted_clock_mode,
    commands,
    command_set_digest: grant.command_set_digest,
    effect: BOOTSTRAP_EFFECT,
    invariants: BOOTSTRAP_INVARIANTS,
  };
  const compiled = deepFreeze({
    ...compiledBasis,
    compiled_operation_digest: hashCanonicalJson(compiledBasis),
  });
  COMPILED_BOOTSTRAP_OPERATIONS.add(compiled);
  return compiled;
}

function assertCompiledChameleonBootstrapOperation(value) {
  if (!value || !COMPILED_BOOTSTRAP_OPERATIONS.has(value) || !Object.isFrozen(value)) {
    throw new Error("compiled Chameleon bootstrap operation must come from the closed grant compiler");
  }
  return value;
}

const BOOTSTRAP_INVARIANT_WITNESS_PAYLOAD_FIELDS = Object.freeze([
  "version",
  "provider_id",
  "bootstrap_grant_projection_digest",
  "execution_request_digest",
  "operation_id",
  "operation_digest",
  "command_set_digest",
  "decoded_payload_digest",
  "instrument_ref",
  "enrollment_candidate_ref",
  "bootstrap_invariants_digest",
  "witness_principal_id",
  "observed_at",
  "rf_invariant_verdict",
  "mode_invariant_verdict",
  "workspace_invariant_verdict",
  "workspace_write_count",
  "independent_observation_hil_status",
]);

const BOOTSTRAP_INVARIANT_WITNESS_AUTHENTICATION_FIELDS = Object.freeze([
  "version",
  "method",
  "key_usage",
  "trust_root_id",
  "trust_root_epoch",
  "trust_registry_digest",
  "signer_key_id",
  "signer_epoch",
  "signer_public_key_digest",
  "signed_at",
  "expires_at",
  "signed_payload_digest",
]);

function normalizeBootstrapInvariantWitnessPayload(input, label) {
  assertClosedObject(input, label, BOOTSTRAP_INVARIANT_WITNESS_PAYLOAD_FIELDS);
  if (input.version !== BOOTSTRAP_SCHEMA_VERSION) {
    throw new Error(`${label}.version must be ${BOOTSTRAP_SCHEMA_VERSION}`);
  }
  if (input.provider_id !== PROVIDER_ID) throw new Error(`${label}.provider_id drifted`);
  if (input.rf_invariant_verdict !== "pending_independent_observation_hil") {
    throw new Error(`${label}.rf_invariant_verdict must remain pending independent observation/HIL`);
  }
  if (input.mode_invariant_verdict !== "not_observed_get_device_mode_not_allowlisted") {
    throw new Error(`${label}.mode_invariant_verdict must honestly report that command 1002 is not allowlisted`);
  }
  if (input.workspace_invariant_verdict
      !== "satisfied_by_closed_command_effect_manifest"
      || input.workspace_write_count !== 0) {
    throw new Error(`${label} workspace verdict must derive from the closed no-write command manifest`);
  }
  if (input.independent_observation_hil_status !== "not_performed") {
    throw new Error(`${label}.independent_observation_hil_status must remain not_performed`);
  }
  return deepFreeze({
    version: BOOTSTRAP_SCHEMA_VERSION,
    provider_id: PROVIDER_ID,
    bootstrap_grant_projection_digest: assertDigest(
      input.bootstrap_grant_projection_digest,
      `${label}.bootstrap_grant_projection_digest`,
    ),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    operation_id: assertIdentifier(input.operation_id, `${label}.operation_id`),
    operation_digest: assertDigest(input.operation_digest, `${label}.operation_digest`),
    command_set_digest: assertDigest(input.command_set_digest, `${label}.command_set_digest`),
    decoded_payload_digest: assertDigest(
      input.decoded_payload_digest,
      `${label}.decoded_payload_digest`,
    ),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    enrollment_candidate_ref: normalizeOpaqueRef(
      input.enrollment_candidate_ref,
      `${label}.enrollment_candidate_ref`,
      { prefix: "enrollment-candidate" },
    ),
    bootstrap_invariants_digest: assertDigest(
      input.bootstrap_invariants_digest,
      `${label}.bootstrap_invariants_digest`,
    ),
    witness_principal_id: normalizeOpaqueRef(
      input.witness_principal_id,
      `${label}.witness_principal_id`,
      { prefix: "principal" },
    ),
    observed_at: assertCanonicalTimestamp(input.observed_at, `${label}.observed_at`),
    rf_invariant_verdict: "pending_independent_observation_hil",
    mode_invariant_verdict: "not_observed_get_device_mode_not_allowlisted",
    workspace_invariant_verdict: "satisfied_by_closed_command_effect_manifest",
    workspace_write_count: 0,
    independent_observation_hil_status: "not_performed",
  });
}

function normalizeBootstrapInvariantWitnessAuthentication(input, payloadDigest, label) {
  assertClosedObject(input, label, BOOTSTRAP_INVARIANT_WITNESS_AUTHENTICATION_FIELDS);
  if (input.version !== BOOTSTRAP_SCHEMA_VERSION || input.method !== "ed25519") {
    throw new Error(`${label} must use version 1 Ed25519 authentication`);
  }
  if (input.key_usage !== BOOTSTRAP_INVARIANT_WITNESS_KEY_USAGE) {
    throw new Error(`${label}.key_usage is not authorized for bootstrap invariant witnesses`);
  }
  const signedAt = assertCanonicalTimestamp(input.signed_at, `${label}.signed_at`);
  const expiresAt = assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(expiresAt) <= Date.parse(signedAt)) {
    throw new Error(`${label}.expires_at must be after signed_at`);
  }
  const normalized = {
    version: BOOTSTRAP_SCHEMA_VERSION,
    method: "ed25519",
    key_usage: BOOTSTRAP_INVARIANT_WITNESS_KEY_USAGE,
    trust_root_id: normalizeOpaqueRef(input.trust_root_id, `${label}.trust_root_id`, {
      prefix: "trust-root",
    }),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, {
      min: 1,
    }),
    trust_registry_digest: assertDigest(
      input.trust_registry_digest,
      `${label}.trust_registry_digest`,
    ),
    signer_key_id: normalizeOpaqueRef(input.signer_key_id, `${label}.signer_key_id`, {
      prefix: "signer-key",
    }),
    signer_epoch: assertInteger(input.signer_epoch, `${label}.signer_epoch`, { min: 1 }),
    signer_public_key_digest: assertDigest(
      input.signer_public_key_digest,
      `${label}.signer_public_key_digest`,
    ),
    signed_at: signedAt,
    expires_at: expiresAt,
    signed_payload_digest: assertDigest(
      input.signed_payload_digest,
      `${label}.signed_payload_digest`,
    ),
  };
  if (normalized.signed_payload_digest !== payloadDigest) {
    throw new Error(`${label}.signed_payload_digest does not bind the witness payload`);
  }
  return deepFreeze(normalized);
}

function bootstrapInvariantWitnessSignatureInputDigest(payloadInput, authenticationInput) {
  const payload = normalizeBootstrapInvariantWitnessPayload(
    payloadInput,
    "bootstrap_invariant_witness.payload",
  );
  const authentication = normalizeBootstrapInvariantWitnessAuthentication(
    authenticationInput,
    hashCanonicalJson(payload),
    "bootstrap_invariant_witness.authentication",
  );
  return hashCanonicalJson({
    domain: BOOTSTRAP_INVARIANT_WITNESS_DOMAIN,
    version: BOOTSTRAP_SCHEMA_VERSION,
    kind: "chameleon_bootstrap_invariant_witness",
    payload,
    authentication,
  });
}

function normalizeSignedBootstrapInvariantWitness(input, label) {
  assertNoPublicByteMaterial(input, label);
  assertClosedObject(input, label, [
    "version",
    "kind",
    "domain",
    "payload",
    "authentication",
  ], ["witness_envelope_digest"]);
  if (input.version !== BOOTSTRAP_SCHEMA_VERSION
      || input.kind !== "chameleon_bootstrap_invariant_witness"
      || input.domain !== BOOTSTRAP_INVARIANT_WITNESS_DOMAIN) {
    throw new Error(`${label} has the wrong version, kind, or signature domain`);
  }
  const payload = normalizeBootstrapInvariantWitnessPayload(input.payload, `${label}.payload`);
  const payloadDigest = hashCanonicalJson(payload);
  assertClosedObject(input.authentication, `${label}.authentication`, [
    ...BOOTSTRAP_INVARIANT_WITNESS_AUTHENTICATION_FIELDS,
    "signature",
  ]);
  const authenticationBasis = normalizeBootstrapInvariantWitnessAuthentication(
    Object.fromEntries(BOOTSTRAP_INVARIANT_WITNESS_AUTHENTICATION_FIELDS.map(
      (field) => [field, input.authentication[field]],
    )),
    payloadDigest,
    `${label}.authentication`,
  );
  const signature = assertCanonicalEd25519Signature(
    input.authentication.signature,
    `${label}.authentication.signature`,
  );
  const signatureInputDigest = bootstrapInvariantWitnessSignatureInputDigest(
    payload,
    authenticationBasis,
  );
  const envelopeBasis = {
    version: BOOTSTRAP_SCHEMA_VERSION,
    kind: "chameleon_bootstrap_invariant_witness",
    domain: BOOTSTRAP_INVARIANT_WITNESS_DOMAIN,
    payload,
    authentication: deepFreeze({ ...authenticationBasis, signature }),
  };
  const witnessEnvelopeDigest = hashCanonicalJson(envelopeBasis);
  assertDerivedDigest(input, "witness_envelope_digest", witnessEnvelopeDigest, label);
  return deepFreeze({
    ...envelopeBasis,
    witness_payload_digest: payloadDigest,
    signature_input_digest: signatureInputDigest,
    witness_envelope_digest: witnessEnvelopeDigest,
  });
}

function createChameleonBootstrapInvariantWitnessVerifier(input) {
  assertClosedObject(input, "chameleon_bootstrap_invariant_witness_verifier", [
    "verifier_id",
    "trusted_clock_port",
    "resolve_current_trust",
    "verify_ed25519",
  ]);
  for (const callback of ["resolve_current_trust", "verify_ed25519"]) {
    if (typeof input[callback] !== "function") {
      throw new Error(`chameleon_bootstrap_invariant_witness_verifier.${callback} must be a function`);
    }
  }
  const verifier = Object.freeze({
    version: BOOTSTRAP_SCHEMA_VERSION,
    verifier_id: assertIdentifier(
      input.verifier_id,
      "chameleon_bootstrap_invariant_witness_verifier.verifier_id",
    ),
    provider_id: PROVIDER_ID,
    trusted_clock_mode: PRODUCTION_TRUSTED_CLOCK_MODE,
  });
  BOOTSTRAP_INVARIANT_WITNESS_VERIFIERS.add(verifier);
  BOOTSTRAP_INVARIANT_WITNESS_VERIFIER_STATE.set(verifier, Object.freeze({
    trusted_clock_port: assertPhysicalTrustedClockPort(input.trusted_clock_port),
    resolve_current_trust: input.resolve_current_trust,
    verify_ed25519: input.verify_ed25519,
  }));
  return verifier;
}

function verifyChameleonBootstrapInvariantWitness(
  envelopeInput,
  decodedPayloadInput,
  grantProjection,
  verifierInput,
) {
  if (arguments.length !== 4) {
    throw new Error("bootstrap invariant witness verification accepts exactly four bound inputs");
  }
  const verifierState = verifierInput == null
    ? null
    : BOOTSTRAP_INVARIANT_WITNESS_VERIFIER_STATE.get(verifierInput);
  if (!verifierInput || !BOOTSTRAP_INVARIANT_WITNESS_VERIFIERS.has(verifierInput)
      || !verifierState) {
    throw new Error("bootstrap invariant witness verifier must be configured by the provider runtime");
  }
  const decoded = require("./bootstrap-response-payloads.js")
    .assertChameleonBootstrapDecodedPayload(decodedPayloadInput);
  const grant = assertBootstrapGrantProjection(grantProjection, { live: false });
  const envelope = normalizeSignedBootstrapInvariantWitness(
    envelopeInput,
    "bootstrap_invariant_witness",
  );
  const { payload, authentication } = envelope;
  const expectedBindings = {
    bootstrap_grant_projection_digest: grant.bootstrap_grant_projection_digest,
    execution_request_digest: grant.execution_request_digest,
    operation_id: grant.operation_id,
    operation_digest: grant.operation_digest,
    command_set_digest: grant.command_set_digest,
    decoded_payload_digest: decoded.decoded_payload_digest,
    instrument_ref: grant.instrument_ref,
    enrollment_candidate_ref: grant.enrollment_candidate_ref,
    bootstrap_invariants_digest: BOOTSTRAP_INVARIANTS_DIGEST,
  };
  for (const [field, expected] of Object.entries(expectedBindings)) {
    if (payload[field] !== expected) {
      throw new Error(`bootstrap invariant witness ${field} is detached from decoded grant evidence`);
    }
  }
  for (const field of [
    "bootstrap_grant_projection_digest",
    "execution_request_digest",
    "operation_id",
    "operation_digest",
  ]) {
    if (decoded[field] !== grant[field]) {
      throw new Error(`source-owned decoded payload ${field} is detached from its grant`);
    }
  }
  assertExactArray(decoded.command_ids, grant.command_ids, "source-owned decoded payload command_ids");
  const trustInput = callSynchronous(
    verifierState.resolve_current_trust,
    "bootstrap invariant witness trust resolver",
    deepFreeze({
      version: BOOTSTRAP_SCHEMA_VERSION,
      provider_id: PROVIDER_ID,
      witness_principal_id: payload.witness_principal_id,
      trust_root_id: authentication.trust_root_id,
      trust_root_epoch: authentication.trust_root_epoch,
      trust_registry_digest: authentication.trust_registry_digest,
      signer_key_id: authentication.signer_key_id,
      signer_epoch: authentication.signer_epoch,
      signer_public_key_digest: authentication.signer_public_key_digest,
      key_usage: authentication.key_usage,
    }),
  );
  assertClosedObject(trustInput, "current_bootstrap_invariant_witness_trust", [
    "version",
    "trusted",
    "revoked",
    "witness_principal_id",
    "trust_root_id",
    "trust_root_epoch",
    "trust_registry_digest",
    "signer_key_id",
    "signer_epoch",
    "signer_public_key_digest",
    "key_usage",
  ]);
  if (trustInput.version !== BOOTSTRAP_SCHEMA_VERSION
      || trustInput.trusted !== true || trustInput.revoked !== false) {
    throw new Error("bootstrap invariant witness signer is not currently trusted");
  }
  for (const [field, expected] of Object.entries({
    witness_principal_id: payload.witness_principal_id,
    trust_root_id: authentication.trust_root_id,
    trust_root_epoch: authentication.trust_root_epoch,
    trust_registry_digest: authentication.trust_registry_digest,
    signer_key_id: authentication.signer_key_id,
    signer_epoch: authentication.signer_epoch,
    signer_public_key_digest: authentication.signer_public_key_digest,
    key_usage: BOOTSTRAP_INVARIANT_WITNESS_KEY_USAGE,
  })) {
    if (trustInput[field] !== expected) {
      throw new Error(`bootstrap invariant witness current ${field} drifted`);
    }
  }
  const signatureVerified = callSynchronous(
    verifierState.verify_ed25519,
    "bootstrap invariant witness signature verifier",
    deepFreeze({
      version: BOOTSTRAP_SCHEMA_VERSION,
      signature_input_digest: envelope.signature_input_digest,
      signature: authentication.signature,
      signer_key_id: authentication.signer_key_id,
      signer_public_key_digest: authentication.signer_public_key_digest,
      key_usage: authentication.key_usage,
    }),
  );
  if (signatureVerified !== true) throw new Error("bootstrap invariant witness signature is invalid");
  const clockSample = samplePhysicalTrustedClock(verifierState.trusted_clock_port);
  assertPhysicalTrustedClockValidityWindow(
    clockSample,
    {
      not_before: authentication.signed_at,
      expires_at: authentication.expires_at,
    },
    "bootstrap invariant witness validity",
  );
  assertPhysicalTrustedClockTimestampNonFuture(
    clockSample,
    payload.observed_at,
    "bootstrap invariant witness observed_at",
  );
  if (Date.parse(authentication.signed_at) < Date.parse(payload.observed_at)) {
    throw new Error("bootstrap invariant witness cannot be signed before its observation");
  }
  if (Date.parse(payload.observed_at) < Date.parse(grant.not_before)
      || Date.parse(payload.observed_at) >= Date.parse(grant.expires_at)) {
    throw new Error("bootstrap invariant witness observed_at is outside the bootstrap grant window");
  }
  const projectionBasis = {
    version: BOOTSTRAP_SCHEMA_VERSION,
    provider_id: PROVIDER_ID,
    witness_ref: `bootstrap-invariant-witness:v1:${envelope.witness_envelope_digest}`,
    witness_digest: envelope.witness_envelope_digest,
    witness_payload_digest: envelope.witness_payload_digest,
    signature_input_digest: envelope.signature_input_digest,
    bootstrap_grant_projection_digest: grant.bootstrap_grant_projection_digest,
    execution_request_digest: grant.execution_request_digest,
    decoded_payload_digest: decoded.decoded_payload_digest,
    instrument_ref: grant.instrument_ref,
    enrollment_candidate_ref: grant.enrollment_candidate_ref,
    operation_id: grant.operation_id,
    operation_digest: grant.operation_digest,
    command_set_digest: grant.command_set_digest,
    bootstrap_invariants_digest: BOOTSTRAP_INVARIANTS_DIGEST,
    witness_principal_id: payload.witness_principal_id,
    observed_at: payload.observed_at,
    rf_invariant_verdict: payload.rf_invariant_verdict,
    mode_invariant_verdict: payload.mode_invariant_verdict,
    workspace_invariant_verdict: payload.workspace_invariant_verdict,
    workspace_write_count: 0,
    independent_observation_hil_status: "not_performed",
    signer_key_id: authentication.signer_key_id,
    signer_epoch: authentication.signer_epoch,
    signer_public_key_digest: authentication.signer_public_key_digest,
    trust_root_id: authentication.trust_root_id,
    trust_root_epoch: authentication.trust_root_epoch,
    trust_registry_digest: authentication.trust_registry_digest,
    trusted_clock_sample_digest: hashCanonicalJson(clockSample),
    authenticated: true,
    production_ready: false,
    execution_authority: false,
    lifecycle_authority: false,
  };
  const projection = deepFreeze({
    ...projectionBasis,
    witness_projection_digest: hashCanonicalJson(projectionBasis),
  });
  BOOTSTRAP_INVARIANT_WITNESSES.add(projection);
  return projection;
}

function assertBootstrapInvariantWitness(value) {
  if (!value || !BOOTSTRAP_INVARIANT_WITNESSES.has(value) || !Object.isFrozen(value)) {
    throw new Error("BootstrapInvariantWitness must be authenticated by the configured verifier");
  }
  return value;
}

function createChameleonBootstrapReceiptAllocator(input) {
  assertClosedObject(input, "chameleon_bootstrap_receipt_allocator", [
    "allocator_id",
    "commit_allocation",
    "resolve_committed_allocation",
  ]);
  for (const callback of ["commit_allocation", "resolve_committed_allocation"]) {
    if (typeof input[callback] !== "function") {
      throw new Error(`chameleon_bootstrap_receipt_allocator.${callback} must be a function`);
    }
  }
  const allocator = Object.freeze({
    version: BOOTSTRAP_SCHEMA_VERSION,
    allocator_id: assertIdentifier(
      input.allocator_id,
      "chameleon_bootstrap_receipt_allocator.allocator_id",
    ),
    provider_id: PROVIDER_ID,
  });
  BOOTSTRAP_RECEIPT_ALLOCATORS.add(allocator);
  BOOTSTRAP_RECEIPT_ALLOCATOR_STATE.set(allocator, Object.freeze({
    commit_allocation: input.commit_allocation,
    resolve_committed_allocation: input.resolve_committed_allocation,
  }));
  return allocator;
}

const BOOTSTRAP_RECEIPT_ALLOCATION_FIELDS = Object.freeze([
  "version",
  "allocation_kind",
  "allocator_id",
  "provider_id",
  "bootstrap_grant_projection_digest",
  "execution_request_digest",
  "operation_id",
  "operation_digest",
  "decoded_payload_digest",
  "invariant_witness_ref",
  "invariant_witness_digest",
  "instrument_ref",
  "enrollment_candidate_ref",
  "observed_at",
  "observation_ref",
  "observation_digest",
  "receipt_ref",
  "receipt_digest",
  "commit_state",
  "allocation_assurance",
  "production_ready",
  "execution_authority",
  "lifecycle_authority",
  "allocation_digest",
]);

function buildBootstrapReceiptAllocation(basis) {
  const observationBasis = {
    version: BOOTSTRAP_SCHEMA_VERSION,
    observation_kind: "chameleon_bootstrap_response",
    allocator_id: basis.allocator_id,
    provider_id: PROVIDER_ID,
    bootstrap_grant_projection_digest: basis.bootstrap_grant_projection_digest,
    execution_request_digest: basis.execution_request_digest,
    operation_id: basis.operation_id,
    operation_digest: basis.operation_digest,
    decoded_payload_digest: basis.decoded_payload_digest,
    invariant_witness_ref: basis.invariant_witness_ref,
    invariant_witness_digest: basis.invariant_witness_digest,
    instrument_ref: basis.instrument_ref,
    enrollment_candidate_ref: basis.enrollment_candidate_ref,
    observed_at: basis.observed_at,
  };
  const observationDigest = hashCanonicalJson(observationBasis);
  const observationRef = `bootstrap-observation:v1:${observationDigest}`;
  const receiptBasis = {
    version: BOOTSTRAP_SCHEMA_VERSION,
    receipt_kind: "chameleon_bootstrap_response",
    ...observationBasis,
    observation_ref: observationRef,
    observation_digest: observationDigest,
  };
  const receiptDigest = hashCanonicalJson(receiptBasis);
  const receiptRef = `bootstrap-receipt:v1:${receiptDigest}`;
  const allocationBasis = {
    version: BOOTSTRAP_SCHEMA_VERSION,
    allocation_kind: "committed_chameleon_bootstrap_response",
    allocator_id: basis.allocator_id,
    provider_id: PROVIDER_ID,
    bootstrap_grant_projection_digest: basis.bootstrap_grant_projection_digest,
    execution_request_digest: basis.execution_request_digest,
    operation_id: basis.operation_id,
    operation_digest: basis.operation_digest,
    decoded_payload_digest: basis.decoded_payload_digest,
    invariant_witness_ref: basis.invariant_witness_ref,
    invariant_witness_digest: basis.invariant_witness_digest,
    instrument_ref: basis.instrument_ref,
    enrollment_candidate_ref: basis.enrollment_candidate_ref,
    observed_at: basis.observed_at,
    observation_ref: observationRef,
    observation_digest: observationDigest,
    receipt_ref: receiptRef,
    receipt_digest: receiptDigest,
    // This local seam proves that the configured source acknowledged and then
    // exactly resolved the allocation. The factory is intentionally public for
    // fixtures, so this is not a claim about a trusted durable production store.
    commit_state: "source_acknowledged",
    allocation_assurance: "fixture_source_acknowledged",
    production_ready: false,
    execution_authority: false,
    lifecycle_authority: false,
  };
  return deepFreeze({
    ...allocationBasis,
    allocation_digest: hashCanonicalJson(allocationBasis),
  });
}

function normalizeBootstrapReceiptAllocation(input, label) {
  assertNoPublicByteMaterial(input, label);
  assertClosedObject(input, label, BOOTSTRAP_RECEIPT_ALLOCATION_FIELDS);
  const normalizedBasis = {
    allocator_id: assertIdentifier(input.allocator_id, `${label}.allocator_id`),
    bootstrap_grant_projection_digest: assertDigest(
      input.bootstrap_grant_projection_digest,
      `${label}.bootstrap_grant_projection_digest`,
    ),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    operation_id: assertIdentifier(input.operation_id, `${label}.operation_id`),
    operation_digest: assertDigest(input.operation_digest, `${label}.operation_digest`),
    decoded_payload_digest: assertDigest(
      input.decoded_payload_digest,
      `${label}.decoded_payload_digest`,
    ),
    invariant_witness_ref: normalizeOpaqueRef(
      input.invariant_witness_ref,
      `${label}.invariant_witness_ref`,
      { prefix: "bootstrap-invariant-witness" },
    ),
    invariant_witness_digest: assertDigest(
      input.invariant_witness_digest,
      `${label}.invariant_witness_digest`,
    ),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    enrollment_candidate_ref: normalizeOpaqueRef(
      input.enrollment_candidate_ref,
      `${label}.enrollment_candidate_ref`,
      { prefix: "enrollment-candidate" },
    ),
    observed_at: assertCanonicalTimestamp(input.observed_at, `${label}.observed_at`),
  };
  const expected = buildBootstrapReceiptAllocation(normalizedBasis);
  for (const field of BOOTSTRAP_RECEIPT_ALLOCATION_FIELDS) {
    if (input[field] !== expected[field]) {
      throw new Error(`${label}.${field} is detached from its content-addressed allocation`);
    }
  }
  return expected;
}

function allocateChameleonBootstrapResponseReceipt(
  decodedPayloadInput,
  invariantWitnessInput,
  grantProjection,
  allocatorInput,
) {
  if (arguments.length !== 4) {
    throw new Error("bootstrap response receipt allocation accepts exactly four bound inputs");
  }
  const allocatorState = allocatorInput == null
    ? null
    : BOOTSTRAP_RECEIPT_ALLOCATOR_STATE.get(allocatorInput);
  if (!allocatorInput || !BOOTSTRAP_RECEIPT_ALLOCATORS.has(allocatorInput) || !allocatorState) {
    throw new Error("bootstrap receipt allocator must be configured by the provider runtime");
  }
  const decoded = require("./bootstrap-response-payloads.js")
    .assertChameleonBootstrapDecodedPayload(decodedPayloadInput);
  const witness = assertBootstrapInvariantWitness(invariantWitnessInput);
  const grant = assertBootstrapGrantProjection(grantProjection, { live: false });
  if (ALLOCATED_BOOTSTRAP_DECODED_PAYLOADS.has(decoded)) {
    throw new Error("source-owned decoded bootstrap payload already has a receipt allocation");
  }
  for (const [field, expected] of Object.entries({
    bootstrap_grant_projection_digest: grant.bootstrap_grant_projection_digest,
    execution_request_digest: grant.execution_request_digest,
    operation_id: grant.operation_id,
    operation_digest: grant.operation_digest,
    decoded_payload_digest: decoded.decoded_payload_digest,
    instrument_ref: grant.instrument_ref,
    enrollment_candidate_ref: grant.enrollment_candidate_ref,
  })) {
    if (witness[field] !== expected) {
      throw new Error(`BootstrapInvariantWitness ${field} is detached from receipt allocation`);
    }
  }
  const prepared = buildBootstrapReceiptAllocation({
    allocator_id: allocatorInput.allocator_id,
    bootstrap_grant_projection_digest: grant.bootstrap_grant_projection_digest,
    execution_request_digest: grant.execution_request_digest,
    operation_id: grant.operation_id,
    operation_digest: grant.operation_digest,
    decoded_payload_digest: decoded.decoded_payload_digest,
    invariant_witness_ref: witness.witness_ref,
    invariant_witness_digest: witness.witness_digest,
    instrument_ref: grant.instrument_ref,
    enrollment_candidate_ref: grant.enrollment_candidate_ref,
    observed_at: witness.observed_at,
  });
  if (callSynchronous(
    allocatorState.commit_allocation,
    "bootstrap receipt allocation commit",
    prepared,
  ) !== true) {
    throw new Error("bootstrap response receipt allocation was not acknowledged by its source");
  }
  const resolvedInput = callSynchronous(
    allocatorState.resolve_committed_allocation,
    "bootstrap committed receipt allocation resolver",
    prepared.receipt_ref,
  );
  const resolved = normalizeBootstrapReceiptAllocation(
    resolvedInput,
    "committed_bootstrap_receipt_allocation",
  );
  if (resolved.allocation_digest !== prepared.allocation_digest) {
    throw new Error("committed bootstrap receipt allocation did not resolve canonically");
  }
  COMMITTED_BOOTSTRAP_RECEIPT_ALLOCATIONS.add(resolved);
  ALLOCATED_BOOTSTRAP_DECODED_PAYLOADS.add(decoded);
  return resolved;
}

function assertCommittedBootstrapReceiptAllocation(value) {
  if (!value || !COMMITTED_BOOTSTRAP_RECEIPT_ALLOCATIONS.has(value)
      || !Object.isFrozen(value)) {
    throw new Error(
      "bootstrap receipt allocation must be source-acknowledged and canonically resolved",
    );
  }
  return value;
}

const RESPONSE_FIELDS_BY_OPERATION = Object.freeze({
  "instrument.inventory": Object.freeze(["model", "application_version", "git_revision"]),
  "instrument.capabilities": Object.freeze(["reported_command_ids"]),
  "instrument.health": Object.freeze(["battery"]),
});

function normalizeBattery(input, label) {
  assertClosedObject(input, label, ["percent", "voltage_mv", "charging_state"]);
  if (input.charging_state !== "not_reported") {
    throw new Error(`${label}.charging_state must honestly report that firmware v2.2.0 omits charging state`);
  }
  return deepFreeze({
    percent: assertInteger(input.percent, `${label}.percent`, { min: 0, max: 100 }),
    voltage_mv: assertInteger(input.voltage_mv, `${label}.voltage_mv`, { min: 0, max: 10_000 }),
    charging_state: "not_reported",
  });
}

function normalizeChameleonBootstrapResponse(
  decodedPayloadInput,
  receiptAllocationInput,
  invariantWitnessInput,
  grantProjection,
  label = "chameleon_bootstrap_response",
) {
  if (arguments.length < 4 || arguments.length > 5) {
    throw new Error(
      "bootstrap response normalization accepts decoded payload, receipt allocation, invariant witness, and grant only",
    );
  }
  // The effect has already occurred when a response is normalized. Preserve a
  // valid in-window receipt even if authority expires or is revoked after the
  // pre-effect compilation fence.
  // Lazy loading is deliberate: bootstrap-response-payloads imports the closed
  // compiler from this module, so a top-level assertion import would form a
  // partially initialized CommonJS cycle.
  const decoded = require("./bootstrap-response-payloads.js")
    .assertChameleonBootstrapDecodedPayload(decodedPayloadInput);
  const allocation = assertCommittedBootstrapReceiptAllocation(receiptAllocationInput);
  const witness = assertBootstrapInvariantWitness(invariantWitnessInput);
  const grant = assertBootstrapGrantProjection(grantProjection, { live: false });
  const variantFields = RESPONSE_FIELDS_BY_OPERATION[grant.operation_id];
  if (!variantFields) throw new Error(`${label}.operation_id is outside the closed bootstrap set`);

  for (const [artifactLabel, artifact, bindings] of [
    ["source-owned decoded payload", decoded, {
      bootstrap_grant_projection_digest: grant.bootstrap_grant_projection_digest,
      execution_request_digest: grant.execution_request_digest,
      operation_id: grant.operation_id,
      operation_digest: grant.operation_digest,
    }],
    ["BootstrapInvariantWitness", witness, {
      bootstrap_grant_projection_digest: grant.bootstrap_grant_projection_digest,
      execution_request_digest: grant.execution_request_digest,
      operation_id: grant.operation_id,
      operation_digest: grant.operation_digest,
      command_set_digest: grant.command_set_digest,
      decoded_payload_digest: decoded.decoded_payload_digest,
      instrument_ref: grant.instrument_ref,
      enrollment_candidate_ref: grant.enrollment_candidate_ref,
    }],
    ["source-acknowledged receipt allocation", allocation, {
      bootstrap_grant_projection_digest: grant.bootstrap_grant_projection_digest,
      execution_request_digest: grant.execution_request_digest,
      operation_id: grant.operation_id,
      operation_digest: grant.operation_digest,
      decoded_payload_digest: decoded.decoded_payload_digest,
      invariant_witness_ref: witness.witness_ref,
      invariant_witness_digest: witness.witness_digest,
      instrument_ref: grant.instrument_ref,
      enrollment_candidate_ref: grant.enrollment_candidate_ref,
      observed_at: witness.observed_at,
    }],
  ]) {
    for (const [field, expected] of Object.entries(bindings)) {
      if (artifact[field] !== expected) {
        throw new Error(`${artifactLabel} ${field} is detached from the normalized response`);
      }
    }
  }
  for (const field of [
    "bootstrap_grant_projection_digest",
    "execution_request_digest",
    "operation_id",
    "operation_digest",
  ]) {
    if (decoded[field] !== grant[field]) {
      throw new Error(`${label}.${field} is detached from its grant`);
    }
  }
  const commandIds = normalizeCommandIds(
    decoded.command_ids,
    `${label}.decoded_payload.command_ids`,
    { minEntries: 1 },
  );
  assertExactArray(commandIds, grant.command_ids, `${label}.command_ids`);
  if (Date.parse(witness.observed_at) < Date.parse(grant.not_before)
      || Date.parse(witness.observed_at) >= Date.parse(grant.expires_at)) {
    throw new Error(`${label}.observed_at is outside the bootstrap grant window`);
  }
  assertClosedObject(decoded.response_fields, `${label}.decoded_payload.response_fields`, variantFields);

  const normalized = {
    version: BOOTSTRAP_SCHEMA_VERSION,
    provider_id: PROVIDER_ID,
    bootstrap_grant_projection_digest: grant.bootstrap_grant_projection_digest,
    signed_grant_digest: grant.signed_grant_digest,
    core_grant_projection_digest: grant.core_grant_projection_digest,
    replay_reservation_receipt_digest: grant.replay_reservation_receipt_digest,
    execution_request_digest: grant.execution_request_digest,
    operation_id: grant.operation_id,
    operation_digest: grant.operation_digest,
    command_ids: commandIds,
    command_set_digest: grant.command_set_digest,
    decoded_payload_digest: decoded.decoded_payload_digest,
    decoded_payload_profile_id: decoded.payload_profile_id,
    compiled_operation_digest: decoded.compiled_operation_digest,
    instrument_ref: grant.instrument_ref,
    enrollment_candidate_ref: grant.enrollment_candidate_ref,
    observation_ref: allocation.observation_ref,
    observation_digest: allocation.observation_digest,
    receipt_ref: allocation.receipt_ref,
    receipt_digest: allocation.receipt_digest,
    receipt_allocation_digest: allocation.allocation_digest,
    receipt_allocation_assurance: allocation.allocation_assurance,
    invariant_witness_ref: witness.witness_ref,
    invariant_witness_digest: witness.witness_digest,
    invariant_witness_projection_digest: witness.witness_projection_digest,
    invariant_witness_principal_id: witness.witness_principal_id,
    observed_at: witness.observed_at,
    assurance_claims: CHAMELEON_BOOTSTRAP_ASSURANCE_CLAIMS,
    invariants: deepFreeze({
      rf_invariant_verdict: witness.rf_invariant_verdict,
      rf_state_before: "not_observed",
      rf_state_after: "not_observed",
      rf_remained_off: null,
      mode_invariant_verdict: witness.mode_invariant_verdict,
      mode_state_before_digest: null,
      mode_state_after_digest: null,
      mode_unchanged: null,
      workspace_invariant_verdict: witness.workspace_invariant_verdict,
      workspace_write_count: 0,
      workspace_unchanged: true,
      independent_observation_hil_status: witness.independent_observation_hil_status,
      production_ready: false,
    }),
    production_readiness_blockers: Object.freeze([
      "independent_rf_observation_hil_not_performed",
      "device_mode_not_observed_get_device_mode_not_allowlisted",
      "durable_receipt_store_not_authenticated",
      "durable_bootstrap_attempt_dispatch_binding_absent",
      "usb_connection_generation_binding_absent",
    ]),
    production_ready: false,
    execution_authority: false,
    lifecycle_authority: false,
  };

  if (grant.operation_id === "instrument.inventory") {
    normalized.model = assertSelfReportedText(decoded.response_fields.model, `${label}.model`, 96);
    normalized.application_version = assertSelfReportedText(
      decoded.response_fields.application_version,
      `${label}.application_version`,
      128,
    );
    normalized.git_revision = assertSelfReportedText(
      decoded.response_fields.git_revision,
      `${label}.git_revision`,
      128,
    );
  } else if (grant.operation_id === "instrument.capabilities") {
    normalized.reported_command_ids = normalizeCommandIds(
      decoded.response_fields.reported_command_ids,
      `${label}.reported_command_ids`,
    );
    normalized.bootstrap_allowlisted_reported_command_ids = Object.freeze(
      normalized.reported_command_ids.filter((commandId) => (
        CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST.includes(commandId)
      )),
    );
    normalized.unrecognized_reported_command_count = normalized.reported_command_ids.length
      - normalized.bootstrap_allowlisted_reported_command_ids.length;
  } else {
    normalized.battery = normalizeBattery(decoded.response_fields.battery, `${label}.battery`);
  }

  const frozen = deepFreeze(normalized);
  return deepFreeze({ ...frozen, response_digest: hashCanonicalJson(frozen) });
}

module.exports = {
  BOOTSTRAP_ASSURANCE_PROFILE_ID,
  BOOTSTRAP_INVARIANT_WITNESS_DOMAIN,
  BOOTSTRAP_INVARIANT_WITNESS_KEY_USAGE,
  BOOTSTRAP_INVARIANTS_DIGEST,
  CHAMELEON_BOOTSTRAP_ASSURANCE_CLAIMS,
  CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST,
  CHAMELEON_BOOTSTRAP_FORBIDDEN_REQUEST_FIELDS,
  CHAMELEON_BOOTSTRAP_MANIFEST,
  CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY,
  allocateChameleonBootstrapResponseReceipt,
  assertCompiledChameleonBootstrapOperation,
  bootstrapInvariantWitnessSignatureInputDigest,
  compileChameleonBootstrapOperation,
  createChameleonBootstrapGrantAttenuator,
  createChameleonBootstrapInvariantWitnessVerifier,
  createChameleonBootstrapReceiptAllocator,
  normalizeChameleonBootstrapRequest,
  normalizeChameleonBootstrapResponse,
  projectChameleonBootstrapGrant,
  verifyChameleonBootstrapInvariantWitness,
};
