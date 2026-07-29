"use strict";

// A provider-side, synchronous liveness capability for the final effect seam.
// Active ports retain a verified grant/verifier pair in private state and
// revalidate current scope, trust, revocation, epoch, and time on every use.
// Mock ports are restricted to deterministic_* provider IDs and exist only so
// hardware-free ABI/conformance fixtures can exercise the same store contract.

const {
  PHYSICAL_GRANT_TRUSTED_CLOCK_MODES,
  assertVerifiedActivePhysicalExecutionGrant,
  normalizeActiveExecutionLineage,
  normalizeMcpPhysicalExecutionRequest,
} = require("./physical-authority.js");
const {
  normalizeOpaqueRef,
} = require("./physical-quantities.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");

const DISPATCH_AUTHORITY_VERSION = 1;
const DETERMINISTIC_TEST_CLOCK_MODE = "deterministic_test_clock";
// This is an exact, closed test-provider registry. Provider names that merely
// resemble the deterministic implementation never inherit its clock policy.
const DETERMINISTIC_ACTIVE_PROVIDER_IDS = Object.freeze(["deterministic_mock"]);
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const DETERMINISTIC_PROVIDER_PATTERN = /^deterministic_[a-z0-9._-]{1,113}$/;
const PORTS = new WeakSet();
const PORT_STATE = new WeakMap();
const EXECUTION_CLAIMS = new WeakSet();
const EXECUTION_CLAIM_STATE = new WeakMap();

const ASSERTION_FIELDS = Object.freeze([
  "session_nucleus_hash",
  "signed_grant_digest",
  "execution_request_digest",
  "experiment_plan_hash",
  "execution_lineage_digest",
  "execution_principal_id",
  "attempt_ref",
  "instrument_ref",
  "lease_id",
  "fencing_token",
  "fencing_generation",
  "operation_id",
  "provider_id",
  "provider_descriptor_digest",
  "effect_not_before",
  "effect_deadline",
]);
const ACTIVE_EXPECTED_BINDING_FIELDS = Object.freeze([
  "execution_request_digest",
  "authority_resolution_digest",
  "execution_principal_id",
  "provider_id",
  "provider_descriptor_digest",
  "instrument_ref",
  "operation_id",
  "operation_digest",
  "attempt_id",
  "experiment_plan_hash",
  "execution_lineage_digest",
  "lease_id",
  "fencing_token",
  "fencing_generation",
  "resource_bundle_digest",
]);
const ACTIVE_EXECUTION_LINEAGE_ASSERTION_FIELDS = Object.freeze([
  "compiler_id",
  "compiler_manifest_digest",
  "compiler_registry_digest",
  "compiled_command_id",
  "compiled_command_capability_digest",
  "compiled_operation_digest",
  "provider_command_ref",
  "command_input_ref",
  "command_input_digest",
  "maximum_response_bytes",
  "vault_reservation_handle",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
  "vault_byte_limit",
  "worker_bundle_digest",
  "worker_launch_profile_digest",
  "worker_fence_plan_digest",
  "transport_profile_digest",
  "durable_exchange_plan_digest",
  "terminal_receipt_recipient_digest",
  "safety_supervisor_plan_digest",
]);
// These fields are already part of the normalized active request and therefore
// transitively covered by execution_request_digest. Preserve them explicitly
// at the final dispatch seam so a composition root can prove which physical
// pack/cell/availability decision, inventory posture, principals, workspace,
// observers, controls, and cleanup plan the signed request authorized. Merely
// presenting the signed digest is not enough for a downstream component to
// perform those exact semantic joins without re-accepting caller metadata.
const ACTIVE_ADMISSION_ASSERTION_FIELDS = Object.freeze([
  "physical_scope_axis_digest",
  "physical_scope_policy_id",
  "physical_scope_policy_digest",
  "physical_scope_projection_digest",
  "authority_epoch",
  "revocation_generation",
  "authority_resolution_digest",
  "caller_role_id",
  "requester_principal_id",
  "ipc_peer_principal_id",
  "capability_pack_id",
  "capability_pack_version",
  "capability_pack_digest",
  "technique_cell_id",
  "inventory_observation_ref",
  "inventory_observation_digest",
  "assurance_profile_id",
  "assurance_claims_digest",
  "provider_manifest_digest",
  "availability_variant_id",
  "availability_variant_digest",
  "authorized_transition_set_digest",
  "workspace_snapshot_ref",
  "workspace_snapshot_digest",
  "observer_plan_digest",
  "control_plan_digest",
  "cleanup_plan_digest",
]);
const EXECUTION_ASSERTION_FIELDS = Object.freeze([
  ...ASSERTION_FIELDS,
  "session_id",
  "node_id",
  "contract_hash",
  "prep_token_hash",
  "dispatch_event_id",
  "graph_context_hash",
  "resource_bundle_digest",
  "operation_digest",
  "parameter_digest",
  "requested_effects_digest",
  ...ACTIVE_ADMISSION_ASSERTION_FIELDS,
  ...ACTIVE_EXECUTION_LINEAGE_ASSERTION_FIELDS,
]);

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, fields) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set(fields);
  const unknown = keys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = fields.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
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

function assertToken(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 191
      || !/^[A-Za-z0-9][A-Za-z0-9._:@-]*$/.test(value)) {
    throw new Error(`${label} must be a bounded opaque token`);
  }
  return value;
}

function assertInteger(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${label} must be a safe integer >= ${minimum}`);
  }
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  return value;
}

function normalizeAssertion(input, label = "physical_dispatch_authority_assertion") {
  assertClosedObject(input, label, ASSERTION_FIELDS);
  const effectNotBefore = assertTimestamp(input.effect_not_before, `${label}.effect_not_before`);
  const effectDeadline = assertTimestamp(input.effect_deadline, `${label}.effect_deadline`);
  if (Date.parse(effectNotBefore) >= Date.parse(effectDeadline)) {
    throw new Error(`${label} effect window is empty`);
  }
  const normalized = Object.freeze({
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    signed_grant_digest: assertDigest(input.signed_grant_digest, `${label}.signed_grant_digest`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    experiment_plan_hash: assertDigest(
      input.experiment_plan_hash,
      `${label}.experiment_plan_hash`,
    ),
    execution_lineage_digest: assertDigest(
      input.execution_lineage_digest,
      `${label}.execution_lineage_digest`,
    ),
    execution_principal_id: normalizeOpaqueRef(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      { prefix: "principal" },
    ),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, {
      prefix: "attempt",
    }),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(
      input.fencing_generation,
      `${label}.fencing_generation`,
      1,
    ),
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    effect_not_before: effectNotBefore,
    effect_deadline: effectDeadline,
  });
  return normalized;
}

function normalizeExecutionAssertion(
  input,
  label = "physical_dispatch_execution_authority_assertion",
) {
  assertClosedObject(input, label, EXECUTION_ASSERTION_FIELDS);
  const base = normalizeAssertion(
    Object.fromEntries(ASSERTION_FIELDS.map((field) => [field, input[field]])),
    label,
  );
  const maximumResponseBytes = assertInteger(
    input.maximum_response_bytes,
    `${label}.maximum_response_bytes`,
    1,
  );
  const vaultByteLimit = assertInteger(
    input.vault_byte_limit,
    `${label}.vault_byte_limit`,
    1,
  );
  if (maximumResponseBytes > vaultByteLimit) {
    throw new Error(`${label} vault byte limit cannot strand the maximum response`);
  }
  const compiledCommandCapabilityDigest = assertDigest(
    input.compiled_command_capability_digest,
    `${label}.compiled_command_capability_digest`,
  );
  const commandInputDigest = assertDigest(
    input.command_input_digest,
    `${label}.command_input_digest`,
  );
  if (compiledCommandCapabilityDigest !== commandInputDigest) {
    throw new Error(`${label} command input must bind the exact compiled command capability`);
  }
  const normalized = Object.freeze({
    ...base,
    session_id: assertToken(input.session_id, `${label}.session_id`),
    node_id: assertToken(input.node_id, `${label}.node_id`),
    contract_hash: assertDigest(input.contract_hash, `${label}.contract_hash`),
    prep_token_hash: assertDigest(input.prep_token_hash, `${label}.prep_token_hash`),
    dispatch_event_id: assertToken(input.dispatch_event_id, `${label}.dispatch_event_id`),
    graph_context_hash: assertDigest(input.graph_context_hash, `${label}.graph_context_hash`),
    resource_bundle_digest: assertDigest(
      input.resource_bundle_digest,
      `${label}.resource_bundle_digest`,
    ),
    operation_digest: assertDigest(input.operation_digest, `${label}.operation_digest`),
    parameter_digest: assertDigest(input.parameter_digest, `${label}.parameter_digest`),
    requested_effects_digest: assertDigest(
      input.requested_effects_digest,
      `${label}.requested_effects_digest`,
    ),
    physical_scope_axis_digest: assertDigest(
      input.physical_scope_axis_digest,
      `${label}.physical_scope_axis_digest`,
    ),
    physical_scope_policy_id: assertIdentifier(
      input.physical_scope_policy_id,
      `${label}.physical_scope_policy_id`,
    ),
    physical_scope_policy_digest: assertDigest(
      input.physical_scope_policy_digest,
      `${label}.physical_scope_policy_digest`,
    ),
    physical_scope_projection_digest: assertDigest(
      input.physical_scope_projection_digest,
      `${label}.physical_scope_projection_digest`,
    ),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
      0,
    ),
    authority_resolution_digest: assertDigest(
      input.authority_resolution_digest,
      `${label}.authority_resolution_digest`,
    ),
    caller_role_id: assertToken(input.caller_role_id, `${label}.caller_role_id`),
    requester_principal_id: normalizeOpaqueRef(
      input.requester_principal_id,
      `${label}.requester_principal_id`,
      { prefix: "principal" },
    ),
    ipc_peer_principal_id: normalizeOpaqueRef(
      input.ipc_peer_principal_id,
      `${label}.ipc_peer_principal_id`,
      { prefix: "principal" },
    ),
    capability_pack_id: assertToken(input.capability_pack_id, `${label}.capability_pack_id`),
    capability_pack_version: assertToken(
      input.capability_pack_version,
      `${label}.capability_pack_version`,
    ),
    capability_pack_digest: assertDigest(
      input.capability_pack_digest,
      `${label}.capability_pack_digest`,
    ),
    technique_cell_id: assertToken(input.technique_cell_id, `${label}.technique_cell_id`),
    inventory_observation_ref: normalizeOpaqueRef(
      input.inventory_observation_ref,
      `${label}.inventory_observation_ref`,
      { prefix: "inventory-observation" },
    ),
    inventory_observation_digest: assertDigest(
      input.inventory_observation_digest,
      `${label}.inventory_observation_digest`,
    ),
    assurance_profile_id: assertToken(
      input.assurance_profile_id,
      `${label}.assurance_profile_id`,
    ),
    assurance_claims_digest: assertDigest(
      input.assurance_claims_digest,
      `${label}.assurance_claims_digest`,
    ),
    provider_manifest_digest: assertDigest(
      input.provider_manifest_digest,
      `${label}.provider_manifest_digest`,
    ),
    availability_variant_id: assertToken(
      input.availability_variant_id,
      `${label}.availability_variant_id`,
    ),
    availability_variant_digest: assertDigest(
      input.availability_variant_digest,
      `${label}.availability_variant_digest`,
    ),
    authorized_transition_set_digest: assertDigest(
      input.authorized_transition_set_digest,
      `${label}.authorized_transition_set_digest`,
    ),
    workspace_snapshot_ref: normalizeOpaqueRef(
      input.workspace_snapshot_ref,
      `${label}.workspace_snapshot_ref`,
      { prefix: "workspace-snapshot" },
    ),
    workspace_snapshot_digest: assertDigest(
      input.workspace_snapshot_digest,
      `${label}.workspace_snapshot_digest`,
    ),
    observer_plan_digest: assertDigest(
      input.observer_plan_digest,
      `${label}.observer_plan_digest`,
    ),
    control_plan_digest: assertDigest(
      input.control_plan_digest,
      `${label}.control_plan_digest`,
    ),
    cleanup_plan_digest: assertDigest(
      input.cleanup_plan_digest,
      `${label}.cleanup_plan_digest`,
    ),
    compiler_id: assertIdentifier(input.compiler_id, `${label}.compiler_id`),
    compiler_manifest_digest: assertDigest(
      input.compiler_manifest_digest,
      `${label}.compiler_manifest_digest`,
    ),
    compiler_registry_digest: assertDigest(
      input.compiler_registry_digest,
      `${label}.compiler_registry_digest`,
    ),
    compiled_command_id: normalizeOpaqueRef(
      input.compiled_command_id,
      `${label}.compiled_command_id`,
      { prefix: "compiled-command" },
    ),
    compiled_command_capability_digest: compiledCommandCapabilityDigest,
    compiled_operation_digest: assertDigest(
      input.compiled_operation_digest,
      `${label}.compiled_operation_digest`,
    ),
    provider_command_ref: normalizeOpaqueRef(
      input.provider_command_ref,
      `${label}.provider_command_ref`,
      { prefix: "command" },
    ),
    command_input_ref: normalizeOpaqueRef(
      input.command_input_ref,
      `${label}.command_input_ref`,
      { prefix: "command-input" },
    ),
    command_input_digest: commandInputDigest,
    maximum_response_bytes: maximumResponseBytes,
    vault_reservation_handle: normalizeOpaqueRef(
      input.vault_reservation_handle,
      `${label}.vault_reservation_handle`,
      { prefix: "vault-reservation" },
    ),
    vault_reservation_digest: assertDigest(
      input.vault_reservation_digest,
      `${label}.vault_reservation_digest`,
    ),
    vault_ingest_capability_digest: assertDigest(
      input.vault_ingest_capability_digest,
      `${label}.vault_ingest_capability_digest`,
    ),
    vault_byte_limit: vaultByteLimit,
    worker_bundle_digest: assertDigest(
      input.worker_bundle_digest,
      `${label}.worker_bundle_digest`,
    ),
    worker_launch_profile_digest: assertDigest(
      input.worker_launch_profile_digest,
      `${label}.worker_launch_profile_digest`,
    ),
    worker_fence_plan_digest: assertDigest(
      input.worker_fence_plan_digest,
      `${label}.worker_fence_plan_digest`,
    ),
    transport_profile_digest: assertDigest(
      input.transport_profile_digest,
      `${label}.transport_profile_digest`,
    ),
    durable_exchange_plan_digest: assertDigest(
      input.durable_exchange_plan_digest,
      `${label}.durable_exchange_plan_digest`,
    ),
    terminal_receipt_recipient_digest: assertDigest(
      input.terminal_receipt_recipient_digest,
      `${label}.terminal_receipt_recipient_digest`,
    ),
    safety_supervisor_plan_digest: assertDigest(
      input.safety_supervisor_plan_digest,
      `${label}.safety_supervisor_plan_digest`,
    ),
  });
  normalizeActiveExecutionLineage({
    version: 1,
    ...Object.fromEntries(
      ACTIVE_EXECUTION_LINEAGE_ASSERTION_FIELDS.map((field) => [field, normalized[field]]),
    ),
    execution_lineage_digest: normalized.execution_lineage_digest,
  }, `${label}.execution_lineage`);
  return normalized;
}

function activeExecutionAssertion(grant, request) {
  const lineage = request.execution_lineage;
  return normalizeExecutionAssertion({
    session_nucleus_hash: grant.session_nucleus_hash,
    signed_grant_digest: grant.signed_grant_digest,
    execution_request_digest: grant.execution_request_digest,
    experiment_plan_hash: grant.experiment_plan_hash,
    execution_lineage_digest: grant.execution_lineage_digest,
    execution_principal_id: grant.execution_principal_id,
    attempt_ref: `attempt:${grant.attempt_id}`,
    instrument_ref: grant.instrument_ref,
    lease_id: grant.lease_id,
    fencing_token: grant.fencing_token,
    fencing_generation: grant.fencing_generation,
    operation_id: grant.operation_id,
    provider_id: grant.provider_id,
    provider_descriptor_digest: grant.provider_descriptor_digest,
    effect_not_before: request.not_before,
    effect_deadline: request.expires_at,
    session_id: request.session_id,
    node_id: request.node_id,
    contract_hash: request.contract_hash,
    prep_token_hash: request.prep_token_hash,
    dispatch_event_id: request.dispatch_event_id,
    graph_context_hash: request.graph_context_hash,
    resource_bundle_digest: request.resource_bundle_digest,
    operation_digest: grant.operation_digest,
    parameter_digest: request.parameter_digest,
    requested_effects_digest: request.requested_effects_digest,
    physical_scope_axis_digest: grant.physical_scope_axis_digest,
    physical_scope_policy_id: grant.physical_scope_policy_id,
    physical_scope_policy_digest: grant.physical_scope_policy_digest,
    physical_scope_projection_digest: grant.physical_scope_projection_digest,
    authority_epoch: request.authority_epoch,
    revocation_generation: request.revocation_generation,
    authority_resolution_digest: grant.authority_resolution_digest,
    caller_role_id: request.caller_role_id,
    requester_principal_id: request.requester_principal_id,
    ipc_peer_principal_id: request.ipc_peer_principal_id,
    capability_pack_id: request.capability_pack_id,
    capability_pack_version: request.capability_pack_version,
    capability_pack_digest: request.capability_pack_digest,
    technique_cell_id: request.technique_cell_id,
    inventory_observation_ref: request.inventory_observation_ref,
    inventory_observation_digest: request.inventory_observation_digest,
    assurance_profile_id: request.assurance_profile_id,
    assurance_claims_digest: request.assurance_claims_digest,
    provider_manifest_digest: request.provider_manifest_digest,
    availability_variant_id: request.availability_variant_id,
    availability_variant_digest: request.availability_variant_digest,
    authorized_transition_set_digest: request.authorized_transition_set_digest,
    workspace_snapshot_ref: request.workspace_snapshot_ref,
    workspace_snapshot_digest: request.workspace_snapshot_digest,
    observer_plan_digest: request.observer_plan_digest,
    control_plan_digest: request.control_plan_digest,
    cleanup_plan_digest: request.cleanup_plan_digest,
    compiler_id: lineage.compiler_id,
    compiler_manifest_digest: lineage.compiler_manifest_digest,
    compiler_registry_digest: lineage.compiler_registry_digest,
    compiled_command_id: lineage.compiled_command_id,
    compiled_command_capability_digest: lineage.compiled_command_capability_digest,
    compiled_operation_digest: lineage.compiled_operation_digest,
    provider_command_ref: lineage.provider_command_ref,
    command_input_ref: lineage.command_input_ref,
    command_input_digest: lineage.command_input_digest,
    maximum_response_bytes: lineage.maximum_response_bytes,
    vault_reservation_handle: lineage.vault_reservation_handle,
    vault_reservation_digest: lineage.vault_reservation_digest,
    vault_ingest_capability_digest: lineage.vault_ingest_capability_digest,
    vault_byte_limit: lineage.vault_byte_limit,
    worker_bundle_digest: lineage.worker_bundle_digest,
    worker_launch_profile_digest: lineage.worker_launch_profile_digest,
    worker_fence_plan_digest: lineage.worker_fence_plan_digest,
    transport_profile_digest: lineage.transport_profile_digest,
    durable_exchange_plan_digest: lineage.durable_exchange_plan_digest,
    terminal_receipt_recipient_digest: lineage.terminal_receipt_recipient_digest,
    safety_supervisor_plan_digest: lineage.safety_supervisor_plan_digest,
  });
}

function createPort(mode, portId, publicBasis, state) {
  const trustedClockMode = publicBasis.trusted_clock_mode;
  if (!PHYSICAL_GRANT_TRUSTED_CLOCK_MODES.includes(trustedClockMode)) {
    throw new Error("physical dispatch authority requires an explicit trusted clock mode");
  }
  const port = Object.freeze({
    version: DISPATCH_AUTHORITY_VERSION,
    port_id: assertIdentifier(portId, "physical_dispatch_authority_port.port_id"),
    authority_mode: mode,
    trusted_clock_mode: trustedClockMode,
    authority_binding_digest: hashCanonicalJson(publicBasis),
  });
  PORTS.add(port);
  PORT_STATE.set(port, Object.freeze(state));
  return port;
}

function createActivePhysicalDispatchAuthorityPort(input = {}) {
  assertClosedObject(input, "active_physical_dispatch_authority_port", [
    "port_id",
    "grant_projection",
    "grant_verifier",
    "expected_grant_bindings",
    "execution_request",
    "effect_registry",
  ]);
  const grant = assertVerifiedActivePhysicalExecutionGrant(
    input.grant_projection,
    input.grant_verifier,
    input.expected_grant_bindings,
  );
  if (grant.trusted_clock_mode === DETERMINISTIC_TEST_CLOCK_MODE
      && !DETERMINISTIC_ACTIVE_PROVIDER_IDS.includes(grant.provider_id)) {
    throw new Error(
      "active physical dispatch for a non-deterministic provider requires a signed trusted clock",
    );
  }
  const request = normalizeMcpPhysicalExecutionRequest(
    input.execution_request,
    input.effect_registry,
    { label: "active_physical_dispatch_authority_port.execution_request" },
  );
  if (request.grant_kind !== "active"
      || request.execution_request_digest !== grant.execution_request_digest) {
    throw new Error(
      "active physical dispatch authority requires the exact signed active execution request",
    );
  }
  const executionAssertion = activeExecutionAssertion(grant, request);
  const expectedGrantBindings = Object.freeze(Object.fromEntries(
    ACTIVE_EXPECTED_BINDING_FIELDS.map((field) => [field, grant[field]]),
  ));
  const publicBasis = {
    version: DISPATCH_AUTHORITY_VERSION,
    authority_mode: "active",
    signed_grant_digest: grant.signed_grant_digest,
    execution_request_digest: grant.execution_request_digest,
    experiment_plan_hash: grant.experiment_plan_hash,
    execution_lineage_digest: grant.execution_lineage_digest,
    session_nucleus_hash: grant.session_nucleus_hash,
    trusted_clock_mode: grant.trusted_clock_mode,
  };
  return createPort("active", input.port_id, publicBasis, {
    mode: "active",
    grant_projection: input.grant_projection,
    grant_verifier: input.grant_verifier,
    expected_grant_bindings: expectedGrantBindings,
    execution_assertion: executionAssertion,
    claim_state: { in_flight: false, claimed: false, claim: null },
  });
}

function createDeterministicMockDispatchAuthorityPort(input = {}) {
  const baseFields = [
    "port_id",
    "session_nucleus_hash",
    "provider_id",
    "provider_descriptor_digest",
    "execution_principal_id",
  ];
  const hasExecutionAssertion = Object.prototype.hasOwnProperty.call(
    input,
    "test_only_execution_assertion",
  );
  assertClosedObject(input, "deterministic_mock_dispatch_authority_port", hasExecutionAssertion
    ? [...baseFields, "test_only_execution_assertion"]
    : baseFields);
  const providerId = assertIdentifier(input.provider_id, "mock_dispatch_authority.provider_id");
  if (!DETERMINISTIC_PROVIDER_PATTERN.test(providerId)) {
    throw new Error("mock dispatch authority is restricted to deterministic_* provider IDs");
  }
  const binding = Object.freeze({
    session_nucleus_hash: assertDigest(
      input.session_nucleus_hash,
      "mock_dispatch_authority.session_nucleus_hash",
    ),
    provider_id: providerId,
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      "mock_dispatch_authority.provider_descriptor_digest",
    ),
    execution_principal_id: normalizeOpaqueRef(
      input.execution_principal_id,
      "mock_dispatch_authority.execution_principal_id",
      { prefix: "principal" },
    ),
  });
  const executionAssertion = hasExecutionAssertion
    ? normalizeExecutionAssertion(
      input.test_only_execution_assertion,
      "deterministic_mock_dispatch_authority_port.test_only_execution_assertion",
    )
    : null;
  if (executionAssertion != null) {
    for (const field of [
      "session_nucleus_hash",
      "provider_id",
      "provider_descriptor_digest",
      "execution_principal_id",
    ]) {
      if (executionAssertion[field] !== binding[field]) {
        throw new Error(`deterministic mock dispatch authority ${field} binding drift`);
      }
    }
  }
  return createPort("deterministic_mock", input.port_id, {
    version: DISPATCH_AUTHORITY_VERSION,
    authority_mode: "deterministic_mock",
    trusted_clock_mode: "deterministic_test_clock",
    ...binding,
  }, {
    mode: "deterministic_mock",
    binding,
    execution_assertion: executionAssertion,
    claim_state: { in_flight: false, claimed: false, claim: null },
  });
}

function assertPhysicalDispatchAuthorityPort(input) {
  if (!input || !PORTS.has(input) || !PORT_STATE.has(input)) {
    throw new Error("physical dispatch authority port must be created by Bob's authority factory");
  }
  return input;
}

function assertCurrentPhysicalDispatchAuthority(portInput, assertionInput) {
  const port = assertPhysicalDispatchAuthorityPort(portInput);
  const state = PORT_STATE.get(port);
  const assertion = normalizeAssertion(assertionInput);
  if (state.mode === "deterministic_mock") {
    for (const field of [
      "session_nucleus_hash",
      "provider_id",
      "provider_descriptor_digest",
      "execution_principal_id",
    ]) {
      if (assertion[field] !== state.binding[field]) {
        throw new Error(`deterministic mock dispatch authority ${field} binding drift`);
      }
    }
    return assertion;
  }
  const grant = assertVerifiedActivePhysicalExecutionGrant(
    state.grant_projection,
    state.grant_verifier,
    state.expected_grant_bindings,
  );
  if (grant.trusted_clock_mode !== port.trusted_clock_mode) {
    throw new Error("active physical dispatch authority trusted clock mode drift");
  }
  const exact = {
    session_nucleus_hash: grant.session_nucleus_hash,
    signed_grant_digest: grant.signed_grant_digest,
    execution_request_digest: grant.execution_request_digest,
    experiment_plan_hash: grant.experiment_plan_hash,
    execution_lineage_digest: grant.execution_lineage_digest,
    execution_principal_id: grant.execution_principal_id,
    attempt_ref: `attempt:${grant.attempt_id}`,
    instrument_ref: grant.instrument_ref,
    lease_id: grant.lease_id,
    fencing_token: grant.fencing_token,
    fencing_generation: grant.fencing_generation,
    operation_id: grant.operation_id,
    provider_id: grant.provider_id,
    provider_descriptor_digest: grant.provider_descriptor_digest,
  };
  for (const [field, expected] of Object.entries(exact)) {
    if (assertion[field] !== expected) {
      throw new Error(`active physical dispatch authority ${field} binding drift`);
    }
  }
  if (Date.parse(assertion.effect_not_before) < Date.parse(grant.not_before)
      || Date.parse(assertion.effect_deadline) > Date.parse(grant.expires_at)) {
    throw new Error("active physical dispatch authority effect window exceeds the signed grant");
  }
  return assertion;
}

function assertExactExecutionAuthority(port, state, assertionInput) {
  if (state.execution_assertion == null) {
    throw new Error(
      "deterministic mock dispatch authority has no explicit test-only execution assertion",
    );
  }
  const assertion = normalizeExecutionAssertion(assertionInput);
  assertCurrentPhysicalDispatchAuthority(
    port,
    Object.freeze(Object.fromEntries(
      ASSERTION_FIELDS.map((field) => [field, assertion[field]]),
    )),
  );
  for (const field of EXECUTION_ASSERTION_FIELDS) {
    if (assertion[field] !== state.execution_assertion[field]) {
      throw new Error(`${state.mode} physical dispatch execution authority ${field} binding drift`);
    }
  }
  return assertion;
}

function executionClaimBasis(port, assertion) {
  return {
    version: DISPATCH_AUTHORITY_VERSION,
    authority_mode: port.authority_mode,
    trusted_clock_mode: port.trusted_clock_mode,
    authority_port_id: port.port_id,
    signed_grant_digest: assertion.signed_grant_digest,
    execution_request_digest: assertion.execution_request_digest,
    experiment_plan_hash: assertion.experiment_plan_hash,
    execution_lineage_digest: assertion.execution_lineage_digest,
    session_id: assertion.session_id,
    session_nucleus_hash: assertion.session_nucleus_hash,
    execution_principal_id: assertion.execution_principal_id,
    attempt_ref: assertion.attempt_ref,
    node_id: assertion.node_id,
    contract_hash: assertion.contract_hash,
    prep_token_hash: assertion.prep_token_hash,
    dispatch_event_id: assertion.dispatch_event_id,
    graph_context_hash: assertion.graph_context_hash,
    resource_bundle_digest: assertion.resource_bundle_digest,
    instrument_ref: assertion.instrument_ref,
    operation_id: assertion.operation_id,
    operation_digest: assertion.operation_digest,
    parameter_digest: assertion.parameter_digest,
    requested_effects_digest: assertion.requested_effects_digest,
    physical_scope_axis_digest: assertion.physical_scope_axis_digest,
    physical_scope_policy_id: assertion.physical_scope_policy_id,
    physical_scope_policy_digest: assertion.physical_scope_policy_digest,
    physical_scope_projection_digest: assertion.physical_scope_projection_digest,
    authority_epoch: assertion.authority_epoch,
    revocation_generation: assertion.revocation_generation,
    authority_resolution_digest: assertion.authority_resolution_digest,
    caller_role_id: assertion.caller_role_id,
    requester_principal_id: assertion.requester_principal_id,
    ipc_peer_principal_id: assertion.ipc_peer_principal_id,
    capability_pack_id: assertion.capability_pack_id,
    capability_pack_version: assertion.capability_pack_version,
    capability_pack_digest: assertion.capability_pack_digest,
    technique_cell_id: assertion.technique_cell_id,
    inventory_observation_ref: assertion.inventory_observation_ref,
    inventory_observation_digest: assertion.inventory_observation_digest,
    assurance_profile_id: assertion.assurance_profile_id,
    assurance_claims_digest: assertion.assurance_claims_digest,
    provider_manifest_digest: assertion.provider_manifest_digest,
    availability_variant_id: assertion.availability_variant_id,
    availability_variant_digest: assertion.availability_variant_digest,
    authorized_transition_set_digest: assertion.authorized_transition_set_digest,
    workspace_snapshot_ref: assertion.workspace_snapshot_ref,
    workspace_snapshot_digest: assertion.workspace_snapshot_digest,
    observer_plan_digest: assertion.observer_plan_digest,
    control_plan_digest: assertion.control_plan_digest,
    cleanup_plan_digest: assertion.cleanup_plan_digest,
    compiler_id: assertion.compiler_id,
    compiler_manifest_digest: assertion.compiler_manifest_digest,
    compiler_registry_digest: assertion.compiler_registry_digest,
    compiled_command_id: assertion.compiled_command_id,
    compiled_command_capability_digest: assertion.compiled_command_capability_digest,
    compiled_operation_digest: assertion.compiled_operation_digest,
    provider_command_ref: assertion.provider_command_ref,
    command_input_ref: assertion.command_input_ref,
    command_input_digest: assertion.command_input_digest,
    maximum_response_bytes: assertion.maximum_response_bytes,
    vault_reservation_handle: assertion.vault_reservation_handle,
    vault_reservation_digest: assertion.vault_reservation_digest,
    vault_ingest_capability_digest: assertion.vault_ingest_capability_digest,
    vault_byte_limit: assertion.vault_byte_limit,
    worker_bundle_digest: assertion.worker_bundle_digest,
    worker_launch_profile_digest: assertion.worker_launch_profile_digest,
    worker_fence_plan_digest: assertion.worker_fence_plan_digest,
    transport_profile_digest: assertion.transport_profile_digest,
    durable_exchange_plan_digest: assertion.durable_exchange_plan_digest,
    terminal_receipt_recipient_digest: assertion.terminal_receipt_recipient_digest,
    safety_supervisor_plan_digest: assertion.safety_supervisor_plan_digest,
    provider_id: assertion.provider_id,
    provider_descriptor_digest: assertion.provider_descriptor_digest,
    lease_id: assertion.lease_id,
    fencing_token_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-dispatch-authority-fencing-token/v1",
      fencing_token: assertion.fencing_token,
    }),
    fencing_generation: assertion.fencing_generation,
    effect_not_before: assertion.effect_not_before,
    effect_deadline: assertion.effect_deadline,
  };
}

function projectCurrentPhysicalDispatchExecutionAuthority(portInput) {
  const port = assertPhysicalDispatchAuthorityPort(portInput);
  const state = PORT_STATE.get(port);
  const assertion = assertExactExecutionAuthority(port, state, state.execution_assertion);
  return Object.freeze({
    ...executionClaimBasis(port, assertion),
    authority_projection_digest: hashCanonicalJson(executionClaimBasis(port, assertion)),
  });
}

function claimPhysicalDispatchExecutionAuthority(portInput) {
  const port = assertPhysicalDispatchAuthorityPort(portInput);
  const state = PORT_STATE.get(port);
  const claimState = state.claim_state;
  if (claimState.claimed || claimState.in_flight) {
    throw new Error("physical dispatch execution authority was already claimed");
  }
  claimState.in_flight = true;
  try {
    // The exact assertion, including the raw fencing token, is retained by the
    // branded port. Claimants cannot inject or extract it.
    const assertion = assertExactExecutionAuthority(port, state, state.execution_assertion);
    const basis = executionClaimBasis(port, assertion);
    const claim = Object.freeze({
      ...basis,
      authority_claim_digest: hashCanonicalJson(basis),
    });
    EXECUTION_CLAIMS.add(claim);
    EXECUTION_CLAIM_STATE.set(claim, Object.freeze({
      port,
      assertion,
      ownership: { owner: null },
    }));
    claimState.claim = claim;
    claimState.claimed = true;
    return claim;
  } finally {
    claimState.in_flight = false;
  }
}

function takePhysicalDispatchExecutionAuthorityClaimOwnership(claimInput, owner) {
  const claim = assertPhysicalDispatchExecutionAuthorityClaim(claimInput);
  if ((typeof owner !== "object" && typeof owner !== "function") || owner == null) {
    throw new Error("physical dispatch execution authority claim owner must be private identity");
  }
  const claimPrivate = EXECUTION_CLAIM_STATE.get(claim);
  if (claimPrivate.ownership.owner != null) {
    throw new Error("physical dispatch execution authority claim ownership was already transferred");
  }
  claimPrivate.ownership.owner = owner;
  return claim;
}

function assertPhysicalDispatchExecutionAuthorityClaim(claim) {
  const state = claim == null ? null : EXECUTION_CLAIM_STATE.get(claim);
  if (!claim || !Object.isFrozen(claim) || !EXECUTION_CLAIMS.has(claim) || !state) {
    throw new Error("physical dispatch execution authority claim is not privately branded");
  }
  const portState = PORT_STATE.get(state.port);
  if (!portState || portState.claim_state.claim !== claim
      || portState.claim_state.claimed !== true) {
    throw new Error("physical dispatch execution authority claim is no longer owned");
  }
  return claim;
}

function assertCurrentPhysicalDispatchExecutionAuthorityClaim(claimInput, owner) {
  const claim = assertPhysicalDispatchExecutionAuthorityClaim(claimInput);
  const claimPrivate = EXECUTION_CLAIM_STATE.get(claim);
  if (claimPrivate.ownership.owner == null || claimPrivate.ownership.owner !== owner) {
    throw new Error("physical dispatch execution authority claim is not owned by this consumer");
  }
  const portState = PORT_STATE.get(claimPrivate.port);
  const assertion = assertExactExecutionAuthority(
    claimPrivate.port,
    portState,
    claimPrivate.assertion,
  );
  const basis = executionClaimBasis(claimPrivate.port, assertion);
  if (hashCanonicalJson(basis) !== claim.authority_claim_digest) {
    throw new Error("physical dispatch execution authority claim binding drift");
  }
  return claim;
}

module.exports = {
  DETERMINISTIC_ACTIVE_PROVIDER_IDS,
  PHYSICAL_DISPATCH_AUTHORITY_VERSION: DISPATCH_AUTHORITY_VERSION,
  assertCurrentPhysicalDispatchAuthority,
  assertCurrentPhysicalDispatchExecutionAuthorityClaim,
  assertPhysicalDispatchExecutionAuthorityClaim,
  assertPhysicalDispatchAuthorityPort,
  claimPhysicalDispatchExecutionAuthority,
  createActivePhysicalDispatchAuthorityPort,
  createDeterministicMockDispatchAuthorityPort,
  projectCurrentPhysicalDispatchExecutionAuthority,
  takePhysicalDispatchExecutionAuthorityClaimOwnership,
};
