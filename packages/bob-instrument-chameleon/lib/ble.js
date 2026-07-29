"use strict";

// PH-P6 is deliberately a contract and conformance surface, not a BLE driver.
// Importing this module performs no discovery, opens no device, and loads no
// Bluetooth framework. The only executable vectors below use internally
// generated synthetic frames and never accept caller bytes, UUIDs, paths, or
// commands. A future native CoreBluetooth custodian must consume the same
// registry and authority bindings behind a separately privileged principal.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const {
  assertNoPublicByteMaterial,
} = require("../../bob-instrument-contracts/lib/instrument-provider-contract.js");
const {
  hashCanonicalJson,
} = require("../../bob-instrument-contracts/lib/verification-contracts.js");
const {
  ABSOLUTE_MAX_DATA_LENGTH,
  FIXED_FRAME_BYTES,
  SOF,
  SOF_LRC,
  calculateLrc,
  createFrameParser,
} = require("./codec.js");
const {
  CHAMELEON_SEMANTIC_MANIFEST,
  dependencyProofContract,
  getChameleonAvailabilityVariant,
  getChameleonCapability,
  getChameleonOperation,
} = require("./operations.js");

const BLE_NUS_TRANSPORT_VERSION = 1;
const BLE_NUS_TRANSPORT_ID = "ble_nus_v1";
const BLE_NUS_CAPABILITY_ID = "CU-TRANSPORT-BLE";
const BLE_NUS_ADMIN_CAPABILITY_ID = "CU-ADMIN-BLE-PAIRING";
const BLE_NUS_DEPENDENCY_REF = "transport:ble_nus_v1";
const USB_CDC_TRANSPORT_ID = "usb_cdc_acm_115200_dtr_v1";
const DISCONNECTED_TRANSPORT_ID = "disconnected";
const BLE_NUS_ENDPOINT_KIND = "corebluetooth_service_characteristic";
const BLE_NUS_SERVICE_UUID = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
const BLE_NUS_RX_CHARACTERISTIC_UUID = "6e400002-b5a3-f393-e0a9-e50e24dcca9e";
const BLE_NUS_TX_CHARACTERISTIC_UUID = "6e400003-b5a3-f393-e0a9-e50e24dcca9e";
const BLE_NUS_AUTHORITY_ASSURANCE = "caller_supplied_inert_conformance_fixture";
const BLE_NUS_MINIMUM_ATT_MTU = 23;
const BLE_NUS_MAXIMUM_ATT_MTU = 517;
const BLE_ATT_VALUE_OVERHEAD_BYTES = 3;
const MAX_UINT64 = (1n << 64n) - 1n;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const OPAQUE_REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}$/u;

const BLE_NUS_READINESS_BLOCKERS = Object.freeze([
  "native_corebluetooth_custody_not_implemented",
  "dedicated_privileged_ble_principal_not_enrolled",
  "durable_ble_identity_and_bond_store_not_implemented",
  "signed_current_pairing_posture_verifier_not_implemented",
  "broker_lineage_to_native_ble_fence_not_implemented",
  "rf_off_ble_nus_hil_not_recorded",
  "usb_ble_safe_state_parity_hil_not_recorded",
  "usb_ble_target_effect_parity_deferred_to_ph_x5",
]);
const BLE_NUS_FORBIDDEN_ENDPOINT_KINDS = Object.freeze([
  "serial_path",
  "bluetooth_pseudo_serial",
  "iokit_tty",
  "usb_cdc_path",
]);
const AUTHORITY_BINDING_FIELDS = Object.freeze([
  "version",
  "broker_ref",
  "session_nucleus_hash",
  "execution_lineage_digest",
  "grant_envelope_digest",
  "grant_journal_entry_digest",
  "execution_claim_receipt_digest",
  "deadline_fence_receipt_digest",
  "task_id",
  "attempt_id",
  "lease_id",
  "resource_epoch",
  "resource_fence_digest",
  "effect_deadline_monotonic_ns",
  "worker_fence_digest",
  "transport_binding_digest",
  "authorized_transport_set_digest",
  "transport_switch_fence_digest",
  "device_enrollment_digest",
  "device_identity_digest",
  "authority_epoch",
  "revocation_generation",
]);
const CURRENT_AUTHORITY_FIELDS = Object.freeze([
  ...AUTHORITY_BINDING_FIELDS,
  "current_monotonic_ns",
  "trusted",
  "revoked",
  "lease_live",
  "resource_fence_live",
  "deadline_live",
  "transport_switch_allowed",
]);
const ENROLLMENT_FIELDS = Object.freeze([
  "version",
  "enrollment_id",
  "device_identity_digest",
  "peripheral_identifier_digest",
  "endpoint_kind",
  "identity_provenance",
]);
const PAIRING_POSTURE_FIELDS = Object.freeze([
  "version",
  "observation_ref",
  "device_identity_digest",
  "observed_at_monotonic_ns",
  "pairing_required",
  "link_encrypted",
  "bond_present",
  "enrolled_bond_match",
  "secure_connections",
]);
const SWITCH_PLAN_FIELDS = Object.freeze([
  "version",
  "authority_binding",
  "from_transport_id",
  "to_transport_id",
  "previous_connection_generation",
  "next_connection_generation",
  "previous_transport_terminal_state",
  "previous_transport_terminal_receipt_digest",
  "previous_transport_fence_digest",
  "outstanding_transaction_count",
]);
const CONFORMANCE_SESSION_FIELDS = Object.freeze([
  "version",
  "switch_plan",
  "enrollment",
  "pairing_posture",
  "negotiated_att_mtu",
]);
const CONFORMANCE_RUN_FIELDS = Object.freeze([
  "version",
  "vector_id",
  "fault",
]);
const CONFORMANCE_FAULT_VALUES = Object.freeze([
  "none",
  "drop_fragment",
  "duplicate_fragment",
  "reorder_fragments",
  "corrupt_fragment",
  "disconnect_after_fragment",
]);

const AUTHORITY_PORTS = new WeakSet();
const AUTHORITY_PORT_STATE = new WeakMap();
const ENROLLMENTS = new WeakSet();
const PAIRING_POSTURES = new WeakSet();
const SWITCH_PLANS = new WeakSet();
const SWITCH_PLAN_STATE = new WeakMap();
const CONFORMANCE_SESSIONS = new WeakSet();
const CONFORMANCE_SESSION_STATE = new WeakMap();
const CONFORMANCE_RESULTS = new WeakSet();

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value) || utilTypes.isPromise(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertExactDataObject(value, fields, label) {
  if (!isPlainObject(value)) throw new Error(`${label} must be a plain synchronous data object`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const unknown = keys.filter((field) => !fields.includes(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = fields.filter((field) => !Object.hasOwn(descriptors, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const field of keys) {
    const descriptor = descriptors[field];
    if (!descriptor || !Object.hasOwn(descriptor, "value") || !descriptor.enumerable) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
  }
  return descriptors;
}

function descriptorValue(descriptors, field) {
  return descriptors[field].value;
}

function assertVersion(value, label) {
  if (value !== BLE_NUS_TRANSPORT_VERSION) {
    throw new Error(`${label}.version must be ${BLE_NUS_TRANSPORT_VERSION}`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertOpaqueRef(value, label) {
  if (typeof value !== "string" || !OPAQUE_REF_PATTERN.test(value)) {
    throw new Error(`${label} must be a bounded opaque reference`);
  }
  return value;
}

function assertInteger(value, label, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function assertUint64(value, label) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/u.test(value)) {
    throw new Error(`${label} must be a canonical unsigned 64-bit decimal string`);
  }
  let parsed;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(`${label} must be a canonical unsigned 64-bit decimal string`);
  }
  if (parsed > MAX_UINT64) throw new Error(`${label} exceeds unsigned 64-bit range`);
  return value;
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} must be boolean`);
  return value;
}

function assertEnum(value, values, label) {
  if (typeof value !== "string" || !values.includes(value)) {
    throw new Error(`${label} is not a registered value`);
  }
  return value;
}

function rejectSerialization() {
  throw new Error("ble_nus_private_capability_not_serializable");
}

function sameValues(left, right) {
  return left.length === right.length
    && left.slice().sort().every((value, index) => value === right.slice().sort()[index]);
}

function buildRegistryContract() {
  const capability = getChameleonCapability(BLE_NUS_CAPABILITY_ID);
  const adminCapability = getChameleonCapability(BLE_NUS_ADMIN_CAPABILITY_ID);
  const variant = getChameleonAvailabilityVariant(BLE_NUS_CAPABILITY_ID, "default");
  const proof = dependencyProofContract(BLE_NUS_DEPENDENCY_REF);
  const expectedOperations = [
    "transport.connect",
    "transport.exchange",
    "transport.disconnect",
  ];
  if (!capability || capability.disposition !== "provider_internal"
      || capability.evaluator_callable !== false || capability.upstream_command_ids.length !== 0
      || !sameValues(capability.normalized_operations, expectedOperations)
      || !sameValues(capability.effect_profile_refs, ["EP-INSTRUMENT-TRANSMIT-BLE"])) {
    throw new Error("BLE NUS transport capability drifted from the reviewed registry");
  }
  if (!variant || variant.disposition !== "provider_internal"
      || !sameValues(variant.all_of, [BLE_NUS_DEPENDENCY_REF])
      || variant.any_of.length !== 0 || variant.technique_bindings.length !== 0
      || !sameValues(variant.normalized_operations, expectedOperations)
      || !sameValues(variant.effect_profile_refs, ["EP-INSTRUMENT-TRANSMIT-BLE"])) {
    throw new Error("BLE NUS availability formula drifted from the reviewed registry");
  }
  if (!proof || proof.provider_kind !== "transport"
      || proof.owner_principal !== "device_execution_worker") {
    throw new Error("BLE NUS proof-provider contract drifted from the reviewed registry");
  }
  if (!adminCapability || adminCapability.disposition !== "operator_only"
      || adminCapability.evaluator_callable !== false
      || adminCapability.data_class !== "credential_secret") {
    throw new Error("BLE pairing administration escaped its operator-only registry boundary");
  }
  const operations = expectedOperations.map((operationId) => {
    const operation = getChameleonOperation(operationId);
    if (!operation || operation.exposure !== "provider_private") {
      throw new Error(`BLE NUS operation ${operationId} is not provider-private`);
    }
    return operation;
  });
  const basis = {
    version: BLE_NUS_TRANSPORT_VERSION,
    provider_id: "chameleon_ultra",
    transport_id: BLE_NUS_TRANSPORT_ID,
    capability_id: BLE_NUS_CAPABILITY_ID,
    capability_coverage_row_digest: capability.coverage_row_digest,
    availability_variant_digest: variant.availability_variant_digest,
    dependency_ref: BLE_NUS_DEPENDENCY_REF,
    dependency_contract_digest: proof.contract_digest,
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    normalized_operations: operations,
    effect_profile_refs: ["EP-INSTRUMENT-TRANSMIT-BLE"],
    endpoint_kind: BLE_NUS_ENDPOINT_KIND,
    service_uuid: BLE_NUS_SERVICE_UUID,
    central_write_characteristic_uuid: BLE_NUS_RX_CHARACTERISTIC_UUID,
    peripheral_notify_characteristic_uuid: BLE_NUS_TX_CHARACTERISTIC_UUID,
    minimum_att_mtu: BLE_NUS_MINIMUM_ATT_MTU,
    maximum_att_mtu: BLE_NUS_MAXIMUM_ATT_MTU,
    att_value_overhead_bytes: BLE_ATT_VALUE_OVERHEAD_BYTES,
    codec_maximum_frame_bytes: FIXED_FRAME_BYTES + ABSOLUTE_MAX_DATA_LENGTH,
    evaluator_callable: false,
    raw_ble_surface_exposed: false,
    raw_frame_surface_exposed: false,
    arbitrary_uuid_surface_exposed: false,
    pairing_key_surface_exposed: false,
    bond_admin_surface_exposed: false,
    live_connect_exported: false,
    auto_connect: false,
    auto_reconnect: false,
    retry_after_ambiguous_write: false,
    bluetooth_pseudo_serial_allowed: false,
    authority_model: "broker_lineage_lease_resource_and_worker_fence_exact_revalidation",
    switching_model: "close_confirm_fence_then_increment_generation_preserving_lease",
    pairing_admin_capability_id: BLE_NUS_ADMIN_CAPABILITY_ID,
    pairing_admin_coverage_row_digest: adminCapability.coverage_row_digest,
    production_ready: false,
    execution_authority: false,
    hardware_access_authorized: false,
    readiness_blockers: BLE_NUS_READINESS_BLOCKERS,
  };
  return deepFreeze({
    ...basis,
    transport_contract_digest: hashCanonicalJson(basis),
  });
}

const BLE_NUS_TRANSPORT_CONTRACT = buildRegistryContract();

function bleNusTransportContract() {
  return BLE_NUS_TRANSPORT_CONTRACT;
}

function normalizeAuthorityBinding(input, label = "ble_nus_authority_binding") {
  const descriptors = assertExactDataObject(input, AUTHORITY_BINDING_FIELDS, label);
  const normalized = {
    version: assertVersion(descriptorValue(descriptors, "version"), label),
    broker_ref: assertOpaqueRef(descriptorValue(descriptors, "broker_ref"), `${label}.broker_ref`),
    session_nucleus_hash: assertDigest(
      descriptorValue(descriptors, "session_nucleus_hash"), `${label}.session_nucleus_hash`,
    ),
    execution_lineage_digest: assertDigest(
      descriptorValue(descriptors, "execution_lineage_digest"),
      `${label}.execution_lineage_digest`,
    ),
    grant_envelope_digest: assertDigest(
      descriptorValue(descriptors, "grant_envelope_digest"), `${label}.grant_envelope_digest`,
    ),
    grant_journal_entry_digest: assertDigest(
      descriptorValue(descriptors, "grant_journal_entry_digest"),
      `${label}.grant_journal_entry_digest`,
    ),
    execution_claim_receipt_digest: assertDigest(
      descriptorValue(descriptors, "execution_claim_receipt_digest"),
      `${label}.execution_claim_receipt_digest`,
    ),
    deadline_fence_receipt_digest: assertDigest(
      descriptorValue(descriptors, "deadline_fence_receipt_digest"),
      `${label}.deadline_fence_receipt_digest`,
    ),
    task_id: assertOpaqueRef(descriptorValue(descriptors, "task_id"), `${label}.task_id`),
    attempt_id: assertOpaqueRef(
      descriptorValue(descriptors, "attempt_id"), `${label}.attempt_id`,
    ),
    lease_id: assertOpaqueRef(descriptorValue(descriptors, "lease_id"), `${label}.lease_id`),
    resource_epoch: assertUint64(
      descriptorValue(descriptors, "resource_epoch"), `${label}.resource_epoch`,
    ),
    resource_fence_digest: assertDigest(
      descriptorValue(descriptors, "resource_fence_digest"), `${label}.resource_fence_digest`,
    ),
    effect_deadline_monotonic_ns: assertUint64(
      descriptorValue(descriptors, "effect_deadline_monotonic_ns"),
      `${label}.effect_deadline_monotonic_ns`,
    ),
    worker_fence_digest: assertDigest(
      descriptorValue(descriptors, "worker_fence_digest"), `${label}.worker_fence_digest`,
    ),
    transport_binding_digest: assertDigest(
      descriptorValue(descriptors, "transport_binding_digest"),
      `${label}.transport_binding_digest`,
    ),
    authorized_transport_set_digest: assertDigest(
      descriptorValue(descriptors, "authorized_transport_set_digest"),
      `${label}.authorized_transport_set_digest`,
    ),
    transport_switch_fence_digest: assertDigest(
      descriptorValue(descriptors, "transport_switch_fence_digest"),
      `${label}.transport_switch_fence_digest`,
    ),
    device_enrollment_digest: assertDigest(
      descriptorValue(descriptors, "device_enrollment_digest"),
      `${label}.device_enrollment_digest`,
    ),
    device_identity_digest: assertDigest(
      descriptorValue(descriptors, "device_identity_digest"), `${label}.device_identity_digest`,
    ),
    authority_epoch: assertInteger(
      descriptorValue(descriptors, "authority_epoch"), `${label}.authority_epoch`, 1,
    ),
    revocation_generation: assertInteger(
      descriptorValue(descriptors, "revocation_generation"),
      `${label}.revocation_generation`,
      0,
    ),
  };
  return Object.freeze(normalized);
}

function normalizeCurrentAuthority(input, label = "ble_nus_current_authority") {
  const descriptors = assertExactDataObject(input, CURRENT_AUTHORITY_FIELDS, label);
  const binding = normalizeAuthorityBinding(
    Object.fromEntries(AUTHORITY_BINDING_FIELDS.map((field) => (
      [field, descriptorValue(descriptors, field)]
    ))),
    label,
  );
  const currentMonotonicNs = assertUint64(
    descriptorValue(descriptors, "current_monotonic_ns"), `${label}.current_monotonic_ns`,
  );
  const current = Object.freeze({
    ...binding,
    current_monotonic_ns: currentMonotonicNs,
    trusted: assertBoolean(descriptorValue(descriptors, "trusted"), `${label}.trusted`),
    revoked: assertBoolean(descriptorValue(descriptors, "revoked"), `${label}.revoked`),
    lease_live: assertBoolean(descriptorValue(descriptors, "lease_live"), `${label}.lease_live`),
    resource_fence_live: assertBoolean(
      descriptorValue(descriptors, "resource_fence_live"), `${label}.resource_fence_live`,
    ),
    deadline_live: assertBoolean(
      descriptorValue(descriptors, "deadline_live"), `${label}.deadline_live`,
    ),
    transport_switch_allowed: assertBoolean(
      descriptorValue(descriptors, "transport_switch_allowed"),
      `${label}.transport_switch_allowed`,
    ),
  });
  if (BigInt(current.current_monotonic_ns) >= BigInt(current.effect_deadline_monotonic_ns)) {
    throw new Error("ble_nus_current_authority deadline is not live");
  }
  return current;
}

function createTestBleNusAuthorityResolverPort(input) {
  if (arguments.length !== 1) {
    throw new Error("BLE NUS conformance authority port requires one closed input");
  }
  const label = "test_ble_nus_authority_resolver_port";
  const descriptors = assertExactDataObject(input, [
    "version",
    "port_id",
    "test_only",
    "resolve_current_authority",
  ], label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  if (descriptorValue(descriptors, "test_only") !== true) {
    throw new Error(`${label}.test_only must be literal true`);
  }
  const resolver = descriptorValue(descriptors, "resolve_current_authority");
  if (typeof resolver !== "function") {
    throw new Error(`${label}.resolve_current_authority must be a synchronous function`);
  }
  const projection = Object.freeze({
    version: BLE_NUS_TRANSPORT_VERSION,
    kind: "ble_nus_authority_resolver_port",
    port_id: assertOpaqueRef(descriptorValue(descriptors, "port_id"), `${label}.port_id`),
    assurance: BLE_NUS_AUTHORITY_ASSURANCE,
    test_only: true,
    production_ready: false,
    execution_authority: false,
    hardware_access_authorized: false,
    toJSON: rejectSerialization,
  });
  AUTHORITY_PORTS.add(projection);
  AUTHORITY_PORT_STATE.set(projection, {
    resolver,
    minimum_authority_epoch: null,
    minimum_revocation_generation: null,
    used_switches: new Set(),
  });
  return projection;
}

function assertAuthorityPort(input) {
  const state = input == null ? null : AUTHORITY_PORT_STATE.get(input);
  if (!input || !state || !AUTHORITY_PORTS.has(input) || !Object.isFrozen(input)
      || input.assurance !== BLE_NUS_AUTHORITY_ASSURANCE
      || input.production_ready !== false || input.execution_authority !== false) {
    throw new Error("BLE NUS authority requires a private inert conformance port");
  }
  return { port: input, state };
}

function resolveAuthority(portInput, expectedBinding, purpose) {
  const { port, state } = assertAuthorityPort(portInput);
  let raw;
  try {
    raw = state.resolver(Object.freeze({
      version: BLE_NUS_TRANSPORT_VERSION,
      purpose,
      port_id: port.port_id,
      execution_lineage_digest: expectedBinding.execution_lineage_digest,
      lease_id: expectedBinding.lease_id,
      resource_epoch: expectedBinding.resource_epoch,
      resource_fence_digest: expectedBinding.resource_fence_digest,
      transport_contract_digest: BLE_NUS_TRANSPORT_CONTRACT.transport_contract_digest,
    }));
  } catch {
    throw new Error("ble_nus_authority_resolution_failed");
  }
  if (raw && utilTypes.isPromise(raw)) {
    throw new Error("ble_nus_authority_resolution_must_be_synchronous");
  }
  let current;
  try {
    current = normalizeCurrentAuthority(raw);
  } catch {
    throw new Error("ble_nus_authority_resolution_rejected");
  }
  for (const field of AUTHORITY_BINDING_FIELDS) {
    if (current[field] !== expectedBinding[field]) {
      throw new Error("ble_nus_authority_binding_drift");
    }
  }
  if (state.minimum_authority_epoch != null
      && current.authority_epoch < state.minimum_authority_epoch) {
    throw new Error("ble_nus_authority_epoch_rollback");
  }
  if (state.minimum_revocation_generation != null
      && current.revocation_generation < state.minimum_revocation_generation) {
    throw new Error("ble_nus_revocation_generation_rollback");
  }
  state.minimum_authority_epoch = current.authority_epoch;
  state.minimum_revocation_generation = current.revocation_generation;
  if (!current.trusted || current.revoked || !current.lease_live
      || !current.resource_fence_live || !current.deadline_live
      || !current.transport_switch_allowed) {
    throw new Error("ble_nus_authority_not_live");
  }
  return current;
}

function normalizeBleNusEnrollment(input, label = "ble_nus_enrollment") {
  if (arguments.length < 1 || arguments.length > 2) {
    throw new Error("BLE NUS enrollment accepts one closed enrollment record");
  }
  const descriptors = assertExactDataObject(input, ENROLLMENT_FIELDS, label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  const endpointKind = descriptorValue(descriptors, "endpoint_kind");
  if (BLE_NUS_FORBIDDEN_ENDPOINT_KINDS.includes(endpointKind)
      || endpointKind !== BLE_NUS_ENDPOINT_KIND) {
    throw new Error(
      `${label}.endpoint_kind must be dedicated CoreBluetooth service/characteristic custody; `
      + "Bluetooth pseudo-serial and arbitrary serial paths are forbidden",
    );
  }
  const identityProvenance = descriptorValue(descriptors, "identity_provenance");
  if (identityProvenance !== "operator_enrolled_corebluetooth_peripheral_service_set") {
    throw new Error(`${label}.identity_provenance is not the reviewed BLE enrollment posture`);
  }
  const basis = {
    version: BLE_NUS_TRANSPORT_VERSION,
    enrollment_id: assertOpaqueRef(
      descriptorValue(descriptors, "enrollment_id"), `${label}.enrollment_id`,
    ),
    device_identity_digest: assertDigest(
      descriptorValue(descriptors, "device_identity_digest"), `${label}.device_identity_digest`,
    ),
    peripheral_identifier_digest: assertDigest(
      descriptorValue(descriptors, "peripheral_identifier_digest"),
      `${label}.peripheral_identifier_digest`,
    ),
    endpoint_kind: endpointKind,
    identity_provenance: identityProvenance,
    service_uuid: BLE_NUS_SERVICE_UUID,
    central_write_characteristic_uuid: BLE_NUS_RX_CHARACTERISTIC_UUID,
    peripheral_notify_characteristic_uuid: BLE_NUS_TX_CHARACTERISTIC_UUID,
    arbitrary_uuid_allowed: false,
    serial_path_allowed: false,
    bluetooth_pseudo_serial_allowed: false,
    production_ready: false,
  };
  const enrollment = deepFreeze({
    ...basis,
    enrollment_digest: hashCanonicalJson(basis),
  });
  ENROLLMENTS.add(enrollment);
  return enrollment;
}

function assertBleNusEnrollment(input) {
  if (!input || !ENROLLMENTS.has(input) || !Object.isFrozen(input)
      || input.endpoint_kind !== BLE_NUS_ENDPOINT_KIND
      || input.service_uuid !== BLE_NUS_SERVICE_UUID
      || input.production_ready !== false) {
    throw new Error("BLE NUS enrollment must be issued by the closed enrollment normalizer");
  }
  return input;
}

function pairingClassification(posture) {
  if (!posture.pairing_required) return "insecure_pairing_not_required";
  if (!posture.link_encrypted) return "insecure_link_unencrypted";
  if (!posture.bond_present) return "insecure_bond_absent";
  if (!posture.enrolled_bond_match) return "insecure_bond_identity_mismatch";
  if (!posture.secure_connections) return "insecure_legacy_pairing";
  return "secure_enrolled_bond";
}

function normalizeBleNusPairingPosture(input, label = "ble_nus_pairing_posture") {
  if (arguments.length < 1 || arguments.length > 2) {
    throw new Error("BLE NUS pairing posture accepts one closed redacted observation");
  }
  const descriptors = assertExactDataObject(input, PAIRING_POSTURE_FIELDS, label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  const basis = {
    version: BLE_NUS_TRANSPORT_VERSION,
    observation_ref: assertOpaqueRef(
      descriptorValue(descriptors, "observation_ref"), `${label}.observation_ref`,
    ),
    device_identity_digest: assertDigest(
      descriptorValue(descriptors, "device_identity_digest"), `${label}.device_identity_digest`,
    ),
    observed_at_monotonic_ns: assertUint64(
      descriptorValue(descriptors, "observed_at_monotonic_ns"),
      `${label}.observed_at_monotonic_ns`,
    ),
    pairing_required: assertBoolean(
      descriptorValue(descriptors, "pairing_required"), `${label}.pairing_required`,
    ),
    link_encrypted: assertBoolean(
      descriptorValue(descriptors, "link_encrypted"), `${label}.link_encrypted`,
    ),
    bond_present: assertBoolean(
      descriptorValue(descriptors, "bond_present"), `${label}.bond_present`,
    ),
    enrolled_bond_match: assertBoolean(
      descriptorValue(descriptors, "enrolled_bond_match"), `${label}.enrolled_bond_match`,
    ),
    secure_connections: assertBoolean(
      descriptorValue(descriptors, "secure_connections"), `${label}.secure_connections`,
    ),
  };
  const classification = pairingClassification(basis);
  const projection = {
    ...basis,
    classification,
    secure_pairing_posture: classification === "secure_enrolled_bond",
    operator_action_required: classification !== "secure_enrolled_bond",
    pairing_secret_disposition: "not_collected_redacted_at_native_boundary",
    pairing_key_exposed: false,
    bond_admin_exposed: false,
    production_ready: false,
  };
  const posture = deepFreeze({
    ...projection,
    pairing_posture_digest: hashCanonicalJson(projection),
  });
  PAIRING_POSTURES.add(posture);
  assertNoPublicByteMaterial(posture, label);
  return posture;
}

function assertPairingPosture(input) {
  if (!input || !PAIRING_POSTURES.has(input) || !Object.isFrozen(input)
      || input.pairing_key_exposed !== false || input.bond_admin_exposed !== false) {
    throw new Error("BLE NUS pairing posture must be a closed redacted observation");
  }
  return input;
}

function createBleNusTransportSwitchPlan(input, authorityPortInput) {
  if (arguments.length !== 2) {
    throw new Error("BLE NUS switch planning requires a plan and authority port");
  }
  const label = "ble_nus_transport_switch_plan";
  const descriptors = assertExactDataObject(input, SWITCH_PLAN_FIELDS, label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  const authorityBinding = normalizeAuthorityBinding(
    descriptorValue(descriptors, "authority_binding"), `${label}.authority_binding`,
  );
  const fromTransportId = assertEnum(
    descriptorValue(descriptors, "from_transport_id"),
    [USB_CDC_TRANSPORT_ID, DISCONNECTED_TRANSPORT_ID],
    `${label}.from_transport_id`,
  );
  const toTransportId = descriptorValue(descriptors, "to_transport_id");
  if (toTransportId !== BLE_NUS_TRANSPORT_ID) {
    throw new Error(`${label}.to_transport_id must be ${BLE_NUS_TRANSPORT_ID}`);
  }
  const previousGeneration = assertInteger(
    descriptorValue(descriptors, "previous_connection_generation"),
    `${label}.previous_connection_generation`,
    0,
  );
  const nextGeneration = assertInteger(
    descriptorValue(descriptors, "next_connection_generation"),
    `${label}.next_connection_generation`,
    1,
  );
  if (nextGeneration !== previousGeneration + 1) {
    throw new Error(`${label} must increment the connection generation exactly once`);
  }
  const terminalState = descriptorValue(descriptors, "previous_transport_terminal_state");
  const expectedState = fromTransportId === USB_CDC_TRANSPORT_ID
    ? "closed_confirmed"
    : "not_opened";
  if (terminalState !== expectedState) {
    throw new Error(`${label} requires a confirmed terminal state before transport switching`);
  }
  if (descriptorValue(descriptors, "outstanding_transaction_count") !== 0) {
    throw new Error(`${label} refuses switching with an outstanding transaction`);
  }
  resolveAuthority(authorityPortInput, authorityBinding, "plan_ble_nus_transport_switch");
  const { state: authorityState } = assertAuthorityPort(authorityPortInput);
  const switchKey = [
    authorityBinding.execution_lineage_digest,
    authorityBinding.lease_id,
    authorityBinding.resource_epoch,
    nextGeneration,
  ].join(":");
  if (authorityState.used_switches.has(switchKey)) {
    throw new Error("ble_nus_transport_switch_generation_replayed");
  }
  authorityState.used_switches.add(switchKey);
  const basis = {
    version: BLE_NUS_TRANSPORT_VERSION,
    kind: "ble_nus_transport_switch_plan",
    transport_contract_digest: BLE_NUS_TRANSPORT_CONTRACT.transport_contract_digest,
    execution_lineage_digest: authorityBinding.execution_lineage_digest,
    grant_envelope_digest: authorityBinding.grant_envelope_digest,
    execution_claim_receipt_digest: authorityBinding.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: authorityBinding.deadline_fence_receipt_digest,
    task_id: authorityBinding.task_id,
    attempt_id: authorityBinding.attempt_id,
    lease_id: authorityBinding.lease_id,
    resource_epoch: authorityBinding.resource_epoch,
    resource_fence_digest: authorityBinding.resource_fence_digest,
    effect_deadline_monotonic_ns: authorityBinding.effect_deadline_monotonic_ns,
    worker_fence_digest: authorityBinding.worker_fence_digest,
    transport_binding_digest: authorityBinding.transport_binding_digest,
    authorized_transport_set_digest: authorityBinding.authorized_transport_set_digest,
    transport_switch_fence_digest: authorityBinding.transport_switch_fence_digest,
    device_enrollment_digest: authorityBinding.device_enrollment_digest,
    device_identity_digest: authorityBinding.device_identity_digest,
    from_transport_id: fromTransportId,
    to_transport_id: toTransportId,
    previous_connection_generation: previousGeneration,
    next_connection_generation: nextGeneration,
    previous_transport_terminal_state: terminalState,
    previous_transport_terminal_receipt_digest: assertDigest(
      descriptorValue(descriptors, "previous_transport_terminal_receipt_digest"),
      `${label}.previous_transport_terminal_receipt_digest`,
    ),
    previous_transport_fence_digest: assertDigest(
      descriptorValue(descriptors, "previous_transport_fence_digest"),
      `${label}.previous_transport_fence_digest`,
    ),
    outstanding_transaction_count: 0,
    lease_preserved: true,
    previous_generation_fenced: true,
    reconnect_replays_command: false,
    activation_authority: false,
    production_ready: false,
  };
  const plan = deepFreeze({
    ...basis,
    switch_plan_digest: hashCanonicalJson(basis),
  });
  SWITCH_PLANS.add(plan);
  SWITCH_PLAN_STATE.set(plan, { authority_binding: authorityBinding, used: false });
  assertNoPublicByteMaterial(plan, label);
  return plan;
}

function assertSwitchPlan(input) {
  const state = input == null ? null : SWITCH_PLAN_STATE.get(input);
  if (!input || !state || !SWITCH_PLANS.has(input) || !Object.isFrozen(input)
      || input.to_transport_id !== BLE_NUS_TRANSPORT_ID
      || input.previous_generation_fenced !== true
      || input.activation_authority !== false) {
    throw new Error("BLE NUS switch plan must be issued by the closed planner");
  }
  return { plan: input, state };
}

function createInertBleNusConformanceSession(input, authorityPortInput) {
  if (arguments.length !== 2) {
    throw new Error("BLE NUS inert conformance session requires input and authority port");
  }
  const label = "inert_ble_nus_conformance_session";
  const descriptors = assertExactDataObject(input, CONFORMANCE_SESSION_FIELDS, label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  const { plan, state: planState } = assertSwitchPlan(
    descriptorValue(descriptors, "switch_plan"),
  );
  if (planState.used) throw new Error("ble_nus_switch_plan_already_consumed");
  const enrollment = assertBleNusEnrollment(descriptorValue(descriptors, "enrollment"));
  const pairingPosture = assertPairingPosture(descriptorValue(descriptors, "pairing_posture"));
  if (enrollment.device_identity_digest !== plan.device_identity_digest
      || pairingPosture.device_identity_digest !== plan.device_identity_digest
      || enrollment.enrollment_digest !== plan.device_enrollment_digest) {
    throw new Error("ble_nus_device_identity_or_enrollment_drift");
  }
  if (!pairingPosture.secure_pairing_posture) {
    throw new Error(`ble_nus_pairing_posture_refused:${pairingPosture.classification}`);
  }
  const mtu = assertInteger(
    descriptorValue(descriptors, "negotiated_att_mtu"),
    `${label}.negotiated_att_mtu`,
    BLE_NUS_MINIMUM_ATT_MTU,
    BLE_NUS_MAXIMUM_ATT_MTU,
  );
  resolveAuthority(
    authorityPortInput,
    planState.authority_binding,
    "create_inert_ble_nus_conformance_session",
  );
  planState.used = true;
  const basis = {
    version: BLE_NUS_TRANSPORT_VERSION,
    kind: "inert_ble_nus_conformance_session",
    transport_contract_digest: BLE_NUS_TRANSPORT_CONTRACT.transport_contract_digest,
    switch_plan_digest: plan.switch_plan_digest,
    execution_lineage_digest: plan.execution_lineage_digest,
    task_id: plan.task_id,
    attempt_id: plan.attempt_id,
    lease_id: plan.lease_id,
    resource_epoch: plan.resource_epoch,
    resource_fence_digest: plan.resource_fence_digest,
    worker_fence_digest: plan.worker_fence_digest,
    device_enrollment_digest: plan.device_enrollment_digest,
    device_identity_digest: plan.device_identity_digest,
    pairing_posture_digest: pairingPosture.pairing_posture_digest,
    connection_generation: plan.next_connection_generation,
    negotiated_att_mtu: mtu,
    maximum_attribute_value_bytes: mtu - BLE_ATT_VALUE_OVERHEAD_BYTES,
    state: "inert_conformance_ready",
    live_connection: false,
    hardware_access_authorized: false,
    execution_authority: false,
    production_ready: false,
  };
  const session = deepFreeze({
    ...basis,
    session_digest: hashCanonicalJson(basis),
    toJSON: rejectSerialization,
  });
  CONFORMANCE_SESSIONS.add(session);
  CONFORMANCE_SESSION_STATE.set(session, {
    authority_port: authorityPortInput,
    authority_binding: planState.authority_binding,
    status: "ready",
  });
  return session;
}

function assertConformanceSession(input) {
  const state = input == null ? null : CONFORMANCE_SESSION_STATE.get(input);
  if (!input || !state || !CONFORMANCE_SESSIONS.has(input) || !Object.isFrozen(input)
      || input.live_connection !== false || input.hardware_access_authorized !== false
      || input.execution_authority !== false || input.production_ready !== false) {
    throw new Error("BLE NUS conformance session must be an inert private capability");
  }
  return { session: input, state };
}

const VECTOR_DEFINITIONS = deepFreeze({
  "two_fragments_exact_v1": {
    direction: "central_to_peripheral",
    sizing: "two_attribute_values_exact",
  },
  "two_fragments_plus_one_v1": {
    direction: "peripheral_to_central",
    sizing: "two_attribute_values_plus_one",
  },
  "maximum_codec_frame_v1": {
    direction: "peripheral_to_central",
    sizing: "maximum_codec_frame",
  },
});

function getBleNusConformanceVector(vectorId) {
  if (typeof vectorId !== "string" || !Object.hasOwn(VECTOR_DEFINITIONS, vectorId)) return null;
  const vector = VECTOR_DEFINITIONS[vectorId];
  return deepFreeze({
    version: BLE_NUS_TRANSPORT_VERSION,
    vector_id: vectorId,
    direction: vector.direction,
    sizing: vector.sizing,
    caller_byte_input: false,
    live_transport: false,
  });
}

function frameLengthForVector(vector, attributeValueBytes) {
  if (vector.sizing === "two_attribute_values_exact") return attributeValueBytes * 2;
  if (vector.sizing === "two_attribute_values_plus_one") return attributeValueBytes * 2 + 1;
  return FIXED_FRAME_BYTES + ABSOLUTE_MAX_DATA_LENGTH;
}

function deterministicData(length, vectorId) {
  const output = Buffer.alloc(length);
  let offset = 0;
  let counter = 0;
  while (offset < output.length) {
    const block = crypto.createHash("sha256")
      .update("hacker-bob/ble-nus-inert-conformance-vector/v1", "utf8")
      .update(Buffer.from([0]))
      .update(vectorId, "utf8")
      .update(Buffer.from([0]))
      .update(String(counter), "utf8")
      .digest();
    block.copy(output, offset, 0, Math.min(block.length, output.length - offset));
    block.fill(0);
    offset += Math.min(block.length, output.length - offset);
    counter += 1;
  }
  return output;
}

function buildSyntheticFrame(vectorId, frameLength) {
  if (frameLength < FIXED_FRAME_BYTES
      || frameLength > FIXED_FRAME_BYTES + ABSOLUTE_MAX_DATA_LENGTH) {
    throw new Error("ble_nus_conformance_vector_frame_length_invalid");
  }
  const data = deterministicData(frameLength - FIXED_FRAME_BYTES, vectorId);
  const frame = Buffer.alloc(frameLength);
  try {
    frame[0] = SOF;
    frame[1] = SOF_LRC;
    frame.writeUInt16BE(1000, 2);
    frame.writeUInt16BE(0, 4);
    frame.writeUInt16BE(data.length, 6);
    frame[8] = calculateLrc(frame.subarray(2, 8));
    data.copy(frame, 9);
    frame[frame.length - 1] = calculateLrc(data);
    return frame;
  } finally {
    data.fill(0);
  }
}

function fragmentFrame(frame, maximumAttributeValueBytes) {
  const fragments = [];
  for (let offset = 0, sequence = 0; offset < frame.length; sequence += 1) {
    const bytes = Buffer.from(frame.subarray(offset, offset + maximumAttributeValueBytes));
    fragments.push({
      sequence,
      offset,
      byte_length: bytes.length,
      fragment_digest: crypto.createHash("sha256").update(bytes).digest("hex"),
      bytes,
    });
    offset += bytes.length;
  }
  return fragments;
}

function zeroFragments(fragments) {
  for (const fragment of fragments) fragment.bytes?.fill(0);
}

function faultedDelivery(fragments, fault) {
  const delivery = fragments.map((fragment) => ({ ...fragment, bytes: Buffer.from(fragment.bytes) }));
  if (fault === "none") return delivery;
  if (fault === "drop_fragment") {
    delivery.splice(Math.floor(delivery.length / 2), 1);
  } else if (fault === "duplicate_fragment") {
    const index = Math.floor(delivery.length / 2);
    delivery.splice(index, 0, { ...delivery[index], bytes: Buffer.from(delivery[index].bytes) });
  } else if (fault === "reorder_fragments") {
    [delivery[0], delivery[1]] = [delivery[1], delivery[0]];
  } else if (fault === "corrupt_fragment") {
    delivery[Math.floor(delivery.length / 2)].bytes[0] ^= 0x01;
  } else if (fault === "disconnect_after_fragment") {
    delivery.splice(1);
  }
  return delivery;
}

function verifyFragmentLedger(delivery, expected, fault) {
  if (fault === "disconnect_after_fragment") return "disconnect_before_reassembly";
  if (delivery.length !== expected.length) return "fragment_count_mismatch";
  for (let index = 0; index < delivery.length; index += 1) {
    const actual = delivery[index];
    const wanted = expected[index];
    if (actual.sequence !== index || actual.sequence !== wanted.sequence
        || actual.offset !== wanted.offset || actual.byte_length !== wanted.byte_length) {
      return "fragment_sequence_or_offset_mismatch";
    }
    const digest = crypto.createHash("sha256").update(actual.bytes).digest("hex");
    if (digest !== actual.fragment_digest || digest !== wanted.fragment_digest) {
      return "fragment_digest_mismatch";
    }
  }
  return null;
}

function conformanceResult(session, vectorId, vector, fault, details) {
  const basis = {
    version: BLE_NUS_TRANSPORT_VERSION,
    kind: "ble_nus_conformance_result",
    transport_contract_digest: session.transport_contract_digest,
    session_digest: session.session_digest,
    execution_lineage_digest: session.execution_lineage_digest,
    lease_id: session.lease_id,
    resource_epoch: session.resource_epoch,
    resource_fence_digest: session.resource_fence_digest,
    worker_fence_digest: session.worker_fence_digest,
    connection_generation: session.connection_generation,
    pairing_posture_digest: session.pairing_posture_digest,
    vector_id: vectorId,
    direction: vector.direction,
    negotiated_att_mtu: session.negotiated_att_mtu,
    maximum_attribute_value_bytes: session.maximum_attribute_value_bytes,
    injected_fault: fault,
    ...details,
    raw_bytes_exposed: false,
    live_connection: false,
    hardware_access_authorized: false,
    execution_authority: false,
    production_ready: false,
  };
  const result = deepFreeze({
    ...basis,
    conformance_result_digest: hashCanonicalJson(basis),
  });
  CONFORMANCE_RESULTS.add(result);
  assertNoPublicByteMaterial(result, "ble_nus_conformance_result");
  return result;
}

function runInertBleNusConformanceVector(sessionInput, input) {
  if (arguments.length !== 2) {
    throw new Error("BLE NUS conformance run requires a session and closed vector selection");
  }
  const { session, state } = assertConformanceSession(sessionInput);
  if (state.status !== "ready") {
    throw new Error(`ble_nus_connection_generation_${state.status}`);
  }
  const label = "ble_nus_conformance_run";
  const descriptors = assertExactDataObject(input, CONFORMANCE_RUN_FIELDS, label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  const vectorId = descriptorValue(descriptors, "vector_id");
  const vector = VECTOR_DEFINITIONS[vectorId];
  if (!vector) throw new Error(`${label}.vector_id is not in the closed vector registry`);
  const fault = assertEnum(
    descriptorValue(descriptors, "fault"), CONFORMANCE_FAULT_VALUES, `${label}.fault`,
  );
  resolveAuthority(state.authority_port, state.authority_binding, "ble_nus_conformance_preflight");
  state.status = "running";
  let frame = null;
  let fragments = [];
  let delivery = [];
  try {
    const frameLength = frameLengthForVector(vector, session.maximum_attribute_value_bytes);
    frame = buildSyntheticFrame(vectorId, frameLength);
    const frameDigest = crypto.createHash("sha256").update(frame).digest("hex");
    fragments = fragmentFrame(frame, session.maximum_attribute_value_bytes);
    delivery = faultedDelivery(fragments, fault);
    const ledgerFailure = verifyFragmentLedger(delivery, fragments, fault);
    if (ledgerFailure) {
      state.status = "fenced";
      return conformanceResult(session, vectorId, vector, fault, {
        disposition: "fenced",
        terminal_code: ledgerFailure,
        original_frame_digest: frameDigest,
        reassembled_frame_digest: null,
        frame_byte_length: frame.length,
        expected_fragment_count: fragments.length,
        observed_fragment_count: delivery.length,
        decoded_frame_count: 0,
        parser_error_count: 0,
        connection_generation_fenced: true,
        automatic_retry_allowed: false,
      });
    }
    const parser = createFrameParser();
    const decodedFrames = [];
    let parserErrorCount = 0;
    for (const fragment of delivery) {
      const parsed = parser.push(fragment.bytes);
      decodedFrames.push(...parsed.frames);
      parserErrorCount += parsed.errors.length;
    }
    const finish = parser.finish();
    decodedFrames.push(...finish.frames);
    parserErrorCount += finish.errors.length;
    const reassembled = Buffer.concat(delivery.map((fragment) => fragment.bytes));
    let decodedData = null;
    try {
      const reassembledDigest = crypto.createHash("sha256").update(reassembled).digest("hex");
      if (reassembledDigest !== frameDigest || decodedFrames.length !== 1
          || parserErrorCount !== 0 || decodedFrames[0].stream_tainted
          || decodedFrames[0].command !== 1000 || decodedFrames[0].status !== 0) {
        state.status = "fenced";
        return conformanceResult(session, vectorId, vector, fault, {
          disposition: "fenced",
          terminal_code: "codec_reassembly_mismatch",
          original_frame_digest: frameDigest,
          reassembled_frame_digest: reassembledDigest,
          frame_byte_length: frame.length,
          expected_fragment_count: fragments.length,
          observed_fragment_count: delivery.length,
          decoded_frame_count: decodedFrames.length,
          parser_error_count: parserErrorCount,
          connection_generation_fenced: true,
          automatic_retry_allowed: false,
        });
      }
      decodedData = decodedFrames[0].data;
      resolveAuthority(
        state.authority_port,
        state.authority_binding,
        "ble_nus_conformance_post_reassembly",
      );
      state.status = "consumed";
      return conformanceResult(session, vectorId, vector, fault, {
        disposition: "passed",
        terminal_code: "inert_fragmentation_reassembly_conformant",
        original_frame_digest: frameDigest,
        reassembled_frame_digest: reassembledDigest,
        decoded_payload_digest: crypto.createHash("sha256").update(decodedData).digest("hex"),
        frame_byte_length: frame.length,
        expected_fragment_count: fragments.length,
        observed_fragment_count: delivery.length,
        decoded_frame_count: 1,
        parser_error_count: 0,
        connection_generation_fenced: false,
        automatic_retry_allowed: false,
      });
    } finally {
      decodedData?.fill(0);
      reassembled.fill(0);
    }
  } catch (error) {
    state.status = "fenced";
    if (error && typeof error.message === "string" && error.message.startsWith("ble_nus_")) {
      throw error;
    }
    throw new Error("ble_nus_conformance_failed_closed");
  } finally {
    frame?.fill(0);
    zeroFragments(fragments);
    zeroFragments(delivery);
  }
}

function assertBleNusConformanceResult(input) {
  if (!input || !CONFORMANCE_RESULTS.has(input) || !Object.isFrozen(input)
      || input.raw_bytes_exposed !== false || input.live_connection !== false
      || input.hardware_access_authorized !== false || input.execution_authority !== false
      || input.production_ready !== false) {
    throw new Error("BLE NUS conformance result must be issued by the inert conformance runner");
  }
  assertNoPublicByteMaterial(input, "ble_nus_conformance_result");
  return input;
}

function inspectInertBleNusConformanceSession(input) {
  const { session, state } = assertConformanceSession(input);
  return deepFreeze({
    version: BLE_NUS_TRANSPORT_VERSION,
    session_digest: session.session_digest,
    connection_generation: session.connection_generation,
    state: state.status,
    live_connection: false,
    hardware_access_authorized: false,
    execution_authority: false,
    production_ready: false,
  });
}

module.exports = {
  BLE_NUS_CAPABILITY_ID,
  BLE_NUS_DEPENDENCY_REF,
  BLE_NUS_ENDPOINT_KIND,
  BLE_NUS_FORBIDDEN_ENDPOINT_KINDS,
  BLE_NUS_MAXIMUM_ATT_MTU,
  BLE_NUS_MINIMUM_ATT_MTU,
  BLE_NUS_READINESS_BLOCKERS,
  BLE_NUS_RX_CHARACTERISTIC_UUID,
  BLE_NUS_SERVICE_UUID,
  BLE_NUS_TRANSPORT_ID,
  BLE_NUS_TRANSPORT_VERSION,
  BLE_NUS_TX_CHARACTERISTIC_UUID,
  assertBleNusConformanceResult,
  bleNusTransportContract,
  createBleNusTransportSwitchPlan,
  createInertBleNusConformanceSession,
  createTestBleNusAuthorityResolverPort,
  getBleNusConformanceVector,
  inspectInertBleNusConformanceSession,
  normalizeBleNusEnrollment,
  normalizeBleNusPairingPosture,
  runInertBleNusConformanceVector,
};
