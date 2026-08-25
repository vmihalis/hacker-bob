"use strict";

// Provider-neutral composition contract for the final broker -> worker ->
// reserved-vault-sink seam.  The only constructible component set in this
// module is deliberately a caller-supplied conformance fixture.  It can prove
// ordering and binding invariants, but it can never authorize hardware.  A
// future production constructor must enroll independently branded native
// components; accepting truthy assurance fields or caller callbacks here is
// intentionally insufficient.

const { types: utilTypes } = require("node:util");

const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const arrayIsArray = Array.isArray;
const arrayPrototype = Array.prototype;
const arrayBufferIsView = ArrayBuffer.isView;
const bufferIsBuffer = Buffer.isBuffer;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectPrototype = Object.prototype;
const promisePrototypeThen = Promise.prototype.then;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const utilIsPromise = utilTypes.isPromise;
const utilIsProxy = utilTypes.isProxy;
const utilIsAnyArrayBuffer = utilTypes.isAnyArrayBuffer;
const utilIsUint8Array = utilTypes.isUint8Array;

const PROVIDER_WORKER_VAULT_COMPOSITION_VERSION = 1;
const PROVIDER_WORKER_VAULT_CONFORMANCE_ASSURANCE =
  "caller_supplied_unattested_composition_fixture";
const PROVIDER_WORKER_VAULT_PROTOCOL_FIXTURE_ASSURANCE =
  "caller_supplied_non_authorizing_production_protocol_fixture";
const PROVIDER_WORKER_VAULT_PRODUCTION_ASSURANCE =
  "native_privately_branded_provider_worker_vault_composition_v1";
const EXECUTION_LINEAGE_DOMAIN =
  "hacker-bob/provider-worker-vault-execution-lineage/v1";
const MAX_BOUNDED_STRING_BYTES = 512;
const MAX_RESPONSE_BYTES = 16 * 1024;
const CONFORMANCE_CALLBACK_TIMEOUT_MS = 300;
const MAX_CONFORMANCE_LINEAGE_CLAIMS = 1024;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const OPAQUE_REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$/u;
const ARTIFACT_HANDLE_PATTERN = /^artifact:v1:[A-Za-z0-9_-]{32,86}$/u;
const RESULT_CODE_PATTERN = /^[a-z][a-z0-9_]{0,63}$/u;
const UINT64_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;
const MAX_UINT64 = (1n << 64n) - 1n;

const LINEAGE_BASIS_FIELDS = objectFreeze([
  "version",
  "execution_ref",
  "experiment_plan_hash",
  "exchange_id",
  "grant_envelope_digest",
  "grant_journal_entry_digest",
  "go_envelope_digest",
  "go_journal_entry_digest",
  "session_nucleus_hash",
  "task_id",
  "attempt_id",
  "lease_id",
  "resource_epoch",
  "resource_fence_digest",
  "effect_deadline_monotonic_ns",
  "provider_id",
  "operation_id",
  "compiler_id",
  "compiler_manifest_digest",
  "compiler_registry_digest",
  "source_profile_digest",
  "schema_id",
  "capability_id",
  "variant_id",
  "parameter_selector_id",
  "canonical_command_digest",
  "compiled_operation_digest",
  "provider_command_ref",
  "requested_effects_digest",
  "safety_supervisor_plan_digest",
  "runtime_availability",
  "compiled_command_id",
  "compiled_command_capability_digest",
  "expected_result_code",
  "active_command_input_ref",
  "active_command_input_digest",
  "cleanup_command_input_ref",
  "cleanup_command_input_digest",
  "maximum_response_bytes",
  "vault_reservation_handle",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
  "vault_byte_ceiling",
  "worker_bundle_digest",
  "worker_launch_digest",
  "worker_process_instance_digest",
  "worker_fence_digest",
  "transport_binding_digest",
  "durable_exchange_plan_digest",
  "terminal_receipt_recipient_digest",
]);
const LINEAGE_FIELDS = objectFreeze([
  ...LINEAGE_BASIS_FIELDS,
  "execution_lineage_digest",
]);
const COMPONENT_CALLBACK_FIELDS = objectFreeze([
  "version",
  "redeem_grant",
  "claim_compiled_command",
  "launch_worker",
  "assert_worker_fence",
  "execute_transport_into_reserved_vault",
  "cancel_before_effect",
  "restore_after_effect",
  "commit_terminal",
]);
const PROTOCOL_FIXTURE_CALLBACK_FIELDS = objectFreeze([
  ...COMPONENT_CALLBACK_FIELDS,
  "claim_execution",
  "readback_execution_claim",
  "assert_effect_deadline_fence",
  "assert_vault_ingest_receipt",
  "readback_terminal_commit",
]);
const PRODUCTION_PORT_OPERATION_FIELDS = objectFreeze(
  PROTOCOL_FIXTURE_CALLBACK_FIELDS.slice(1),
);
const COMPONENT_PUBLIC_FIELDS = objectFreeze([
  "version",
  "kind",
  "assurance",
  "production_ready",
  "hardware_access_authorized",
  "execution_authority",
  "toJSON",
]);
const TRANSACTION_CAPABILITY_PUBLIC_FIELDS = objectFreeze([
  "version",
  "kind",
  "execution_lineage_digest",
  "provider_id",
  "operation_id",
  "compiler_id",
  "compiler_manifest_digest",
  "compiler_registry_digest",
  "source_profile_digest",
  "schema_id",
  "capability_id",
  "variant_id",
  "parameter_selector_id",
  "canonical_command_digest",
  "compiled_operation_digest",
  "provider_command_ref",
  "requested_effects_digest",
  "safety_supervisor_plan_digest",
  "runtime_availability",
  "compiled_command_id",
  "compiled_command_capability_digest",
  "active_command_input_ref",
  "active_command_input_digest",
  "expected_result_code",
  "maximum_response_bytes",
  "lease_id",
  "resource_epoch",
  "resource_fence_digest",
  "effect_deadline_monotonic_ns",
  "worker_bundle_digest",
  "worker_launch_digest",
  "worker_fence_digest",
  "transport_binding_digest",
  "vault_reservation_handle",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
  "vault_byte_ceiling",
  "production_ready",
  "hardware_access_authorized",
  "execution_authority",
  "toJSON",
]);
const COMPILED_COMMAND_DELEGATE_FIELDS = objectFreeze([
  "version", "kind", "compiled_command_id", "provider_id", "compiler_id",
  "compiler_manifest_digest", "compiler_registry_digest", "source_profile_digest",
  "schema_id", "operation_id", "capability_id", "variant_id", "parameter_selector_id",
  "canonical_command_digest", "compiled_operation_digest",
  "compiled_command_capability_digest", "runtime_availability", "execution_authority",
  "production_ready", "toJSON",
]);

const COMPONENTS = new WeakSet();
const COMPONENT_PRIVATE = new WeakMap();
const PROTOCOL_FIXTURE_COMPONENTS = new WeakSet();
const PROTOCOL_FIXTURE_PRIVATE = new WeakMap();
const PRODUCTION_PORT_SETS = new WeakSet();
const PRODUCTION_PORT_SET_PRIVATE = new WeakMap();
const TRANSACTION_CAPABILITIES = new WeakSet();
const TRANSACTION_CAPABILITY_PRIVATE = new WeakMap();
const ROOTS = new WeakSet();
const ROOT_PRIVATE = new WeakMap();

const PRODUCTION_REQUIREMENTS = objectFreeze([
  objectFreeze({
    requirement_id: "qualified_native_grant_redemption_and_journal",
    status: "missing",
    blocker_code: "native_grant_redemption_not_enrolled",
  }),
  objectFreeze({
    requirement_id: "durable_global_execution_claim_and_readback",
    status: "missing",
    blocker_code: "durable_cross_process_execution_claim_missing",
  }),
  objectFreeze({
    requirement_id: "qualified_provider_neutral_worker_transaction",
    status: "missing",
    blocker_code: "provider_neutral_worker_transaction_not_enrolled",
  }),
  objectFreeze({
    requirement_id: "qualified_native_worker_launch_and_live_fence",
    status: "missing",
    blocker_code: "native_worker_launch_fence_not_enrolled",
  }),
  objectFreeze({
    requirement_id: "trusted_monotonic_deadline_recheck_and_preemption",
    status: "missing",
    blocker_code: "native_deadline_preemption_not_enrolled",
  }),
  objectFreeze({
    requirement_id: "qualified_reserved_vault_response_sink",
    status: "missing",
    blocker_code: "reservation_scoped_vault_ingest_capability_missing",
  }),
  objectFreeze({
    requirement_id: "qualified_durable_vault_ingest_receipt",
    status: "missing",
    blocker_code: "durable_vault_ingest_receipt_missing",
  }),
  objectFreeze({
    requirement_id: "qualified_external_vault_key_custodian",
    status: "missing",
    blocker_code: "external_vault_key_custodian_not_enrolled",
  }),
  objectFreeze({
    requirement_id: "qualified_native_terminal_receipt_outbox_writer",
    status: "missing",
    blocker_code: "native_terminal_outbox_writer_not_enrolled",
  }),
  objectFreeze({
    requirement_id: "qualified_independent_cancellation_restoration",
    status: "missing",
    blocker_code: "independent_restoration_custodian_not_enrolled",
  }),
  objectFreeze({
    requirement_id: "hardware_in_loop_qualification",
    status: "missing",
    blocker_code: "production_hil_evidence_missing",
  }),
]);
const SATISFIED_PRODUCTION_REQUIREMENTS = objectFreeze(PRODUCTION_REQUIREMENTS.map(
  (requirement) => objectFreeze({
    requirement_id: requirement.requirement_id,
    status: "satisfied",
    blocker_code: null,
  }),
));

function compositionError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || utilIsProxy(value) || arrayIsArray(value)) {
    return false;
  }
  const prototype = objectGetPrototypeOf(value);
  return prototype === objectPrototype || prototype === null;
}

function assertExactDataObject(value, fields, label) {
  if (!isPlainDataObject(value)) {
    throw compositionError(`${label}_must_be_closed_data`);
  }
  const descriptors = objectGetOwnPropertyDescriptors(value);
  const keys = reflectOwnKeys(descriptors);
  if (keys.some((key) => typeof key !== "string")) {
    throw compositionError(`${label}_symbol_field_forbidden`);
  }
  const missing = fields.filter((field) => !objectHasOwn(descriptors, field));
  const unknown = keys.filter((field) => !fields.includes(field));
  if (missing.length > 0 || unknown.length > 0) {
    throw compositionError(`${label}_field_set_invalid`);
  }
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || !objectHasOwn(descriptor, "value")
        || !descriptor.enumerable) {
      throw compositionError(`${label}_${field}_must_be_data`);
    }
  }
  return descriptors;
}

function descriptorValue(descriptors, field) {
  return descriptors[field].value;
}

function assertVersion(value, label) {
  if (value !== PROVIDER_WORKER_VAULT_COMPOSITION_VERSION) {
    throw compositionError(`${label}_version_invalid`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    throw compositionError(`${label}_digest_invalid`);
  }
  return value;
}

function assertOpaqueRef(value, label) {
  if (typeof value !== "string" || !OPAQUE_REF_PATTERN.test(value)
      || Buffer.byteLength(value, "utf8") > MAX_BOUNDED_STRING_BYTES) {
    throw compositionError(`${label}_opaque_ref_invalid`);
  }
  return value;
}

function assertBoundedString(value, label) {
  if (typeof value !== "string" || value.length < 1
      || Buffer.byteLength(value, "utf8") > MAX_BOUNDED_STRING_BYTES
      || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw compositionError(`${label}_bounded_string_invalid`);
  }
  return value;
}

function assertResultCode(value, label) {
  if (typeof value !== "string" || !RESULT_CODE_PATTERN.test(value)) {
    throw compositionError(`${label}_result_code_invalid`);
  }
  return value;
}

function assertArtifactHandle(value, label) {
  if (typeof value !== "string" || !ARTIFACT_HANDLE_PATTERN.test(value)) {
    throw compositionError(`${label}_artifact_handle_invalid`);
  }
  return value;
}

function assertUint64(value, label) {
  if (typeof value !== "string" || !UINT64_PATTERN.test(value)) {
    throw compositionError(`${label}_uint64_invalid`);
  }
  let parsed;
  try {
    parsed = BigInt(value);
  } catch {
    throw compositionError(`${label}_uint64_invalid`);
  }
  if (parsed > MAX_UINT64) throw compositionError(`${label}_uint64_invalid`);
  return value;
}

function assertPositiveInteger(value, label, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw compositionError(`${label}_integer_invalid`);
  }
  return value;
}

function assertBoolean(value, expected, label) {
  if (value !== expected) throw compositionError(`${label}_boolean_invalid`);
  return value;
}

function assertEnum(value, values, label) {
  if (typeof value !== "string" || !values.includes(value)) {
    throw compositionError(`${label}_enum_invalid`);
  }
  return value;
}

function assertNullableDigest(value, label) {
  return value === null ? null : assertDigest(value, label);
}

function assertNullableOpaqueRef(value, label) {
  return value === null ? null : assertOpaqueRef(value, label);
}

function assertNoByteSurface(value, label, seen = new WeakSet(), depth = 0) {
  if (value == null || typeof value === "string" || typeof value === "number"
      || typeof value === "boolean" || typeof value === "bigint"
      || typeof value === "symbol") {
    return;
  }
  if (typeof value === "function") {
    if (utilIsProxy(value)) throw compositionError(`${label}_async_or_proxy_forbidden`);
    if (seen.has(value)) return;
    if (depth > 6) throw compositionError(`${label}_surface_too_deep`);
    seen.add(value);
    const functionDescriptors = objectGetOwnPropertyDescriptors(value);
    for (const key of reflectOwnKeys(functionDescriptors)) {
      if (typeof key === "string"
          && ["length", "name", "prototype", "arguments", "caller"].includes(key)) {
        continue;
      }
      const descriptor = functionDescriptors[key];
      if (descriptor && objectHasOwn(descriptor, "value")) {
        assertNoByteSurface(descriptor.value, label, seen, depth + 1);
      }
    }
    return;
  }
  if (bufferIsBuffer(value) || utilIsUint8Array(value)
      || arrayBufferIsView(value) || utilIsAnyArrayBuffer(value)) {
    throw compositionError(`${label}_byte_surface_forbidden`);
  }
  if (utilIsProxy(value) || utilIsPromise(value)) {
    throw compositionError(`${label}_async_or_proxy_forbidden`);
  }
  const prototype = objectGetPrototypeOf(value);
  if (!objectIsFrozen(value)
      || (prototype !== objectPrototype && prototype !== null && prototype !== arrayPrototype)) {
    throw compositionError(`${label}_nonplain_or_mutable_surface_forbidden`);
  }
  if (seen.has(value)) return;
  if (depth > 6) throw compositionError(`${label}_surface_too_deep`);
  seen.add(value);
  const descriptors = objectGetOwnPropertyDescriptors(value);
  for (const key of reflectOwnKeys(descriptors)) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw compositionError(`${label}_accessor_surface_forbidden`);
    }
    assertNoByteSurface(descriptor.value, label, seen, depth + 1);
  }
}

function zeroExposedByteSurface(value, seen = new WeakSet(), depth = 0) {
  try {
    if (bufferIsBuffer(value) || utilIsUint8Array(value)) {
      value.fill(0);
      return;
    }
    if (arrayBufferIsView(value)) {
      new Uint8Array(value.buffer, value.byteOffset, value.byteLength).fill(0);
      return;
    }
    if (utilIsAnyArrayBuffer(value)) {
      new Uint8Array(value).fill(0);
      return;
    }
    if (value == null || (typeof value !== "object" && typeof value !== "function")
        || utilIsProxy(value) || seen.has(value) || depth > 6) {
      return;
    }
    seen.add(value);
    const descriptors = objectGetOwnPropertyDescriptors(value);
    for (const key of reflectOwnKeys(descriptors)) {
      const descriptor = descriptors[key];
      if (descriptor && objectHasOwn(descriptor, "value")) {
        zeroExposedByteSurface(descriptor.value, seen, depth + 1);
      }
    }
  } catch {
    // This is best-effort scrubbing after a caller violated the digest-only
    // transport result contract. The primary response-custody rejection wins.
  }
}

function assertOpaqueCapability(value, label) {
  if (value == null || typeof value !== "object"
      || utilIsProxy(value) || utilIsPromise(value) || !objectIsFrozen(value)) {
    throw compositionError(`${label}_opaque_capability_invalid`);
  }
  assertNoByteSurface(value, label);
  return value;
}

function digestRecord(domain, projection) {
  return hashCanonicalJson({ domain, ...projection });
}

function assertRecordDigest(projection, supplied, domain, label) {
  const expected = digestRecord(domain, projection);
  if (supplied !== expected) throw compositionError(`${label}_binding_digest_invalid`);
  return supplied;
}

function normalizeProviderWorkerVaultExecutionLineage(input) {
  const label = "provider_worker_vault_execution_lineage";
  const descriptors = assertExactDataObject(input, LINEAGE_FIELDS, label);
  const normalized = {
    version: assertVersion(descriptorValue(descriptors, "version"), label),
    execution_ref: assertOpaqueRef(descriptorValue(descriptors, "execution_ref"), "execution_ref"),
    experiment_plan_hash: assertDigest(
      descriptorValue(descriptors, "experiment_plan_hash"), "experiment_plan_hash",
    ),
    exchange_id: assertOpaqueRef(descriptorValue(descriptors, "exchange_id"), "exchange_id"),
    grant_envelope_digest: assertDigest(
      descriptorValue(descriptors, "grant_envelope_digest"), "grant_envelope_digest",
    ),
    grant_journal_entry_digest: assertDigest(
      descriptorValue(descriptors, "grant_journal_entry_digest"),
      "grant_journal_entry_digest",
    ),
    go_envelope_digest: assertDigest(
      descriptorValue(descriptors, "go_envelope_digest"), "go_envelope_digest",
    ),
    go_journal_entry_digest: assertDigest(
      descriptorValue(descriptors, "go_journal_entry_digest"), "go_journal_entry_digest",
    ),
    session_nucleus_hash: assertDigest(
      descriptorValue(descriptors, "session_nucleus_hash"), "session_nucleus_hash",
    ),
    task_id: assertOpaqueRef(descriptorValue(descriptors, "task_id"), "task_id"),
    attempt_id: assertOpaqueRef(descriptorValue(descriptors, "attempt_id"), "attempt_id"),
    lease_id: assertOpaqueRef(descriptorValue(descriptors, "lease_id"), "lease_id"),
    resource_epoch: assertUint64(
      descriptorValue(descriptors, "resource_epoch"), "resource_epoch",
    ),
    resource_fence_digest: assertDigest(
      descriptorValue(descriptors, "resource_fence_digest"), "resource_fence_digest",
    ),
    effect_deadline_monotonic_ns: assertUint64(
      descriptorValue(descriptors, "effect_deadline_monotonic_ns"),
      "effect_deadline_monotonic_ns",
    ),
    provider_id: assertOpaqueRef(descriptorValue(descriptors, "provider_id"), "provider_id"),
    operation_id: assertOpaqueRef(descriptorValue(descriptors, "operation_id"), "operation_id"),
    compiler_id: assertOpaqueRef(descriptorValue(descriptors, "compiler_id"), "compiler_id"),
    compiler_manifest_digest: assertDigest(
      descriptorValue(descriptors, "compiler_manifest_digest"), "compiler_manifest_digest",
    ),
    compiler_registry_digest: assertDigest(
      descriptorValue(descriptors, "compiler_registry_digest"), "compiler_registry_digest",
    ),
    source_profile_digest: assertDigest(
      descriptorValue(descriptors, "source_profile_digest"), "source_profile_digest",
    ),
    schema_id: assertOpaqueRef(descriptorValue(descriptors, "schema_id"), "schema_id"),
    capability_id: assertOpaqueRef(
      descriptorValue(descriptors, "capability_id"), "capability_id",
    ),
    variant_id: assertOpaqueRef(descriptorValue(descriptors, "variant_id"), "variant_id"),
    parameter_selector_id: assertOpaqueRef(
      descriptorValue(descriptors, "parameter_selector_id"), "parameter_selector_id",
    ),
    canonical_command_digest: assertDigest(
      descriptorValue(descriptors, "canonical_command_digest"), "canonical_command_digest",
    ),
    compiled_operation_digest: assertDigest(
      descriptorValue(descriptors, "compiled_operation_digest"), "compiled_operation_digest",
    ),
    provider_command_ref: assertOpaqueRef(
      descriptorValue(descriptors, "provider_command_ref"), "provider_command_ref",
    ),
    requested_effects_digest: assertDigest(
      descriptorValue(descriptors, "requested_effects_digest"), "requested_effects_digest",
    ),
    safety_supervisor_plan_digest: assertDigest(
      descriptorValue(descriptors, "safety_supervisor_plan_digest"),
      "safety_supervisor_plan_digest",
    ),
    runtime_availability: assertOpaqueRef(
      descriptorValue(descriptors, "runtime_availability"), "runtime_availability",
    ),
    compiled_command_id: assertOpaqueRef(
      descriptorValue(descriptors, "compiled_command_id"), "compiled_command_id",
    ),
    compiled_command_capability_digest: assertDigest(
      descriptorValue(descriptors, "compiled_command_capability_digest"),
      "compiled_command_capability_digest",
    ),
    expected_result_code: assertResultCode(
      descriptorValue(descriptors, "expected_result_code"), "expected_result_code",
    ),
    active_command_input_ref: assertOpaqueRef(
      descriptorValue(descriptors, "active_command_input_ref"), "active_command_input_ref",
    ),
    active_command_input_digest: assertDigest(
      descriptorValue(descriptors, "active_command_input_digest"),
      "active_command_input_digest",
    ),
    cleanup_command_input_ref: assertOpaqueRef(
      descriptorValue(descriptors, "cleanup_command_input_ref"), "cleanup_command_input_ref",
    ),
    cleanup_command_input_digest: assertDigest(
      descriptorValue(descriptors, "cleanup_command_input_digest"),
      "cleanup_command_input_digest",
    ),
    maximum_response_bytes: assertPositiveInteger(
      descriptorValue(descriptors, "maximum_response_bytes"),
      "maximum_response_bytes",
      MAX_RESPONSE_BYTES,
    ),
    vault_reservation_handle: assertOpaqueRef(
      descriptorValue(descriptors, "vault_reservation_handle"), "vault_reservation_handle",
    ),
    vault_reservation_digest: assertDigest(
      descriptorValue(descriptors, "vault_reservation_digest"), "vault_reservation_digest",
    ),
    vault_ingest_capability_digest: assertDigest(
      descriptorValue(descriptors, "vault_ingest_capability_digest"),
      "vault_ingest_capability_digest",
    ),
    vault_byte_ceiling: assertPositiveInteger(
      descriptorValue(descriptors, "vault_byte_ceiling"), "vault_byte_ceiling", MAX_RESPONSE_BYTES,
    ),
    worker_bundle_digest: assertDigest(
      descriptorValue(descriptors, "worker_bundle_digest"), "worker_bundle_digest",
    ),
    worker_launch_digest: assertDigest(
      descriptorValue(descriptors, "worker_launch_digest"), "worker_launch_digest",
    ),
    worker_process_instance_digest: assertDigest(
      descriptorValue(descriptors, "worker_process_instance_digest"),
      "worker_process_instance_digest",
    ),
    worker_fence_digest: assertDigest(
      descriptorValue(descriptors, "worker_fence_digest"), "worker_fence_digest",
    ),
    transport_binding_digest: assertDigest(
      descriptorValue(descriptors, "transport_binding_digest"), "transport_binding_digest",
    ),
    durable_exchange_plan_digest: assertDigest(
      descriptorValue(descriptors, "durable_exchange_plan_digest"),
      "durable_exchange_plan_digest",
    ),
    terminal_receipt_recipient_digest: assertDigest(
      descriptorValue(descriptors, "terminal_receipt_recipient_digest"),
      "terminal_receipt_recipient_digest",
    ),
  };
  if (normalized.active_command_input_ref === normalized.cleanup_command_input_ref
      || normalized.active_command_input_digest === normalized.cleanup_command_input_digest) {
    throw compositionError("active_and_cleanup_command_inputs_must_be_distinct");
  }
  if (normalized.maximum_response_bytes > normalized.vault_byte_ceiling) {
    throw compositionError("maximum_response_exceeds_reserved_vault_sink");
  }
  const suppliedDigest = assertDigest(
    descriptorValue(descriptors, "execution_lineage_digest"), "execution_lineage_digest",
  );
  const expectedDigest = digestRecord(EXECUTION_LINEAGE_DOMAIN, normalized);
  if (suppliedDigest !== expectedDigest) {
    throw compositionError("execution_lineage_digest_mismatch");
  }
  return objectFreeze({ ...normalized, execution_lineage_digest: suppliedDigest });
}

function projectLineage(lineage, fields) {
  const projection = {};
  for (const field of fields) projection[field] = lineage[field];
  return objectFreeze(projection);
}

function createStageLineageProjections(lineage) {
  const common = [
    "version", "execution_ref", "experiment_plan_hash", "exchange_id",
    "grant_envelope_digest", "grant_journal_entry_digest", "go_envelope_digest",
    "go_journal_entry_digest", "session_nucleus_hash", "task_id", "attempt_id",
    "execution_lineage_digest",
  ];
  const command = [
    "provider_id", "operation_id", "compiler_id", "compiler_manifest_digest",
    "compiler_registry_digest", "source_profile_digest", "schema_id", "capability_id",
    "variant_id", "parameter_selector_id", "canonical_command_digest",
    "compiled_operation_digest", "provider_command_ref", "requested_effects_digest",
    "runtime_availability",
    "compiled_command_id", "compiled_command_capability_digest", "expected_result_code",
    "active_command_input_ref", "active_command_input_digest", "maximum_response_bytes",
  ];
  const resource = [
    "lease_id", "resource_epoch", "resource_fence_digest",
    "effect_deadline_monotonic_ns", "safety_supervisor_plan_digest",
  ];
  const worker = [
    "worker_bundle_digest", "worker_launch_digest", "worker_process_instance_digest",
    "worker_fence_digest", "transport_binding_digest",
  ];
  const vault = [
    "vault_reservation_handle", "vault_reservation_digest",
    "vault_ingest_capability_digest", "vault_byte_ceiling",
  ];
  return objectFreeze({
    redemption: lineage,
    active: projectLineage(lineage, [...common, ...resource, ...command]),
    launch: projectLineage(lineage, [...common, ...resource, ...worker]),
    fence: projectLineage(lineage, [...common, ...resource, ...worker]),
    transport: projectLineage(lineage, [...common, ...resource, ...command, ...worker, ...vault]),
    cleanup: projectLineage(lineage, [
      ...common,
      ...resource,
      ...worker,
      ...vault,
      "active_command_input_ref",
      "active_command_input_digest",
      "cleanup_command_input_ref",
      "cleanup_command_input_digest",
    ]),
    terminal: projectLineage(lineage, [
      ...common,
      "vault_reservation_handle",
      "vault_reservation_digest",
      "durable_exchange_plan_digest",
      "terminal_receipt_recipient_digest",
    ]),
  });
}

function assertCompiledCommandDelegate(input, lineage) {
  const label = "compiled_command_delegate";
  assertOpaqueCapability(input, label);
  const descriptors = assertExactDataObject(input, COMPILED_COMMAND_DELEGATE_FIELDS, label);
  const expected = {
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: "compiled_provider_command_capability",
    compiled_command_id: lineage.compiled_command_id,
    provider_id: lineage.provider_id,
    compiler_id: lineage.compiler_id,
    compiler_manifest_digest: lineage.compiler_manifest_digest,
    compiler_registry_digest: lineage.compiler_registry_digest,
    source_profile_digest: lineage.source_profile_digest,
    schema_id: lineage.schema_id,
    operation_id: lineage.operation_id,
    capability_id: lineage.capability_id,
    variant_id: lineage.variant_id,
    parameter_selector_id: lineage.parameter_selector_id,
    canonical_command_digest: lineage.canonical_command_digest,
    compiled_operation_digest: lineage.compiled_operation_digest,
    compiled_command_capability_digest: lineage.compiled_command_capability_digest,
    runtime_availability: lineage.runtime_availability,
    execution_authority: false,
    production_ready: false,
  };
  for (const [field, expectedValue] of Object.entries(expected)) {
    if (descriptorValue(descriptors, field) !== expectedValue) {
      throw compositionError(`compiled_command_delegate_${field}_mismatch`);
    }
  }
  if (typeof descriptorValue(descriptors, "toJSON") !== "function") {
    throw compositionError("compiled_command_delegate_toJSON_invalid");
  }
  return input;
}

function createProviderWorkerVaultConformanceTransactionCapability(input) {
  const label = "provider_worker_vault_conformance_transaction_capability";
  const descriptors = assertExactDataObject(
    input,
    ["version", "lineage", "compiled_command_capability"],
    label,
  );
  assertVersion(descriptorValue(descriptors, "version"), label);
  const lineage = normalizeProviderWorkerVaultExecutionLineage(
    descriptorValue(descriptors, "lineage"),
  );
  const delegate = assertCompiledCommandDelegate(
    descriptorValue(descriptors, "compiled_command_capability"),
    lineage,
  );
  const capability = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: "provider_worker_vault_conformance_transaction_capability",
    execution_lineage_digest: lineage.execution_lineage_digest,
    provider_id: lineage.provider_id,
    operation_id: lineage.operation_id,
    compiler_id: lineage.compiler_id,
    compiler_manifest_digest: lineage.compiler_manifest_digest,
    compiler_registry_digest: lineage.compiler_registry_digest,
    source_profile_digest: lineage.source_profile_digest,
    schema_id: lineage.schema_id,
    capability_id: lineage.capability_id,
    variant_id: lineage.variant_id,
    parameter_selector_id: lineage.parameter_selector_id,
    canonical_command_digest: lineage.canonical_command_digest,
    compiled_operation_digest: lineage.compiled_operation_digest,
    provider_command_ref: lineage.provider_command_ref,
    requested_effects_digest: lineage.requested_effects_digest,
    safety_supervisor_plan_digest: lineage.safety_supervisor_plan_digest,
    runtime_availability: lineage.runtime_availability,
    compiled_command_id: lineage.compiled_command_id,
    compiled_command_capability_digest: lineage.compiled_command_capability_digest,
    active_command_input_ref: lineage.active_command_input_ref,
    active_command_input_digest: lineage.active_command_input_digest,
    expected_result_code: lineage.expected_result_code,
    maximum_response_bytes: lineage.maximum_response_bytes,
    lease_id: lineage.lease_id,
    resource_epoch: lineage.resource_epoch,
    resource_fence_digest: lineage.resource_fence_digest,
    effect_deadline_monotonic_ns: lineage.effect_deadline_monotonic_ns,
    worker_bundle_digest: lineage.worker_bundle_digest,
    worker_launch_digest: lineage.worker_launch_digest,
    worker_fence_digest: lineage.worker_fence_digest,
    transport_binding_digest: lineage.transport_binding_digest,
    vault_reservation_handle: lineage.vault_reservation_handle,
    vault_reservation_digest: lineage.vault_reservation_digest,
    vault_ingest_capability_digest: lineage.vault_ingest_capability_digest,
    vault_byte_ceiling: lineage.vault_byte_ceiling,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
    toJSON: rejectSerialization,
  });
  TRANSACTION_CAPABILITIES.add(capability);
  TRANSACTION_CAPABILITY_PRIVATE.set(capability, {
    lineage_digest: lineage.execution_lineage_digest,
    delegate,
    consumed: false,
  });
  return capability;
}

function assertConformanceTransactionCapability(input, lineage) {
  const state = input == null ? null : TRANSACTION_CAPABILITY_PRIVATE.get(input);
  if (!input || !state || !TRANSACTION_CAPABILITIES.has(input) || !objectIsFrozen(input)
      || input.version !== PROVIDER_WORKER_VAULT_COMPOSITION_VERSION
      || input.kind !== "provider_worker_vault_conformance_transaction_capability"
      || state.lineage_digest !== lineage.execution_lineage_digest
      || input.execution_lineage_digest !== lineage.execution_lineage_digest
      || input.provider_id !== lineage.provider_id
      || input.operation_id !== lineage.operation_id
      || input.compiler_id !== lineage.compiler_id
      || input.compiler_manifest_digest !== lineage.compiler_manifest_digest
      || input.compiler_registry_digest !== lineage.compiler_registry_digest
      || input.source_profile_digest !== lineage.source_profile_digest
      || input.schema_id !== lineage.schema_id
      || input.capability_id !== lineage.capability_id
      || input.variant_id !== lineage.variant_id
      || input.parameter_selector_id !== lineage.parameter_selector_id
      || input.canonical_command_digest !== lineage.canonical_command_digest
      || input.compiled_operation_digest !== lineage.compiled_operation_digest
      || input.provider_command_ref !== lineage.provider_command_ref
      || input.requested_effects_digest !== lineage.requested_effects_digest
      || input.safety_supervisor_plan_digest !== lineage.safety_supervisor_plan_digest
      || input.runtime_availability !== lineage.runtime_availability
      || input.compiled_command_id !== lineage.compiled_command_id
      || input.compiled_command_capability_digest !== lineage.compiled_command_capability_digest
      || input.active_command_input_ref !== lineage.active_command_input_ref
      || input.active_command_input_digest !== lineage.active_command_input_digest
      || input.expected_result_code !== lineage.expected_result_code
      || input.maximum_response_bytes !== lineage.maximum_response_bytes
      || input.lease_id !== lineage.lease_id
      || input.resource_epoch !== lineage.resource_epoch
      || input.resource_fence_digest !== lineage.resource_fence_digest
      || input.effect_deadline_monotonic_ns !== lineage.effect_deadline_monotonic_ns
      || input.worker_bundle_digest !== lineage.worker_bundle_digest
      || input.worker_launch_digest !== lineage.worker_launch_digest
      || input.worker_fence_digest !== lineage.worker_fence_digest
      || input.transport_binding_digest !== lineage.transport_binding_digest
      || input.vault_reservation_handle !== lineage.vault_reservation_handle
      || input.vault_reservation_digest !== lineage.vault_reservation_digest
      || input.vault_ingest_capability_digest !== lineage.vault_ingest_capability_digest
      || input.vault_byte_ceiling !== lineage.vault_byte_ceiling
      || input.production_ready !== false
      || input.hardware_access_authorized !== false
      || input.execution_authority !== false
      || input.toJSON !== rejectSerialization
      || reflectOwnKeys(input).length !== TRANSACTION_CAPABILITY_PUBLIC_FIELDS.length
      || reflectOwnKeys(input).some(
        (field) => typeof field !== "string" || !TRANSACTION_CAPABILITY_PUBLIC_FIELDS.includes(field),
      )) {
    throw compositionError("provider_worker_vault_transaction_capability_untrusted");
  }
  return state;
}

function rejectSerialization() {
  throw compositionError("provider_worker_vault_capability_not_serializable");
}

function createProviderWorkerVaultConformanceComponents(input) {
  const label = "provider_worker_vault_conformance_components";
  const descriptors = assertExactDataObject(input, COMPONENT_CALLBACK_FIELDS, label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  const callbacks = Object.create(null);
  for (const field of COMPONENT_CALLBACK_FIELDS.slice(1)) {
    const callback = descriptorValue(descriptors, field);
    if (typeof callback !== "function" || utilIsProxy(callback)) {
      throw compositionError(`${label}_${field}_callback_invalid`);
    }
    callbacks[field] = callback;
  }
  const components = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: "provider_worker_vault_conformance_components",
    assurance: PROVIDER_WORKER_VAULT_CONFORMANCE_ASSURANCE,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
    toJSON: rejectSerialization,
  });
  COMPONENTS.add(components);
  COMPONENT_PRIVATE.set(components, objectFreeze({
    callbacks: objectFreeze(callbacks),
    claimed_lineages: new Set(),
  }));
  return components;
}

function createProviderWorkerVaultProductionProtocolFixtureComponents(input) {
  const label = "provider_worker_vault_production_protocol_fixture_components";
  const descriptors = assertExactDataObject(input, PROTOCOL_FIXTURE_CALLBACK_FIELDS, label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  const callbacks = Object.create(null);
  for (const field of PROTOCOL_FIXTURE_CALLBACK_FIELDS.slice(1)) {
    const callback = descriptorValue(descriptors, field);
    if (typeof callback !== "function" || utilIsProxy(callback)) {
      throw compositionError(`${label}_${field}_callback_invalid`);
    }
    callbacks[field] = callback;
  }
  const components = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: "provider_worker_vault_production_protocol_fixture_components",
    assurance: PROVIDER_WORKER_VAULT_PROTOCOL_FIXTURE_ASSURANCE,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
    toJSON: rejectSerialization,
  });
  PROTOCOL_FIXTURE_COMPONENTS.add(components);
  PROTOCOL_FIXTURE_PRIVATE.set(components, objectFreeze({
    callbacks: objectFreeze(callbacks),
    claimed_lineages: new Set(),
  }));
  return components;
}

function assertProtocolFixtureComponents(input) {
  const state = input == null ? null : PROTOCOL_FIXTURE_PRIVATE.get(input);
  if (!input || !state || !PROTOCOL_FIXTURE_COMPONENTS.has(input) || !objectIsFrozen(input)
      || input.version !== PROVIDER_WORKER_VAULT_COMPOSITION_VERSION
      || input.kind !== "provider_worker_vault_production_protocol_fixture_components"
      || input.assurance !== PROVIDER_WORKER_VAULT_PROTOCOL_FIXTURE_ASSURANCE
      || input.production_ready !== false
      || input.hardware_access_authorized !== false
      || input.execution_authority !== false
      || input.toJSON !== rejectSerialization
      || reflectOwnKeys(input).length !== COMPONENT_PUBLIC_FIELDS.length) {
    throw compositionError("provider_worker_vault_protocol_fixture_components_untrusted");
  }
  return state;
}

function assertProviderWorkerVaultProductionPortSet(input, expectedLineage = null) {
  const state = input == null ? null : PRODUCTION_PORT_SET_PRIVATE.get(input);
  const operations = state == null ? null : state.operations;
  const operationDescriptors = isPlainDataObject(operations)
    ? objectGetOwnPropertyDescriptors(operations) : null;
  const operationKeys = operationDescriptors === null
    ? [] : reflectOwnKeys(operationDescriptors);
  if (!input || !state || !PRODUCTION_PORT_SETS.has(input) || !objectIsFrozen(input)
      || input.version !== PROVIDER_WORKER_VAULT_COMPOSITION_VERSION
      || input.kind !== "provider_worker_vault_production_port_set"
      || input.assurance !== PROVIDER_WORKER_VAULT_PRODUCTION_ASSURANCE
      || input.production_ready !== true
      || input.hardware_access_authorized !== true
      || input.execution_authority !== true
      || input.toJSON !== rejectSerialization
      || reflectOwnKeys(input).length !== COMPONENT_PUBLIC_FIELDS.length
      || !objectIsFrozen(state)
      || typeof state.assert_transaction_capability !== "function"
      || utilIsProxy(state.assert_transaction_capability)
      || !objectIsFrozen(operations)
      || operationKeys.length !== PRODUCTION_PORT_OPERATION_FIELDS.length
      || operationKeys.some(
        (field) => typeof field !== "string"
          || !PRODUCTION_PORT_OPERATION_FIELDS.includes(field)
          || !operationDescriptors[field]
          || !objectHasOwn(operationDescriptors[field], "value")
          || typeof operationDescriptors[field].value !== "function"
          || utilIsProxy(operationDescriptors[field].value),
      )
      || !DIGEST_PATTERN.test(state.execution_lineage_digest)
      || (expectedLineage !== null
        && state.execution_lineage_digest !== expectedLineage.execution_lineage_digest)) {
    throw compositionError("provider_worker_vault_production_port_set_untrusted");
  }
  // No JavaScript constructor exists. Future native/vault integration must
  // populate this private brand only after each owning module's own private
  // assertion succeeds; booleans, digests, and callback objects never enroll.
  return input;
}

function assertConformanceComponents(input) {
  const state = input == null ? null : COMPONENT_PRIVATE.get(input);
  if (!input || !state || !COMPONENTS.has(input) || !objectIsFrozen(input)) {
    throw compositionError("provider_worker_vault_components_untrusted");
  }
  const descriptors = objectGetOwnPropertyDescriptors(input);
  const keys = reflectOwnKeys(descriptors);
  if (keys.length !== COMPONENT_PUBLIC_FIELDS.length
      || keys.some((key) => typeof key !== "string" || !COMPONENT_PUBLIC_FIELDS.includes(key))) {
    throw compositionError("provider_worker_vault_components_corrupt");
  }
  if (input.version !== PROVIDER_WORKER_VAULT_COMPOSITION_VERSION
      || input.kind !== "provider_worker_vault_conformance_components"
      || input.assurance !== PROVIDER_WORKER_VAULT_CONFORMANCE_ASSURANCE
      || input.production_ready !== false
      || input.hardware_access_authorized !== false
      || input.execution_authority !== false
      || input.toJSON !== rejectSerialization) {
    throw compositionError("provider_worker_vault_components_corrupt");
  }
  return state;
}

async function invokeConformanceComponent(componentState, name, request) {
  let raw;
  try {
    const startedAt = process.hrtime.bigint();
    raw = reflectApply(componentState.callbacks[name], undefined, [objectFreeze(request)]);
    if (utilIsProxy(raw)) throw compositionError("component_result_proxy_forbidden");
    const synchronousElapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
    if (synchronousElapsedMs >= CONFORMANCE_CALLBACK_TIMEOUT_MS) {
      if (utilIsPromise(raw)) {
        reflectApply(promisePrototypeThen, raw, [
          (lateValue) => zeroExposedByteSurface(lateValue),
          () => undefined,
        ]);
      } else {
        zeroExposedByteSurface(raw);
      }
      throw compositionError("component_result_timeout");
    }
    if (utilIsPromise(raw)) {
      const pending = raw;
      let timer = null;
      const observed = new Promise((resolve) => {
        reflectApply(promisePrototypeThen, pending, [
          (value) => resolve({ disposition: "fulfilled", value }),
          () => resolve({ disposition: "rejected", value: null }),
        ]);
      });
      const timeout = new Promise((resolve) => {
        timer = setTimeout(
          () => resolve({ disposition: "timeout", value: null }),
          Math.max(1, CONFORMANCE_CALLBACK_TIMEOUT_MS - synchronousElapsedMs),
        );
      });
      const settled = await Promise.race([observed, timeout]);
      if (timer !== null) clearTimeout(timer);
      if (settled.disposition === "timeout") {
        reflectApply(promisePrototypeThen, pending, [
          (lateValue) => zeroExposedByteSurface(lateValue),
          () => undefined,
        ]);
        throw compositionError("component_result_timeout");
      }
      if (settled.disposition !== "fulfilled") {
        throw compositionError("component_result_rejected");
      }
      raw = settled.value;
    }
  } catch {
    throw compositionError(`provider_worker_vault_${name}_failed`);
  }
  if (utilIsProxy(raw) || utilIsPromise(raw)) {
    throw compositionError(`provider_worker_vault_${name}_result_invalid`);
  }
  return raw;
}

async function invokeProductionComponent(componentState, name, request) {
  let raw;
  try {
    const operations = componentState == null ? null : componentState.operations;
    const operation = operations == null ? null : operations[name];
    if (typeof operation !== "function" || utilIsProxy(operation)) {
      throw compositionError("production_component_operation_unavailable");
    }
    raw = reflectApply(operation, undefined, [objectFreeze(request)]);
    if (utilIsProxy(raw)) throw compositionError("production_component_result_proxy_forbidden");
    if (utilIsPromise(raw)) raw = await raw;
  } catch {
    throw compositionError(`provider_worker_vault_${name}_failed`);
  }
  if (utilIsProxy(raw) || utilIsPromise(raw)) {
    throw compositionError(`provider_worker_vault_${name}_result_invalid`);
  }
  return raw;
}

function invokeCompositionComponent(componentState, name, request, production) {
  return production
    ? invokeProductionComponent(componentState, name, request)
    : invokeConformanceComponent(componentState, name, request);
}

function commonReceiptProjection(raw, fields, label) {
  const descriptors = assertExactDataObject(raw, fields, label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  const kind = descriptorValue(descriptors, "kind");
  if (kind !== label) throw compositionError(`${label}_kind_invalid`);
  return descriptors;
}

function normalizeRedemptionReceipt(raw, lineage) {
  const label = "grant_redemption_receipt";
  const fields = [
    "version", "kind", "execution_lineage_digest", "exchange_id",
    "grant_envelope_digest", "grant_journal_entry_digest", "go_envelope_digest",
    "go_journal_entry_digest", "active_command_input_ref", "active_command_input_digest",
    "cleanup_command_input_ref", "cleanup_command_input_digest", "receipt_digest",
  ];
  const d = commonReceiptProjection(raw, fields, label);
  const projection = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: label,
    execution_lineage_digest: assertDigest(descriptorValue(d, "execution_lineage_digest"), label),
    exchange_id: assertOpaqueRef(descriptorValue(d, "exchange_id"), label),
    grant_envelope_digest: assertDigest(descriptorValue(d, "grant_envelope_digest"), label),
    grant_journal_entry_digest: assertDigest(
      descriptorValue(d, "grant_journal_entry_digest"), label,
    ),
    go_envelope_digest: assertDigest(descriptorValue(d, "go_envelope_digest"), label),
    go_journal_entry_digest: assertDigest(
      descriptorValue(d, "go_journal_entry_digest"), label,
    ),
    active_command_input_ref: assertOpaqueRef(
      descriptorValue(d, "active_command_input_ref"), label,
    ),
    active_command_input_digest: assertDigest(
      descriptorValue(d, "active_command_input_digest"), label,
    ),
    cleanup_command_input_ref: assertOpaqueRef(
      descriptorValue(d, "cleanup_command_input_ref"), label,
    ),
    cleanup_command_input_digest: assertDigest(
      descriptorValue(d, "cleanup_command_input_digest"), label,
    ),
  });
  for (const field of [
    "execution_lineage_digest", "exchange_id", "grant_envelope_digest",
    "grant_journal_entry_digest", "go_envelope_digest", "go_journal_entry_digest",
    "active_command_input_ref", "active_command_input_digest", "cleanup_command_input_ref",
    "cleanup_command_input_digest",
  ]) {
    if (projection[field] !== lineage[field]) {
      throw compositionError(`grant_redemption_${field}_mismatch`);
    }
  }
  const receiptDigest = assertDigest(descriptorValue(d, "receipt_digest"), label);
  assertRecordDigest(
    projection,
    receiptDigest,
    "hacker-bob/provider-worker-vault-grant-redemption-receipt/v1",
    label,
  );
  return objectFreeze({ ...projection, receipt_digest: receiptDigest });
}

function normalizeCommandClaim(raw, lineage) {
  const label = "compiled_command_claim_receipt";
  const fields = [
    "version", "kind", "execution_lineage_digest", "provider_id", "operation_id",
    "compiler_id", "compiler_manifest_digest", "compiler_registry_digest",
    "source_profile_digest", "schema_id", "capability_id", "variant_id",
    "parameter_selector_id", "canonical_command_digest", "compiled_operation_digest",
    "provider_command_ref", "requested_effects_digest", "safety_supervisor_plan_digest",
    "runtime_availability", "compiled_command_id", "compiled_command_capability_digest",
    "active_command_input_ref",
    "active_command_input_digest", "maximum_response_bytes", "claim_receipt_digest",
    "command_handle",
  ];
  const d = commonReceiptProjection(raw, fields, label);
  const commandHandle = assertOpaqueCapability(descriptorValue(d, "command_handle"), label);
  const projection = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: label,
    execution_lineage_digest: assertDigest(descriptorValue(d, "execution_lineage_digest"), label),
    provider_id: assertOpaqueRef(descriptorValue(d, "provider_id"), label),
    operation_id: assertOpaqueRef(descriptorValue(d, "operation_id"), label),
    compiler_id: assertOpaqueRef(descriptorValue(d, "compiler_id"), label),
    compiler_manifest_digest: assertDigest(
      descriptorValue(d, "compiler_manifest_digest"), label,
    ),
    compiler_registry_digest: assertDigest(
      descriptorValue(d, "compiler_registry_digest"), label,
    ),
    source_profile_digest: assertDigest(descriptorValue(d, "source_profile_digest"), label),
    schema_id: assertOpaqueRef(descriptorValue(d, "schema_id"), label),
    capability_id: assertOpaqueRef(descriptorValue(d, "capability_id"), label),
    variant_id: assertOpaqueRef(descriptorValue(d, "variant_id"), label),
    parameter_selector_id: assertOpaqueRef(
      descriptorValue(d, "parameter_selector_id"), label,
    ),
    canonical_command_digest: assertDigest(
      descriptorValue(d, "canonical_command_digest"), label,
    ),
    compiled_operation_digest: assertDigest(
      descriptorValue(d, "compiled_operation_digest"), label,
    ),
    provider_command_ref: assertOpaqueRef(descriptorValue(d, "provider_command_ref"), label),
    requested_effects_digest: assertDigest(
      descriptorValue(d, "requested_effects_digest"), label,
    ),
    safety_supervisor_plan_digest: assertDigest(
      descriptorValue(d, "safety_supervisor_plan_digest"), label,
    ),
    runtime_availability: assertOpaqueRef(descriptorValue(d, "runtime_availability"), label),
    compiled_command_id: assertOpaqueRef(descriptorValue(d, "compiled_command_id"), label),
    compiled_command_capability_digest: assertDigest(
      descriptorValue(d, "compiled_command_capability_digest"), label,
    ),
    active_command_input_ref: assertOpaqueRef(
      descriptorValue(d, "active_command_input_ref"), label,
    ),
    active_command_input_digest: assertDigest(
      descriptorValue(d, "active_command_input_digest"), label,
    ),
    maximum_response_bytes: assertPositiveInteger(
      descriptorValue(d, "maximum_response_bytes"), label, MAX_RESPONSE_BYTES,
    ),
  });
  for (const field of [
    "execution_lineage_digest", "provider_id", "operation_id", "compiler_id",
    "compiler_manifest_digest", "compiler_registry_digest", "source_profile_digest",
    "schema_id", "capability_id", "variant_id", "parameter_selector_id",
    "canonical_command_digest", "compiled_operation_digest", "provider_command_ref",
    "requested_effects_digest", "safety_supervisor_plan_digest", "runtime_availability",
    "compiled_command_id",
    "compiled_command_capability_digest",
    "active_command_input_ref", "active_command_input_digest", "maximum_response_bytes",
  ]) {
    if (projection[field] !== lineage[field]) {
      throw compositionError(`compiled_command_claim_${field}_mismatch`);
    }
  }
  const receiptDigest = assertDigest(descriptorValue(d, "claim_receipt_digest"), label);
  assertRecordDigest(
    projection,
    receiptDigest,
    "hacker-bob/provider-worker-vault-compiled-command-claim/v1",
    label,
  );
  return objectFreeze({ ...projection, claim_receipt_digest: receiptDigest, command_handle: commandHandle });
}

function normalizeWorkerLaunch(raw, lineage) {
  const label = "worker_launch_receipt";
  const fields = [
    "version", "kind", "execution_lineage_digest", "worker_bundle_digest",
    "worker_launch_digest", "worker_process_instance_digest", "launch_receipt_digest",
    "worker_handle",
  ];
  const d = commonReceiptProjection(raw, fields, label);
  const workerHandle = assertOpaqueCapability(descriptorValue(d, "worker_handle"), label);
  const projection = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: label,
    execution_lineage_digest: assertDigest(descriptorValue(d, "execution_lineage_digest"), label),
    worker_bundle_digest: assertDigest(descriptorValue(d, "worker_bundle_digest"), label),
    worker_launch_digest: assertDigest(descriptorValue(d, "worker_launch_digest"), label),
    worker_process_instance_digest: assertDigest(
      descriptorValue(d, "worker_process_instance_digest"), label,
    ),
  });
  for (const field of [
    "execution_lineage_digest", "worker_bundle_digest", "worker_launch_digest",
    "worker_process_instance_digest",
  ]) {
    if (projection[field] !== lineage[field]) {
      throw compositionError(`worker_launch_${field}_mismatch`);
    }
  }
  const receiptDigest = assertDigest(descriptorValue(d, "launch_receipt_digest"), label);
  assertRecordDigest(
    projection, receiptDigest, "hacker-bob/provider-worker-vault-worker-launch/v1", label,
  );
  return objectFreeze({ ...projection, launch_receipt_digest: receiptDigest, worker_handle: workerHandle });
}

function normalizeWorkerFence(raw, lineage) {
  const label = "worker_fence_receipt";
  const fields = [
    "version", "kind", "execution_lineage_digest", "worker_launch_digest",
    "worker_fence_digest", "resource_fence_digest", "lease_id", "resource_epoch",
    "effect_deadline_monotonic_ns", "transport_binding_digest", "fence_receipt_digest",
    "worker_fence_handle",
  ];
  const d = commonReceiptProjection(raw, fields, label);
  const workerFenceHandle = assertOpaqueCapability(
    descriptorValue(d, "worker_fence_handle"), label,
  );
  const projection = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: label,
    execution_lineage_digest: assertDigest(descriptorValue(d, "execution_lineage_digest"), label),
    worker_launch_digest: assertDigest(descriptorValue(d, "worker_launch_digest"), label),
    worker_fence_digest: assertDigest(descriptorValue(d, "worker_fence_digest"), label),
    resource_fence_digest: assertDigest(descriptorValue(d, "resource_fence_digest"), label),
    lease_id: assertOpaqueRef(descriptorValue(d, "lease_id"), label),
    resource_epoch: assertUint64(descriptorValue(d, "resource_epoch"), label),
    effect_deadline_monotonic_ns: assertUint64(
      descriptorValue(d, "effect_deadline_monotonic_ns"), label,
    ),
    transport_binding_digest: assertDigest(
      descriptorValue(d, "transport_binding_digest"), label,
    ),
  });
  for (const field of [
    "execution_lineage_digest", "worker_launch_digest", "worker_fence_digest",
    "resource_fence_digest", "lease_id", "resource_epoch", "effect_deadline_monotonic_ns",
    "transport_binding_digest",
  ]) {
    if (projection[field] !== lineage[field]) {
      throw compositionError(`worker_fence_${field}_mismatch`);
    }
  }
  const receiptDigest = assertDigest(descriptorValue(d, "fence_receipt_digest"), label);
  assertRecordDigest(
    projection, receiptDigest, "hacker-bob/provider-worker-vault-worker-fence/v1", label,
  );
  return objectFreeze({
    ...projection,
    fence_receipt_digest: receiptDigest,
    worker_fence_handle: workerFenceHandle,
  });
}

function normalizeDurableExecutionClaim(raw, lineage) {
  const label = "durable_execution_claim_receipt";
  const fields = [
    "version", "kind", "execution_lineage_digest", "attempt_id", "execution_claim_ref",
    "claim_generation", "claim_disposition", "claimed_at_monotonic_ns",
    "claim_receipt_digest",
  ];
  const d = commonReceiptProjection(raw, fields, label);
  const projection = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: label,
    execution_lineage_digest: assertDigest(descriptorValue(d, "execution_lineage_digest"), label),
    attempt_id: assertOpaqueRef(descriptorValue(d, "attempt_id"), label),
    execution_claim_ref: assertOpaqueRef(descriptorValue(d, "execution_claim_ref"), label),
    claim_generation: assertUint64(descriptorValue(d, "claim_generation"), label),
    claim_disposition: assertEnum(
      descriptorValue(d, "claim_disposition"), ["new", "existing"], label,
    ),
    claimed_at_monotonic_ns: assertUint64(
      descriptorValue(d, "claimed_at_monotonic_ns"), label,
    ),
  });
  if (projection.execution_lineage_digest !== lineage.execution_lineage_digest
      || projection.attempt_id !== lineage.attempt_id) {
    throw compositionError("durable_execution_claim_lineage_mismatch");
  }
  const receiptDigest = assertDigest(descriptorValue(d, "claim_receipt_digest"), label);
  assertRecordDigest(
    projection,
    receiptDigest,
    "hacker-bob/provider-worker-vault-durable-execution-claim/v1",
    label,
  );
  return objectFreeze({ ...projection, claim_receipt_digest: receiptDigest });
}

function assertExactExecutionClaimReadback(readback, claimed) {
  for (const field of [
    "execution_lineage_digest", "attempt_id", "execution_claim_ref", "claim_generation",
    "claimed_at_monotonic_ns", "claim_receipt_digest",
  ]) {
    if (readback[field] !== claimed[field]) {
      throw compositionError("durable_execution_claim_readback_mismatch");
    }
  }
  return readback;
}

function normalizeEffectDeadlineFence(raw, lineage) {
  const label = "trusted_effect_deadline_fence_receipt";
  const fields = [
    "version", "kind", "execution_lineage_digest", "effect_deadline_monotonic_ns",
    "resource_fence_digest", "worker_fence_digest", "transport_binding_digest",
    "live_observation_digest", "deadline_fence_receipt_digest",
  ];
  const d = commonReceiptProjection(raw, fields, label);
  const projection = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: label,
    execution_lineage_digest: assertDigest(descriptorValue(d, "execution_lineage_digest"), label),
    effect_deadline_monotonic_ns: assertUint64(
      descriptorValue(d, "effect_deadline_monotonic_ns"), label,
    ),
    resource_fence_digest: assertDigest(descriptorValue(d, "resource_fence_digest"), label),
    worker_fence_digest: assertDigest(descriptorValue(d, "worker_fence_digest"), label),
    transport_binding_digest: assertDigest(
      descriptorValue(d, "transport_binding_digest"), label,
    ),
    live_observation_digest: assertDigest(
      descriptorValue(d, "live_observation_digest"), label,
    ),
  });
  for (const field of [
    "execution_lineage_digest", "effect_deadline_monotonic_ns", "resource_fence_digest",
    "worker_fence_digest", "transport_binding_digest",
  ]) {
    if (projection[field] !== lineage[field]) {
      throw compositionError(`trusted_effect_deadline_fence_${field}_mismatch`);
    }
  }
  const receiptDigest = assertDigest(
    descriptorValue(d, "deadline_fence_receipt_digest"), label,
  );
  assertRecordDigest(
    projection,
    receiptDigest,
    "hacker-bob/provider-worker-vault-trusted-effect-deadline-fence/v1",
    label,
  );
  return objectFreeze({ ...projection, deadline_fence_receipt_digest: receiptDigest });
}

function normalizeTransportVaultResult(
  raw,
  lineage,
  executionClaim = null,
  deadlineFence = null,
) {
  const label = "transport_reserved_vault_result";
  const productionProtocol = executionClaim !== null && deadlineFence !== null;
  if ((executionClaim === null) !== (deadlineFence === null)) {
    throw compositionError("transport_vault_protocol_context_incomplete");
  }
  const fields = [
    "version", "kind", "execution_lineage_digest", "transaction_ref",
    "provider_id", "operation_id", "compiler_id", "compiler_manifest_digest",
    "compiler_registry_digest", "compiled_operation_digest", "provider_command_ref",
    "requested_effects_digest", "runtime_availability", "compiled_command_id",
    "compiled_command_capability_digest",
    "active_command_input_ref",
    "active_command_input_digest", "worker_launch_digest", "worker_fence_digest",
    "resource_fence_digest", "transport_binding_digest", "vault_reservation_handle",
    "vault_reservation_digest", "vault_ingest_capability_digest", "artifact_handle",
    ...(productionProtocol
      ? ["execution_claim_receipt_digest", "deadline_fence_receipt_digest"] : []),
    "response_digest", "response_byte_length", "result_code", "device_state_digest",
    "vault_commit_receipt_digest", "raw_response_custody_digest", "transaction_receipt_digest",
  ];
  const d = commonReceiptProjection(raw, fields, label);
  const projection = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: label,
    execution_lineage_digest: assertDigest(descriptorValue(d, "execution_lineage_digest"), label),
    transaction_ref: assertOpaqueRef(descriptorValue(d, "transaction_ref"), label),
    provider_id: assertOpaqueRef(descriptorValue(d, "provider_id"), label),
    operation_id: assertOpaqueRef(descriptorValue(d, "operation_id"), label),
    compiler_id: assertOpaqueRef(descriptorValue(d, "compiler_id"), label),
    compiler_manifest_digest: assertDigest(
      descriptorValue(d, "compiler_manifest_digest"), label,
    ),
    compiler_registry_digest: assertDigest(
      descriptorValue(d, "compiler_registry_digest"), label,
    ),
    compiled_operation_digest: assertDigest(
      descriptorValue(d, "compiled_operation_digest"), label,
    ),
    provider_command_ref: assertOpaqueRef(descriptorValue(d, "provider_command_ref"), label),
    requested_effects_digest: assertDigest(
      descriptorValue(d, "requested_effects_digest"), label,
    ),
    runtime_availability: assertOpaqueRef(descriptorValue(d, "runtime_availability"), label),
    compiled_command_id: assertOpaqueRef(descriptorValue(d, "compiled_command_id"), label),
    compiled_command_capability_digest: assertDigest(
      descriptorValue(d, "compiled_command_capability_digest"), label,
    ),
    active_command_input_ref: assertOpaqueRef(
      descriptorValue(d, "active_command_input_ref"), label,
    ),
    active_command_input_digest: assertDigest(
      descriptorValue(d, "active_command_input_digest"), label,
    ),
    worker_launch_digest: assertDigest(descriptorValue(d, "worker_launch_digest"), label),
    worker_fence_digest: assertDigest(descriptorValue(d, "worker_fence_digest"), label),
    resource_fence_digest: assertDigest(descriptorValue(d, "resource_fence_digest"), label),
    transport_binding_digest: assertDigest(
      descriptorValue(d, "transport_binding_digest"), label,
    ),
    vault_reservation_handle: assertOpaqueRef(
      descriptorValue(d, "vault_reservation_handle"), label,
    ),
    vault_reservation_digest: assertDigest(
      descriptorValue(d, "vault_reservation_digest"), label,
    ),
    vault_ingest_capability_digest: assertDigest(
      descriptorValue(d, "vault_ingest_capability_digest"), label,
    ),
    ...(productionProtocol ? {
      execution_claim_receipt_digest: assertDigest(
        descriptorValue(d, "execution_claim_receipt_digest"), label,
      ),
      deadline_fence_receipt_digest: assertDigest(
        descriptorValue(d, "deadline_fence_receipt_digest"), label,
      ),
    } : {}),
    artifact_handle: assertArtifactHandle(descriptorValue(d, "artifact_handle"), "artifact_handle"),
    response_digest: assertDigest(descriptorValue(d, "response_digest"), label),
    response_byte_length: assertPositiveInteger(
      descriptorValue(d, "response_byte_length"), label, MAX_RESPONSE_BYTES,
    ),
    result_code: assertResultCode(descriptorValue(d, "result_code"), label),
    device_state_digest: assertDigest(descriptorValue(d, "device_state_digest"), label),
    vault_commit_receipt_digest: assertDigest(
      descriptorValue(d, "vault_commit_receipt_digest"), label,
    ),
    raw_response_custody_digest: assertDigest(
      descriptorValue(d, "raw_response_custody_digest"), label,
    ),
  });
  for (const field of [
    "execution_lineage_digest", "provider_id", "operation_id", "compiler_id",
    "compiler_manifest_digest", "compiler_registry_digest", "compiled_operation_digest",
    "provider_command_ref", "requested_effects_digest", "runtime_availability",
    "compiled_command_id",
    "compiled_command_capability_digest",
    "active_command_input_ref", "active_command_input_digest", "worker_launch_digest",
    "worker_fence_digest", "resource_fence_digest", "transport_binding_digest",
    "vault_reservation_handle", "vault_reservation_digest", "vault_ingest_capability_digest",
  ]) {
    if (projection[field] !== lineage[field]) {
      throw compositionError(`transport_vault_${field}_mismatch`);
    }
  }
  if (projection.response_byte_length > lineage.maximum_response_bytes
      || projection.response_byte_length > lineage.vault_byte_ceiling) {
    throw compositionError("transport_vault_response_exceeds_bound_sink");
  }
  if (projection.result_code !== lineage.expected_result_code) {
    throw compositionError("transport_vault_result_code_not_precommitted");
  }
  if (productionProtocol
      && (projection.execution_claim_receipt_digest !== executionClaim.claim_receipt_digest
        || projection.deadline_fence_receipt_digest
          !== deadlineFence.deadline_fence_receipt_digest)) {
    throw compositionError("transport_vault_production_protocol_binding_mismatch");
  }
  const receiptDigest = assertDigest(descriptorValue(d, "transaction_receipt_digest"), label);
  assertRecordDigest(
    projection,
    receiptDigest,
    "hacker-bob/provider-worker-vault-transport-reserved-vault-result/v1",
    label,
  );
  return objectFreeze({ ...projection, transaction_receipt_digest: receiptDigest });
}

function normalizeVaultIngestReceipt(raw, lineage, transaction, executionClaim, deadlineFence) {
  const label = "reserved_vault_ingest_receipt";
  const fields = [
    "version", "kind", "execution_lineage_digest", "vault_reservation_handle",
    "vault_reservation_digest", "vault_ingest_capability_digest", "artifact_handle",
    "execution_claim_receipt_digest", "deadline_fence_receipt_digest",
    "response_digest", "response_byte_length", "transaction_receipt_digest",
    "vault_commit_receipt_digest", "raw_response_custody_digest", "ingest_receipt_digest",
  ];
  const d = commonReceiptProjection(raw, fields, label);
  const projection = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: label,
    execution_lineage_digest: assertDigest(descriptorValue(d, "execution_lineage_digest"), label),
    vault_reservation_handle: assertOpaqueRef(
      descriptorValue(d, "vault_reservation_handle"), label,
    ),
    vault_reservation_digest: assertDigest(
      descriptorValue(d, "vault_reservation_digest"), label,
    ),
    vault_ingest_capability_digest: assertDigest(
      descriptorValue(d, "vault_ingest_capability_digest"), label,
    ),
    execution_claim_receipt_digest: assertDigest(
      descriptorValue(d, "execution_claim_receipt_digest"), label,
    ),
    deadline_fence_receipt_digest: assertDigest(
      descriptorValue(d, "deadline_fence_receipt_digest"), label,
    ),
    artifact_handle: assertArtifactHandle(descriptorValue(d, "artifact_handle"), label),
    response_digest: assertDigest(descriptorValue(d, "response_digest"), label),
    response_byte_length: assertPositiveInteger(
      descriptorValue(d, "response_byte_length"), label, MAX_RESPONSE_BYTES,
    ),
    transaction_receipt_digest: assertDigest(
      descriptorValue(d, "transaction_receipt_digest"), label,
    ),
    vault_commit_receipt_digest: assertDigest(
      descriptorValue(d, "vault_commit_receipt_digest"), label,
    ),
    raw_response_custody_digest: assertDigest(
      descriptorValue(d, "raw_response_custody_digest"), label,
    ),
  });
  for (const field of [
    "execution_lineage_digest", "vault_reservation_handle", "vault_reservation_digest",
    "vault_ingest_capability_digest",
  ]) {
    if (projection[field] !== lineage[field]) {
      throw compositionError(`reserved_vault_ingest_${field}_mismatch`);
    }
  }
  if (projection.execution_claim_receipt_digest !== executionClaim.claim_receipt_digest
      || projection.deadline_fence_receipt_digest
        !== deadlineFence.deadline_fence_receipt_digest) {
    throw compositionError("reserved_vault_ingest_production_protocol_binding_mismatch");
  }
  for (const field of [
    "artifact_handle", "response_digest", "response_byte_length", "transaction_receipt_digest",
    "vault_commit_receipt_digest", "raw_response_custody_digest",
  ]) {
    if (projection[field] !== transaction[field]) {
      throw compositionError(`reserved_vault_ingest_${field}_mismatch`);
    }
  }
  const receiptDigest = assertDigest(descriptorValue(d, "ingest_receipt_digest"), label);
  assertRecordDigest(
    projection,
    receiptDigest,
    "hacker-bob/provider-worker-vault-reserved-vault-ingest/v1",
    label,
  );
  return objectFreeze({ ...projection, ingest_receipt_digest: receiptDigest });
}

function normalizeCancellationReceipt(raw, lineage) {
  const label = "before_effect_cancellation_receipt";
  const fields = [
    "version", "kind", "execution_lineage_digest", "active_command_input_ref",
    "active_command_input_digest", "cleanup_command_input_ref", "cleanup_command_input_digest",
    "effect_state", "transport_fenced", "capabilities_closed", "worker_terminated",
    "reservation_state", "cancellation_receipt_digest",
  ];
  const d = commonReceiptProjection(raw, fields, label);
  const projection = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: label,
    execution_lineage_digest: assertDigest(descriptorValue(d, "execution_lineage_digest"), label),
    active_command_input_ref: assertOpaqueRef(
      descriptorValue(d, "active_command_input_ref"), label,
    ),
    active_command_input_digest: assertDigest(
      descriptorValue(d, "active_command_input_digest"), label,
    ),
    cleanup_command_input_ref: assertOpaqueRef(
      descriptorValue(d, "cleanup_command_input_ref"), label,
    ),
    cleanup_command_input_digest: assertDigest(
      descriptorValue(d, "cleanup_command_input_digest"), label,
    ),
    effect_state: assertEnum(descriptorValue(d, "effect_state"), ["no_effect"], label),
    transport_fenced: assertBoolean(descriptorValue(d, "transport_fenced"), true, label),
    capabilities_closed: assertBoolean(descriptorValue(d, "capabilities_closed"), true, label),
    worker_terminated: assertBoolean(descriptorValue(d, "worker_terminated"), true, label),
    reservation_state: assertEnum(descriptorValue(d, "reservation_state"), ["released"], label),
  });
  for (const field of [
    "execution_lineage_digest", "active_command_input_ref", "active_command_input_digest",
    "cleanup_command_input_ref", "cleanup_command_input_digest",
  ]) {
    if (projection[field] !== lineage[field]) {
      throw compositionError(`cancellation_${field}_mismatch`);
    }
  }
  const receiptDigest = assertDigest(descriptorValue(d, "cancellation_receipt_digest"), label);
  assertRecordDigest(
    projection, receiptDigest, "hacker-bob/provider-worker-vault-before-effect-cancellation/v1", label,
  );
  return objectFreeze({ ...projection, cancellation_receipt_digest: receiptDigest });
}

function normalizeRestorationReceipt(raw, lineage, completedTransaction) {
  const label = "post_effect_restoration_receipt";
  const fields = [
    "version", "kind", "execution_lineage_digest", "active_command_input_ref",
    "active_command_input_digest", "cleanup_command_input_ref", "cleanup_command_input_digest",
    "transaction_receipt_digest", "transport_fenced", "capabilities_closed",
    "restoration_state", "reservation_state", "restoration_receipt_digest",
  ];
  const d = commonReceiptProjection(raw, fields, label);
  const projection = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: label,
    execution_lineage_digest: assertDigest(descriptorValue(d, "execution_lineage_digest"), label),
    active_command_input_ref: assertOpaqueRef(
      descriptorValue(d, "active_command_input_ref"), label,
    ),
    active_command_input_digest: assertDigest(
      descriptorValue(d, "active_command_input_digest"), label,
    ),
    cleanup_command_input_ref: assertOpaqueRef(
      descriptorValue(d, "cleanup_command_input_ref"), label,
    ),
    cleanup_command_input_digest: assertDigest(
      descriptorValue(d, "cleanup_command_input_digest"), label,
    ),
    transaction_receipt_digest: assertNullableDigest(
      descriptorValue(d, "transaction_receipt_digest"), label,
    ),
    transport_fenced: assertBoolean(descriptorValue(d, "transport_fenced"), true, label),
    capabilities_closed: assertBoolean(descriptorValue(d, "capabilities_closed"), true, label),
    restoration_state: assertEnum(
      descriptorValue(d, "restoration_state"),
      ["baseline_unchanged", "restored", "quarantined"],
      label,
    ),
    reservation_state: assertEnum(
      descriptorValue(d, "reservation_state"), ["consumed", "released", "quarantined"], label,
    ),
  });
  for (const field of [
    "execution_lineage_digest", "active_command_input_ref", "active_command_input_digest",
    "cleanup_command_input_ref", "cleanup_command_input_digest",
  ]) {
    if (projection[field] !== lineage[field]) {
      throw compositionError(`restoration_${field}_mismatch`);
    }
  }
  if (completedTransaction) {
    if (projection.transaction_receipt_digest !== completedTransaction.transaction_receipt_digest
        || !["baseline_unchanged", "restored"].includes(projection.restoration_state)
        || projection.reservation_state !== "consumed") {
      throw compositionError("completed_transaction_restoration_invalid");
    }
  } else if (projection.transaction_receipt_digest !== null
      || projection.restoration_state !== "quarantined"
      || projection.reservation_state !== "quarantined") {
    throw compositionError("ambiguous_restoration_must_remain_quarantined");
  }
  const receiptDigest = assertDigest(descriptorValue(d, "restoration_receipt_digest"), label);
  assertRecordDigest(
    projection, receiptDigest, "hacker-bob/provider-worker-vault-post-effect-restoration/v1", label,
  );
  return objectFreeze({ ...projection, restoration_receipt_digest: receiptDigest });
}

function createTerminalOutcome({
  lineage,
  terminalState,
  effectState,
  resultCode,
  transaction,
  cleanup,
  executionClaim,
  deadlineFence,
  vaultIngest,
}) {
  const projection = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    execution_lineage_digest: lineage.execution_lineage_digest,
    terminal_state: terminalState,
    effect_state: effectState,
    result_code: assertBoundedString(resultCode, "terminal_result_code"),
    transaction_result_code: transaction ? transaction.result_code : null,
    failure_code: terminalState === "completed" ? null : assertBoundedString(
      resultCode,
      "terminal_failure_code",
    ),
    vault_reservation_handle: lineage.vault_reservation_handle,
    vault_reservation_digest: lineage.vault_reservation_digest,
    artifact_handle: transaction ? transaction.artifact_handle : null,
    response_digest: transaction ? transaction.response_digest : null,
    response_byte_length: transaction ? transaction.response_byte_length : 0,
    device_state_digest: transaction ? transaction.device_state_digest : null,
    transaction_receipt_digest: transaction ? transaction.transaction_receipt_digest : null,
    vault_commit_receipt_digest: transaction ? transaction.vault_commit_receipt_digest : null,
    raw_response_custody_digest: transaction ? transaction.raw_response_custody_digest : null,
    execution_claim_ref: executionClaim ? executionClaim.execution_claim_ref : null,
    execution_claim_generation: executionClaim ? executionClaim.claim_generation : null,
    execution_claim_receipt_digest: executionClaim
      ? executionClaim.claim_receipt_digest : null,
    deadline_fence_receipt_digest: deadlineFence
      ? deadlineFence.deadline_fence_receipt_digest : null,
    vault_ingest_receipt_digest: vaultIngest ? vaultIngest.ingest_receipt_digest : null,
    cleanup_state: cleanup
      ? cleanup.restoration_state || "cancelled_no_effect"
      : "failed_ambiguous",
    cleanup_receipt_digest: cleanup
      ? cleanup.restoration_receipt_digest || cleanup.cancellation_receipt_digest
      : null,
  });
  return objectFreeze({
    ...projection,
    outcome_digest: digestRecord(
      "hacker-bob/provider-worker-vault-terminal-outcome/v1",
      projection,
    ),
  });
}

function normalizeTerminalCommit(raw, lineage, outcome) {
  const label = "durable_terminal_commit_receipt";
  const fields = [
    "version", "kind", "execution_lineage_digest", "outcome_digest", "terminal_state",
    "durable_exchange_plan_digest", "terminal_receipt_recipient_digest",
    "terminal_receipt_ref", "terminal_receipt_digest", "terminal_journal_entry_digest",
    "outbox_entry_ref", "outbox_entry_digest", "outbox_acknowledgement_digest",
    "journal_head_digest", "outbox_head_digest", "durability_head_digest",
    "commit_receipt_digest",
  ];
  const d = commonReceiptProjection(raw, fields, label);
  const projection = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: label,
    execution_lineage_digest: assertDigest(descriptorValue(d, "execution_lineage_digest"), label),
    outcome_digest: assertDigest(descriptorValue(d, "outcome_digest"), label),
    terminal_state: assertEnum(
      descriptorValue(d, "terminal_state"),
      ["completed", "rejected_no_effect", "ambiguous_quarantined"],
      label,
    ),
    durable_exchange_plan_digest: assertDigest(
      descriptorValue(d, "durable_exchange_plan_digest"), label,
    ),
    terminal_receipt_recipient_digest: assertDigest(
      descriptorValue(d, "terminal_receipt_recipient_digest"), label,
    ),
    terminal_receipt_ref: assertOpaqueRef(descriptorValue(d, "terminal_receipt_ref"), label),
    terminal_receipt_digest: assertDigest(descriptorValue(d, "terminal_receipt_digest"), label),
    terminal_journal_entry_digest: assertDigest(
      descriptorValue(d, "terminal_journal_entry_digest"), label,
    ),
    outbox_entry_ref: assertOpaqueRef(descriptorValue(d, "outbox_entry_ref"), label),
    outbox_entry_digest: assertDigest(descriptorValue(d, "outbox_entry_digest"), label),
    outbox_acknowledgement_digest: assertDigest(
      descriptorValue(d, "outbox_acknowledgement_digest"), label,
    ),
    journal_head_digest: assertDigest(descriptorValue(d, "journal_head_digest"), label),
    outbox_head_digest: assertDigest(descriptorValue(d, "outbox_head_digest"), label),
    durability_head_digest: assertDigest(descriptorValue(d, "durability_head_digest"), label),
  });
  if (projection.execution_lineage_digest !== lineage.execution_lineage_digest
      || projection.outcome_digest !== outcome.outcome_digest
      || projection.terminal_state !== outcome.terminal_state
      || projection.durable_exchange_plan_digest !== lineage.durable_exchange_plan_digest
      || projection.terminal_receipt_recipient_digest
        !== lineage.terminal_receipt_recipient_digest) {
    throw compositionError("durable_terminal_commit_binding_mismatch");
  }
  const receiptDigest = assertDigest(descriptorValue(d, "commit_receipt_digest"), label);
  assertRecordDigest(
    projection, receiptDigest, "hacker-bob/provider-worker-vault-durable-terminal-commit/v1", label,
  );
  return objectFreeze({ ...projection, commit_receipt_digest: receiptDigest });
}

function normalizeTerminalCommitReadback(
  raw,
  lineage,
  expectedOutcome = null,
  expectedTerminalCommit = null,
  expectedExecutionClaim = null,
) {
  const label = "durable_terminal_commit_readback";
  const fields = [
    "version", "kind", "execution_lineage_digest", "execution_claim_ref",
    "execution_claim_generation", "execution_claim_receipt_digest",
    "outcome_digest", "terminal_state", "terminal_commit_receipt_digest", "artifact_handle", "result_code",
    "response_byte_length", "readback_receipt_digest",
  ];
  const d = commonReceiptProjection(raw, fields, label);
  const terminalState = assertEnum(
    descriptorValue(d, "terminal_state"),
    ["completed", "rejected_no_effect", "ambiguous_quarantined"],
    label,
  );
  const artifactHandle = descriptorValue(d, "artifact_handle");
  const resultCode = descriptorValue(d, "result_code");
  const responseByteLength = descriptorValue(d, "response_byte_length");
  if (terminalState === "completed") {
    assertArtifactHandle(artifactHandle, label);
    if (resultCode !== lineage.expected_result_code) {
      throw compositionError("terminal_readback_result_code_not_precommitted");
    }
    assertPositiveInteger(responseByteLength, label, lineage.maximum_response_bytes);
  } else if (artifactHandle !== null || resultCode !== null || responseByteLength !== 0) {
    throw compositionError("noncompleted_terminal_readback_must_be_redacted");
  }
  const projection = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: label,
    execution_lineage_digest: assertDigest(descriptorValue(d, "execution_lineage_digest"), label),
    execution_claim_ref: assertOpaqueRef(descriptorValue(d, "execution_claim_ref"), label),
    execution_claim_generation: assertUint64(
      descriptorValue(d, "execution_claim_generation"), label,
    ),
    execution_claim_receipt_digest: assertDigest(
      descriptorValue(d, "execution_claim_receipt_digest"), label,
    ),
    outcome_digest: assertDigest(descriptorValue(d, "outcome_digest"), label),
    terminal_state: terminalState,
    terminal_commit_receipt_digest: assertDigest(
      descriptorValue(d, "terminal_commit_receipt_digest"), label,
    ),
    artifact_handle: artifactHandle,
    result_code: resultCode,
    response_byte_length: responseByteLength,
  });
  if (projection.execution_lineage_digest !== lineage.execution_lineage_digest
      || (expectedOutcome !== null
        && projection.outcome_digest !== expectedOutcome.outcome_digest)
      || (expectedOutcome !== null
        && projection.terminal_state !== expectedOutcome.terminal_state)
      || (expectedTerminalCommit !== null
        && projection.terminal_commit_receipt_digest
          !== expectedTerminalCommit.commit_receipt_digest)
      || (expectedExecutionClaim !== null
        && (projection.execution_claim_ref !== expectedExecutionClaim.execution_claim_ref
          || projection.execution_claim_generation !== expectedExecutionClaim.claim_generation))
      || (expectedOutcome !== null
        && projection.execution_claim_receipt_digest
          !== expectedOutcome.execution_claim_receipt_digest)
      || (expectedOutcome !== null && expectedOutcome.terminal_state === "completed"
        && (projection.artifact_handle !== expectedOutcome.artifact_handle
          || projection.result_code !== expectedOutcome.transaction_result_code
          || projection.response_byte_length !== expectedOutcome.response_byte_length))) {
    throw compositionError("durable_terminal_readback_binding_mismatch");
  }
  const receiptDigest = assertDigest(descriptorValue(d, "readback_receipt_digest"), label);
  assertRecordDigest(
    projection,
    receiptDigest,
    "hacker-bob/provider-worker-vault-durable-terminal-readback/v1",
    label,
  );
  return objectFreeze({ ...projection, readback_receipt_digest: receiptDigest });
}

function safeFailureCode(phase) {
  const normalized = typeof phase === "string"
    ? phase.replace(/[^a-z0-9_]/gu, "_").slice(0, 80)
    : "unknown";
  return `composition_${normalized}_failed`;
}

function createBoundedPublicSummary(source, production) {
  return objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: production
      ? "provider_worker_vault_execution_summary"
      : "provider_worker_vault_conformance_summary",
    artifact_handle: assertArtifactHandle(source.artifact_handle, "public_artifact_handle"),
    summary: objectFreeze({
      terminal_state: production ? "completed" : "fixture_complete_non_authorizing",
      result_code: assertResultCode(source.result_code, "public_result_code"),
      response_byte_length: assertPositiveInteger(
        source.response_byte_length,
        "public_response_byte_length",
        MAX_RESPONSE_BYTES,
      ),
    }),
  });
}

function resolveProductionTransactionCapability(componentState, capability, lineage) {
  if (!componentState || typeof componentState.assert_transaction_capability !== "function") {
    throw compositionError("production_transaction_capability_assertion_unavailable");
  }
  const raw = componentState.assert_transaction_capability(capability, lineage);
  const d = assertExactDataObject(
    raw,
    ["execution_lineage_digest", "delegate"],
    "production_transaction_capability_resolution",
  );
  if (descriptorValue(d, "execution_lineage_digest") !== lineage.execution_lineage_digest) {
    throw compositionError("production_transaction_capability_lineage_mismatch");
  }
  return {
    delegate: assertOpaqueCapability(
      descriptorValue(d, "delegate"),
      "production_transaction_capability_delegate",
    ),
    consumed: false,
  };
}

async function executeCompositionRoot(root, input) {
  const state = ROOT_PRIVATE.get(root);
  if (!state) throw compositionError("provider_worker_vault_composition_root_untrusted");
  const production = state.mode === "production";
  const usesProductionProtocol = production || state.mode === "production_protocol_fixture";
  const executionLabel = production
    ? "provider_worker_vault_production_execution"
    : "provider_worker_vault_conformance_execution";
  const inputDescriptors = assertExactDataObject(
    input,
    ["version", "transaction_capability"],
    executionLabel,
  );
  assertVersion(
    descriptorValue(inputDescriptors, "version"),
    executionLabel,
  );
  const transactionCapability = descriptorValue(inputDescriptors, "transaction_capability");
  const transactionCapabilityState = production
    ? resolveProductionTransactionCapability(
      state.component_state,
      transactionCapability,
      state.lineage,
    )
    : assertConformanceTransactionCapability(transactionCapability, state.lineage);
  if (state.used || state.phase !== "idle") {
    throw compositionError("provider_worker_vault_execution_replay_forbidden");
  }
  if (transactionCapabilityState.consumed
      || (!usesProductionProtocol
        && state.component_state.claimed_lineages.has(state.lineage.execution_lineage_digest))) {
    throw compositionError("provider_worker_vault_execution_replay_forbidden");
  }
  if (!usesProductionProtocol
      && state.component_state.claimed_lineages.size >= MAX_CONFORMANCE_LINEAGE_CLAIMS) {
    throw compositionError("provider_worker_vault_conformance_claim_capacity_exhausted");
  }
  // Reserve the whole immutable lineage synchronously before the first caller
  // callback or await. Reentrant and concurrent attempts observe `used`.
  state.used = true;
  transactionCapabilityState.consumed = true;
  if (!usesProductionProtocol) {
    state.component_state.claimed_lineages.add(state.lineage.execution_lineage_digest);
  }
  state.phase = usesProductionProtocol ? "claiming_durable_execution" : "redeeming_grant";

  const lineage = state.lineage;
  const stageLineages = state.stage_lineages;
  const componentState = state.component_state;
  let redemption = null;
  let claim = null;
  let launch = null;
  let fence = null;
  let executionClaim = null;
  let deadlineFence = null;
  let transaction = null;
  let vaultIngest = null;
  let cleanup = null;
  let effectBoundaryEntered = false;
  let restorationAttempted = false;
  let operationalFailure = null;

  if (usesProductionProtocol) {
    try {
      executionClaim = normalizeDurableExecutionClaim(await invokeCompositionComponent(
        componentState,
        "claim_execution",
        {
          version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
          kind: "claim_durable_execution_request",
          lineage: stageLineages.terminal,
        },
        production,
      ), lineage);

      state.phase = "reading_back_durable_execution_claim";
      const claimReadback = normalizeDurableExecutionClaim(await invokeCompositionComponent(
        componentState,
        "readback_execution_claim",
        {
          version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
          kind: "readback_durable_execution_claim_request",
          lineage: stageLineages.terminal,
          execution_claim_ref: executionClaim.execution_claim_ref,
          claim_generation: executionClaim.claim_generation,
          claim_receipt_digest: executionClaim.claim_receipt_digest,
        },
        production,
      ), lineage);
      assertExactExecutionClaimReadback(claimReadback, executionClaim);
    } catch {
      state.phase = "durable_execution_claim_uncertain";
      state.reconciliation_required = true;
      throw compositionError("provider_worker_vault_execution_claim_ambiguous");
    }

    if (executionClaim.claim_disposition === "existing") {
      state.phase = "reading_existing_terminal_commit";
      let existingTerminal;
      try {
        existingTerminal = normalizeTerminalCommitReadback(await invokeCompositionComponent(
          componentState,
          "readback_terminal_commit",
          {
            version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
            kind: "readback_durable_terminal_commit_request",
            lineage: stageLineages.terminal,
            execution_claim_ref: executionClaim.execution_claim_ref,
            execution_claim_generation: executionClaim.claim_generation,
            execution_claim_receipt_digest: executionClaim.claim_receipt_digest,
          },
          production,
        ), lineage, null, null, executionClaim);
      } catch {
        state.phase = "existing_execution_reconciliation_required";
        state.reconciliation_required = true;
        throw compositionError("provider_worker_vault_existing_execution_reconciliation_required");
      }
      state.phase = "terminal";
      state.terminal_state = existingTerminal.terminal_state;
      state.reconciliation_required = false;
      if (existingTerminal.terminal_state === "completed") {
        return createBoundedPublicSummary(existingTerminal, production);
      }
      throw compositionError(
        existingTerminal.terminal_state === "rejected_no_effect"
          ? "provider_worker_vault_rejected_no_effect"
          : "provider_worker_vault_ambiguous_quarantined",
      );
    }
    state.phase = "redeeming_grant";
  }

  try {
    redemption = normalizeRedemptionReceipt(await invokeCompositionComponent(
      componentState,
      "redeem_grant",
      {
        version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
        kind: "redeem_grant_request",
        lineage: stageLineages.redemption,
      },
      production,
    ), lineage);

    state.phase = "claiming_compiled_command";
    claim = normalizeCommandClaim(await invokeCompositionComponent(
      componentState,
      "claim_compiled_command",
      {
        version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
        kind: "claim_compiled_command_request",
        lineage: stageLineages.active,
        redemption_receipt_digest: redemption.receipt_digest,
        transaction_capability: transactionCapability,
        compiled_command_capability: transactionCapabilityState.delegate,
      },
      production,
    ), lineage);

    state.phase = "launching_worker";
    launch = normalizeWorkerLaunch(await invokeCompositionComponent(
      componentState,
      "launch_worker",
      {
        version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
        kind: "launch_worker_request",
        lineage: stageLineages.launch,
        redemption_receipt_digest: redemption.receipt_digest,
        claim_receipt_digest: claim.claim_receipt_digest,
      },
      production,
    ), lineage);

    state.phase = "asserting_worker_fence";
    fence = normalizeWorkerFence(await invokeCompositionComponent(
      componentState,
      "assert_worker_fence",
      {
        version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
        kind: "assert_worker_fence_request",
        lineage: stageLineages.fence,
        worker_handle: launch.worker_handle,
        launch_receipt_digest: launch.launch_receipt_digest,
        claim_receipt_digest: claim.claim_receipt_digest,
      },
      production,
    ), lineage);

    if (usesProductionProtocol) {
      state.phase = "asserting_trusted_effect_deadline_fence";
      deadlineFence = normalizeEffectDeadlineFence(await invokeCompositionComponent(
        componentState,
        "assert_effect_deadline_fence",
        {
          version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
          kind: "assert_trusted_effect_deadline_fence_request",
          lineage: stageLineages.fence,
          execution_claim_receipt_digest: executionClaim.claim_receipt_digest,
          worker_handle: launch.worker_handle,
          worker_fence_handle: fence.worker_fence_handle,
          worker_fence_receipt_digest: fence.fence_receipt_digest,
        },
        production,
      ), lineage);
    }

    // Invocation begins the possibly-effectful interval. Any throw, malformed
    // result, or lost response after this point is terminally ambiguous.
    state.phase = "transport_to_reserved_vault";
    effectBoundaryEntered = true;
    const transportRequest = {
      version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
      kind: "execute_transport_into_reserved_vault_request",
      lineage: stageLineages.transport,
      command_handle: claim.command_handle,
      worker_handle: launch.worker_handle,
      worker_fence_handle: fence.worker_fence_handle,
      vault_sink: objectFreeze({
        reservation_handle: lineage.vault_reservation_handle,
        reservation_digest: lineage.vault_reservation_digest,
        ingest_capability_digest: lineage.vault_ingest_capability_digest,
        byte_ceiling: lineage.vault_byte_ceiling,
      }),
    };
    if (usesProductionProtocol) {
      transportRequest.execution_claim_receipt_digest = executionClaim.claim_receipt_digest;
      transportRequest.deadline_fence_receipt_digest =
        deadlineFence.deadline_fence_receipt_digest;
    }
    const rawTransactionResult = await invokeCompositionComponent(
      componentState,
      "execute_transport_into_reserved_vault",
      transportRequest,
      production,
    );
    try {
      transaction = normalizeTransportVaultResult(
        rawTransactionResult,
        lineage,
        usesProductionProtocol ? executionClaim : null,
        usesProductionProtocol ? deadlineFence : null,
      );
    } catch (error) {
      zeroExposedByteSurface(rawTransactionResult);
      throw error;
    }

    if (usesProductionProtocol) {
      state.phase = "asserting_durable_vault_ingest";
      vaultIngest = normalizeVaultIngestReceipt(await invokeCompositionComponent(
        componentState,
        "assert_vault_ingest_receipt",
        {
          version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
          kind: "assert_reserved_vault_ingest_receipt_request",
          lineage: stageLineages.transport,
          execution_claim_receipt_digest: executionClaim.claim_receipt_digest,
          deadline_fence_receipt_digest: deadlineFence.deadline_fence_receipt_digest,
          transaction_result: transaction,
        },
        production,
      ), lineage, transaction, executionClaim, deadlineFence);
    }

    state.phase = "restoring_after_effect";
    restorationAttempted = true;
    cleanup = normalizeRestorationReceipt(await invokeCompositionComponent(
      componentState,
      "restore_after_effect",
      {
        version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
        kind: "restore_after_effect_request",
        lineage: stageLineages.cleanup,
        disposition: "completed",
        worker_handle: launch.worker_handle,
        worker_fence_handle: fence.worker_fence_handle,
        transaction_result: transaction,
      },
      production,
    ), lineage, transaction);
  } catch {
    operationalFailure = safeFailureCode(state.phase);
  }

  if (operationalFailure !== null) {
    if (!effectBoundaryEntered) {
      state.phase = "cancelling_before_effect";
      try {
        cleanup = normalizeCancellationReceipt(await invokeCompositionComponent(
          componentState,
          "cancel_before_effect",
          {
            version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
            kind: "cancel_before_effect_request",
            lineage: stageLineages.cleanup,
            worker_handle: launch ? launch.worker_handle : null,
            worker_fence_handle: fence ? fence.worker_fence_handle : null,
            failure_code: operationalFailure,
          },
          production,
        ), lineage);
      } catch {
        cleanup = null;
      }
    } else if (cleanup === null && !restorationAttempted) {
      state.phase = "restoring_ambiguous_effect";
      restorationAttempted = true;
      try {
        cleanup = normalizeRestorationReceipt(await invokeCompositionComponent(
          componentState,
          "restore_after_effect",
          {
            version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
            kind: "restore_after_effect_request",
            lineage: stageLineages.cleanup,
            disposition: "ambiguous",
            worker_handle: launch ? launch.worker_handle : null,
            worker_fence_handle: fence ? fence.worker_fence_handle : null,
            transaction_result: null,
          },
          production,
        ), lineage, null);
      } catch {
        cleanup = null;
      }
    }
  }

  const completed = operationalFailure === null;
  const rejectedNoEffect = !completed && !effectBoundaryEntered && cleanup !== null;
  const terminalState = completed
    ? "completed"
    : rejectedNoEffect ? "rejected_no_effect" : "ambiguous_quarantined";
  const outcome = createTerminalOutcome({
    lineage,
    terminalState,
    effectState: transaction
      ? "effect_completed"
      : completed ? "effect_completed" : rejectedNoEffect ? "no_effect" : "unknown_effect",
    resultCode: completed ? transaction.result_code : operationalFailure,
    transaction,
    cleanup,
    executionClaim,
    deadlineFence,
    vaultIngest,
  });

  state.phase = "committing_terminal";
  let terminalCommit;
  try {
    terminalCommit = normalizeTerminalCommit(await invokeCompositionComponent(
      componentState,
      "commit_terminal",
      {
        version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
        kind: "commit_terminal_request",
        lineage: stageLineages.terminal,
        outcome,
      },
      production,
    ), lineage, outcome);
  } catch {
    state.phase = "terminal_commit_uncertain";
    state.terminal_state = "ambiguous_quarantined";
    state.reconciliation_required = true;
    throw compositionError("provider_worker_vault_terminal_commit_ambiguous");
  }

  let terminalReadback = null;
  if (usesProductionProtocol) {
    state.phase = "reading_back_terminal_commit";
    try {
      terminalReadback = normalizeTerminalCommitReadback(await invokeCompositionComponent(
        componentState,
        "readback_terminal_commit",
        {
          version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
          kind: "readback_durable_terminal_commit_request",
          lineage: stageLineages.terminal,
          execution_claim_ref: executionClaim.execution_claim_ref,
          execution_claim_generation: executionClaim.claim_generation,
          execution_claim_receipt_digest: executionClaim.claim_receipt_digest,
          outcome_digest: outcome.outcome_digest,
          terminal_commit_receipt_digest: terminalCommit.commit_receipt_digest,
        },
        production,
      ), lineage, outcome, terminalCommit, executionClaim);
    } catch {
      state.phase = "terminal_readback_uncertain";
      state.terminal_state = terminalCommit.terminal_state;
      state.reconciliation_required = true;
      throw compositionError("provider_worker_vault_terminal_readback_ambiguous");
    }
  }

  state.phase = "terminal";
  state.terminal_state = terminalReadback
    ? terminalReadback.terminal_state : terminalCommit.terminal_state;
  state.reconciliation_required = false;
  if (!completed) {
    throw compositionError(
      rejectedNoEffect
        ? "provider_worker_vault_rejected_no_effect"
        : "provider_worker_vault_ambiguous_quarantined",
    );
  }

  // The public execution result deliberately omits lineage, response digests,
  // terminal records, command handles, and every byte-bearing object. Only a
  // bounded summary and the vault's opaque artifact handle cross back. The
  // production protocol returns the independently read-back durable record.
  return createBoundedPublicSummary(terminalReadback || transaction, production);
}

function createReadiness(state) {
  const production = state.mode === "production";
  const protocolFixture = state.mode === "production_protocol_fixture";
  return objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: "provider_worker_vault_composition_readiness",
    execution_lineage_digest: state.lineage.execution_lineage_digest,
    topology_status: production
      ? "privately_branded_production_path_complete"
      : protocolFixture
        ? "production_protocol_fixture_complete_non_authorizing"
        : "typed_conformance_path_complete",
    admitted_component_assurance: state.assurance,
    production_component_enrollment: production ? "privately_branded" : "unavailable",
    requirements: production ? SATISFIED_PRODUCTION_REQUIREMENTS : PRODUCTION_REQUIREMENTS,
    production_ready: production,
    hardware_access_authorized: production,
    execution_authority: production,
  });
}

function createProviderWorkerVaultCompositionRoot(input) {
  const label = "provider_worker_vault_composition_root";
  const descriptors = assertExactDataObject(input, ["version", "lineage", "components"], label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  const lineage = normalizeProviderWorkerVaultExecutionLineage(
    descriptorValue(descriptors, "lineage"),
  );
  const components = descriptorValue(descriptors, "components");
  let componentState;
  let mode;
  let assurance;
  if (components != null && COMPONENTS.has(components)) {
    componentState = assertConformanceComponents(components);
    mode = "legacy_conformance";
    assurance = PROVIDER_WORKER_VAULT_CONFORMANCE_ASSURANCE;
  } else if (components != null && PROTOCOL_FIXTURE_COMPONENTS.has(components)) {
    componentState = assertProtocolFixtureComponents(components);
    mode = "production_protocol_fixture";
    assurance = PROVIDER_WORKER_VAULT_PROTOCOL_FIXTURE_ASSURANCE;
  } else if (components != null && PRODUCTION_PORT_SETS.has(components)) {
    assertProviderWorkerVaultProductionPortSet(components, lineage);
    componentState = PRODUCTION_PORT_SET_PRIVATE.get(components);
    mode = "production";
    assurance = PROVIDER_WORKER_VAULT_PRODUCTION_ASSURANCE;
  } else {
    throw compositionError("provider_worker_vault_components_untrusted");
  }
  const production = mode === "production";
  const state = {
    lineage,
    stage_lineages: createStageLineageProjections(lineage),
    component_state: componentState,
    mode,
    assurance,
    phase: "idle",
    used: false,
    terminal_state: null,
    reconciliation_required: false,
  };
  let root;
  root = objectFreeze({
    version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
    kind: "provider_worker_vault_composition_root",
    execution_lineage_digest: lineage.execution_lineage_digest,
    assurance,
    production_ready: production,
    hardware_access_authorized: production,
    execution_authority: production,
    readiness() {
      assertProviderWorkerVaultCompositionRoot(root);
      return createReadiness(state);
    },
    execute(executionInput) {
      assertProviderWorkerVaultCompositionRoot(root);
      if (!production) {
        // There is no public production enrollment constructor. This refusal
        // occurs before input inspection, state reservation, or any fixture
        // callback, so caller booleans cannot promote either fixture path.
        throw compositionError("provider_worker_vault_production_components_unavailable");
      }
      return executeCompositionRoot(root, executionInput);
    },
    exerciseConformance(executionInput) {
      assertProviderWorkerVaultCompositionRoot(root);
      if (production) {
        throw compositionError("provider_worker_vault_conformance_unavailable_for_production");
      }
      return executeCompositionRoot(root, executionInput);
    },
    snapshot() {
      assertProviderWorkerVaultCompositionRoot(root);
      return objectFreeze({
        version: PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
        phase: state.phase,
        one_use_consumed: state.used,
        terminal_state: state.terminal_state,
        reconciliation_required: state.reconciliation_required,
        production_ready: production,
        hardware_access_authorized: production,
      });
    },
    toJSON: rejectSerialization,
  });
  ROOTS.add(root);
  ROOT_PRIVATE.set(root, state);
  return root;
}

function assertProviderWorkerVaultCompositionRoot(input) {
  const state = input == null ? null : ROOT_PRIVATE.get(input);
  if (!input || !state || !ROOTS.has(input) || !objectIsFrozen(input)
      || input.version !== PROVIDER_WORKER_VAULT_COMPOSITION_VERSION
      || input.kind !== "provider_worker_vault_composition_root"
      || input.execution_lineage_digest !== state.lineage.execution_lineage_digest
      || input.assurance !== state.assurance
      || input.production_ready !== (state.mode === "production")
      || input.hardware_access_authorized !== (state.mode === "production")
      || input.execution_authority !== (state.mode === "production")
      || input.toJSON !== rejectSerialization
      || reflectOwnKeys(input).length !== 12) {
    throw compositionError("provider_worker_vault_composition_root_untrusted");
  }
  return input;
}

// Validate an opaque transaction capability against the exact privately
// enrolled production root without exposing its worker delegate.  The
// capability is only enrolled; execution still performs the same assertion
// again and consumes it atomically with the root's one-use lineage claim.
function assertProviderWorkerVaultProductionTransactionCapability(rootInput, capability) {
  const root = assertProviderWorkerVaultCompositionRoot(rootInput);
  const state = ROOT_PRIVATE.get(root);
  if (state.mode !== "production") {
    throw compositionError("provider_worker_vault_production_components_unavailable");
  }
  resolveProductionTransactionCapability(
    state.component_state,
    capability,
    state.lineage,
  );
  return capability;
}

module.exports = objectFreeze({
  PROVIDER_WORKER_VAULT_COMPOSITION_VERSION,
  PROVIDER_WORKER_VAULT_CONFORMANCE_ASSURANCE,
  PROVIDER_WORKER_VAULT_PROTOCOL_FIXTURE_ASSURANCE,
  PROVIDER_WORKER_VAULT_PRODUCTION_ASSURANCE,
  PROVIDER_WORKER_VAULT_PRODUCTION_PORT_OPERATION_FIELDS:
    PRODUCTION_PORT_OPERATION_FIELDS,
  PROVIDER_WORKER_VAULT_PRODUCTION_REQUIREMENTS: PRODUCTION_REQUIREMENTS,
  assertProviderWorkerVaultCompositionRoot,
  assertProviderWorkerVaultProductionTransactionCapability,
  assertProviderWorkerVaultProductionPortSet,
  createProviderWorkerVaultCompositionRoot,
  createProviderWorkerVaultConformanceComponents,
  createProviderWorkerVaultProductionProtocolFixtureComponents,
  createProviderWorkerVaultConformanceTransactionCapability,
  normalizeProviderWorkerVaultExecutionLineage,
});
