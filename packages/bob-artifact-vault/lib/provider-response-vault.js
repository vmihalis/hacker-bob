"use strict";

// Worker-owner surface for committing a bounded provider response directly to
// a pre-reserved vault slot and independently proving that commit afterwards.
// This module intentionally does not authorize hardware.  Its JavaScript
// Buffer entrypoint is the owner-side seam that a qualified native descriptor
// bridge must eventually replace or call without projecting bytes through the
// broker process.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const {
  ARTIFACT_VAULT_SCHEMA_VERSION,
  PUBLIC_ARTIFACT_HANDLE_RE,
  PUBLIC_RESERVATION_HANDLE_RE,
  normalizeArtifactMetadata,
} = require("./contracts.js");
const {
  getProviderResponseVaultOwner,
  materializeForWorker,
} = require("./vault.js");
const {
  TRUSTED_CLOCK_VERSION,
  assertPhysicalTrustedClockPort,
  assertPhysicalTrustedClockSample,
  samplePhysicalTrustedClock,
} = require("../../../mcp/domains/physical/physical-trusted-clock.js");

const arrayIsArray = Array.isArray;
const bufferIsBuffer = Buffer.isBuffer;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectPrototype = Object.prototype;
const reflectOwnKeys = Reflect.ownKeys;
const utilIsPromise = utilTypes.isPromise;
const utilIsProxy = utilTypes.isProxy;

const PROVIDER_RESPONSE_VAULT_VERSION = 1;
const MAX_RESPONSE_BYTES = 16 * 1024;
const MAX_STATE_BYTES = 128 * 1024;
const SHA256_RE = /^[a-f0-9]{64}$/u;
const BASE64URL_256_RE = /^[A-Za-z0-9_-]{43}$/u;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,190}$/u;
const OPAQUE_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$/u;
const RESULT_CODE_RE = /^[a-z][a-z0-9_]{0,63}$/u;
const UINT64_RE = /^(?:0|[1-9][0-9]{0,19})$/u;
const MAX_UINT64 = (1n << 64n) - 1n;
const STATE_FILE_RE = /^[a-f0-9]{64}\.json$/u;
const RESERVATION_JOURNAL_FENCE_FILE_RE = /^reservation-([a-f0-9]{64})\.json$/u;
const RESERVATION_JOURNAL_FENCE_TEMP_FILE_RE =
  /^\.reservation-([a-f0-9]{64})\.json\.[1-9][0-9]*\.[A-Za-z0-9_-]{43}\.tmp$/u;
const TEMP_FILE_RE = /^\.(?:[a-f0-9]{64}|reservation-[a-f0-9]{64})\.json\.[1-9][0-9]*\.[A-Za-z0-9_-]{43}\.tmp$/u;

const RESERVATION_DIGEST_DOMAIN =
  "hacker-bob/provider-response-vault-reservation/v1";
const CAPABILITY_DIGEST_DOMAIN =
  "hacker-bob/provider-response-vault-ingest-capability/v1";
const VAULT_COMMIT_DIGEST_DOMAIN =
  "hacker-bob/provider-response-vault-commit/v1";
const RAW_CUSTODY_DIGEST_DOMAIN =
  "hacker-bob/provider-response-vault-raw-custody/v1";
const TRANSACTION_DIGEST_DOMAIN =
  "hacker-bob/provider-worker-vault-transport-reserved-vault-result/v1";
const INGEST_RECEIPT_DIGEST_DOMAIN =
  "hacker-bob/provider-worker-vault-reserved-vault-ingest/v1";
const EXECUTION_LINEAGE_DIGEST_DOMAIN =
  "hacker-bob/provider-worker-vault-execution-lineage/v1";
const RAW_CUSTODY_VAULT_COMMIT_DIGEST_DOMAIN =
  "hacker-bob/provider-response-vault-raw-custody-commit/v1";
const RAW_CUSTODY_RECEIPT_DIGEST_DOMAIN =
  "hacker-bob/provider-response-vault-raw-custody-receipt/v1";
const RAW_CUSTODY_OBSERVATION_DIGEST_DOMAIN =
  "hacker-bob/provider-response-vault-raw-custody-observation/v1";
const RESERVATION_JOURNAL_FENCE_DIGEST_DOMAIN =
  "hacker-bob/provider-response-vault-reservation-journal-fence/v1";
const RAW_CUSTODY_CLEANUP_RECEIPT_DIGEST_DOMAIN =
  "hacker-bob/provider-response-vault-raw-custody-cleanup-receipt/v1";

const PROVIDER_RESPONSE_VAULT_ASSURANCE = objectFreeze({
  version: PROVIDER_RESPONSE_VAULT_VERSION,
  assurance: "private_branded_pre_reserved_response_vault_owner_v1",
  production_ready: false,
  hardware_access_authorized: false,
  execution_authority: false,
  reservation_scoped: true,
  hard_byte_ceiling_enforced: true,
  response_buffer_zeroized: true,
  raw_response_bytes_projected_to_broker: false,
  durable_authenticated_sink_commit: true,
  durable_authenticated_raw_custody_receipt: true,
  raw_custody_and_semantic_journal_modes_mutually_exclusive: true,
  raw_custody_receipt_carries_semantic_result_claim: false,
  raw_custody_receipt_carries_device_state_claim: false,
  independent_digest_only_ingest_receipt: true,
  byte_blind_receipt_port: true,
  separately_isolated_receipt_process: false,
  independently_enrolled_receipt_key: false,
  execution_claim_signature_verified: false,
  live_deadline_rechecked: false,
  restart_readback: true,
  external_monotonic_receipt_anchor: false,
  disaster_recovery_included: false,
  receipt_retention_lifecycle: false,
  receipt_quota_configuration_externally_enrolled: false,
  source_owned_native_descriptor_sink: false,
  native_directory_descriptor_path_hardening: false,
  external_vault_key_custody_enrolled: false,
  hardware_in_loop_proven: false,
  production_blockers: objectFreeze([
    "external_monotonic_receipt_anchor_missing",
    "separately_isolated_receipt_process_and_key_missing",
    "receipt_disaster_recovery_and_retention_lifecycle_missing",
    "externally_enrolled_receipt_quota_configuration_missing",
    "native_openat_directory_descriptor_path_hardening_missing",
    "source_owned_native_descriptor_sink_missing",
    "qualified_native_worker_to_vault_bridge_missing",
    "external_vault_key_custodian_not_enrolled",
    "provider_response_vault_hil_missing",
  ]),
});

const TRANSPORT_LINEAGE_FIELDS = objectFreeze([
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
  "execution_lineage_digest",
]);

const TRANSPORT_RESULT_FIELDS = objectFreeze([
  "version",
  "kind",
  "execution_lineage_digest",
  "transaction_ref",
  "provider_id",
  "operation_id",
  "compiler_id",
  "compiler_manifest_digest",
  "compiler_registry_digest",
  "compiled_operation_digest",
  "provider_command_ref",
  "requested_effects_digest",
  "runtime_availability",
  "compiled_command_id",
  "compiled_command_capability_digest",
  "active_command_input_ref",
  "active_command_input_digest",
  "worker_launch_digest",
  "worker_fence_digest",
  "resource_fence_digest",
  "transport_binding_digest",
  "vault_reservation_handle",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
  "execution_claim_receipt_digest",
  "deadline_fence_receipt_digest",
  "artifact_handle",
  "response_digest",
  "response_byte_length",
  "result_code",
  "device_state_digest",
  "vault_commit_receipt_digest",
  "raw_response_custody_digest",
  "transaction_receipt_digest",
]);

const INGEST_RECEIPT_FIELDS = objectFreeze([
  "version",
  "kind",
  "execution_lineage_digest",
  "vault_reservation_handle",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
  "artifact_handle",
  "execution_claim_receipt_digest",
  "deadline_fence_receipt_digest",
  "response_digest",
  "response_byte_length",
  "transaction_receipt_digest",
  "vault_commit_receipt_digest",
  "raw_response_custody_digest",
  "ingest_receipt_digest",
]);

const RAW_CUSTODY_OBSERVATION_FIELDS = objectFreeze([
  "transport_settlement_kind",
  "dispatch_envelope_digest",
  "source_descriptor_identity_digest",
  "sink_descriptor_identity_digest",
  "sink_record_digest",
  "ticket_sequence",
  "settled_monotonic_ns",
]);

const RAW_CUSTODY_RECEIPT_FIELDS = objectFreeze([
  "version",
  "kind",
  "execution_lineage_digest",
  "custody_ref",
  "provider_id",
  "operation_id",
  "compiler_id",
  "compiler_manifest_digest",
  "compiler_registry_digest",
  "compiled_operation_digest",
  "provider_command_ref",
  "requested_effects_digest",
  "runtime_availability",
  "compiled_command_id",
  "compiled_command_capability_digest",
  "active_command_input_ref",
  "active_command_input_digest",
  "worker_launch_digest",
  "worker_fence_digest",
  "resource_fence_digest",
  "transport_binding_digest",
  "vault_reservation_handle",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
  "execution_claim_receipt_digest",
  "deadline_fence_receipt_digest",
  "artifact_handle",
  "response_digest",
  "response_byte_length",
  "transport_settlement_kind",
  "dispatch_envelope_digest",
  "source_descriptor_identity_digest",
  "sink_descriptor_identity_digest",
  "sink_record_digest",
  "ticket_sequence",
  "settled_monotonic_ns",
  "transport_observation_digest",
  "vault_commit_receipt_digest",
  "raw_custody_receipt_digest",
  "semantic_validation_performed",
  "production_ready",
  "hardware_access_authorized",
  "authoritative",
]);

const RAW_CUSTODY_CLEANUP_RECEIPT_FIELDS = objectFreeze([
  "version",
  "kind",
  "execution_lineage_digest",
  "raw_custody_receipt_digest",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
  "artifact_handle",
  "source_descriptor_identity_digest",
  "sink_descriptor_identity_digest",
  "sink_record_digest",
  "cleanup_reconciled_at",
  "cleanup_receipt_digest",
]);


const RESERVATION_STATE_FIELDS = objectFreeze([
  "reservation_handle",
  "reservation_ref",
  "reservation_binding_digest",
  "byte_ceiling",
  "expires_at",
  "task_id",
  "attempt_id",
  "artifact_handle",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
]);

const JOURNAL_FIELDS = objectFreeze([
  "version",
  "kind",
  "state",
  "vault_id",
  "vault_slot",
  "session_nucleus_hash",
  "execution_lineage_digest",
  "lineage",
  "reservation",
  "metadata",
  "metadata_digest",
  "execution_claim_receipt_digest",
  "deadline_fence_receipt_digest",
  "transaction_ref",
  "result_code",
  "device_state_digest",
  "response_digest",
  "response_byte_length",
  "content_token",
  "prepared_at",
  "vault_committed_at",
  "transport_result",
  "ingest_receipt",
]);

const RAW_CUSTODY_JOURNAL_FIELDS = objectFreeze([
  "version",
  "kind",
  "state",
  "vault_id",
  "vault_slot",
  "session_nucleus_hash",
  "execution_lineage_digest",
  "lineage",
  "reservation",
  "metadata",
  "metadata_digest",
  "execution_claim_receipt_digest",
  "deadline_fence_receipt_digest",
  "custody_ref",
  "transport_observation",
  "transport_observation_digest",
  "response_digest",
  "response_byte_length",
  "content_token",
  "prepared_at",
  "vault_committed_at",
  "raw_custody_receipt",
  "plaintext_cleanup_receipt",
  "semantic_observation_receipt",
]);

const RESERVATION_JOURNAL_FENCE_FIELDS = objectFreeze([
  "version",
  "kind",
  "vault_id",
  "vault_slot",
  "session_nucleus_hash",
  "reservation_handle",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
  "execution_lineage_digest",
  "journal_mode",
  "fence_digest",
]);

const DIGEST_LINEAGE_FIELDS = new Set([
  "experiment_plan_hash",
  "grant_envelope_digest",
  "grant_journal_entry_digest",
  "go_envelope_digest",
  "go_journal_entry_digest",
  "session_nucleus_hash",
  "execution_lineage_digest",
  "resource_fence_digest",
  "safety_supervisor_plan_digest",
  "compiler_manifest_digest",
  "compiler_registry_digest",
  "source_profile_digest",
  "canonical_command_digest",
  "compiled_operation_digest",
  "requested_effects_digest",
  "compiled_command_capability_digest",
  "active_command_input_digest",
  "cleanup_command_input_digest",
  "worker_bundle_digest",
  "worker_launch_digest",
  "worker_process_instance_digest",
  "worker_fence_digest",
  "transport_binding_digest",
  "durable_exchange_plan_digest",
  "terminal_receipt_recipient_digest",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
]);

const UINT64_LINEAGE_FIELDS = new Set([
  "resource_epoch",
  "effect_deadline_monotonic_ns",
]);

const POSITIVE_INTEGER_LINEAGE_FIELDS = new Set([
  "maximum_response_bytes",
  "vault_byte_ceiling",
]);

const SINKS = new WeakSet();
const SINK_PRIVATE = new WeakMap();
const RECEIPT_PORTS = new WeakSet();
const RECEIPT_PORT_PRIVATE = new WeakMap();
const SINK_COMMITS = new WeakSet();
const INGEST_RECEIPTS = new WeakSet();
const RAW_CUSTODY_RECEIPTS = new WeakSet();
const RAW_CUSTODY_RECEIPT_PORTS = new WeakSet();
const RAW_CUSTODY_RECEIPT_PORT_PRIVATE = new WeakMap();
const PROVIDER_SEMANTIC_VALIDATION_PORTS = new WeakSet();
const PROVIDER_SEMANTIC_VALIDATION_PORT_PRIVATE = new WeakMap();

// Provider-neutral registry of semantic-observation-receipt normalizers, keyed
// by the receipt's own `kind` string. An out-of-package provider validator
// registers its normalizer through the substrate; the durable state layer
// re-validates an embedded receipt by data (its kind) and never names a
// provider.
const SEMANTIC_RECEIPT_NORMALIZERS = new Map();

function registerSemanticReceiptNormalizer(kind, normalizer) {
  if (typeof kind !== "string" || kind.length === 0) {
    throw new Error("semantic receipt normalizer kind must be a non-empty string");
  }
  if (typeof normalizer !== "function") {
    throw new Error("semantic receipt normalizer must be a function");
  }
  const existing = SEMANTIC_RECEIPT_NORMALIZERS.get(kind);
  if (existing && existing !== normalizer) {
    throw new Error("semantic receipt normalizer kind is already registered");
  }
  SEMANTIC_RECEIPT_NORMALIZERS.set(kind, normalizer);
}

function registerSemanticValidationPort(port, privateState) {
  PROVIDER_SEMANTIC_VALIDATION_PORTS.add(port);
  PROVIDER_SEMANTIC_VALIDATION_PORT_PRIVATE.set(port, privateState);
}

function readSemanticValidationPortPrivate(port) {
  assertProviderResponseSemanticValidationPort(port);
  return PROVIDER_SEMANTIC_VALIDATION_PORT_PRIVATE.get(port);
}

function canonicalize(value) {
  if (arrayIsArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    const output = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      if (value[key] !== undefined) output[key] = canonicalize(value[key]);
    }
    return output;
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digestRecord(domain, projection) {
  return sha256(canonicalJson({ domain, ...projection }));
}



function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");
  try {
    return leftBuffer.length === rightBuffer.length
      && crypto.timingSafeEqual(leftBuffer, rightBuffer);
  } finally {
    leftBuffer.fill(0);
    rightBuffer.fill(0);
  }
}

function assertExactDataObject(input, fields, label) {
  if (input == null || typeof input !== "object" || arrayIsArray(input)
      || bufferIsBuffer(input) || utilIsProxy(input) || utilIsPromise(input)) {
    throw new Error(`${label} must be a non-proxy data object`);
  }
  const prototype = objectGetPrototypeOf(input);
  if (prototype !== objectPrototype && prototype !== null) {
    throw new Error(`${label} must have an ordinary or null prototype`);
  }
  const descriptors = objectGetOwnPropertyDescriptors(input);
  const ownKeys = reflectOwnKeys(descriptors);
  if (ownKeys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} must not contain symbol fields`);
  }
  const allowed = new Set(fields);
  const unknown = ownKeys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) {
    throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  }
  const missing = fields.filter((field) => !objectHasOwn(descriptors, field));
  if (missing.length > 0) {
    throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  }
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!objectHasOwn(descriptor, "value")
        || objectHasOwn(descriptor, "get") || objectHasOwn(descriptor, "set")
        || descriptor.enumerable !== true) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
  }
  return descriptors;
}

function descriptorValue(descriptors, field) {
  return descriptors[field].value;
}

function assertVersion(value, label) {
  if (value !== PROVIDER_RESPONSE_VAULT_VERSION) {
    throw new Error(`${label}.version must be ${PROVIDER_RESPONSE_VAULT_VERSION}`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !SHA256_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_RE.test(value)) {
    throw new Error(`${label} must be a bounded identifier`);
  }
  return value;
}

function assertOpaqueRef(value, label) {
  if (typeof value !== "string" || !OPAQUE_REF_RE.test(value)) {
    throw new Error(`${label} must be a bounded opaque reference`);
  }
  return value;
}

function assertResultCode(value, label) {
  if (typeof value !== "string" || !RESULT_CODE_RE.test(value)) {
    throw new Error(`${label} must be a bounded result code`);
  }
  return value;
}

function assertCanonicalTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC timestamp`);
  }
  return value;
}

function assertUint64(value, label) {
  if (typeof value !== "string" || !UINT64_RE.test(value) || BigInt(value) > MAX_UINT64) {
    throw new Error(`${label} must be a canonical uint64 string`);
  }
  return value;
}

function assertPositiveInteger(value, label, ceiling = MAX_RESPONSE_BYTES) {
  if (!Number.isSafeInteger(value) || value < 1 || value > ceiling) {
    throw new Error(`${label} must be an integer between 1 and ${ceiling}`);
  }
  return value;
}

function assertNonnegativeInteger(value, label, ceiling = MAX_RESPONSE_BYTES) {
  if (!Number.isSafeInteger(value) || value < 0 || value > ceiling) {
    throw new Error(`${label} must be an integer between 0 and ${ceiling}`);
  }
  return value;
}

function normalizeMetadata(input, label = "provider_response_metadata") {
  const fields = [
    "version",
    "session_nucleus_hash",
    "task_id",
    "attempt_id",
    "data_class",
    "media_type",
    "source_ref",
    "retention_expires_at",
  ];
  const descriptors = assertExactDataObject(input, fields, label);
  const copy = {};
  for (const field of fields) copy[field] = descriptorValue(descriptors, field);
  return normalizeArtifactMetadata(copy, label);
}

function normalizeTransportLineage(input, label = "provider_response_transport_lineage") {
  const descriptors = assertExactDataObject(input, TRANSPORT_LINEAGE_FIELDS, label);
  const normalized = {};
  for (const field of TRANSPORT_LINEAGE_FIELDS) {
    const value = descriptorValue(descriptors, field);
    if (field === "version") normalized[field] = assertVersion(value, label);
    else if (DIGEST_LINEAGE_FIELDS.has(field)) normalized[field] = assertDigest(value, `${label}.${field}`);
    else if (UINT64_LINEAGE_FIELDS.has(field)) normalized[field] = assertUint64(value, `${label}.${field}`);
    else if (POSITIVE_INTEGER_LINEAGE_FIELDS.has(field)) {
      normalized[field] = assertPositiveInteger(value, `${label}.${field}`);
    } else if (field === "expected_result_code") {
      normalized[field] = assertResultCode(value, `${label}.${field}`);
    } else if (field === "vault_reservation_handle") {
      if (typeof value !== "string" || !PUBLIC_RESERVATION_HANDLE_RE.test(value)) {
        throw new Error(`${label}.${field} is invalid`);
      }
      normalized[field] = value;
    } else {
      normalized[field] = assertOpaqueRef(value, `${label}.${field}`);
    }
  }
  if (normalized.maximum_response_bytes > normalized.vault_byte_ceiling) {
    throw new Error(`${label}.maximum_response_bytes exceeds its vault byte ceiling`);
  }
  if (normalized.active_command_input_ref === normalized.cleanup_command_input_ref
      || normalized.active_command_input_digest === normalized.cleanup_command_input_digest) {
    throw new Error(`${label} active and cleanup command inputs must be distinct`);
  }
  const suppliedDigest = normalized.execution_lineage_digest;
  const digestBasis = { ...normalized };
  delete digestBasis.execution_lineage_digest;
  const expectedDigest = digestRecord(EXECUTION_LINEAGE_DIGEST_DOMAIN, digestBasis);
  if (!constantTimeEqual(suppliedDigest, expectedDigest)) {
    throw new Error(`${label}.execution_lineage_digest does not match the complete lineage`);
  }
  return objectFreeze(normalized);
}

function reservationProjection(owner, reservation, reservationDigest, capabilityDigest) {
  return objectFreeze({
    reservation_handle: reservation.reservation_handle,
    reservation_ref: reservation.reservation_ref,
    reservation_binding_digest: reservation.reservation_binding_digest,
    byte_ceiling: reservation.byte_ceiling,
    expires_at: reservation.expires_at,
    task_id: reservation.task_id,
    attempt_id: reservation.attempt_id,
    artifact_handle: reservation.artifact_handle,
    vault_reservation_digest: reservationDigest,
    vault_ingest_capability_digest: capabilityDigest,
  });
}

function computeReservationDigest(owner, reservation) {
  return digestRecord(RESERVATION_DIGEST_DOMAIN, {
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    vault_id: owner.vault_id,
    vault_slot: owner.vault_slot,
    session_nucleus_hash: owner.session_nucleus_hash,
    reservation_handle: reservation.reservation_handle,
    reservation_ref: reservation.reservation_ref,
    reservation_binding_digest: reservation.reservation_binding_digest,
    byte_ceiling: reservation.byte_ceiling,
    expires_at: reservation.expires_at,
    task_id: reservation.task_id,
    attempt_id: reservation.attempt_id,
    artifact_handle: reservation.artifact_handle,
  });
}

function computeCapabilityDigest(reservationDigest, metadataDigest) {
  return digestRecord(CAPABILITY_DIGEST_DOMAIN, {
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    vault_reservation_digest: reservationDigest,
    metadata_digest: metadataDigest,
  });
}

function assertPrivateDirectory(directory, label) {
  let created = false;
  try {
    fs.mkdirSync(directory, { mode: 0o700 });
    created = true;
  } catch (error) {
    if (!error || error.code !== "EEXIST") throw error;
  }
  const stats = fs.lstatSync(directory);
  if (!stats.isDirectory() || stats.isSymbolicLink()
      || (typeof process.getuid === "function" && stats.uid !== process.getuid())) {
    throw new Error(`${label} must be a real directory owned by this process identity`);
  }
  if (created) fs.chmodSync(directory, 0o700);
  const after = fs.lstatSync(directory);
  if ((after.mode & 0o777) !== 0o700) {
    throw new Error(`${label} must have mode 0700`);
  }
  if (created) fsyncDirectory(path.dirname(directory));
  return after;
}

function assertSafeStateDescriptor(descriptor, label) {
  const stats = fs.fstatSync(descriptor);
  if (!stats.isFile() || stats.nlink !== 1
      || (stats.mode & 0o777) !== 0o600
      || (typeof process.getuid === "function" && stats.uid !== process.getuid())) {
    throw new Error(`${label} must be a single-link mode-0600 file owned by this process identity`);
  }
  return stats;
}

function assertSafeStatePath(filePath, label, { required = true } = {}) {
  let stats;
  try {
    stats = fs.lstatSync(filePath);
  } catch (error) {
    if (!required && error && error.code === "ENOENT") return null;
    throw error;
  }
  if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1
      || (stats.mode & 0o777) !== 0o600
      || (typeof process.getuid === "function" && stats.uid !== process.getuid())) {
    throw new Error(`${label} must be a single-link mode-0600 file owned by this process identity`);
  }
  return stats;
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(
    directory,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0),
  );
  try {
    const stats = fs.fstatSync(descriptor);
    if (!stats.isDirectory()
        || (typeof process.getuid === "function" && stats.uid !== process.getuid())
        || (stats.mode & 0o077) !== 0) {
      throw new Error("provider response receipt directory is unsafe");
    }
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function ensureReceiptRoot(owner) {
  owner.assert_live();
  assertPrivateDirectory(owner.receipt_root, "provider response receipt directory");
}

function statePath(owner, executionLineageDigest) {
  assertDigest(executionLineageDigest, "execution_lineage_digest");
  return path.join(owner.receipt_root, `${executionLineageDigest}.json`);
}

function repairReservationJournalFencePublication(owner, reservationDigest) {
  ensureReceiptRoot(owner);
  assertDigest(reservationDigest, "vault_reservation_digest");
  const filePath = path.join(owner.receipt_root, `reservation-${reservationDigest}.json`);
  let finalStats;
  try {
    finalStats = fs.lstatSync(filePath);
  } catch (error) {
    if (error && error.code === "ENOENT") return false;
    throw error;
  }
  if (!finalStats.isFile() || finalStats.isSymbolicLink()
      || (finalStats.mode & 0o777) !== 0o600
      || (typeof process.getuid === "function" && finalStats.uid !== process.getuid())) {
    throw new Error("provider response reservation journal fence publication is unsafe");
  }
  if (finalStats.nlink === 1) return false;
  let repaired = false;
  for (const entry of fs.readdirSync(owner.receipt_root, { withFileTypes: true })) {
    const match = RESERVATION_JOURNAL_FENCE_TEMP_FILE_RE.exec(entry.name);
    if (!match || match[1] !== reservationDigest || !entry.isFile()) continue;
    const candidate = path.join(owner.receipt_root, entry.name);
    const candidateStats = fs.lstatSync(candidate);
    if (candidateStats.dev !== finalStats.dev || candidateStats.ino !== finalStats.ino) continue;
    if (!candidateStats.isFile() || candidateStats.isSymbolicLink()
        || (candidateStats.mode & 0o777) !== 0o600
        || (typeof process.getuid === "function"
          && candidateStats.uid !== process.getuid())) {
      throw new Error("provider response reservation journal fence temporary publication is unsafe");
    }
    fs.unlinkSync(candidate);
    repaired = true;
  }
  const after = fs.lstatSync(filePath);
  if (!after.isFile() || after.isSymbolicLink()
      || after.dev !== finalStats.dev || after.ino !== finalStats.ino
      || after.nlink !== 1 || (after.mode & 0o777) !== 0o600
      || (typeof process.getuid === "function" && after.uid !== process.getuid())) {
    throw new Error("provider response reservation journal fence has an unexplained hardlink");
  }
  if (repaired) fsyncDirectory(owner.receipt_root);
  return repaired;
}

function readAuthenticatedPayload(owner, filePath, label, { required = true } = {}) {
  ensureReceiptRoot(owner);
  const prior = assertSafeStatePath(filePath, label, { required });
  if (!prior) return null;
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0),
  );
  let encoded = null;
  try {
    const before = assertSafeStateDescriptor(descriptor, label);
    if (!Number.isSafeInteger(before.size) || before.size < 1 || before.size > MAX_STATE_BYTES) {
      throw new Error(`${label} exceeds its byte ceiling`);
    }
    encoded = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < encoded.length) {
      const count = fs.readSync(descriptor, encoded, offset, encoded.length - offset, offset);
      if (count === 0) throw new Error(`${label} changed during read`);
      offset += count;
    }
    const after = fs.fstatSync(descriptor);
    const pathState = fs.lstatSync(filePath);
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size
        || !pathState.isFile() || pathState.isSymbolicLink() || pathState.nlink !== 1
        || pathState.dev !== after.dev || pathState.ino !== after.ino) {
      throw new Error(`${label} changed during read`);
    }
    let wrapper;
    try {
      wrapper = JSON.parse(encoded.toString("utf8"));
    } catch {
      throw new Error(`${label} is unreadable or corrupt`);
    }
    const descriptors = assertExactDataObject(
      wrapper,
      ["version", "payload", "mac"],
      `${label}_wrapper`,
    );
    assertVersion(descriptorValue(descriptors, "version"), `${label}_wrapper`);
    const payload = descriptorValue(descriptors, "payload");
    const mac = assertDigest(
      descriptorValue(descriptors, "mac"),
      `${label}_wrapper.mac`,
    );
    const serialized = canonicalJson(payload);
    if (!constantTimeEqual(mac, owner.authenticate_state(serialized))) {
      throw new Error(`${label} authentication failed`);
    }
    return payload;
  } finally {
    if (encoded) encoded.fill(0);
    fs.closeSync(descriptor);
  }
}

function readStatePayload(owner, executionLineageDigest, options = {}) {
  return readAuthenticatedPayload(
    owner,
    statePath(owner, executionLineageDigest),
    "provider response receipt state",
    options,
  );
}

function readStateFile(owner, executionLineageDigest, options = {}) {
  const payload = readStatePayload(owner, executionLineageDigest, options);
  if (payload != null && payload.kind !== "provider_response_vault_receipt_state") {
    throw new Error("provider response journal is fenced to raw custody mode");
  }
  return payload == null
    ? null
    : normalizeJournalPayload(payload, owner, executionLineageDigest);
}

function cleanAndCountStateFiles(owner) {
  ensureReceiptRoot(owner);
  let count = 0;
  let removed = false;
  for (const entry of fs.readdirSync(owner.receipt_root, { withFileTypes: true })) {
    const candidate = path.join(owner.receipt_root, entry.name);
    if (STATE_FILE_RE.test(entry.name)) {
      assertSafeStatePath(candidate, "provider response receipt inventory entry");
      count += 1;
      continue;
    }
    const fenceMatch = RESERVATION_JOURNAL_FENCE_FILE_RE.exec(entry.name);
    if (fenceMatch) {
      repairReservationJournalFencePublication(owner, fenceMatch[1]);
      assertSafeStatePath(candidate, "provider response reservation journal fence");
      continue;
    }
    if (TEMP_FILE_RE.test(entry.name)) {
      const fenceTempMatch = RESERVATION_JOURNAL_FENCE_TEMP_FILE_RE.exec(entry.name);
      if (fenceTempMatch) {
        repairReservationJournalFencePublication(owner, fenceTempMatch[1]);
      }
      const remaining = assertSafeStatePath(
        candidate,
        "orphaned provider response receipt temporary file",
        { required: false },
      );
      if (remaining) {
        fs.unlinkSync(candidate);
        removed = true;
      }
      continue;
    }
    throw new Error("provider response receipt directory contains an unregistered entry");
  }
  if (removed) fsyncDirectory(owner.receipt_root);
  return count;
}

function writeAuthenticatedPayload(owner, filePath, payload, label) {
  ensureReceiptRoot(owner);
  assertSafeStatePath(filePath, label, { required: false });
  const serialized = canonicalJson(payload);
  const wrapper = canonicalJson({
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    payload,
    mac: owner.authenticate_state(serialized),
  });
  const encoded = Buffer.from(`${wrapper}\n`, "utf8");
  if (encoded.length > MAX_STATE_BYTES) {
    encoded.fill(0);
    throw new Error(`${label} exceeds its byte ceiling`);
  }
  const tempPath = path.join(
    owner.receipt_root,
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(32).toString("base64url")}.tmp`,
  );
  let descriptor = null;
  try {
    descriptor = fs.openSync(
      tempPath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY
        | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0),
      0o600,
    );
    fs.fchmodSync(descriptor, 0o600);
    assertSafeStateDescriptor(descriptor, `${label} temporary state`);
    let offset = 0;
    while (offset < encoded.length) {
      offset += fs.writeSync(descriptor, encoded, offset, encoded.length - offset, offset);
    }
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    fs.renameSync(tempPath, filePath);
    assertSafeStatePath(filePath, label);
    fsyncDirectory(owner.receipt_root);
  } finally {
    encoded.fill(0);
    if (descriptor !== null) {
      try { fs.closeSync(descriptor); } catch {}
    }
    try { fs.unlinkSync(tempPath); } catch {}
  }
}

function writeStateFile(owner, payload) {
  writeAuthenticatedPayload(
    owner,
    statePath(owner, payload.execution_lineage_digest),
    payload,
    "provider response receipt state",
  );
}

function reservationJournalFencePath(owner, reservationDigest) {
  assertDigest(reservationDigest, "vault_reservation_digest");
  return path.join(owner.receipt_root, `reservation-${reservationDigest}.json`);
}

function reservationJournalFenceProjection(input) {
  const projection = {};
  for (const field of RESERVATION_JOURNAL_FENCE_FIELDS) {
    if (field !== "fence_digest") projection[field] = input[field];
  }
  return objectFreeze(projection);
}

function normalizeReservationJournalFence(input, owner, expectedReservationDigest) {
  const label = "provider_response_reservation_journal_fence";
  const descriptors = assertExactDataObject(input, RESERVATION_JOURNAL_FENCE_FIELDS, label);
  const fence = {};
  for (const field of RESERVATION_JOURNAL_FENCE_FIELDS) {
    fence[field] = descriptorValue(descriptors, field);
  }
  assertVersion(fence.version, label);
  if (fence.kind !== "provider_response_reservation_journal_fence"
      || fence.vault_id !== owner.vault_id
      || fence.vault_slot !== owner.vault_slot
      || fence.session_nucleus_hash !== owner.session_nucleus_hash
      || !["semantic_result", "raw_custody"].includes(fence.journal_mode)) {
    throw new Error("provider response reservation journal fence identity is invalid");
  }
  if (!PUBLIC_RESERVATION_HANDLE_RE.test(fence.reservation_handle || "")) {
    throw new Error("provider response reservation journal fence handle is invalid");
  }
  for (const field of [
    "session_nucleus_hash",
    "vault_reservation_digest",
    "vault_ingest_capability_digest",
    "execution_lineage_digest",
    "fence_digest",
  ]) assertDigest(fence[field], `${label}.${field}`);
  if (fence.vault_reservation_digest !== expectedReservationDigest) {
    throw new Error("provider response reservation journal fence path binding is invalid");
  }
  const projection = reservationJournalFenceProjection(fence);
  if (fence.fence_digest !== digestRecord(
    RESERVATION_JOURNAL_FENCE_DIGEST_DOMAIN,
    projection,
  )) {
    throw new Error("provider response reservation journal fence digest is invalid");
  }
  return objectFreeze({ ...projection, fence_digest: fence.fence_digest });
}

function readReservationJournalFence(owner, reservationDigest, { required = true } = {}) {
  repairReservationJournalFencePublication(owner, reservationDigest);
  const payload = readAuthenticatedPayload(
    owner,
    reservationJournalFencePath(owner, reservationDigest),
    "provider response reservation journal fence",
    { required },
  );
  return payload == null
    ? null
    : normalizeReservationJournalFence(payload, owner, reservationDigest);
}

function publishReservationJournalFenceExclusive(owner, fence) {
  ensureReceiptRoot(owner);
  const filePath = reservationJournalFencePath(owner, fence.vault_reservation_digest);
  assertSafeStatePath(filePath, "provider response reservation journal fence", {
    required: false,
  });
  const serialized = canonicalJson(fence);
  const wrapper = canonicalJson({
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    payload: fence,
    mac: owner.authenticate_state(serialized),
  });
  const encoded = Buffer.from(`${wrapper}\n`, "utf8");
  if (encoded.length > MAX_STATE_BYTES) {
    encoded.fill(0);
    throw new Error("provider response reservation journal fence exceeds its byte ceiling");
  }
  const tempPath = path.join(
    owner.receipt_root,
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(32).toString("base64url")}.tmp`,
  );
  let descriptor = null;
  let published = false;
  try {
    descriptor = fs.openSync(
      tempPath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY
        | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0),
      0o600,
    );
    fs.fchmodSync(descriptor, 0o600);
    assertSafeStateDescriptor(descriptor, "provider response reservation journal fence temporary state");
    let offset = 0;
    while (offset < encoded.length) {
      offset += fs.writeSync(descriptor, encoded, offset, encoded.length - offset, offset);
    }
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    try {
      fs.linkSync(tempPath, filePath);
      published = true;
    } catch (error) {
      if (!error || error.code !== "EEXIST") throw error;
    }
  } finally {
    encoded.fill(0);
    if (descriptor !== null) {
      try { fs.closeSync(descriptor); } catch {}
    }
    try { fs.unlinkSync(tempPath); } catch {}
    fsyncDirectory(owner.receipt_root);
  }
  if (published) {
    assertSafeStatePath(filePath, "provider response reservation journal fence");
  }
  return published;
}

function reservationJournalFenceBasis(owner, reservation, lineage, journalMode) {
  if (!["semantic_result", "raw_custody"].includes(journalMode)) {
    throw new Error("provider response reservation journal mode is invalid");
  }
  const projection = {
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "provider_response_reservation_journal_fence",
    vault_id: owner.vault_id,
    vault_slot: owner.vault_slot,
    session_nucleus_hash: owner.session_nucleus_hash,
    reservation_handle: reservation.reservation_handle,
    vault_reservation_digest: reservation.vault_reservation_digest,
    vault_ingest_capability_digest: reservation.vault_ingest_capability_digest,
    execution_lineage_digest: lineage.execution_lineage_digest,
    journal_mode: journalMode,
  };
  return objectFreeze({
    ...projection,
    fence_digest: digestRecord(RESERVATION_JOURNAL_FENCE_DIGEST_DOMAIN, projection),
  });
}

function assertReservationJournalFenceMatches(owner, reservation, lineage, journalMode,
  { create = false } = {}) {
  const expected = reservationJournalFenceBasis(owner, reservation, lineage, journalMode);
  let current = readReservationJournalFence(
    owner,
    reservation.vault_reservation_digest,
    { required: false },
  );
  if (!current && create) {
    publishReservationJournalFenceExclusive(owner, expected);
    current = readReservationJournalFence(owner, reservation.vault_reservation_digest);
  }
  if (!current) {
    throw new Error("provider response reservation journal fence is absent");
  }
  if (canonicalJson(current) !== canonicalJson(expected)) {
    throw new Error("provider response reservation is fenced to a different journal mode or lineage");
  }
  return current;
}

function normalizeReservationState(input, owner, metadataDigest) {
  const descriptors = assertExactDataObject(
    input,
    RESERVATION_STATE_FIELDS,
    "provider_response_receipt_state.reservation",
  );
  const reservation = {
    reservation_handle: descriptorValue(descriptors, "reservation_handle"),
    reservation_ref: assertOpaqueRef(
      descriptorValue(descriptors, "reservation_ref"),
      "provider_response_receipt_state.reservation.reservation_ref",
    ),
    reservation_binding_digest: assertDigest(
      descriptorValue(descriptors, "reservation_binding_digest"),
      "provider_response_receipt_state.reservation.reservation_binding_digest",
    ),
    byte_ceiling: assertPositiveInteger(
      descriptorValue(descriptors, "byte_ceiling"),
      "provider_response_receipt_state.reservation.byte_ceiling",
    ),
    expires_at: assertCanonicalTimestamp(
      descriptorValue(descriptors, "expires_at"),
      "provider_response_receipt_state.reservation.expires_at",
    ),
    task_id: assertIdentifier(
      descriptorValue(descriptors, "task_id"),
      "provider_response_receipt_state.reservation.task_id",
    ),
    attempt_id: assertIdentifier(
      descriptorValue(descriptors, "attempt_id"),
      "provider_response_receipt_state.reservation.attempt_id",
    ),
    artifact_handle: descriptorValue(descriptors, "artifact_handle"),
    vault_reservation_digest: assertDigest(
      descriptorValue(descriptors, "vault_reservation_digest"),
      "provider_response_receipt_state.reservation.vault_reservation_digest",
    ),
    vault_ingest_capability_digest: assertDigest(
      descriptorValue(descriptors, "vault_ingest_capability_digest"),
      "provider_response_receipt_state.reservation.vault_ingest_capability_digest",
    ),
  };
  if (typeof reservation.reservation_handle !== "string"
      || !PUBLIC_RESERVATION_HANDLE_RE.test(reservation.reservation_handle)
      || typeof reservation.artifact_handle !== "string"
      || !PUBLIC_ARTIFACT_HANDLE_RE.test(reservation.artifact_handle)) {
    throw new Error("provider response receipt reservation handles are invalid");
  }
  const expectedReservationDigest = computeReservationDigest(owner, reservation);
  const expectedCapabilityDigest = computeCapabilityDigest(expectedReservationDigest, metadataDigest);
  if (reservation.vault_reservation_digest !== expectedReservationDigest
      || reservation.vault_ingest_capability_digest !== expectedCapabilityDigest) {
    throw new Error("provider response receipt reservation capability binding is invalid");
  }
  return objectFreeze(reservation);
}

function transportProjectionWithoutDigest(input) {
  const projection = {};
  for (const field of TRANSPORT_RESULT_FIELDS) {
    if (field !== "transaction_receipt_digest") projection[field] = input[field];
  }
  return objectFreeze(projection);
}

function normalizeTransportResult(input, lineage, label = "transport_reserved_vault_result") {
  const descriptors = assertExactDataObject(input, TRANSPORT_RESULT_FIELDS, label);
  const result = {};
  for (const field of TRANSPORT_RESULT_FIELDS) result[field] = descriptorValue(descriptors, field);
  assertVersion(result.version, label);
  if (result.kind !== "transport_reserved_vault_result") {
    throw new Error(`${label}.kind is invalid`);
  }
  for (const field of [
    "execution_lineage_digest",
    "compiler_manifest_digest",
    "compiler_registry_digest",
    "compiled_operation_digest",
    "requested_effects_digest",
    "compiled_command_capability_digest",
    "active_command_input_digest",
    "worker_launch_digest",
    "worker_fence_digest",
    "resource_fence_digest",
    "transport_binding_digest",
    "vault_reservation_digest",
    "vault_ingest_capability_digest",
    "execution_claim_receipt_digest",
    "deadline_fence_receipt_digest",
    "response_digest",
    "device_state_digest",
    "vault_commit_receipt_digest",
    "raw_response_custody_digest",
    "transaction_receipt_digest",
  ]) assertDigest(result[field], `${label}.${field}`);
  for (const field of [
    "transaction_ref",
    "provider_id",
    "operation_id",
    "compiler_id",
    "provider_command_ref",
    "runtime_availability",
    "compiled_command_id",
    "active_command_input_ref",
  ]) assertOpaqueRef(result[field], `${label}.${field}`);
  if (!PUBLIC_RESERVATION_HANDLE_RE.test(result.vault_reservation_handle || "")
      || !PUBLIC_ARTIFACT_HANDLE_RE.test(result.artifact_handle || "")) {
    throw new Error(`${label} contains an invalid vault or artifact handle`);
  }
  assertNonnegativeInteger(result.response_byte_length, `${label}.response_byte_length`);
  assertResultCode(result.result_code, `${label}.result_code`);
  const lineageBindings = [
    "execution_lineage_digest",
    "provider_id",
    "operation_id",
    "compiler_id",
    "compiler_manifest_digest",
    "compiler_registry_digest",
    "compiled_operation_digest",
    "provider_command_ref",
    "requested_effects_digest",
    "runtime_availability",
    "compiled_command_id",
    "compiled_command_capability_digest",
    "active_command_input_ref",
    "active_command_input_digest",
    "worker_launch_digest",
    "worker_fence_digest",
    "resource_fence_digest",
    "transport_binding_digest",
    "vault_reservation_handle",
    "vault_reservation_digest",
    "vault_ingest_capability_digest",
  ];
  for (const field of lineageBindings) {
    if (result[field] !== lineage[field]) throw new Error(`${label}.${field} drifted from lineage`);
  }
  if (result.result_code !== lineage.expected_result_code
      || result.response_byte_length > lineage.maximum_response_bytes
      || result.response_byte_length > lineage.vault_byte_ceiling) {
    throw new Error(`${label} violates its precommitted result or response bound`);
  }
  const projection = transportProjectionWithoutDigest(result);
  if (result.transaction_receipt_digest !== digestRecord(TRANSACTION_DIGEST_DOMAIN, projection)) {
    throw new Error(`${label}.transaction_receipt_digest is invalid`);
  }
  return objectFreeze({ ...projection, transaction_receipt_digest: result.transaction_receipt_digest });
}

function ingestReceiptProjectionWithoutDigest(input) {
  const projection = {};
  for (const field of INGEST_RECEIPT_FIELDS) {
    if (field !== "ingest_receipt_digest") projection[field] = input[field];
  }
  return objectFreeze(projection);
}

function normalizeIngestReceipt(input, lineage, transport, label = "reserved_vault_ingest_receipt") {
  const descriptors = assertExactDataObject(input, INGEST_RECEIPT_FIELDS, label);
  const receipt = {};
  for (const field of INGEST_RECEIPT_FIELDS) receipt[field] = descriptorValue(descriptors, field);
  assertVersion(receipt.version, label);
  if (receipt.kind !== "reserved_vault_ingest_receipt") throw new Error(`${label}.kind is invalid`);
  for (const field of [
    "execution_lineage_digest",
    "vault_reservation_digest",
    "vault_ingest_capability_digest",
    "execution_claim_receipt_digest",
    "deadline_fence_receipt_digest",
    "response_digest",
    "transaction_receipt_digest",
    "vault_commit_receipt_digest",
    "raw_response_custody_digest",
    "ingest_receipt_digest",
  ]) assertDigest(receipt[field], `${label}.${field}`);
  if (!PUBLIC_RESERVATION_HANDLE_RE.test(receipt.vault_reservation_handle || "")
      || !PUBLIC_ARTIFACT_HANDLE_RE.test(receipt.artifact_handle || "")) {
    throw new Error(`${label} contains an invalid vault or artifact handle`);
  }
  assertNonnegativeInteger(receipt.response_byte_length, `${label}.response_byte_length`);
  for (const field of [
    "execution_lineage_digest",
    "vault_reservation_handle",
    "vault_reservation_digest",
    "vault_ingest_capability_digest",
  ]) {
    if (receipt[field] !== lineage[field]) throw new Error(`${label}.${field} drifted from lineage`);
  }
  for (const field of [
    "artifact_handle",
    "execution_claim_receipt_digest",
    "deadline_fence_receipt_digest",
    "response_digest",
    "response_byte_length",
    "transaction_receipt_digest",
    "vault_commit_receipt_digest",
    "raw_response_custody_digest",
  ]) {
    if (receipt[field] !== transport[field]) throw new Error(`${label}.${field} drifted from transaction`);
  }
  const projection = ingestReceiptProjectionWithoutDigest(receipt);
  if (receipt.ingest_receipt_digest !== digestRecord(INGEST_RECEIPT_DIGEST_DOMAIN, projection)) {
    throw new Error(`${label}.ingest_receipt_digest is invalid`);
  }
  return objectFreeze({ ...projection, ingest_receipt_digest: receipt.ingest_receipt_digest });
}

function normalizeJournalPayload(input, owner, expectedLineageDigest) {
  const descriptors = assertExactDataObject(input, JOURNAL_FIELDS, "provider_response_receipt_state");
  const value = {};
  for (const field of JOURNAL_FIELDS) value[field] = descriptorValue(descriptors, field);
  assertVersion(value.version, "provider_response_receipt_state");
  if (value.kind !== "provider_response_vault_receipt_state"
      || !["prepared", "sink_committed", "receipt_committed"].includes(value.state)
      || value.vault_id !== owner.vault_id
      || value.vault_slot !== owner.vault_slot
      || value.session_nucleus_hash !== owner.session_nucleus_hash) {
    throw new Error("provider response receipt state identity is invalid");
  }
  assertDigest(value.execution_lineage_digest, "provider_response_receipt_state.execution_lineage_digest");
  if (value.execution_lineage_digest !== expectedLineageDigest) {
    throw new Error("provider response receipt state path binding is invalid");
  }
  const lineage = normalizeTransportLineage(value.lineage);
  if (lineage.execution_lineage_digest !== value.execution_lineage_digest
      || lineage.session_nucleus_hash !== owner.session_nucleus_hash) {
    throw new Error("provider response receipt state lineage identity is invalid");
  }
  const metadata = normalizeMetadata(value.metadata);
  const metadataDigest = assertDigest(value.metadata_digest, "provider_response_receipt_state.metadata_digest");
  if (metadataDigest !== sha256(canonicalJson(metadata))) {
    throw new Error("provider response receipt metadata digest is invalid");
  }
  const reservation = normalizeReservationState(value.reservation, owner, metadataDigest);
  if (lineage.task_id !== reservation.task_id
      || lineage.attempt_id !== reservation.attempt_id
      || lineage.vault_reservation_handle !== reservation.reservation_handle
      || lineage.vault_reservation_digest !== reservation.vault_reservation_digest
      || lineage.vault_ingest_capability_digest !== reservation.vault_ingest_capability_digest
      || lineage.vault_byte_ceiling !== reservation.byte_ceiling
      || metadata.session_nucleus_hash !== owner.session_nucleus_hash
      || metadata.task_id !== reservation.task_id
      || metadata.attempt_id !== reservation.attempt_id) {
    throw new Error("provider response receipt state reservation or task binding is invalid");
  }
  assertDigest(value.execution_claim_receipt_digest, "provider_response_receipt_state.execution_claim_receipt_digest");
  assertDigest(value.deadline_fence_receipt_digest, "provider_response_receipt_state.deadline_fence_receipt_digest");
  assertOpaqueRef(value.transaction_ref, "provider_response_receipt_state.transaction_ref");
  assertResultCode(value.result_code, "provider_response_receipt_state.result_code");
  assertDigest(value.device_state_digest, "provider_response_receipt_state.device_state_digest");
  assertDigest(value.response_digest, "provider_response_receipt_state.response_digest");
  assertNonnegativeInteger(
    value.response_byte_length,
    "provider_response_receipt_state.response_byte_length",
  );
  if (value.response_byte_length > lineage.maximum_response_bytes
      || value.response_byte_length > reservation.byte_ceiling
      || value.result_code !== lineage.expected_result_code
      || typeof value.content_token !== "string" || !BASE64URL_256_RE.test(value.content_token)) {
    throw new Error("provider response receipt state violates its precommitted response binding");
  }
  assertCanonicalTimestamp(value.prepared_at, "provider_response_receipt_state.prepared_at");
  let transport = null;
  let receipt = null;
  if (value.state === "prepared") {
    if (value.vault_committed_at !== null || value.transport_result !== null
        || value.ingest_receipt !== null) {
      throw new Error("prepared provider response receipt state has terminal fields");
    }
  } else {
    assertCanonicalTimestamp(value.vault_committed_at, "provider_response_receipt_state.vault_committed_at");
    transport = normalizeTransportResult(value.transport_result, lineage);
    if (transport.transaction_ref !== value.transaction_ref
        || transport.execution_claim_receipt_digest !== value.execution_claim_receipt_digest
        || transport.deadline_fence_receipt_digest !== value.deadline_fence_receipt_digest
        || transport.response_digest !== value.response_digest
        || transport.response_byte_length !== value.response_byte_length
        || transport.result_code !== value.result_code
        || transport.device_state_digest !== value.device_state_digest
        || transport.artifact_handle !== reservation.artifact_handle) {
      throw new Error("provider response receipt state transaction binding is invalid");
    }
    const expectedCommitDigest = digestRecord(VAULT_COMMIT_DIGEST_DOMAIN, {
      version: PROVIDER_RESPONSE_VAULT_VERSION,
      execution_lineage_digest: lineage.execution_lineage_digest,
      vault_reservation_handle: reservation.reservation_handle,
      vault_reservation_digest: reservation.vault_reservation_digest,
      vault_ingest_capability_digest: reservation.vault_ingest_capability_digest,
      artifact_handle: reservation.artifact_handle,
      response_digest: value.response_digest,
      response_byte_length: value.response_byte_length,
      metadata_digest: value.metadata_digest,
      content_token: value.content_token,
      committed_at: value.vault_committed_at,
    });
    const expectedCustodyDigest = digestRecord(RAW_CUSTODY_DIGEST_DOMAIN, {
      version: PROVIDER_RESPONSE_VAULT_VERSION,
      execution_lineage_digest: lineage.execution_lineage_digest,
      transaction_ref: value.transaction_ref,
      execution_claim_receipt_digest: value.execution_claim_receipt_digest,
      deadline_fence_receipt_digest: value.deadline_fence_receipt_digest,
      artifact_handle: reservation.artifact_handle,
      response_digest: value.response_digest,
      response_byte_length: value.response_byte_length,
      vault_commit_receipt_digest: expectedCommitDigest,
    });
    if (transport.vault_commit_receipt_digest !== expectedCommitDigest
        || transport.raw_response_custody_digest !== expectedCustodyDigest) {
      throw new Error("provider response receipt state custody binding is invalid");
    }
    if (value.state === "sink_committed") {
      if (value.ingest_receipt !== null) {
        throw new Error("sink-committed provider response state has an ingest receipt");
      }
    } else {
      receipt = normalizeIngestReceipt(value.ingest_receipt, lineage, transport);
    }
  }
  return objectFreeze({
    ...value,
    lineage,
    reservation,
    metadata,
    transport_result: transport,
    ingest_receipt: receipt,
  });
}

function normalizeRawCustodyObservation(input, label = "raw_custody_transport_observation") {
  const descriptors = assertExactDataObject(input, RAW_CUSTODY_OBSERVATION_FIELDS, label);
  const observation = objectFreeze({
    transport_settlement_kind: assertOpaqueRef(
      descriptorValue(descriptors, "transport_settlement_kind"),
      `${label}.transport_settlement_kind`,
    ),
    dispatch_envelope_digest: assertDigest(
      descriptorValue(descriptors, "dispatch_envelope_digest"),
      `${label}.dispatch_envelope_digest`,
    ),
    source_descriptor_identity_digest: assertDigest(
      descriptorValue(descriptors, "source_descriptor_identity_digest"),
      `${label}.source_descriptor_identity_digest`,
    ),
    sink_descriptor_identity_digest: assertDigest(
      descriptorValue(descriptors, "sink_descriptor_identity_digest"),
      `${label}.sink_descriptor_identity_digest`,
    ),
    sink_record_digest: assertDigest(
      descriptorValue(descriptors, "sink_record_digest"),
      `${label}.sink_record_digest`,
    ),
    ticket_sequence: assertUint64(
      descriptorValue(descriptors, "ticket_sequence"),
      `${label}.ticket_sequence`,
    ),
    settled_monotonic_ns: assertUint64(
      descriptorValue(descriptors, "settled_monotonic_ns"),
      `${label}.settled_monotonic_ns`,
    ),
  });
  if (BigInt(observation.ticket_sequence) < 1n
      || BigInt(observation.settled_monotonic_ns) < 1n) {
    throw new Error(`${label} sequence and settlement time must be positive`);
  }
  return observation;
}

function rawCustodyReceiptProjection(input) {
  const projection = {};
  for (const field of RAW_CUSTODY_RECEIPT_FIELDS) {
    if (field !== "raw_custody_receipt_digest") projection[field] = input[field];
  }
  return objectFreeze(projection);
}

function normalizeRawCustodyReceipt(input, lineage, observation,
  label = "provider_response_raw_custody_receipt") {
  const descriptors = assertExactDataObject(input, RAW_CUSTODY_RECEIPT_FIELDS, label);
  const receipt = {};
  for (const field of RAW_CUSTODY_RECEIPT_FIELDS) {
    receipt[field] = descriptorValue(descriptors, field);
  }
  assertVersion(receipt.version, label);
  if (receipt.kind !== "provider_response_raw_custody_receipt") {
    throw new Error(`${label}.kind is invalid`);
  }
  for (const field of [
    "execution_lineage_digest",
    "compiler_manifest_digest",
    "compiler_registry_digest",
    "compiled_operation_digest",
    "requested_effects_digest",
    "compiled_command_capability_digest",
    "active_command_input_digest",
    "worker_launch_digest",
    "worker_fence_digest",
    "resource_fence_digest",
    "transport_binding_digest",
    "vault_reservation_digest",
    "vault_ingest_capability_digest",
    "execution_claim_receipt_digest",
    "deadline_fence_receipt_digest",
    "response_digest",
    "dispatch_envelope_digest",
    "source_descriptor_identity_digest",
    "sink_descriptor_identity_digest",
    "sink_record_digest",
    "transport_observation_digest",
    "vault_commit_receipt_digest",
    "raw_custody_receipt_digest",
  ]) assertDigest(receipt[field], `${label}.${field}`);
  for (const field of [
    "custody_ref",
    "provider_id",
    "operation_id",
    "compiler_id",
    "provider_command_ref",
    "runtime_availability",
    "compiled_command_id",
    "active_command_input_ref",
    "transport_settlement_kind",
  ]) assertOpaqueRef(receipt[field], `${label}.${field}`);
  if (!PUBLIC_RESERVATION_HANDLE_RE.test(receipt.vault_reservation_handle || "")
      || !PUBLIC_ARTIFACT_HANDLE_RE.test(receipt.artifact_handle || "")) {
    throw new Error(`${label} contains an invalid vault or artifact handle`);
  }
  assertNonnegativeInteger(receipt.response_byte_length, `${label}.response_byte_length`);
  assertUint64(receipt.ticket_sequence, `${label}.ticket_sequence`);
  assertUint64(receipt.settled_monotonic_ns, `${label}.settled_monotonic_ns`);
  if (receipt.semantic_validation_performed !== false
      || receipt.production_ready !== false
      || receipt.hardware_access_authorized !== false
      || receipt.authoritative !== false) {
    throw new Error(`${label} cannot carry semantic, production, hardware, or authority claims`);
  }
  const lineageBindings = [
    "execution_lineage_digest",
    "provider_id",
    "operation_id",
    "compiler_id",
    "compiler_manifest_digest",
    "compiler_registry_digest",
    "compiled_operation_digest",
    "provider_command_ref",
    "requested_effects_digest",
    "runtime_availability",
    "compiled_command_id",
    "compiled_command_capability_digest",
    "active_command_input_ref",
    "active_command_input_digest",
    "worker_launch_digest",
    "worker_fence_digest",
    "resource_fence_digest",
    "transport_binding_digest",
    "vault_reservation_handle",
    "vault_reservation_digest",
    "vault_ingest_capability_digest",
  ];
  for (const field of lineageBindings) {
    if (receipt[field] !== lineage[field]) {
      throw new Error(`${label}.${field} drifted from lineage`);
    }
  }
  const observationBindings = {
    transport_settlement_kind: "transport_settlement_kind",
    dispatch_envelope_digest: "dispatch_envelope_digest",
    source_descriptor_identity_digest: "source_descriptor_identity_digest",
    sink_descriptor_identity_digest: "sink_descriptor_identity_digest",
    sink_record_digest: "sink_record_digest",
    ticket_sequence: "ticket_sequence",
    settled_monotonic_ns: "settled_monotonic_ns",
  };
  for (const [receiptField, observationField] of Object.entries(observationBindings)) {
    if (receipt[receiptField] !== observation[observationField]) {
      throw new Error(`${label}.${receiptField} drifted from its transport observation`);
    }
  }
  const expectedObservationDigest = digestRecord(
    RAW_CUSTODY_OBSERVATION_DIGEST_DOMAIN,
    observation,
  );
  if (receipt.transport_observation_digest !== expectedObservationDigest
      || receipt.response_byte_length > lineage.maximum_response_bytes
      || receipt.response_byte_length > lineage.vault_byte_ceiling) {
    throw new Error(`${label} violates its raw transport custody binding`);
  }
  const projection = rawCustodyReceiptProjection(receipt);
  if (receipt.raw_custody_receipt_digest
      !== digestRecord(RAW_CUSTODY_RECEIPT_DIGEST_DOMAIN, projection)) {
    throw new Error(`${label}.raw_custody_receipt_digest is invalid`);
  }
  return objectFreeze({
    ...projection,
    raw_custody_receipt_digest: receipt.raw_custody_receipt_digest,
  });
}

function projectionWithoutField(input, fields, omittedField) {
  const projection = {};
  for (const field of fields) {
    if (field !== omittedField) projection[field] = input[field];
  }
  return objectFreeze(projection);
}

function normalizeRawCustodyCleanupReceipt(input, lineage, reservation, rawReceipt,
  label = "provider_response_raw_custody_cleanup_receipt") {
  const descriptors = assertExactDataObject(
    input,
    RAW_CUSTODY_CLEANUP_RECEIPT_FIELDS,
    label,
  );
  const receipt = {};
  for (const field of RAW_CUSTODY_CLEANUP_RECEIPT_FIELDS) {
    receipt[field] = descriptorValue(descriptors, field);
  }
  assertVersion(receipt.version, label);
  if (receipt.kind !== "provider_response_raw_custody_cleanup_receipt") {
    throw new Error(`${label}.kind is invalid`);
  }
  for (const field of [
    "execution_lineage_digest",
    "raw_custody_receipt_digest",
    "vault_reservation_digest",
    "vault_ingest_capability_digest",
    "source_descriptor_identity_digest",
    "sink_descriptor_identity_digest",
    "sink_record_digest",
    "cleanup_receipt_digest",
  ]) assertDigest(receipt[field], `${label}.${field}`);
  if (!PUBLIC_ARTIFACT_HANDLE_RE.test(receipt.artifact_handle || "")) {
    throw new Error(`${label}.artifact_handle is invalid`);
  }
  assertCanonicalTimestamp(receipt.cleanup_reconciled_at, `${label}.cleanup_reconciled_at`);
  const expected = {
    execution_lineage_digest: lineage.execution_lineage_digest,
    raw_custody_receipt_digest: rawReceipt.raw_custody_receipt_digest,
    vault_reservation_digest: reservation.vault_reservation_digest,
    vault_ingest_capability_digest: reservation.vault_ingest_capability_digest,
    artifact_handle: reservation.artifact_handle,
    source_descriptor_identity_digest: rawReceipt.source_descriptor_identity_digest,
    sink_descriptor_identity_digest: rawReceipt.sink_descriptor_identity_digest,
    sink_record_digest: rawReceipt.sink_record_digest,
  };
  for (const [field, value] of Object.entries(expected)) {
    if (receipt[field] !== value) throw new Error(`${label}.${field} drifted`);
  }
  const projection = projectionWithoutField(
    receipt,
    RAW_CUSTODY_CLEANUP_RECEIPT_FIELDS,
    "cleanup_receipt_digest",
  );
  if (receipt.cleanup_receipt_digest !== digestRecord(
    RAW_CUSTODY_CLEANUP_RECEIPT_DIGEST_DOMAIN,
    projection,
  )) {
    throw new Error(`${label}.cleanup_receipt_digest is invalid`);
  }
  return objectFreeze({ ...projection, cleanup_receipt_digest: receipt.cleanup_receipt_digest });
}





function normalizeRawCustodyJournalPayload(input, owner, expectedLineageDigest) {
  const label = "provider_response_raw_custody_state";
  const descriptors = assertExactDataObject(input, RAW_CUSTODY_JOURNAL_FIELDS, label);
  const value = {};
  for (const field of RAW_CUSTODY_JOURNAL_FIELDS) {
    value[field] = descriptorValue(descriptors, field);
  }
  assertVersion(value.version, label);
  if (value.kind !== "provider_response_raw_custody_state"
      || ![
        "prepared",
        "raw_custody_committed",
        "semantic_observation_committed",
      ].includes(value.state)
      || value.vault_id !== owner.vault_id
      || value.vault_slot !== owner.vault_slot
      || value.session_nucleus_hash !== owner.session_nucleus_hash) {
    throw new Error("provider response raw custody state identity is invalid");
  }
  assertDigest(value.execution_lineage_digest, `${label}.execution_lineage_digest`);
  if (value.execution_lineage_digest !== expectedLineageDigest) {
    throw new Error("provider response raw custody state path binding is invalid");
  }
  const lineage = normalizeTransportLineage(value.lineage);
  const metadata = normalizeMetadata(value.metadata);
  const metadataDigest = assertDigest(value.metadata_digest, `${label}.metadata_digest`);
  if (lineage.execution_lineage_digest !== value.execution_lineage_digest
      || lineage.session_nucleus_hash !== owner.session_nucleus_hash
      || metadataDigest !== sha256(canonicalJson(metadata))) {
    throw new Error("provider response raw custody lineage or metadata identity is invalid");
  }
  const reservation = normalizeReservationState(value.reservation, owner, metadataDigest);
  if (lineage.task_id !== reservation.task_id
      || lineage.attempt_id !== reservation.attempt_id
      || lineage.vault_reservation_handle !== reservation.reservation_handle
      || lineage.vault_reservation_digest !== reservation.vault_reservation_digest
      || lineage.vault_ingest_capability_digest !== reservation.vault_ingest_capability_digest
      || lineage.vault_byte_ceiling !== reservation.byte_ceiling
      || metadata.session_nucleus_hash !== owner.session_nucleus_hash
      || metadata.task_id !== reservation.task_id
      || metadata.attempt_id !== reservation.attempt_id) {
    throw new Error("provider response raw custody reservation binding is invalid");
  }
  assertDigest(value.execution_claim_receipt_digest,
    `${label}.execution_claim_receipt_digest`);
  assertDigest(value.deadline_fence_receipt_digest,
    `${label}.deadline_fence_receipt_digest`);
  assertOpaqueRef(value.custody_ref, `${label}.custody_ref`);
  const observation = normalizeRawCustodyObservation(value.transport_observation);
  const observationDigest = assertDigest(
    value.transport_observation_digest,
    `${label}.transport_observation_digest`,
  );
  if (observationDigest !== digestRecord(RAW_CUSTODY_OBSERVATION_DIGEST_DOMAIN, observation)) {
    throw new Error("provider response raw custody observation digest is invalid");
  }
  assertDigest(value.response_digest, `${label}.response_digest`);
  assertNonnegativeInteger(value.response_byte_length, `${label}.response_byte_length`);
  if (value.response_byte_length > lineage.maximum_response_bytes
      || value.response_byte_length > reservation.byte_ceiling
      || typeof value.content_token !== "string" || !BASE64URL_256_RE.test(value.content_token)) {
    throw new Error("provider response raw custody state violates its byte binding");
  }
  assertCanonicalTimestamp(value.prepared_at, `${label}.prepared_at`);
  let receipt = null;
  let cleanupReceipt = null;
  let semanticReceipt = null;
  if (value.state === "prepared") {
    if (value.vault_committed_at !== null || value.raw_custody_receipt !== null
        || value.plaintext_cleanup_receipt !== null
        || value.semantic_observation_receipt !== null) {
      throw new Error("prepared provider response raw custody state has terminal fields");
    }
  } else {
    assertCanonicalTimestamp(value.vault_committed_at, `${label}.vault_committed_at`);
    receipt = normalizeRawCustodyReceipt(
      value.raw_custody_receipt,
      lineage,
      observation,
    );
    const expectedCommitDigest = digestRecord(RAW_CUSTODY_VAULT_COMMIT_DIGEST_DOMAIN, {
      version: PROVIDER_RESPONSE_VAULT_VERSION,
      execution_lineage_digest: lineage.execution_lineage_digest,
      custody_ref: value.custody_ref,
      vault_reservation_handle: reservation.reservation_handle,
      vault_reservation_digest: reservation.vault_reservation_digest,
      vault_ingest_capability_digest: reservation.vault_ingest_capability_digest,
      artifact_handle: reservation.artifact_handle,
      execution_claim_receipt_digest: value.execution_claim_receipt_digest,
      deadline_fence_receipt_digest: value.deadline_fence_receipt_digest,
      transport_observation_digest: observationDigest,
      response_digest: value.response_digest,
      response_byte_length: value.response_byte_length,
      metadata_digest: metadataDigest,
      content_token: value.content_token,
      committed_at: value.vault_committed_at,
    });
    if (receipt.custody_ref !== value.custody_ref
        || receipt.execution_claim_receipt_digest !== value.execution_claim_receipt_digest
        || receipt.deadline_fence_receipt_digest !== value.deadline_fence_receipt_digest
        || receipt.artifact_handle !== reservation.artifact_handle
        || receipt.response_digest !== value.response_digest
        || receipt.response_byte_length !== value.response_byte_length
        || receipt.transport_observation_digest !== observationDigest
        || receipt.vault_commit_receipt_digest !== expectedCommitDigest) {
      throw new Error("provider response raw custody receipt drifted from durable state");
    }
    if (value.plaintext_cleanup_receipt !== null) {
      cleanupReceipt = normalizeRawCustodyCleanupReceipt(
        value.plaintext_cleanup_receipt,
        lineage,
        reservation,
        receipt,
      );
    }
    if (value.state === "raw_custody_committed") {
      if (value.semantic_observation_receipt !== null) {
        throw new Error("raw-custody committed state cannot carry a semantic receipt");
      }
    } else {
      if (!cleanupReceipt || value.semantic_observation_receipt === null) {
        throw new Error("semantic observation state lacks confirmed plaintext cleanup or receipt");
      }
      const semanticKind = value.semantic_observation_receipt
        && value.semantic_observation_receipt.kind;
      const normalizeSemanticReceipt = SEMANTIC_RECEIPT_NORMALIZERS.get(semanticKind);
      if (typeof normalizeSemanticReceipt !== "function") {
        throw new Error(
          "semantic observation receipt kind has no registered provider normalizer",
        );
      }
      semanticReceipt = normalizeSemanticReceipt(
        value.semantic_observation_receipt,
        lineage,
        reservation,
        receipt,
        cleanupReceipt,
        observation,
      );
    }
  }
  return objectFreeze({
    ...value,
    lineage,
    reservation,
    metadata,
    transport_observation: observation,
    raw_custody_receipt: receipt,
    plaintext_cleanup_receipt: cleanupReceipt,
    semantic_observation_receipt: semanticReceipt,
  });
}

function readRawCustodyStateFile(owner, executionLineageDigest, options = {}) {
  const payload = readStatePayload(owner, executionLineageDigest, options);
  if (payload != null && payload.kind !== "provider_response_raw_custody_state") {
    throw new Error("provider response journal is fenced to semantic result mode");
  }
  return payload == null
    ? null
    : normalizeRawCustodyJournalPayload(payload, owner, executionLineageDigest);
}

function assertSinkLineage(sinkState, lineage) {
  const { owner, reservation, metadata } = sinkState;
  if (lineage.session_nucleus_hash !== owner.session_nucleus_hash
      || lineage.task_id !== reservation.task_id
      || lineage.attempt_id !== reservation.attempt_id
      || lineage.vault_reservation_handle !== reservation.reservation_handle
      || lineage.vault_reservation_digest !== reservation.vault_reservation_digest
      || lineage.vault_ingest_capability_digest !== reservation.vault_ingest_capability_digest
      || lineage.vault_byte_ceiling !== reservation.byte_ceiling
      || metadata.session_nucleus_hash !== lineage.session_nucleus_hash
      || metadata.task_id !== lineage.task_id
      || metadata.attempt_id !== lineage.attempt_id) {
    throw new Error("provider response sink lineage does not match its reservation capability");
  }
}

function assertSinkCommitBinding(state, request, responseDigest, contentToken) {
  if (canonicalJson(state.lineage) !== canonicalJson(request.lineage)
      || state.execution_claim_receipt_digest !== request.execution_claim_receipt_digest
      || state.deadline_fence_receipt_digest !== request.deadline_fence_receipt_digest
      || state.transaction_ref !== request.transaction_ref
      || state.result_code !== request.result_code
      || state.device_state_digest !== request.device_state_digest
      || state.response_digest !== responseDigest
      || state.response_byte_length !== request.response_bytes.length
      || !constantTimeEqual(state.content_token, contentToken)) {
    throw new Error("execution lineage was reused with a different provider response binding");
  }
}

function createPreparedState(sinkState, request, responseDigest, contentToken, preparedAt) {
  return objectFreeze({
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "provider_response_vault_receipt_state",
    state: "prepared",
    vault_id: sinkState.owner.vault_id,
    vault_slot: sinkState.owner.vault_slot,
    session_nucleus_hash: sinkState.owner.session_nucleus_hash,
    execution_lineage_digest: request.lineage.execution_lineage_digest,
    lineage: request.lineage,
    reservation: sinkState.reservation,
    metadata: sinkState.metadata,
    metadata_digest: sinkState.metadata_digest,
    execution_claim_receipt_digest: request.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: request.deadline_fence_receipt_digest,
    transaction_ref: request.transaction_ref,
    result_code: request.result_code,
    device_state_digest: request.device_state_digest,
    response_digest: responseDigest,
    response_byte_length: request.response_bytes.length,
    content_token: contentToken,
    prepared_at: preparedAt,
    vault_committed_at: null,
    transport_result: null,
    ingest_receipt: null,
  });
}

function createTransportResult(state, committedReservation) {
  const lineage = state.lineage;
  const vaultCommitReceiptDigest = digestRecord(VAULT_COMMIT_DIGEST_DOMAIN, {
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    execution_lineage_digest: lineage.execution_lineage_digest,
    vault_reservation_handle: state.reservation.reservation_handle,
    vault_reservation_digest: state.reservation.vault_reservation_digest,
    vault_ingest_capability_digest: state.reservation.vault_ingest_capability_digest,
    artifact_handle: committedReservation.artifact_handle,
    response_digest: state.response_digest,
    response_byte_length: state.response_byte_length,
    metadata_digest: state.metadata_digest,
    content_token: state.content_token,
    committed_at: committedReservation.created_at,
  });
  const rawResponseCustodyDigest = digestRecord(RAW_CUSTODY_DIGEST_DOMAIN, {
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    execution_lineage_digest: lineage.execution_lineage_digest,
    transaction_ref: state.transaction_ref,
    execution_claim_receipt_digest: state.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: state.deadline_fence_receipt_digest,
    artifact_handle: committedReservation.artifact_handle,
    response_digest: state.response_digest,
    response_byte_length: state.response_byte_length,
    vault_commit_receipt_digest: vaultCommitReceiptDigest,
  });
  const projection = {
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "transport_reserved_vault_result",
    execution_lineage_digest: lineage.execution_lineage_digest,
    transaction_ref: state.transaction_ref,
    provider_id: lineage.provider_id,
    operation_id: lineage.operation_id,
    compiler_id: lineage.compiler_id,
    compiler_manifest_digest: lineage.compiler_manifest_digest,
    compiler_registry_digest: lineage.compiler_registry_digest,
    compiled_operation_digest: lineage.compiled_operation_digest,
    provider_command_ref: lineage.provider_command_ref,
    requested_effects_digest: lineage.requested_effects_digest,
    runtime_availability: lineage.runtime_availability,
    compiled_command_id: lineage.compiled_command_id,
    compiled_command_capability_digest: lineage.compiled_command_capability_digest,
    active_command_input_ref: lineage.active_command_input_ref,
    active_command_input_digest: lineage.active_command_input_digest,
    worker_launch_digest: lineage.worker_launch_digest,
    worker_fence_digest: lineage.worker_fence_digest,
    resource_fence_digest: lineage.resource_fence_digest,
    transport_binding_digest: lineage.transport_binding_digest,
    vault_reservation_handle: lineage.vault_reservation_handle,
    vault_reservation_digest: lineage.vault_reservation_digest,
    vault_ingest_capability_digest: lineage.vault_ingest_capability_digest,
    execution_claim_receipt_digest: state.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: state.deadline_fence_receipt_digest,
    artifact_handle: committedReservation.artifact_handle,
    response_digest: state.response_digest,
    response_byte_length: state.response_byte_length,
    result_code: state.result_code,
    device_state_digest: state.device_state_digest,
    vault_commit_receipt_digest: vaultCommitReceiptDigest,
    raw_response_custody_digest: rawResponseCustodyDigest,
  };
  return objectFreeze({
    ...projection,
    transaction_receipt_digest: digestRecord(TRANSACTION_DIGEST_DOMAIN, projection),
  });
}

function reconcilePreparedStateLocked(owner, state) {
  assertReservationJournalFenceMatches(
    owner,
    state.reservation,
    state.lineage,
    "semantic_result",
  );
  if (state.state !== "prepared") return state;
  const committed = owner.read_reservation(state.reservation.reservation_handle);
  if (!committed || committed.state !== "committed") return state;
  if (committed.reservation_ref !== state.reservation.reservation_ref
      || committed.reservation_binding_digest !== state.reservation.reservation_binding_digest
      || committed.byte_ceiling !== state.reservation.byte_ceiling
      || committed.task_id !== state.reservation.task_id
      || committed.attempt_id !== state.reservation.attempt_id
      || committed.artifact_handle !== state.reservation.artifact_handle
      || canonicalJson(committed.metadata) !== canonicalJson(state.metadata)
      || committed.byte_length !== state.response_byte_length
      || !constantTimeEqual(committed.integrity_token, state.content_token)) {
    throw new Error("committed vault artifact drifted from its prepared provider response binding");
  }
  const transportResult = createTransportResult(state, committed);
  const next = objectFreeze({
    ...state,
    state: "sink_committed",
    vault_committed_at: committed.created_at,
    transport_result: transportResult,
    ingest_receipt: null,
  });
  writeStateFile(owner, next);
  return next;
}

function assertRawCustodyCommitBinding(state, request, responseDigest, contentToken) {
  if (canonicalJson(state.lineage) !== canonicalJson(request.lineage)
      || state.execution_claim_receipt_digest !== request.execution_claim_receipt_digest
      || state.deadline_fence_receipt_digest !== request.deadline_fence_receipt_digest
      || state.custody_ref !== request.custody_ref
      || canonicalJson(state.transport_observation)
        !== canonicalJson(request.transport_observation)
      || state.transport_observation_digest !== request.transport_observation_digest
      || state.response_digest !== responseDigest
      || state.response_byte_length !== request.response_bytes.length
      || !constantTimeEqual(state.content_token, contentToken)) {
    throw new Error("execution lineage was reused with a different raw custody binding");
  }
}

function createRawCustodyPreparedState(sinkState, request, responseDigest,
  contentToken, preparedAt) {
  return objectFreeze({
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "provider_response_raw_custody_state",
    state: "prepared",
    vault_id: sinkState.owner.vault_id,
    vault_slot: sinkState.owner.vault_slot,
    session_nucleus_hash: sinkState.owner.session_nucleus_hash,
    execution_lineage_digest: request.lineage.execution_lineage_digest,
    lineage: request.lineage,
    reservation: sinkState.reservation,
    metadata: sinkState.metadata,
    metadata_digest: sinkState.metadata_digest,
    execution_claim_receipt_digest: request.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: request.deadline_fence_receipt_digest,
    custody_ref: request.custody_ref,
    transport_observation: request.transport_observation,
    transport_observation_digest: request.transport_observation_digest,
    response_digest: responseDigest,
    response_byte_length: request.response_bytes.length,
    content_token: contentToken,
    prepared_at: preparedAt,
    vault_committed_at: null,
    raw_custody_receipt: null,
    plaintext_cleanup_receipt: null,
    semantic_observation_receipt: null,
  });
}

function createRawCustodyReceipt(state, committedReservation) {
  const lineage = state.lineage;
  const observation = state.transport_observation;
  const vaultCommitReceiptDigest = digestRecord(RAW_CUSTODY_VAULT_COMMIT_DIGEST_DOMAIN, {
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    execution_lineage_digest: lineage.execution_lineage_digest,
    custody_ref: state.custody_ref,
    vault_reservation_handle: state.reservation.reservation_handle,
    vault_reservation_digest: state.reservation.vault_reservation_digest,
    vault_ingest_capability_digest: state.reservation.vault_ingest_capability_digest,
    artifact_handle: committedReservation.artifact_handle,
    execution_claim_receipt_digest: state.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: state.deadline_fence_receipt_digest,
    transport_observation_digest: state.transport_observation_digest,
    response_digest: state.response_digest,
    response_byte_length: state.response_byte_length,
    metadata_digest: state.metadata_digest,
    content_token: state.content_token,
    committed_at: committedReservation.created_at,
  });
  const projection = {
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "provider_response_raw_custody_receipt",
    execution_lineage_digest: lineage.execution_lineage_digest,
    custody_ref: state.custody_ref,
    provider_id: lineage.provider_id,
    operation_id: lineage.operation_id,
    compiler_id: lineage.compiler_id,
    compiler_manifest_digest: lineage.compiler_manifest_digest,
    compiler_registry_digest: lineage.compiler_registry_digest,
    compiled_operation_digest: lineage.compiled_operation_digest,
    provider_command_ref: lineage.provider_command_ref,
    requested_effects_digest: lineage.requested_effects_digest,
    runtime_availability: lineage.runtime_availability,
    compiled_command_id: lineage.compiled_command_id,
    compiled_command_capability_digest: lineage.compiled_command_capability_digest,
    active_command_input_ref: lineage.active_command_input_ref,
    active_command_input_digest: lineage.active_command_input_digest,
    worker_launch_digest: lineage.worker_launch_digest,
    worker_fence_digest: lineage.worker_fence_digest,
    resource_fence_digest: lineage.resource_fence_digest,
    transport_binding_digest: lineage.transport_binding_digest,
    vault_reservation_handle: lineage.vault_reservation_handle,
    vault_reservation_digest: lineage.vault_reservation_digest,
    vault_ingest_capability_digest: lineage.vault_ingest_capability_digest,
    execution_claim_receipt_digest: state.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: state.deadline_fence_receipt_digest,
    artifact_handle: committedReservation.artifact_handle,
    response_digest: state.response_digest,
    response_byte_length: state.response_byte_length,
    transport_settlement_kind: observation.transport_settlement_kind,
    dispatch_envelope_digest: observation.dispatch_envelope_digest,
    source_descriptor_identity_digest: observation.source_descriptor_identity_digest,
    sink_descriptor_identity_digest: observation.sink_descriptor_identity_digest,
    sink_record_digest: observation.sink_record_digest,
    ticket_sequence: observation.ticket_sequence,
    settled_monotonic_ns: observation.settled_monotonic_ns,
    transport_observation_digest: state.transport_observation_digest,
    vault_commit_receipt_digest: vaultCommitReceiptDigest,
    semantic_validation_performed: false,
    production_ready: false,
    hardware_access_authorized: false,
    authoritative: false,
  };
  return objectFreeze({
    ...projection,
    raw_custody_receipt_digest: digestRecord(
      RAW_CUSTODY_RECEIPT_DIGEST_DOMAIN,
      projection,
    ),
  });
}

function reconcileRawCustodyPreparedStateLocked(owner, state) {
  assertReservationJournalFenceMatches(
    owner,
    state.reservation,
    state.lineage,
    "raw_custody",
  );
  if (state.state !== "prepared") return state;
  const committed = owner.read_reservation(state.reservation.reservation_handle);
  if (!committed || committed.state !== "committed") return state;
  if (committed.reservation_ref !== state.reservation.reservation_ref
      || committed.reservation_binding_digest !== state.reservation.reservation_binding_digest
      || committed.byte_ceiling !== state.reservation.byte_ceiling
      || committed.task_id !== state.reservation.task_id
      || committed.attempt_id !== state.reservation.attempt_id
      || committed.artifact_handle !== state.reservation.artifact_handle
      || canonicalJson(committed.metadata) !== canonicalJson(state.metadata)
      || committed.byte_length !== state.response_byte_length
      || !constantTimeEqual(committed.integrity_token, state.content_token)) {
    throw new Error("committed vault artifact drifted from its prepared raw custody binding");
  }
  const receipt = createRawCustodyReceipt(state, committed);
  const next = objectFreeze({
    ...state,
    state: "raw_custody_committed",
    vault_committed_at: committed.created_at,
    raw_custody_receipt: receipt,
  });
  writeStateFile(owner, next);
  return next;
}

function brandSinkCommit(value) {
  const output = objectFreeze({ ...value });
  SINK_COMMITS.add(output);
  return output;
}

function brandIngestReceipt(value) {
  const output = objectFreeze({ ...value });
  INGEST_RECEIPTS.add(output);
  return output;
}

function brandRawCustodyReceipt(value) {
  const output = objectFreeze({ ...value });
  RAW_CUSTODY_RECEIPTS.add(output);
  return output;
}


function assertProviderResponseSink(value) {
  if (!SINKS.has(value)) throw new Error("provider response sink is not privately branded");
  return value;
}

function assertProviderResponseSinkCommit(value) {
  if (!SINK_COMMITS.has(value)) {
    throw new Error("provider response sink commit is not privately branded");
  }
  return value;
}

function assertProviderResponseIngestReceiptPort(value) {
  if (!RECEIPT_PORTS.has(value)) {
    throw new Error("provider response ingest receipt port is not privately branded");
  }
  return value;
}

function assertProviderResponseIngestReceipt(value) {
  if (!INGEST_RECEIPTS.has(value)) {
    throw new Error("provider response ingest receipt is not privately branded");
  }
  return value;
}

function assertProviderResponseRawCustodyReceipt(value) {
  if (!RAW_CUSTODY_RECEIPTS.has(value)) {
    throw new Error("provider response raw custody receipt is not privately branded");
  }
  return value;
}

function assertProviderResponseRawCustodyReceiptPort(value) {
  if (!RAW_CUSTODY_RECEIPT_PORTS.has(value)) {
    throw new Error("provider response raw custody receipt port is not privately branded");
  }
  return value;
}

function assertProviderResponseSemanticValidationPort(value) {
  if (!PROVIDER_SEMANTIC_VALIDATION_PORTS.has(value)
      || !PROVIDER_SEMANTIC_VALIDATION_PORT_PRIVATE.has(value)) {
    throw new Error("provider response semantic validation port is not privately branded");
  }
  return value;
}


function createProviderResponseSink(vault, input) {
  const owner = getProviderResponseVaultOwner(vault);
  const descriptors = assertExactDataObject(
    input,
    ["version", "reservation_handle", "metadata"],
    "create_provider_response_sink_request",
  );
  assertVersion(descriptorValue(descriptors, "version"), "create_provider_response_sink_request");
  const reservationHandle = descriptorValue(descriptors, "reservation_handle");
  if (typeof reservationHandle !== "string" || !PUBLIC_RESERVATION_HANDLE_RE.test(reservationHandle)) {
    throw new Error("create_provider_response_sink_request.reservation_handle is invalid");
  }
  const metadata = normalizeMetadata(descriptorValue(descriptors, "metadata"));
  const metadataDigest = sha256(canonicalJson(metadata));
  const reservation = owner.with_lock(() => {
    ensureReceiptRoot(owner);
    const current = owner.read_reservation(reservationHandle);
    if (!current) throw new Error("provider response reservation is absent, expired, or terminal");
    if (current.task_id !== metadata.task_id || current.attempt_id !== metadata.attempt_id
        || metadata.session_nucleus_hash !== owner.session_nucleus_hash) {
      throw new Error("provider response metadata does not match its reservation or vault session");
    }
    if (current.byte_ceiling > MAX_RESPONSE_BYTES) {
      throw new Error(`provider response reservation exceeds the ${MAX_RESPONSE_BYTES}-byte protocol ceiling`);
    }
    if (current.state === "committed"
        && canonicalJson(current.metadata) !== canonicalJson(metadata)) {
      throw new Error("committed provider response metadata does not match the requested sink");
    }
    return current;
  });
  const reservationDigest = computeReservationDigest(owner, reservation);
  const capabilityDigest = computeCapabilityDigest(reservationDigest, metadataDigest);
  const projection = reservationProjection(
    owner,
    reservation,
    reservationDigest,
    capabilityDigest,
  );
  const sink = objectFreeze({
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "pre_reserved_provider_response_vault_sink",
    vault_reservation_handle: projection.reservation_handle,
    vault_reservation_digest: projection.vault_reservation_digest,
    vault_ingest_capability_digest: projection.vault_ingest_capability_digest,
    byte_ceiling: projection.byte_ceiling,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
    toJSON() {
      return {
        version: PROVIDER_RESPONSE_VAULT_VERSION,
        kind: "pre_reserved_provider_response_vault_sink",
        vault_reservation_handle: projection.reservation_handle,
        vault_reservation_digest: projection.vault_reservation_digest,
        vault_ingest_capability_digest: projection.vault_ingest_capability_digest,
        byte_ceiling: projection.byte_ceiling,
        production_ready: false,
        hardware_access_authorized: false,
        execution_authority: false,
      };
    },
  });
  SINKS.add(sink);
  SINK_PRIVATE.set(sink, objectFreeze({
    owner,
    reservation: projection,
    metadata,
    metadata_digest: metadataDigest,
  }));
  return sink;
}

function normalizeSinkCommitRequest(input) {
  const fields = [
    "version",
    "kind",
    "lineage",
    "execution_claim_receipt_digest",
    "deadline_fence_receipt_digest",
    "transaction_ref",
    "result_code",
    "device_state_digest",
    "response_bytes",
  ];
  const descriptors = assertExactDataObject(input, fields, "commit_provider_response_sink_request");
  assertVersion(descriptorValue(descriptors, "version"), "commit_provider_response_sink_request");
  if (descriptorValue(descriptors, "kind") !== "commit_provider_response_sink_request") {
    throw new Error("commit_provider_response_sink_request.kind is invalid");
  }
  const responseBytes = descriptorValue(descriptors, "response_bytes");
  if (!bufferIsBuffer(responseBytes)) {
    throw new Error("commit_provider_response_sink_request.response_bytes must be an explicit Buffer");
  }
  return objectFreeze({
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "commit_provider_response_sink_request",
    lineage: normalizeTransportLineage(descriptorValue(descriptors, "lineage")),
    execution_claim_receipt_digest: assertDigest(
      descriptorValue(descriptors, "execution_claim_receipt_digest"),
      "commit_provider_response_sink_request.execution_claim_receipt_digest",
    ),
    deadline_fence_receipt_digest: assertDigest(
      descriptorValue(descriptors, "deadline_fence_receipt_digest"),
      "commit_provider_response_sink_request.deadline_fence_receipt_digest",
    ),
    transaction_ref: assertOpaqueRef(
      descriptorValue(descriptors, "transaction_ref"),
      "commit_provider_response_sink_request.transaction_ref",
    ),
    result_code: assertResultCode(
      descriptorValue(descriptors, "result_code"),
      "commit_provider_response_sink_request.result_code",
    ),
    device_state_digest: assertDigest(
      descriptorValue(descriptors, "device_state_digest"),
      "commit_provider_response_sink_request.device_state_digest",
    ),
    response_bytes: responseBytes,
  });
}

function extractResponseBufferForScrub(input) {
  if (input == null || typeof input !== "object" || utilIsProxy(input)) return null;
  let descriptors;
  try {
    descriptors = objectGetOwnPropertyDescriptors(input);
  } catch {
    return null;
  }
  const descriptor = objectHasOwn(descriptors, "response_bytes")
    ? descriptors.response_bytes : null;
  return descriptor && objectHasOwn(descriptor, "value") && bufferIsBuffer(descriptor.value)
    ? descriptor.value : null;
}

function commitProviderResponseSink(sink, input) {
  assertProviderResponseSink(sink);
  let responseBytes = extractResponseBufferForScrub(input);
  let custodyBytes = null;
  try {
    const request = normalizeSinkCommitRequest(input);
    responseBytes = request.response_bytes;
    const sinkState = SINK_PRIVATE.get(sink);
    sinkState.owner.assert_live();
    assertSinkLineage(sinkState, request.lineage);
    if (request.result_code !== request.lineage.expected_result_code) {
      throw new Error("provider response result code was not precommitted by lineage");
    }
    if (responseBytes.length > request.lineage.maximum_response_bytes
        || responseBytes.length > sinkState.reservation.byte_ceiling) {
      throw new Error("provider response exceeds its pre-stimulus byte ceiling");
    }
    if (Date.parse(sinkState.metadata.retention_expires_at)
        <= Date.parse(sinkState.owner.now_iso())) {
      throw new Error("provider response retention expired before sink commit");
    }
    // Hash, authenticate, and ingest one private snapshot.  A caller may own a
    // SharedArrayBuffer-backed Buffer or retain aliases; using that mutable
    // object across the prepared/commit boundary could otherwise strand a
    // journal intent around bytes different from the recorded digest.
    custodyBytes = Buffer.from(responseBytes);
    const responseDigest = sha256(custodyBytes);
    const contentToken = sinkState.owner.content_token(sinkState.metadata, custodyBytes);
    let state = sinkState.owner.with_lock(() => {
      ensureReceiptRoot(sinkState.owner);
      assertReservationJournalFenceMatches(
        sinkState.owner,
        sinkState.reservation,
        request.lineage,
        "semantic_result",
        { create: true },
      );
      const existing = readStateFile(
        sinkState.owner,
        request.lineage.execution_lineage_digest,
        { required: false },
      );
      if (existing) {
        assertSinkCommitBinding(existing, request, responseDigest, contentToken);
        return reconcilePreparedStateLocked(sinkState.owner, existing);
      }
      const currentReservation = sinkState.owner.read_reservation(
        sinkState.reservation.reservation_handle,
      );
      if (!currentReservation || currentReservation.state !== "active") {
        throw new Error("a committed artifact without a prepared provider sink cannot mint a receipt");
      }
      if (cleanAndCountStateFiles(sinkState.owner) >= sinkState.owner.max_receipts) {
        throw new Error("provider response durable receipt count ceiling is exhausted");
      }
      const prepared = createPreparedState(
        sinkState,
        request,
        responseDigest,
        contentToken,
        sinkState.owner.now_iso(),
      );
      writeStateFile(sinkState.owner, prepared);
      return prepared;
    });
    if (state.state === "prepared") {
      try {
        sinkState.owner.ingest(
          sinkState.reservation.reservation_handle,
          sinkState.metadata,
          custodyBytes,
        );
      } catch (ingestError) {
        try {
          state = sinkState.owner.with_lock(() => {
            const current = readStateFile(
              sinkState.owner,
              request.lineage.execution_lineage_digest,
            );
            return reconcilePreparedStateLocked(sinkState.owner, current);
          });
        } catch {}
        if (state.state === "prepared") throw ingestError;
      }
    }
    if (state.state === "prepared") {
      state = sinkState.owner.with_lock(() => {
        const current = readStateFile(
          sinkState.owner,
          request.lineage.execution_lineage_digest,
        );
        return reconcilePreparedStateLocked(sinkState.owner, current);
      });
    }
    if (state.state === "prepared" || !state.transport_result) {
      throw new Error("provider response vault commit is not durably readable");
    }
    return brandSinkCommit(state.transport_result);
  } finally {
    if (custodyBytes) custodyBytes.fill(0);
    if (responseBytes) responseBytes.fill(0);
  }
}

function normalizeRawCustodyCommitRequest(input) {
  const label = "commit_provider_response_raw_custody_request";
  const fields = [
    "version",
    "kind",
    "lineage",
    "execution_claim_receipt_digest",
    "deadline_fence_receipt_digest",
    "custody_ref",
    "transport_observation",
    "response_bytes",
  ];
  const descriptors = assertExactDataObject(input, fields, label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  if (descriptorValue(descriptors, "kind") !== label) {
    throw new Error(`${label}.kind is invalid`);
  }
  const responseBytes = descriptorValue(descriptors, "response_bytes");
  if (!bufferIsBuffer(responseBytes)) {
    throw new Error(`${label}.response_bytes must be an explicit Buffer`);
  }
  const transportObservation = normalizeRawCustodyObservation(
    descriptorValue(descriptors, "transport_observation"),
    `${label}.transport_observation`,
  );
  return objectFreeze({
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: label,
    lineage: normalizeTransportLineage(descriptorValue(descriptors, "lineage")),
    execution_claim_receipt_digest: assertDigest(
      descriptorValue(descriptors, "execution_claim_receipt_digest"),
      `${label}.execution_claim_receipt_digest`,
    ),
    deadline_fence_receipt_digest: assertDigest(
      descriptorValue(descriptors, "deadline_fence_receipt_digest"),
      `${label}.deadline_fence_receipt_digest`,
    ),
    custody_ref: assertOpaqueRef(
      descriptorValue(descriptors, "custody_ref"),
      `${label}.custody_ref`,
    ),
    transport_observation: transportObservation,
    transport_observation_digest: digestRecord(
      RAW_CUSTODY_OBSERVATION_DIGEST_DOMAIN,
      transportObservation,
    ),
    response_bytes: responseBytes,
  });
}

function commitProviderResponseRawCustody(sink, input) {
  assertProviderResponseSink(sink);
  let responseBytes = extractResponseBufferForScrub(input);
  let custodyBytes = null;
  try {
    const request = normalizeRawCustodyCommitRequest(input);
    responseBytes = request.response_bytes;
    const sinkState = SINK_PRIVATE.get(sink);
    sinkState.owner.assert_live();
    assertSinkLineage(sinkState, request.lineage);
    if (responseBytes.length > request.lineage.maximum_response_bytes
        || responseBytes.length > sinkState.reservation.byte_ceiling) {
      throw new Error("raw provider response exceeds its pre-stimulus byte ceiling");
    }
    if (Date.parse(sinkState.metadata.retention_expires_at)
        <= Date.parse(sinkState.owner.now_iso())) {
      throw new Error("provider response retention expired before raw custody commit");
    }
    custodyBytes = Buffer.from(responseBytes);
    const responseDigest = sha256(custodyBytes);
    const contentToken = sinkState.owner.content_token(sinkState.metadata, custodyBytes);
    let state = sinkState.owner.with_lock(() => {
      ensureReceiptRoot(sinkState.owner);
      assertReservationJournalFenceMatches(
        sinkState.owner,
        sinkState.reservation,
        request.lineage,
        "raw_custody",
        { create: true },
      );
      const existing = readRawCustodyStateFile(
        sinkState.owner,
        request.lineage.execution_lineage_digest,
        { required: false },
      );
      if (existing) {
        assertRawCustodyCommitBinding(existing, request, responseDigest, contentToken);
        return reconcileRawCustodyPreparedStateLocked(sinkState.owner, existing);
      }
      const currentReservation = sinkState.owner.read_reservation(
        sinkState.reservation.reservation_handle,
      );
      if (!currentReservation || currentReservation.state !== "active") {
        throw new Error("a committed artifact without a prepared raw custody intent cannot mint a receipt");
      }
      if (cleanAndCountStateFiles(sinkState.owner) >= sinkState.owner.max_receipts) {
        throw new Error("provider response durable receipt count ceiling is exhausted");
      }
      const prepared = createRawCustodyPreparedState(
        sinkState,
        request,
        responseDigest,
        contentToken,
        sinkState.owner.now_iso(),
      );
      writeStateFile(sinkState.owner, prepared);
      return prepared;
    });
    if (state.state === "prepared") {
      try {
        sinkState.owner.ingest(
          sinkState.reservation.reservation_handle,
          sinkState.metadata,
          custodyBytes,
        );
      } catch (ingestError) {
        try {
          state = sinkState.owner.with_lock(() => {
            const current = readRawCustodyStateFile(
              sinkState.owner,
              request.lineage.execution_lineage_digest,
            );
            return reconcileRawCustodyPreparedStateLocked(sinkState.owner, current);
          });
        } catch {}
        if (state.state === "prepared") throw ingestError;
      }
    }
    if (state.state === "prepared") {
      state = sinkState.owner.with_lock(() => {
        const current = readRawCustodyStateFile(
          sinkState.owner,
          request.lineage.execution_lineage_digest,
        );
        return reconcileRawCustodyPreparedStateLocked(sinkState.owner, current);
      });
    }
    if (!["raw_custody_committed", "semantic_observation_committed"].includes(state.state)
        || !state.raw_custody_receipt) {
      throw new Error("provider response raw custody commit is not durably readable");
    }
    return brandRawCustodyReceipt(state.raw_custody_receipt);
  } finally {
    if (custodyBytes) custodyBytes.fill(0);
    if (responseBytes) responseBytes.fill(0);
  }
}

function createProviderResponseIngestReceiptPort(vault) {
  const owner = getProviderResponseVaultOwner(vault);
  owner.with_lock(() => ensureReceiptRoot(owner));
  const port = objectFreeze({
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "provider_response_vault_ingest_receipt_port",
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
    byte_input_accepted: false,
    toJSON() {
      return {
        version: PROVIDER_RESPONSE_VAULT_VERSION,
        kind: "provider_response_vault_ingest_receipt_port",
        production_ready: false,
        hardware_access_authorized: false,
        execution_authority: false,
        byte_input_accepted: false,
      };
    },
  });
  RECEIPT_PORTS.add(port);
  RECEIPT_PORT_PRIVATE.set(port, objectFreeze({ owner }));
  return port;
}

function createProviderResponseRawCustodyReceiptPort(vault) {
  const owner = getProviderResponseVaultOwner(vault);
  owner.with_lock(() => ensureReceiptRoot(owner));
  const port = objectFreeze({
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "provider_response_raw_custody_receipt_port",
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
    byte_input_accepted: false,
    semantic_validation_authority: false,
    toJSON() {
      return {
        version: PROVIDER_RESPONSE_VAULT_VERSION,
        kind: "provider_response_raw_custody_receipt_port",
        production_ready: false,
        hardware_access_authorized: false,
        execution_authority: false,
        byte_input_accepted: false,
        semantic_validation_authority: false,
      };
    },
  });
  RAW_CUSTODY_RECEIPT_PORTS.add(port);
  RAW_CUSTODY_RECEIPT_PORT_PRIVATE.set(port, objectFreeze({ owner }));
  return port;
}



function rawCustodyCleanupReceiptForState(state, cleanupReconciledAt) {
  const raw = state.raw_custody_receipt;
  const projection = {
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "provider_response_raw_custody_cleanup_receipt",
    execution_lineage_digest: state.execution_lineage_digest,
    raw_custody_receipt_digest: raw.raw_custody_receipt_digest,
    vault_reservation_digest: state.reservation.vault_reservation_digest,
    vault_ingest_capability_digest: state.reservation.vault_ingest_capability_digest,
    artifact_handle: state.reservation.artifact_handle,
    source_descriptor_identity_digest: raw.source_descriptor_identity_digest,
    sink_descriptor_identity_digest: raw.sink_descriptor_identity_digest,
    sink_record_digest: raw.sink_record_digest,
    cleanup_reconciled_at: cleanupReconciledAt,
  };
  return objectFreeze({
    ...projection,
    cleanup_receipt_digest: digestRecord(
      RAW_CUSTODY_CLEANUP_RECEIPT_DIGEST_DOMAIN,
      projection,
    ),
  });
}

function confirmProviderResponseRawCustodyPlaintextCleanup(vault, receiptInput) {
  if (arguments.length !== 2) {
    throw new Error("raw custody plaintext cleanup confirmation accepts a vault and receipt");
  }
  const rawReceipt = assertProviderResponseRawCustodyReceipt(receiptInput);
  if (!["native-settlement:fixture_complete_non_authorizing",
    "native-settlement:ambiguous_quarantined"].includes(
    rawReceipt.transport_settlement_kind,
  )) {
    throw new Error("raw custody plaintext cleanup can be confirmed only for committed native custody");
  }
  const owner = getProviderResponseVaultOwner(vault);
  return owner.with_lock(() => {
    let state = readRawCustodyStateFile(owner, rawReceipt.execution_lineage_digest);
    state = reconcileRawCustodyPreparedStateLocked(owner, state);
    if (!["raw_custody_committed", "semantic_observation_committed"].includes(state.state)
        || !state.raw_custody_receipt
        || canonicalJson(state.raw_custody_receipt) !== canonicalJson(rawReceipt)) {
      throw new Error("raw custody plaintext cleanup receipt is detached from durable custody");
    }
    assertReservationJournalFenceMatches(
      owner,
      state.reservation,
      state.lineage,
      "raw_custody",
    );
    if (state.plaintext_cleanup_receipt) return true;
    const cleanupReceipt = rawCustodyCleanupReceiptForState(state, owner.now_iso());
    normalizeRawCustodyCleanupReceipt(
      cleanupReceipt,
      state.lineage,
      state.reservation,
      state.raw_custody_receipt,
    );
    const next = objectFreeze({
      ...state,
      plaintext_cleanup_receipt: cleanupReceipt,
    });
    writeStateFile(owner, next);
    const observed = readRawCustodyStateFile(owner, state.execution_lineage_digest);
    if (!observed.plaintext_cleanup_receipt
        || observed.plaintext_cleanup_receipt.cleanup_receipt_digest
          !== cleanupReceipt.cleanup_receipt_digest) {
      throw new Error("raw custody plaintext cleanup confirmation is not durably readable");
    }
    return true;
  });
}







function normalizeReceiptCommitRequest(input) {
  const fields = [
    "version",
    "kind",
    "lineage",
    "execution_claim_receipt_digest",
    "deadline_fence_receipt_digest",
    "transaction_result",
  ];
  const descriptors = assertExactDataObject(
    input,
    fields,
    "assert_reserved_vault_ingest_receipt_request",
  );
  assertVersion(
    descriptorValue(descriptors, "version"),
    "assert_reserved_vault_ingest_receipt_request",
  );
  if (descriptorValue(descriptors, "kind") !== "assert_reserved_vault_ingest_receipt_request") {
    throw new Error("assert_reserved_vault_ingest_receipt_request.kind is invalid");
  }
  const lineage = normalizeTransportLineage(descriptorValue(descriptors, "lineage"));
  return objectFreeze({
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "assert_reserved_vault_ingest_receipt_request",
    lineage,
    execution_claim_receipt_digest: assertDigest(
      descriptorValue(descriptors, "execution_claim_receipt_digest"),
      "assert_reserved_vault_ingest_receipt_request.execution_claim_receipt_digest",
    ),
    deadline_fence_receipt_digest: assertDigest(
      descriptorValue(descriptors, "deadline_fence_receipt_digest"),
      "assert_reserved_vault_ingest_receipt_request.deadline_fence_receipt_digest",
    ),
    transaction_result: normalizeTransportResult(
      descriptorValue(descriptors, "transaction_result"),
      lineage,
    ),
  });
}

function createIngestReceipt(state) {
  const transaction = state.transport_result;
  const projection = {
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "reserved_vault_ingest_receipt",
    execution_lineage_digest: state.execution_lineage_digest,
    vault_reservation_handle: state.reservation.reservation_handle,
    vault_reservation_digest: state.reservation.vault_reservation_digest,
    vault_ingest_capability_digest: state.reservation.vault_ingest_capability_digest,
    execution_claim_receipt_digest: state.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: state.deadline_fence_receipt_digest,
    artifact_handle: transaction.artifact_handle,
    response_digest: transaction.response_digest,
    response_byte_length: transaction.response_byte_length,
    transaction_receipt_digest: transaction.transaction_receipt_digest,
    vault_commit_receipt_digest: transaction.vault_commit_receipt_digest,
    raw_response_custody_digest: transaction.raw_response_custody_digest,
  };
  return objectFreeze({
    ...projection,
    ingest_receipt_digest: digestRecord(INGEST_RECEIPT_DIGEST_DOMAIN, projection),
  });
}

function assertReceiptRequestMatchesState(request, state) {
  if (canonicalJson(request.lineage) !== canonicalJson(state.lineage)
      || request.execution_claim_receipt_digest !== state.execution_claim_receipt_digest
      || request.deadline_fence_receipt_digest !== state.deadline_fence_receipt_digest
      || canonicalJson(request.transaction_result) !== canonicalJson(state.transport_result)) {
    throw new Error("reserved vault ingest receipt request drifted from durable sink state");
  }
}

function commitProviderResponseIngestReceipt(port, input) {
  assertProviderResponseIngestReceiptPort(port);
  const request = normalizeReceiptCommitRequest(input);
  const { owner } = RECEIPT_PORT_PRIVATE.get(port);
  owner.assert_live();
  let state = owner.with_lock(() => {
    let current = readStateFile(owner, request.lineage.execution_lineage_digest);
    current = reconcilePreparedStateLocked(owner, current);
    if (current.state === "prepared" || !current.transport_result) {
      throw new Error("provider response sink commit is not durable");
    }
    assertReceiptRequestMatchesState(request, current);
    if (current.state === "receipt_committed") return current;
    const receipt = createIngestReceipt(current);
    const next = objectFreeze({
      ...current,
      state: "receipt_committed",
      ingest_receipt: receipt,
    });
    writeStateFile(owner, next);
    return next;
  });
  if (state.state !== "receipt_committed" || !state.ingest_receipt) {
    throw new Error("provider response ingest receipt is not durably readable");
  }
  return brandIngestReceipt(state.ingest_receipt);
}

function normalizeReadbackRequest(input, expectedKind) {
  const descriptors = assertExactDataObject(
    input,
    ["version", "kind", "execution_lineage_digest"],
    expectedKind,
  );
  assertVersion(descriptorValue(descriptors, "version"), expectedKind);
  if (descriptorValue(descriptors, "kind") !== expectedKind) {
    throw new Error(`${expectedKind}.kind is invalid`);
  }
  return objectFreeze({
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: expectedKind,
    execution_lineage_digest: assertDigest(
      descriptorValue(descriptors, "execution_lineage_digest"),
      `${expectedKind}.execution_lineage_digest`,
    ),
  });
}

function readProviderResponseSinkCommit(port, input) {
  assertProviderResponseIngestReceiptPort(port);
  const request = normalizeReadbackRequest(input, "read_provider_response_sink_commit_request");
  const { owner } = RECEIPT_PORT_PRIVATE.get(port);
  owner.assert_live();
  const state = owner.with_lock(() => {
    const current = readStateFile(owner, request.execution_lineage_digest);
    return reconcilePreparedStateLocked(owner, current);
  });
  if (state.state === "prepared" || !state.transport_result) {
    throw new Error("provider response sink commit is not durable");
  }
  return brandSinkCommit(state.transport_result);
}

function readProviderResponseRawCustodyReceipt(port, input) {
  assertProviderResponseRawCustodyReceiptPort(port);
  const request = normalizeReadbackRequest(
    input,
    "read_provider_response_raw_custody_receipt_request",
  );
  const { owner } = RAW_CUSTODY_RECEIPT_PORT_PRIVATE.get(port);
  owner.assert_live();
  const state = owner.with_lock(() => {
    const current = readRawCustodyStateFile(
      owner,
      request.execution_lineage_digest,
    );
    return reconcileRawCustodyPreparedStateLocked(owner, current);
  });
  if (!["raw_custody_committed", "semantic_observation_committed"].includes(state.state)
      || !state.raw_custody_receipt) {
    throw new Error("provider response raw custody receipt is not durable");
  }
  return brandRawCustodyReceipt(state.raw_custody_receipt);
}


function readProviderResponseIngestReceipt(port, input) {
  assertProviderResponseIngestReceiptPort(port);
  const request = normalizeReadbackRequest(input, "read_provider_response_ingest_receipt_request");
  const { owner } = RECEIPT_PORT_PRIVATE.get(port);
  owner.assert_live();
  const state = owner.with_lock(() => {
    const current = readStateFile(owner, request.execution_lineage_digest);
    assertReservationJournalFenceMatches(
      owner,
      current.reservation,
      current.lineage,
      "semantic_result",
    );
    return current;
  });
  if (state.state !== "receipt_committed" || !state.ingest_receipt) {
    throw new Error("provider response ingest receipt is not durable");
  }
  return brandIngestReceipt(state.ingest_receipt);
}

// Provider-neutral substrate surfaced for out-of-package semantic validators
// (e.g. the Chameleon get_app_version validator, which lives in the provider
// package and plugs in here). It carries data-only primitives — crypto,
// exact-object asserts, durable raw-custody state readers, receipt branding by
// kind, and semantic-validation-PORT registration — never provider identity.
const providerResponseSemanticSubstrate = Object.freeze({
  PROVIDER_RESPONSE_VAULT_VERSION,
  PUBLIC_ARTIFACT_HANDLE_RE,
  sha256,
  canonicalJson,
  digestRecord,
  assertExactDataObject,
  descriptorValue,
  assertVersion,
  assertDigest,
  assertOpaqueRef,
  assertNonnegativeInteger,
  assertUint64,
  assertCanonicalTimestamp,
  projectionWithoutField,
  normalizeTransportLineage,
  normalizeReadbackRequest,
  assertProviderResponseRawCustodyReceipt,
  assertProviderResponseSemanticValidationPort,
  getProviderResponseVaultOwner,
  materializeForWorker,
  ensureReceiptRoot,
  readRawCustodyStateFile,
  writeStateFile,
  reconcileRawCustodyPreparedStateLocked,
  assertReservationJournalFenceMatches,
  registerSemanticValidationPort,
  readSemanticValidationPortPrivate,
  registerSemanticReceiptNormalizer,
});

module.exports = {
  PROVIDER_RESPONSE_VAULT_ASSURANCE,
  PROVIDER_RESPONSE_VAULT_VERSION,
  assertProviderResponseIngestReceipt,
  assertProviderResponseIngestReceiptPort,
  assertProviderResponseRawCustodyReceipt,
  assertProviderResponseRawCustodyReceiptPort,
  assertProviderResponseSemanticValidationPort,
  assertProviderResponseSink,
  assertProviderResponseSinkCommit,
  commitProviderResponseIngestReceipt,
  commitProviderResponseRawCustody,
  commitProviderResponseSink,
  confirmProviderResponseRawCustodyPlaintextCleanup,
  createProviderResponseIngestReceiptPort,
  createProviderResponseRawCustodyReceiptPort,
  createProviderResponseSink,
  providerResponseSemanticSubstrate,
  readProviderResponseIngestReceipt,
  readProviderResponseRawCustodyReceipt,
  readProviderResponseSinkCommit,
};
