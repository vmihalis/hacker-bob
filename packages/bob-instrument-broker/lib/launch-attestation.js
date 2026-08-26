"use strict";

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const {
  canonicalJson,
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");
const {
  publicKeyDigest,
  _internals: {
    assertDigest,
    assertEd25519Key,
    assertIdentifier,
    assertInteger,
    assertToken,
  },
} = require("./ipc-contract.js");

const LAUNCH_ATTESTATION_VERSION = 1;
const LAUNCH_ATTESTATION_DOMAIN =
  "hacker-bob/instrument-broker-launch-attestation/v1";
const LAUNCH_ATTESTATION_SIGNATURE_DOMAIN =
  "hacker-bob/instrument-broker-launch-attestation-signature/v1";
const LAUNCH_ATTESTATION_AUTHORITY_STATE_DOMAIN =
  "hacker-bob/instrument-broker-launch-authority-state/v1";
const LAUNCH_ATTESTATION_PROCESS_INSTANCE_DOMAIN =
  "hacker-bob/instrument-broker-launch-process-instance/v1";
const LAUNCH_ATTESTATION_PROFILE_DOMAIN =
  "hacker-bob/instrument-broker-launch-profile/v1";
const LAUNCH_ATTESTATION_HOST_SNAPSHOT_DOMAIN =
  "hacker-bob/instrument-broker-launch-host-snapshot/v1";
const LAUNCH_ATTESTATION_REPLAY_CLAIM_DOMAIN =
  "hacker-bob/instrument-broker-launch-replay-claim/v1";
const LAUNCH_ATTESTATION_REPLAY_RECEIPT_DOMAIN =
  "hacker-bob/instrument-broker-launch-replay-receipt/v1";
const LAUNCH_ATTESTATION_KEY_USAGE =
  "instrument_broker_process_launch_attestation";
const LAUNCH_ATTESTATION_MAX_LIFETIME_MS = 60_000;
const LAUNCH_ATTESTATION_MAX_CLOCK_SKEW_MS = 5_000;
const LAUNCH_ATTESTATION_MAX_PAYLOAD_BYTES = 24 * 1024;

const LAUNCH_ATTESTATION_ROLES = Object.freeze([
  "issuer_peer",
  "active_device_worker",
  "cleanup_only_worker",
  "safety_supervisor",
]);
const ROLE_SET = new Set(LAUNCH_ATTESTATION_ROLES);
const PROVIDER_ROLES = new Set([
  "issuer_peer",
  "active_device_worker",
  "cleanup_only_worker",
]);
const DEVICE_OWNING_ROLES = new Set([
  "active_device_worker",
  "cleanup_only_worker",
]);
const IPC_PEER_PROCESS_ROLES = new Set([
  "issuer_peer",
  "safety_supervisor",
]);
const ROLE_KEY_USAGE_BY_ROLE = Object.freeze({
  issuer_peer: "physical_grant_signing",
  active_device_worker: "worker_receipt_provenance_signing",
  cleanup_only_worker: "recovery_receipt_signing",
  safety_supervisor: "nondelegable_cleanup_root_signing",
});

const COMMON_PAYLOAD_FIELDS = Object.freeze([
  "version",
  "launch_attestation_id",
  "role",
  "attestation_assurance",
  "production_ready",
  "separate_identity_authorized",
  "hardware_authorized",
  "host_snapshot_scheme",
  "os_platform",
  "os_architecture",
  "os_effective_uid",
  "os_effective_gid",
  "os_real_uid",
  "os_real_gid",
  "process_id",
  "process_credential_scheme",
  "process_credential_digest",
  "process_start_token_digest",
  "runtime_implementation",
  "runtime_abi",
  "runtime_implementation_digest",
  "native_inspector_measurement_scheme",
  "native_inspector_implementation_digest",
  "native_inspector_measurement_digest",
  "native_inspector_measurement_complete",
  "code_signing_identity_scheme",
  "code_signing_identity_digest",
  "code_signing_identity_complete",
  "mapped_code_identity_scheme",
  "mapped_code_identity_digest",
  "mapped_code_identity_complete",
  "mapped_code_identity_audit_token_bound",
  "mapped_code_identity_stable",
  "cdhash_algorithm",
  "cdhash_set_digest",
  "cdhash_complete",
  "dynamic_code_validity_scheme",
  "dynamic_code_validity_state",
  "dynamic_code_validity_digest",
  "dynamic_code_validity_complete",
  "bundle_immutability_scheme",
  "bundle_immutability_evidence_digest",
  "bundle_immutability_complete",
  "bundle_manifest_digest",
  "entrypoint_digest",
  "config_manifest_digest",
  "process_principal_id",
  "ipc_peer_principal_id",
  "execution_principal_id",
  "ipc_profile_request_key_id",
  "ipc_profile_request_public_key_digest",
  "ipc_profile_response_key_id",
  "ipc_profile_response_public_key_digest",
  "ipc_process_key_custody",
  "role_key_usage",
  "role_key_id",
  "role_public_key_digest",
  "role_key_custody_profile_digest",
  "anchor_digest",
  "trusted_clock_digest",
  "runtime_epoch_digest",
  "revocation_generation",
  "revocation_state_digest",
  "hil_qualification_digest",
  "authority_id",
  "authority_key_id",
  "authority_public_key_digest",
  "authority_trust_root_epoch",
  "authority_epoch",
  "authority_generation",
  "authority_state_digest",
  "issued_at",
  "expires_at",
  "nonce",
]);
const PROVIDER_PAYLOAD_FIELDS = Object.freeze([
  "provider_id",
  "provider_descriptor_digest",
  "provider_implementation_digest",
]);
const DEVICE_PAYLOAD_FIELDS = Object.freeze([
  "device_acl_profile_digest",
  "device_enrollment_profile_digest",
]);
const CLEANUP_PAYLOAD_FIELDS = Object.freeze([
  "precommitted_cleanup_plan_digest",
  "precommitted_snapshot_digest",
  "precommitted_restore_digest",
  "fence_state_digest",
  "cleanup_root_profile_digest",
]);
const SAFETY_PAYLOAD_FIELDS = Object.freeze([
  "deadman_profile_digest",
  "interlock_profile_digest",
  "cleanup_policy_digest",
  "fence_authority_profile_digest",
  "cleanup_root_profile_digest",
]);
const HOST_PROCESS_FIELDS = Object.freeze([
  "host_snapshot_scheme",
  "os_platform",
  "os_architecture",
  "os_effective_uid",
  "os_effective_gid",
  "os_real_uid",
  "os_real_gid",
  "process_id",
  "process_credential_scheme",
  "process_credential_digest",
  "process_start_token_digest",
  "runtime_implementation",
  "runtime_abi",
  "runtime_implementation_digest",
  "native_inspector_measurement_scheme",
  "native_inspector_implementation_digest",
  "native_inspector_measurement_digest",
  "native_inspector_measurement_complete",
  "code_signing_identity_scheme",
  "code_signing_identity_digest",
  "code_signing_identity_complete",
  "mapped_code_identity_scheme",
  "mapped_code_identity_digest",
  "mapped_code_identity_complete",
  "mapped_code_identity_audit_token_bound",
  "mapped_code_identity_stable",
  "cdhash_algorithm",
  "cdhash_set_digest",
  "cdhash_complete",
  "dynamic_code_validity_scheme",
  "dynamic_code_validity_state",
  "dynamic_code_validity_digest",
  "dynamic_code_validity_complete",
  "bundle_immutability_scheme",
  "bundle_immutability_evidence_digest",
  "bundle_immutability_complete",
  "bundle_manifest_digest",
  "entrypoint_digest",
  "config_manifest_digest",
]);
const AUTHORITY_STATE_FIELDS = Object.freeze([
  "authority_id",
  "authority_key_id",
  "authority_public_key_digest",
  "authority_trust_root_epoch",
  "authority_epoch",
  "authority_generation",
  "revocation_generation",
  "revocation_state_digest",
  "anchor_digest",
  "trusted_clock_digest",
  "runtime_epoch_digest",
  "hil_qualification_digest",
]);
const CURRENT_AUTHORITY_FIELDS = Object.freeze([
  "version",
  "trusted",
  "revoked",
  ...AUTHORITY_STATE_FIELDS,
  "authority_state_digest",
  "authority_public_key",
  "current_launch_attestation_digest",
  "current_launch_profile_digest",
  "current_process_instance_binding_digest",
  "trusted_now",
]);
const SIGNED_ATTESTATION_FIELDS = Object.freeze([
  "version",
  "kind",
  "domain",
  "payload",
  "payload_digest",
  "authentication",
  "launch_attestation_digest",
]);
const AUTHENTICATION_FIELDS = Object.freeze([
  "scheme",
  "key_usage",
  "authority_key_id",
  "authority_public_key_digest",
  "signed_payload_digest",
  "signature",
]);
const HOST_SNAPSHOT_FIELDS = Object.freeze([
  "version",
  ...HOST_PROCESS_FIELDS,
  "snapshot_digest",
]);

const SIGNER_PORTS = new WeakSet();
const SIGNER_PRIVATE = new WeakMap();
const VERIFIER_PORTS = new WeakSet();
const VERIFIER_PRIVATE = new WeakMap();
const HOST_RESOLVER_PORTS = new WeakSet();
const HOST_RESOLVER_PRIVATE = new WeakMap();
const REPLAY_PORTS = new WeakSet();
const REPLAY_PRIVATE = new WeakMap();
const ACTIVE_CALLBACKS = new WeakSet();
const VERIFIED_LAUNCH_ATTESTATIONS = new WeakSet();

const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectIsFrozen = Object.isFrozen;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;

const CONFORMANCE_BLOCKERS = Object.freeze([
  "immutable_privileged_launcher_not_qualified",
  "native_live_host_resolver_hil_missing",
  "durable_external_replay_hil_missing",
  "dedicated_principal_device_acl_hil_missing",
]);

function launchAttestationRejected() {
  const error = new Error("Launch attestation was rejected");
  Object.defineProperty(error, "code", {
    value: "launch_attestation_rejected",
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return error;
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return reflectOwnKeys(value).every((key) => {
    if (typeof key !== "string") return false;
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    return descriptor != null && Object.hasOwn(descriptor, "value")
      && descriptor.enumerable === true;
  });
}

function assertExactDataObject(value, label, fields) {
  if (!isPlainDataObject(value)) {
    throw new Error(`${label} must be a plain own-data object`);
  }
  const actual = reflectOwnKeys(value).slice().sort();
  const expected = fields.slice().sort();
  const unknown = actual.filter((field) => !expected.includes(field));
  if (unknown.length > 0) {
    throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  }
  const missing = expected.filter((field) => !actual.includes(field));
  if (missing.length > 0) {
    throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  }
  return value;
}

function ownDataValue(value, field, label) {
  const descriptor = objectGetOwnPropertyDescriptor(value, field);
  if (descriptor == null || !Object.hasOwn(descriptor, "value")
      || descriptor.enumerable !== true) {
    throw new Error(`${label}.${field} must be an enumerable own data field`);
  }
  return descriptor.value;
}

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || objectIsFrozen(value)) return value;
  for (const field of reflectOwnKeys(value)) {
    const descriptor = objectGetOwnPropertyDescriptor(value, field);
    if (descriptor != null && Object.hasOwn(descriptor, "value")) deepFreeze(descriptor.value);
  }
  return objectFreeze(value);
}

function assertFunction(value, label) {
  if (typeof value !== "function" || utilTypes.isProxy(value)) {
    throw new Error(`${label} must be a non-Proxy function`);
  }
  return value;
}

function assertCanonicalTimestamp(value, label) {
  if (typeof value !== "string") throw new Error(`${label} must be a canonical timestamp`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`${label} must be a canonical ISO-8601 UTC timestamp`);
  }
  return value;
}

function assertNonce(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22,128}$/u.test(value)) {
    throw new Error(`${label} must be a canonical 128-bit-or-stronger base64url nonce`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < 16 || bytes.toString("base64url") !== value) {
    throw new Error(`${label} must use canonical base64url encoding`);
  }
  return value;
}

function assertSignature(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{86}$/u.test(value)) {
    throw new Error(`${label} must be a canonical Ed25519 signature`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    throw new Error(`${label} must use canonical Ed25519 base64url encoding`);
  }
  return value;
}

function assertBooleanTrue(value, label) {
  if (value !== true) throw new Error(`${label} must be true`);
  return true;
}

function payloadFieldsForRole(role) {
  if (!ROLE_SET.has(role)) throw new Error("launch_attestation.payload.role is invalid");
  return [
    ...COMMON_PAYLOAD_FIELDS,
    ...(PROVIDER_ROLES.has(role) ? PROVIDER_PAYLOAD_FIELDS : []),
    ...(DEVICE_OWNING_ROLES.has(role) ? DEVICE_PAYLOAD_FIELDS : []),
    ...(role === "cleanup_only_worker" ? CLEANUP_PAYLOAD_FIELDS : []),
    ...(role === "safety_supervisor" ? SAFETY_PAYLOAD_FIELDS : []),
  ];
}

function normalizeHostFields(input, label) {
  const result = {
    host_snapshot_scheme: assertIdentifier(
      input.host_snapshot_scheme,
      `${label}.host_snapshot_scheme`,
    ),
    os_platform: assertIdentifier(input.os_platform, `${label}.os_platform`),
    os_architecture: assertIdentifier(input.os_architecture, `${label}.os_architecture`),
    os_effective_uid: assertInteger(
      input.os_effective_uid,
      `${label}.os_effective_uid`,
      0,
      2 ** 32 - 2,
    ),
    os_effective_gid: assertInteger(
      input.os_effective_gid,
      `${label}.os_effective_gid`,
      0,
      2 ** 32 - 2,
    ),
    os_real_uid: assertInteger(input.os_real_uid, `${label}.os_real_uid`, 0, 2 ** 32 - 2),
    os_real_gid: assertInteger(input.os_real_gid, `${label}.os_real_gid`, 0, 2 ** 32 - 2),
    process_id: assertInteger(input.process_id, `${label}.process_id`, 1, 2 ** 31 - 1),
    process_credential_scheme: assertIdentifier(
      input.process_credential_scheme,
      `${label}.process_credential_scheme`,
    ),
    process_credential_digest: assertDigest(
      input.process_credential_digest,
      `${label}.process_credential_digest`,
    ),
    process_start_token_digest: assertDigest(
      input.process_start_token_digest,
      `${label}.process_start_token_digest`,
    ),
    runtime_implementation: assertIdentifier(
      input.runtime_implementation,
      `${label}.runtime_implementation`,
    ),
    runtime_abi: assertIdentifier(input.runtime_abi, `${label}.runtime_abi`),
    runtime_implementation_digest: assertDigest(
      input.runtime_implementation_digest,
      `${label}.runtime_implementation_digest`,
    ),
    native_inspector_measurement_scheme: assertIdentifier(
      input.native_inspector_measurement_scheme,
      `${label}.native_inspector_measurement_scheme`,
    ),
    native_inspector_implementation_digest: assertDigest(
      input.native_inspector_implementation_digest,
      `${label}.native_inspector_implementation_digest`,
    ),
    native_inspector_measurement_digest: assertDigest(
      input.native_inspector_measurement_digest,
      `${label}.native_inspector_measurement_digest`,
    ),
    native_inspector_measurement_complete: assertBooleanTrue(
      input.native_inspector_measurement_complete,
      `${label}.native_inspector_measurement_complete`,
    ),
    code_signing_identity_scheme: assertIdentifier(
      input.code_signing_identity_scheme,
      `${label}.code_signing_identity_scheme`,
    ),
    code_signing_identity_digest: assertDigest(
      input.code_signing_identity_digest,
      `${label}.code_signing_identity_digest`,
    ),
    code_signing_identity_complete: assertBooleanTrue(
      input.code_signing_identity_complete,
      `${label}.code_signing_identity_complete`,
    ),
    mapped_code_identity_scheme: assertIdentifier(
      input.mapped_code_identity_scheme,
      `${label}.mapped_code_identity_scheme`,
    ),
    mapped_code_identity_digest: assertDigest(
      input.mapped_code_identity_digest,
      `${label}.mapped_code_identity_digest`,
    ),
    mapped_code_identity_complete: assertBooleanTrue(
      input.mapped_code_identity_complete,
      `${label}.mapped_code_identity_complete`,
    ),
    mapped_code_identity_audit_token_bound: assertBooleanTrue(
      input.mapped_code_identity_audit_token_bound,
      `${label}.mapped_code_identity_audit_token_bound`,
    ),
    mapped_code_identity_stable: assertBooleanTrue(
      input.mapped_code_identity_stable,
      `${label}.mapped_code_identity_stable`,
    ),
    cdhash_algorithm: assertInteger(
      input.cdhash_algorithm,
      `${label}.cdhash_algorithm`,
      1,
      2 ** 32 - 1,
    ),
    cdhash_set_digest: assertDigest(input.cdhash_set_digest, `${label}.cdhash_set_digest`),
    cdhash_complete: assertBooleanTrue(input.cdhash_complete, `${label}.cdhash_complete`),
    dynamic_code_validity_scheme: assertIdentifier(
      input.dynamic_code_validity_scheme,
      `${label}.dynamic_code_validity_scheme`,
    ),
    dynamic_code_validity_state: input.dynamic_code_validity_state,
    dynamic_code_validity_digest: assertDigest(
      input.dynamic_code_validity_digest,
      `${label}.dynamic_code_validity_digest`,
    ),
    dynamic_code_validity_complete: assertBooleanTrue(
      input.dynamic_code_validity_complete,
      `${label}.dynamic_code_validity_complete`,
    ),
    bundle_immutability_scheme: assertIdentifier(
      input.bundle_immutability_scheme,
      `${label}.bundle_immutability_scheme`,
    ),
    bundle_immutability_evidence_digest: assertDigest(
      input.bundle_immutability_evidence_digest,
      `${label}.bundle_immutability_evidence_digest`,
    ),
    bundle_immutability_complete: assertBooleanTrue(
      input.bundle_immutability_complete,
      `${label}.bundle_immutability_complete`,
    ),
    bundle_manifest_digest: assertDigest(
      input.bundle_manifest_digest,
      `${label}.bundle_manifest_digest`,
    ),
    entrypoint_digest: assertDigest(input.entrypoint_digest, `${label}.entrypoint_digest`),
    config_manifest_digest: assertDigest(
      input.config_manifest_digest,
      `${label}.config_manifest_digest`,
    ),
  };
  if (result.os_effective_uid !== result.os_real_uid
      || result.os_effective_gid !== result.os_real_gid) {
    throw new Error(`${label} real and effective UID/GID must be exactly equal`);
  }
  if (result.dynamic_code_validity_state !== "valid") {
    throw new Error(`${label}.dynamic_code_validity_state must be valid`);
  }
  const derivedMappedIdentityComplete = result.native_inspector_measurement_complete
    && result.code_signing_identity_complete
    && result.cdhash_complete
    && result.dynamic_code_validity_complete
    && result.dynamic_code_validity_state === "valid"
    && result.mapped_code_identity_audit_token_bound
    && result.mapped_code_identity_stable;
  if (result.mapped_code_identity_complete !== derivedMappedIdentityComplete) {
    throw new Error(`${label}.mapped_code_identity_complete is not derived from complete evidence`);
  }
  return deepFreeze(result);
}

function authorityStateBasis(input, label = "launch_authority_state") {
  return deepFreeze({
    authority_id: assertToken(input.authority_id, `${label}.authority_id`, "launch-authority"),
    authority_key_id: assertToken(
      input.authority_key_id,
      `${label}.authority_key_id`,
      "launch-key",
    ),
    authority_public_key_digest: assertDigest(
      input.authority_public_key_digest,
      `${label}.authority_public_key_digest`,
    ),
    authority_trust_root_epoch: assertInteger(
      input.authority_trust_root_epoch,
      `${label}.authority_trust_root_epoch`,
      1,
    ),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    authority_generation: assertInteger(
      input.authority_generation,
      `${label}.authority_generation`,
      1,
    ),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
      0,
    ),
    revocation_state_digest: assertDigest(
      input.revocation_state_digest,
      `${label}.revocation_state_digest`,
    ),
    anchor_digest: assertDigest(input.anchor_digest, `${label}.anchor_digest`),
    trusted_clock_digest: assertDigest(
      input.trusted_clock_digest,
      `${label}.trusted_clock_digest`,
    ),
    runtime_epoch_digest: assertDigest(
      input.runtime_epoch_digest,
      `${label}.runtime_epoch_digest`,
    ),
    hil_qualification_digest: assertDigest(
      input.hil_qualification_digest,
      `${label}.hil_qualification_digest`,
    ),
  });
}

function launchAttestationAuthorityStateDigest(input) {
  return hashCanonicalJson({
    domain: LAUNCH_ATTESTATION_AUTHORITY_STATE_DOMAIN,
    version: LAUNCH_ATTESTATION_VERSION,
    authority: authorityStateBasis(input),
  });
}

function normalizeLaunchAttestationPayload(input, label = "launch_attestation.payload") {
  if (!isPlainDataObject(input)) throw new Error(`${label} must be a plain own-data object`);
  const role = ownDataValue(input, "role", label);
  assertExactDataObject(input, label, payloadFieldsForRole(role));
  if (input.version !== LAUNCH_ATTESTATION_VERSION) {
    throw new Error(`${label}.version must be ${LAUNCH_ATTESTATION_VERSION}`);
  }
  const host = normalizeHostFields(input, label);
  const normalized = {
    version: LAUNCH_ATTESTATION_VERSION,
    launch_attestation_id: assertToken(
      input.launch_attestation_id,
      `${label}.launch_attestation_id`,
      "launch-attestation",
    ),
    role,
    attestation_assurance: input.attestation_assurance,
    production_ready: input.production_ready,
    separate_identity_authorized: input.separate_identity_authorized,
    hardware_authorized: input.hardware_authorized,
    ...host,
    process_principal_id: assertToken(
      input.process_principal_id,
      `${label}.process_principal_id`,
      "principal",
    ),
    ipc_peer_principal_id: assertToken(
      input.ipc_peer_principal_id,
      `${label}.ipc_peer_principal_id`,
      "principal",
    ),
    execution_principal_id: assertToken(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      "principal",
    ),
    ipc_profile_request_key_id: assertToken(
      input.ipc_profile_request_key_id,
      `${label}.ipc_profile_request_key_id`,
      "ipc-key",
    ),
    ipc_profile_request_public_key_digest: assertDigest(
      input.ipc_profile_request_public_key_digest,
      `${label}.ipc_profile_request_public_key_digest`,
    ),
    ipc_profile_response_key_id: assertToken(
      input.ipc_profile_response_key_id,
      `${label}.ipc_profile_response_key_id`,
      "ipc-key",
    ),
    ipc_profile_response_public_key_digest: assertDigest(
      input.ipc_profile_response_public_key_digest,
      `${label}.ipc_profile_response_public_key_digest`,
    ),
    ipc_process_key_custody: input.ipc_process_key_custody,
    role_key_usage: input.role_key_usage,
    role_key_id: assertToken(input.role_key_id, `${label}.role_key_id`, "role-key"),
    role_public_key_digest: assertDigest(
      input.role_public_key_digest,
      `${label}.role_public_key_digest`,
    ),
    role_key_custody_profile_digest: assertDigest(
      input.role_key_custody_profile_digest,
      `${label}.role_key_custody_profile_digest`,
    ),
    anchor_digest: input.anchor_digest,
    trusted_clock_digest: input.trusted_clock_digest,
    runtime_epoch_digest: input.runtime_epoch_digest,
    revocation_generation: input.revocation_generation,
    revocation_state_digest: input.revocation_state_digest,
    hil_qualification_digest: input.hil_qualification_digest,
    authority_id: input.authority_id,
    authority_key_id: input.authority_key_id,
    authority_public_key_digest: input.authority_public_key_digest,
    authority_trust_root_epoch: input.authority_trust_root_epoch,
    authority_epoch: input.authority_epoch,
    authority_generation: input.authority_generation,
    authority_state_digest: assertDigest(
      input.authority_state_digest,
      `${label}.authority_state_digest`,
    ),
    issued_at: assertCanonicalTimestamp(input.issued_at, `${label}.issued_at`),
    expires_at: assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`),
    nonce: assertNonce(input.nonce, `${label}.nonce`),
  };
  const authority = authorityStateBasis(normalized, label);
  Object.assign(normalized, authority);
  if (normalized.attestation_assurance !== "caller_injected_conformance_only"
      || normalized.production_ready !== false
      || normalized.separate_identity_authorized !== false
      || normalized.hardware_authorized !== false) {
    throw new Error(`${label} cannot claim production, separate-identity, or hardware authority`);
  }
  if (normalized.authority_state_digest !== launchAttestationAuthorityStateDigest(authority)) {
    throw new Error(`${label}.authority_state_digest does not bind the authority state`);
  }
  if (normalized.ipc_peer_principal_id === normalized.execution_principal_id) {
    throw new Error(`${label} IPC peer and execution principals must be distinct`);
  }
  const expectedProcessPrincipal = IPC_PEER_PROCESS_ROLES.has(role)
    ? normalized.ipc_peer_principal_id
    : normalized.execution_principal_id;
  if (normalized.process_principal_id !== expectedProcessPrincipal) {
    throw new Error(`${label}.process_principal_id does not match role custody`);
  }
  const expectedIpcKeyCustody = IPC_PEER_PROCESS_ROLES.has(role)
    ? "request_signer_response_verifier"
    : "request_verifier_response_signer";
  if (normalized.ipc_process_key_custody !== expectedIpcKeyCustody) {
    throw new Error(`${label}.ipc_process_key_custody does not match role custody`);
  }
  if (normalized.role_key_usage !== ROLE_KEY_USAGE_BY_ROLE[role]) {
    throw new Error(`${label}.role_key_usage does not match role custody`);
  }
  const distinctKeyIds = new Set([
    normalized.ipc_profile_request_key_id,
    normalized.ipc_profile_response_key_id,
    normalized.authority_key_id,
    normalized.role_key_id,
  ]);
  const distinctKeyDigests = new Set([
    normalized.ipc_profile_request_public_key_digest,
    normalized.ipc_profile_response_public_key_digest,
    normalized.authority_public_key_digest,
    normalized.role_public_key_digest,
  ]);
  if (distinctKeyIds.size !== 4 || distinctKeyDigests.size !== 4) {
    throw new Error(
      `${label} request, response, role, and authority keys must be pairwise distinct`,
    );
  }
  const lifetime = Date.parse(normalized.expires_at) - Date.parse(normalized.issued_at);
  if (lifetime <= 0 || lifetime > LAUNCH_ATTESTATION_MAX_LIFETIME_MS) {
    throw new Error(
      `${label} lifetime must be positive and at most ${LAUNCH_ATTESTATION_MAX_LIFETIME_MS}ms`,
    );
  }
  if (PROVIDER_ROLES.has(role)) {
    Object.assign(normalized, {
      provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
      provider_descriptor_digest: assertDigest(
        input.provider_descriptor_digest,
        `${label}.provider_descriptor_digest`,
      ),
      provider_implementation_digest: assertDigest(
        input.provider_implementation_digest,
        `${label}.provider_implementation_digest`,
      ),
    });
  }
  if (DEVICE_OWNING_ROLES.has(role)) {
    Object.assign(normalized, {
      device_acl_profile_digest: assertDigest(
        input.device_acl_profile_digest,
        `${label}.device_acl_profile_digest`,
      ),
      device_enrollment_profile_digest: assertDigest(
        input.device_enrollment_profile_digest,
        `${label}.device_enrollment_profile_digest`,
      ),
    });
  }
  if (role === "cleanup_only_worker") {
    for (const field of CLEANUP_PAYLOAD_FIELDS) {
      normalized[field] = assertDigest(input[field], `${label}.${field}`);
    }
  }
  if (role === "safety_supervisor") {
    for (const field of SAFETY_PAYLOAD_FIELDS) {
      normalized[field] = assertDigest(input[field], `${label}.${field}`);
    }
  }
  const result = deepFreeze(normalized);
  if (Buffer.byteLength(canonicalJson(result), "utf8") > LAUNCH_ATTESTATION_MAX_PAYLOAD_BYTES) {
    throw new Error(`${label} exceeds the fixed byte limit`);
  }
  return result;
}

function launchProcessInstanceBindingDigest(payloadInput) {
  const payload = normalizeLaunchAttestationPayload(payloadInput);
  const processInstance = {};
  for (const field of HOST_PROCESS_FIELDS) processInstance[field] = payload[field];
  return hashCanonicalJson({
    domain: LAUNCH_ATTESTATION_PROCESS_INSTANCE_DOMAIN,
    version: LAUNCH_ATTESTATION_VERSION,
    process_instance: processInstance,
  });
}

function launchProfileDigest(payloadInput) {
  const payload = normalizeLaunchAttestationPayload(payloadInput);
  const profile = {
    role: payload.role,
    process_principal_id: payload.process_principal_id,
    ipc_peer_principal_id: payload.ipc_peer_principal_id,
    execution_principal_id: payload.execution_principal_id,
    ipc_profile_request_key_id: payload.ipc_profile_request_key_id,
    ipc_profile_request_public_key_digest: payload.ipc_profile_request_public_key_digest,
    ipc_profile_response_key_id: payload.ipc_profile_response_key_id,
    ipc_profile_response_public_key_digest: payload.ipc_profile_response_public_key_digest,
    ipc_process_key_custody: payload.ipc_process_key_custody,
    role_key_usage: payload.role_key_usage,
    role_key_id: payload.role_key_id,
    role_public_key_digest: payload.role_public_key_digest,
    role_key_custody_profile_digest: payload.role_key_custody_profile_digest,
    process_instance_binding_digest: launchProcessInstanceBindingDigest(payload),
    authority_state_digest: payload.authority_state_digest,
  };
  for (const field of PROVIDER_PAYLOAD_FIELDS) {
    if (Object.hasOwn(payload, field)) profile[field] = payload[field];
  }
  for (const field of DEVICE_PAYLOAD_FIELDS) {
    if (Object.hasOwn(payload, field)) profile[field] = payload[field];
  }
  for (const field of CLEANUP_PAYLOAD_FIELDS) {
    if (Object.hasOwn(payload, field)) profile[field] = payload[field];
  }
  for (const field of SAFETY_PAYLOAD_FIELDS) {
    if (Object.hasOwn(payload, field)) profile[field] = payload[field];
  }
  return hashCanonicalJson({
    domain: LAUNCH_ATTESTATION_PROFILE_DOMAIN,
    version: LAUNCH_ATTESTATION_VERSION,
    profile,
  });
}

function signatureMessage(payloadDigest) {
  return Buffer.from(
    `${LAUNCH_ATTESTATION_SIGNATURE_DOMAIN}\0${assertDigest(payloadDigest, "payload_digest")}`,
    "utf8",
  );
}

function normalizeSignedLaunchAttestation(input, label = "signed_launch_attestation") {
  assertExactDataObject(input, label, SIGNED_ATTESTATION_FIELDS);
  if (input.version !== LAUNCH_ATTESTATION_VERSION
      || input.kind !== "process_launch_attestation"
      || input.domain !== LAUNCH_ATTESTATION_DOMAIN) {
    throw new Error(`${label} version, kind, or domain is invalid`);
  }
  const payload = normalizeLaunchAttestationPayload(input.payload, `${label}.payload`);
  const payloadDigest = assertDigest(input.payload_digest, `${label}.payload_digest`);
  if (payloadDigest !== hashCanonicalJson(payload)) {
    throw new Error(`${label}.payload_digest does not bind the canonical payload`);
  }
  assertExactDataObject(input.authentication, `${label}.authentication`, AUTHENTICATION_FIELDS);
  const authentication = deepFreeze({
    scheme: input.authentication.scheme,
    key_usage: input.authentication.key_usage,
    authority_key_id: assertToken(
      input.authentication.authority_key_id,
      `${label}.authentication.authority_key_id`,
      "launch-key",
    ),
    authority_public_key_digest: assertDigest(
      input.authentication.authority_public_key_digest,
      `${label}.authentication.authority_public_key_digest`,
    ),
    signed_payload_digest: assertDigest(
      input.authentication.signed_payload_digest,
      `${label}.authentication.signed_payload_digest`,
    ),
    signature: assertSignature(input.authentication.signature, `${label}.authentication.signature`),
  });
  if (authentication.scheme !== "ed25519"
      || authentication.key_usage !== LAUNCH_ATTESTATION_KEY_USAGE
      || authentication.authority_key_id !== payload.authority_key_id
      || authentication.authority_public_key_digest !== payload.authority_public_key_digest
      || authentication.signed_payload_digest !== payloadDigest) {
    throw new Error(`${label}.authentication is not bound to the payload authority`);
  }
  const basis = deepFreeze({
    version: LAUNCH_ATTESTATION_VERSION,
    kind: "process_launch_attestation",
    domain: LAUNCH_ATTESTATION_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    authentication,
  });
  const attestationDigest = assertDigest(
    input.launch_attestation_digest,
    `${label}.launch_attestation_digest`,
  );
  if (attestationDigest !== hashCanonicalJson(basis)) {
    throw new Error(`${label}.launch_attestation_digest does not bind the signed envelope`);
  }
  return deepFreeze({ ...basis, launch_attestation_digest: attestationDigest });
}

function conformanceProjection(kind, portId, extra = {}) {
  return deepFreeze({
    version: LAUNCH_ATTESTATION_VERSION,
    port_kind: kind,
    port_id: portId,
    assurance: "caller_injected_conformance_only",
    production_ready: false,
    separate_identity_authorized: false,
    hardware_authorized: false,
    production_blockers: CONFORMANCE_BLOCKERS,
    ...extra,
  });
}

function createConformanceLaunchAttestationSigner(input = {}) {
  assertExactDataObject(input, "conformance_launch_attestation_signer", [
    "port_id",
    ...AUTHORITY_STATE_FIELDS,
    "authority_private_key",
  ]);
  const privateKey = assertEd25519Key(
    input.authority_private_key,
    "private",
    "conformance_launch_attestation_signer.authority_private_key",
  );
  if (utilTypes.isProxy(privateKey)) {
    throw new Error("conformance_launch_attestation_signer.authority_private_key cannot be a Proxy");
  }
  const authorityPublicKeyDigest = publicKeyDigest(privateKey);
  if (input.authority_public_key_digest !== authorityPublicKeyDigest) {
    throw new Error("conformance launch signer public-key digest is inconsistent");
  }
  const authority = authorityStateBasis(input, "conformance_launch_attestation_signer");
  const authorityStateDigest = launchAttestationAuthorityStateDigest(authority);
  const port = conformanceProjection(
    "launch_attestation_signer",
    assertIdentifier(input.port_id, "conformance_launch_attestation_signer.port_id"),
    {
      authority_id: authority.authority_id,
      authority_state_digest: authorityStateDigest,
    },
  );
  SIGNER_PORTS.add(port);
  SIGNER_PRIVATE.set(port, objectFreeze({ private_key: privateKey, authority }));
  return port;
}

function assertConformanceLaunchAttestationSigner(port) {
  if (port == null || typeof port !== "object" || !objectIsFrozen(port)
      || !SIGNER_PORTS.has(port) || !SIGNER_PRIVATE.has(port)) {
    throw new Error("launch attestation signer must be a privately branded conformance port");
  }
  return port;
}

function signLaunchAttestation(port, payloadInput) {
  assertConformanceLaunchAttestationSigner(port);
  const payload = normalizeLaunchAttestationPayload(payloadInput);
  const state = SIGNER_PRIVATE.get(port);
  const authority = authorityStateBasis(payload);
  if (hashCanonicalJson(authority) !== hashCanonicalJson(state.authority)
      || payload.authority_state_digest !== port.authority_state_digest) {
    throw new Error("launch attestation payload drifted from signer authority state");
  }
  const payloadDigest = hashCanonicalJson(payload);
  const authentication = deepFreeze({
    scheme: "ed25519",
    key_usage: LAUNCH_ATTESTATION_KEY_USAGE,
    authority_key_id: payload.authority_key_id,
    authority_public_key_digest: payload.authority_public_key_digest,
    signed_payload_digest: payloadDigest,
    signature: crypto.sign(null, signatureMessage(payloadDigest), state.private_key).toString("base64url"),
  });
  const basis = deepFreeze({
    version: LAUNCH_ATTESTATION_VERSION,
    kind: "process_launch_attestation",
    domain: LAUNCH_ATTESTATION_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    authentication,
  });
  return deepFreeze({
    ...basis,
    launch_attestation_digest: hashCanonicalJson(basis),
  });
}

function createCallbackPort(input, label, callbackField, kind, ports, privatePorts) {
  assertExactDataObject(input, label, ["port_id", callbackField]);
  const portId = assertIdentifier(input.port_id, `${label}.port_id`);
  const callback = assertFunction(input[callbackField], `${label}.${callbackField}`);
  const port = conformanceProjection(kind, portId);
  ports.add(port);
  privatePorts.set(port, objectFreeze({ callback }));
  return port;
}

function createConformanceLaunchAttestationVerifier(input = {}) {
  return createCallbackPort(
    input,
    "conformance_launch_attestation_verifier",
    "resolve_current_authority",
    "launch_attestation_verifier",
    VERIFIER_PORTS,
    VERIFIER_PRIVATE,
  );
}

function createConformanceLaunchHostResolver(input = {}) {
  return createCallbackPort(
    input,
    "conformance_launch_host_resolver",
    "resolve_live_process",
    "launch_host_resolver",
    HOST_RESOLVER_PORTS,
    HOST_RESOLVER_PRIVATE,
  );
}

function createConformanceLaunchReplayPort(input = {}) {
  return createCallbackPort(
    input,
    "conformance_launch_replay_port",
    "reserve_once",
    "launch_replay_reservation",
    REPLAY_PORTS,
    REPLAY_PRIVATE,
  );
}

function assertPrivatePort(port, ports, privatePorts, label) {
  if (port == null || typeof port !== "object" || !objectIsFrozen(port)
      || !ports.has(port) || !privatePorts.has(port)) {
    throw new Error(`${label} must be a privately branded conformance port`);
  }
  return port;
}

function assertConformanceLaunchAttestationVerifier(port) {
  return assertPrivatePort(port, VERIFIER_PORTS, VERIFIER_PRIVATE, "launch attestation verifier");
}

function assertConformanceLaunchHostResolver(port) {
  return assertPrivatePort(port, HOST_RESOLVER_PORTS, HOST_RESOLVER_PRIVATE, "launch host resolver");
}

function assertConformanceLaunchReplayPort(port) {
  return assertPrivatePort(port, REPLAY_PORTS, REPLAY_PRIVATE, "launch replay port");
}

function callPort(port, privatePorts, query, label) {
  if (ACTIVE_CALLBACKS.has(port)) throw new Error(`${label} cannot re-enter its port`);
  ACTIVE_CALLBACKS.add(port);
  try {
    const result = reflectApply(privatePorts.get(port).callback, undefined, [deepFreeze(query)]);
    if (utilTypes.isPromise(result) || utilTypes.isProxy(result)) {
      throw new Error(`${label} must return a synchronous own-data object`);
    }
    return result;
  } finally {
    ACTIVE_CALLBACKS.delete(port);
  }
}

function normalizeCurrentAuthority(input) {
  assertExactDataObject(input, "current_launch_authority", CURRENT_AUTHORITY_FIELDS);
  if (input.version !== LAUNCH_ATTESTATION_VERSION
      || input.trusted !== true || input.revoked !== false) {
    throw new Error("current launch authority is not trusted and active");
  }
  const publicKey = assertEd25519Key(
    input.authority_public_key,
    "public",
    "current_launch_authority.authority_public_key",
  );
  if (utilTypes.isProxy(publicKey)) throw new Error("current launch authority key cannot be a Proxy");
  const basis = authorityStateBasis(input, "current_launch_authority");
  const keyDigest = publicKeyDigest(publicKey);
  if (basis.authority_public_key_digest !== keyDigest) {
    throw new Error("current launch authority public key digest is invalid");
  }
  const authorityStateDigest = assertDigest(
    input.authority_state_digest,
    "current_launch_authority.authority_state_digest",
  );
  if (authorityStateDigest !== launchAttestationAuthorityStateDigest(basis)) {
    throw new Error("current launch authority state digest is invalid");
  }
  return deepFreeze({
    version: LAUNCH_ATTESTATION_VERSION,
    trusted: true,
    revoked: false,
    ...basis,
    authority_state_digest: authorityStateDigest,
    authority_public_key: publicKey,
    current_launch_attestation_digest: assertDigest(
      input.current_launch_attestation_digest,
      "current_launch_authority.current_launch_attestation_digest",
    ),
    current_launch_profile_digest: assertDigest(
      input.current_launch_profile_digest,
      "current_launch_authority.current_launch_profile_digest",
    ),
    current_process_instance_binding_digest: assertDigest(
      input.current_process_instance_binding_digest,
      "current_launch_authority.current_process_instance_binding_digest",
    ),
    trusted_now: assertCanonicalTimestamp(input.trusted_now, "current_launch_authority.trusted_now"),
  });
}

function normalizeHostSnapshot(input, resolverId) {
  assertExactDataObject(input, "live_launch_host_snapshot", HOST_SNAPSHOT_FIELDS);
  if (input.version !== LAUNCH_ATTESTATION_VERSION) {
    throw new Error("live_launch_host_snapshot.version is invalid");
  }
  const basis = normalizeHostFields(input, "live_launch_host_snapshot");
  const snapshotDigest = assertDigest(
    input.snapshot_digest,
    "live_launch_host_snapshot.snapshot_digest",
  );
  if (snapshotDigest !== hashCanonicalJson({
    domain: LAUNCH_ATTESTATION_HOST_SNAPSHOT_DOMAIN,
    version: LAUNCH_ATTESTATION_VERSION,
    resolver_id: resolverId,
    snapshot: basis,
  })) {
    throw new Error("live launch host snapshot digest is invalid");
  }
  return deepFreeze({
    version: LAUNCH_ATTESTATION_VERSION,
    ...basis,
    snapshot_digest: snapshotDigest,
  });
}

function launchHostSnapshotDigest(resolverId, snapshotInput) {
  const portId = assertIdentifier(resolverId, "launch_host_snapshot.resolver_id");
  assertExactDataObject(snapshotInput, "launch_host_snapshot", HOST_PROCESS_FIELDS);
  const snapshot = normalizeHostFields(snapshotInput, "launch_host_snapshot");
  return hashCanonicalJson({
    domain: LAUNCH_ATTESTATION_HOST_SNAPSHOT_DOMAIN,
    version: LAUNCH_ATTESTATION_VERSION,
    resolver_id: portId,
    snapshot,
  });
}

function assertExactHostBinding(payload, liveSnapshot) {
  for (const field of HOST_PROCESS_FIELDS) {
    if (payload[field] !== liveSnapshot[field]) {
      throw new Error(`live launch host snapshot drifted at ${field}`);
    }
  }
}

function assertExactAuthorityBinding(attestation, current) {
  const payload = attestation.payload;
  for (const field of AUTHORITY_STATE_FIELDS) {
    if (payload[field] !== current[field]) {
      throw new Error(`launch authority drifted at ${field}`);
    }
  }
  const processDigest = launchProcessInstanceBindingDigest(payload);
  const profileDigest = launchProfileDigest(payload);
  if (payload.authority_state_digest !== current.authority_state_digest
      || attestation.launch_attestation_digest !== current.current_launch_attestation_digest
      || processDigest !== current.current_process_instance_binding_digest
      || profileDigest !== current.current_launch_profile_digest) {
    throw new Error("launch authority current-state binding forked or drifted");
  }
}

function assertFresh(payload, trustedNow) {
  const now = Date.parse(trustedNow);
  const issued = Date.parse(payload.issued_at);
  const expires = Date.parse(payload.expires_at);
  if (issued > now + LAUNCH_ATTESTATION_MAX_CLOCK_SKEW_MS || now >= expires) {
    throw new Error("launch attestation is stale, expired, or issued in the future");
  }
}

function launchReplayClaim(attestation) {
  const payload = attestation.payload;
  const basis = deepFreeze({
    version: LAUNCH_ATTESTATION_VERSION,
    launch_attestation_digest: attestation.launch_attestation_digest,
    payload_digest: attestation.payload_digest,
    launch_profile_digest: launchProfileDigest(payload),
    process_instance_binding_digest: launchProcessInstanceBindingDigest(payload),
    authority_state_digest: payload.authority_state_digest,
    authority_generation: payload.authority_generation,
    role: payload.role,
    nonce_digest: hashCanonicalJson({ nonce: payload.nonce }),
    expires_at: payload.expires_at,
  });
  return deepFreeze({
    ...basis,
    claim_digest: hashCanonicalJson({
      domain: LAUNCH_ATTESTATION_REPLAY_CLAIM_DOMAIN,
      claim: basis,
    }),
  });
}

function launchReplayReceiptDigest(replayPortId, receiptBasisInput) {
  const portId = assertIdentifier(replayPortId, "launch_replay_receipt.replay_port_id");
  assertExactDataObject(receiptBasisInput, "launch_replay_receipt", [
    "version", "disposition", "claim_digest", "reservation_generation",
  ]);
  const basis = {
    version: receiptBasisInput.version,
    disposition: receiptBasisInput.disposition,
    claim_digest: assertDigest(
      receiptBasisInput.claim_digest,
      "launch_replay_receipt.claim_digest",
    ),
    reservation_generation: assertInteger(
      receiptBasisInput.reservation_generation,
      "launch_replay_receipt.reservation_generation",
      1,
    ),
  };
  if (basis.version !== LAUNCH_ATTESTATION_VERSION
      || !["reserved", "replay", "fork", "stale"].includes(basis.disposition)) {
    throw new Error("launch replay receipt version or disposition is invalid");
  }
  return hashCanonicalJson({
    domain: LAUNCH_ATTESTATION_REPLAY_RECEIPT_DOMAIN,
    replay_port_id: portId,
    receipt: basis,
  });
}

function normalizeReplayReceipt(input, replayPort, claim) {
  assertExactDataObject(input, "launch_replay_receipt", [
    "version",
    "disposition",
    "claim_digest",
    "reservation_generation",
    "receipt_digest",
  ]);
  const basis = {
    version: input.version,
    disposition: input.disposition,
    claim_digest: input.claim_digest,
    reservation_generation: input.reservation_generation,
  };
  const expectedDigest = launchReplayReceiptDigest(replayPort.port_id, basis);
  if (assertDigest(input.receipt_digest, "launch_replay_receipt.receipt_digest")
        !== expectedDigest
      || basis.claim_digest !== claim.claim_digest
      || basis.disposition !== "reserved") {
    throw new Error("launch attestation replay reservation was not accepted exactly once");
  }
  return deepFreeze({ ...basis, receipt_digest: expectedDigest });
}

function verifyAndReserveLaunchAttestation(input = {}) {
  try {
    assertExactDataObject(input, "launch_attestation_verification", [
      "attestation",
      "verifier_port",
      "host_resolver_port",
      "replay_port",
    ]);
    const verifierPort = assertConformanceLaunchAttestationVerifier(input.verifier_port);
    const hostResolverPort = assertConformanceLaunchHostResolver(input.host_resolver_port);
    const replayPort = assertConformanceLaunchReplayPort(input.replay_port);
    const attestation = normalizeSignedLaunchAttestation(input.attestation);
    const current = normalizeCurrentAuthority(callPort(
      verifierPort,
      VERIFIER_PRIVATE,
      {
        version: LAUNCH_ATTESTATION_VERSION,
        purpose: "resolve_exact_current_launch_authority",
        launch_attestation_digest: attestation.launch_attestation_digest,
      },
      "launch attestation authority resolver",
    ));
    assertExactAuthorityBinding(attestation, current);
    if (!crypto.verify(
      null,
      signatureMessage(attestation.payload_digest),
      current.authority_public_key,
      Buffer.from(attestation.authentication.signature, "base64url"),
    )) {
      throw new Error("launch attestation signature is invalid");
    }
    assertFresh(attestation.payload, current.trusted_now);
    const liveSnapshot = normalizeHostSnapshot(callPort(
      hostResolverPort,
      HOST_RESOLVER_PRIVATE,
      {
        version: LAUNCH_ATTESTATION_VERSION,
        purpose: "resolve_exact_live_launch_process",
        launch_attestation_digest: attestation.launch_attestation_digest,
        role: attestation.payload.role,
      },
      "launch host resolver",
    ), hostResolverPort.port_id);
    assertExactHostBinding(attestation.payload, liveSnapshot);
    const processInstanceBindingDigest = launchProcessInstanceBindingDigest(attestation.payload);
    if (processInstanceBindingDigest !== current.current_process_instance_binding_digest) {
      throw new Error("live process instance is not the authority-enrolled process instance");
    }
    const claim = launchReplayClaim(attestation);
    const receipt = normalizeReplayReceipt(callPort(
      replayPort,
      REPLAY_PRIVATE,
      claim,
      "launch replay reservation",
    ), replayPort, claim);
    const currentAfterReservation = normalizeCurrentAuthority(callPort(
      verifierPort,
      VERIFIER_PRIVATE,
      {
        version: LAUNCH_ATTESTATION_VERSION,
        purpose: "revalidate_exact_current_launch_authority_after_reservation",
        launch_attestation_digest: attestation.launch_attestation_digest,
        replay_receipt_digest: receipt.receipt_digest,
      },
      "post-reservation launch authority resolver",
    ));
    assertExactAuthorityBinding(attestation, currentAfterReservation);
    if (Date.parse(currentAfterReservation.trusted_now) < Date.parse(current.trusted_now)) {
      throw new Error("post-reservation trusted time moved backwards");
    }
    assertFresh(attestation.payload, currentAfterReservation.trusted_now);
    const verified = deepFreeze({
      version: LAUNCH_ATTESTATION_VERSION,
      launch_attestation_id: attestation.payload.launch_attestation_id,
      launch_attestation_digest: attestation.launch_attestation_digest,
      role: attestation.payload.role,
      process_principal_id: attestation.payload.process_principal_id,
      process_instance_binding_digest: processInstanceBindingDigest,
      launch_profile_digest: launchProfileDigest(attestation.payload),
      authority_state_digest: attestation.payload.authority_state_digest,
      authority_epoch: attestation.payload.authority_epoch,
      authority_generation: attestation.payload.authority_generation,
      replay_receipt_digest: receipt.receipt_digest,
      issued_at: attestation.payload.issued_at,
      expires_at: attestation.payload.expires_at,
      assurance: "signed_live_resolved_replay_reserved_conformance_only",
      production_ready: false,
      separate_identity_authorized: false,
      hardware_authorized: false,
      production_blockers: CONFORMANCE_BLOCKERS,
    });
    VERIFIED_LAUNCH_ATTESTATIONS.add(verified);
    return verified;
  } catch {
    throw launchAttestationRejected();
  }
}

function assertVerifiedLaunchAttestation(value) {
  if (value == null || typeof value !== "object" || !objectIsFrozen(value)
      || !VERIFIED_LAUNCH_ATTESTATIONS.has(value)) {
    throw new Error("verified launch attestation must be a privately branded conformance result");
  }
  return value;
}

module.exports = {
  LAUNCH_ATTESTATION_AUTHORITY_STATE_DOMAIN,
  LAUNCH_ATTESTATION_DOMAIN,
  LAUNCH_ATTESTATION_HOST_SNAPSHOT_DOMAIN,
  LAUNCH_ATTESTATION_KEY_USAGE,
  LAUNCH_ATTESTATION_MAX_CLOCK_SKEW_MS,
  LAUNCH_ATTESTATION_MAX_LIFETIME_MS,
  LAUNCH_ATTESTATION_PROCESS_INSTANCE_DOMAIN,
  LAUNCH_ATTESTATION_PROFILE_DOMAIN,
  LAUNCH_ATTESTATION_REPLAY_CLAIM_DOMAIN,
  LAUNCH_ATTESTATION_REPLAY_RECEIPT_DOMAIN,
  LAUNCH_ATTESTATION_ROLES,
  LAUNCH_ATTESTATION_SIGNATURE_DOMAIN,
  LAUNCH_ATTESTATION_VERSION,
  assertConformanceLaunchAttestationSigner,
  assertConformanceLaunchAttestationVerifier,
  assertConformanceLaunchHostResolver,
  assertConformanceLaunchReplayPort,
  assertVerifiedLaunchAttestation,
  createConformanceLaunchAttestationSigner,
  createConformanceLaunchAttestationVerifier,
  createConformanceLaunchHostResolver,
  createConformanceLaunchReplayPort,
  launchAttestationAuthorityStateDigest,
  launchHostSnapshotDigest,
  launchProcessInstanceBindingDigest,
  launchProfileDigest,
  launchReplayReceiptDigest,
  normalizeLaunchAttestationPayload,
  normalizeSignedLaunchAttestation,
  signLaunchAttestation,
  verifyAndReserveLaunchAttestation,
};
