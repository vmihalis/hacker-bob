"use strict";

const crypto = require("node:crypto");
const {
  arraysEqual,
  assertAbsoluteSystemDependency,
  assertBoolean,
  assertDarwinDescriptorFlagSemantics,
  assertDenseArray,
  assertDigest,
  assertExactObject,
  assertIdentifier,
  assertInteger,
  assertOpaqueToken,
  assertRelativeArtifactPath,
  assertString,
  assertTimestamp,
  domainDigest,
  makeArray,
  makeRecord,
  ownValue,
  reject,
  setArrayIndex,
  timestampMilliseconds,
} = require("./data-contract");

const cryptoCreateHash = crypto.createHash;
const cryptoCreatePublicKey = crypto.createPublicKey;
const cryptoVerify = crypto.verify;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const reflectApply = Reflect.apply;
const regexpTest = RegExp.prototype.test;
const bufferFrom = Buffer.from;
const bufferToString = Buffer.prototype.toString;
const hashPrototype = objectGetPrototypeOf(reflectApply(cryptoCreateHash, crypto, ["sha256"]));
const hashUpdate = objectGetOwnPropertyDescriptor(hashPrototype, "update").value;
const hashDigest = objectGetOwnPropertyDescriptor(hashPrototype, "digest").value;
const SafeSet = Set;
const setAdd = Set.prototype.add;
const setHas = Set.prototype.has;
const stringStartsWith = String.prototype.startsWith;

const NATIVE_PREBUILD_TRUST_V2_VERSION = 2;
const NATIVE_PREBUILD_MANIFEST_V2_DOMAIN =
  "hacker-bob/native-prebuild-release-manifest/v2";
const NATIVE_PREBUILD_SIGNATURE_V2_DOMAIN =
  "hacker-bob/native-prebuild-release-signature/v2";
const NATIVE_PREBUILD_ENVELOPE_V2_DOMAIN =
  "hacker-bob/native-prebuild-release-envelope/v2";
const NATIVE_PREBUILD_KEY_V2_USAGE = "native_prebuild_release_v2";
const NATIVE_PREBUILD_HANDOFF_SCHEME =
  "post_exec_audittoken_seccode_scm_rights_v1";

const NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2 = objectFreeze([
  "native_ipc_acceptor",
  "chameleon_cdc_custody",
  "safety_watchdog",
  "privileged_launcher",
  "lifecycle_custodian",
  "native_dispatch_custodian",
]);

const COMPONENT_KINDS = objectFreeze({
  native_ipc_acceptor: "node_native_addon",
  chameleon_cdc_custody: "node_native_addon",
  safety_watchdog: "mach_o_executable",
  privileged_launcher: "mach_o_executable",
  lifecycle_custodian: "mach_o_executable",
  native_dispatch_custodian: "mach_o_executable",
});
const COMPONENT_CODE_TYPES = objectFreeze({
  native_ipc_acceptor: "bundle",
  chameleon_cdc_custody: "bundle",
  safety_watchdog: "executable",
  privileged_launcher: "executable",
  lifecycle_custodian: "executable",
  native_dispatch_custodian: "executable",
});
const COMPONENT_MACHO_FILE_TYPES = objectFreeze({
  native_ipc_acceptor: 8,
  chameleon_cdc_custody: 8,
  safety_watchdog: 2,
  privileged_launcher: 2,
  lifecycle_custodian: 2,
  native_dispatch_custodian: 2,
});

const V2_VERIFICATION_BLOCKERS = objectFreeze([
  "caller_supplied_keyring_is_not_external_immutable_keyring",
  "caller_supplied_evidence_is_not_live_native_attestation",
  "release_signature_is_not_running_code_attestation",
  "audit_token_and_pidversion_must_be_kernel_observed_post_exec",
  "seccode_guest_validation_must_complete_before_capability_transfer",
  "scm_rights_grant_go_receipt_must_be_natively_enforced",
  "verification_result_is_diagnostic_not_authority",
]);

const MANIFEST_FIELDS = objectFreeze([
  "version", "kind", "package_name", "package_version", "release_id", "release_epoch",
  "target", "components", "source_tree_digest", "builder_identity_digest",
  "toolchain_manifest_digest", "provenance_statement_digest",
  "principal_acl_policy_digest", "immutable_install_policy_digest",
  "authority_handoff_policy", "doctor_policy", "issued_at", "expires_at",
]);
const TARGET_FIELDS = objectFreeze([
  "os", "architecture", "node_major", "napi_version", "node_api_only",
  "deployment_format",
]);
const COMPONENT_FIELDS = objectFreeze([
  "component_id", "artifact_path", "artifact_kind", "byte_size", "sha256",
  "source_digest", "builder_digest", "toolchain_digest", "provenance_digest",
  "exact_dynamic_dependencies", "code_identity", "macho_identity", "launch_principal",
  "mapped_measurement", "capability_abi",
]);
const CODE_IDENTITY_FIELDS = objectFreeze([
  "signature_kind", "code_type", "team_identifier", "signing_identifier",
  "cdhash_algorithm", "selected_cdhash", "candidate_set_digest_scheme",
  "candidate_set_digest",
  "serialized_sec_requirement_format", "serialized_sec_requirement_data_base64url",
  "serialized_sec_requirement_byte_size", "serialized_sec_requirement_digest",
  "code_directory_flags", "entitlements_digest_scheme", "entitlements_digest",
  "hardened_runtime_required", "notarization_required", "adhoc_allowed",
]);
const MACHO_IDENTITY_FIELDS = objectFreeze([
  "file_type", "cpu_type", "cpu_subtype", "macho_flags", "uuid",
  "load_commands_digest", "code_signature_blob_digest", "text_segment_file_digest",
  "slice_offset", "slice_size",
]);
const LAUNCH_PRINCIPAL_FIELDS = objectFreeze([
  "principal_id", "uid", "gid", "supplementary_groups_digest",
  "audit_session_policy_digest", "sandbox_profile_digest", "no_login_identity",
  "clear_supplementary_groups", "identity_drop_before_capability_grant",
]);
const MAPPED_MEASUREMENT_FIELDS = objectFreeze([
  "scheme", "expected_mapped_text_digest", "expected_mapped_linkedit_digest",
  "expected_loaded_uuid", "measurement_layout_digest", "require_kernel_audit_token",
  "require_pidversion_binding", "require_running_code_guest_validation",
  "require_cdhash_match", "require_macho_uuid_match", "require_pre_grant_measurement",
  "require_post_grant_identity_stability",
]);
const CAPABILITY_ABI_FIELDS = objectFreeze([
  "abi_id", "abi_version", "request_schema", "result_schema", "effect_journal_schema",
  "receipt_schema", "descriptor_count", "descriptor_table", "single_grant",
  "forbid_path_reopen", "close_unexpected_descriptors",
]);
const SCHEMA_ARTIFACT_FIELDS = objectFreeze([
  "artifact_path", "byte_size", "sha256", "media_type", "canonicalization",
  "load_scheme",
]);
const DESCRIPTOR_ROW_FIELDS = objectFreeze([
  "ordinal", "role", "descriptor_type", "access_mode", "required_status_flags",
  "forbidden_status_flags", "required_descriptor_flags", "forbidden_descriptor_flags",
  "sender_cloexec_required", "receiver_cloexec_before_ack",
  "identity_recheck_before_effect", "close_before_receipt", "transfer_mode",
]);
const HANDOFF_POLICY_FIELDS = objectFreeze([
  "scheme", "supervisor_component_id", "supervisor_role", "process_lineage_scheme",
  "listener_identity_scheme", "post_exec_connection_scheme",
  "capability_set_digest_scheme", "grant_go_binding_scheme", "transport",
  "peer_identity_scheme", "running_code_validation_scheme",
  "security_requirement_validation_scheme", "deadline_policy", "nonce_policy",
  "durable_exchange_policy",
]);
const DEADLINE_POLICY_FIELDS = objectFreeze([
  "clock", "challenge_timeout_ms", "attestation_timeout_ms", "grant_timeout_ms",
  "go_timeout_ms", "receipt_timeout_ms", "cleanup_timeout_ms", "total_timeout_ms",
  "clamp_to_parent_deadline", "signed_deadline_in_grant", "check_before_each_effect",
]);
const NONCE_POLICY_FIELDS = objectFreeze([
  "scheme", "entropy_bits", "generation_bits", "bind_manifest_digest",
  "bind_component_id", "bind_audit_token", "monotonic_generation", "single_use",
  "durable_replay_fence_before_grant",
]);
const DURABLE_EXCHANGE_POLICY_FIELDS = objectFreeze([
  "scheme", "grant_record_schema", "go_record_schema", "receipt_record_schema",
  "outbox_record_schema", "fsync_grant_before_go",
  "go_only_after_scm_rights_ack", "fsync_receipt_before_success",
  "fsync_outbox_before_ack", "effect_receipt_correlation_required",
  "unreceipted_grant_recovery_required", "close_capabilities_before_receipt",
  "authenticated_receipt_required", "fail_closed_on_receipt_loss",
]);
const DOCTOR_POLICY_FIELDS = objectFreeze([
  "external_keyring_policy_digest", "live_attestor_policy_digest",
  "max_evidence_age_ms", "require_external_immutable_keyring",
  "require_live_native_attestation", "require_native_transcript_authentication",
]);
const ENVELOPE_FIELDS = objectFreeze([
  "version", "kind", "signature_domain", "manifest", "manifest_digest", "authentication",
]);
const AUTHENTICATION_FIELDS = objectFreeze([
  "scheme", "key_usage", "key_id", "public_key_digest", "trust_epoch",
  "signed_manifest_digest", "signature",
]);
const TRUST_POLICY_FIELDS = objectFreeze([
  "version", "kind", "current_trust_epoch", "minimum_release_epoch",
  "revoked_release_ids", "revoked_manifest_digests", "keys",
]);
const TRUST_KEY_FIELDS = objectFreeze([
  "key_id", "public_key_spki_der", "public_key_digest", "trust_epoch", "not_before",
  "not_after", "revoked", "revocation_epoch", "allowed_package_names",
  "allowed_component_ids",
]);

const PACKAGE_PATTERN = /^@hacker-bob\/[a-z0-9][a-z0-9._-]{0,127}$/u;
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u;
const TEAM_PATTERN = /^[A-Z0-9]{10}$/u;
const SIGNING_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9.-]{0,190}$/u;
const CDHASH_PATTERN = /^[a-f0-9]{40}$/u;
const UUID_PATTERN = /^[a-f0-9]{32}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const ED25519_SPKI_HEX_PATTERN = /^302a300506032b6570032100[a-f0-9]{64}$/u;
const DESCRIPTOR_TYPES = objectFreeze([
  "directory", "regular_file", "unix_stream_socket", "character_device",
  "event_notification",
]);
const ACCESS_MODES = objectFreeze(["read_only", "write_only", "read_write"]);

function sha256Bytes(bytes) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [bytes]);
  return reflectApply(hashDigest, hash, ["hex"]);
}

function exactBoolean(input, field, label, expected, code) {
  const value = assertBoolean(ownValue(input, field, label, code), `${label}.${field}`, code);
  if (value !== expected) reject(code, `${label}.${field} must be ${expected}`);
  return value;
}

function exactString(input, field, label, expected, code) {
  const value = assertString(ownValue(input, field, label, code), `${label}.${field}`, {
    maximumBytes: 191,
    code,
  });
  if (value !== expected) reject(code, `${label}.${field} is unsupported`);
  return value;
}

function normalizeTarget(input) {
  const label = "native_prebuild_manifest_v2.target";
  assertExactObject(input, TARGET_FIELDS, label, "target_invalid");
  return makeRecord(TARGET_FIELDS, [
    exactString(input, "os", label, "darwin", "target_invalid"),
    exactString(input, "architecture", label, "arm64", "target_invalid"),
    assertInteger(ownValue(input, "node_major", label), `${label}.node_major`, 20, 20,
      "abi_invalid"),
    assertInteger(ownValue(input, "napi_version", label), `${label}.napi_version`, 9, 9,
      "abi_invalid"),
    exactBoolean(input, "node_api_only", label, true, "abi_invalid"),
    exactString(input, "deployment_format", label, "signed_immutable_prebuild_set_v2",
      "target_invalid"),
  ]);
}

function normalizeDependencies(input, label) {
  assertDenseArray(input, label, 64, "dependency_invalid");
  const values = [];
  let previous = null;
  for (let index = 0; index < input.length; index += 1) {
    const value = assertAbsoluteSystemDependency(
      ownValue(input, `${index}`, label, "dependency_invalid"), `${label}[${index}]`,
      "dependency_invalid",
    );
    if (previous != null && value <= previous) {
      reject("dependency_invalid", `${label} must be strictly sorted and unique`);
    }
    setArrayIndex(values, index, value);
    previous = value;
  }
  return makeArray(values);
}

function normalizeCodeIdentity(input, label, componentId) {
  assertExactObject(input, CODE_IDENTITY_FIELDS, label, "code_identity_invalid");
  const requirementFormat = exactString(input, "serialized_sec_requirement_format", label,
    "security_framework_sec_requirement_data_v1", "code_identity_invalid");
  const requirementText = ownValue(input, "serialized_sec_requirement_data_base64url", label,
    "code_identity_invalid");
  const requirementBytes = assertCanonicalBase64Url(requirementText,
    `${label}.serialized_sec_requirement_data_base64url`, null, "code_identity_invalid");
  if (requirementBytes.length < 16 || requirementBytes.length > 16 * 1024) {
    reject("code_identity_invalid", `${label} serialized SecRequirement size is out of bounds`);
  }
  const requirementSize = assertInteger(ownValue(input,
    "serialized_sec_requirement_byte_size", label),
  `${label}.serialized_sec_requirement_byte_size`, 16, 16 * 1024, "code_identity_invalid");
  if (requirementSize !== requirementBytes.length) {
    reject("code_identity_invalid", `${label} serialized SecRequirement size does not match`);
  }
  const requirementDigest = assertDigest(ownValue(input,
    "serialized_sec_requirement_digest", label),
  `${label}.serialized_sec_requirement_digest`, "code_identity_invalid");
  if (requirementDigest !== sha256Bytes(requirementBytes)) {
    reject("code_identity_invalid", `${label} serialized SecRequirement digest does not match`);
  }
  return makeRecord(CODE_IDENTITY_FIELDS, [
    exactString(input, "signature_kind", label, "developer_id", "code_identity_invalid"),
    exactString(input, "code_type", label, COMPONENT_CODE_TYPES[componentId],
      "code_identity_invalid"),
    assertString(ownValue(input, "team_identifier", label), `${label}.team_identifier`, {
      pattern: TEAM_PATTERN, minimumBytes: 10, maximumBytes: 10,
      code: "code_identity_invalid",
    }),
    assertString(ownValue(input, "signing_identifier", label), `${label}.signing_identifier`, {
      pattern: SIGNING_IDENTIFIER_PATTERN, maximumBytes: 191,
      code: "code_identity_invalid",
    }),
    exactString(input, "cdhash_algorithm", label, "sha256_truncated_160",
      "code_identity_invalid"),
    assertString(ownValue(input, "selected_cdhash", label), `${label}.selected_cdhash`, {
      pattern: CDHASH_PATTERN, minimumBytes: 40, maximumBytes: 40,
      code: "code_identity_invalid",
    }),
    exactString(input, "candidate_set_digest_scheme", label,
      "darwin_cdhash_candidate_set_jcs_v1", "code_identity_invalid"),
    assertDigest(ownValue(input, "candidate_set_digest", label),
      `${label}.candidate_set_digest`, "code_identity_invalid"),
    requirementFormat,
    requirementText,
    requirementSize,
    requirementDigest,
    assertInteger(ownValue(input, "code_directory_flags", label),
      `${label}.code_directory_flags`, 0, 0xffffffff, "code_identity_invalid"),
    exactString(input, "entitlements_digest_scheme", label,
      "security_entitlements_der_sha256_v1", "code_identity_invalid"),
    assertDigest(ownValue(input, "entitlements_digest", label),
      `${label}.entitlements_digest`, "code_identity_invalid"),
    exactBoolean(input, "hardened_runtime_required", label, true, "code_identity_invalid"),
    exactBoolean(input, "notarization_required", label, true, "code_identity_invalid"),
    exactBoolean(input, "adhoc_allowed", label, false, "code_identity_invalid"),
  ]);
}

function normalizeMachoIdentity(input, label, componentId, byteSize) {
  assertExactObject(input, MACHO_IDENTITY_FIELDS, label, "macho_identity_invalid");
  const fileType = assertInteger(ownValue(input, "file_type", label), `${label}.file_type`,
    COMPONENT_MACHO_FILE_TYPES[componentId], COMPONENT_MACHO_FILE_TYPES[componentId],
    "macho_identity_invalid");
  const sliceOffset = assertInteger(ownValue(input, "slice_offset", label),
    `${label}.slice_offset`, 0, byteSize - 1, "macho_identity_invalid");
  const sliceSize = assertInteger(ownValue(input, "slice_size", label), `${label}.slice_size`,
    1, byteSize, "macho_identity_invalid");
  if (sliceOffset + sliceSize > byteSize) {
    reject("macho_identity_invalid", `${label} slice exceeds the signed artifact`);
  }
  return makeRecord(MACHO_IDENTITY_FIELDS, [
    fileType,
    assertInteger(ownValue(input, "cpu_type", label), `${label}.cpu_type`, 16777228, 16777228,
      "macho_identity_invalid"),
    assertInteger(ownValue(input, "cpu_subtype", label), `${label}.cpu_subtype`, 0, 0xffffffff,
      "macho_identity_invalid"),
    assertInteger(ownValue(input, "macho_flags", label), `${label}.macho_flags`, 0, 0xffffffff,
      "macho_identity_invalid"),
    assertString(ownValue(input, "uuid", label), `${label}.uuid`, {
      pattern: UUID_PATTERN, minimumBytes: 32, maximumBytes: 32,
      code: "macho_identity_invalid",
    }),
    assertDigest(ownValue(input, "load_commands_digest", label),
      `${label}.load_commands_digest`, "macho_identity_invalid"),
    assertDigest(ownValue(input, "code_signature_blob_digest", label),
      `${label}.code_signature_blob_digest`, "macho_identity_invalid"),
    assertDigest(ownValue(input, "text_segment_file_digest", label),
      `${label}.text_segment_file_digest`, "macho_identity_invalid"),
    sliceOffset,
    sliceSize,
  ]);
}

function normalizeLaunchPrincipal(input, label) {
  assertExactObject(input, LAUNCH_PRINCIPAL_FIELDS, label, "launch_principal_invalid");
  return makeRecord(LAUNCH_PRINCIPAL_FIELDS, [
    assertIdentifier(ownValue(input, "principal_id", label), `${label}.principal_id`,
      "launch_principal_invalid"),
    assertInteger(ownValue(input, "uid", label), `${label}.uid`, 1, 0xffffffff,
      "launch_principal_invalid"),
    assertInteger(ownValue(input, "gid", label), `${label}.gid`, 1, 0xffffffff,
      "launch_principal_invalid"),
    assertDigest(ownValue(input, "supplementary_groups_digest", label),
      `${label}.supplementary_groups_digest`, "launch_principal_invalid"),
    assertDigest(ownValue(input, "audit_session_policy_digest", label),
      `${label}.audit_session_policy_digest`, "launch_principal_invalid"),
    assertDigest(ownValue(input, "sandbox_profile_digest", label),
      `${label}.sandbox_profile_digest`, "launch_principal_invalid"),
    exactBoolean(input, "no_login_identity", label, true, "launch_principal_invalid"),
    exactBoolean(input, "clear_supplementary_groups", label, true,
      "launch_principal_invalid"),
    exactBoolean(input, "identity_drop_before_capability_grant", label, true,
      "launch_principal_invalid"),
  ]);
}

function normalizeMappedMeasurement(input, label, machoIdentity) {
  assertExactObject(input, MAPPED_MEASUREMENT_FIELDS, label, "mapped_measurement_invalid");
  const loadedUuid = assertString(ownValue(input, "expected_loaded_uuid", label),
    `${label}.expected_loaded_uuid`, {
      pattern: UUID_PATTERN, minimumBytes: 32, maximumBytes: 32,
      code: "mapped_measurement_invalid",
    });
  if (loadedUuid !== machoIdentity.uuid) {
    reject("mapped_measurement_invalid", `${label} UUID does not bind the Mach-O slice`);
  }
  return makeRecord(MAPPED_MEASUREMENT_FIELDS, [
    exactString(input, "scheme", label, "darwin_running_code_guest_audit_token_v1",
      "mapped_measurement_invalid"),
    assertDigest(ownValue(input, "expected_mapped_text_digest", label),
      `${label}.expected_mapped_text_digest`, "mapped_measurement_invalid"),
    assertDigest(ownValue(input, "expected_mapped_linkedit_digest", label),
      `${label}.expected_mapped_linkedit_digest`, "mapped_measurement_invalid"),
    loadedUuid,
    assertDigest(ownValue(input, "measurement_layout_digest", label),
      `${label}.measurement_layout_digest`, "mapped_measurement_invalid"),
    exactBoolean(input, "require_kernel_audit_token", label, true,
      "mapped_measurement_invalid"),
    exactBoolean(input, "require_pidversion_binding", label, true,
      "mapped_measurement_invalid"),
    exactBoolean(input, "require_running_code_guest_validation", label, true,
      "mapped_measurement_invalid"),
    exactBoolean(input, "require_cdhash_match", label, true, "mapped_measurement_invalid"),
    exactBoolean(input, "require_macho_uuid_match", label, true,
      "mapped_measurement_invalid"),
    exactBoolean(input, "require_pre_grant_measurement", label, true,
      "mapped_measurement_invalid"),
    exactBoolean(input, "require_post_grant_identity_stability", label, true,
      "mapped_measurement_invalid"),
  ]);
}

function normalizeSchemaArtifact(input, label) {
  assertExactObject(input, SCHEMA_ARTIFACT_FIELDS, label, "capability_abi_invalid");
  return makeRecord(SCHEMA_ARTIFACT_FIELDS, [
    assertRelativeArtifactPath(ownValue(input, "artifact_path", label),
      `${label}.artifact_path`, "capability_abi_invalid"),
    assertInteger(ownValue(input, "byte_size", label), `${label}.byte_size`, 2,
      1024 * 1024, "capability_abi_invalid"),
    assertDigest(ownValue(input, "sha256", label), `${label}.sha256`,
      "capability_abi_invalid"),
    exactString(input, "media_type", label, "application/schema+json",
      "capability_abi_invalid"),
    exactString(input, "canonicalization", label, "jcs_rfc8785_v1",
      "capability_abi_invalid"),
    exactString(input, "load_scheme", label, "openat_no_follow_fd_sha256_v1",
      "capability_abi_invalid"),
  ]);
}

function assertEnumValue(value, allowed, label) {
  for (let index = 0; index < allowed.length; index += 1) {
    if (value === allowed[index]) return value;
  }
  reject("capability_abi_invalid", `${label} is unsupported`);
}

function normalizeDescriptorRow(input, index, label) {
  assertExactObject(input, DESCRIPTOR_ROW_FIELDS, label, "capability_abi_invalid");
  const accessMode = assertEnumValue(ownValue(input, "access_mode", label,
    "capability_abi_invalid"), ACCESS_MODES, `${label}.access_mode`);
  const requiredStatusFlags = assertInteger(ownValue(input, "required_status_flags", label),
    `${label}.required_status_flags`, 0, 0xffffffff, "capability_abi_invalid");
  const forbiddenStatusFlags = assertInteger(ownValue(input, "forbidden_status_flags", label),
    `${label}.forbidden_status_flags`, 0, 0xffffffff, "capability_abi_invalid");
  const requiredDescriptorFlags = assertInteger(ownValue(input, "required_descriptor_flags",
    label), `${label}.required_descriptor_flags`, 0, 0xffffffff, "capability_abi_invalid");
  const forbiddenDescriptorFlags = assertInteger(ownValue(input, "forbidden_descriptor_flags",
    label), `${label}.forbidden_descriptor_flags`, 0, 0xffffffff,
    "capability_abi_invalid");
  assertDarwinDescriptorFlagSemantics(accessMode, requiredStatusFlags,
    forbiddenStatusFlags, requiredDescriptorFlags, forbiddenDescriptorFlags,
    null, null, label, "capability_abi_invalid");
  return makeRecord(DESCRIPTOR_ROW_FIELDS, [
    assertInteger(ownValue(input, "ordinal", label), `${label}.ordinal`, index, index,
      "capability_abi_invalid"),
    assertIdentifier(ownValue(input, "role", label), `${label}.role`,
      "capability_abi_invalid"),
    assertEnumValue(ownValue(input, "descriptor_type", label, "capability_abi_invalid"),
      DESCRIPTOR_TYPES, `${label}.descriptor_type`),
    accessMode,
    requiredStatusFlags,
    forbiddenStatusFlags,
    requiredDescriptorFlags,
    forbiddenDescriptorFlags,
    exactBoolean(input, "sender_cloexec_required", label, true, "capability_abi_invalid"),
    exactBoolean(input, "receiver_cloexec_before_ack", label, true,
      "capability_abi_invalid"),
    exactBoolean(input, "identity_recheck_before_effect", label, true,
      "capability_abi_invalid"),
    exactBoolean(input, "close_before_receipt", label, true, "capability_abi_invalid"),
    exactString(input, "transfer_mode", label, "scm_rights_once_v1",
      "capability_abi_invalid"),
  ]);
}

function normalizeCapabilityAbi(input, label) {
  assertExactObject(input, CAPABILITY_ABI_FIELDS, label, "capability_abi_invalid");
  const descriptorCount = assertInteger(ownValue(input, "descriptor_count", label),
    `${label}.descriptor_count`, 1, 32, "capability_abi_invalid");
  const descriptorInputs = ownValue(input, "descriptor_table", label,
    "capability_abi_invalid");
  assertDenseArray(descriptorInputs, `${label}.descriptor_table`, 32,
    "capability_abi_invalid");
  if (descriptorInputs.length !== descriptorCount) {
    reject("capability_abi_invalid", `${label}.descriptor_table count does not match`);
  }
  const descriptors = [];
  const roles = new SafeSet();
  for (let index = 0; index < descriptorInputs.length; index += 1) {
    const row = normalizeDescriptorRow(ownValue(descriptorInputs, `${index}`,
      `${label}.descriptor_table`, "capability_abi_invalid"), index,
    `${label}.descriptor_table[${index}]`);
    if (reflectApply(setHas, roles, [row.role])) {
      reject("capability_abi_invalid", `${label}.descriptor_table roles must be distinct`);
    }
    if (((row.required_status_flags & row.forbidden_status_flags) >>> 0) !== 0
        || ((row.required_descriptor_flags & row.forbidden_descriptor_flags) >>> 0) !== 0) {
      reject("capability_abi_invalid", `${label}.descriptor_table flag sets overlap`);
    }
    reflectApply(setAdd, roles, [row.role]);
    setArrayIndex(descriptors, index, row);
  }
  const requestSchema = normalizeSchemaArtifact(ownValue(input, "request_schema", label),
    `${label}.request_schema`);
  const resultSchema = normalizeSchemaArtifact(ownValue(input, "result_schema", label),
    `${label}.result_schema`);
  const journalSchema = normalizeSchemaArtifact(ownValue(input, "effect_journal_schema", label),
    `${label}.effect_journal_schema`);
  const receiptSchema = normalizeSchemaArtifact(ownValue(input, "receipt_schema", label),
    `${label}.receipt_schema`);
  const schemas = [requestSchema, resultSchema, journalSchema, receiptSchema];
  const paths = new SafeSet();
  const hashes = new SafeSet();
  for (let index = 0; index < schemas.length; index += 1) {
    if (reflectApply(setHas, paths, [schemas[index].artifact_path])
        || reflectApply(setHas, hashes, [schemas[index].sha256])) {
      reject("capability_abi_invalid", `${label} schema artifacts must be distinct`);
    }
    reflectApply(setAdd, paths, [schemas[index].artifact_path]);
    reflectApply(setAdd, hashes, [schemas[index].sha256]);
  }
  return makeRecord(CAPABILITY_ABI_FIELDS, [
    assertIdentifier(ownValue(input, "abi_id", label), `${label}.abi_id`,
      "capability_abi_invalid"),
    assertInteger(ownValue(input, "abi_version", label), `${label}.abi_version`, 1, 1,
      "capability_abi_invalid"),
    requestSchema,
    resultSchema,
    journalSchema,
    receiptSchema,
    descriptorCount,
    makeArray(descriptors),
    exactBoolean(input, "single_grant", label, true, "capability_abi_invalid"),
    exactBoolean(input, "forbid_path_reopen", label, true, "capability_abi_invalid"),
    exactBoolean(input, "close_unexpected_descriptors", label, true,
      "capability_abi_invalid"),
  ]);
}

function normalizeComponent(input, index) {
  const label = `native_prebuild_manifest_v2.components[${index}]`;
  assertExactObject(input, COMPONENT_FIELDS, label, "component_invalid");
  const expectedId = NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2[index];
  const componentId = ownValue(input, "component_id", label, "component_invalid");
  const artifactKind = ownValue(input, "artifact_kind", label, "component_invalid");
  if (componentId !== expectedId || artifactKind !== COMPONENT_KINDS[expectedId]) {
    reject("component_invalid", `${label} is not the required component and artifact kind`);
  }
  const byteSize = assertInteger(ownValue(input, "byte_size", label), `${label}.byte_size`, 1,
    256 * 1024 * 1024, "component_invalid");
  const machoIdentity = normalizeMachoIdentity(ownValue(input, "macho_identity", label),
    `${label}.macho_identity`, componentId, byteSize);
  return makeRecord(COMPONENT_FIELDS, [
    componentId,
    assertRelativeArtifactPath(ownValue(input, "artifact_path", label),
      `${label}.artifact_path`, "component_invalid"),
    artifactKind,
    byteSize,
    assertDigest(ownValue(input, "sha256", label), `${label}.sha256`, "component_invalid"),
    assertDigest(ownValue(input, "source_digest", label), `${label}.source_digest`,
      "component_invalid"),
    assertDigest(ownValue(input, "builder_digest", label), `${label}.builder_digest`,
      "component_invalid"),
    assertDigest(ownValue(input, "toolchain_digest", label), `${label}.toolchain_digest`,
      "component_invalid"),
    assertDigest(ownValue(input, "provenance_digest", label), `${label}.provenance_digest`,
      "component_invalid"),
    normalizeDependencies(ownValue(input, "exact_dynamic_dependencies", label),
      `${label}.exact_dynamic_dependencies`),
    normalizeCodeIdentity(ownValue(input, "code_identity", label),
      `${label}.code_identity`, componentId),
    machoIdentity,
    normalizeLaunchPrincipal(ownValue(input, "launch_principal", label),
      `${label}.launch_principal`),
    normalizeMappedMeasurement(ownValue(input, "mapped_measurement", label),
      `${label}.mapped_measurement`, machoIdentity),
    normalizeCapabilityAbi(ownValue(input, "capability_abi", label),
      `${label}.capability_abi`),
  ]);
}

function normalizeComponents(input) {
  const label = "native_prebuild_manifest_v2.components";
  assertDenseArray(input, label, NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2.length,
    "component_invalid");
  if (input.length !== NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2.length) {
    reject("component_invalid", `${label} must contain the complete required component set`);
  }
  const result = [];
  const allArtifactPaths = [];
  const sets = {
    paths: new SafeSet(),
    artifacts: new SafeSet(),
    cdhashes: new SafeSet(),
    candidateSets: new SafeSet(),
    requirements: new SafeSet(),
    identifiers: new SafeSet(),
    uuids: new SafeSet(),
    principals: new SafeSet(),
    uids: new SafeSet(),
    gids: new SafeSet(),
    abis: new SafeSet(),
  };
  let totalBytes = 0;
  for (let index = 0; index < input.length; index += 1) {
    const component = normalizeComponent(
      ownValue(input, `${index}`, label, "component_invalid"), index,
    );
    for (let priorIndex = 0; priorIndex < allArtifactPaths.length; priorIndex += 1) {
      const priorPath = allArtifactPaths[priorIndex];
      if (reflectApply(stringStartsWith, component.artifact_path, [`${priorPath}/`])
          || reflectApply(stringStartsWith, priorPath, [`${component.artifact_path}/`])) {
        reject("component_invalid", `${label} artifact paths cannot alias directories`);
      }
    }
    const identities = [
      [sets.paths, component.artifact_path, "artifact paths"],
      [sets.artifacts, component.sha256, "artifact hashes"],
      [sets.cdhashes, component.code_identity.selected_cdhash, "selected CDHashes"],
      [sets.candidateSets, component.code_identity.candidate_set_digest,
        "CodeDirectory candidate sets"],
      [sets.requirements, component.code_identity.serialized_sec_requirement_digest,
        "serialized SecRequirements"],
      [sets.identifiers, component.code_identity.signing_identifier, "signing identifiers"],
      [sets.uuids, component.macho_identity.uuid, "Mach-O UUIDs"],
      [sets.principals, component.launch_principal.principal_id, "launch principals"],
      [sets.uids, component.launch_principal.uid, "launch UIDs"],
      [sets.gids, component.launch_principal.gid, "launch GIDs"],
      [sets.abis, component.capability_abi.abi_id, "capability ABI IDs"],
    ];
    for (let identityIndex = 0; identityIndex < identities.length; identityIndex += 1) {
      const identity = identities[identityIndex];
      const set = identity[0];
      const value = identity[1];
      const description = identity[2];
      if (reflectApply(setHas, set, [value])) {
        reject("component_identity_collision", `${label} ${description} must be distinct`);
      }
      reflectApply(setAdd, set, [value]);
    }
    setArrayIndex(allArtifactPaths, allArtifactPaths.length, component.artifact_path);
    const schemaFields = [
      "request_schema", "result_schema", "effect_journal_schema", "receipt_schema",
    ];
    for (let schemaIndex = 0; schemaIndex < schemaFields.length; schemaIndex += 1) {
      const schema = component.capability_abi[schemaFields[schemaIndex]];
      if (reflectApply(setHas, sets.paths, [schema.artifact_path])
          || reflectApply(setHas, sets.artifacts, [schema.sha256])) {
        reject("component_identity_collision",
          `${label} schema paths and hashes must be role-distinct`);
      }
      for (let priorIndex = 0; priorIndex < allArtifactPaths.length; priorIndex += 1) {
        const priorPath = allArtifactPaths[priorIndex];
        if (reflectApply(stringStartsWith, schema.artifact_path, [`${priorPath}/`])
            || reflectApply(stringStartsWith, priorPath, [`${schema.artifact_path}/`])) {
          reject("component_invalid", `${label} schema paths cannot alias artifact directories`);
        }
      }
      reflectApply(setAdd, sets.paths, [schema.artifact_path]);
      reflectApply(setAdd, sets.artifacts, [schema.sha256]);
      setArrayIndex(allArtifactPaths, allArtifactPaths.length, schema.artifact_path);
    }
    totalBytes += component.byte_size;
    if (totalBytes > 768 * 1024 * 1024) {
      reject("component_invalid", `${label} exceeds the total byte bound`);
    }
    setArrayIndex(result, index, component);
  }
  return makeArray(result);
}

function normalizeDeadlinePolicy(input) {
  const label = "native_prebuild_manifest_v2.authority_handoff_policy.deadline_policy";
  assertExactObject(input, DEADLINE_POLICY_FIELDS, label, "deadline_policy_invalid");
  const timeouts = [];
  for (let index = 1; index <= 6; index += 1) {
    const field = DEADLINE_POLICY_FIELDS[index];
    setArrayIndex(timeouts, index - 1, assertInteger(ownValue(input, field, label),
      `${label}.${field}`, 1, 120_000, "deadline_policy_invalid"));
  }
  const total = assertInteger(ownValue(input, "total_timeout_ms", label),
    `${label}.total_timeout_ms`, 1, 300_000, "deadline_policy_invalid");
  let sum = 0;
  for (let index = 0; index < timeouts.length; index += 1) sum += timeouts[index];
  if (total > sum) {
    reject("deadline_policy_invalid", `${label}.total_timeout_ms exceeds phase deadlines`);
  }
  return makeRecord(DEADLINE_POLICY_FIELDS, [
    exactString(input, "clock", label, "mach_continuous_time_v1", "deadline_policy_invalid"),
    timeouts[0],
    timeouts[1],
    timeouts[2],
    timeouts[3],
    timeouts[4],
    timeouts[5],
    total,
    exactBoolean(input, "clamp_to_parent_deadline", label, true, "deadline_policy_invalid"),
    exactBoolean(input, "signed_deadline_in_grant", label, true, "deadline_policy_invalid"),
    exactBoolean(input, "check_before_each_effect", label, true, "deadline_policy_invalid"),
  ]);
}

function normalizeNoncePolicy(input) {
  const label = "native_prebuild_manifest_v2.authority_handoff_policy.nonce_policy";
  assertExactObject(input, NONCE_POLICY_FIELDS, label, "nonce_policy_invalid");
  return makeRecord(NONCE_POLICY_FIELDS, [
    exactString(input, "scheme", label, "getentropy_256bit_monotonic_generation_v1",
      "nonce_policy_invalid"),
    assertInteger(ownValue(input, "entropy_bits", label), `${label}.entropy_bits`, 256, 256,
      "nonce_policy_invalid"),
    assertInteger(ownValue(input, "generation_bits", label), `${label}.generation_bits`, 64, 64,
      "nonce_policy_invalid"),
    exactBoolean(input, "bind_manifest_digest", label, true, "nonce_policy_invalid"),
    exactBoolean(input, "bind_component_id", label, true, "nonce_policy_invalid"),
    exactBoolean(input, "bind_audit_token", label, true, "nonce_policy_invalid"),
    exactBoolean(input, "monotonic_generation", label, true, "nonce_policy_invalid"),
    exactBoolean(input, "single_use", label, true, "nonce_policy_invalid"),
    exactBoolean(input, "durable_replay_fence_before_grant", label, true,
      "nonce_policy_invalid"),
  ]);
}

function normalizeDurableExchangePolicy(input) {
  const label = "native_prebuild_manifest_v2.authority_handoff_policy.durable_exchange_policy";
  assertExactObject(input, DURABLE_EXCHANGE_POLICY_FIELDS, label,
    "durable_exchange_policy_invalid");
  const values = [exactString(input, "scheme", label,
    "durable_grant_go_receipt_outbox_v1", "durable_exchange_policy_invalid")];
  const schemaPaths = new SafeSet();
  const schemaHashes = new SafeSet();
  for (let index = 1; index <= 4; index += 1) {
    const field = DURABLE_EXCHANGE_POLICY_FIELDS[index];
    const schema = normalizeSchemaArtifact(ownValue(input, field, label),
      `${label}.${field}`);
    if (reflectApply(setHas, schemaPaths, [schema.artifact_path])
        || reflectApply(setHas, schemaHashes, [schema.sha256])) {
      reject("durable_exchange_policy_invalid",
        `${label} durable record schema artifacts must be distinct`);
    }
    reflectApply(setAdd, schemaPaths, [schema.artifact_path]);
    reflectApply(setAdd, schemaHashes, [schema.sha256]);
    setArrayIndex(values, index, schema);
  }
  for (let index = 5; index < DURABLE_EXCHANGE_POLICY_FIELDS.length; index += 1) {
    setArrayIndex(values, index, exactBoolean(input, DURABLE_EXCHANGE_POLICY_FIELDS[index],
      label, true, "durable_exchange_policy_invalid"));
  }
  return makeRecord(DURABLE_EXCHANGE_POLICY_FIELDS, values);
}

function normalizeHandoffPolicy(input) {
  const label = "native_prebuild_manifest_v2.authority_handoff_policy";
  assertExactObject(input, HANDOFF_POLICY_FIELDS, label, "handoff_policy_invalid");
  return makeRecord(HANDOFF_POLICY_FIELDS, [
    exactString(input, "scheme", label, NATIVE_PREBUILD_HANDOFF_SCHEME,
      "handoff_policy_invalid"),
    exactString(input, "supervisor_component_id", label, "privileged_launcher",
      "handoff_policy_invalid"),
    exactString(input, "supervisor_role", label, "post_exec_capability_supervisor",
      "handoff_policy_invalid"),
    exactString(input, "process_lineage_scheme", label,
      "audit_token_pidversion_instance_start_direct_parent_v1", "handoff_policy_invalid"),
    exactString(input, "listener_identity_scheme", label,
      "root_owned_single_launch_listener_generation_v1", "handoff_policy_invalid"),
    exactString(input, "post_exec_connection_scheme", label,
      "fresh_post_exec_af_unix_connection_v1", "handoff_policy_invalid"),
    exactString(input, "capability_set_digest_scheme", label,
      "ordered_descriptor_semantics_sha256_v1", "handoff_policy_invalid"),
    exactString(input, "grant_go_binding_scheme", label,
      "durable_grant_go_sequence_binding_v1", "handoff_policy_invalid"),
    exactString(input, "transport", label, "af_unix_sock_stream_scm_rights_v1",
      "handoff_policy_invalid"),
    exactString(input, "peer_identity_scheme", label,
      "local_peertoken_audit_token_pidversion_v1", "handoff_policy_invalid"),
    exactString(input, "running_code_validation_scheme", label,
      "seccodecopyguestwithattributes_audit_v1", "handoff_policy_invalid"),
    exactString(input, "security_requirement_validation_scheme", label,
      "serialized_secrequirement_exact_match_v1", "handoff_policy_invalid"),
    normalizeDeadlinePolicy(ownValue(input, "deadline_policy", label)),
    normalizeNoncePolicy(ownValue(input, "nonce_policy", label)),
    normalizeDurableExchangePolicy(ownValue(input, "durable_exchange_policy", label)),
  ]);
}

function normalizeDoctorPolicy(input) {
  const label = "native_prebuild_manifest_v2.doctor_policy";
  assertExactObject(input, DOCTOR_POLICY_FIELDS, label, "doctor_policy_invalid");
  return makeRecord(DOCTOR_POLICY_FIELDS, [
    assertDigest(ownValue(input, "external_keyring_policy_digest", label),
      `${label}.external_keyring_policy_digest`, "doctor_policy_invalid"),
    assertDigest(ownValue(input, "live_attestor_policy_digest", label),
      `${label}.live_attestor_policy_digest`, "doctor_policy_invalid"),
    assertInteger(ownValue(input, "max_evidence_age_ms", label),
      `${label}.max_evidence_age_ms`, 1, 3_600_000, "doctor_policy_invalid"),
    exactBoolean(input, "require_external_immutable_keyring", label, true,
      "doctor_policy_invalid"),
    exactBoolean(input, "require_live_native_attestation", label, true,
      "doctor_policy_invalid"),
    exactBoolean(input, "require_native_transcript_authentication", label, true,
      "doctor_policy_invalid"),
  ]);
}

function assertAllSchemaArtifactsDistinct(components, handoff) {
  const paths = new SafeSet();
  const hashes = new SafeSet();
  const allPaths = [];
  function addArtifact(path, hash) {
    if (reflectApply(setHas, paths, [path]) || reflectApply(setHas, hashes, [hash])) {
      reject("schema_artifact_collision", "signed code and schema artifacts must be distinct");
    }
    for (let index = 0; index < allPaths.length; index += 1) {
      if (reflectApply(stringStartsWith, path, [`${allPaths[index]}/`])
          || reflectApply(stringStartsWith, allPaths[index], [`${path}/`])) {
        reject("schema_artifact_collision", "signed artifact paths cannot alias directories");
      }
    }
    reflectApply(setAdd, paths, [path]);
    reflectApply(setAdd, hashes, [hash]);
    setArrayIndex(allPaths, allPaths.length, path);
  }
  const abiSchemaFields = [
    "request_schema", "result_schema", "effect_journal_schema", "receipt_schema",
  ];
  for (let index = 0; index < components.length; index += 1) {
    addArtifact(components[index].artifact_path, components[index].sha256);
    for (let schemaIndex = 0; schemaIndex < abiSchemaFields.length; schemaIndex += 1) {
      const schema = components[index].capability_abi[abiSchemaFields[schemaIndex]];
      addArtifact(schema.artifact_path, schema.sha256);
    }
  }
  const durable = handoff.durable_exchange_policy;
  const durableFields = [
    "grant_record_schema", "go_record_schema", "receipt_record_schema",
    "outbox_record_schema",
  ];
  for (let index = 0; index < durableFields.length; index += 1) {
    const schema = durable[durableFields[index]];
    addArtifact(schema.artifact_path, schema.sha256);
  }
}

function normalizeReleaseManifestV2(input) {
  const label = "native_prebuild_manifest_v2";
  assertExactObject(input, MANIFEST_FIELDS, label, "manifest_invalid");
  const issuedAt = assertTimestamp(ownValue(input, "issued_at", label), `${label}.issued_at`);
  const expiresAt = assertTimestamp(ownValue(input, "expires_at", label), `${label}.expires_at`);
  if (timestampMilliseconds(expiresAt, `${label}.expires_at`)
      <= timestampMilliseconds(issuedAt, `${label}.issued_at`)) {
    reject("time_invalid", `${label} expiry must follow issuance`);
  }
  const kind = ownValue(input, "kind", label, "manifest_invalid");
  if (kind !== "native_prebuild_release_manifest") {
    reject("manifest_invalid", `${label}.kind is invalid`);
  }
  const components = normalizeComponents(ownValue(input, "components", label));
  const handoff = normalizeHandoffPolicy(ownValue(input, "authority_handoff_policy", label));
  assertAllSchemaArtifactsDistinct(components, handoff);
  return makeRecord(MANIFEST_FIELDS, [
    assertInteger(ownValue(input, "version", label), `${label}.version`, 2, 2,
      "manifest_invalid"),
    kind,
    assertString(ownValue(input, "package_name", label), `${label}.package_name`, {
      pattern: PACKAGE_PATTERN, maximumBytes: 140, code: "package_identity_invalid",
    }),
    assertString(ownValue(input, "package_version", label), `${label}.package_version`, {
      pattern: VERSION_PATTERN, maximumBytes: 128, code: "package_identity_invalid",
    }),
    assertOpaqueToken(ownValue(input, "release_id", label), `${label}.release_id`,
      "release_identity_invalid"),
    assertInteger(ownValue(input, "release_epoch", label), `${label}.release_epoch`, 1,
      Number.MAX_SAFE_INTEGER, "release_identity_invalid"),
    normalizeTarget(ownValue(input, "target", label)),
    components,
    assertDigest(ownValue(input, "source_tree_digest", label), `${label}.source_tree_digest`),
    assertDigest(ownValue(input, "builder_identity_digest", label),
      `${label}.builder_identity_digest`),
    assertDigest(ownValue(input, "toolchain_manifest_digest", label),
      `${label}.toolchain_manifest_digest`),
    assertDigest(ownValue(input, "provenance_statement_digest", label),
      `${label}.provenance_statement_digest`),
    assertDigest(ownValue(input, "principal_acl_policy_digest", label),
      `${label}.principal_acl_policy_digest`),
    assertDigest(ownValue(input, "immutable_install_policy_digest", label),
      `${label}.immutable_install_policy_digest`),
    handoff,
    normalizeDoctorPolicy(ownValue(input, "doctor_policy", label)),
    issuedAt,
    expiresAt,
  ]);
}

function digestReleaseManifestV2(input) {
  return domainDigest(NATIVE_PREBUILD_MANIFEST_V2_DOMAIN, normalizeReleaseManifestV2(input));
}

function releaseSignatureMessageV2(input) {
  const label = "native_prebuild_signature_claim_v2";
  const fields = ["manifest_digest", "key_id", "public_key_digest", "trust_epoch"];
  assertExactObject(input, fields, label, "signature_claim_invalid");
  const claim = makeRecord(fields, [
    assertDigest(ownValue(input, "manifest_digest", label), `${label}.manifest_digest`),
    assertOpaqueToken(ownValue(input, "key_id", label), `${label}.key_id`,
      "signature_claim_invalid"),
    assertDigest(ownValue(input, "public_key_digest", label), `${label}.public_key_digest`,
      "signature_claim_invalid"),
    assertInteger(ownValue(input, "trust_epoch", label), `${label}.trust_epoch`, 1,
      Number.MAX_SAFE_INTEGER, "signature_claim_invalid"),
  ]);
  return bufferFrom(`${NATIVE_PREBUILD_SIGNATURE_V2_DOMAIN}\0${domainDigest(
    NATIVE_PREBUILD_SIGNATURE_V2_DOMAIN, claim,
  )}`, "utf8");
}

function assertCanonicalBase64Url(value, label, expectedBytes, code) {
  assertString(value, label, { pattern: BASE64URL_PATTERN, maximumBytes: 24 * 1024, code });
  const bytes = bufferFrom(value, "base64url");
  if ((expectedBytes != null && bytes.length !== expectedBytes)
      || reflectApply(bufferToString, bytes, ["base64url"]) !== value) {
    reject(code, `${label} is not canonical base64url`);
  }
  return bytes;
}

function publicKeyDigest(publicKeyDer) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [publicKeyDer]);
  return reflectApply(hashDigest, hash, ["hex"]);
}

function normalizeSortedStrings(input, label, validator, maximum, allowEmpty, code) {
  assertDenseArray(input, label, maximum, code);
  if (!allowEmpty && input.length === 0) reject(code, `${label} cannot be empty`);
  const values = [];
  let previous = null;
  for (let index = 0; index < input.length; index += 1) {
    const value = validator(ownValue(input, `${index}`, label, code), `${label}[${index}]`);
    if (previous != null && value <= previous) {
      reject(code, `${label} must be strictly sorted and unique`);
    }
    setArrayIndex(values, index, value);
    previous = value;
  }
  return makeArray(values);
}

function normalizeFixedComponents(input, label, code) {
  assertDenseArray(input, label, NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2.length, code);
  if (input.length !== NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2.length) {
    reject(code, `${label} is incomplete`);
  }
  const values = [];
  for (let index = 0; index < NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2.length; index += 1) {
    const value = ownValue(input, `${index}`, label, code);
    if (value !== NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2[index]) {
      reject(code, `${label} is not the closed v2 component set`);
    }
    setArrayIndex(values, index, value);
  }
  return makeArray(values);
}

function normalizeTrustKey(input, index) {
  const label = `native_prebuild_trust_policy_v2.keys[${index}]`;
  assertExactObject(input, TRUST_KEY_FIELDS, label, "trust_policy_invalid");
  const derText = ownValue(input, "public_key_spki_der", label, "trust_policy_invalid");
  const der = assertCanonicalBase64Url(derText, `${label}.public_key_spki_der`, null,
    "public_key_invalid");
  const derHex = reflectApply(bufferToString, der, ["hex"]);
  if (der.length !== 44 || !reflectApply(regexpTest, ED25519_SPKI_HEX_PATTERN, [derHex])) {
    reject("public_key_invalid", `${label} is not canonical Ed25519 SPKI`);
  }
  let key;
  try {
    key = reflectApply(cryptoCreatePublicKey, crypto, [{ key: der, type: "spki", format: "der" }]);
  } catch {
    reject("public_key_invalid", `${label} is not a public key`);
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    reject("public_key_invalid", `${label} must contain an Ed25519 public key`);
  }
  const digest = assertDigest(ownValue(input, "public_key_digest", label),
    `${label}.public_key_digest`, "public_key_invalid");
  if (digest !== publicKeyDigest(der)) {
    reject("public_key_invalid", `${label}.public_key_digest does not bind the SPKI key`);
  }
  const revoked = assertBoolean(ownValue(input, "revoked", label), `${label}.revoked`,
    "trust_policy_invalid");
  const revocationEpoch = assertInteger(ownValue(input, "revocation_epoch", label),
    `${label}.revocation_epoch`, 0, Number.MAX_SAFE_INTEGER, "trust_policy_invalid");
  if ((!revoked && revocationEpoch !== 0) || (revoked && revocationEpoch < 1)) {
    reject("trust_policy_invalid", `${label} revocation fields are inconsistent`);
  }
  const notBefore = assertTimestamp(ownValue(input, "not_before", label),
    `${label}.not_before`, "trust_policy_invalid");
  const notAfter = assertTimestamp(ownValue(input, "not_after", label),
    `${label}.not_after`, "trust_policy_invalid");
  if (timestampMilliseconds(notAfter, `${label}.not_after`, "trust_policy_invalid")
      <= timestampMilliseconds(notBefore, `${label}.not_before`, "trust_policy_invalid")) {
    reject("trust_policy_invalid", `${label} key validity window is invalid`);
  }
  return {
    normalized: makeRecord(TRUST_KEY_FIELDS, [
      assertOpaqueToken(ownValue(input, "key_id", label), `${label}.key_id`,
        "trust_policy_invalid"),
      derText,
      digest,
      assertInteger(ownValue(input, "trust_epoch", label), `${label}.trust_epoch`, 1,
        Number.MAX_SAFE_INTEGER, "trust_policy_invalid"),
      notBefore,
      notAfter,
      revoked,
      revocationEpoch,
      normalizeSortedStrings(ownValue(input, "allowed_package_names", label),
        `${label}.allowed_package_names`, (value, itemLabel) => assertString(value, itemLabel, {
          pattern: PACKAGE_PATTERN, maximumBytes: 140, code: "trust_policy_invalid",
        }), 32, false, "trust_policy_invalid"),
      normalizeFixedComponents(ownValue(input, "allowed_component_ids", label),
        `${label}.allowed_component_ids`, "trust_policy_invalid"),
    ]),
    key,
  };
}

function normalizeTrustPolicyV2(input) {
  const label = "native_prebuild_trust_policy_v2";
  assertExactObject(input, TRUST_POLICY_FIELDS, label, "trust_policy_invalid");
  const kind = ownValue(input, "kind", label, "trust_policy_invalid");
  if (kind !== "native_prebuild_trust_policy") {
    reject("trust_policy_invalid", `${label}.kind is invalid`);
  }
  const currentEpoch = assertInteger(ownValue(input, "current_trust_epoch", label),
    `${label}.current_trust_epoch`, 1, Number.MAX_SAFE_INTEGER, "trust_policy_invalid");
  const keyInputs = ownValue(input, "keys", label, "trust_policy_invalid");
  assertDenseArray(keyInputs, `${label}.keys`, 32, "trust_policy_invalid");
  if (keyInputs.length < 1) reject("trust_policy_invalid", `${label}.keys cannot be empty`);
  const keys = [];
  const runtimeKeys = [];
  const spkis = new SafeSet();
  const digests = new SafeSet();
  let previous = null;
  for (let index = 0; index < keyInputs.length; index += 1) {
    const entry = normalizeTrustKey(ownValue(keyInputs, `${index}`, `${label}.keys`,
      "trust_policy_invalid"), index);
    if (previous != null && entry.normalized.key_id <= previous) {
      reject("trust_policy_invalid", `${label}.keys must be strictly sorted and unique`);
    }
    if (entry.normalized.trust_epoch > currentEpoch
        || entry.normalized.revocation_epoch > currentEpoch) {
      reject("trust_policy_invalid", `${label}.keys contain a future epoch`);
    }
    if (reflectApply(setHas, spkis, [entry.normalized.public_key_spki_der])
        || reflectApply(setHas, digests, [entry.normalized.public_key_digest])) {
      reject("trust_policy_invalid", `${label}.keys cannot alias Ed25519 key material`);
    }
    reflectApply(setAdd, spkis, [entry.normalized.public_key_spki_der]);
    reflectApply(setAdd, digests, [entry.normalized.public_key_digest]);
    setArrayIndex(keys, index, entry.normalized);
    setArrayIndex(runtimeKeys, index, entry.key);
    previous = entry.normalized.key_id;
  }
  return {
    normalized: makeRecord(TRUST_POLICY_FIELDS, [
      assertInteger(ownValue(input, "version", label), `${label}.version`, 2, 2,
        "trust_policy_invalid"),
      kind,
      currentEpoch,
      assertInteger(ownValue(input, "minimum_release_epoch", label),
        `${label}.minimum_release_epoch`, 1, Number.MAX_SAFE_INTEGER,
        "trust_policy_invalid"),
      normalizeSortedStrings(ownValue(input, "revoked_release_ids", label),
        `${label}.revoked_release_ids`, (value, itemLabel) => assertOpaqueToken(value,
          itemLabel, "trust_policy_invalid"), 256, true, "trust_policy_invalid"),
      normalizeSortedStrings(ownValue(input, "revoked_manifest_digests", label),
        `${label}.revoked_manifest_digests`, (value, itemLabel) => assertDigest(value,
          itemLabel, "trust_policy_invalid"), 256, true, "trust_policy_invalid"),
      makeArray(keys),
    ]),
    runtimeKeys,
  };
}

function normalizeAuthentication(input, manifestDigest) {
  const label = "native_prebuild_release_envelope_v2.authentication";
  assertExactObject(input, AUTHENTICATION_FIELDS, label, "authentication_invalid");
  const signedDigest = assertDigest(ownValue(input, "signed_manifest_digest", label),
    `${label}.signed_manifest_digest`, "authentication_invalid");
  if (signedDigest !== manifestDigest) {
    reject("authentication_invalid", `${label} does not bind the manifest digest`);
  }
  const signature = assertString(ownValue(input, "signature", label), `${label}.signature`, {
    pattern: SIGNATURE_PATTERN, minimumBytes: 86, maximumBytes: 86, code: "signature_invalid",
  });
  assertCanonicalBase64Url(signature, `${label}.signature`, 64, "signature_invalid");
  return makeRecord(AUTHENTICATION_FIELDS, [
    exactString(input, "scheme", label, "ed25519", "authentication_invalid"),
    exactString(input, "key_usage", label, NATIVE_PREBUILD_KEY_V2_USAGE,
      "authentication_invalid"),
    assertOpaqueToken(ownValue(input, "key_id", label), `${label}.key_id`,
      "authentication_invalid"),
    assertDigest(ownValue(input, "public_key_digest", label), `${label}.public_key_digest`,
      "authentication_invalid"),
    assertInteger(ownValue(input, "trust_epoch", label), `${label}.trust_epoch`, 1,
      Number.MAX_SAFE_INTEGER, "authentication_invalid"),
    signedDigest,
    signature,
  ]);
}

function normalizeEnvelopeV2(input) {
  const label = "native_prebuild_release_envelope_v2";
  assertExactObject(input, ENVELOPE_FIELDS, label, "envelope_invalid");
  const kind = ownValue(input, "kind", label, "envelope_invalid");
  const signatureDomain = ownValue(input, "signature_domain", label, "envelope_invalid");
  if (kind !== "signed_native_prebuild_release"
      || signatureDomain !== NATIVE_PREBUILD_SIGNATURE_V2_DOMAIN) {
    reject("domain_invalid", `${label} kind or signature domain is invalid`);
  }
  const manifest = normalizeReleaseManifestV2(ownValue(input, "manifest", label));
  const manifestDigest = assertDigest(ownValue(input, "manifest_digest", label),
    `${label}.manifest_digest`, "manifest_digest_invalid");
  if (manifestDigest !== domainDigest(NATIVE_PREBUILD_MANIFEST_V2_DOMAIN, manifest)) {
    reject("manifest_digest_invalid", `${label}.manifest_digest does not match the manifest`);
  }
  return makeRecord(ENVELOPE_FIELDS, [
    assertInteger(ownValue(input, "version", label), `${label}.version`, 2, 2,
      "envelope_invalid"),
    kind,
    signatureDomain,
    manifest,
    manifestDigest,
    normalizeAuthentication(ownValue(input, "authentication", label), manifestDigest),
  ]);
}

function verifyReleaseEnvelopeV2(input) {
  const label = "native_prebuild_release_verification_v2";
  const fields = ["envelope", "trust_policy", "now"];
  assertExactObject(input, fields, label, "verification_input_invalid");
  const envelope = normalizeEnvelopeV2(ownValue(input, "envelope", label));
  const trust = normalizeTrustPolicyV2(ownValue(input, "trust_policy", label));
  const now = assertTimestamp(ownValue(input, "now", label), `${label}.now`);
  const nowMs = timestampMilliseconds(now, `${label}.now`);
  const manifest = envelope.manifest;
  if (manifest.release_epoch < trust.normalized.minimum_release_epoch) {
    reject("release_epoch_rejected", "release epoch is below the trust-policy floor");
  }
  for (let index = 0; index < trust.normalized.revoked_release_ids.length; index += 1) {
    if (trust.normalized.revoked_release_ids[index] === manifest.release_id) {
      reject("release_revoked", "release ID is emergency-revoked");
    }
  }
  for (let index = 0; index < trust.normalized.revoked_manifest_digests.length; index += 1) {
    if (trust.normalized.revoked_manifest_digests[index] === envelope.manifest_digest) {
      reject("manifest_revoked", "manifest digest is emergency-revoked");
    }
  }
  if (nowMs < timestampMilliseconds(manifest.issued_at, "manifest.issued_at")
      || nowMs >= timestampMilliseconds(manifest.expires_at, "manifest.expires_at")) {
    reject("release_time_rejected", "release is not valid at the supplied trusted time");
  }
  const auth = envelope.authentication;
  let keyIndex = -1;
  for (let index = 0; index < trust.normalized.keys.length; index += 1) {
    if (trust.normalized.keys[index].key_id === auth.key_id) keyIndex = index;
  }
  if (keyIndex < 0) reject("untrusted_key", "release key is not in the supplied trust policy");
  const keyRecord = trust.normalized.keys[keyIndex];
  if (keyRecord.revoked) reject("revoked_key", "release key is revoked");
  if (keyRecord.trust_epoch !== auth.trust_epoch
      || auth.trust_epoch > trust.normalized.current_trust_epoch
      || keyRecord.public_key_digest !== auth.public_key_digest) {
    reject("trust_binding_rejected", "release authentication does not bind the trusted key");
  }
  let packageAllowed = false;
  for (let index = 0; index < keyRecord.allowed_package_names.length; index += 1) {
    if (keyRecord.allowed_package_names[index] === manifest.package_name) packageAllowed = true;
  }
  if (!packageAllowed
      || !arraysEqual(keyRecord.allowed_component_ids,
        NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2)) {
    reject("key_scope_rejected", "release package or component set is outside key scope");
  }
  if (nowMs < timestampMilliseconds(keyRecord.not_before, "key.not_before")
      || nowMs >= timestampMilliseconds(keyRecord.not_after, "key.not_after")) {
    reject("key_time_rejected", "release key is not valid at the supplied trusted time");
  }
  const claim = {
    manifest_digest: envelope.manifest_digest,
    key_id: auth.key_id,
    public_key_digest: auth.public_key_digest,
    trust_epoch: auth.trust_epoch,
  };
  let signatureValid = false;
  try {
    signatureValid = reflectApply(cryptoVerify, crypto, [
      null,
      releaseSignatureMessageV2(claim),
      trust.runtimeKeys[keyIndex],
      bufferFrom(auth.signature, "base64url"),
    ]);
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) reject("signature_invalid", "Ed25519 release signature failed");
  return objectFreeze({
    version: NATIVE_PREBUILD_TRUST_V2_VERSION,
    kind: "verified_native_prebuild_release_diagnostic_v2",
    manifest,
    manifest_digest: envelope.manifest_digest,
    envelope_digest: domainDigest(NATIVE_PREBUILD_ENVELOPE_V2_DOMAIN, envelope),
    key_id: keyRecord.key_id,
    public_key_digest: keyRecord.public_key_digest,
    trust_epoch: keyRecord.trust_epoch,
    release_signature_valid: true,
    assurance: "ed25519_release_signature_only_non_authorizing_v2",
    external_immutable_keyring_observed: false,
    live_native_attestation_observed: false,
    production_ready: false,
    hardware_access_authorized: false,
    authoritative: false,
    blockers: V2_VERIFICATION_BLOCKERS,
  });
}

module.exports = {
  NATIVE_PREBUILD_ENVELOPE_V2_DOMAIN,
  NATIVE_PREBUILD_HANDOFF_SCHEME,
  NATIVE_PREBUILD_KEY_V2_USAGE,
  NATIVE_PREBUILD_MANIFEST_V2_DOMAIN,
  NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2,
  NATIVE_PREBUILD_SIGNATURE_V2_DOMAIN,
  NATIVE_PREBUILD_TRUST_V2_VERSION,
  V2_VERIFICATION_BLOCKERS,
  digestReleaseManifestV2,
  releaseSignatureMessageV2,
  verifyReleaseEnvelopeV2,
};
