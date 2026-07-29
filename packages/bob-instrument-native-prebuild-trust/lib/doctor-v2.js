"use strict";

const {
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
  assertUint64Decimal,
  domainDigest,
  makeArray,
  makeRecord,
  ownValue,
  reject,
  setArrayIndex,
  timestampMilliseconds,
} = require("./data-contract");
const {
  NATIVE_PREBUILD_HANDOFF_SCHEME,
  NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2,
  NATIVE_PREBUILD_TRUST_V2_VERSION,
  verifyReleaseEnvelopeV2,
} = require("./release-trust-v2");

const objectFreeze = Object.freeze;
const SafeSet = Set;
const setAdd = Set.prototype.add;
const setHas = Set.prototype.has;
const reflectApply = Reflect.apply;
const bigintFromString = BigInt;
const EMPTY_DIGEST = "0".repeat(64);

const NATIVE_PREBUILD_ATTESTATION_V2_DOMAIN =
  "hacker-bob/native-prebuild-post-exec-attestation-evidence/v2";
const NATIVE_PREBUILD_COMPONENT_BINDING_V2_DOMAIN =
  "hacker-bob/native-prebuild-component-attestation-binding/v2";
const NATIVE_PREBUILD_OBSERVED_MACHO_V2_DOMAIN =
  "hacker-bob/native-prebuild-observed-macho/v2";
const NATIVE_PREBUILD_OBSERVED_PRINCIPAL_V2_DOMAIN =
  "hacker-bob/native-prebuild-observed-principal/v2";
const NATIVE_PREBUILD_OBSERVED_MAPPED_V2_DOMAIN =
  "hacker-bob/native-prebuild-observed-mapped-measurement/v2";
const NATIVE_PREBUILD_OBSERVED_ABI_V2_DOMAIN =
  "hacker-bob/native-prebuild-observed-capability-abi/v2";
const NATIVE_PREBUILD_HANDOFF_SESSION_V2_DOMAIN =
  "hacker-bob/native-prebuild-handoff-session-transcript/v2";
const NATIVE_PREBUILD_CAPABILITY_SET_V2_DOMAIN =
  "hacker-bob/native-prebuild-observed-capability-set/v2";
const NATIVE_PREBUILD_GRANT_RECORD_V2_DOMAIN =
  "hacker-bob/native-prebuild-authenticated-grant-record/v2";
const NATIVE_PREBUILD_GO_RECORD_V2_DOMAIN =
  "hacker-bob/native-prebuild-authenticated-go-record/v2";

const DOCTOR_V2_STATUSES = objectFreeze([
  "unavailable",
  "blocked",
  "diagnostic_complete_non_authorizing",
]);
const NATIVE_PREBUILD_RECIPIENT_COMPONENTS_V2 = objectFreeze([
  "native_ipc_acceptor",
  "chameleon_cdc_custody",
  "safety_watchdog",
  "lifecycle_custodian",
  "native_dispatch_custodian",
]);

const CONTEXT_FIELDS = objectFreeze([
  "now", "expected_manifest_digest", "expected_package_name", "expected_package_version",
  "expected_release_epoch", "host_os", "host_architecture", "host_node_major",
  "host_napi_version", "principal_acl_policy_digest",
  "expected_principal_acl_evidence_digest", "immutable_install_policy_digest",
  "expected_immutable_install_evidence_digest", "expected_install_identity_digest",
  "external_keyring_policy_digest", "expected_external_keyring_evidence_digest",
  "expected_external_keyring_identity_digest", "live_attestor_policy_digest",
  "expected_live_attestor_identity_digest", "expected_replay_fence_identity_digest",
  "expected_replay_fence_snapshot_digest",
]);
const DOCTOR_INPUT_FIELDS = objectFreeze([
  "envelope", "trust_policy", "evaluation_context", "live_attestation",
]);
const EVIDENCE_BODY_FIELDS = objectFreeze([
  "version", "kind", "manifest_digest", "evidence_id", "observed_at", "valid_until",
  "host", "external_keyring", "immutable_install", "attestor", "handoff", "components",
]);
const EVIDENCE_FIELDS = objectFreeze([
  "version", "kind", "manifest_digest", "evidence_id", "observed_at", "valid_until",
  "host", "external_keyring", "immutable_install", "attestor", "handoff", "components",
  "attestation_digest",
]);
const HOST_FIELDS = objectFreeze(["os", "architecture", "node_major", "napi_version"]);
const KEYRING_FIELDS = objectFreeze([
  "policy_digest", "evidence_digest", "keyring_identity_digest",
  "immutable_storage_evidence_digest", "revocation_snapshot_digest", "observed_trust_epoch",
  "root_owned", "immutable", "external_to_caller", "verified_by_native_attestor",
]);
const INSTALL_FIELDS = objectFreeze([
  "policy_digest", "evidence_digest", "install_identity_digest",
  "principal_acl_policy_digest", "principal_acl_evidence_digest", "root_owned", "immutable",
  "descriptor_walk_complete", "no_symlink_walk", "native_attested",
]);
const ATTESTOR_FIELDS = objectFreeze([
  "implementation_digest", "loaded_image_digest", "identity_digest", "audit_token_digest",
  "native_process", "live_observation", "external_keyring_read_native",
  "caller_js_authority",
]);
const HANDOFF_FIELDS = objectFreeze([
  "scheme", "supervisor_identity", "process_lineage_scheme", "listener_identity_scheme",
  "post_exec_connection_scheme", "capability_set_digest_scheme", "grant_go_binding_scheme",
  "transport", "peer_identity_scheme", "running_code_validation_scheme",
  "security_requirement_validation_scheme", "deadline_clock", "nonce_scheme",
  "nonce_entropy_bits", "nonce_generation_bits", "durable_exchange_scheme",
  "grant_record_schema", "go_record_schema", "receipt_record_schema",
  "outbox_record_schema", "replay_fence_identity_digest", "replay_fence_snapshot_digest",
  "previous_committed_generation", "committed_generation", "sessions",
  "all_capabilities_withheld_until_attestation",
  "all_scm_rights_single_grant", "all_receipts_authenticated", "replay_fence_durable",
  "outbox_recovery_complete", "native_transcript_authenticated",
]);
const SESSION_FIELDS = objectFreeze([
  "component_id", "handoff_session_id", "worker_lineage", "exchange_binding",
  "started_at", "challenged_at", "attested_at", "grant_recorded_at",
  "scm_rights_acked_at", "go_recorded_at", "effect_recorded_at", "receipt_recorded_at",
  "outbox_recorded_at", "completed_at", "receipt_record_digest", "outbox_record_digest",
  "handoff_session_digest",
  "attested_before_grant", "single_scm_rights_grant", "grant_fsynced_before_go",
  "go_after_scm_rights_ack", "receipt_fsynced_before_success", "outbox_fsynced_before_ack",
  "capabilities_closed_before_receipt", "receipt_authenticated", "effect_receipt_correlated",
]);
const SESSION_BODY_FIELDS = objectFreeze([
  "component_id", "handoff_session_id", "worker_lineage", "exchange_binding",
  "started_at", "challenged_at", "attested_at", "grant_recorded_at",
  "scm_rights_acked_at", "go_recorded_at", "effect_recorded_at", "receipt_recorded_at",
  "outbox_recorded_at", "completed_at", "receipt_record_digest", "outbox_record_digest",
  "attested_before_grant",
  "single_scm_rights_grant", "grant_fsynced_before_go", "go_after_scm_rights_ack",
  "receipt_fsynced_before_success", "outbox_fsynced_before_ack",
  "capabilities_closed_before_receipt", "receipt_authenticated", "effect_receipt_correlated",
]);
const COMPONENT_FIELDS = objectFreeze([
  "component_id", "artifact_sha256", "on_disk_fd_identity_digest", "component_handoff",
  "signature_kind", "code_type", "team_identifier",
  "signing_identifier", "cdhash_algorithm", "selected_cdhash",
  "candidate_set_digest_scheme", "candidate_set_digest",
  "serialized_sec_requirement_digest", "code_directory_flags", "entitlements_digest_scheme",
  "entitlements_digest",
  "candidate_set_enumeration_complete", "serialized_sec_requirement_instantiated",
  "code_signing_information_complete", "hardened_runtime", "notarization_verified", "adhoc",
  "macho_identity",
  "launch_principal", "mapped_measurement", "capability_abi",
  "running_code_identity_digest", "component_binding_digest",
  "static_code_fd_validated", "running_code_guest_validated", "audit_token_kernel_originated",
  "pre_grant_measurement_complete", "post_grant_identity_stable",
]);
const MACHO_FIELDS = objectFreeze([
  "file_type", "cpu_type", "cpu_subtype", "macho_flags", "uuid",
  "load_commands_digest", "code_signature_blob_digest", "text_segment_file_digest",
  "slice_offset", "slice_size",
]);
const PRINCIPAL_FIELDS = objectFreeze([
  "principal_id", "uid", "gid", "supplementary_groups_digest",
  "audit_session_policy_digest", "sandbox_profile_digest", "no_login_identity",
  "supplementary_groups_cleared", "identity_dropped_before_capability_grant",
]);
const MAPPED_FIELDS = objectFreeze([
  "scheme", "mapped_text_digest", "mapped_linkedit_digest", "loaded_uuid",
  "measurement_layout_digest", "measurement_digest", "audit_token_bound",
  "pidversion_bound", "seccode_guest_validated", "cdhash_matched", "macho_uuid_matched",
]);
const MAPPED_BODY_FIELDS = objectFreeze([
  "scheme", "mapped_text_digest", "mapped_linkedit_digest", "loaded_uuid",
  "measurement_layout_digest", "audit_token_bound", "pidversion_bound",
  "seccode_guest_validated", "cdhash_matched", "macho_uuid_matched",
]);
const ABI_FIELDS = objectFreeze([
  "abi_id", "abi_version", "request_schema", "result_schema", "effect_journal_schema",
  "receipt_schema", "descriptor_count", "descriptor_table", "single_grant_observed",
  "no_path_reopen_observed", "unexpected_descriptors_closed",
]);
const SCHEMA_OBSERVATION_FIELDS = objectFreeze([
  "artifact_path", "byte_size", "sha256", "fd_identity_digest", "media_type",
  "canonicalization", "load_scheme", "regular_file", "single_link", "immutable",
  "openat_no_follow", "pre_post_identity_match", "sha256_verified", "parser_compiled",
]);
const DESCRIPTOR_OBSERVATION_FIELDS = objectFreeze([
  "ordinal", "role", "descriptor_type", "access_mode", "required_status_flags",
  "forbidden_status_flags", "required_descriptor_flags", "forbidden_descriptor_flags",
  "observed_status_flags", "observed_descriptor_flags", "descriptor_identity_digest",
  "sender_cloexec_required", "receiver_cloexec_before_ack",
  "identity_recheck_before_effect", "close_before_receipt", "transfer_mode",
  "type_validation_complete", "access_validation_complete",
]);
const COMPONENT_BINDING_FIELDS = objectFreeze([
  "version", "manifest_digest", "component_id", "artifact_sha256",
  "on_disk_fd_identity_digest", "component_handoff",
  "selected_cdhash", "candidate_set_digest", "serialized_sec_requirement_digest",
  "code_directory_flags", "entitlements_digest", "macho_identity_digest",
  "launch_principal_digest", "mapped_measurement_digest", "capability_abi_digest",
  "running_code_identity_digest", "attestor_identity_digest",
]);
const SUPERVISOR_IDENTITY_FIELDS = objectFreeze([
  "supervisor_component_id", "supervisor_role", "supervisor_audit_token_digest",
  "supervisor_process_id", "supervisor_process_pidversion",
  "supervisor_process_instance_digest", "supervisor_process_start_digest",
  "supervisor_mapped_image_digest", "supervisor_principal_id",
  "supervisor_principal_policy_digest", "supervisor_listener_generation",
  "supervisor_listener_identity_digest",
]);
const WORKER_LINEAGE_FIELDS = objectFreeze([
  "worker_audit_token_digest", "worker_process_id", "worker_process_pidversion",
  "worker_process_instance_digest", "worker_process_start_digest",
  "worker_mapped_image_digest", "worker_principal_id", "worker_principal_policy_digest",
  "worker_direct_parent_process_id", "worker_direct_parent_audit_token_digest",
  "worker_direct_parent_instance_digest", "worker_direct_parent_start_digest",
  "supervisor_listener_generation", "supervisor_listener_identity_digest",
  "post_exec_connection_identity_digest", "fresh_post_exec_connection",
  "direct_child_of_supervisor",
]);
const EXCHANGE_BINDING_FIELDS = objectFreeze([
  "launch_nonce_digest", "launch_generation", "capability_set_digest",
  "capability_generation", "capability_abi_digest", "grant_id", "grant_nonce_digest",
  "grant_sequence", "grant_record_digest", "go_id", "go_sequence", "go_record_digest",
]);
const SUPERVISOR_COMPONENT_HANDOFF_FIELDS = objectFreeze([
  "kind", "supervisor_identity",
]);
const RECIPIENT_COMPONENT_HANDOFF_FIELDS = objectFreeze([
  "kind", "worker_lineage", "exchange_binding", "handoff_session_digest",
]);
const CAPABILITY_SET_FIELDS = objectFreeze([
  "version", "component_id", "capability_abi_digest",
]);
const GRANT_RECORD_FIELDS = objectFreeze([
  "version", "manifest_digest", "component_id", "handoff_session_id",
  "supervisor_identity", "worker_lineage", "launch_nonce_digest", "launch_generation",
  "capability_set_digest", "capability_generation", "capability_abi_digest", "grant_id",
  "grant_nonce_digest", "grant_sequence",
]);
const GO_RECORD_FIELDS = objectFreeze([
  "version", "manifest_digest", "component_id", "handoff_session_id",
  "supervisor_identity", "worker_lineage", "launch_nonce_digest", "launch_generation",
  "capability_set_digest",
  "capability_generation", "grant_id", "grant_sequence", "grant_record_digest", "go_id",
  "go_sequence",
]);
const SESSION_TIMESTAMP_FIELDS = objectFreeze([
  "started_at", "challenged_at", "attested_at", "grant_recorded_at",
  "scm_rights_acked_at", "go_recorded_at", "effect_recorded_at", "receipt_recorded_at",
  "outbox_recorded_at", "completed_at",
]);

const PACKAGE_PATTERN = /^@hacker-bob\/[a-z0-9][a-z0-9._-]{0,127}$/u;
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u;
const CDHASH_PATTERN = /^[a-f0-9]{40}$/u;
const UUID_PATTERN = /^[a-f0-9]{32}$/u;
const TEAM_PATTERN = /^[A-Z0-9]{10}$/u;
const SIGNING_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9.-]{0,190}$/u;

function exactBoolean(input, field, label, expected, code = "evidence_schema_invalid") {
  const value = assertBoolean(ownValue(input, field, label, code), `${label}.${field}`, code);
  if (value !== expected) reject(code, `${label}.${field} must be ${expected}`);
  return value;
}

function exactString(input, field, label, expected, code = "evidence_schema_invalid") {
  const value = assertString(ownValue(input, field, label, code), `${label}.${field}`, {
    maximumBytes: 191,
    code,
  });
  if (value !== expected) reject(code, `${label}.${field} is unsupported`);
  return value;
}

function digestNormalized(domain, fields, values) {
  return domainDigest(domain, makeRecord(fields, values));
}

function valuesForFields(input, fields) {
  const values = [];
  for (let index = 0; index < fields.length; index += 1) {
    setArrayIndex(values, index, input[fields[index]]);
  }
  return values;
}

function normalizeContext(input) {
  const label = "native_prebuild_doctor_v2.evaluation_context";
  assertExactObject(input, CONTEXT_FIELDS, label, "context_invalid");
  return makeRecord(CONTEXT_FIELDS, [
    assertTimestamp(ownValue(input, "now", label), `${label}.now`, "context_invalid"),
    assertDigest(ownValue(input, "expected_manifest_digest", label),
      `${label}.expected_manifest_digest`, "context_invalid"),
    assertString(ownValue(input, "expected_package_name", label),
      `${label}.expected_package_name`, {
        pattern: PACKAGE_PATTERN, maximumBytes: 140, code: "context_invalid",
      }),
    assertString(ownValue(input, "expected_package_version", label),
      `${label}.expected_package_version`, {
        pattern: VERSION_PATTERN, maximumBytes: 128, code: "context_invalid",
      }),
    assertInteger(ownValue(input, "expected_release_epoch", label),
      `${label}.expected_release_epoch`, 1, Number.MAX_SAFE_INTEGER, "context_invalid"),
    exactString(input, "host_os", label, "darwin", "context_invalid"),
    exactString(input, "host_architecture", label, "arm64", "context_invalid"),
    assertInteger(ownValue(input, "host_node_major", label), `${label}.host_node_major`, 20, 20,
      "context_invalid"),
    assertInteger(ownValue(input, "host_napi_version", label), `${label}.host_napi_version`, 9, 9,
      "context_invalid"),
    assertDigest(ownValue(input, "principal_acl_policy_digest", label),
      `${label}.principal_acl_policy_digest`, "context_invalid"),
    assertDigest(ownValue(input, "expected_principal_acl_evidence_digest", label),
      `${label}.expected_principal_acl_evidence_digest`, "context_invalid"),
    assertDigest(ownValue(input, "immutable_install_policy_digest", label),
      `${label}.immutable_install_policy_digest`, "context_invalid"),
    assertDigest(ownValue(input, "expected_immutable_install_evidence_digest", label),
      `${label}.expected_immutable_install_evidence_digest`, "context_invalid"),
    assertDigest(ownValue(input, "expected_install_identity_digest", label),
      `${label}.expected_install_identity_digest`, "context_invalid"),
    assertDigest(ownValue(input, "external_keyring_policy_digest", label),
      `${label}.external_keyring_policy_digest`, "context_invalid"),
    assertDigest(ownValue(input, "expected_external_keyring_evidence_digest", label),
      `${label}.expected_external_keyring_evidence_digest`, "context_invalid"),
    assertDigest(ownValue(input, "expected_external_keyring_identity_digest", label),
      `${label}.expected_external_keyring_identity_digest`, "context_invalid"),
    assertDigest(ownValue(input, "live_attestor_policy_digest", label),
      `${label}.live_attestor_policy_digest`, "context_invalid"),
    assertDigest(ownValue(input, "expected_live_attestor_identity_digest", label),
      `${label}.expected_live_attestor_identity_digest`, "context_invalid"),
    assertDigest(ownValue(input, "expected_replay_fence_identity_digest", label),
      `${label}.expected_replay_fence_identity_digest`, "context_invalid"),
    assertDigest(ownValue(input, "expected_replay_fence_snapshot_digest", label),
      `${label}.expected_replay_fence_snapshot_digest`, "context_invalid"),
  ]);
}

function assertContextMatches(context, verified) {
  const manifest = verified.manifest;
  if (context.expected_manifest_digest !== verified.manifest_digest
      || context.expected_package_name !== manifest.package_name
      || context.expected_package_version !== manifest.package_version
      || context.expected_release_epoch !== manifest.release_epoch
      || context.host_os !== manifest.target.os
      || context.host_architecture !== manifest.target.architecture
      || context.host_node_major !== manifest.target.node_major
      || context.host_napi_version !== manifest.target.napi_version
      || context.principal_acl_policy_digest !== manifest.principal_acl_policy_digest
      || context.immutable_install_policy_digest !== manifest.immutable_install_policy_digest
      || context.external_keyring_policy_digest
        !== manifest.doctor_policy.external_keyring_policy_digest
      || context.live_attestor_policy_digest !== manifest.doctor_policy.live_attestor_policy_digest) {
    reject("context_binding_rejected", "doctor v2 context does not bind the selected release");
  }
}

function normalizeHost(input) {
  const label = "native_prebuild_attestation_v2.host";
  assertExactObject(input, HOST_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(HOST_FIELDS, [
    exactString(input, "os", label, "darwin"),
    exactString(input, "architecture", label, "arm64"),
    assertInteger(ownValue(input, "node_major", label), `${label}.node_major`, 20, 20,
      "evidence_schema_invalid"),
    assertInteger(ownValue(input, "napi_version", label), `${label}.napi_version`, 9, 9,
      "evidence_schema_invalid"),
  ]);
}

function normalizeKeyring(input) {
  const label = "native_prebuild_attestation_v2.external_keyring";
  assertExactObject(input, KEYRING_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(KEYRING_FIELDS, [
    assertDigest(ownValue(input, "policy_digest", label), `${label}.policy_digest`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "evidence_digest", label), `${label}.evidence_digest`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "keyring_identity_digest", label),
      `${label}.keyring_identity_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "immutable_storage_evidence_digest", label),
      `${label}.immutable_storage_evidence_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "revocation_snapshot_digest", label),
      `${label}.revocation_snapshot_digest`, "evidence_schema_invalid"),
    assertInteger(ownValue(input, "observed_trust_epoch", label),
      `${label}.observed_trust_epoch`, 1, Number.MAX_SAFE_INTEGER, "evidence_schema_invalid"),
    exactBoolean(input, "root_owned", label, true),
    exactBoolean(input, "immutable", label, true),
    exactBoolean(input, "external_to_caller", label, true),
    exactBoolean(input, "verified_by_native_attestor", label, true),
  ]);
}

function normalizeInstall(input) {
  const label = "native_prebuild_attestation_v2.immutable_install";
  assertExactObject(input, INSTALL_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(INSTALL_FIELDS, [
    assertDigest(ownValue(input, "policy_digest", label), `${label}.policy_digest`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "evidence_digest", label), `${label}.evidence_digest`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "install_identity_digest", label),
      `${label}.install_identity_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "principal_acl_policy_digest", label),
      `${label}.principal_acl_policy_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "principal_acl_evidence_digest", label),
      `${label}.principal_acl_evidence_digest`, "evidence_schema_invalid"),
    exactBoolean(input, "root_owned", label, true),
    exactBoolean(input, "immutable", label, true),
    exactBoolean(input, "descriptor_walk_complete", label, true),
    exactBoolean(input, "no_symlink_walk", label, true),
    exactBoolean(input, "native_attested", label, true),
  ]);
}

function normalizeAttestor(input) {
  const label = "native_prebuild_attestation_v2.attestor";
  assertExactObject(input, ATTESTOR_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(ATTESTOR_FIELDS, [
    assertDigest(ownValue(input, "implementation_digest", label),
      `${label}.implementation_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "loaded_image_digest", label),
      `${label}.loaded_image_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "identity_digest", label), `${label}.identity_digest`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "audit_token_digest", label), `${label}.audit_token_digest`,
      "evidence_schema_invalid"),
    exactBoolean(input, "native_process", label, true),
    exactBoolean(input, "live_observation", label, true),
    exactBoolean(input, "external_keyring_read_native", label, true),
    exactBoolean(input, "caller_js_authority", label, false),
  ]);
}

function normalizeSupervisorIdentity(input, label, code = "evidence_schema_invalid") {
  assertExactObject(input, SUPERVISOR_IDENTITY_FIELDS, label, code);
  return makeRecord(SUPERVISOR_IDENTITY_FIELDS, [
    assertIdentifier(ownValue(input, "supervisor_component_id", label, code),
      `${label}.supervisor_component_id`, code),
    assertIdentifier(ownValue(input, "supervisor_role", label, code),
      `${label}.supervisor_role`, code),
    assertDigest(ownValue(input, "supervisor_audit_token_digest", label, code),
      `${label}.supervisor_audit_token_digest`, code),
    assertInteger(ownValue(input, "supervisor_process_id", label, code),
      `${label}.supervisor_process_id`, 1, 0x7fffffff, code),
    assertInteger(ownValue(input, "supervisor_process_pidversion", label, code),
      `${label}.supervisor_process_pidversion`, 1, 0xffffffff, code),
    assertDigest(ownValue(input, "supervisor_process_instance_digest", label, code),
      `${label}.supervisor_process_instance_digest`, code),
    assertDigest(ownValue(input, "supervisor_process_start_digest", label, code),
      `${label}.supervisor_process_start_digest`, code),
    assertDigest(ownValue(input, "supervisor_mapped_image_digest", label, code),
      `${label}.supervisor_mapped_image_digest`, code),
    assertIdentifier(ownValue(input, "supervisor_principal_id", label, code),
      `${label}.supervisor_principal_id`, code),
    assertDigest(ownValue(input, "supervisor_principal_policy_digest", label, code),
      `${label}.supervisor_principal_policy_digest`, code),
    assertUint64Decimal(ownValue(input, "supervisor_listener_generation", label, code),
      `${label}.supervisor_listener_generation`, 1n, code),
    assertDigest(ownValue(input, "supervisor_listener_identity_digest", label, code),
      `${label}.supervisor_listener_identity_digest`, code),
  ]);
}

function normalizeWorkerLineage(input, label, code = "evidence_schema_invalid") {
  assertExactObject(input, WORKER_LINEAGE_FIELDS, label, code);
  return makeRecord(WORKER_LINEAGE_FIELDS, [
    assertDigest(ownValue(input, "worker_audit_token_digest", label, code),
      `${label}.worker_audit_token_digest`, code),
    assertInteger(ownValue(input, "worker_process_id", label, code),
      `${label}.worker_process_id`, 1, 0x7fffffff, code),
    assertInteger(ownValue(input, "worker_process_pidversion", label, code),
      `${label}.worker_process_pidversion`, 1, 0xffffffff, code),
    assertDigest(ownValue(input, "worker_process_instance_digest", label, code),
      `${label}.worker_process_instance_digest`, code),
    assertDigest(ownValue(input, "worker_process_start_digest", label, code),
      `${label}.worker_process_start_digest`, code),
    assertDigest(ownValue(input, "worker_mapped_image_digest", label, code),
      `${label}.worker_mapped_image_digest`, code),
    assertIdentifier(ownValue(input, "worker_principal_id", label, code),
      `${label}.worker_principal_id`, code),
    assertDigest(ownValue(input, "worker_principal_policy_digest", label, code),
      `${label}.worker_principal_policy_digest`, code),
    assertInteger(ownValue(input, "worker_direct_parent_process_id", label, code),
      `${label}.worker_direct_parent_process_id`, 1, 0x7fffffff, code),
    assertDigest(ownValue(input, "worker_direct_parent_audit_token_digest", label, code),
      `${label}.worker_direct_parent_audit_token_digest`, code),
    assertDigest(ownValue(input, "worker_direct_parent_instance_digest", label, code),
      `${label}.worker_direct_parent_instance_digest`, code),
    assertDigest(ownValue(input, "worker_direct_parent_start_digest", label, code),
      `${label}.worker_direct_parent_start_digest`, code),
    assertUint64Decimal(ownValue(input, "supervisor_listener_generation", label, code),
      `${label}.supervisor_listener_generation`, 1n, code),
    assertDigest(ownValue(input, "supervisor_listener_identity_digest", label, code),
      `${label}.supervisor_listener_identity_digest`, code),
    assertDigest(ownValue(input, "post_exec_connection_identity_digest", label, code),
      `${label}.post_exec_connection_identity_digest`, code),
    exactBoolean(input, "fresh_post_exec_connection", label, true, code),
    exactBoolean(input, "direct_child_of_supervisor", label, true, code),
  ]);
}

function normalizeExchangeBinding(input, label, code = "evidence_schema_invalid") {
  assertExactObject(input, EXCHANGE_BINDING_FIELDS, label, code);
  return makeRecord(EXCHANGE_BINDING_FIELDS, [
    assertDigest(ownValue(input, "launch_nonce_digest", label, code),
      `${label}.launch_nonce_digest`, code),
    assertUint64Decimal(ownValue(input, "launch_generation", label, code),
      `${label}.launch_generation`, 1n, code),
    assertDigest(ownValue(input, "capability_set_digest", label, code),
      `${label}.capability_set_digest`, code),
    assertUint64Decimal(ownValue(input, "capability_generation", label, code),
      `${label}.capability_generation`, 1n, code),
    assertDigest(ownValue(input, "capability_abi_digest", label, code),
      `${label}.capability_abi_digest`, code),
    assertOpaqueToken(ownValue(input, "grant_id", label, code), `${label}.grant_id`, code),
    assertDigest(ownValue(input, "grant_nonce_digest", label, code),
      `${label}.grant_nonce_digest`, code),
    assertUint64Decimal(ownValue(input, "grant_sequence", label, code),
      `${label}.grant_sequence`, 1n, code),
    assertDigest(ownValue(input, "grant_record_digest", label, code),
      `${label}.grant_record_digest`, code),
    assertOpaqueToken(ownValue(input, "go_id", label, code), `${label}.go_id`, code),
    assertUint64Decimal(ownValue(input, "go_sequence", label, code),
      `${label}.go_sequence`, 1n, code),
    assertDigest(ownValue(input, "go_record_digest", label, code),
      `${label}.go_record_digest`, code),
  ]);
}

function normalizeComponentHandoff(input, label, expectedKind,
  code = "evidence_schema_invalid") {
  if (expectedKind === "supervisor") {
    assertExactObject(input, SUPERVISOR_COMPONENT_HANDOFF_FIELDS, label, code);
    return makeRecord(SUPERVISOR_COMPONENT_HANDOFF_FIELDS, [
      exactString(input, "kind", label, "supervisor", code),
      normalizeSupervisorIdentity(ownValue(input, "supervisor_identity", label, code),
        `${label}.supervisor_identity`, code),
    ]);
  }
  if (expectedKind === "capability_recipient") {
    assertExactObject(input, RECIPIENT_COMPONENT_HANDOFF_FIELDS, label, code);
    return makeRecord(RECIPIENT_COMPONENT_HANDOFF_FIELDS, [
      exactString(input, "kind", label, "capability_recipient", code),
      normalizeWorkerLineage(ownValue(input, "worker_lineage", label, code),
        `${label}.worker_lineage`, code),
      normalizeExchangeBinding(ownValue(input, "exchange_binding", label, code),
        `${label}.exchange_binding`, code),
      assertDigest(ownValue(input, "handoff_session_digest", label, code),
        `${label}.handoff_session_digest`, code),
    ]);
  }
  reject(code, `${label}.kind expectation is unsupported`);
}

function normalizeSessionBody(input, label) {
  assertExactObject(input, SESSION_BODY_FIELDS, label, "evidence_schema_invalid");
  const values = [
    assertIdentifier(ownValue(input, "component_id", label), `${label}.component_id`,
      "evidence_schema_invalid"),
    assertOpaqueToken(ownValue(input, "handoff_session_id", label),
      `${label}.handoff_session_id`, "evidence_schema_invalid"),
    normalizeWorkerLineage(ownValue(input, "worker_lineage", label),
      `${label}.worker_lineage`),
    normalizeExchangeBinding(ownValue(input, "exchange_binding", label),
      `${label}.exchange_binding`),
  ];
  for (let fieldIndex = 4; fieldIndex <= 13; fieldIndex += 1) {
    const field = SESSION_BODY_FIELDS[fieldIndex];
    setArrayIndex(values, fieldIndex, assertTimestamp(ownValue(input, field, label),
      `${label}.${field}`, "evidence_schema_invalid"));
  }
  for (let fieldIndex = 14; fieldIndex <= 15; fieldIndex += 1) {
    const field = SESSION_BODY_FIELDS[fieldIndex];
    setArrayIndex(values, fieldIndex, assertDigest(ownValue(input, field, label),
      `${label}.${field}`, "evidence_schema_invalid"));
  }
  for (let fieldIndex = 16; fieldIndex < SESSION_BODY_FIELDS.length; fieldIndex += 1) {
    setArrayIndex(values, fieldIndex,
      exactBoolean(input, SESSION_BODY_FIELDS[fieldIndex], label, true));
  }
  return makeRecord(SESSION_BODY_FIELDS, values);
}

function digestHandoffSessionV2(input) {
  return domainDigest(NATIVE_PREBUILD_HANDOFF_SESSION_V2_DOMAIN,
    normalizeSessionBody(input, "native_prebuild_handoff_session_v2"));
}

function normalizeSession(input, index) {
  const label = `native_prebuild_attestation_v2.handoff.sessions[${index}]`;
  assertExactObject(input, SESSION_FIELDS, label, "evidence_schema_invalid");
  const bodyValues = [];
  for (let fieldIndex = 0; fieldIndex < SESSION_BODY_FIELDS.length; fieldIndex += 1) {
    const field = SESSION_BODY_FIELDS[fieldIndex];
    setArrayIndex(bodyValues, fieldIndex,
      ownValue(input, field, label, "evidence_schema_invalid"));
  }
  const body = normalizeSessionBody(makeRecord(SESSION_BODY_FIELDS, bodyValues),
    `${label}.transcript_body`);
  if (body.component_id !== NATIVE_PREBUILD_RECIPIENT_COMPONENTS_V2[index]) {
    reject("evidence_schema_invalid", `${label}.component_id is outside the closed order`);
  }
  const handoffSessionDigest = assertDigest(ownValue(input, "handoff_session_digest", label),
    `${label}.handoff_session_digest`, "evidence_schema_invalid");
  if (handoffSessionDigest !== domainDigest(NATIVE_PREBUILD_HANDOFF_SESSION_V2_DOMAIN, body)) {
    reject("session_transcript_rejected", `${label}.handoff_session_digest does not match`);
  }
  const values = [];
  for (let fieldIndex = 0; fieldIndex <= 15; fieldIndex += 1) {
    setArrayIndex(values, fieldIndex, body[SESSION_FIELDS[fieldIndex]]);
  }
  setArrayIndex(values, 16, handoffSessionDigest);
  for (let fieldIndex = 17; fieldIndex < SESSION_FIELDS.length; fieldIndex += 1) {
    setArrayIndex(values, fieldIndex, body[SESSION_FIELDS[fieldIndex]]);
  }
  return makeRecord(SESSION_FIELDS, values);
}

function normalizeHandoff(input) {
  const label = "native_prebuild_attestation_v2.handoff";
  assertExactObject(input, HANDOFF_FIELDS, label, "evidence_schema_invalid");
  const sessionInputs = ownValue(input, "sessions", label, "evidence_schema_invalid");
  assertDenseArray(sessionInputs, `${label}.sessions`,
    NATIVE_PREBUILD_RECIPIENT_COMPONENTS_V2.length, "evidence_schema_invalid");
  if (sessionInputs.length !== NATIVE_PREBUILD_RECIPIENT_COMPONENTS_V2.length) {
    reject("evidence_schema_invalid", `${label}.sessions is incomplete`);
  }
  const sessions = [];
  for (let index = 0; index < sessionInputs.length; index += 1) {
    setArrayIndex(sessions, index, normalizeSession(ownValue(sessionInputs, `${index}`,
      `${label}.sessions`, "evidence_schema_invalid"), index));
  }
  return makeRecord(HANDOFF_FIELDS, [
    exactString(input, "scheme", label, NATIVE_PREBUILD_HANDOFF_SCHEME),
    normalizeSupervisorIdentity(ownValue(input, "supervisor_identity", label),
      `${label}.supervisor_identity`),
    exactString(input, "process_lineage_scheme", label,
      "audit_token_pidversion_instance_start_direct_parent_v1"),
    exactString(input, "listener_identity_scheme", label,
      "root_owned_single_launch_listener_generation_v1"),
    exactString(input, "post_exec_connection_scheme", label,
      "fresh_post_exec_af_unix_connection_v1"),
    exactString(input, "capability_set_digest_scheme", label,
      "ordered_descriptor_semantics_sha256_v1"),
    exactString(input, "grant_go_binding_scheme", label,
      "durable_grant_go_sequence_binding_v1"),
    exactString(input, "transport", label, "af_unix_sock_stream_scm_rights_v1"),
    exactString(input, "peer_identity_scheme", label,
      "local_peertoken_audit_token_pidversion_v1"),
    exactString(input, "running_code_validation_scheme", label,
      "seccodecopyguestwithattributes_audit_v1"),
    exactString(input, "security_requirement_validation_scheme", label,
      "serialized_secrequirement_exact_match_v1"),
    exactString(input, "deadline_clock", label, "mach_continuous_time_v1"),
    exactString(input, "nonce_scheme", label,
      "getentropy_256bit_monotonic_generation_v1"),
    assertInteger(ownValue(input, "nonce_entropy_bits", label),
      `${label}.nonce_entropy_bits`, 256, 256, "evidence_schema_invalid"),
    assertInteger(ownValue(input, "nonce_generation_bits", label),
      `${label}.nonce_generation_bits`, 64, 64, "evidence_schema_invalid"),
    exactString(input, "durable_exchange_scheme", label,
      "durable_grant_go_receipt_outbox_v1"),
    normalizeSchemaObservation(ownValue(input, "grant_record_schema", label),
      `${label}.grant_record_schema`),
    normalizeSchemaObservation(ownValue(input, "go_record_schema", label),
      `${label}.go_record_schema`),
    normalizeSchemaObservation(ownValue(input, "receipt_record_schema", label),
      `${label}.receipt_record_schema`),
    normalizeSchemaObservation(ownValue(input, "outbox_record_schema", label),
      `${label}.outbox_record_schema`),
    assertDigest(ownValue(input, "replay_fence_identity_digest", label),
      `${label}.replay_fence_identity_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "replay_fence_snapshot_digest", label),
      `${label}.replay_fence_snapshot_digest`, "evidence_schema_invalid"),
    assertUint64Decimal(ownValue(input, "previous_committed_generation", label),
      `${label}.previous_committed_generation`, 0n, "evidence_schema_invalid"),
    assertUint64Decimal(ownValue(input, "committed_generation", label),
      `${label}.committed_generation`, 1n, "evidence_schema_invalid"),
    makeArray(sessions),
    exactBoolean(input, "all_capabilities_withheld_until_attestation", label, true),
    exactBoolean(input, "all_scm_rights_single_grant", label, true),
    exactBoolean(input, "all_receipts_authenticated", label, true),
    exactBoolean(input, "replay_fence_durable", label, true),
    exactBoolean(input, "outbox_recovery_complete", label, true),
    exactBoolean(input, "native_transcript_authenticated", label, true),
  ]);
}

function normalizeMacho(input, label) {
  assertExactObject(input, MACHO_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(MACHO_FIELDS, [
    assertInteger(ownValue(input, "file_type", label), `${label}.file_type`, 1, 0xffffffff,
      "evidence_schema_invalid"),
    assertInteger(ownValue(input, "cpu_type", label), `${label}.cpu_type`, 0, 0xffffffff,
      "evidence_schema_invalid"),
    assertInteger(ownValue(input, "cpu_subtype", label), `${label}.cpu_subtype`, 0, 0xffffffff,
      "evidence_schema_invalid"),
    assertInteger(ownValue(input, "macho_flags", label), `${label}.macho_flags`, 0, 0xffffffff,
      "evidence_schema_invalid"),
    assertString(ownValue(input, "uuid", label), `${label}.uuid`, {
      pattern: UUID_PATTERN, minimumBytes: 32, maximumBytes: 32,
      code: "evidence_schema_invalid",
    }),
    assertDigest(ownValue(input, "load_commands_digest", label),
      `${label}.load_commands_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "code_signature_blob_digest", label),
      `${label}.code_signature_blob_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "text_segment_file_digest", label),
      `${label}.text_segment_file_digest`, "evidence_schema_invalid"),
    assertInteger(ownValue(input, "slice_offset", label), `${label}.slice_offset`, 0,
      Number.MAX_SAFE_INTEGER, "evidence_schema_invalid"),
    assertInteger(ownValue(input, "slice_size", label), `${label}.slice_size`, 1,
      Number.MAX_SAFE_INTEGER, "evidence_schema_invalid"),
  ]);
}

function normalizePrincipal(input, label) {
  assertExactObject(input, PRINCIPAL_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(PRINCIPAL_FIELDS, [
    assertIdentifier(ownValue(input, "principal_id", label), `${label}.principal_id`,
      "evidence_schema_invalid"),
    assertInteger(ownValue(input, "uid", label), `${label}.uid`, 1, 0xffffffff,
      "evidence_schema_invalid"),
    assertInteger(ownValue(input, "gid", label), `${label}.gid`, 1, 0xffffffff,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "supplementary_groups_digest", label),
      `${label}.supplementary_groups_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "audit_session_policy_digest", label),
      `${label}.audit_session_policy_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "sandbox_profile_digest", label),
      `${label}.sandbox_profile_digest`, "evidence_schema_invalid"),
    exactBoolean(input, "no_login_identity", label, true),
    exactBoolean(input, "supplementary_groups_cleared", label, true),
    exactBoolean(input, "identity_dropped_before_capability_grant", label, true),
  ]);
}

function normalizeMapped(input, label) {
  assertExactObject(input, MAPPED_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(MAPPED_FIELDS, [
    exactString(input, "scheme", label, "darwin_running_code_guest_audit_token_v1"),
    assertDigest(ownValue(input, "mapped_text_digest", label), `${label}.mapped_text_digest`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "mapped_linkedit_digest", label),
      `${label}.mapped_linkedit_digest`, "evidence_schema_invalid"),
    assertString(ownValue(input, "loaded_uuid", label), `${label}.loaded_uuid`, {
      pattern: UUID_PATTERN, minimumBytes: 32, maximumBytes: 32,
      code: "evidence_schema_invalid",
    }),
    assertDigest(ownValue(input, "measurement_layout_digest", label),
      `${label}.measurement_layout_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "measurement_digest", label), `${label}.measurement_digest`,
      "evidence_schema_invalid"),
    exactBoolean(input, "audit_token_bound", label, true),
    exactBoolean(input, "pidversion_bound", label, true),
    exactBoolean(input, "seccode_guest_validated", label, true),
    exactBoolean(input, "cdhash_matched", label, true),
    exactBoolean(input, "macho_uuid_matched", label, true),
  ]);
}

function digestObservedMachoIdentityV2(input) {
  const normalized = normalizeMacho(input, "native_prebuild_observed_macho_v2");
  return digestNormalized(NATIVE_PREBUILD_OBSERVED_MACHO_V2_DOMAIN, MACHO_FIELDS,
    valuesForFields(normalized, MACHO_FIELDS));
}

function digestObservedLaunchPrincipalV2(input) {
  const normalized = normalizePrincipal(input, "native_prebuild_observed_principal_v2");
  return digestNormalized(NATIVE_PREBUILD_OBSERVED_PRINCIPAL_V2_DOMAIN, PRINCIPAL_FIELDS,
    valuesForFields(normalized, PRINCIPAL_FIELDS));
}

function normalizeMappedBody(input, label) {
  assertExactObject(input, MAPPED_BODY_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(MAPPED_BODY_FIELDS, [
    exactString(input, "scheme", label, "darwin_running_code_guest_audit_token_v1"),
    assertDigest(ownValue(input, "mapped_text_digest", label), `${label}.mapped_text_digest`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "mapped_linkedit_digest", label),
      `${label}.mapped_linkedit_digest`, "evidence_schema_invalid"),
    assertString(ownValue(input, "loaded_uuid", label), `${label}.loaded_uuid`, {
      pattern: UUID_PATTERN, minimumBytes: 32, maximumBytes: 32,
      code: "evidence_schema_invalid",
    }),
    assertDigest(ownValue(input, "measurement_layout_digest", label),
      `${label}.measurement_layout_digest`, "evidence_schema_invalid"),
    exactBoolean(input, "audit_token_bound", label, true),
    exactBoolean(input, "pidversion_bound", label, true),
    exactBoolean(input, "seccode_guest_validated", label, true),
    exactBoolean(input, "cdhash_matched", label, true),
    exactBoolean(input, "macho_uuid_matched", label, true),
  ]);
}

function digestObservedMappedMeasurementV2(input) {
  return domainDigest(NATIVE_PREBUILD_OBSERVED_MAPPED_V2_DOMAIN,
    normalizeMappedBody(input, "native_prebuild_observed_mapped_measurement_v2"));
}

function normalizeSchemaObservation(input, label) {
  assertExactObject(input, SCHEMA_OBSERVATION_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(SCHEMA_OBSERVATION_FIELDS, [
    assertRelativeArtifactPath(ownValue(input, "artifact_path", label),
      `${label}.artifact_path`, "evidence_schema_invalid"),
    assertInteger(ownValue(input, "byte_size", label), `${label}.byte_size`, 2,
      1024 * 1024, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "sha256", label), `${label}.sha256`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "fd_identity_digest", label),
      `${label}.fd_identity_digest`, "evidence_schema_invalid"),
    assertString(ownValue(input, "media_type", label), `${label}.media_type`, {
      maximumBytes: 64, code: "evidence_schema_invalid",
    }),
    assertString(ownValue(input, "canonicalization", label), `${label}.canonicalization`, {
      maximumBytes: 64, code: "evidence_schema_invalid",
    }),
    assertString(ownValue(input, "load_scheme", label), `${label}.load_scheme`, {
      maximumBytes: 128, code: "evidence_schema_invalid",
    }),
    exactBoolean(input, "regular_file", label, true),
    exactBoolean(input, "single_link", label, true),
    exactBoolean(input, "immutable", label, true),
    exactBoolean(input, "openat_no_follow", label, true),
    exactBoolean(input, "pre_post_identity_match", label, true),
    exactBoolean(input, "sha256_verified", label, true),
    exactBoolean(input, "parser_compiled", label, true),
  ]);
}

function normalizeDescriptorObservation(input, index, label) {
  assertExactObject(input, DESCRIPTOR_OBSERVATION_FIELDS, label, "evidence_schema_invalid");
  const accessMode = assertString(ownValue(input, "access_mode", label),
    `${label}.access_mode`, { maximumBytes: 32, code: "evidence_schema_invalid" });
  const requiredStatusFlags = assertInteger(ownValue(input, "required_status_flags", label),
    `${label}.required_status_flags`, 0, 0xffffffff, "evidence_schema_invalid");
  const forbiddenStatusFlags = assertInteger(ownValue(input, "forbidden_status_flags", label),
    `${label}.forbidden_status_flags`, 0, 0xffffffff, "evidence_schema_invalid");
  const requiredDescriptorFlags = assertInteger(ownValue(input, "required_descriptor_flags",
    label), `${label}.required_descriptor_flags`, 0, 0xffffffff, "evidence_schema_invalid");
  const forbiddenDescriptorFlags = assertInteger(ownValue(input, "forbidden_descriptor_flags",
    label), `${label}.forbidden_descriptor_flags`, 0, 0xffffffff,
    "evidence_schema_invalid");
  const observedStatusFlags = assertInteger(ownValue(input, "observed_status_flags", label),
    `${label}.observed_status_flags`, 0, 0xffffffff, "evidence_schema_invalid");
  const observedDescriptorFlags = assertInteger(ownValue(input, "observed_descriptor_flags",
    label), `${label}.observed_descriptor_flags`, 0, 0xffffffff,
    "evidence_schema_invalid");
  assertDarwinDescriptorFlagSemantics(accessMode, requiredStatusFlags,
    forbiddenStatusFlags, requiredDescriptorFlags, forbiddenDescriptorFlags,
    observedStatusFlags, observedDescriptorFlags, label, "evidence_schema_invalid");
  return makeRecord(DESCRIPTOR_OBSERVATION_FIELDS, [
    assertInteger(ownValue(input, "ordinal", label), `${label}.ordinal`, index, index,
      "evidence_schema_invalid"),
    assertIdentifier(ownValue(input, "role", label), `${label}.role`,
      "evidence_schema_invalid"),
    assertString(ownValue(input, "descriptor_type", label), `${label}.descriptor_type`, {
      maximumBytes: 64, code: "evidence_schema_invalid",
    }),
    accessMode,
    requiredStatusFlags,
    forbiddenStatusFlags,
    requiredDescriptorFlags,
    forbiddenDescriptorFlags,
    observedStatusFlags,
    observedDescriptorFlags,
    assertDigest(ownValue(input, "descriptor_identity_digest", label),
      `${label}.descriptor_identity_digest`, "evidence_schema_invalid"),
    exactBoolean(input, "sender_cloexec_required", label, true),
    exactBoolean(input, "receiver_cloexec_before_ack", label, true),
    exactBoolean(input, "identity_recheck_before_effect", label, true),
    exactBoolean(input, "close_before_receipt", label, true),
    assertString(ownValue(input, "transfer_mode", label), `${label}.transfer_mode`, {
      maximumBytes: 64, code: "evidence_schema_invalid",
    }),
    exactBoolean(input, "type_validation_complete", label, true),
    exactBoolean(input, "access_validation_complete", label, true),
  ]);
}

function normalizeAbi(input, label) {
  assertExactObject(input, ABI_FIELDS, label, "evidence_schema_invalid");
  const descriptorCount = assertInteger(ownValue(input, "descriptor_count", label),
    `${label}.descriptor_count`, 1, 32, "evidence_schema_invalid");
  const descriptorInputs = ownValue(input, "descriptor_table", label,
    "evidence_schema_invalid");
  assertDenseArray(descriptorInputs, `${label}.descriptor_table`, 32,
    "evidence_schema_invalid");
  if (descriptorInputs.length !== descriptorCount) {
    reject("evidence_schema_invalid", `${label}.descriptor_table count does not match`);
  }
  const descriptors = [];
  for (let index = 0; index < descriptorInputs.length; index += 1) {
    setArrayIndex(descriptors, index, normalizeDescriptorObservation(ownValue(
      descriptorInputs, `${index}`, `${label}.descriptor_table`, "evidence_schema_invalid"),
    index, `${label}.descriptor_table[${index}]`));
  }
  return makeRecord(ABI_FIELDS, [
    assertIdentifier(ownValue(input, "abi_id", label), `${label}.abi_id`,
      "evidence_schema_invalid"),
    assertInteger(ownValue(input, "abi_version", label), `${label}.abi_version`, 1, 1,
      "evidence_schema_invalid"),
    normalizeSchemaObservation(ownValue(input, "request_schema", label),
      `${label}.request_schema`),
    normalizeSchemaObservation(ownValue(input, "result_schema", label),
      `${label}.result_schema`),
    normalizeSchemaObservation(ownValue(input, "effect_journal_schema", label),
      `${label}.effect_journal_schema`),
    normalizeSchemaObservation(ownValue(input, "receipt_schema", label),
      `${label}.receipt_schema`),
    descriptorCount,
    makeArray(descriptors),
    exactBoolean(input, "single_grant_observed", label, true),
    exactBoolean(input, "no_path_reopen_observed", label, true),
    exactBoolean(input, "unexpected_descriptors_closed", label, true),
  ]);
}

function digestObservedCapabilityAbiV2(input) {
  const normalized = normalizeAbi(input, "native_prebuild_observed_capability_abi_v2");
  return digestNormalized(NATIVE_PREBUILD_OBSERVED_ABI_V2_DOMAIN, ABI_FIELDS,
    valuesForFields(normalized, ABI_FIELDS));
}

function digestCapabilitySetV2(input) {
  const label = "native_prebuild_capability_set_v2";
  assertExactObject(input, CAPABILITY_SET_FIELDS, label, "capability_set_invalid");
  return domainDigest(NATIVE_PREBUILD_CAPABILITY_SET_V2_DOMAIN,
    makeRecord(CAPABILITY_SET_FIELDS, [
      assertInteger(ownValue(input, "version", label), `${label}.version`, 2, 2,
        "capability_set_invalid"),
      assertIdentifier(ownValue(input, "component_id", label), `${label}.component_id`,
        "capability_set_invalid"),
      assertDigest(ownValue(input, "capability_abi_digest", label),
        `${label}.capability_abi_digest`, "capability_set_invalid"),
    ]));
}

function digestGrantRecordV2(input) {
  const label = "native_prebuild_grant_record_v2";
  assertExactObject(input, GRANT_RECORD_FIELDS, label, "grant_record_invalid");
  return domainDigest(NATIVE_PREBUILD_GRANT_RECORD_V2_DOMAIN,
    makeRecord(GRANT_RECORD_FIELDS, [
      assertInteger(ownValue(input, "version", label), `${label}.version`, 2, 2,
        "grant_record_invalid"),
      assertDigest(ownValue(input, "manifest_digest", label), `${label}.manifest_digest`,
        "grant_record_invalid"),
      assertIdentifier(ownValue(input, "component_id", label), `${label}.component_id`,
        "grant_record_invalid"),
      assertOpaqueToken(ownValue(input, "handoff_session_id", label),
        `${label}.handoff_session_id`, "grant_record_invalid"),
      normalizeSupervisorIdentity(ownValue(input, "supervisor_identity", label,
        "grant_record_invalid"), `${label}.supervisor_identity`, "grant_record_invalid"),
      normalizeWorkerLineage(ownValue(input, "worker_lineage", label,
        "grant_record_invalid"), `${label}.worker_lineage`, "grant_record_invalid"),
      assertDigest(ownValue(input, "launch_nonce_digest", label),
        `${label}.launch_nonce_digest`, "grant_record_invalid"),
      assertUint64Decimal(ownValue(input, "launch_generation", label),
        `${label}.launch_generation`, 1n, "grant_record_invalid"),
      assertDigest(ownValue(input, "capability_set_digest", label),
        `${label}.capability_set_digest`, "grant_record_invalid"),
      assertUint64Decimal(ownValue(input, "capability_generation", label),
        `${label}.capability_generation`, 1n, "grant_record_invalid"),
      assertDigest(ownValue(input, "capability_abi_digest", label),
        `${label}.capability_abi_digest`, "grant_record_invalid"),
      assertOpaqueToken(ownValue(input, "grant_id", label), `${label}.grant_id`,
        "grant_record_invalid"),
      assertDigest(ownValue(input, "grant_nonce_digest", label),
        `${label}.grant_nonce_digest`, "grant_record_invalid"),
      assertUint64Decimal(ownValue(input, "grant_sequence", label),
        `${label}.grant_sequence`, 1n, "grant_record_invalid"),
    ]));
}

function digestGoRecordV2(input) {
  const label = "native_prebuild_go_record_v2";
  assertExactObject(input, GO_RECORD_FIELDS, label, "go_record_invalid");
  return domainDigest(NATIVE_PREBUILD_GO_RECORD_V2_DOMAIN,
    makeRecord(GO_RECORD_FIELDS, [
      assertInteger(ownValue(input, "version", label), `${label}.version`, 2, 2,
        "go_record_invalid"),
      assertDigest(ownValue(input, "manifest_digest", label), `${label}.manifest_digest`,
        "go_record_invalid"),
      assertIdentifier(ownValue(input, "component_id", label), `${label}.component_id`,
        "go_record_invalid"),
      assertOpaqueToken(ownValue(input, "handoff_session_id", label),
        `${label}.handoff_session_id`, "go_record_invalid"),
      normalizeSupervisorIdentity(ownValue(input, "supervisor_identity", label,
        "go_record_invalid"), `${label}.supervisor_identity`, "go_record_invalid"),
      normalizeWorkerLineage(ownValue(input, "worker_lineage", label,
        "go_record_invalid"), `${label}.worker_lineage`, "go_record_invalid"),
      assertDigest(ownValue(input, "launch_nonce_digest", label),
        `${label}.launch_nonce_digest`, "go_record_invalid"),
      assertUint64Decimal(ownValue(input, "launch_generation", label),
        `${label}.launch_generation`, 1n, "go_record_invalid"),
      assertDigest(ownValue(input, "capability_set_digest", label),
        `${label}.capability_set_digest`, "go_record_invalid"),
      assertUint64Decimal(ownValue(input, "capability_generation", label),
        `${label}.capability_generation`, 1n, "go_record_invalid"),
      assertOpaqueToken(ownValue(input, "grant_id", label), `${label}.grant_id`,
        "go_record_invalid"),
      assertUint64Decimal(ownValue(input, "grant_sequence", label),
        `${label}.grant_sequence`, 1n, "go_record_invalid"),
      assertDigest(ownValue(input, "grant_record_digest", label),
        `${label}.grant_record_digest`, "go_record_invalid"),
      assertOpaqueToken(ownValue(input, "go_id", label), `${label}.go_id`,
        "go_record_invalid"),
      assertUint64Decimal(ownValue(input, "go_sequence", label),
        `${label}.go_sequence`, 1n, "go_record_invalid"),
    ]));
}

function digestComponentBindingV2(input) {
  const label = "native_prebuild_component_binding_v2";
  assertExactObject(input, COMPONENT_BINDING_FIELDS, label, "component_binding_invalid");
  const componentId = assertIdentifier(ownValue(input, "component_id", label),
    `${label}.component_id`, "component_binding_invalid");
  const expectedHandoffKind = componentId === "privileged_launcher"
    ? "supervisor" : "capability_recipient";
  const values = [
    assertInteger(ownValue(input, "version", label), `${label}.version`, 2, 2,
      "component_binding_invalid"),
    assertDigest(ownValue(input, "manifest_digest", label), `${label}.manifest_digest`,
      "component_binding_invalid"),
    componentId,
    assertDigest(ownValue(input, "artifact_sha256", label), `${label}.artifact_sha256`,
      "component_binding_invalid"),
    assertDigest(ownValue(input, "on_disk_fd_identity_digest", label),
      `${label}.on_disk_fd_identity_digest`, "component_binding_invalid"),
    normalizeComponentHandoff(ownValue(input, "component_handoff", label,
      "component_binding_invalid"), `${label}.component_handoff`, expectedHandoffKind,
    "component_binding_invalid"),
    assertString(ownValue(input, "selected_cdhash", label), `${label}.selected_cdhash`, {
      pattern: CDHASH_PATTERN, minimumBytes: 40, maximumBytes: 40,
      code: "component_binding_invalid",
    }),
  ];
  for (let index = 7; index < COMPONENT_BINDING_FIELDS.length; index += 1) {
    const field = COMPONENT_BINDING_FIELDS[index];
    if (field === "code_directory_flags") {
      setArrayIndex(values, index, assertInteger(ownValue(input, field, label),
        `${label}.${field}`, 0, 0xffffffff, "component_binding_invalid"));
    } else {
      setArrayIndex(values, index, assertDigest(ownValue(input, field, label),
        `${label}.${field}`, "component_binding_invalid"));
    }
  }
  return domainDigest(NATIVE_PREBUILD_COMPONENT_BINDING_V2_DOMAIN,
    makeRecord(COMPONENT_BINDING_FIELDS, values));
}

function normalizeComponent(input, index) {
  const label = `native_prebuild_attestation_v2.components[${index}]`;
  assertExactObject(input, COMPONENT_FIELDS, label, "evidence_schema_invalid");
  const componentId = ownValue(input, "component_id", label, "evidence_schema_invalid");
  if (componentId !== NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2[index]) {
    reject("evidence_schema_invalid", `${label}.component_id is outside the closed order`);
  }
  const expectedHandoffKind = componentId === "privileged_launcher"
    ? "supervisor" : "capability_recipient";
  return makeRecord(COMPONENT_FIELDS, [
    componentId,
    assertDigest(ownValue(input, "artifact_sha256", label), `${label}.artifact_sha256`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "on_disk_fd_identity_digest", label),
      `${label}.on_disk_fd_identity_digest`, "evidence_schema_invalid"),
    normalizeComponentHandoff(ownValue(input, "component_handoff", label),
      `${label}.component_handoff`, expectedHandoffKind),
    exactString(input, "signature_kind", label, "developer_id"),
    assertString(ownValue(input, "code_type", label), `${label}.code_type`, {
      maximumBytes: 32, code: "evidence_schema_invalid",
    }),
    assertString(ownValue(input, "team_identifier", label), `${label}.team_identifier`, {
      pattern: TEAM_PATTERN, minimumBytes: 10, maximumBytes: 10,
      code: "evidence_schema_invalid",
    }),
    assertString(ownValue(input, "signing_identifier", label), `${label}.signing_identifier`, {
      pattern: SIGNING_IDENTIFIER_PATTERN, maximumBytes: 191,
      code: "evidence_schema_invalid",
    }),
    exactString(input, "cdhash_algorithm", label, "sha256_truncated_160"),
    assertString(ownValue(input, "selected_cdhash", label), `${label}.selected_cdhash`, {
      pattern: CDHASH_PATTERN, minimumBytes: 40, maximumBytes: 40,
      code: "evidence_schema_invalid",
    }),
    exactString(input, "candidate_set_digest_scheme", label,
      "darwin_cdhash_candidate_set_jcs_v1"),
    assertDigest(ownValue(input, "candidate_set_digest", label),
      `${label}.candidate_set_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "serialized_sec_requirement_digest", label),
      `${label}.serialized_sec_requirement_digest`, "evidence_schema_invalid"),
    assertInteger(ownValue(input, "code_directory_flags", label),
      `${label}.code_directory_flags`, 0, 0xffffffff, "evidence_schema_invalid"),
    exactString(input, "entitlements_digest_scheme", label,
      "security_entitlements_der_sha256_v1"),
    assertDigest(ownValue(input, "entitlements_digest", label),
      `${label}.entitlements_digest`, "evidence_schema_invalid"),
    exactBoolean(input, "candidate_set_enumeration_complete", label, true),
    exactBoolean(input, "serialized_sec_requirement_instantiated", label, true),
    exactBoolean(input, "code_signing_information_complete", label, true),
    exactBoolean(input, "hardened_runtime", label, true),
    exactBoolean(input, "notarization_verified", label, true),
    exactBoolean(input, "adhoc", label, false),
    normalizeMacho(ownValue(input, "macho_identity", label), `${label}.macho_identity`),
    normalizePrincipal(ownValue(input, "launch_principal", label),
      `${label}.launch_principal`),
    normalizeMapped(ownValue(input, "mapped_measurement", label),
      `${label}.mapped_measurement`),
    normalizeAbi(ownValue(input, "capability_abi", label), `${label}.capability_abi`),
    assertDigest(ownValue(input, "running_code_identity_digest", label),
      `${label}.running_code_identity_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "component_binding_digest", label),
      `${label}.component_binding_digest`, "evidence_schema_invalid"),
    exactBoolean(input, "static_code_fd_validated", label, true),
    exactBoolean(input, "running_code_guest_validated", label, true),
    exactBoolean(input, "audit_token_kernel_originated", label, true),
    exactBoolean(input, "pre_grant_measurement_complete", label, true),
    exactBoolean(input, "post_grant_identity_stable", label, true),
  ]);
}

function normalizeEvidenceBody(input) {
  const label = "native_prebuild_attestation_v2";
  assertExactObject(input, EVIDENCE_BODY_FIELDS, label, "evidence_schema_invalid");
  const kind = ownValue(input, "kind", label, "evidence_schema_invalid");
  if (kind !== "native_prebuild_post_exec_attestation") {
    reject("evidence_schema_invalid", `${label}.kind is invalid`);
  }
  const componentInputs = ownValue(input, "components", label, "evidence_schema_invalid");
  assertDenseArray(componentInputs, `${label}.components`,
    NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2.length, "evidence_schema_invalid");
  if (componentInputs.length !== NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2.length) {
    reject("evidence_schema_invalid", `${label}.components is incomplete`);
  }
  const components = [];
  for (let index = 0; index < componentInputs.length; index += 1) {
    setArrayIndex(components, index, normalizeComponent(ownValue(componentInputs, `${index}`,
      `${label}.components`, "evidence_schema_invalid"), index));
  }
  return makeRecord(EVIDENCE_BODY_FIELDS, [
    assertInteger(ownValue(input, "version", label), `${label}.version`, 2, 2,
      "evidence_schema_invalid"),
    kind,
    assertDigest(ownValue(input, "manifest_digest", label), `${label}.manifest_digest`,
      "evidence_schema_invalid"),
    assertOpaqueToken(ownValue(input, "evidence_id", label), `${label}.evidence_id`,
      "evidence_schema_invalid"),
    assertTimestamp(ownValue(input, "observed_at", label), `${label}.observed_at`,
      "evidence_schema_invalid"),
    assertTimestamp(ownValue(input, "valid_until", label), `${label}.valid_until`,
      "evidence_schema_invalid"),
    normalizeHost(ownValue(input, "host", label)),
    normalizeKeyring(ownValue(input, "external_keyring", label)),
    normalizeInstall(ownValue(input, "immutable_install", label)),
    normalizeAttestor(ownValue(input, "attestor", label)),
    normalizeHandoff(ownValue(input, "handoff", label)),
    makeArray(components),
  ]);
}

function digestNativePrebuildAttestationV2Body(input) {
  return domainDigest(NATIVE_PREBUILD_ATTESTATION_V2_DOMAIN, normalizeEvidenceBody(input));
}

function normalizeEvidence(input) {
  const label = "native_prebuild_attestation_v2";
  assertExactObject(input, EVIDENCE_FIELDS, label, "evidence_schema_invalid");
  const bodyValues = [];
  for (let index = 0; index < EVIDENCE_BODY_FIELDS.length; index += 1) {
    setArrayIndex(bodyValues, index, ownValue(input, EVIDENCE_BODY_FIELDS[index], label,
      "evidence_schema_invalid"));
  }
  const body = normalizeEvidenceBody(makeRecord(EVIDENCE_BODY_FIELDS, bodyValues));
  const digest = assertDigest(ownValue(input, "attestation_digest", label),
    `${label}.attestation_digest`, "evidence_digest_invalid");
  if (digest !== domainDigest(NATIVE_PREBUILD_ATTESTATION_V2_DOMAIN, body)) {
    reject("evidence_digest_invalid", `${label}.attestation_digest does not match`);
  }
  const values = valuesForFields(body, EVIDENCE_BODY_FIELDS);
  setArrayIndex(values, EVIDENCE_BODY_FIELDS.length, digest);
  return makeRecord(EVIDENCE_FIELDS, values);
}

function objectsEqualByFields(left, right, fields) {
  for (let index = 0; index < fields.length; index += 1) {
    if (left[fields[index]] !== right[fields[index]]) return false;
  }
  return true;
}

function supervisorIdentityAtWorkerListener(supervisor, lineage) {
  return {
    supervisor_component_id: supervisor.supervisor_component_id,
    supervisor_role: supervisor.supervisor_role,
    supervisor_audit_token_digest: supervisor.supervisor_audit_token_digest,
    supervisor_process_id: supervisor.supervisor_process_id,
    supervisor_process_pidversion: supervisor.supervisor_process_pidversion,
    supervisor_process_instance_digest: supervisor.supervisor_process_instance_digest,
    supervisor_process_start_digest: supervisor.supervisor_process_start_digest,
    supervisor_mapped_image_digest: supervisor.supervisor_mapped_image_digest,
    supervisor_principal_id: supervisor.supervisor_principal_id,
    supervisor_principal_policy_digest: supervisor.supervisor_principal_policy_digest,
    supervisor_listener_generation: lineage.supervisor_listener_generation,
    supervisor_listener_identity_digest: lineage.supervisor_listener_identity_digest,
  };
}

function assertSchemaObservationMatches(actual, expected, label) {
  if (actual.artifact_path !== expected.artifact_path
      || actual.byte_size !== expected.byte_size
      || actual.sha256 !== expected.sha256
      || actual.media_type !== expected.media_type
      || actual.canonicalization !== expected.canonicalization
      || actual.load_scheme !== expected.load_scheme) {
    reject("schema_artifact_rejected", `${label} does not bind the signed schema artifact`);
  }
}

function assertCapabilityAbiMatches(actual, expected, label) {
  if (actual.abi_id !== expected.abi_id || actual.abi_version !== expected.abi_version
      || actual.descriptor_count !== expected.descriptor_count
      || actual.descriptor_table.length !== expected.descriptor_table.length) {
    reject("capability_abi_rejected", `${label} identity or descriptor count drifted`);
  }
  assertSchemaObservationMatches(actual.request_schema, expected.request_schema,
    `${label}.request_schema`);
  assertSchemaObservationMatches(actual.result_schema, expected.result_schema,
    `${label}.result_schema`);
  assertSchemaObservationMatches(actual.effect_journal_schema, expected.effect_journal_schema,
    `${label}.effect_journal_schema`);
  assertSchemaObservationMatches(actual.receipt_schema, expected.receipt_schema,
    `${label}.receipt_schema`);
  const policyFields = [
    "ordinal", "role", "descriptor_type", "access_mode", "required_status_flags",
    "forbidden_status_flags", "required_descriptor_flags", "forbidden_descriptor_flags",
    "sender_cloexec_required", "receiver_cloexec_before_ack",
    "identity_recheck_before_effect", "close_before_receipt", "transfer_mode",
  ];
  for (let index = 0; index < expected.descriptor_table.length; index += 1) {
    const observed = actual.descriptor_table[index];
    const signed = expected.descriptor_table[index];
    assertDarwinDescriptorFlagSemantics(signed.access_mode, signed.required_status_flags,
      signed.forbidden_status_flags, signed.required_descriptor_flags,
      signed.forbidden_descriptor_flags, observed.observed_status_flags,
      observed.observed_descriptor_flags, `${label}.descriptor_table[${index}]`,
      "capability_descriptor_rejected");
    if (!objectsEqualByFields(observed, signed, policyFields)
        || ((observed.observed_status_flags & signed.required_status_flags) >>> 0)
          !== signed.required_status_flags
        || ((observed.observed_status_flags & signed.forbidden_status_flags) >>> 0) !== 0
        || ((observed.observed_descriptor_flags & signed.required_descriptor_flags) >>> 0)
          !== signed.required_descriptor_flags
        || ((observed.observed_descriptor_flags & signed.forbidden_descriptor_flags) >>> 0)
          !== 0) {
      reject("capability_descriptor_rejected", `${label} descriptor row ${index} drifted`);
    }
  }
}

function assertSessionDeadlines(session, policy) {
  const timestamps = [];
  for (let index = 0; index < SESSION_TIMESTAMP_FIELDS.length; index += 1) {
    const field = SESSION_TIMESTAMP_FIELDS[index];
    setArrayIndex(timestamps, index, timestampMilliseconds(session[field],
      `session.${field}`, "handoff_deadline_rejected"));
  }
  for (let index = 1; index < timestamps.length; index += 1) {
    if (timestamps[index] < timestamps[index - 1]) {
      reject("handoff_order_rejected", "handoff timestamps are not monotonic");
    }
  }
  const limits = [
    policy.challenge_timeout_ms,
    policy.attestation_timeout_ms,
    policy.grant_timeout_ms,
    policy.grant_timeout_ms,
    policy.go_timeout_ms,
    policy.receipt_timeout_ms,
    policy.receipt_timeout_ms,
    policy.receipt_timeout_ms,
    policy.cleanup_timeout_ms,
  ];
  for (let index = 1; index < timestamps.length; index += 1) {
    if (timestamps[index] - timestamps[index - 1] > limits[index - 1]) {
      reject("handoff_deadline_rejected", "handoff phase exceeded its signed deadline");
    }
  }
  if (timestamps[timestamps.length - 1] - timestamps[0] > policy.total_timeout_ms) {
    reject("handoff_deadline_rejected", "handoff exceeded the signed total deadline");
  }
  return { started: timestamps[0], completed: timestamps[timestamps.length - 1] };
}

function assertEvidenceQualified(evidence, verified, context) {
  const manifest = verified.manifest;
  const handoffPolicy = manifest.authority_handoff_policy;
  if (evidence.manifest_digest !== verified.manifest_digest
      || evidence.host.os !== context.host_os
      || evidence.host.architecture !== context.host_architecture
      || evidence.host.node_major !== context.host_node_major
      || evidence.host.napi_version !== context.host_napi_version
      || evidence.external_keyring.policy_digest !== context.external_keyring_policy_digest
      || evidence.external_keyring.evidence_digest
        !== context.expected_external_keyring_evidence_digest
      || evidence.external_keyring.keyring_identity_digest
        !== context.expected_external_keyring_identity_digest
      || evidence.external_keyring.observed_trust_epoch !== verified.trust_epoch
      || evidence.immutable_install.policy_digest !== context.immutable_install_policy_digest
      || evidence.immutable_install.evidence_digest
        !== context.expected_immutable_install_evidence_digest
      || evidence.immutable_install.install_identity_digest
        !== context.expected_install_identity_digest
      || evidence.immutable_install.principal_acl_policy_digest
        !== context.principal_acl_policy_digest
      || evidence.immutable_install.principal_acl_evidence_digest
        !== context.expected_principal_acl_evidence_digest
      || evidence.attestor.identity_digest !== context.expected_live_attestor_identity_digest
      || evidence.handoff.replay_fence_identity_digest
        !== context.expected_replay_fence_identity_digest
      || evidence.handoff.replay_fence_snapshot_digest
        !== context.expected_replay_fence_snapshot_digest
      || evidence.handoff.scheme !== handoffPolicy.scheme
      || evidence.handoff.supervisor_identity.supervisor_component_id
        !== handoffPolicy.supervisor_component_id
      || evidence.handoff.supervisor_identity.supervisor_role !== handoffPolicy.supervisor_role
      || evidence.handoff.process_lineage_scheme !== handoffPolicy.process_lineage_scheme
      || evidence.handoff.listener_identity_scheme !== handoffPolicy.listener_identity_scheme
      || evidence.handoff.post_exec_connection_scheme
        !== handoffPolicy.post_exec_connection_scheme
      || evidence.handoff.capability_set_digest_scheme
        !== handoffPolicy.capability_set_digest_scheme
      || evidence.handoff.grant_go_binding_scheme !== handoffPolicy.grant_go_binding_scheme
      || evidence.handoff.transport !== handoffPolicy.transport
      || evidence.handoff.peer_identity_scheme
        !== handoffPolicy.peer_identity_scheme
      || evidence.handoff.running_code_validation_scheme
        !== handoffPolicy.running_code_validation_scheme
      || evidence.handoff.security_requirement_validation_scheme
        !== handoffPolicy.security_requirement_validation_scheme
      || evidence.handoff.deadline_clock
        !== handoffPolicy.deadline_policy.clock
      || evidence.handoff.nonce_scheme !== handoffPolicy.nonce_policy.scheme
      || evidence.handoff.nonce_entropy_bits
        !== handoffPolicy.nonce_policy.entropy_bits
      || evidence.handoff.nonce_generation_bits
        !== handoffPolicy.nonce_policy.generation_bits
      || evidence.handoff.durable_exchange_scheme
        !== handoffPolicy.durable_exchange_policy.scheme) {
    reject("attestation_binding_rejected", "v2 attestation does not bind release and context");
  }
  const durable = handoffPolicy.durable_exchange_policy;
  assertSchemaObservationMatches(evidence.handoff.grant_record_schema,
    durable.grant_record_schema, "handoff.grant_record_schema");
  assertSchemaObservationMatches(evidence.handoff.go_record_schema,
    durable.go_record_schema, "handoff.go_record_schema");
  assertSchemaObservationMatches(evidence.handoff.receipt_record_schema,
    durable.receipt_record_schema, "handoff.receipt_record_schema");
  assertSchemaObservationMatches(evidence.handoff.outbox_record_schema,
    durable.outbox_record_schema, "handoff.outbox_record_schema");

  const handoffSessionIds = new SafeSet();
  const auditTokens = new SafeSet();
  const workerProcessIds = new SafeSet();
  const processInstances = new SafeSet();
  const processStarts = new SafeSet();
  const listenerIdentities = new SafeSet();
  const connectionIdentities = new SafeSet();
  const launchNonceDigests = new SafeSet();
  const capabilitySetDigests = new SafeSet();
  const grantIds = new SafeSet();
  const grantNonceDigests = new SafeSet();
  const grantRecordDigests = new SafeSet();
  const goIds = new SafeSet();
  const goRecordDigests = new SafeSet();
  const receiptRecordDigests = new SafeSet();
  const outboxRecordDigests = new SafeSet();
  const objectIdentities = new SafeSet();
  const handoffSchemaFields = [
    "grant_record_schema", "go_record_schema", "receipt_record_schema", "outbox_record_schema",
  ];
  for (let index = 0; index < handoffSchemaFields.length; index += 1) {
    const identity = evidence.handoff[handoffSchemaFields[index]].fd_identity_digest;
    if (reflectApply(setHas, objectIdentities, [identity])) {
      reject("schema_artifact_collision", "handoff schema descriptors alias one object");
    }
    reflectApply(setAdd, objectIdentities, [identity]);
  }
  const evidenceObservedMs = timestampMilliseconds(evidence.observed_at,
    "attestation observed_at", "attestation_time_rejected");
  const manifestIssuedMs = timestampMilliseconds(manifest.issued_at, "manifest issued_at");
  const supervisor = evidence.handoff.supervisor_identity;
  let supervisorIndex = -1;
  for (let index = 0; index < manifest.components.length; index += 1) {
    if (manifest.components[index].component_id === handoffPolicy.supervisor_component_id) {
      supervisorIndex = index;
    }
  }
  if (supervisorIndex < 0) {
    reject("supervisor_identity_rejected", "signed supervisor component is absent");
  }
  const supervisorComponent = evidence.components[supervisorIndex];
  const supervisorPrincipalDigest = digestObservedLaunchPrincipalV2(
    supervisorComponent.launch_principal,
  );
  if (supervisor.supervisor_mapped_image_digest
        !== supervisorComponent.mapped_measurement.measurement_digest
      || supervisor.supervisor_principal_id
        !== supervisorComponent.launch_principal.principal_id
      || supervisor.supervisor_principal_policy_digest !== supervisorPrincipalDigest
      || !objectsEqualByFields(
        supervisorComponent.component_handoff.supervisor_identity,
        supervisor,
        SUPERVISOR_IDENTITY_FIELDS,
      )
      || supervisor.supervisor_audit_token_digest === evidence.attestor.audit_token_digest) {
    reject("supervisor_identity_rejected",
      "observed supervisor identity does not bind the signed supervisor component");
  }
  reflectApply(setAdd, auditTokens, [supervisor.supervisor_audit_token_digest]);
  reflectApply(setAdd, workerProcessIds, [supervisor.supervisor_process_id]);
  reflectApply(setAdd, processInstances, [supervisor.supervisor_process_instance_digest]);
  reflectApply(setAdd, processStarts, [supervisor.supervisor_process_start_digest]);

  let previousLaunchGeneration = bigintFromString(
    evidence.handoff.previous_committed_generation,
  );
  let previousCapabilityGeneration = 0n;
  let previousListenerGeneration = 0n;
  let previousExchangeSequence = 0n;
  let finalListenerIdentity = null;
  let recipientIndex = 0;
  for (let index = 0; index < manifest.components.length; index += 1) {
    const expected = manifest.components[index];
    const actual = evidence.components[index];
    const isSupervisor = actual.component_id === handoffPolicy.supervisor_component_id;
    const session = isSupervisor ? null : evidence.handoff.sessions[recipientIndex];
    if (actual.component_id !== expected.component_id
        || actual.artifact_sha256 !== expected.sha256
        || actual.signature_kind !== expected.code_identity.signature_kind
        || actual.code_type !== expected.code_identity.code_type
        || actual.team_identifier !== expected.code_identity.team_identifier
        || actual.signing_identifier !== expected.code_identity.signing_identifier
        || actual.cdhash_algorithm !== expected.code_identity.cdhash_algorithm
        || actual.selected_cdhash !== expected.code_identity.selected_cdhash
        || actual.candidate_set_digest_scheme
          !== expected.code_identity.candidate_set_digest_scheme
        || actual.candidate_set_digest !== expected.code_identity.candidate_set_digest
        || actual.serialized_sec_requirement_digest
          !== expected.code_identity.serialized_sec_requirement_digest
        || actual.code_directory_flags !== expected.code_identity.code_directory_flags
        || actual.entitlements_digest_scheme
          !== expected.code_identity.entitlements_digest_scheme
        || actual.entitlements_digest !== expected.code_identity.entitlements_digest
        || actual.hardened_runtime !== true
        || actual.notarization_verified !== true
        || actual.adhoc !== false
        || !objectsEqualByFields(actual.macho_identity, expected.macho_identity, MACHO_FIELDS)
        || actual.launch_principal.principal_id !== expected.launch_principal.principal_id
        || actual.launch_principal.uid !== expected.launch_principal.uid
        || actual.launch_principal.gid !== expected.launch_principal.gid
        || actual.launch_principal.supplementary_groups_digest
          !== expected.launch_principal.supplementary_groups_digest
        || actual.launch_principal.audit_session_policy_digest
          !== expected.launch_principal.audit_session_policy_digest
        || actual.launch_principal.sandbox_profile_digest
          !== expected.launch_principal.sandbox_profile_digest
        || actual.mapped_measurement.scheme !== expected.mapped_measurement.scheme
        || actual.mapped_measurement.mapped_text_digest
          !== expected.mapped_measurement.expected_mapped_text_digest
        || actual.mapped_measurement.mapped_linkedit_digest
          !== expected.mapped_measurement.expected_mapped_linkedit_digest
        || actual.mapped_measurement.loaded_uuid
          !== expected.mapped_measurement.expected_loaded_uuid
        || actual.mapped_measurement.measurement_layout_digest
          !== expected.mapped_measurement.measurement_layout_digest) {
      reject("component_attestation_rejected", `v2 attestation rejected ${expected.component_id}`);
    }
    assertCapabilityAbiMatches(actual.capability_abi, expected.capability_abi,
      `components[${index}].capability_abi`);
    if (reflectApply(setHas, objectIdentities, [actual.on_disk_fd_identity_digest])) {
      reject("component_identity_collision", "component and schema descriptors alias an object");
    }
    reflectApply(setAdd, objectIdentities, [actual.on_disk_fd_identity_digest]);
    const abiSchemaFields = [
      "request_schema", "result_schema", "effect_journal_schema", "receipt_schema",
    ];
    for (let schemaIndex = 0; schemaIndex < abiSchemaFields.length; schemaIndex += 1) {
      const identity = actual.capability_abi[abiSchemaFields[schemaIndex]].fd_identity_digest;
      if (reflectApply(setHas, objectIdentities, [identity])) {
        reject("schema_artifact_collision", "ABI schema descriptors alias an object");
      }
      reflectApply(setAdd, objectIdentities, [identity]);
    }
    for (let descriptorIndex = 0;
      descriptorIndex < actual.capability_abi.descriptor_table.length; descriptorIndex += 1) {
      const identity = actual.capability_abi.descriptor_table[descriptorIndex]
        .descriptor_identity_digest;
      if (reflectApply(setHas, objectIdentities, [identity])) {
        reject("capability_descriptor_collision", "capability descriptors alias an object");
      }
      reflectApply(setAdd, objectIdentities, [identity]);
    }

    const machoDigest = digestObservedMachoIdentityV2(actual.macho_identity);
    const principalDigest = digestObservedLaunchPrincipalV2(actual.launch_principal);
    const mappedValues = [];
    for (let fieldIndex = 0; fieldIndex < MAPPED_BODY_FIELDS.length; fieldIndex += 1) {
      const field = MAPPED_BODY_FIELDS[fieldIndex];
      setArrayIndex(mappedValues, fieldIndex, actual.mapped_measurement[field]);
    }
    const mappedDigest = digestObservedMappedMeasurementV2(
      makeRecord(MAPPED_BODY_FIELDS, mappedValues));
    const abiDigest = digestObservedCapabilityAbiV2(actual.capability_abi);
    if (actual.mapped_measurement.measurement_digest !== mappedDigest) {
      reject("mapped_measurement_rejected",
        `mapped measurement digest rejected ${expected.component_id}`);
    }
    if (isSupervisor) {
      const supervisorBindingDigest = digestComponentBindingV2({
        version: 2,
        manifest_digest: evidence.manifest_digest,
        component_id: actual.component_id,
        artifact_sha256: actual.artifact_sha256,
        on_disk_fd_identity_digest: actual.on_disk_fd_identity_digest,
        component_handoff: actual.component_handoff,
        selected_cdhash: actual.selected_cdhash,
        candidate_set_digest: actual.candidate_set_digest,
        serialized_sec_requirement_digest: actual.serialized_sec_requirement_digest,
        code_directory_flags: actual.code_directory_flags,
        entitlements_digest: actual.entitlements_digest,
        macho_identity_digest: machoDigest,
        launch_principal_digest: principalDigest,
        mapped_measurement_digest: actual.mapped_measurement.measurement_digest,
        capability_abi_digest: abiDigest,
        running_code_identity_digest: actual.running_code_identity_digest,
        attestor_identity_digest: evidence.attestor.identity_digest,
      });
      if (actual.component_binding_digest !== supervisorBindingDigest) {
        reject("component_binding_rejected",
          `component binding rejected ${expected.component_id}`);
      }
      continue;
    }
    const componentHandoff = actual.component_handoff;
    const lineage = componentHandoff.worker_lineage;
    const exchange = componentHandoff.exchange_binding;
    if (session.component_id !== actual.component_id
        || session.handoff_session_digest !== componentHandoff.handoff_session_digest
        || !objectsEqualByFields(session.worker_lineage, lineage, WORKER_LINEAGE_FIELDS)
        || !objectsEqualByFields(session.exchange_binding, exchange, EXCHANGE_BINDING_FIELDS)) {
      reject("component_attestation_rejected",
        `recipient session rejected ${expected.component_id}`);
    }
    if (lineage.worker_mapped_image_digest !== mappedDigest
        || lineage.worker_principal_id !== actual.launch_principal.principal_id
        || lineage.worker_principal_policy_digest !== principalDigest
        || lineage.worker_direct_parent_process_id !== supervisor.supervisor_process_id
        || lineage.worker_direct_parent_audit_token_digest
          !== supervisor.supervisor_audit_token_digest
        || lineage.worker_direct_parent_instance_digest
          !== supervisor.supervisor_process_instance_digest
        || lineage.worker_direct_parent_start_digest
          !== supervisor.supervisor_process_start_digest) {
      reject("process_lineage_rejected",
        `worker lineage rejected ${expected.component_id}`);
    }
    const expectedCapabilitySetDigest = digestCapabilitySetV2({
      version: 2,
      component_id: actual.component_id,
      capability_abi_digest: abiDigest,
    });
    if (exchange.capability_abi_digest !== abiDigest
        || exchange.capability_set_digest !== expectedCapabilitySetDigest) {
      reject("capability_set_rejected",
        `capability set rejected ${expected.component_id}`);
    }
    const sessionSupervisor = supervisorIdentityAtWorkerListener(supervisor, lineage);
    const expectedGrantRecordDigest = digestGrantRecordV2({
      version: 2,
      manifest_digest: evidence.manifest_digest,
      component_id: actual.component_id,
      handoff_session_id: session.handoff_session_id,
      supervisor_identity: sessionSupervisor,
      worker_lineage: lineage,
      launch_nonce_digest: exchange.launch_nonce_digest,
      launch_generation: exchange.launch_generation,
      capability_set_digest: exchange.capability_set_digest,
      capability_generation: exchange.capability_generation,
      capability_abi_digest: exchange.capability_abi_digest,
      grant_id: exchange.grant_id,
      grant_nonce_digest: exchange.grant_nonce_digest,
      grant_sequence: exchange.grant_sequence,
    });
    const expectedGoRecordDigest = digestGoRecordV2({
      version: 2,
      manifest_digest: evidence.manifest_digest,
      component_id: actual.component_id,
      handoff_session_id: session.handoff_session_id,
      supervisor_identity: sessionSupervisor,
      worker_lineage: lineage,
      launch_nonce_digest: exchange.launch_nonce_digest,
      launch_generation: exchange.launch_generation,
      capability_set_digest: exchange.capability_set_digest,
      capability_generation: exchange.capability_generation,
      grant_id: exchange.grant_id,
      grant_sequence: exchange.grant_sequence,
      grant_record_digest: exchange.grant_record_digest,
      go_id: exchange.go_id,
      go_sequence: exchange.go_sequence,
    });
    if (exchange.grant_record_digest !== expectedGrantRecordDigest
        || exchange.go_record_digest !== expectedGoRecordDigest) {
      reject("authenticated_exchange_rejected",
        `grant/GO record binding rejected ${expected.component_id}`);
    }
    const bindingDigest = digestComponentBindingV2({
      version: 2,
      manifest_digest: evidence.manifest_digest,
      component_id: actual.component_id,
      artifact_sha256: actual.artifact_sha256,
      on_disk_fd_identity_digest: actual.on_disk_fd_identity_digest,
      component_handoff: actual.component_handoff,
      selected_cdhash: actual.selected_cdhash,
      candidate_set_digest: actual.candidate_set_digest,
      serialized_sec_requirement_digest: actual.serialized_sec_requirement_digest,
      code_directory_flags: actual.code_directory_flags,
      entitlements_digest: actual.entitlements_digest,
      macho_identity_digest: machoDigest,
      launch_principal_digest: principalDigest,
      mapped_measurement_digest: actual.mapped_measurement.measurement_digest,
      capability_abi_digest: abiDigest,
      running_code_identity_digest: actual.running_code_identity_digest,
      attestor_identity_digest: evidence.attestor.identity_digest,
    });
    if (actual.component_binding_digest !== bindingDigest) {
      reject("component_binding_rejected", `component binding rejected ${expected.component_id}`);
    }
    const launchGeneration = bigintFromString(exchange.launch_generation);
    const capabilityGeneration = bigintFromString(exchange.capability_generation);
    const listenerGeneration = bigintFromString(lineage.supervisor_listener_generation);
    const grantSequence = bigintFromString(exchange.grant_sequence);
    const goSequence = bigintFromString(exchange.go_sequence);
    const replayed = reflectApply(setHas, handoffSessionIds, [session.handoff_session_id])
      || reflectApply(setHas, auditTokens, [lineage.worker_audit_token_digest])
      || reflectApply(setHas, workerProcessIds, [lineage.worker_process_id])
      || reflectApply(setHas, processInstances, [lineage.worker_process_instance_digest])
      || reflectApply(setHas, processStarts, [lineage.worker_process_start_digest])
      || reflectApply(setHas, listenerIdentities,
        [lineage.supervisor_listener_identity_digest])
      || reflectApply(setHas, connectionIdentities,
        [lineage.post_exec_connection_identity_digest])
      || reflectApply(setHas, launchNonceDigests, [exchange.launch_nonce_digest])
      || reflectApply(setHas, capabilitySetDigests, [exchange.capability_set_digest])
      || reflectApply(setHas, grantIds, [exchange.grant_id])
      || reflectApply(setHas, grantNonceDigests, [exchange.grant_nonce_digest])
      || reflectApply(setHas, grantRecordDigests, [exchange.grant_record_digest])
      || reflectApply(setHas, goIds, [exchange.go_id])
      || reflectApply(setHas, goRecordDigests, [exchange.go_record_digest])
      || reflectApply(setHas, receiptRecordDigests, [session.receipt_record_digest])
      || reflectApply(setHas, outboxRecordDigests, [session.outbox_record_digest]);
    if (replayed || launchGeneration <= previousLaunchGeneration
        || capabilityGeneration <= previousCapabilityGeneration
        || listenerGeneration <= previousListenerGeneration
        || grantSequence <= previousExchangeSequence
        || goSequence !== grantSequence + 1n) {
      reject("replay_fence_rejected",
        "lineage, nonce, capability, grant, and GO identities must be fresh and monotonic");
    }
    const uniqueClaims = [
      [handoffSessionIds, session.handoff_session_id],
      [auditTokens, lineage.worker_audit_token_digest],
      [workerProcessIds, lineage.worker_process_id],
      [processInstances, lineage.worker_process_instance_digest],
      [processStarts, lineage.worker_process_start_digest],
      [listenerIdentities, lineage.supervisor_listener_identity_digest],
      [connectionIdentities, lineage.post_exec_connection_identity_digest],
      [launchNonceDigests, exchange.launch_nonce_digest],
      [capabilitySetDigests, exchange.capability_set_digest],
      [grantIds, exchange.grant_id],
      [grantNonceDigests, exchange.grant_nonce_digest],
      [grantRecordDigests, exchange.grant_record_digest],
      [goIds, exchange.go_id],
      [goRecordDigests, exchange.go_record_digest],
      [receiptRecordDigests, session.receipt_record_digest],
      [outboxRecordDigests, session.outbox_record_digest],
    ];
    for (let claimIndex = 0; claimIndex < uniqueClaims.length; claimIndex += 1) {
      reflectApply(setAdd, uniqueClaims[claimIndex][0], [uniqueClaims[claimIndex][1]]);
    }
    previousLaunchGeneration = launchGeneration;
    previousCapabilityGeneration = capabilityGeneration;
    previousListenerGeneration = listenerGeneration;
    previousExchangeSequence = goSequence;
    finalListenerIdentity = lineage.supervisor_listener_identity_digest;
    const interval = assertSessionDeadlines(session, handoffPolicy.deadline_policy);
    if (interval.started < manifestIssuedMs || interval.completed > evidenceObservedMs) {
      reject("handoff_time_rejected",
        "handoff session is outside the release and observation interval");
    }
    recipientIndex += 1;
  }

  if (recipientIndex !== evidence.handoff.sessions.length) {
    reject("component_attestation_rejected", "recipient sessions do not close the component set");
  }

  if (previousLaunchGeneration !== bigintFromString(evidence.handoff.committed_generation)) {
    reject("replay_fence_rejected",
      "committed replay-fence generation does not close the observed sessions");
  }
  if (previousListenerGeneration
        !== bigintFromString(supervisor.supervisor_listener_generation)
      || finalListenerIdentity !== supervisor.supervisor_listener_identity_digest) {
    reject("listener_identity_rejected",
      "terminal supervisor listener identity does not close the launch sequence");
  }

  const observed = evidenceObservedMs;
  const validUntil = timestampMilliseconds(evidence.valid_until, "attestation valid_until",
    "attestation_time_rejected");
  const now = timestampMilliseconds(context.now, "doctor now", "attestation_time_rejected");
  const maximumAge = manifest.doctor_policy.max_evidence_age_ms;
  if (observed > now || validUntil <= now || validUntil <= observed
      || validUntil - observed > maximumAge || now - observed > maximumAge
      || observed < manifestIssuedMs) {
    reject("attestation_time_rejected", "v2 attestation is stale, future, or over-age");
  }
}

function report(status, fields = {}) {
  return objectFreeze({
    version: NATIVE_PREBUILD_TRUST_V2_VERSION,
    kind: "native_prebuild_doctor_report_v2",
    status,
    manifest_digest: fields.manifest_digest || EMPTY_DIGEST,
    release_signature_valid: fields.release_signature_valid === true,
    v2_schema_valid: fields.v2_schema_valid === true,
    external_immutable_keyring_evidence_valid:
      fields.external_immutable_keyring_evidence_valid === true,
    live_native_attestation_evidence_valid:
      fields.live_native_attestation_evidence_valid === true,
    production_ready: false,
    hardware_access_authorized: false,
    authoritative: false,
    host_inspection_performed: false,
    native_execution_performed: false,
    external_keyring_read_performed: false,
    capability_transfer_performed: false,
    findings: objectFreeze(fields.findings || []),
  });
}

function finding(error, prefix) {
  const code = error != null && typeof error === "object" && typeof error.code === "string"
    ? error.code
    : "rejected";
  return `${prefix}:${code}`;
}

function evaluateNativePrebuildDoctorV2(input) {
  let context;
  let verified;
  try {
    assertExactObject(input, DOCTOR_INPUT_FIELDS, "native_prebuild_doctor_v2",
      "doctor_input_invalid");
    context = normalizeContext(ownValue(input, "evaluation_context",
      "native_prebuild_doctor_v2", "doctor_input_invalid"));
    verified = verifyReleaseEnvelopeV2({
      envelope: ownValue(input, "envelope", "native_prebuild_doctor_v2",
        "doctor_input_invalid"),
      trust_policy: ownValue(input, "trust_policy", "native_prebuild_doctor_v2",
        "doctor_input_invalid"),
      now: context.now,
    });
  } catch (error) {
    return report("unavailable", { findings: [finding(error, "release_unavailable")] });
  }
  try {
    assertContextMatches(context, verified);
  } catch (error) {
    return report("blocked", {
      manifest_digest: verified.manifest_digest,
      release_signature_valid: true,
      findings: [finding(error, "release_context_blocked")],
    });
  }
  const evidenceInput = ownValue(input, "live_attestation", "native_prebuild_doctor_v2",
    "doctor_input_invalid");
  if (evidenceInput === null) {
    return report("blocked", {
      manifest_digest: verified.manifest_digest,
      release_signature_valid: true,
      findings: ["live_attestation:unavailable", "doctor_v2:non_authorizing"],
    });
  }
  try {
    const evidence = normalizeEvidence(evidenceInput);
    assertEvidenceQualified(evidence, verified, context);
  } catch (error) {
    return report("blocked", {
      manifest_digest: verified.manifest_digest,
      release_signature_valid: true,
      findings: [finding(error, "live_attestation")],
    });
  }
  return report("diagnostic_complete_non_authorizing", {
    manifest_digest: verified.manifest_digest,
    release_signature_valid: true,
    v2_schema_valid: true,
    external_immutable_keyring_evidence_valid: true,
    live_native_attestation_evidence_valid: true,
    findings: [
      "doctor_v2:caller_supplied_evidence_only",
      "doctor_v2:non_authorizing",
      "external_native_admission_authority_required",
    ],
  });
}

module.exports = {
  DOCTOR_V2_STATUSES,
  NATIVE_PREBUILD_ATTESTATION_V2_DOMAIN,
  NATIVE_PREBUILD_CAPABILITY_SET_V2_DOMAIN,
  NATIVE_PREBUILD_COMPONENT_BINDING_V2_DOMAIN,
  NATIVE_PREBUILD_GO_RECORD_V2_DOMAIN,
  NATIVE_PREBUILD_GRANT_RECORD_V2_DOMAIN,
  NATIVE_PREBUILD_HANDOFF_SESSION_V2_DOMAIN,
  NATIVE_PREBUILD_OBSERVED_ABI_V2_DOMAIN,
  NATIVE_PREBUILD_OBSERVED_MACHO_V2_DOMAIN,
  NATIVE_PREBUILD_OBSERVED_MAPPED_V2_DOMAIN,
  NATIVE_PREBUILD_OBSERVED_PRINCIPAL_V2_DOMAIN,
  NATIVE_PREBUILD_RECIPIENT_COMPONENTS_V2,
  digestComponentBindingV2,
  digestCapabilitySetV2,
  digestGoRecordV2,
  digestGrantRecordV2,
  digestHandoffSessionV2,
  digestNativePrebuildAttestationV2Body,
  digestObservedCapabilityAbiV2,
  digestObservedLaunchPrincipalV2,
  digestObservedMachoIdentityV2,
  digestObservedMappedMeasurementV2,
  evaluateNativePrebuildDoctorV2,
};
