"use strict";

const {
  arraysEqual,
  assertAbsoluteSystemDependency,
  assertBoolean,
  assertDenseArray,
  assertDigest,
  assertExactObject,
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
const {
  NATIVE_PREBUILD_REQUIRED_COMPONENTS,
  NATIVE_PREBUILD_REQUIRED_HIL_GATES,
  NATIVE_PREBUILD_TRUST_VERSION,
  verifyReleaseEnvelope,
} = require("./release-trust");

const objectFreeze = Object.freeze;

const STATIC_INSPECTION_DOMAIN =
  "hacker-bob/native-prebuild-static-inspection-evidence/v1";
const NATIVE_ATTESTATION_DOMAIN =
  "hacker-bob/native-prebuild-native-attestation-evidence/v1";
const NATIVE_COMPONENT_IDENTITY_BINDING_DOMAIN =
  "hacker-bob/native-prebuild-component-identity-binding/v1";
const HIL_EVIDENCE_DOMAIN =
  "hacker-bob/native-prebuild-hil-evidence/v1";
const EMPTY_DIGEST = "0".repeat(64);

const DOCTOR_STATUSES = objectFreeze([
  "unavailable",
  "blocked",
  "qualified_pending_hil",
  "diagnostic_complete_non_authorizing",
]);

const STATIC_BODY_FIELDS = objectFreeze([
  "version",
  "kind",
  "manifest_digest",
  "inspection_id",
  "inspected_at",
  "valid_until",
  "root",
  "components",
]);
const STATIC_FIELDS = objectFreeze([
  "version",
  "kind",
  "manifest_digest",
  "inspection_id",
  "inspected_at",
  "valid_until",
  "root",
  "components",
  "inspection_digest",
]);
const STATIC_ROOT_FIELDS = objectFreeze([
  "install_root_path_digest",
  "install_root_owner_uid",
  "install_root_owner_gid",
  "install_root_mode",
  "root_owned_ancestry",
  "no_symlink_walk",
  "open_scheme",
  "openat_walk_complete",
  "stable_file_identity",
  "terminal_reopen_match",
  "retained_artifact_fds",
  "root_immutable",
  "immutability_scheme",
  "filesystem_immutability_evidence_digest",
  "principal_acl_policy_digest",
  "principal_acl_evidence_digest",
]);
const STATIC_COMPONENT_FIELDS = objectFreeze([
  "component_id",
  "artifact_path",
  "artifact_kind",
  "byte_size",
  "sha256",
  "owner_uid",
  "owner_gid",
  "mode",
  "nlink",
  "regular_file",
  "symlink",
  "immutable",
  "openat_no_follow",
  "pre_post_identity_match",
  "fd_identity_digest",
  "actual_dynamic_dependencies",
  "weak_dependencies_present",
  "upward_dependencies_present",
  "rpaths",
  "macho_signature",
]);
const MACHO_EVIDENCE_FIELDS = objectFreeze([
  "signature_kind",
  "code_type",
  "team_identifier",
  "signing_identifier",
  "cdhash_algorithm",
  "selected_cdhash",
  "hardened_runtime",
  "notarization_verified",
  "adhoc",
  "designated_requirement_digest",
  "entitlements_digest",
  "signature_validation_complete",
]);

const NATIVE_BODY_FIELDS = objectFreeze([
  "version",
  "kind",
  "manifest_digest",
  "inspection_digest",
  "attestation_id",
  "observed_at",
  "valid_until",
  "host",
  "attestor",
  "components",
]);
const NATIVE_FIELDS = objectFreeze([
  "version",
  "kind",
  "manifest_digest",
  "inspection_digest",
  "attestation_id",
  "observed_at",
  "valid_until",
  "host",
  "attestor",
  "components",
  "attestation_digest",
]);
const NATIVE_HOST_FIELDS = objectFreeze([
  "os",
  "architecture",
  "node_major",
  "napi_version",
]);
const NATIVE_ATTESTOR_FIELDS = objectFreeze([
  "implementation_digest",
  "source_digest",
  "loaded_image_digest",
  "install_root_path_digest",
  "filesystem_immutability_evidence_digest",
  "root_owned_immutable",
  "principal_acl_policy_digest",
  "principal_acl_evidence_digest",
  "kernel_evidence_complete",
  "live_double_read_complete",
]);
const NATIVE_COMPONENT_FIELDS = objectFreeze([
  "component_id",
  "artifact_sha256",
  "static_cdhash",
  "on_disk_fd_identity_digest",
  "loaded_image_sha256",
  "loaded_or_exec_image_identity_digest",
  "mapped_process_image_identity_digest",
  "identity_binding_scheme",
  "identity_binding_digest",
  "host_or_equivalent_validation_mode",
  "host_or_equivalent_validation_complete",
  "on_disk_fd_bound",
  "loaded_or_exec_image_bound",
  "mapped_process_image_bound",
  "pre_post_identity_match",
  "kernel_originated",
]);
const NATIVE_COMPONENT_IDENTITY_BINDING_FIELDS = objectFreeze([
  "version",
  "scheme",
  "manifest_digest",
  "inspection_digest",
  "component_id",
  "artifact_kind",
  "artifact_sha256",
  "static_cdhash",
  "designated_requirement_digest",
  "on_disk_fd_identity_digest",
  "loaded_image_sha256",
  "loaded_or_exec_image_identity_digest",
  "mapped_process_image_identity_digest",
  "host_or_equivalent_validation_mode",
  "attestor_implementation_digest",
  "principal_acl_evidence_digest",
]);

const HIL_BODY_FIELDS = objectFreeze([
  "version",
  "kind",
  "manifest_digest",
  "native_attestation_digest",
  "suite_id",
  "suite_digest",
  "authority_scope_digest",
  "device_qualification_policy_digest",
  "fixture_manifest_digest",
  "operator_witness_policy_digest",
  "hil_run_id",
  "run_at",
  "valid_until",
  "gate_results",
]);
const HIL_FIELDS = objectFreeze([
  "version",
  "kind",
  "manifest_digest",
  "native_attestation_digest",
  "suite_id",
  "suite_digest",
  "authority_scope_digest",
  "device_qualification_policy_digest",
  "fixture_manifest_digest",
  "operator_witness_policy_digest",
  "hil_run_id",
  "run_at",
  "valid_until",
  "gate_results",
  "hil_evidence_digest",
]);
const HIL_GATE_FIELDS = objectFreeze([
  "gate_id",
  "passed",
  "evidence_digest",
  "authority_scope_digest",
  "device_identity_digest",
  "operator_witness_digest",
]);

const CONTEXT_FIELDS = objectFreeze([
  "now",
  "expected_manifest_digest",
  "expected_package_name",
  "expected_package_version",
  "expected_release_epoch",
  "expected_install_root_path_digest",
  "host_os",
  "host_architecture",
  "host_node_major",
  "host_napi_version",
  "principal_acl_policy_digest",
  "expected_principal_acl_evidence_digest",
  "expected_hil_authority_scope_digest",
  "expected_hil_device_identity_digest",
  "expected_hil_fixture_manifest_digest",
  "expected_hil_operator_witness_digest",
]);
const DOCTOR_INPUT_FIELDS = objectFreeze([
  "envelope",
  "trust_policy",
  "evaluation_context",
  "static_inspection",
  "native_attestation",
  "hil_evidence",
]);
const CDHASH_PATTERN = /^[a-f0-9]{40}$/u;
const TEAM_PATTERN = /^[A-Z0-9]{10}$/u;
const SIGNING_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9.-]{0,190}$/u;

function evidenceRecord(body, bodyFields, fullFields, digest) {
  const values = [];
  for (let index = 0; index < bodyFields.length; index += 1) {
    setArrayIndex(values, index, body[bodyFields[index]]);
  }
  setArrayIndex(values, bodyFields.length, digest);
  return makeRecord(fullFields, values);
}

function normalizeStringArray(input, label, validator, maximum = 64) {
  assertDenseArray(input, label, maximum, "evidence_schema_invalid");
  const values = [];
  for (let index = 0; index < input.length; index += 1) {
    setArrayIndex(values, index, validator(
      ownValue(input, `${index}`, label, "evidence_schema_invalid"),
      `${label}[${index}]`,
    ));
  }
  return makeArray(values);
}

function normalizeStaticRoot(input) {
  const label = "static_inspection.root";
  assertExactObject(input, STATIC_ROOT_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(STATIC_ROOT_FIELDS, [
    assertDigest(ownValue(input, "install_root_path_digest", label),
      `${label}.install_root_path_digest`, "evidence_schema_invalid"),
    assertInteger(ownValue(input, "install_root_owner_uid", label),
      `${label}.install_root_owner_uid`, 0, 0xffffffff, "evidence_schema_invalid"),
    assertInteger(ownValue(input, "install_root_owner_gid", label),
      `${label}.install_root_owner_gid`, 0, 0xffffffff, "evidence_schema_invalid"),
    assertInteger(ownValue(input, "install_root_mode", label),
      `${label}.install_root_mode`, 0, 0o7777, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "root_owned_ancestry", label),
      `${label}.root_owned_ancestry`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "no_symlink_walk", label), `${label}.no_symlink_walk`,
      "evidence_schema_invalid"),
    assertString(ownValue(input, "open_scheme", label), `${label}.open_scheme`, {
      maximumBytes: 128, code: "evidence_schema_invalid",
    }),
    assertBoolean(ownValue(input, "openat_walk_complete", label),
      `${label}.openat_walk_complete`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "stable_file_identity", label),
      `${label}.stable_file_identity`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "terminal_reopen_match", label),
      `${label}.terminal_reopen_match`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "retained_artifact_fds", label),
      `${label}.retained_artifact_fds`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "root_immutable", label), `${label}.root_immutable`,
      "evidence_schema_invalid"),
    assertString(ownValue(input, "immutability_scheme", label),
      `${label}.immutability_scheme`, { maximumBytes: 128, code: "evidence_schema_invalid" }),
    assertDigest(ownValue(input, "filesystem_immutability_evidence_digest", label),
      `${label}.filesystem_immutability_evidence_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "principal_acl_policy_digest", label),
      `${label}.principal_acl_policy_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "principal_acl_evidence_digest", label),
      `${label}.principal_acl_evidence_digest`, "evidence_schema_invalid"),
  ]);
}

function normalizeMachOEvidence(input, label) {
  assertExactObject(input, MACHO_EVIDENCE_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(MACHO_EVIDENCE_FIELDS, [
    assertString(ownValue(input, "signature_kind", label), `${label}.signature_kind`, {
      maximumBytes: 64, code: "evidence_schema_invalid",
    }),
    assertString(ownValue(input, "code_type", label), `${label}.code_type`, {
      maximumBytes: 64, code: "evidence_schema_invalid",
    }),
    assertString(ownValue(input, "team_identifier", label), `${label}.team_identifier`, {
      pattern: TEAM_PATTERN, maximumBytes: 10, code: "evidence_schema_invalid",
    }),
    assertString(ownValue(input, "signing_identifier", label), `${label}.signing_identifier`, {
      pattern: SIGNING_IDENTIFIER_PATTERN, maximumBytes: 191,
      code: "evidence_schema_invalid",
    }),
    assertString(ownValue(input, "cdhash_algorithm", label), `${label}.cdhash_algorithm`, {
      maximumBytes: 32, code: "evidence_schema_invalid",
    }),
    assertString(ownValue(input, "selected_cdhash", label), `${label}.selected_cdhash`, {
      pattern: CDHASH_PATTERN, minimumBytes: 40, maximumBytes: 40,
      code: "evidence_schema_invalid",
    }),
    assertBoolean(ownValue(input, "hardened_runtime", label), `${label}.hardened_runtime`,
      "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "notarization_verified", label),
      `${label}.notarization_verified`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "adhoc", label), `${label}.adhoc`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "designated_requirement_digest", label),
      `${label}.designated_requirement_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "entitlements_digest", label),
      `${label}.entitlements_digest`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "signature_validation_complete", label),
      `${label}.signature_validation_complete`, "evidence_schema_invalid"),
  ]);
}

function normalizeStaticComponent(input, index) {
  const label = `static_inspection.components[${index}]`;
  assertExactObject(input, STATIC_COMPONENT_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(STATIC_COMPONENT_FIELDS, [
    assertString(ownValue(input, "component_id", label), `${label}.component_id`, {
      maximumBytes: 128, code: "evidence_schema_invalid",
    }),
    assertRelativeArtifactPath(ownValue(input, "artifact_path", label),
      `${label}.artifact_path`, "evidence_schema_invalid"),
    assertString(ownValue(input, "artifact_kind", label), `${label}.artifact_kind`, {
      maximumBytes: 64, code: "evidence_schema_invalid",
    }),
    assertInteger(ownValue(input, "byte_size", label), `${label}.byte_size`, 1,
      256 * 1024 * 1024, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "sha256", label), `${label}.sha256`,
      "evidence_schema_invalid"),
    assertInteger(ownValue(input, "owner_uid", label), `${label}.owner_uid`, 0, 0xffffffff,
      "evidence_schema_invalid"),
    assertInteger(ownValue(input, "owner_gid", label), `${label}.owner_gid`, 0, 0xffffffff,
      "evidence_schema_invalid"),
    assertInteger(ownValue(input, "mode", label), `${label}.mode`, 0, 0o7777,
      "evidence_schema_invalid"),
    assertInteger(ownValue(input, "nlink", label), `${label}.nlink`, 0, 1024,
      "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "regular_file", label), `${label}.regular_file`,
      "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "symlink", label), `${label}.symlink`,
      "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "immutable", label), `${label}.immutable`,
      "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "openat_no_follow", label), `${label}.openat_no_follow`,
      "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "pre_post_identity_match", label),
      `${label}.pre_post_identity_match`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "fd_identity_digest", label), `${label}.fd_identity_digest`,
      "evidence_schema_invalid"),
    normalizeStringArray(ownValue(input, "actual_dynamic_dependencies", label),
      `${label}.actual_dynamic_dependencies`, (value, itemLabel) =>
        assertAbsoluteSystemDependency(value, itemLabel, "evidence_schema_invalid")),
    assertBoolean(ownValue(input, "weak_dependencies_present", label),
      `${label}.weak_dependencies_present`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "upward_dependencies_present", label),
      `${label}.upward_dependencies_present`, "evidence_schema_invalid"),
    normalizeStringArray(ownValue(input, "rpaths", label), `${label}.rpaths`,
      (value, itemLabel) => assertString(value, itemLabel, {
        maximumBytes: 512, code: "evidence_schema_invalid",
      })),
    normalizeMachOEvidence(ownValue(input, "macho_signature", label),
      `${label}.macho_signature`),
  ]);
}

function normalizeStaticBody(input) {
  const label = "static_inspection";
  assertExactObject(input, STATIC_BODY_FIELDS, label, "evidence_schema_invalid");
  const version = assertInteger(ownValue(input, "version", label), `${label}.version`, 1, 1,
    "evidence_schema_invalid");
  const kind = ownValue(input, "kind", label);
  if (kind !== "native_prebuild_static_inspection") {
    reject("evidence_schema_invalid", `${label}.kind is invalid`);
  }
  const componentInputs = ownValue(input, "components", label);
  assertDenseArray(componentInputs, `${label}.components`,
    NATIVE_PREBUILD_REQUIRED_COMPONENTS.length, "evidence_schema_invalid");
  if (componentInputs.length !== NATIVE_PREBUILD_REQUIRED_COMPONENTS.length) {
    reject("evidence_schema_invalid", `${label}.components is incomplete`);
  }
  const components = [];
  for (let index = 0; index < componentInputs.length; index += 1) {
    setArrayIndex(components, index, normalizeStaticComponent(
      ownValue(componentInputs, `${index}`, `${label}.components`, "evidence_schema_invalid"),
      index,
    ));
  }
  return makeRecord(STATIC_BODY_FIELDS, [
    version,
    kind,
    assertDigest(ownValue(input, "manifest_digest", label), `${label}.manifest_digest`,
      "evidence_schema_invalid"),
    assertOpaqueToken(ownValue(input, "inspection_id", label), `${label}.inspection_id`,
      "evidence_schema_invalid"),
    assertTimestamp(ownValue(input, "inspected_at", label), `${label}.inspected_at`,
      "evidence_schema_invalid"),
    assertTimestamp(ownValue(input, "valid_until", label), `${label}.valid_until`,
      "evidence_schema_invalid"),
    normalizeStaticRoot(ownValue(input, "root", label)),
    makeArray(components),
  ]);
}

function digestStaticInspectionEvidenceBody(input) {
  return domainDigest(STATIC_INSPECTION_DOMAIN, normalizeStaticBody(input));
}

function normalizeStaticEvidence(input) {
  const label = "static_inspection";
  assertExactObject(input, STATIC_FIELDS, label, "evidence_schema_invalid");
  const bodyValues = [];
  for (let index = 0; index < STATIC_BODY_FIELDS.length; index += 1) {
    setArrayIndex(bodyValues, index, ownValue(input, STATIC_BODY_FIELDS[index], label,
      "evidence_schema_invalid"));
  }
  const body = normalizeStaticBody(makeRecord(STATIC_BODY_FIELDS, bodyValues));
  const digest = assertDigest(ownValue(input, "inspection_digest", label),
    `${label}.inspection_digest`, "evidence_digest_invalid");
  if (digest !== domainDigest(STATIC_INSPECTION_DOMAIN, body)) {
    reject("evidence_digest_invalid", `${label}.inspection_digest does not match`);
  }
  return evidenceRecord(body, STATIC_BODY_FIELDS, STATIC_FIELDS, digest);
}

function normalizeNativeHost(input) {
  const label = "native_attestation.host";
  assertExactObject(input, NATIVE_HOST_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(NATIVE_HOST_FIELDS, [
    assertString(ownValue(input, "os", label), `${label}.os`, {
      maximumBytes: 32, code: "evidence_schema_invalid",
    }),
    assertString(ownValue(input, "architecture", label), `${label}.architecture`, {
      maximumBytes: 32, code: "evidence_schema_invalid",
    }),
    assertInteger(ownValue(input, "node_major", label), `${label}.node_major`, 1, 999,
      "evidence_schema_invalid"),
    assertInteger(ownValue(input, "napi_version", label), `${label}.napi_version`, 1, 999,
      "evidence_schema_invalid"),
  ]);
}

function normalizeNativeAttestor(input) {
  const label = "native_attestation.attestor";
  assertExactObject(input, NATIVE_ATTESTOR_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(NATIVE_ATTESTOR_FIELDS, [
    assertDigest(ownValue(input, "implementation_digest", label),
      `${label}.implementation_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "source_digest", label), `${label}.source_digest`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "loaded_image_digest", label),
      `${label}.loaded_image_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "install_root_path_digest", label),
      `${label}.install_root_path_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "filesystem_immutability_evidence_digest", label),
      `${label}.filesystem_immutability_evidence_digest`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "root_owned_immutable", label),
      `${label}.root_owned_immutable`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "principal_acl_policy_digest", label),
      `${label}.principal_acl_policy_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "principal_acl_evidence_digest", label),
      `${label}.principal_acl_evidence_digest`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "kernel_evidence_complete", label),
      `${label}.kernel_evidence_complete`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "live_double_read_complete", label),
      `${label}.live_double_read_complete`, "evidence_schema_invalid"),
  ]);
}

function normalizeNativeComponent(input, index) {
  const label = `native_attestation.components[${index}]`;
  assertExactObject(input, NATIVE_COMPONENT_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(NATIVE_COMPONENT_FIELDS, [
    assertString(ownValue(input, "component_id", label), `${label}.component_id`, {
      maximumBytes: 128, code: "evidence_schema_invalid",
    }),
    assertDigest(ownValue(input, "artifact_sha256", label), `${label}.artifact_sha256`,
      "evidence_schema_invalid"),
    assertString(ownValue(input, "static_cdhash", label), `${label}.static_cdhash`, {
      pattern: CDHASH_PATTERN, minimumBytes: 40, maximumBytes: 40,
      code: "evidence_schema_invalid",
    }),
    assertDigest(ownValue(input, "on_disk_fd_identity_digest", label),
      `${label}.on_disk_fd_identity_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "loaded_image_sha256", label),
      `${label}.loaded_image_sha256`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "loaded_or_exec_image_identity_digest", label),
      `${label}.loaded_or_exec_image_identity_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "mapped_process_image_identity_digest", label),
      `${label}.mapped_process_image_identity_digest`, "evidence_schema_invalid"),
    assertString(ownValue(input, "identity_binding_scheme", label),
      `${label}.identity_binding_scheme`, {
        maximumBytes: 128, code: "evidence_schema_invalid",
      }),
    assertDigest(ownValue(input, "identity_binding_digest", label),
      `${label}.identity_binding_digest`, "evidence_schema_invalid"),
    assertString(ownValue(input, "host_or_equivalent_validation_mode", label),
      `${label}.host_or_equivalent_validation_mode`, {
        maximumBytes: 128, code: "evidence_schema_invalid",
      }),
    assertBoolean(ownValue(input, "host_or_equivalent_validation_complete", label),
      `${label}.host_or_equivalent_validation_complete`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "on_disk_fd_bound", label), `${label}.on_disk_fd_bound`,
      "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "loaded_or_exec_image_bound", label),
      `${label}.loaded_or_exec_image_bound`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "mapped_process_image_bound", label),
      `${label}.mapped_process_image_bound`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "pre_post_identity_match", label),
      `${label}.pre_post_identity_match`, "evidence_schema_invalid"),
    assertBoolean(ownValue(input, "kernel_originated", label), `${label}.kernel_originated`,
      "evidence_schema_invalid"),
  ]);
}

function normalizeNativeComponentIdentityBinding(input) {
  const label = "native_component_identity_binding";
  assertExactObject(input, NATIVE_COMPONENT_IDENTITY_BINDING_FIELDS, label,
    "identity_binding_invalid");
  const scheme = ownValue(input, "scheme", label);
  if (scheme !== "darwin_fd_codesign_loaded_mapped_cross_binding_v1") {
    reject("identity_binding_invalid", `${label}.scheme is unsupported`);
  }
  const artifactKind = ownValue(input, "artifact_kind", label);
  if (artifactKind !== "node_native_addon" && artifactKind !== "mach_o_executable") {
    reject("identity_binding_invalid", `${label}.artifact_kind is unsupported`);
  }
  return makeRecord(NATIVE_COMPONENT_IDENTITY_BINDING_FIELDS, [
    assertInteger(ownValue(input, "version", label), `${label}.version`, 1, 1,
      "identity_binding_invalid"),
    scheme,
    assertDigest(ownValue(input, "manifest_digest", label), `${label}.manifest_digest`,
      "identity_binding_invalid"),
    assertDigest(ownValue(input, "inspection_digest", label), `${label}.inspection_digest`,
      "identity_binding_invalid"),
    assertString(ownValue(input, "component_id", label), `${label}.component_id`, {
      maximumBytes: 128, code: "identity_binding_invalid",
    }),
    artifactKind,
    assertDigest(ownValue(input, "artifact_sha256", label), `${label}.artifact_sha256`,
      "identity_binding_invalid"),
    assertString(ownValue(input, "static_cdhash", label), `${label}.static_cdhash`, {
      pattern: CDHASH_PATTERN, minimumBytes: 40, maximumBytes: 40,
      code: "identity_binding_invalid",
    }),
    assertDigest(ownValue(input, "designated_requirement_digest", label),
      `${label}.designated_requirement_digest`, "identity_binding_invalid"),
    assertDigest(ownValue(input, "on_disk_fd_identity_digest", label),
      `${label}.on_disk_fd_identity_digest`, "identity_binding_invalid"),
    assertDigest(ownValue(input, "loaded_image_sha256", label),
      `${label}.loaded_image_sha256`, "identity_binding_invalid"),
    assertDigest(ownValue(input, "loaded_or_exec_image_identity_digest", label),
      `${label}.loaded_or_exec_image_identity_digest`, "identity_binding_invalid"),
    assertDigest(ownValue(input, "mapped_process_image_identity_digest", label),
      `${label}.mapped_process_image_identity_digest`, "identity_binding_invalid"),
    assertString(ownValue(input, "host_or_equivalent_validation_mode", label),
      `${label}.host_or_equivalent_validation_mode`, {
        maximumBytes: 128, code: "identity_binding_invalid",
      }),
    assertDigest(ownValue(input, "attestor_implementation_digest", label),
      `${label}.attestor_implementation_digest`, "identity_binding_invalid"),
    assertDigest(ownValue(input, "principal_acl_evidence_digest", label),
      `${label}.principal_acl_evidence_digest`, "identity_binding_invalid"),
  ]);
}

function digestNativeComponentIdentityBinding(input) {
  return domainDigest(NATIVE_COMPONENT_IDENTITY_BINDING_DOMAIN,
    normalizeNativeComponentIdentityBinding(input));
}

function normalizeNativeBody(input) {
  const label = "native_attestation";
  assertExactObject(input, NATIVE_BODY_FIELDS, label, "evidence_schema_invalid");
  const version = assertInteger(ownValue(input, "version", label), `${label}.version`, 1, 1,
    "evidence_schema_invalid");
  const kind = ownValue(input, "kind", label);
  if (kind !== "native_prebuild_loaded_image_attestation") {
    reject("evidence_schema_invalid", `${label}.kind is invalid`);
  }
  const componentInputs = ownValue(input, "components", label);
  assertDenseArray(componentInputs, `${label}.components`,
    NATIVE_PREBUILD_REQUIRED_COMPONENTS.length, "evidence_schema_invalid");
  if (componentInputs.length !== NATIVE_PREBUILD_REQUIRED_COMPONENTS.length) {
    reject("evidence_schema_invalid", `${label}.components is incomplete`);
  }
  const components = [];
  for (let index = 0; index < componentInputs.length; index += 1) {
    setArrayIndex(components, index, normalizeNativeComponent(
      ownValue(componentInputs, `${index}`, `${label}.components`, "evidence_schema_invalid"),
      index,
    ));
  }
  return makeRecord(NATIVE_BODY_FIELDS, [
    version,
    kind,
    assertDigest(ownValue(input, "manifest_digest", label), `${label}.manifest_digest`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "inspection_digest", label), `${label}.inspection_digest`,
      "evidence_schema_invalid"),
    assertOpaqueToken(ownValue(input, "attestation_id", label), `${label}.attestation_id`,
      "evidence_schema_invalid"),
    assertTimestamp(ownValue(input, "observed_at", label), `${label}.observed_at`,
      "evidence_schema_invalid"),
    assertTimestamp(ownValue(input, "valid_until", label), `${label}.valid_until`,
      "evidence_schema_invalid"),
    normalizeNativeHost(ownValue(input, "host", label)),
    normalizeNativeAttestor(ownValue(input, "attestor", label)),
    makeArray(components),
  ]);
}

function digestNativeAttestationEvidenceBody(input) {
  return domainDigest(NATIVE_ATTESTATION_DOMAIN, normalizeNativeBody(input));
}

function normalizeNativeEvidence(input) {
  const label = "native_attestation";
  assertExactObject(input, NATIVE_FIELDS, label, "evidence_schema_invalid");
  const bodyValues = [];
  for (let index = 0; index < NATIVE_BODY_FIELDS.length; index += 1) {
    setArrayIndex(bodyValues, index, ownValue(input, NATIVE_BODY_FIELDS[index], label,
      "evidence_schema_invalid"));
  }
  const body = normalizeNativeBody(makeRecord(NATIVE_BODY_FIELDS, bodyValues));
  const digest = assertDigest(ownValue(input, "attestation_digest", label),
    `${label}.attestation_digest`, "evidence_digest_invalid");
  if (digest !== domainDigest(NATIVE_ATTESTATION_DOMAIN, body)) {
    reject("evidence_digest_invalid", `${label}.attestation_digest does not match`);
  }
  return evidenceRecord(body, NATIVE_BODY_FIELDS, NATIVE_FIELDS, digest);
}

function normalizeHilGate(input, index) {
  const label = `hil_evidence.gate_results[${index}]`;
  assertExactObject(input, HIL_GATE_FIELDS, label, "evidence_schema_invalid");
  return makeRecord(HIL_GATE_FIELDS, [
    assertString(ownValue(input, "gate_id", label), `${label}.gate_id`, {
      maximumBytes: 128, code: "evidence_schema_invalid",
    }),
    assertBoolean(ownValue(input, "passed", label), `${label}.passed`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "evidence_digest", label), `${label}.evidence_digest`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "authority_scope_digest", label),
      `${label}.authority_scope_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "device_identity_digest", label),
      `${label}.device_identity_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "operator_witness_digest", label),
      `${label}.operator_witness_digest`, "evidence_schema_invalid"),
  ]);
}

function normalizeHilBody(input) {
  const label = "hil_evidence";
  assertExactObject(input, HIL_BODY_FIELDS, label, "evidence_schema_invalid");
  const version = assertInteger(ownValue(input, "version", label), `${label}.version`, 1, 1,
    "evidence_schema_invalid");
  const kind = ownValue(input, "kind", label);
  if (kind !== "native_prebuild_hil_qualification") {
    reject("evidence_schema_invalid", `${label}.kind is invalid`);
  }
  const gateInputs = ownValue(input, "gate_results", label);
  assertDenseArray(gateInputs, `${label}.gate_results`,
    NATIVE_PREBUILD_REQUIRED_HIL_GATES.length, "evidence_schema_invalid");
  if (gateInputs.length !== NATIVE_PREBUILD_REQUIRED_HIL_GATES.length) {
    reject("evidence_schema_invalid", `${label}.gate_results is incomplete`);
  }
  const gates = [];
  for (let index = 0; index < gateInputs.length; index += 1) {
    setArrayIndex(gates, index, normalizeHilGate(
      ownValue(gateInputs, `${index}`, `${label}.gate_results`, "evidence_schema_invalid"),
      index,
    ));
  }
  return makeRecord(HIL_BODY_FIELDS, [
    version,
    kind,
    assertDigest(ownValue(input, "manifest_digest", label), `${label}.manifest_digest`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "native_attestation_digest", label),
      `${label}.native_attestation_digest`, "evidence_schema_invalid"),
    assertString(ownValue(input, "suite_id", label), `${label}.suite_id`, {
      maximumBytes: 128, code: "evidence_schema_invalid",
    }),
    assertDigest(ownValue(input, "suite_digest", label), `${label}.suite_digest`,
      "evidence_schema_invalid"),
    assertDigest(ownValue(input, "authority_scope_digest", label),
      `${label}.authority_scope_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "device_qualification_policy_digest", label),
      `${label}.device_qualification_policy_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "fixture_manifest_digest", label),
      `${label}.fixture_manifest_digest`, "evidence_schema_invalid"),
    assertDigest(ownValue(input, "operator_witness_policy_digest", label),
      `${label}.operator_witness_policy_digest`, "evidence_schema_invalid"),
    assertOpaqueToken(ownValue(input, "hil_run_id", label), `${label}.hil_run_id`,
      "evidence_schema_invalid"),
    assertTimestamp(ownValue(input, "run_at", label), `${label}.run_at`,
      "evidence_schema_invalid"),
    assertTimestamp(ownValue(input, "valid_until", label), `${label}.valid_until`,
      "evidence_schema_invalid"),
    makeArray(gates),
  ]);
}

function digestHilEvidenceBody(input) {
  return domainDigest(HIL_EVIDENCE_DOMAIN, normalizeHilBody(input));
}

function normalizeHilEvidence(input) {
  const label = "hil_evidence";
  assertExactObject(input, HIL_FIELDS, label, "evidence_schema_invalid");
  const bodyValues = [];
  for (let index = 0; index < HIL_BODY_FIELDS.length; index += 1) {
    setArrayIndex(bodyValues, index, ownValue(input, HIL_BODY_FIELDS[index], label,
      "evidence_schema_invalid"));
  }
  const body = normalizeHilBody(makeRecord(HIL_BODY_FIELDS, bodyValues));
  const digest = assertDigest(ownValue(input, "hil_evidence_digest", label),
    `${label}.hil_evidence_digest`, "evidence_digest_invalid");
  if (digest !== domainDigest(HIL_EVIDENCE_DOMAIN, body)) {
    reject("evidence_digest_invalid", `${label}.hil_evidence_digest does not match`);
  }
  return evidenceRecord(body, HIL_BODY_FIELDS, HIL_FIELDS, digest);
}

function normalizeContext(input) {
  const label = "native_prebuild_doctor.evaluation_context";
  assertExactObject(input, CONTEXT_FIELDS, label, "context_invalid");
  return makeRecord(CONTEXT_FIELDS, [
    assertTimestamp(ownValue(input, "now", label), `${label}.now`, "context_invalid"),
    assertDigest(ownValue(input, "expected_manifest_digest", label),
      `${label}.expected_manifest_digest`, "context_invalid"),
    assertString(ownValue(input, "expected_package_name", label),
      `${label}.expected_package_name`, { maximumBytes: 140, code: "context_invalid" }),
    assertString(ownValue(input, "expected_package_version", label),
      `${label}.expected_package_version`, { maximumBytes: 128, code: "context_invalid" }),
    assertInteger(ownValue(input, "expected_release_epoch", label),
      `${label}.expected_release_epoch`, 1, Number.MAX_SAFE_INTEGER, "context_invalid"),
    assertDigest(ownValue(input, "expected_install_root_path_digest", label),
      `${label}.expected_install_root_path_digest`, "context_invalid"),
    assertString(ownValue(input, "host_os", label), `${label}.host_os`, {
      maximumBytes: 32, code: "context_invalid",
    }),
    assertString(ownValue(input, "host_architecture", label), `${label}.host_architecture`, {
      maximumBytes: 32, code: "context_invalid",
    }),
    assertInteger(ownValue(input, "host_node_major", label), `${label}.host_node_major`, 1, 999,
      "context_invalid"),
    assertInteger(ownValue(input, "host_napi_version", label), `${label}.host_napi_version`, 1,
      999, "context_invalid"),
    assertDigest(ownValue(input, "principal_acl_policy_digest", label),
      `${label}.principal_acl_policy_digest`, "context_invalid"),
    assertDigest(ownValue(input, "expected_principal_acl_evidence_digest", label),
      `${label}.expected_principal_acl_evidence_digest`, "context_invalid"),
    assertDigest(ownValue(input, "expected_hil_authority_scope_digest", label),
      `${label}.expected_hil_authority_scope_digest`, "context_invalid"),
    assertDigest(ownValue(input, "expected_hil_device_identity_digest", label),
      `${label}.expected_hil_device_identity_digest`, "context_invalid"),
    assertDigest(ownValue(input, "expected_hil_fixture_manifest_digest", label),
      `${label}.expected_hil_fixture_manifest_digest`, "context_invalid"),
    assertDigest(ownValue(input, "expected_hil_operator_witness_digest", label),
      `${label}.expected_hil_operator_witness_digest`, "context_invalid"),
  ]);
}

function assertContextMatches(context, verified) {
  const manifest = verified.manifest;
  if (context.expected_manifest_digest !== verified.manifest_digest
      || context.expected_package_name !== manifest.package_name
      || context.expected_package_version !== manifest.package_version
      || context.expected_release_epoch !== manifest.release_epoch
      || context.expected_install_root_path_digest
        !== manifest.filesystem_policy.install_root_path_digest
      || context.host_os !== manifest.target.os
      || context.host_architecture !== manifest.target.architecture
      || context.host_node_major !== manifest.target.node_major
      || context.host_napi_version !== manifest.target.napi_version
      || context.principal_acl_policy_digest !== manifest.principal_acl_policy_digest
      || context.expected_hil_authority_scope_digest
        !== manifest.hil_policy.authority_scope_digest
      || context.expected_hil_fixture_manifest_digest
        !== manifest.hil_policy.fixture_manifest_digest) {
    reject("context_binding_rejected", "doctor context does not bind the selected release and host");
  }
}

function isSecureMode(mode) {
  return (mode & 0o6022) === 0;
}

function assertStaticComponentIdentitiesDistinct(components) {
  for (let index = 0; index < components.length; index += 1) {
    const current = components[index];
    for (let priorIndex = 0; priorIndex < index; priorIndex += 1) {
      const prior = components[priorIndex];
      if (current.sha256 === prior.sha256
          || current.fd_identity_digest === prior.fd_identity_digest
          || current.macho_signature.selected_cdhash
            === prior.macho_signature.selected_cdhash
          || current.macho_signature.signing_identifier
            === prior.macho_signature.signing_identifier
          || current.macho_signature.designated_requirement_digest
            === prior.macho_signature.designated_requirement_digest) {
        reject("static_component_identity_collision",
          "static inspection collapses distinct component roles onto one code identity");
      }
    }
  }
}

function assertNativeComponentIdentitiesDistinct(components) {
  for (let index = 0; index < components.length; index += 1) {
    const current = components[index];
    for (let priorIndex = 0; priorIndex < index; priorIndex += 1) {
      const prior = components[priorIndex];
      if (current.artifact_sha256 === prior.artifact_sha256
          || current.on_disk_fd_identity_digest === prior.on_disk_fd_identity_digest
          || current.loaded_image_sha256 === prior.loaded_image_sha256
          || current.loaded_or_exec_image_identity_digest
            === prior.loaded_or_exec_image_identity_digest
          || current.mapped_process_image_identity_digest
            === prior.mapped_process_image_identity_digest) {
        reject("native_component_identity_collision",
          "native attestation collapses distinct component roles onto one object or image");
      }
    }
  }
}

function assertEvidenceFresh(observedAt, validUntil, maximumAgeMs, now, code, label) {
  const observedMs = timestampMilliseconds(observedAt, `${label}.observed_at`, code);
  const validUntilMs = timestampMilliseconds(validUntil, `${label}.valid_until`, code);
  const nowMs = timestampMilliseconds(now, "doctor context now", code);
  if (observedMs > nowMs || validUntilMs <= nowMs || validUntilMs <= observedMs
      || validUntilMs - observedMs > maximumAgeMs || nowMs - observedMs > maximumAgeMs) {
    reject(code, `${label} is stale, future-dated, or exceeds the signed maximum age`);
  }
  return observedMs;
}

function assertStaticQualified(evidence, verified, context) {
  const manifest = verified.manifest;
  const root = evidence.root;
  if (evidence.manifest_digest !== verified.manifest_digest
      || root.install_root_path_digest !== manifest.filesystem_policy.install_root_path_digest
      || root.install_root_path_digest !== context.expected_install_root_path_digest
      || root.install_root_owner_uid !== 0 || root.install_root_owner_gid !== 0
      || !isSecureMode(root.install_root_mode)
      || root.root_owned_ancestry !== true || root.no_symlink_walk !== true
      || root.open_scheme !== manifest.filesystem_policy.required_open_scheme
      || root.openat_walk_complete !== true || root.stable_file_identity !== true
      || root.terminal_reopen_match !== true || root.retained_artifact_fds !== true
      || root.root_immutable !== true
      || (root.immutability_scheme !== "read_only_mount_v1"
        && root.immutability_scheme !== "darwin_system_immutable_flags_v1")
      || root.principal_acl_policy_digest !== context.principal_acl_policy_digest
      || root.principal_acl_policy_digest !== manifest.principal_acl_policy_digest
      || root.principal_acl_evidence_digest
        !== context.expected_principal_acl_evidence_digest) {
    reject("static_filesystem_rejected", "static inspection does not prove the filesystem policy");
  }
  for (let index = 0; index < manifest.components.length; index += 1) {
    const expected = manifest.components[index];
    const actual = evidence.components[index];
    const signing = actual.macho_signature;
    const policy = expected.macho_signing_policy;
    if (actual.component_id !== expected.component_id
        || actual.artifact_path !== expected.artifact_path
        || actual.artifact_kind !== expected.artifact_kind
        || actual.byte_size !== expected.byte_size || actual.sha256 !== expected.sha256
        || actual.owner_uid !== 0 || actual.owner_gid !== 0 || !isSecureMode(actual.mode)
        || actual.nlink !== 1 || actual.regular_file !== true || actual.symlink !== false
        || actual.immutable !== true || actual.openat_no_follow !== true
        || actual.pre_post_identity_match !== true
        || !arraysEqual(actual.actual_dynamic_dependencies,
          expected.dynamic_dependency_policy.exact_dependencies)
        || actual.weak_dependencies_present !== false
        || actual.upward_dependencies_present !== false || actual.rpaths.length !== 0) {
      reject("static_component_rejected", `static inspection rejected ${expected.component_id}`);
    }
    if (signing.signature_kind !== policy.signature_kind
        || signing.code_type !== policy.code_type
        || signing.team_identifier !== policy.team_identifier
        || signing.signing_identifier !== policy.signing_identifier
        || signing.cdhash_algorithm !== policy.cdhash_algorithm
        || signing.hardened_runtime !== true
        || signing.notarization_verified !== true || signing.adhoc !== false
        || signing.designated_requirement_digest !== policy.designated_requirement_digest
        || signing.entitlements_digest !== policy.entitlements_digest
        || signing.signature_validation_complete !== true) {
      reject("static_codesign_rejected", `Mach-O signature evidence rejected ${expected.component_id}`);
    }
  }
  assertStaticComponentIdentitiesDistinct(evidence.components);
  const inspectedMs = assertEvidenceFresh(evidence.inspected_at, evidence.valid_until,
    manifest.filesystem_policy.max_static_inspection_age_ms, context.now,
    "static_time_rejected", "static inspection");
  if (inspectedMs < timestampMilliseconds(manifest.issued_at, "manifest issued_at")) {
    reject("static_time_rejected", "static inspection time is outside the release evaluation window");
  }
}

function assertNativeQualified(evidence, staticEvidence, verified, context) {
  const manifest = verified.manifest;
  if (evidence.manifest_digest !== verified.manifest_digest
      || evidence.inspection_digest !== staticEvidence.inspection_digest
      || evidence.host.os !== context.host_os
      || evidence.host.architecture !== context.host_architecture
      || evidence.host.node_major !== context.host_node_major
      || evidence.host.napi_version !== context.host_napi_version
      || evidence.attestor.install_root_path_digest !== staticEvidence.root.install_root_path_digest
      || evidence.attestor.filesystem_immutability_evidence_digest
        !== staticEvidence.root.filesystem_immutability_evidence_digest
      || evidence.attestor.root_owned_immutable !== true
      || evidence.attestor.principal_acl_policy_digest
        !== context.principal_acl_policy_digest
      || evidence.attestor.principal_acl_evidence_digest
        !== context.expected_principal_acl_evidence_digest
      || evidence.attestor.principal_acl_evidence_digest
        !== staticEvidence.root.principal_acl_evidence_digest
      || evidence.attestor.implementation_digest
        !== manifest.native_attestation_policy.attestor_implementation_digest
      || evidence.attestor.source_digest
        !== manifest.native_attestation_policy.attestor_source_digest
      || evidence.attestor.loaded_image_digest
        !== manifest.native_attestation_policy.attestor_loaded_image_digest
      || evidence.attestor.kernel_evidence_complete !== true
      || evidence.attestor.live_double_read_complete !== true) {
    reject("native_attestation_rejected", "native attestation does not bind the release and host");
  }
  for (let index = 0; index < manifest.components.length; index += 1) {
    const expected = manifest.components[index];
    const staticComponent = staticEvidence.components[index];
    const actual = evidence.components[index];
    const validationMode = expected.artifact_kind === "node_native_addon"
      ? "exact_openat_loaded_mapped_image_identity_v1"
      : "hardened_runtime_designated_requirement_v1";
    const bindingDigest = digestNativeComponentIdentityBinding({
      version: 1,
      scheme: actual.identity_binding_scheme,
      manifest_digest: evidence.manifest_digest,
      inspection_digest: evidence.inspection_digest,
      component_id: actual.component_id,
      artifact_kind: expected.artifact_kind,
      artifact_sha256: actual.artifact_sha256,
      static_cdhash: actual.static_cdhash,
      designated_requirement_digest:
        staticComponent.macho_signature.designated_requirement_digest,
      on_disk_fd_identity_digest: actual.on_disk_fd_identity_digest,
      loaded_image_sha256: actual.loaded_image_sha256,
      loaded_or_exec_image_identity_digest: actual.loaded_or_exec_image_identity_digest,
      mapped_process_image_identity_digest: actual.mapped_process_image_identity_digest,
      host_or_equivalent_validation_mode: actual.host_or_equivalent_validation_mode,
      attestor_implementation_digest: evidence.attestor.implementation_digest,
      principal_acl_evidence_digest: evidence.attestor.principal_acl_evidence_digest,
    });
    if (actual.component_id !== expected.component_id
        || actual.artifact_sha256 !== expected.sha256
        || actual.static_cdhash !== staticComponent.macho_signature.selected_cdhash
        || actual.on_disk_fd_identity_digest !== staticComponent.fd_identity_digest
        || actual.loaded_image_sha256 !== expected.sha256
        || actual.identity_binding_scheme
          !== manifest.native_attestation_policy.component_identity_binding_scheme
        || actual.identity_binding_digest !== bindingDigest
        || actual.host_or_equivalent_validation_mode !== validationMode
        || actual.host_or_equivalent_validation_complete !== true
        || actual.on_disk_fd_bound !== true || actual.loaded_or_exec_image_bound !== true
        || actual.mapped_process_image_bound !== true
        || actual.pre_post_identity_match !== true || actual.kernel_originated !== true) {
      reject("mapped_image_rejected", `loaded image identity rejected ${expected.component_id}`);
    }
  }
  assertNativeComponentIdentitiesDistinct(evidence.components);
  const observedMs = assertEvidenceFresh(evidence.observed_at, evidence.valid_until,
    manifest.native_attestation_policy.max_attestation_age_ms, context.now,
    "native_time_rejected", "native attestation");
  if (observedMs < timestampMilliseconds(staticEvidence.inspected_at, "static inspected_at")
      || observedMs >= timestampMilliseconds(staticEvidence.valid_until,
        "static valid_until")) {
    reject("native_time_rejected", "native attestation time is outside the evidence sequence");
  }
}

function assertHilQualified(evidence, nativeEvidence, verified, context) {
  if (evidence.manifest_digest !== verified.manifest_digest
      || evidence.native_attestation_digest !== nativeEvidence.attestation_digest
      || evidence.suite_id !== verified.manifest.hil_policy.suite_id
      || evidence.suite_digest !== verified.manifest.hil_policy.suite_digest
      || evidence.authority_scope_digest
        !== verified.manifest.hil_policy.authority_scope_digest
      || evidence.authority_scope_digest !== context.expected_hil_authority_scope_digest
      || evidence.device_qualification_policy_digest
        !== verified.manifest.hil_policy.device_qualification_policy_digest
      || evidence.fixture_manifest_digest
        !== verified.manifest.hil_policy.fixture_manifest_digest
      || evidence.fixture_manifest_digest !== context.expected_hil_fixture_manifest_digest
      || evidence.operator_witness_policy_digest
        !== verified.manifest.hil_policy.operator_witness_policy_digest) {
    reject("hil_binding_rejected", "HIL evidence does not bind the release and native attestation");
  }
  for (let index = 0; index < NATIVE_PREBUILD_REQUIRED_HIL_GATES.length; index += 1) {
    const gate = evidence.gate_results[index];
    if (gate.gate_id !== NATIVE_PREBUILD_REQUIRED_HIL_GATES[index] || gate.passed !== true
        || gate.authority_scope_digest !== context.expected_hil_authority_scope_digest
        || gate.device_identity_digest !== context.expected_hil_device_identity_digest
        || gate.operator_witness_digest !== context.expected_hil_operator_witness_digest) {
      reject("hil_gate_rejected", `HIL gate failed: ${NATIVE_PREBUILD_REQUIRED_HIL_GATES[index]}`);
    }
  }
  const runMs = assertEvidenceFresh(evidence.run_at, evidence.valid_until,
    verified.manifest.hil_policy.max_evidence_age_ms, context.now,
    "hil_time_rejected", "HIL evidence");
  if (runMs < timestampMilliseconds(nativeEvidence.observed_at, "native observed_at")
      || runMs >= timestampMilliseconds(nativeEvidence.valid_until, "native valid_until")) {
    reject("hil_time_rejected", "HIL evidence time is outside the evidence sequence");
  }
}

function diagnosticReport(status, fields = {}) {
  const findings = [];
  const inputFindings = fields.findings || [];
  for (let index = 0; index < inputFindings.length; index += 1) {
    setArrayIndex(findings, index, inputFindings[index]);
  }
  return objectFreeze({
    version: NATIVE_PREBUILD_TRUST_VERSION,
    kind: "native_prebuild_doctor_report",
    status,
    manifest_digest: fields.manifest_digest || EMPTY_DIGEST,
    release_signature_valid: fields.release_signature_valid === true,
    static_inspection_valid: fields.static_inspection_valid === true,
    native_attestation_valid: fields.native_attestation_valid === true,
    hil_evidence_valid: fields.hil_evidence_valid === true,
    production_ready: false,
    hardware_access_authorized: false,
    authoritative: false,
    host_inspection_performed: false,
    native_execution_performed: false,
    findings: objectFreeze(findings),
  });
}

function findingFor(error, prefix) {
  const code = error != null && typeof error === "object" && typeof error.code === "string"
    ? error.code
    : "rejected";
  return `${prefix}:${code}`;
}

function evaluateNativePrebuildDoctor(input) {
  let verified;
  let context;
  try {
    assertExactObject(input, DOCTOR_INPUT_FIELDS, "native_prebuild_doctor",
      "doctor_input_invalid");
    context = normalizeContext(ownValue(input, "evaluation_context", "native_prebuild_doctor",
      "doctor_input_invalid"));
    verified = verifyReleaseEnvelope({
      envelope: ownValue(input, "envelope", "native_prebuild_doctor", "doctor_input_invalid"),
      trust_policy: ownValue(input, "trust_policy", "native_prebuild_doctor",
        "doctor_input_invalid"),
      now: context.now,
    });
  } catch (error) {
    return diagnosticReport("unavailable", {
      findings: [findingFor(error, "release_unavailable")],
    });
  }
  try {
    assertContextMatches(context, verified);
  } catch (error) {
    return diagnosticReport("blocked", {
      manifest_digest: verified.manifest_digest,
      release_signature_valid: true,
      findings: [findingFor(error, "release_context_blocked")],
    });
  }

  const staticInput = ownValue(input, "static_inspection", "native_prebuild_doctor",
    "doctor_input_invalid");
  if (staticInput === null) {
    return diagnosticReport("blocked", {
      manifest_digest: verified.manifest_digest,
      release_signature_valid: true,
      findings: ["static_inspection:unavailable"],
    });
  }
  let staticEvidence;
  try {
    staticEvidence = normalizeStaticEvidence(staticInput);
    assertStaticQualified(staticEvidence, verified, context);
  } catch (error) {
    return diagnosticReport("blocked", {
      manifest_digest: verified.manifest_digest,
      release_signature_valid: true,
      findings: [findingFor(error, "static_inspection")],
    });
  }

  const nativeInput = ownValue(input, "native_attestation", "native_prebuild_doctor",
    "doctor_input_invalid");
  if (nativeInput === null) {
    return diagnosticReport("blocked", {
      manifest_digest: verified.manifest_digest,
      release_signature_valid: true,
      static_inspection_valid: true,
      findings: ["native_attestation:unavailable"],
    });
  }
  let nativeEvidence;
  try {
    nativeEvidence = normalizeNativeEvidence(nativeInput);
    assertNativeQualified(nativeEvidence, staticEvidence, verified, context);
  } catch (error) {
    return diagnosticReport("blocked", {
      manifest_digest: verified.manifest_digest,
      release_signature_valid: true,
      static_inspection_valid: true,
      findings: [findingFor(error, "native_attestation")],
    });
  }

  const hilInput = ownValue(input, "hil_evidence", "native_prebuild_doctor",
    "doctor_input_invalid");
  if (hilInput === null) {
    return diagnosticReport("qualified_pending_hil", {
      manifest_digest: verified.manifest_digest,
      release_signature_valid: true,
      static_inspection_valid: true,
      native_attestation_valid: true,
      findings: ["hil_evidence:unavailable", "doctor:non_authorizing"],
    });
  }
  try {
    const hilEvidence = normalizeHilEvidence(hilInput);
    assertHilQualified(hilEvidence, nativeEvidence, verified, context);
  } catch (error) {
    return diagnosticReport("blocked", {
      manifest_digest: verified.manifest_digest,
      release_signature_valid: true,
      static_inspection_valid: true,
      native_attestation_valid: true,
      findings: [findingFor(error, "hil_evidence")],
    });
  }
  return diagnosticReport("diagnostic_complete_non_authorizing", {
    manifest_digest: verified.manifest_digest,
    release_signature_valid: true,
    static_inspection_valid: true,
    native_attestation_valid: true,
    hil_evidence_valid: true,
    findings: ["doctor:non_authorizing", "separate_admission_authority_required"],
  });
}

module.exports = {
  DOCTOR_STATUSES,
  HIL_EVIDENCE_DOMAIN,
  NATIVE_ATTESTATION_DOMAIN,
  NATIVE_COMPONENT_IDENTITY_BINDING_DOMAIN,
  STATIC_INSPECTION_DOMAIN,
  digestHilEvidenceBody,
  digestNativeAttestationEvidenceBody,
  digestNativeComponentIdentityBinding,
  digestStaticInspectionEvidenceBody,
  evaluateNativePrebuildDoctor,
};
