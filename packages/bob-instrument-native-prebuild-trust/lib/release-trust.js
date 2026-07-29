"use strict";

const crypto = require("node:crypto");
const {
  arraysEqual,
  assertAbsoluteSystemDependency,
  assertBoolean,
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

const cryptoCreatePublicKey = crypto.createPublicKey;
const cryptoVerify = crypto.verify;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const reflectApply = Reflect.apply;
const regexpTest = RegExp.prototype.test;
const bufferFrom = Buffer.from;
const bufferToString = Buffer.prototype.toString;
const cryptoCreateHash = crypto.createHash;
const hashPrototype = objectGetPrototypeOf(reflectApply(cryptoCreateHash, crypto, ["sha256"]));
const hashUpdate = objectGetOwnPropertyDescriptor(hashPrototype, "update").value;
const hashDigest = objectGetOwnPropertyDescriptor(hashPrototype, "digest").value;
const SafeSet = Set;
const setAdd = Set.prototype.add;
const setHas = Set.prototype.has;
const stringStartsWith = String.prototype.startsWith;

const NATIVE_PREBUILD_TRUST_VERSION = 1;
const NATIVE_PREBUILD_MANIFEST_DOMAIN =
  "hacker-bob/native-prebuild-release-manifest/v1";
const NATIVE_PREBUILD_SIGNATURE_DOMAIN =
  "hacker-bob/native-prebuild-release-signature/v1";
const NATIVE_PREBUILD_ENVELOPE_DOMAIN =
  "hacker-bob/native-prebuild-release-envelope/v1";
const NATIVE_PREBUILD_KEY_USAGE = "native_prebuild_release";

const NATIVE_PREBUILD_REQUIRED_COMPONENTS = objectFreeze([
  "native_ipc_acceptor",
  "chameleon_cdc_custody",
  "safety_watchdog",
  "privileged_launcher",
]);
const NATIVE_PREBUILD_REQUIRED_HIL_GATES = objectFreeze([
  "ipc_descriptor_binding",
  "chameleon_read_only_inventory",
  "safety_cleanup_fault_matrix",
  "privileged_launcher_principal_matrix",
  "cross_component_custody_chain",
  "negative_tamper_matrix",
]);
const COMPONENT_KINDS = objectFreeze({
  native_ipc_acceptor: "node_native_addon",
  chameleon_cdc_custody: "node_native_addon",
  safety_watchdog: "mach_o_executable",
  privileged_launcher: "mach_o_executable",
});
const COMPONENT_CODE_TYPES = objectFreeze({
  native_ipc_acceptor: "bundle",
  chameleon_cdc_custody: "bundle",
  safety_watchdog: "executable",
  privileged_launcher: "executable",
});
const VERIFICATION_BLOCKERS = objectFreeze([
  "release_signature_is_not_macho_signature",
  "caller_supplied_inspection_is_not_native_attestation",
  "filesystem_immutability_must_be_proved_at_install_and_use",
  "loaded_or_exec_image_identity_must_be_natively_bound",
  "dedicated_principal_and_acl_binding_must_be_provisioned",
  "hardware_in_loop_qualification_must_pass",
  "verification_result_is_diagnostic_not_authority",
]);

const MANIFEST_FIELDS = objectFreeze([
  "version",
  "kind",
  "package_name",
  "package_version",
  "release_id",
  "release_epoch",
  "target",
  "components",
  "source_tree_digest",
  "builder_identity_digest",
  "toolchain_manifest_digest",
  "provenance_statement_digest",
  "principal_acl_policy_digest",
  "filesystem_policy",
  "native_attestation_policy",
  "hil_policy",
  "issued_at",
  "expires_at",
]);
const TARGET_FIELDS = objectFreeze([
  "os",
  "architecture",
  "node_major",
  "napi_version",
  "node_api_only",
  "deployment_format",
]);
const COMPONENT_FIELDS = objectFreeze([
  "component_id",
  "artifact_path",
  "artifact_kind",
  "byte_size",
  "sha256",
  "source_digest",
  "builder_digest",
  "toolchain_digest",
  "provenance_digest",
  "dynamic_dependency_policy",
  "macho_signing_policy",
]);
const DYNAMIC_DEPENDENCY_POLICY_FIELDS = objectFreeze([
  "exact_dependencies",
  "weak_dependencies_allowed",
  "upward_dependencies_allowed",
  "rpaths_allowed",
]);
const MACHO_SIGNING_POLICY_FIELDS = objectFreeze([
  "signature_kind",
  "code_type",
  "team_identifier",
  "signing_identifier",
  "cdhash_algorithm",
  "hardened_runtime_required",
  "notarization_required",
  "adhoc_allowed",
  "designated_requirement_digest",
  "entitlements_digest",
]);
const FILESYSTEM_POLICY_FIELDS = objectFreeze([
  "install_root_owner_uid",
  "install_root_owner_gid",
  "artifact_owner_uid",
  "artifact_owner_gid",
  "install_root_path_digest",
  "required_open_scheme",
  "max_static_inspection_age_ms",
  "required_immutability_evidence_scheme",
  "require_root_owned_ancestry",
  "require_no_symlinks",
  "require_regular_files",
  "require_single_link",
  "require_stable_file_identity",
  "require_retained_artifact_fds",
  "require_root_immutable",
  "require_artifact_immutable",
  "require_read_only_mount_or_system_immutable",
  "require_mapped_image_binding",
]);
const NATIVE_ATTESTATION_POLICY_FIELDS = objectFreeze([
  "scheme",
  "attestor_implementation_digest",
  "attestor_source_digest",
  "attestor_loaded_image_digest",
  "component_identity_binding_scheme",
  "max_attestation_age_ms",
  "require_kernel_originated_identity",
  "require_on_disk_fd_binding",
  "require_loaded_or_exec_image_binding",
  "require_mapped_process_image_binding",
  "require_component_host_or_equivalent_validation",
  "require_pre_post_identity_match",
  "require_live_double_read",
  "require_principal_acl_binding",
]);
const HIL_POLICY_FIELDS = objectFreeze([
  "suite_id",
  "suite_digest",
  "authority_scope_digest",
  "device_qualification_policy_digest",
  "fixture_manifest_digest",
  "operator_witness_policy_digest",
  "max_evidence_age_ms",
  "required_gate_ids",
]);
const ENVELOPE_FIELDS = objectFreeze([
  "version",
  "kind",
  "signature_domain",
  "manifest",
  "manifest_digest",
  "authentication",
]);
const AUTHENTICATION_FIELDS = objectFreeze([
  "scheme",
  "key_usage",
  "key_id",
  "public_key_digest",
  "trust_epoch",
  "signed_manifest_digest",
  "signature",
]);
const TRUST_POLICY_FIELDS = objectFreeze([
  "version",
  "kind",
  "current_trust_epoch",
  "minimum_release_epoch",
  "revoked_release_ids",
  "revoked_manifest_digests",
  "keys",
]);
const TRUST_KEY_FIELDS = objectFreeze([
  "key_id",
  "public_key_spki_der",
  "public_key_digest",
  "trust_epoch",
  "not_before",
  "not_after",
  "revoked",
  "revocation_epoch",
  "allowed_package_names",
  "allowed_component_ids",
]);

const PACKAGE_PATTERN = /^@hacker-bob\/[a-z0-9][a-z0-9._-]{0,127}$/u;
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u;
const TEAM_PATTERN = /^[A-Z0-9]{10}$/u;
const SIGNING_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9.-]{0,190}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const ED25519_SPKI_HEX_PATTERN = /^302a300506032b6570032100[a-f0-9]{64}$/u;

function exactBoolean(input, field, label, expected, code) {
  const value = assertBoolean(ownValue(input, field, label, code), `${label}.${field}`, code);
  if (value !== expected) reject(code, `${label}.${field} must be ${expected}`);
  return value;
}

function normalizeTarget(input) {
  const label = "native_prebuild_manifest.target";
  assertExactObject(input, TARGET_FIELDS, label, "target_invalid");
  const values = [
    ownValue(input, "os", label),
    ownValue(input, "architecture", label),
    assertInteger(ownValue(input, "node_major", label), `${label}.node_major`, 20, 20,
      "abi_invalid"),
    assertInteger(ownValue(input, "napi_version", label), `${label}.napi_version`, 9, 9,
      "abi_invalid"),
    exactBoolean(input, "node_api_only", label, true, "abi_invalid"),
    ownValue(input, "deployment_format", label),
  ];
  if (values[0] !== "darwin" || values[1] !== "arm64"
      || values[5] !== "signed_immutable_prebuild_set") {
    reject("target_invalid", `${label} is not the supported darwin-arm64 deployment target`);
  }
  return makeRecord(TARGET_FIELDS, values);
}

function normalizeDependencies(input, label) {
  assertDenseArray(input, label, 64, "dependency_invalid");
  const result = [];
  let previous = null;
  for (let index = 0; index < input.length; index += 1) {
    const value = assertAbsoluteSystemDependency(
      ownValue(input, `${index}`, label, "dependency_invalid"),
      `${label}[${index}]`,
    );
    if (previous != null && value <= previous) {
      reject("dependency_invalid", `${label} must be strictly sorted and unique`);
    }
    setArrayIndex(result, index, value);
    previous = value;
  }
  return makeArray(result);
}

function normalizeDynamicDependencyPolicy(input, label) {
  assertExactObject(input, DYNAMIC_DEPENDENCY_POLICY_FIELDS, label, "dependency_invalid");
  return makeRecord(DYNAMIC_DEPENDENCY_POLICY_FIELDS, [
    normalizeDependencies(ownValue(input, "exact_dependencies", label, "dependency_invalid"),
      `${label}.exact_dependencies`),
    exactBoolean(input, "weak_dependencies_allowed", label, false, "dependency_invalid"),
    exactBoolean(input, "upward_dependencies_allowed", label, false, "dependency_invalid"),
    exactBoolean(input, "rpaths_allowed", label, false, "dependency_invalid"),
  ]);
}

function normalizeMachOSigningPolicy(input, label, expectedCodeType) {
  assertExactObject(input, MACHO_SIGNING_POLICY_FIELDS, label, "codesign_policy_invalid");
  const signatureKind = ownValue(input, "signature_kind", label);
  const codeType = ownValue(input, "code_type", label);
  const team = assertString(ownValue(input, "team_identifier", label),
    `${label}.team_identifier`, { pattern: TEAM_PATTERN, maximumBytes: 10,
      code: "codesign_policy_invalid" });
  const identifier = assertString(ownValue(input, "signing_identifier", label),
    `${label}.signing_identifier`, { pattern: SIGNING_IDENTIFIER_PATTERN, maximumBytes: 191,
      code: "codesign_policy_invalid" });
  const algorithm = ownValue(input, "cdhash_algorithm", label);
  if (signatureKind !== "developer_id" || codeType !== expectedCodeType
      || algorithm !== "sha256") {
    reject("codesign_policy_invalid", `${label} requires Developer ID SHA-256 signing`);
  }
  return makeRecord(MACHO_SIGNING_POLICY_FIELDS, [
    signatureKind,
    codeType,
    team,
    identifier,
    algorithm,
    exactBoolean(input, "hardened_runtime_required", label, true,
      "codesign_policy_invalid"),
    exactBoolean(input, "notarization_required", label, true,
      "codesign_policy_invalid"),
    exactBoolean(input, "adhoc_allowed", label, false, "codesign_policy_invalid"),
    assertDigest(ownValue(input, "designated_requirement_digest", label),
      `${label}.designated_requirement_digest`, "codesign_policy_invalid"),
    assertDigest(ownValue(input, "entitlements_digest", label),
      `${label}.entitlements_digest`, "codesign_policy_invalid"),
  ]);
}

function normalizeComponent(input, index) {
  const label = `native_prebuild_manifest.components[${index}]`;
  assertExactObject(input, COMPONENT_FIELDS, label, "component_invalid");
  const expectedId = NATIVE_PREBUILD_REQUIRED_COMPONENTS[index];
  const componentId = ownValue(input, "component_id", label);
  const artifactKind = ownValue(input, "artifact_kind", label);
  if (componentId !== expectedId || artifactKind !== COMPONENT_KINDS[expectedId]) {
    reject("component_invalid", `${label} is not the required component and artifact kind`);
  }
  return makeRecord(COMPONENT_FIELDS, [
    componentId,
    assertRelativeArtifactPath(ownValue(input, "artifact_path", label),
      `${label}.artifact_path`),
    artifactKind,
    assertInteger(ownValue(input, "byte_size", label), `${label}.byte_size`, 1,
      256 * 1024 * 1024, "component_invalid"),
    assertDigest(ownValue(input, "sha256", label), `${label}.sha256`, "component_invalid"),
    assertDigest(ownValue(input, "source_digest", label), `${label}.source_digest`,
      "component_invalid"),
    assertDigest(ownValue(input, "builder_digest", label), `${label}.builder_digest`,
      "component_invalid"),
    assertDigest(ownValue(input, "toolchain_digest", label), `${label}.toolchain_digest`,
      "component_invalid"),
    assertDigest(ownValue(input, "provenance_digest", label), `${label}.provenance_digest`,
      "component_invalid"),
    normalizeDynamicDependencyPolicy(ownValue(input, "dynamic_dependency_policy", label),
      `${label}.dynamic_dependency_policy`),
    normalizeMachOSigningPolicy(ownValue(input, "macho_signing_policy", label),
      `${label}.macho_signing_policy`, COMPONENT_CODE_TYPES[expectedId]),
  ]);
}

function normalizeComponents(input) {
  const label = "native_prebuild_manifest.components";
  assertDenseArray(input, label, NATIVE_PREBUILD_REQUIRED_COMPONENTS.length,
    "component_invalid");
  if (input.length !== NATIVE_PREBUILD_REQUIRED_COMPONENTS.length) {
    reject("component_invalid", `${label} must contain the complete required component set`);
  }
  const result = [];
  const paths = new SafeSet();
  const artifactDigests = new SafeSet();
  const signingIdentifiers = new SafeSet();
  const designatedRequirements = new SafeSet();
  let totalBytes = 0;
  for (let index = 0; index < input.length; index += 1) {
    const component = normalizeComponent(ownValue(input, `${index}`, label, "component_invalid"),
      index);
    if (reflectApply(setHas, paths, [component.artifact_path])) {
      reject("path_invalid", `${label} artifact paths must be unique`);
    }
    for (let priorIndex = 0; priorIndex < index; priorIndex += 1) {
      const priorPath = result[priorIndex].artifact_path;
      if (reflectApply(stringStartsWith, component.artifact_path, [`${priorPath}/`])
          || reflectApply(stringStartsWith, priorPath, [`${component.artifact_path}/`])) {
        reject("path_invalid", `${label} artifact paths cannot have file-directory aliases`);
      }
    }
    if (reflectApply(setHas, artifactDigests, [component.sha256])) {
      reject("component_invalid", `${label} artifact SHA-256 identities must be distinct`);
    }
    if (reflectApply(setHas, signingIdentifiers,
      [component.macho_signing_policy.signing_identifier])) {
      reject("codesign_policy_invalid",
        `${label} component signing identifiers must be distinct`);
    }
    if (reflectApply(setHas, designatedRequirements,
      [component.macho_signing_policy.designated_requirement_digest])) {
      reject("codesign_policy_invalid",
        `${label} designated requirement identities must be distinct`);
    }
    reflectApply(setAdd, paths, [component.artifact_path]);
    reflectApply(setAdd, artifactDigests, [component.sha256]);
    reflectApply(setAdd, signingIdentifiers,
      [component.macho_signing_policy.signing_identifier]);
    reflectApply(setAdd, designatedRequirements,
      [component.macho_signing_policy.designated_requirement_digest]);
    totalBytes += component.byte_size;
    if (totalBytes > 512 * 1024 * 1024) {
      reject("component_invalid", `${label} exceeds the fixed total byte bound`);
    }
    setArrayIndex(result, index, component);
  }
  return makeArray(result);
}

function normalizeFilesystemPolicy(input) {
  const label = "native_prebuild_manifest.filesystem_policy";
  assertExactObject(input, FILESYSTEM_POLICY_FIELDS, label, "filesystem_policy_invalid");
  const values = [
    assertInteger(ownValue(input, "install_root_owner_uid", label),
      `${label}.install_root_owner_uid`, 0, 0, "filesystem_policy_invalid"),
    assertInteger(ownValue(input, "install_root_owner_gid", label),
      `${label}.install_root_owner_gid`, 0, 0, "filesystem_policy_invalid"),
    assertInteger(ownValue(input, "artifact_owner_uid", label),
      `${label}.artifact_owner_uid`, 0, 0, "filesystem_policy_invalid"),
    assertInteger(ownValue(input, "artifact_owner_gid", label),
      `${label}.artifact_owner_gid`, 0, 0, "filesystem_policy_invalid"),
    assertDigest(ownValue(input, "install_root_path_digest", label),
      `${label}.install_root_path_digest`, "filesystem_policy_invalid"),
    ownValue(input, "required_open_scheme", label),
    assertInteger(ownValue(input, "max_static_inspection_age_ms", label),
      `${label}.max_static_inspection_age_ms`, 1, 86_400_000,
      "filesystem_policy_invalid"),
    ownValue(input, "required_immutability_evidence_scheme", label),
  ];
  if (values[5] !== "openat_no_follow_descriptor_walk_v1") {
    reject("filesystem_policy_invalid", `${label}.required_open_scheme is unsupported`);
  }
  if (values[7] !== "read_only_mount_or_darwin_system_immutable_flags_v1") {
    reject("filesystem_policy_invalid", `${label} immutability evidence scheme is unsupported`);
  }
  for (let index = 8; index < FILESYSTEM_POLICY_FIELDS.length; index += 1) {
    setArrayIndex(values, index, exactBoolean(input, FILESYSTEM_POLICY_FIELDS[index], label,
      true, "filesystem_policy_invalid"));
  }
  return makeRecord(FILESYSTEM_POLICY_FIELDS, values);
}

function normalizeNativeAttestationPolicy(input) {
  const label = "native_prebuild_manifest.native_attestation_policy";
  assertExactObject(input, NATIVE_ATTESTATION_POLICY_FIELDS, label,
    "native_attestation_policy_invalid");
  const values = [
    ownValue(input, "scheme", label),
    assertDigest(ownValue(input, "attestor_implementation_digest", label),
      `${label}.attestor_implementation_digest`, "native_attestation_policy_invalid"),
    assertDigest(ownValue(input, "attestor_source_digest", label),
      `${label}.attestor_source_digest`, "native_attestation_policy_invalid"),
    assertDigest(ownValue(input, "attestor_loaded_image_digest", label),
      `${label}.attestor_loaded_image_digest`, "native_attestation_policy_invalid"),
    ownValue(input, "component_identity_binding_scheme", label),
    assertInteger(ownValue(input, "max_attestation_age_ms", label),
      `${label}.max_attestation_age_ms`, 1, 3_600_000,
      "native_attestation_policy_invalid"),
  ];
  if (values[0] !== "darwin_loaded_image_identity_v1") {
    reject("native_attestation_policy_invalid", `${label}.scheme is unsupported`);
  }
  if (values[4] !== "darwin_fd_codesign_loaded_mapped_cross_binding_v1") {
    reject("native_attestation_policy_invalid", `${label} component binding scheme is unsupported`);
  }
  for (let index = 6; index < NATIVE_ATTESTATION_POLICY_FIELDS.length; index += 1) {
    setArrayIndex(values, index, exactBoolean(input, NATIVE_ATTESTATION_POLICY_FIELDS[index],
      label, true, "native_attestation_policy_invalid"));
  }
  return makeRecord(NATIVE_ATTESTATION_POLICY_FIELDS, values);
}

function normalizeFixedStringArray(input, expected, label, code) {
  assertDenseArray(input, label, expected.length, code);
  if (input.length !== expected.length) reject(code, `${label} is incomplete`);
  const result = [];
  for (let index = 0; index < expected.length; index += 1) {
    const value = ownValue(input, `${index}`, label, code);
    if (value !== expected[index]) reject(code, `${label} is not the closed required set`);
    setArrayIndex(result, index, value);
  }
  return makeArray(result);
}

function normalizeSortedStrings(input, label, validator, maximum, allowEmpty, code) {
  assertDenseArray(input, label, maximum, code);
  if (!allowEmpty && input.length === 0) reject(code, `${label} cannot be empty`);
  const result = [];
  let previous = null;
  for (let index = 0; index < input.length; index += 1) {
    const value = validator(ownValue(input, `${index}`, label, code), `${label}[${index}]`);
    if (previous != null && value <= previous) {
      reject(code, `${label} must be strictly sorted and unique`);
    }
    setArrayIndex(result, index, value);
    previous = value;
  }
  return makeArray(result);
}

function normalizeHilPolicy(input) {
  const label = "native_prebuild_manifest.hil_policy";
  assertExactObject(input, HIL_POLICY_FIELDS, label, "hil_policy_invalid");
  return makeRecord(HIL_POLICY_FIELDS, [
    assertIdentifier(ownValue(input, "suite_id", label), `${label}.suite_id`,
      "hil_policy_invalid"),
    assertDigest(ownValue(input, "suite_digest", label), `${label}.suite_digest`,
      "hil_policy_invalid"),
    assertDigest(ownValue(input, "authority_scope_digest", label),
      `${label}.authority_scope_digest`, "hil_policy_invalid"),
    assertDigest(ownValue(input, "device_qualification_policy_digest", label),
      `${label}.device_qualification_policy_digest`, "hil_policy_invalid"),
    assertDigest(ownValue(input, "fixture_manifest_digest", label),
      `${label}.fixture_manifest_digest`, "hil_policy_invalid"),
    assertDigest(ownValue(input, "operator_witness_policy_digest", label),
      `${label}.operator_witness_policy_digest`, "hil_policy_invalid"),
    assertInteger(ownValue(input, "max_evidence_age_ms", label),
      `${label}.max_evidence_age_ms`, 1, 3_600_000, "hil_policy_invalid"),
    normalizeFixedStringArray(ownValue(input, "required_gate_ids", label),
      NATIVE_PREBUILD_REQUIRED_HIL_GATES, `${label}.required_gate_ids`, "hil_policy_invalid"),
  ]);
}

function normalizeReleaseManifest(input) {
  const label = "native_prebuild_manifest";
  assertExactObject(input, MANIFEST_FIELDS, label, "manifest_invalid");
  const version = assertInteger(ownValue(input, "version", label), `${label}.version`,
    NATIVE_PREBUILD_TRUST_VERSION, NATIVE_PREBUILD_TRUST_VERSION, "manifest_invalid");
  const kind = ownValue(input, "kind", label);
  if (kind !== "native_prebuild_release_manifest") {
    reject("manifest_invalid", `${label}.kind is invalid`);
  }
  const issuedAt = assertTimestamp(ownValue(input, "issued_at", label), `${label}.issued_at`);
  const expiresAt = assertTimestamp(ownValue(input, "expires_at", label), `${label}.expires_at`);
  if (timestampMilliseconds(expiresAt, `${label}.expires_at`)
      <= timestampMilliseconds(issuedAt, `${label}.issued_at`)) {
    reject("time_invalid", `${label} expiry must follow issuance`);
  }
  return makeRecord(MANIFEST_FIELDS, [
    version,
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
    normalizeComponents(ownValue(input, "components", label)),
    assertDigest(ownValue(input, "source_tree_digest", label), `${label}.source_tree_digest`),
    assertDigest(ownValue(input, "builder_identity_digest", label),
      `${label}.builder_identity_digest`),
    assertDigest(ownValue(input, "toolchain_manifest_digest", label),
      `${label}.toolchain_manifest_digest`),
    assertDigest(ownValue(input, "provenance_statement_digest", label),
      `${label}.provenance_statement_digest`),
    assertDigest(ownValue(input, "principal_acl_policy_digest", label),
      `${label}.principal_acl_policy_digest`),
    normalizeFilesystemPolicy(ownValue(input, "filesystem_policy", label)),
    normalizeNativeAttestationPolicy(ownValue(input, "native_attestation_policy", label)),
    normalizeHilPolicy(ownValue(input, "hil_policy", label)),
    issuedAt,
    expiresAt,
  ]);
}

function digestReleaseManifest(input) {
  return domainDigest(NATIVE_PREBUILD_MANIFEST_DOMAIN, normalizeReleaseManifest(input));
}

function releaseSignatureMessage(input) {
  const label = "native_prebuild_signature_claim";
  const fields = [
    "manifest_digest",
    "key_id",
    "public_key_digest",
    "trust_epoch",
  ];
  assertExactObject(input, fields, label, "signature_claim_invalid");
  const claim = makeRecord(fields, [
    assertDigest(ownValue(input, "manifest_digest", label), `${label}.manifest_digest`),
    assertOpaqueToken(ownValue(input, "key_id", label), `${label}.key_id`,
      "signature_claim_invalid"),
    assertDigest(ownValue(input, "public_key_digest", label),
      `${label}.public_key_digest`, "signature_claim_invalid"),
    assertInteger(ownValue(input, "trust_epoch", label), `${label}.trust_epoch`, 1,
      Number.MAX_SAFE_INTEGER, "signature_claim_invalid"),
  ]);
  return bufferFrom(`${NATIVE_PREBUILD_SIGNATURE_DOMAIN}\0${domainDigest(
    NATIVE_PREBUILD_SIGNATURE_DOMAIN,
    claim,
  )}`, "utf8");
}

function assertCanonicalBase64Url(value, label, expectedBytes, code) {
  assertString(value, label, { pattern: BASE64URL_PATTERN, maximumBytes: 1024, code });
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

function normalizeTrustKey(input, index) {
  const label = `native_prebuild_trust_policy.keys[${index}]`;
  assertExactObject(input, TRUST_KEY_FIELDS, label, "trust_policy_invalid");
  const derText = ownValue(input, "public_key_spki_der", label);
  const der = assertCanonicalBase64Url(derText, `${label}.public_key_spki_der`, null,
    "public_key_invalid");
  const derHex = reflectApply(bufferToString, der, ["hex"]);
  if (der.length !== 44
      || !reflectApply(regexpTest, ED25519_SPKI_HEX_PATTERN, [derHex])) {
    reject("public_key_invalid", `${label}.public_key_spki_der is not canonical Ed25519 SPKI`);
  }
  let key;
  try {
    key = reflectApply(cryptoCreatePublicKey, crypto, [{ key: der, type: "spki", format: "der" }]);
  } catch {
    reject("public_key_invalid", `${label}.public_key_spki_der is not a public key`);
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
          pattern: PACKAGE_PATTERN,
          maximumBytes: 140,
          code: "trust_policy_invalid",
        }), 32, false, "trust_policy_invalid"),
      normalizeFixedStringArray(ownValue(input, "allowed_component_ids", label),
        NATIVE_PREBUILD_REQUIRED_COMPONENTS, `${label}.allowed_component_ids`,
        "trust_policy_invalid"),
    ]),
    key,
  };
}

function normalizeTrustPolicy(input) {
  const label = "native_prebuild_trust_policy";
  assertExactObject(input, TRUST_POLICY_FIELDS, label, "trust_policy_invalid");
  const version = assertInteger(ownValue(input, "version", label), `${label}.version`, 1, 1,
    "trust_policy_invalid");
  const kind = ownValue(input, "kind", label);
  if (kind !== "native_prebuild_trust_policy") {
    reject("trust_policy_invalid", `${label}.kind is invalid`);
  }
  const currentEpoch = assertInteger(ownValue(input, "current_trust_epoch", label),
    `${label}.current_trust_epoch`, 1, Number.MAX_SAFE_INTEGER, "trust_policy_invalid");
  const minimumReleaseEpoch = assertInteger(ownValue(input, "minimum_release_epoch", label),
    `${label}.minimum_release_epoch`, 1, Number.MAX_SAFE_INTEGER, "trust_policy_invalid");
  const keyInputs = ownValue(input, "keys", label);
  assertDenseArray(keyInputs, `${label}.keys`, 32, "trust_policy_invalid");
  if (keyInputs.length < 1) reject("trust_policy_invalid", `${label}.keys cannot be empty`);
  const keys = [];
  const runtimeKeys = [];
  const publicKeySpkis = new SafeSet();
  const publicKeyDigests = new SafeSet();
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
    if (reflectApply(setHas, publicKeySpkis, [entry.normalized.public_key_spki_der])
        || reflectApply(setHas, publicKeyDigests,
          [entry.normalized.public_key_digest])) {
      reject("trust_policy_invalid",
        `${label}.keys cannot alias Ed25519 key material across key IDs`);
    }
    reflectApply(setAdd, publicKeySpkis, [entry.normalized.public_key_spki_der]);
    reflectApply(setAdd, publicKeyDigests, [entry.normalized.public_key_digest]);
    setArrayIndex(keys, index, entry.normalized);
    setArrayIndex(runtimeKeys, index, entry.key);
    previous = entry.normalized.key_id;
  }
  return {
    normalized: makeRecord(TRUST_POLICY_FIELDS, [
      version,
      kind,
      currentEpoch,
      minimumReleaseEpoch,
      normalizeSortedStrings(ownValue(input, "revoked_release_ids", label),
        `${label}.revoked_release_ids`, (value, itemLabel) =>
          assertOpaqueToken(value, itemLabel, "trust_policy_invalid"), 256, true,
        "trust_policy_invalid"),
      normalizeSortedStrings(ownValue(input, "revoked_manifest_digests", label),
        `${label}.revoked_manifest_digests`, (value, itemLabel) =>
          assertDigest(value, itemLabel, "trust_policy_invalid"), 256, true,
        "trust_policy_invalid"),
      makeArray(keys),
    ]),
    runtimeKeys,
  };
}

function normalizeAuthentication(input, manifestDigest) {
  const label = "native_prebuild_release_envelope.authentication";
  assertExactObject(input, AUTHENTICATION_FIELDS, label, "authentication_invalid");
  const scheme = ownValue(input, "scheme", label);
  const usage = ownValue(input, "key_usage", label);
  if (scheme !== "ed25519" || usage !== NATIVE_PREBUILD_KEY_USAGE) {
    reject("authentication_invalid", `${label} scheme or key usage is invalid`);
  }
  const signedDigest = assertDigest(ownValue(input, "signed_manifest_digest", label),
    `${label}.signed_manifest_digest`, "authentication_invalid");
  if (signedDigest !== manifestDigest) {
    reject("authentication_invalid", `${label} does not bind the manifest digest`);
  }
  const signature = ownValue(input, "signature", label);
  assertString(signature, `${label}.signature`, { pattern: SIGNATURE_PATTERN, minimumBytes: 86,
    maximumBytes: 86, code: "signature_invalid" });
  assertCanonicalBase64Url(signature, `${label}.signature`, 64, "signature_invalid");
  return makeRecord(AUTHENTICATION_FIELDS, [
    scheme,
    usage,
    assertOpaqueToken(ownValue(input, "key_id", label), `${label}.key_id`,
      "authentication_invalid"),
    assertDigest(ownValue(input, "public_key_digest", label),
      `${label}.public_key_digest`, "authentication_invalid"),
    assertInteger(ownValue(input, "trust_epoch", label), `${label}.trust_epoch`, 1,
      Number.MAX_SAFE_INTEGER, "authentication_invalid"),
    signedDigest,
    signature,
  ]);
}

function normalizeEnvelope(input) {
  const label = "native_prebuild_release_envelope";
  assertExactObject(input, ENVELOPE_FIELDS, label, "envelope_invalid");
  const version = assertInteger(ownValue(input, "version", label), `${label}.version`, 1, 1,
    "envelope_invalid");
  const kind = ownValue(input, "kind", label);
  const signatureDomain = ownValue(input, "signature_domain", label);
  if (kind !== "signed_native_prebuild_release"
      || signatureDomain !== NATIVE_PREBUILD_SIGNATURE_DOMAIN) {
    reject("domain_invalid", `${label} kind or signature domain is invalid`);
  }
  const manifest = normalizeReleaseManifest(ownValue(input, "manifest", label));
  const manifestDigest = assertDigest(ownValue(input, "manifest_digest", label),
    `${label}.manifest_digest`, "manifest_digest_invalid");
  if (manifestDigest !== domainDigest(NATIVE_PREBUILD_MANIFEST_DOMAIN, manifest)) {
    reject("manifest_digest_invalid", `${label}.manifest_digest does not match the manifest`);
  }
  return makeRecord(ENVELOPE_FIELDS, [
    version,
    kind,
    signatureDomain,
    manifest,
    manifestDigest,
    normalizeAuthentication(ownValue(input, "authentication", label), manifestDigest),
  ]);
}

function verifyReleaseEnvelope(input) {
  const label = "native_prebuild_release_verification";
  const fields = ["envelope", "trust_policy", "now"];
  assertExactObject(input, fields, label, "verification_input_invalid");
  const envelope = normalizeEnvelope(ownValue(input, "envelope", label));
  const trust = normalizeTrustPolicy(ownValue(input, "trust_policy", label));
  const now = assertTimestamp(ownValue(input, "now", label), `${label}.now`);
  const nowMs = timestampMilliseconds(now, `${label}.now`);
  const manifest = envelope.manifest;
  if (manifest.release_epoch < trust.normalized.minimum_release_epoch) {
    reject("release_epoch_rejected", "release epoch is below the trust-policy floor");
  }
  for (let index = 0; index < trust.normalized.revoked_release_ids.length; index += 1) {
    if (trust.normalized.revoked_release_ids[index] === manifest.release_id) {
      reject("release_revoked", "release ID is emergency-revoked by the trust policy");
    }
  }
  for (let index = 0; index < trust.normalized.revoked_manifest_digests.length; index += 1) {
    if (trust.normalized.revoked_manifest_digests[index] === envelope.manifest_digest) {
      reject("manifest_revoked", "manifest digest is emergency-revoked by the trust policy");
    }
  }
  if (nowMs < timestampMilliseconds(manifest.issued_at, "manifest.issued_at")
      || nowMs >= timestampMilliseconds(manifest.expires_at, "manifest.expires_at")) {
    reject("release_time_rejected", "release is not valid at the supplied trusted time");
  }
  const auth = envelope.authentication;
  let keyIndex = -1;
  for (let index = 0; index < trust.normalized.keys.length; index += 1) {
    if (trust.normalized.keys[index].key_id === auth.key_id) {
      keyIndex = index;
      break;
    }
  }
  if (keyIndex < 0) reject("untrusted_key", "release key is not in the supplied trust policy");
  const keyRecord = trust.normalized.keys[keyIndex];
  if (keyRecord.revoked) reject("revoked_key", "release key is revoked");
  if (keyRecord.trust_epoch !== auth.trust_epoch
      || auth.trust_epoch > trust.normalized.current_trust_epoch
      || keyRecord.public_key_digest !== auth.public_key_digest) {
    reject("trust_binding_rejected", "release authentication does not bind the trusted key epoch");
  }
  let packageAllowed = false;
  for (let index = 0; index < keyRecord.allowed_package_names.length; index += 1) {
    if (keyRecord.allowed_package_names[index] === manifest.package_name) {
      packageAllowed = true;
      break;
    }
  }
  if (!packageAllowed
      || !arraysEqual(keyRecord.allowed_component_ids, NATIVE_PREBUILD_REQUIRED_COMPONENTS)) {
    reject("key_scope_rejected", "release package or component set is outside the key scope");
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
  const signature = bufferFrom(auth.signature, "base64url");
  let verified = false;
  try {
    verified = reflectApply(cryptoVerify, crypto, [
      null,
      releaseSignatureMessage(claim),
      trust.runtimeKeys[keyIndex],
      signature,
    ]);
  } catch {
    verified = false;
  }
  if (!verified) reject("signature_invalid", "Ed25519 release signature verification failed");
  return objectFreeze({
    version: NATIVE_PREBUILD_TRUST_VERSION,
    kind: "verified_native_prebuild_release_diagnostic",
    manifest,
    manifest_digest: envelope.manifest_digest,
    envelope_digest: domainDigest(NATIVE_PREBUILD_ENVELOPE_DOMAIN, envelope),
    key_id: keyRecord.key_id,
    public_key_digest: keyRecord.public_key_digest,
    trust_epoch: keyRecord.trust_epoch,
    release_signature_valid: true,
    assurance: "ed25519_release_signature_only",
    production_ready: false,
    hardware_access_authorized: false,
    blockers: VERIFICATION_BLOCKERS,
  });
}

module.exports = {
  NATIVE_PREBUILD_ENVELOPE_DOMAIN,
  NATIVE_PREBUILD_KEY_USAGE,
  NATIVE_PREBUILD_MANIFEST_DOMAIN,
  NATIVE_PREBUILD_REQUIRED_COMPONENTS,
  NATIVE_PREBUILD_REQUIRED_HIL_GATES,
  NATIVE_PREBUILD_SIGNATURE_DOMAIN,
  NATIVE_PREBUILD_TRUST_VERSION,
  VERIFICATION_BLOCKERS,
  digestReleaseManifest,
  releaseSignatureMessage,
  verifyReleaseEnvelope,
};
