"use strict";

const { types: utilTypes } = require("node:util");
const { digestFixedSnapshot } = require("./canonical-snapshot.js");
const {
  getHostIdentity,
  loadNativeBindingOnce,
  reserveSelfIdentityInspection,
} = require("./native-binding-loader.js");

const SafeError = Error;
const arrayIsArray = Array.isArray;
const objectDefineProperty = Object.defineProperty;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectKeys = Object.keys;
const objectPrototype = Object.prototype;
const objectValues = Object.values;
const objectFreeze = Object.freeze;
const numberIsInteger = Number.isInteger;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regExpTest = RegExp.prototype.test;
const utilTypesIsProxy = utilTypes.isProxy;
const weakMapGet = WeakMap.prototype.get;
const weakMapHas = WeakMap.prototype.has;
const weakMapSet = WeakMap.prototype.set;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;

const DARWIN_NATIVE_SELF_IDENTITY_VERSION = 1;
const DARWIN_NATIVE_SELF_IDENTITY_PRIMITIVE =
  "darwin_task_audit_token_seccode_self_identity_v1";
const DARWIN_NATIVE_SELF_IDENTITY_DOMAIN =
  "hacker-bob/darwin-native-self-identity-snapshot/v1";
const DARWIN_NATIVE_SELF_IDENTITY_PRODUCTION_BLOCKERS = objectFreeze([
  "self_code_identity_policy_allowlist_missing",
  "self_code_identity_hil_missing",
  "native_addon_non_executable_runtime_state_unverified",
  "native_addon_signed_immutable_delivery_unverified",
  "root_owned_immutable_bundle_unverified",
  "launch_ticket_binding_missing",
  "broker_activation_not_implemented",
  "dedicated_worker_uid_unverified",
  "device_acl_hil_missing",
  "raw_native_primitive_not_policy_one_shot",
]);
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const CODE_DIRECTORY_HASH_PATTERN = /^(?:[a-f0-9]{2}){16,64}$/u;
const TOKEN_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;
const SELF_INSPECTORS = new WeakSet();
const SELF_INSPECTOR_STATE = new WeakMap();

function selfError() {
  const error = new SafeError("Darwin native self identity was rejected");
  objectDefineProperty(error, "code", {
    value: "darwin_native_self_rejected",
    writable: false,
    enumerable: false,
    configurable: false,
  });
  return error;
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || utilTypesIsProxy(value)
      || arrayIsArray(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== objectPrototype && prototype !== null) return false;
  const keys = reflectOwnKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (typeof key !== "string") return false;
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true) return false;
  }
  return true;
}

function assertExactObject(value, fields) {
  if (!isPlainDataObject(value)) throw selfError();
  const actual = objectKeys(value);
  if (actual.length !== fields.length) throw selfError();
  for (let fieldIndex = 0; fieldIndex < fields.length; fieldIndex += 1) {
    const field = fields[fieldIndex];
    let found = false;
    for (let actualIndex = 0; actualIndex < actual.length; actualIndex += 1) {
      const candidate = actual[actualIndex];
      if (candidate === field) found = true;
    }
    if (!found) throw selfError();
  }
  return value;
}

function assertExactNativeObject(value, fields) {
  assertExactObject(value, fields);
  if (objectGetPrototypeOf(value) !== objectPrototype) throw selfError();
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    const descriptor = objectGetOwnPropertyDescriptor(value, field);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true || descriptor.writable !== false
        || descriptor.configurable !== false) throw selfError();
  }
  return value;
}

function assertDigest(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, DIGEST_PATTERN, [value])) throw selfError();
  return value;
}

function assertCodeDirectoryHash(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, CODE_DIRECTORY_HASH_PATTERN, [value])) {
    throw selfError();
  }
  return value;
}

function assertClosedValue(value, allowed) {
  if (typeof value !== "string") throw selfError();
  for (let index = 0; index < allowed.length; index += 1) {
    const candidate = allowed[index];
    if (value === candidate) return value;
  }
  throw selfError();
}

function assertUint32(value) {
  if (!numberIsInteger(value) || value < 0 || value > 0xffff_ffff) throw selfError();
  return value;
}

function assertDecimal(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, DECIMAL_PATTERN, [value])) throw selfError();
  return value;
}

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || objectIsFrozen(value)) return value;
  const children = objectValues(value);
  for (let index = 0; index < children.length; index += 1) {
    deepFreeze(children[index]);
  }
  return objectFreeze(value);
}

function createDarwinNativeSelfIdentityInspector(input) {
  if (arguments.length !== 1) throw selfError();
  assertExactObject(input, ["adapter_id"]);
  if (typeof input.adapter_id !== "string"
      || !reflectApply(regExpTest, TOKEN_PATTERN, [input.adapter_id])) {
    throw selfError();
  }
  let native;
  try {
    getHostIdentity();
    native = loadNativeBindingOnce();
  } catch {
    throw selfError();
  }
  const port = deepFreeze({
    version: DARWIN_NATIVE_SELF_IDENTITY_VERSION,
    adapter_id: input.adapter_id,
    platform: "darwin",
    architecture: "arm64",
    node_abi: "napi-v9",
    primitive: DARWIN_NATIVE_SELF_IDENTITY_PRIMITIVE,
    credential_source:
      "darwin_task_audit_token_and_security_framework_dynamic_code_self",
    native_binding_implementation_digest: native.implementation_digest,
    native_binding_measurement_scheme: native.measurement_scheme,
    native_loaded_image_measurement_scheme:
      native.loaded_image_measurement_scheme,
    native_loaded_image_identity_digest:
      native.loaded_image_identity_digest,
    native_loaded_image_file_sha256: native.loaded_image_file_sha256,
    native_loaded_image_canonical_path_digest:
      native.loaded_image_canonical_path_digest,
    native_loaded_image_file_identity_digest:
      native.loaded_image_file_identity_digest,
    native_loaded_image_lc_uuid_digest:
      native.loaded_image_lc_uuid_digest,
    native_loaded_image_header_and_load_commands_digest:
      native.loaded_image_header_and_load_commands_digest,
    native_loaded_image_executable_segments_digest:
      native.loaded_image_executable_segments_digest,
    native_loaded_image_executable_segment_count:
      native.loaded_image_executable_segment_count,
    native_loaded_image_executable_file_bytes:
      native.loaded_image_executable_file_bytes,
    native_loaded_image_dyld_header_unique:
      native.loaded_image_dyld_header_unique,
    native_loaded_image_dladdr_base_matches_dyld:
      native.loaded_image_dladdr_base_matches_dyld,
    native_loaded_image_dyld_snapshot_stable:
      native.loaded_image_dyld_snapshot_stable,
    native_loaded_image_dyld_canonical_path_matches_dladdr:
      native.loaded_image_dyld_canonical_path_matches_dladdr,
    native_loaded_image_callback_in_executable_segment:
      native.loaded_image_callback_in_executable_segment,
    native_loaded_image_header_and_load_commands_match_file:
      native.loaded_image_header_and_load_commands_match_file,
    native_loaded_image_executable_segments_match_file:
      native.loaded_image_executable_segments_match_file,
    native_loaded_image_executable_pages_read_execute_only:
      native.loaded_image_executable_pages_read_execute_only,
    native_loaded_image_executable_segment_file_size_equals_vm_size:
      native.loaded_image_executable_segment_file_size_equals_vm_size,
    native_loaded_image_non_executable_runtime_state_measured:
      native.loaded_image_non_executable_runtime_state_measured,
    native_loaded_image_executable_identity_complete:
      native.loaded_image_executable_identity_complete,
    native_loaded_image_full_runtime_state_identity_complete:
      native.loaded_image_full_runtime_state_identity_complete,
    native_loaded_image_signed_immutable_delivery_verified: false,
    production_ready: false,
    production_blockers: DARWIN_NATIVE_SELF_IDENTITY_PRODUCTION_BLOCKERS,
  });
  reflectApply(weakSetAdd, SELF_INSPECTORS, [port]);
  reflectApply(weakMapSet, SELF_INSPECTOR_STATE, [port, objectFreeze({
    inspectCurrentSelf: native.inspectCurrentSelf,
  })]);
  return port;
}

function assertDarwinNativeSelfIdentityInspector(port) {
  if (arguments.length !== 1 || port == null || typeof port !== "object"
      || utilTypesIsProxy(port) || !objectIsFrozen(port)
      || !reflectApply(weakSetHas, SELF_INSPECTORS, [port])
      || !reflectApply(weakMapHas, SELF_INSPECTOR_STATE, [port])) {
    throw selfError();
  }
  return port;
}

function reserveCurrentSelfInspection() {
  try {
    reserveSelfIdentityInspection();
  } catch {
    throw selfError();
  }
}

const NATIVE_SELF_SNAPSHOT_FIELDS = objectFreeze([
  "version",
  "primitive",
  "self_euid",
  "self_egid",
  "self_ruid",
  "self_rgid",
  "self_pid",
  "self_pidversion",
  "self_process_start_tvsec",
  "self_process_start_tvusec",
  "self_audit_token_digest",
  "self_process_start_token_digest",
  "self_executable_path_digest",
  "self_code_identity_scheme",
  "self_code_identity_completeness",
  "self_code_identity_audit_token_bound",
  "self_code_identity_seccode_self_cross_checked",
  "self_code_identity_stable",
  "self_code_dynamic_validity_scheme",
  "self_code_dynamic_validity",
  "self_code_directory_hash",
  "self_code_directory_hash_algorithm",
  "self_code_directory_hashes_digest",
  "self_code_signing_identifier_digest",
  "self_code_team_identifier_state",
  "self_code_team_identifier_digest",
  "self_code_certificate_chain_state",
  "self_code_certificate_count",
  "self_code_certificate_chain_digest",
  "self_code_designated_requirement_digest",
  "self_code_static_flags_digest",
  "self_code_dynamic_status_digest",
  "self_code_signature_class",
  "self_code_signer_identity_complete",
  "self_code_signing_identity_digest",
  "self_mapped_code_identity_digest",
  "self_kernel_snapshot_stable",
]);

function normalizeNativeSelfSnapshot(input) {
  assertExactNativeObject(input, NATIVE_SELF_SNAPSHOT_FIELDS);
  if (input.version !== DARWIN_NATIVE_SELF_IDENTITY_VERSION
      || input.primitive !== DARWIN_NATIVE_SELF_IDENTITY_PRIMITIVE
      || input.self_kernel_snapshot_stable !== true
      || input.self_code_identity_scheme
        !== "darwin_task_audit_token_guest_and_seccode_self_cdhash_v1"
      || input.self_code_identity_completeness
        !== "dynamic_seccode_identity_complete"
      || input.self_code_identity_audit_token_bound !== true
      || input.self_code_identity_seccode_self_cross_checked !== true
      || input.self_code_identity_stable !== true
      || input.self_code_dynamic_validity_scheme
        !== "darwin_seccode_check_validity_dynamic_default_v1"
      || input.self_code_dynamic_validity !== "valid") throw selfError();
  const teamState = assertClosedValue(
    input.self_code_team_identifier_state,
    ["absent", "present"],
  );
  const certificateState = assertClosedValue(
    input.self_code_certificate_chain_state,
    ["absent", "present"],
  );
  const signatureClass = assertClosedValue(
    input.self_code_signature_class,
    ["adhoc", "certificate_signed", "non_adhoc_certificate_absent"],
  );
  const certificateCount = assertUint32(input.self_code_certificate_count);
  if ((certificateState === "present") !== (certificateCount > 0)
      || (signatureClass === "certificate_signed") !== (certificateCount > 0)
      || (signatureClass === "adhoc" && teamState !== "absent")
      || input.self_code_signer_identity_complete
        !== (signatureClass === "certificate_signed" && teamState === "present")) {
    throw selfError();
  }
  return {
    self_uid: assertUint32(input.self_euid),
    self_gid: assertUint32(input.self_egid),
    self_real_uid: assertUint32(input.self_ruid),
    self_real_gid: assertUint32(input.self_rgid),
    self_pid: assertUint32(input.self_pid),
    self_pidversion: assertUint32(input.self_pidversion),
    self_process_start_tvsec: assertDecimal(input.self_process_start_tvsec),
    self_process_start_tvusec: assertDecimal(input.self_process_start_tvusec),
    self_audit_token_digest: assertDigest(input.self_audit_token_digest),
    self_process_start_token_digest: assertDigest(input.self_process_start_token_digest),
    self_executable_path_digest: assertDigest(input.self_executable_path_digest),
    self_code_identity_scheme: input.self_code_identity_scheme,
    self_code_identity_completeness: input.self_code_identity_completeness,
    self_code_identity_audit_token_bound: input.self_code_identity_audit_token_bound,
    self_code_identity_seccode_self_cross_checked:
      input.self_code_identity_seccode_self_cross_checked,
    self_code_identity_stable: input.self_code_identity_stable,
    self_code_dynamic_validity_scheme: input.self_code_dynamic_validity_scheme,
    self_code_dynamic_validity: input.self_code_dynamic_validity,
    self_code_directory_hash: assertCodeDirectoryHash(input.self_code_directory_hash),
    self_code_directory_hash_algorithm: assertUint32(
      input.self_code_directory_hash_algorithm,
    ),
    self_code_directory_hashes_digest: assertDigest(
      input.self_code_directory_hashes_digest,
    ),
    self_code_signing_identifier_digest: assertDigest(
      input.self_code_signing_identifier_digest,
    ),
    self_code_team_identifier_state: teamState,
    self_code_team_identifier_digest: assertDigest(input.self_code_team_identifier_digest),
    self_code_certificate_chain_state: certificateState,
    self_code_certificate_count: certificateCount,
    self_code_certificate_chain_digest: assertDigest(
      input.self_code_certificate_chain_digest,
    ),
    self_code_designated_requirement_digest: assertDigest(
      input.self_code_designated_requirement_digest,
    ),
    self_code_static_flags_digest: assertDigest(input.self_code_static_flags_digest),
    self_code_dynamic_status_digest: assertDigest(input.self_code_dynamic_status_digest),
    self_code_signature_class: signatureClass,
    self_code_signer_identity_complete: input.self_code_signer_identity_complete,
    self_code_signing_identity_digest: assertDigest(input.self_code_signing_identity_digest),
    self_mapped_code_identity_digest: assertDigest(input.self_mapped_code_identity_digest),
  };
}

const SELF_SNAPSHOT_BASIS_FIELDS = objectFreeze([
  "version",
  "adapter_id",
  "credential_source",
  "platform",
  "architecture",
  "primitive",
  "native_binding_implementation_digest",
  "native_binding_measurement_scheme",
  "native_loaded_image_measurement_scheme",
  "native_loaded_image_identity_digest",
  "native_loaded_image_file_sha256",
  "native_loaded_image_canonical_path_digest",
  "native_loaded_image_file_identity_digest",
  "native_loaded_image_lc_uuid_digest",
  "native_loaded_image_header_and_load_commands_digest",
  "native_loaded_image_executable_segments_digest",
  "native_loaded_image_executable_segment_count",
  "native_loaded_image_executable_file_bytes",
  "native_loaded_image_dyld_header_unique",
  "native_loaded_image_dladdr_base_matches_dyld",
  "native_loaded_image_dyld_snapshot_stable",
  "native_loaded_image_dyld_canonical_path_matches_dladdr",
  "native_loaded_image_callback_in_executable_segment",
  "native_loaded_image_header_and_load_commands_match_file",
  "native_loaded_image_executable_segments_match_file",
  "native_loaded_image_executable_pages_read_execute_only",
  "native_loaded_image_executable_segment_file_size_equals_vm_size",
  "native_loaded_image_non_executable_runtime_state_measured",
  "native_loaded_image_executable_identity_complete",
  "native_loaded_image_full_runtime_state_identity_complete",
  "native_loaded_image_signed_immutable_delivery_verified",
  "self_uid",
  "self_gid",
  "self_real_uid",
  "self_real_gid",
  "self_pid",
  "self_pidversion",
  "self_process_start_tvsec",
  "self_process_start_tvusec",
  "self_audit_token_digest",
  "self_process_start_token_digest",
  "self_executable_path_digest",
  "self_code_identity_scheme",
  "self_code_identity_completeness",
  "self_code_identity_audit_token_bound",
  "self_code_identity_seccode_self_cross_checked",
  "self_code_identity_stable",
  "self_code_dynamic_validity_scheme",
  "self_code_dynamic_validity",
  "self_code_directory_hash",
  "self_code_directory_hash_algorithm",
  "self_code_directory_hashes_digest",
  "self_code_signing_identifier_digest",
  "self_code_team_identifier_state",
  "self_code_team_identifier_digest",
  "self_code_certificate_chain_state",
  "self_code_certificate_count",
  "self_code_certificate_chain_digest",
  "self_code_designated_requirement_digest",
  "self_code_static_flags_digest",
  "self_code_dynamic_status_digest",
  "self_code_signature_class",
  "self_code_signer_identity_complete",
  "self_code_signing_identity_digest",
  "self_mapped_code_identity_digest",
  "self_executable_path_measurement_scheme",
  "self_executable_path_measurement_complete",
  "self_executable_bytes_measurement_scheme",
  "self_executable_bytes_measurement_complete",
  "production_ready",
  "production_blockers",
]);

function inspectCurrentDarwinSelf(port) {
  if (arguments.length !== 1) throw selfError();
  assertDarwinNativeSelfIdentityInspector(port);
  const state = reflectApply(weakMapGet, SELF_INSPECTOR_STATE, [port]);
  let hostIdentity;
  try {
    hostIdentity = getHostIdentity();
  } catch {
    throw selfError();
  }
  reserveCurrentSelfInspection();
  let native;
  try {
    native = reflectApply(state.inspectCurrentSelf, undefined, []);
  } catch {
    throw selfError();
  }
  const projection = normalizeNativeSelfSnapshot(native);
  if (projection.self_pid !== hostIdentity.pid
      || projection.self_uid !== hostIdentity.uid
      || projection.self_gid !== hostIdentity.gid
      || projection.self_real_uid !== hostIdentity.real_uid
      || projection.self_real_gid !== hostIdentity.real_gid) {
    throw selfError();
  }
  const basis = {
    version: DARWIN_NATIVE_SELF_IDENTITY_VERSION,
    adapter_id: port.adapter_id,
    credential_source:
      "darwin_task_audit_token_and_security_framework_dynamic_code_self",
    platform: "darwin",
    architecture: "arm64",
    primitive: DARWIN_NATIVE_SELF_IDENTITY_PRIMITIVE,
    native_binding_implementation_digest: port.native_binding_implementation_digest,
    native_binding_measurement_scheme: port.native_binding_measurement_scheme,
    native_loaded_image_measurement_scheme:
      port.native_loaded_image_measurement_scheme,
    native_loaded_image_identity_digest:
      port.native_loaded_image_identity_digest,
    native_loaded_image_file_sha256:
      port.native_loaded_image_file_sha256,
    native_loaded_image_canonical_path_digest:
      port.native_loaded_image_canonical_path_digest,
    native_loaded_image_file_identity_digest:
      port.native_loaded_image_file_identity_digest,
    native_loaded_image_lc_uuid_digest:
      port.native_loaded_image_lc_uuid_digest,
    native_loaded_image_header_and_load_commands_digest:
      port.native_loaded_image_header_and_load_commands_digest,
    native_loaded_image_executable_segments_digest:
      port.native_loaded_image_executable_segments_digest,
    native_loaded_image_executable_segment_count:
      port.native_loaded_image_executable_segment_count,
    native_loaded_image_executable_file_bytes:
      port.native_loaded_image_executable_file_bytes,
    native_loaded_image_dyld_header_unique:
      port.native_loaded_image_dyld_header_unique,
    native_loaded_image_dladdr_base_matches_dyld:
      port.native_loaded_image_dladdr_base_matches_dyld,
    native_loaded_image_dyld_snapshot_stable:
      port.native_loaded_image_dyld_snapshot_stable,
    native_loaded_image_dyld_canonical_path_matches_dladdr:
      port.native_loaded_image_dyld_canonical_path_matches_dladdr,
    native_loaded_image_callback_in_executable_segment:
      port.native_loaded_image_callback_in_executable_segment,
    native_loaded_image_header_and_load_commands_match_file:
      port.native_loaded_image_header_and_load_commands_match_file,
    native_loaded_image_executable_segments_match_file:
      port.native_loaded_image_executable_segments_match_file,
    native_loaded_image_executable_pages_read_execute_only:
      port.native_loaded_image_executable_pages_read_execute_only,
    native_loaded_image_executable_segment_file_size_equals_vm_size:
      port.native_loaded_image_executable_segment_file_size_equals_vm_size,
    native_loaded_image_non_executable_runtime_state_measured:
      port.native_loaded_image_non_executable_runtime_state_measured,
    native_loaded_image_executable_identity_complete:
      port.native_loaded_image_executable_identity_complete,
    native_loaded_image_full_runtime_state_identity_complete:
      port.native_loaded_image_full_runtime_state_identity_complete,
    native_loaded_image_signed_immutable_delivery_verified:
      port.native_loaded_image_signed_immutable_delivery_verified,
    ...projection,
    self_executable_path_measurement_scheme:
      "darwin_proc_pidpath_audittoken_path_digest_v1",
    self_executable_path_measurement_complete: true,
    self_executable_bytes_measurement_scheme: "unavailable",
    self_executable_bytes_measurement_complete: false,
    production_ready: false,
    production_blockers: DARWIN_NATIVE_SELF_IDENTITY_PRODUCTION_BLOCKERS,
  };
  let snapshotDigest;
  try {
    snapshotDigest = digestFixedSnapshot(
      DARWIN_NATIVE_SELF_IDENTITY_DOMAIN,
      basis,
      SELF_SNAPSHOT_BASIS_FIELDS,
    );
  } catch {
    throw selfError();
  }
  return deepFreeze({ ...basis, snapshot_digest: snapshotDigest });
}

module.exports = {
  DARWIN_NATIVE_SELF_IDENTITY_DOMAIN,
  DARWIN_NATIVE_SELF_IDENTITY_PRIMITIVE,
  DARWIN_NATIVE_SELF_IDENTITY_PRODUCTION_BLOCKERS,
  DARWIN_NATIVE_SELF_IDENTITY_VERSION,
  assertDarwinNativeSelfIdentityInspector,
  createDarwinNativeSelfIdentityInspector,
  inspectCurrentDarwinSelf,
};
