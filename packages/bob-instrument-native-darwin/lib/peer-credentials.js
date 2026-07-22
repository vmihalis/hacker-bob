"use strict";

const { types: utilTypes } = require("node:util");
const { digestFixedSnapshot } = require("./canonical-snapshot.js");
const {
  getHostIdentity,
  loadNativeBindingOnce,
} = require("./native-binding-loader.js");

const SafeError = Error;
const SafeBuffer = Buffer;
const arrayIsArray = Array.isArray;
const bufferFrom = Buffer.from;
const bufferToString = Buffer.prototype.toString;
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

const DARWIN_NATIVE_PEER_CREDENTIAL_VERSION = 3;
const DARWIN_NATIVE_PEER_CREDENTIAL_PRIMITIVE =
  "darwin_registered_descriptor_peertoken_seccode_dynamic_identity_v3";
const DARWIN_NATIVE_PEER_MEASUREMENT_VERSION = 2;
const DARWIN_NATIVE_PEER_MEASUREMENT_PRIMITIVE =
  "darwin_local_peertoken_seccode_dynamic_identity_v2";
const DARWIN_NATIVE_PEER_CREDENTIAL_DOMAIN =
  "hacker-bob/darwin-native-peer-credential-snapshot/v3";
const DARWIN_NATIVE_PEER_DESCRIPTOR_BINDING_SCHEME =
  "darwin_f_dupfd_cloexec_native_registration_token_v1";
const DARWIN_NATIVE_PEER_DESCRIPTOR_BINDING_SCOPE =
  "exact_native_duplicate_of_supplied_descriptor_at_registration";
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const CODE_DIRECTORY_HASH_PATTERN = /^(?:[a-f0-9]{2}){16,64}$/u;
const TOKEN_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,128}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;
const INSPECTORS = new WeakSet();
const INSPECTOR_STATE = new WeakMap();
const DESCRIPTOR_REGISTRATIONS = new WeakSet();
const DESCRIPTOR_REGISTRATION_STATE = new WeakMap();
const CONSUMED_DESCRIPTOR_REGISTRATIONS = new WeakSet();

function peerError() {
  const error = new SafeError("Darwin native peer identity was rejected");
  objectDefineProperty(error, "code", {
    value: "darwin_native_peer_rejected",
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
  if (!isPlainDataObject(value)) throw peerError();
  const actual = objectKeys(value);
  if (actual.length !== fields.length) throw peerError();
  for (let fieldIndex = 0; fieldIndex < fields.length; fieldIndex += 1) {
    const field = fields[fieldIndex];
    let found = false;
    for (let actualIndex = 0; actualIndex < actual.length; actualIndex += 1) {
      const candidate = actual[actualIndex];
      if (candidate === field) found = true;
    }
    if (!found) throw peerError();
  }
  return value;
}

function assertExactNativeObject(value, fields) {
  assertExactObject(value, fields);
  if (objectGetPrototypeOf(value) !== objectPrototype) throw peerError();
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    const descriptor = objectGetOwnPropertyDescriptor(value, field);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true || descriptor.writable !== false
        || descriptor.configurable !== false) throw peerError();
  }
  return value;
}

function assertDigest(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, DIGEST_PATTERN, [value])) throw peerError();
  return value;
}

function assertCodeDirectoryHash(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, CODE_DIRECTORY_HASH_PATTERN, [value])) {
    throw peerError();
  }
  return value;
}

function assertClosedValue(value, allowed) {
  if (typeof value !== "string") throw peerError();
  for (let index = 0; index < allowed.length; index += 1) {
    const candidate = allowed[index];
    if (value === candidate) return value;
  }
  throw peerError();
}

function assertUint32(value) {
  if (!numberIsInteger(value) || value < 0 || value > 0xffff_ffff) throw peerError();
  return value;
}

function assertDescriptor(value) {
  if (!numberIsInteger(value) || value < 0 || value > 0x7fff_ffff) throw peerError();
  return value;
}

function assertDecimal(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, DECIMAL_PATTERN, [value])) throw peerError();
  return value;
}

function normalizeNonce(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, NONCE_PATTERN, [value])) throw peerError();
  const bytes = reflectApply(bufferFrom, SafeBuffer, [value, "base64url"]);
  if (bytes.length < 16
      || reflectApply(bufferToString, bytes, ["base64url"]) !== value) throw peerError();
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

function createDarwinNativePeerCredentialInspector(input) {
  if (arguments.length !== 1) throw peerError();
  assertExactObject(input, ["adapter_id"]);
  if (typeof input.adapter_id !== "string"
      || !reflectApply(regExpTest, TOKEN_PATTERN, [input.adapter_id])) {
    throw peerError();
  }
  let native;
  try {
    getHostIdentity();
    native = loadNativeBindingOnce();
  } catch {
    throw peerError();
  }
  const port = deepFreeze({
    version: DARWIN_NATIVE_PEER_CREDENTIAL_VERSION,
    adapter_id: input.adapter_id,
    platform: "darwin",
    architecture: "arm64",
    node_abi: "napi-v9",
    primitive: DARWIN_NATIVE_PEER_CREDENTIAL_PRIMITIVE,
    native_peer_measurement_version: DARWIN_NATIVE_PEER_MEASUREMENT_VERSION,
    native_peer_measurement_primitive: DARWIN_NATIVE_PEER_MEASUREMENT_PRIMITIVE,
    credential_source:
      "darwin_supplied_registered_unix_descriptor_audit_token_and_dynamic_code",
    descriptor_binding_scheme: DARWIN_NATIVE_PEER_DESCRIPTOR_BINDING_SCHEME,
    descriptor_binding_scope: DARWIN_NATIVE_PEER_DESCRIPTOR_BINDING_SCOPE,
    accepted_socket_object_binding_complete: false,
    native_acceptor_registration_handoff_complete: false,
    descriptor_provenance_complete: false,
    descriptor_reregistration_prevented: false,
    descriptor_evidence_ipc_handshake_binding_complete: false,
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
    production_blockers: [
      "mapped_code_identity_policy_allowlist_missing",
      "mapped_code_identity_hil_missing",
      "native_addon_non_executable_runtime_state_unverified",
      "native_addon_signed_immutable_delivery_unverified",
      "root_owned_immutable_bundle_unverified",
      "dedicated_principal_and_acl_hil_missing",
      "launch_ticket_binding_missing",
      "native_acceptor_to_descriptor_registration_handoff_missing",
      "js_socket_to_fd_custody_unproven",
      "descriptor_provenance_unverified",
      "descriptor_reregistration_not_prevented",
      "descriptor_evidence_to_ipc_handshake_binding_missing",
    ],
  });
  reflectApply(weakSetAdd, INSPECTORS, [port]);
  reflectApply(weakMapSet, INSPECTOR_STATE, [port, objectFreeze({
    registerUnixPeerDescriptor: native.registerUnixPeerDescriptor,
    inspectRegisteredUnixPeer: native.inspectRegisteredUnixPeer,
  })]);
  return port;
}

function assertDarwinNativePeerCredentialInspector(port) {
  if (arguments.length !== 1 || port == null || typeof port !== "object"
      || utilTypesIsProxy(port) || !objectIsFrozen(port)
      || !reflectApply(weakSetHas, INSPECTORS, [port])
      || !reflectApply(weakMapHas, INSPECTOR_STATE, [port])) throw peerError();
  return port;
}

function registerDarwinUnixPeerDescriptor(
  port,
  descriptor,
  descriptorRegistrationNonce,
) {
  if (arguments.length !== 3) throw peerError();
  assertDarwinNativePeerCredentialInspector(port);
  try {
    getHostIdentity();
  } catch {
    throw peerError();
  }
  const fd = assertDescriptor(descriptor);
  const nonce = normalizeNonce(descriptorRegistrationNonce);
  const state = reflectApply(weakMapGet, INSPECTOR_STATE, [port]);
  let nativeToken;
  try {
    nativeToken = reflectApply(state.registerUnixPeerDescriptor, undefined, [fd]);
  } catch {
    throw peerError();
  }
  if (nativeToken == null || typeof nativeToken !== "object"
      || utilTypesIsProxy(nativeToken) || !objectIsFrozen(nativeToken)
      || objectGetPrototypeOf(nativeToken) !== objectPrototype
      || reflectOwnKeys(nativeToken).length !== 1
      || reflectOwnKeys(nativeToken)[0] !== "registration_token_digest") {
    throw peerError();
  }
  const tokenDigestDescriptor = objectGetOwnPropertyDescriptor(
    nativeToken,
    "registration_token_digest",
  );
  if (tokenDigestDescriptor == null
      || !objectHasOwn(tokenDigestDescriptor, "value")
      || tokenDigestDescriptor.writable !== false
      || tokenDigestDescriptor.enumerable !== false
      || tokenDigestDescriptor.configurable !== false) throw peerError();
  const registrationTokenDigest = assertDigest(tokenDigestDescriptor.value);
  const registration = deepFreeze({
    version: DARWIN_NATIVE_PEER_CREDENTIAL_VERSION,
    adapter_id: port.adapter_id,
    platform: "darwin",
    architecture: "arm64",
    primitive: DARWIN_NATIVE_PEER_CREDENTIAL_PRIMITIVE,
    descriptor_binding_scheme: DARWIN_NATIVE_PEER_DESCRIPTOR_BINDING_SCHEME,
    descriptor_binding_scope: DARWIN_NATIVE_PEER_DESCRIPTOR_BINDING_SCOPE,
    descriptor_registration_token_digest: registrationTokenDigest,
    native_loaded_image_identity_digest:
      port.native_loaded_image_identity_digest,
    accepted_socket_object_binding_complete: false,
    native_acceptor_registration_handoff_complete: false,
    descriptor_provenance_complete: false,
    descriptor_reregistration_prevented: false,
    descriptor_evidence_ipc_handshake_binding_complete: false,
    production_ready: false,
  });
  reflectApply(weakSetAdd, DESCRIPTOR_REGISTRATIONS, [registration]);
  reflectApply(weakMapSet, DESCRIPTOR_REGISTRATION_STATE, [registration, objectFreeze({
    port,
    native_token: nativeToken,
    descriptor_registration_nonce: nonce,
    descriptor_registration_token_digest: registrationTokenDigest,
  })]);
  return registration;
}

function assertDarwinUnixPeerDescriptorRegistration(port, registration) {
  if (registration == null || typeof registration !== "object"
      || utilTypesIsProxy(registration) || !objectIsFrozen(registration)
      || !reflectApply(weakSetHas, DESCRIPTOR_REGISTRATIONS, [registration])
      || !reflectApply(weakMapHas, DESCRIPTOR_REGISTRATION_STATE, [registration])
      || reflectApply(weakSetHas, CONSUMED_DESCRIPTOR_REGISTRATIONS, [registration])) {
    throw peerError();
  }
  const state = reflectApply(weakMapGet, DESCRIPTOR_REGISTRATION_STATE, [registration]);
  if (state.port !== port) throw peerError();
  return state;
}

const NATIVE_SNAPSHOT_FIELDS = objectFreeze([
  "version",
  "primitive",
  "descriptor_registration_token_digest",
  "peer_euid",
  "peer_egid",
  "peer_ruid",
  "peer_rgid",
  "peer_pid",
  "peer_pidversion",
  "peer_process_start_tvsec",
  "peer_process_start_tvusec",
  "peer_audit_token_digest",
  "peer_process_start_token_digest",
  "peer_executable_path_digest",
  "peer_code_identity_scheme",
  "peer_code_identity_completeness",
  "peer_code_identity_audit_token_bound",
  "peer_code_identity_stable",
  "peer_code_dynamic_validity_scheme",
  "peer_code_dynamic_validity",
  "peer_code_directory_hash",
  "peer_code_directory_hash_algorithm",
  "peer_code_directory_hashes_digest",
  "peer_code_signing_identifier_digest",
  "peer_code_team_identifier_state",
  "peer_code_team_identifier_digest",
  "peer_code_certificate_chain_state",
  "peer_code_certificate_count",
  "peer_code_certificate_chain_digest",
  "peer_code_designated_requirement_digest",
  "peer_code_static_flags_digest",
  "peer_code_dynamic_status_digest",
  "peer_code_signature_class",
  "peer_code_signer_identity_complete",
  "peer_code_signing_identity_digest",
  "peer_mapped_code_identity_digest",
  "kernel_snapshot_stable",
]);

function normalizeNativeSnapshot(input) {
  assertExactNativeObject(input, NATIVE_SNAPSHOT_FIELDS);
  if (input.version !== DARWIN_NATIVE_PEER_MEASUREMENT_VERSION
      || input.primitive !== DARWIN_NATIVE_PEER_MEASUREMENT_PRIMITIVE
      || input.kernel_snapshot_stable !== true
      || input.peer_code_identity_scheme
        !== "darwin_seccode_guest_audit_token_dynamic_cdhash_v1"
      || input.peer_code_identity_completeness
        !== "dynamic_seccode_identity_complete"
      || input.peer_code_identity_audit_token_bound !== true
      || input.peer_code_identity_stable !== true
      || input.peer_code_dynamic_validity_scheme
        !== "darwin_seccode_check_validity_dynamic_default_v1"
      || input.peer_code_dynamic_validity !== "valid") throw peerError();
  const teamState = assertClosedValue(
    input.peer_code_team_identifier_state,
    ["absent", "present"],
  );
  const certificateState = assertClosedValue(
    input.peer_code_certificate_chain_state,
    ["absent", "present"],
  );
  const signatureClass = assertClosedValue(
    input.peer_code_signature_class,
    ["adhoc", "certificate_signed", "non_adhoc_certificate_absent"],
  );
  const certificateCount = assertUint32(input.peer_code_certificate_count);
  if ((certificateState === "present") !== (certificateCount > 0)
      || (signatureClass === "certificate_signed") !== (certificateCount > 0)
      || (signatureClass === "adhoc" && teamState !== "absent")
      || input.peer_code_signer_identity_complete
        !== (signatureClass === "certificate_signed" && teamState === "present")) {
    throw peerError();
  }
  return {
    descriptor_registration_token_digest: assertDigest(
      input.descriptor_registration_token_digest,
    ),
    peer_uid: assertUint32(input.peer_euid),
    peer_gid: assertUint32(input.peer_egid),
    peer_real_uid: assertUint32(input.peer_ruid),
    peer_real_gid: assertUint32(input.peer_rgid),
    peer_pid: assertUint32(input.peer_pid),
    peer_pidversion: assertUint32(input.peer_pidversion),
    peer_process_start_tvsec: assertDecimal(input.peer_process_start_tvsec),
    peer_process_start_tvusec: assertDecimal(input.peer_process_start_tvusec),
    peer_audit_token_digest: assertDigest(input.peer_audit_token_digest),
    peer_process_start_token_digest: assertDigest(input.peer_process_start_token_digest),
    peer_executable_path_digest: assertDigest(input.peer_executable_path_digest),
    peer_code_identity_scheme: input.peer_code_identity_scheme,
    peer_code_identity_completeness: input.peer_code_identity_completeness,
    peer_code_identity_audit_token_bound: input.peer_code_identity_audit_token_bound,
    peer_code_identity_stable: input.peer_code_identity_stable,
    peer_code_dynamic_validity_scheme: input.peer_code_dynamic_validity_scheme,
    peer_code_dynamic_validity: input.peer_code_dynamic_validity,
    peer_code_directory_hash: assertCodeDirectoryHash(input.peer_code_directory_hash),
    peer_code_directory_hash_algorithm: assertUint32(
      input.peer_code_directory_hash_algorithm,
    ),
    peer_code_directory_hashes_digest: assertDigest(
      input.peer_code_directory_hashes_digest,
    ),
    peer_code_signing_identifier_digest: assertDigest(
      input.peer_code_signing_identifier_digest,
    ),
    peer_code_team_identifier_state: teamState,
    peer_code_team_identifier_digest: assertDigest(input.peer_code_team_identifier_digest),
    peer_code_certificate_chain_state: certificateState,
    peer_code_certificate_count: certificateCount,
    peer_code_certificate_chain_digest: assertDigest(
      input.peer_code_certificate_chain_digest,
    ),
    peer_code_designated_requirement_digest: assertDigest(
      input.peer_code_designated_requirement_digest,
    ),
    peer_code_static_flags_digest: assertDigest(input.peer_code_static_flags_digest),
    peer_code_dynamic_status_digest: assertDigest(input.peer_code_dynamic_status_digest),
    peer_code_signature_class: signatureClass,
    peer_code_signer_identity_complete: input.peer_code_signer_identity_complete,
    peer_code_signing_identity_digest: assertDigest(input.peer_code_signing_identity_digest),
    peer_mapped_code_identity_digest: assertDigest(input.peer_mapped_code_identity_digest),
  };
}

const PEER_SNAPSHOT_BASIS_FIELDS = objectFreeze([
  "version",
  "adapter_id",
  "credential_source",
  "platform",
  "architecture",
  "primitive",
  "native_peer_measurement_version",
  "native_peer_measurement_primitive",
  "descriptor_registration_nonce",
  "descriptor_registration_token_digest",
  "descriptor_binding_scheme",
  "descriptor_binding_scope",
  "accepted_socket_object_binding_complete",
  "native_acceptor_registration_handoff_complete",
  "descriptor_provenance_complete",
  "descriptor_reregistration_prevented",
  "descriptor_evidence_ipc_handshake_binding_complete",
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
  "peer_uid",
  "peer_gid",
  "peer_real_uid",
  "peer_real_gid",
  "peer_pid",
  "peer_pidversion",
  "peer_process_start_tvsec",
  "peer_process_start_tvusec",
  "peer_audit_token_digest",
  "peer_process_start_token_digest",
  "peer_executable_path_digest",
  "peer_code_identity_scheme",
  "peer_code_identity_completeness",
  "peer_code_identity_audit_token_bound",
  "peer_code_identity_stable",
  "peer_code_dynamic_validity_scheme",
  "peer_code_dynamic_validity",
  "peer_code_directory_hash",
  "peer_code_directory_hash_algorithm",
  "peer_code_directory_hashes_digest",
  "peer_code_signing_identifier_digest",
  "peer_code_team_identifier_state",
  "peer_code_team_identifier_digest",
  "peer_code_certificate_chain_state",
  "peer_code_certificate_count",
  "peer_code_certificate_chain_digest",
  "peer_code_designated_requirement_digest",
  "peer_code_static_flags_digest",
  "peer_code_dynamic_status_digest",
  "peer_code_signature_class",
  "peer_code_signer_identity_complete",
  "peer_code_signing_identity_digest",
  "peer_mapped_code_identity_digest",
  "peer_executable_path_measurement_scheme",
  "peer_executable_path_measurement_complete",
  "peer_executable_bytes_measurement_scheme",
  "peer_executable_bytes_measurement_complete",
  "production_ready",
]);

function inspectRegisteredDarwinUnixPeer(port, registration) {
  if (arguments.length !== 2) throw peerError();
  assertDarwinNativePeerCredentialInspector(port);
  try {
    getHostIdentity();
  } catch {
    throw peerError();
  }
  const registrationState = assertDarwinUnixPeerDescriptorRegistration(
    port,
    registration,
  );
  const inspectorState = reflectApply(weakMapGet, INSPECTOR_STATE, [port]);
  reflectApply(weakSetAdd, CONSUMED_DESCRIPTOR_REGISTRATIONS, [registration]);
  let native;
  try {
    native = reflectApply(
      inspectorState.inspectRegisteredUnixPeer,
      undefined,
      [registrationState.native_token],
    );
  } catch {
    throw peerError();
  }
  const projection = normalizeNativeSnapshot(native);
  if (projection.descriptor_registration_token_digest
      !== registrationState.descriptor_registration_token_digest) throw peerError();
  const basis = {
    version: DARWIN_NATIVE_PEER_CREDENTIAL_VERSION,
    adapter_id: port.adapter_id,
    credential_source:
      "darwin_supplied_registered_unix_descriptor_audit_token_and_dynamic_code",
    platform: "darwin",
    architecture: "arm64",
    primitive: DARWIN_NATIVE_PEER_CREDENTIAL_PRIMITIVE,
    native_peer_measurement_version: DARWIN_NATIVE_PEER_MEASUREMENT_VERSION,
    native_peer_measurement_primitive: DARWIN_NATIVE_PEER_MEASUREMENT_PRIMITIVE,
    descriptor_registration_nonce:
      registrationState.descriptor_registration_nonce,
    descriptor_registration_token_digest:
      registrationState.descriptor_registration_token_digest,
    descriptor_binding_scheme: DARWIN_NATIVE_PEER_DESCRIPTOR_BINDING_SCHEME,
    descriptor_binding_scope: DARWIN_NATIVE_PEER_DESCRIPTOR_BINDING_SCOPE,
    accepted_socket_object_binding_complete: false,
    native_acceptor_registration_handoff_complete: false,
    descriptor_provenance_complete: false,
    descriptor_reregistration_prevented: false,
    descriptor_evidence_ipc_handshake_binding_complete: false,
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
    peer_executable_path_measurement_scheme:
      "darwin_proc_pidpath_audittoken_path_digest_v2",
    peer_executable_path_measurement_complete: true,
    peer_executable_bytes_measurement_scheme: "unavailable",
    peer_executable_bytes_measurement_complete: false,
    production_ready: false,
  };
  let snapshotDigest;
  try {
    snapshotDigest = digestFixedSnapshot(
      DARWIN_NATIVE_PEER_CREDENTIAL_DOMAIN,
      basis,
      PEER_SNAPSHOT_BASIS_FIELDS,
    );
  } catch {
    throw peerError();
  }
  return deepFreeze({ ...basis, snapshot_digest: snapshotDigest });
}

module.exports = {
  DARWIN_NATIVE_PEER_CREDENTIAL_DOMAIN,
  DARWIN_NATIVE_PEER_CREDENTIAL_PRIMITIVE,
  DARWIN_NATIVE_PEER_CREDENTIAL_VERSION,
  assertDarwinNativePeerCredentialInspector,
  createDarwinNativePeerCredentialInspector,
  inspectRegisteredDarwinUnixPeer,
  registerDarwinUnixPeerDescriptor,
};
