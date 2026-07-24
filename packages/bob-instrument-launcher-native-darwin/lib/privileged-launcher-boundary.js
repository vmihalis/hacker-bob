"use strict";

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");
const {
  assertVerifiedWorkerBundleEnrollment,
} = require("../../bob-instrument-broker/lib/worker-bundle-attestation.js");
const {
  normalizeDarwinNativeFixtureContractRecord,
} = require("./native-fixture-record.js");

const DARWIN_LAUNCHER_VERSION = 1;
const DARWIN_LAUNCH_PLAN_DOMAIN =
  "hacker-bob/instrument-darwin-launch-plan/v1";
const DARWIN_LAUNCH_TICKET_DOMAIN =
  "hacker-bob/instrument-darwin-launch-ticket/v1";
const DARWIN_LAUNCH_TICKET_SIGNATURE_DOMAIN =
  "hacker-bob/instrument-darwin-launch-ticket-signature/v1";
const DARWIN_LAUNCH_TICKET_KEY_USAGE =
  "instrument_darwin_privileged_launch_ticket";
const DARWIN_LAUNCH_AUTHORITY_STATE_DOMAIN =
  "hacker-bob/instrument-darwin-launch-authority-state/v1";
const DARWIN_LAUNCH_WORKER_BUNDLE_PROJECTION_DOMAIN =
  "hacker-bob/instrument-darwin-launch-worker-bundle-projection/v1";
const DARWIN_LAUNCH_PATH_IDENTITY_DOMAIN =
  "hacker-bob/instrument-darwin-launch-path-identity/v1";
const DARWIN_LAUNCH_ARGV_DOMAIN =
  "hacker-bob/instrument-darwin-launch-argv/v1";
const DARWIN_LAUNCH_ENVIRONMENT_DOMAIN =
  "hacker-bob/instrument-darwin-launch-environment/v1";
const DARWIN_LAUNCH_FD_SET_DOMAIN =
  "hacker-bob/instrument-darwin-launch-fd-set/v1";
const DARWIN_LAUNCH_CREDENTIAL_PLAN_DOMAIN =
  "hacker-bob/instrument-darwin-launch-credential-plan/v1";
const DARWIN_LAUNCH_NATIVE_EVIDENCE_DOMAIN =
  "hacker-bob/instrument-darwin-launch-native-evidence/v1";
const DARWIN_LAUNCH_NATIVE_SNAPSHOT_DOMAIN =
  "hacker-bob/instrument-darwin-launch-native-snapshot/v1";
const DARWIN_LAUNCH_REPLAY_CLAIM_DOMAIN =
  "hacker-bob/instrument-darwin-launch-replay-claim/v1";
const DARWIN_LAUNCH_REPLAY_RECEIPT_DOMAIN =
  "hacker-bob/instrument-darwin-launch-replay-receipt/v1";

const DARWIN_LAUNCH_MAX_TICKET_LIFETIME_MS = 30_000;
const DARWIN_LAUNCH_MAX_CLOCK_SKEW_MS = 2_000;
const DARWIN_LAUNCH_MAX_PATH_BYTES = 768;
const DARWIN_LAUNCH_MAX_PATH_DEPTH = 20;
const DARWIN_LAUNCH_MAX_FDS = 8;
const DARWIN_LAUNCH_MAX_TICKET_BYTES = 96 * 1024;

const DARWIN_LAUNCH_ROLES = Object.freeze([
  "issuer_peer",
  "active_device_worker",
  "cleanup_only_worker",
  "safety_supervisor",
]);
const ROLE_SET = new Set(DARWIN_LAUNCH_ROLES);
const DARWIN_LAUNCH_ENV_ALLOWLIST = Object.freeze([]);
const ROLE_PROFILES = Object.freeze({
  issuer_peer: Object.freeze({
    target_principal_id: "principal:grant-issuer",
    authorizer_principal_id: "principal:operator-control-plane",
    supplementary_group_purposes: Object.freeze(["ipc_transport"]),
    fd_purposes: Object.freeze(["grant_signer", "ipc_channel"]),
  }),
  active_device_worker: Object.freeze({
    target_principal_id: "principal:active-device-worker",
    authorizer_principal_id: "principal:operator-control-plane",
    supplementary_group_purposes: Object.freeze(["active_device_access", "ipc_transport"]),
    fd_purposes: Object.freeze([
      "device_handle", "ipc_channel", "lease_journal", "receipt_signer",
    ]),
  }),
  cleanup_only_worker: Object.freeze({
    target_principal_id: "principal:cleanup-worker",
    authorizer_principal_id: "principal:safety-supervisor",
    supplementary_group_purposes: Object.freeze(["cleanup_device_access"]),
    fd_purposes: Object.freeze([
      "cleanup_device_handle", "cleanup_journal", "recovery_signer", "snapshot_materialization",
    ]),
  }),
  safety_supervisor: Object.freeze({
    target_principal_id: "principal:safety-supervisor",
    authorizer_principal_id: "principal:operator-control-plane",
    supplementary_group_purposes: Object.freeze([]),
    fd_purposes: Object.freeze(["cleanup_journal", "cleanup_root", "safety_control"]),
  }),
});

const PLAN_FIELDS = Object.freeze([
  "version",
  "plan_id",
  "role",
  "bundle_id",
  "launcher_principal_id",
  "authorizer_principal_id",
  "target_principal_id",
  "execution_method",
  "shell_allowed",
  "path_lookup_allowed",
  "working_directory",
  "executable_path",
  "entrypoint_path",
  "config_manifest_path",
  "argv",
  "environment_policy",
  "environment",
  "stdio_policy",
  "fd_enumeration_scheme",
  "fd_close_policy",
  "all_unlisted_file_descriptors_closed",
  "allowed_file_descriptors",
  "principal_matrix",
  "real_uid",
  "effective_uid",
  "saved_uid",
  "real_gid",
  "effective_gid",
  "saved_gid",
]);
const PRINCIPAL_MATRIX_ENTRY_FIELDS = Object.freeze([
  "role", "principal_id", "uid", "gid", "supplementary_groups",
]);
const GROUP_FIELDS = Object.freeze(["purpose", "gid"]);
const FD_FIELDS = Object.freeze([
  "fd",
  "purpose",
  "capability_digest",
  "owner_principal_id",
  "one_shot",
  "inherited_across_exec",
]);
const LAUNCH_BUNDLE_FIELDS = Object.freeze([
  "bundle_immutability_scheme",
  "bundle_immutability_evidence_digest",
  "bundle_immutability_complete",
  "bundle_manifest_digest",
  "entrypoint_digest",
  "config_manifest_digest",
]);
const WORKER_BUNDLE_PROJECTION_FIELDS = Object.freeze([
  "version",
  "enrollment_digest",
  "bundle_id",
  "role",
  "manifest_digest",
  "native_addon_set_digest",
  "runtime_identity_digest",
  "reservation_receipt_digest",
  "live_snapshot_digest",
  "launch_attestation_bundle_fields",
  "assurance",
  "production_ready",
]);
const NATIVE_EVIDENCE_FIELDS = Object.freeze([
  "version",
  "platform",
  "architecture",
  "plan_digest",
  "worker_bundle_projection_digest",
  "native_resolver_implementation_digest",
  "native_launcher_binary_digest",
  "native_launcher_code_signing_scheme",
  "native_launcher_code_signing_identity_digest",
  "native_launcher_code_signing_complete",
  "working_root_path_digest",
  "executable_path_digest",
  "entrypoint_path_digest",
  "config_manifest_path_digest",
  "working_directory_identity_digest",
  "root_owner_uid",
  "root_owner_gid",
  "root_mode",
  "root_nlink",
  "root_directory_identity_digest",
  "mount_identity_digest",
  "filesystem_identity_digest",
  "immutable_flags_digest",
  "openat_fstatat_walk_digest",
  "all_path_components_openat_verified",
  "all_bundle_objects_root_owned",
  "all_bundle_objects_immutable",
  "entrypoint_content_digest",
  "config_manifest_content_digest",
  "native_addon_set_digest",
  "runtime_identity_digest",
  "static_code_identity_digest",
  "static_code_identity_complete",
  "argv_digest",
  "environment_digest",
  "allowed_fd_set_digest",
  "fd_enumeration_digest",
  "all_unlisted_fds_closed",
  "stdio_reopened_dev_null",
  "real_uid",
  "effective_uid",
  "saved_uid",
  "real_gid",
  "effective_gid",
  "saved_gid",
  "supplementary_groups",
  "credential_drop_readback_digest",
  "credential_drop_complete",
  "snapshot_complete",
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
const TICKET_PAYLOAD_FIELDS = Object.freeze([
  "version",
  "ticket_id",
  "role",
  "bundle_id",
  "attestation_assurance",
  "production_attested",
  "production_ready",
  "separate_identity_authorized",
  "hardware_authorized",
  "worker_bundle_enrollment_digest",
  "worker_bundle_projection_digest",
  "worker_bundle_manifest_digest",
  "worker_bundle_reservation_receipt_digest",
  "worker_bundle_live_snapshot_digest",
  "launch_plan",
  "launch_plan_digest",
  "expected_native_evidence_digest",
  ...AUTHORITY_STATE_FIELDS,
  "authority_state_digest",
  "issued_at",
  "expires_at",
  "nonce",
]);
const AUTHENTICATION_FIELDS = Object.freeze([
  "scheme",
  "key_usage",
  "authority_key_id",
  "authority_public_key_digest",
  "signed_payload_digest",
  "signature",
]);
const SIGNED_TICKET_FIELDS = Object.freeze([
  "version", "kind", "domain", "payload", "payload_digest", "authentication", "ticket_digest",
]);
const CURRENT_AUTHORITY_FIELDS = Object.freeze([
  "version",
  "trusted",
  "revoked",
  ...AUTHORITY_STATE_FIELDS,
  "authority_state_digest",
  "authority_public_key",
  "current_ticket_digest",
  "current_launch_plan_digest",
  "current_worker_bundle_projection_digest",
  "current_native_evidence_digest",
  "trusted_now",
]);
const LIVE_SNAPSHOT_FIELDS = Object.freeze([
  "version",
  "ticket_digest",
  "native_evidence",
  "native_evidence_digest",
  "snapshot_digest",
]);

const objectFreeze = Object.freeze;
const objectDefineProperty = Object.defineProperty;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectIsFrozen = Object.isFrozen;
const objectPrototype = Object.prototype;
const objectEntries = Object.entries;
const objectIs = Object.is;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const utilIsKeyObject = utilTypes.isKeyObject;
const utilIsPromise = utilTypes.isPromise;
const utilIsProxy = utilTypes.isProxy;
const arrayIsArray = Array.isArray;
const arrayIncludes = Array.prototype.includes;
const arrayIndexOf = Array.prototype.indexOf;
const arraySort = Array.prototype.sort;
const ArrayCtor = Array;
const DateCtor = Date;
const ErrorCtor = Error;
const MapCtor = Map;
const SetCtor = Set;
const StringCtor = String;
const numberIsFinite = Number.isFinite;
const numberIsSafeInteger = Number.isSafeInteger;
const numberMaxSafeInteger = Number.MAX_SAFE_INTEGER;
const jsonStringify = JSON.stringify;
const dateParse = Date.parse;
const dateToISOString = Date.prototype.toISOString;
const bufferByteLength = Buffer.byteLength;
const bufferCompare = Buffer.compare;
const bufferFrom = Buffer.from;
const bufferToString = Buffer.prototype.toString;
const regexpTest = RegExp.prototype.test;
const stringSplit = String.prototype.split;
const stringSlice = String.prototype.slice;
const stringEndsWith = String.prototype.endsWith;
const stringIncludes = String.prototype.includes;
const stringStartsWith = String.prototype.startsWith;
const mapGet = Map.prototype.get;
const mapHas = Map.prototype.has;
const mapSet = Map.prototype.set;
const setAdd = Set.prototype.add;
const setHas = Set.prototype.has;
const setSize = objectGetOwnPropertyDescriptor(Set.prototype, "size").get;
const weakMapGet = WeakMap.prototype.get;
const weakMapHas = WeakMap.prototype.has;
const weakMapSet = WeakMap.prototype.set;
const weakSetAdd = WeakSet.prototype.add;
const weakSetDelete = WeakSet.prototype.delete;
const weakSetHas = WeakSet.prototype.has;
const cryptoCreateHash = crypto.createHash;
const cryptoCreatePublicKey = crypto.createPublicKey;
const cryptoSign = crypto.sign;
const cryptoVerify = crypto.verify;
const keyObjectTypeGet = objectGetOwnPropertyDescriptor(
  crypto.KeyObject.prototype,
  "type",
).get;
const hashPrototype = objectGetPrototypeOf(reflectApply(cryptoCreateHash, crypto, ["sha256"]));
const hashUpdate = objectGetOwnPropertyDescriptor(hashPrototype, "update").value;
const hashDigest = objectGetOwnPropertyDescriptor(hashPrototype, "digest").value;

const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const PATH_COMPONENT_PATTERN = /^[A-Za-z0-9._@+-]{1,128}$/u;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,128}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;

const SIGNER_PORTS = new WeakSet();
const SIGNER_PRIVATE = new WeakMap();
const AUTHORITY_PORTS = new WeakSet();
const AUTHORITY_PRIVATE = new WeakMap();
const NATIVE_RESOLVER_PORTS = new WeakSet();
const NATIVE_RESOLVER_PRIVATE = new WeakMap();
const REPLAY_PORTS = new WeakSet();
const REPLAY_PRIVATE = new WeakMap();
const ACTIVE_CALLBACKS = new WeakSet();
const VERIFIED_PLANS = new WeakSet();
const VERIFIED_PLAN_PRIVATE = new WeakMap();
const VERIFIED_NATIVE_FIXTURE_CONSISTENCY_RESULTS = new WeakSet();

let asymmetricKeyTypeGet = null;
let publicKeyExport = null;

const PRODUCTION_BLOCKERS = Object.freeze([
  "native_launcher_executor_source_not_linked",
  "native_launcher_binary_signature_not_qualified",
  "root_owned_immutable_install_not_qualified",
  "native_openat_fstatat_fd_hil_missing",
  "credential_drop_readback_hil_missing",
  "negative_principal_matrix_hil_missing",
  "verified_bundle_brand_bridge_packaging_missing",
]);
const NATIVE_FIXTURE_CONSISTENCY_PRODUCTION_BLOCKERS = Object.freeze([
  "native_launcher_executor_source_not_linked",
  "native_launcher_binary_signature_not_qualified",
  "root_owned_immutable_install_not_qualified",
  "native_openat_fstatat_fd_hil_missing",
  "credential_drop_readback_hil_missing",
  "negative_principal_matrix_hil_missing",
  "verified_bundle_brand_bridge_packaging_missing",
  "adhoc_native_signature_not_production_qualified",
  "real_credential_drop_readback_hil_missing",
  "capability_fd_projection_not_linked_into_fixture",
  "privileged_launch_wire_authority_verifier_not_integrated",
  "privileged_launch_provenance_persistence_not_integrated",
  "standalone_native_dispatch_custodian_prebuild_missing",
  "node_fixture_adapter_argv_not_executor_contract",
  "production_executor_not_linked",
  "fixture_mode_execve_disabled",
  "root_owned_immutable_ancestry_hil_missing",
  "darwin_fd_bound_exec_unavailable",
  "native_launcher_mapped_process_image_identity_unbound",
  "native_fixture_record_provenance_unattested",
  "writable_fixture_bracketing_not_production_immutability",
]);

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object"
      || reflectApply(utilIsProxy, utilTypes, [value])
      || arrayIsArray(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== objectPrototype && prototype !== null) return false;
  const keys = reflectOwnKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (typeof key !== "string") return false;
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true) {
      return false;
    }
  }
  return true;
}

function assertExactDataObject(value, label, fields) {
  if (!isPlainDataObject(value)) throw new Error(`${label} must be a plain own-data object`);
  const keys = reflectOwnKeys(value);
  if (keys.length !== fields.length) throw new Error(`${label} fields are not exact`);
  const expected = new SetCtor();
  for (let index = 0; index < fields.length; index += 1) {
    reflectApply(setAdd, expected, [fields[index]]);
  }
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (!reflectApply(setHas, expected, [key])) throw new Error(`${label} fields are not exact`);
  }
  return value;
}

function ownDataValue(value, field, label) {
  const descriptor = objectGetOwnPropertyDescriptor(value, field);
  if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true) {
    throw new Error(`${label}.${field} must be an enumerable own data field`);
  }
  return descriptor.value;
}

function denseArrayValues(value, label, minimum, maximum) {
  if (value == null || typeof value !== "object"
      || reflectApply(utilIsProxy, utilTypes, [value])
      || !arrayIsArray(value)) throw new Error(`${label} must be a dense non-Proxy array`);
  const lengthDescriptor = objectGetOwnPropertyDescriptor(value, "length");
  if (lengthDescriptor == null || !("value" in lengthDescriptor)
      || !reflectApply(numberIsSafeInteger, Number, [lengthDescriptor.value])
      || lengthDescriptor.value < minimum || lengthDescriptor.value > maximum) {
    throw new Error(`${label} is outside its fixed count bound`);
  }
  const length = lengthDescriptor.value;
  const keys = reflectOwnKeys(value);
  if (keys.length !== length + 1) throw new Error(`${label} must not have holes or extra fields`);
  const result = new ArrayCtor(length);
  for (let index = 0; index < length; index += 1) {
    const descriptor = objectGetOwnPropertyDescriptor(value, StringCtor(index));
    if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new Error(`${label} must contain enumerable own data entries only`);
    }
    result[index] = descriptor.value;
  }
  return result;
}

function compareStrings(left, right) {
  return bufferCompare(bufferFrom(left, "utf8"), bufferFrom(right, "utf8"));
}

function safeCanonicalJson(value) {
  function encode(candidate) {
    if (candidate === null) return "null";
    if (candidate === true) return "true";
    if (candidate === false) return "false";
    if (typeof candidate === "string") return reflectApply(jsonStringify, JSON, [candidate]);
    if (typeof candidate === "number") {
      if (!reflectApply(numberIsSafeInteger, Number, [candidate])
          || reflectApply(objectIs, Object, [candidate, -0])) {
        throw new Error("canonical launcher evidence contains an invalid number");
      }
      return `${candidate}`;
    }
    if (candidate == null || typeof candidate !== "object"
        || reflectApply(utilIsProxy, utilTypes, [candidate])) {
      throw new Error("canonical launcher evidence contains an unsupported value");
    }
    if (arrayIsArray(candidate)) {
      const values = denseArrayValues(candidate, "canonical launcher array", 0, 1024);
      let result = "[";
      for (let index = 0; index < values.length; index += 1) {
        if (index > 0) result += ",";
        result += encode(values[index]);
      }
      return `${result}]`;
    }
    if (!isPlainDataObject(candidate)) throw new Error("canonical launcher evidence is not plain data");
    const keys = reflectOwnKeys(candidate);
    reflectApply(arraySort, keys, [compareStrings]);
    let result = "{";
    for (let index = 0; index < keys.length; index += 1) {
      if (index > 0) result += ",";
      const key = keys[index];
      result += `${reflectApply(jsonStringify, JSON, [key])}:${encode(
        ownDataValue(candidate, key, "canonical launcher evidence"),
      )}`;
    }
    return `${result}}`;
  }
  return encode(value);
}

function safeHash(value) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [safeCanonicalJson(value), "utf8"]);
  return reflectApply(hashDigest, hash, ["hex"]);
}

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || objectIsFrozen(value)) return value;
  if (arrayIsArray(value)) {
    const children = denseArrayValues(value, "internal launcher array", 0, 1024);
    for (let index = 0; index < children.length; index += 1) deepFreeze(children[index]);
    return objectFreeze(value);
  }
  if (!isPlainDataObject(value)) return value;
  const keys = reflectOwnKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    deepFreeze(ownDataValue(value, keys[index], "internal launcher object"));
  }
  return objectFreeze(value);
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !reflectApply(regexpTest, HASH_PATTERN, [value])) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !reflectApply(regexpTest, IDENTIFIER_PATTERN, [value])) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertToken(value, label, prefix = null) {
  if (typeof value !== "string" || !reflectApply(regexpTest, TOKEN_PATTERN, [value])
      || (prefix != null && !reflectApply(stringStartsWith, value, [`${prefix}:`]))) {
    throw new Error(`${label} must be a bounded opaque token`);
  }
  return value;
}

function assertInteger(value, label, minimum, maximum = numberMaxSafeInteger) {
  if (!reflectApply(numberIsSafeInteger, Number, [value])
      || value < minimum || value > maximum) {
    throw new Error(`${label} is outside its fixed integer bound`);
  }
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string") throw new Error(`${label} must be a canonical timestamp`);
  const milliseconds = reflectApply(dateParse, Date, [value]);
  if (!reflectApply(numberIsFinite, Number, [milliseconds])
      || reflectApply(dateToISOString, new DateCtor(milliseconds), []) !== value) {
    throw new Error(`${label} must be a canonical ISO-8601 UTC timestamp`);
  }
  return value;
}

function assertNonce(value, label) {
  if (typeof value !== "string" || !reflectApply(regexpTest, NONCE_PATTERN, [value])) {
    throw new Error(`${label} must be a canonical strong nonce`);
  }
  const bytes = bufferFrom(value, "base64url");
  if (bytes.length < 16 || reflectApply(bufferToString, bytes, ["base64url"]) !== value) {
    throw new Error(`${label} must use canonical base64url encoding`);
  }
  return value;
}

function assertSignature(value, label) {
  if (typeof value !== "string" || !reflectApply(regexpTest, SIGNATURE_PATTERN, [value])) {
    throw new Error(`${label} must be a canonical Ed25519 signature`);
  }
  const bytes = bufferFrom(value, "base64url");
  if (bytes.length !== 64 || reflectApply(bufferToString, bytes, ["base64url"]) !== value) {
    throw new Error(`${label} must use canonical Ed25519 base64url encoding`);
  }
  return value;
}

function findPrototypeDescriptor(value, property) {
  let prototype = objectGetPrototypeOf(value);
  while (prototype != null && prototype !== objectPrototype) {
    const descriptor = objectGetOwnPropertyDescriptor(prototype, property);
    if (descriptor != null) return descriptor;
    prototype = objectGetPrototypeOf(prototype);
  }
  return null;
}

function assertEd25519Key(key, kind, label) {
  if (key == null || typeof key !== "object"
      || reflectApply(utilIsProxy, utilTypes, [key])
      || !reflectApply(utilIsKeyObject, utilTypes, [key])) {
    throw new Error(`${label} must be an Ed25519 ${kind} KeyObject`);
  }
  if (asymmetricKeyTypeGet == null) {
    const descriptor = findPrototypeDescriptor(key, "asymmetricKeyType");
    if (descriptor == null || typeof descriptor.get !== "function"
        || reflectApply(utilIsProxy, utilTypes, [descriptor.get])) {
      throw new Error(`${label} must expose a native asymmetric-key type`);
    }
    asymmetricKeyTypeGet = descriptor.get;
  }
  if (reflectApply(keyObjectTypeGet, key, []) !== kind
      || reflectApply(asymmetricKeyTypeGet, key, []) !== "ed25519") {
    throw new Error(`${label} must be an Ed25519 ${kind} KeyObject`);
  }
  return key;
}

function publicKeyDigest(keyInput) {
  const key = reflectApply(keyObjectTypeGet, keyInput, []) === "private"
    ? reflectApply(cryptoCreatePublicKey, crypto, [keyInput])
    : keyInput;
  assertEd25519Key(key, "public", "darwin_launcher_authority_public_key");
  if (publicKeyExport == null) {
    const descriptor = findPrototypeDescriptor(key, "export");
    if (descriptor == null || typeof descriptor.value !== "function"
        || reflectApply(utilIsProxy, utilTypes, [descriptor.value])) {
      throw new Error("darwin launcher authority public-key export is not native data");
    }
    publicKeyExport = descriptor.value;
  }
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [reflectApply(publicKeyExport, key, [{
    type: "spki",
    format: "der",
  }])]);
  return reflectApply(hashDigest, hash, ["hex"]);
}

function assertAbsolutePath(value, label) {
  if (typeof value !== "string" || value.length < 2 || value[0] !== "/"
      || reflectApply(stringEndsWith, value, ["/"])
      || reflectApply(stringIncludes, value, ["\\"])
      || reflectApply(stringIncludes, value, ["//"])
      || bufferByteLength(value, "utf8") > DARWIN_LAUNCH_MAX_PATH_BYTES) {
    throw new Error(`${label} must be a bounded canonical absolute POSIX path`);
  }
  const components = reflectApply(stringSplit, reflectApply(stringSlice, value, [1]), ["/"]);
  if (components.length < 1 || components.length > DARWIN_LAUNCH_MAX_PATH_DEPTH) {
    throw new Error(`${label} exceeds the path-depth bound`);
  }
  for (let index = 0; index < components.length; index += 1) {
    const component = components[index];
    if (component === "." || component === ".."
        || !reflectApply(regexpTest, PATH_COMPONENT_PATTERN, [component])) {
      throw new Error(`${label} contains a non-canonical path component`);
    }
  }
  return value;
}

function assertPathBelowRoot(pathValue, root, label) {
  const path = assertAbsolutePath(pathValue, label);
  if (!reflectApply(stringStartsWith, path, [`${root}/`])) {
    throw new Error(`${label} must be strictly below the working root`);
  }
  return path;
}

function normalizeGroups(input, label, expectedPurposes) {
  const values = denseArrayValues(input, label, expectedPurposes.length, expectedPurposes.length);
  const groups = [];
  const gids = new SetCtor();
  for (let index = 0; index < values.length; index += 1) {
    const itemLabel = `${label}[${index}]`;
    assertExactDataObject(values[index], itemLabel, GROUP_FIELDS);
    const purpose = assertIdentifier(ownDataValue(values[index], "purpose", itemLabel), `${itemLabel}.purpose`);
    const gid = assertInteger(ownDataValue(values[index], "gid", itemLabel), `${itemLabel}.gid`, 1, 2 ** 32 - 2);
    if (purpose !== expectedPurposes[index] || reflectApply(setHas, gids, [gid])) {
      throw new Error(`${label} does not match the closed role group profile`);
    }
    reflectApply(setAdd, gids, [gid]);
    groups[groups.length] = deepFreeze({ purpose, gid });
  }
  return deepFreeze(groups);
}

function normalizePrincipalMatrix(input) {
  const values = denseArrayValues(
    input,
    "darwin_launch_plan.principal_matrix",
    DARWIN_LAUNCH_ROLES.length,
    DARWIN_LAUNCH_ROLES.length,
  );
  const result = [];
  const uids = new SetCtor();
  const primaryGids = new SetCtor();
  const groupPurposeGids = new MapCtor();
  for (let index = 0; index < values.length; index += 1) {
    const label = `darwin_launch_plan.principal_matrix[${index}]`;
    assertExactDataObject(values[index], label, PRINCIPAL_MATRIX_ENTRY_FIELDS);
    const role = ownDataValue(values[index], "role", label);
    if (role !== DARWIN_LAUNCH_ROLES[index]) throw new Error("principal matrix roles are not exact");
    const profile = ROLE_PROFILES[role];
    const principalId = assertToken(
      ownDataValue(values[index], "principal_id", label),
      `${label}.principal_id`,
      "principal",
    );
    if (principalId !== profile.target_principal_id) throw new Error("principal matrix identity is invalid");
    const uid = assertInteger(ownDataValue(values[index], "uid", label), `${label}.uid`, 1, 2 ** 32 - 2);
    const gid = assertInteger(ownDataValue(values[index], "gid", label), `${label}.gid`, 1, 2 ** 32 - 2);
    if (reflectApply(setHas, uids, [uid]) || reflectApply(setHas, primaryGids, [gid])) {
      throw new Error("launcher role UID/GID identities must be distinct");
    }
    reflectApply(setAdd, uids, [uid]);
    reflectApply(setAdd, primaryGids, [gid]);
    const groups = normalizeGroups(
      ownDataValue(values[index], "supplementary_groups", label),
      `${label}.supplementary_groups`,
      profile.supplementary_group_purposes,
    );
    for (let groupIndex = 0; groupIndex < groups.length; groupIndex += 1) {
      const group = groups[groupIndex];
      if (reflectApply(mapHas, groupPurposeGids, [group.purpose])
          && reflectApply(mapGet, groupPurposeGids, [group.purpose]) !== group.gid) {
        throw new Error("shared launcher group purpose has inconsistent GID identity");
      }
      reflectApply(mapSet, groupPurposeGids, [group.purpose, group.gid]);
    }
    result[result.length] = deepFreeze({
      role,
      principal_id: principalId,
      uid,
      gid,
      supplementary_groups: groups,
    });
  }
  if (!reflectApply(mapHas, groupPurposeGids, ["ipc_transport"])
      || !reflectApply(mapHas, groupPurposeGids, ["active_device_access"])
      || !reflectApply(mapHas, groupPurposeGids, ["cleanup_device_access"])) {
    throw new Error("launcher IPC, active-device, and cleanup-device groups must be distinct");
  }
  const custodyGids = [
    reflectApply(mapGet, groupPurposeGids, ["ipc_transport"]),
    reflectApply(mapGet, groupPurposeGids, ["active_device_access"]),
    reflectApply(mapGet, groupPurposeGids, ["cleanup_device_access"]),
  ];
  const distinctCustodyGids = new SetCtor();
  for (let index = 0; index < custodyGids.length; index += 1) {
    reflectApply(setAdd, distinctCustodyGids, [custodyGids[index]]);
  }
  if (reflectApply(setSize, distinctCustodyGids, []) !== custodyGids.length) {
    throw new Error("launcher IPC, active-device, and cleanup-device groups must be distinct");
  }
  for (let index = 0; index < custodyGids.length; index += 1) {
    const gid = custodyGids[index];
    if (reflectApply(setHas, primaryGids, [gid])) {
      throw new Error("supplementary launcher groups cannot alias primary groups");
    }
  }
  return deepFreeze(result);
}

function normalizeFileDescriptors(input, role, targetPrincipalId) {
  const expectedPurposes = ROLE_PROFILES[role].fd_purposes;
  const values = denseArrayValues(
    input,
    "darwin_launch_plan.allowed_file_descriptors",
    expectedPurposes.length,
    expectedPurposes.length,
  );
  const descriptors = [];
  const purposes = new SetCtor();
  const capabilities = new SetCtor();
  let priorFd = 2;
  for (let index = 0; index < values.length; index += 1) {
    const label = `darwin_launch_plan.allowed_file_descriptors[${index}]`;
    assertExactDataObject(values[index], label, FD_FIELDS);
    const fd = assertInteger(ownDataValue(values[index], "fd", label), `${label}.fd`, 3, 1_048_575);
    const purpose = assertIdentifier(ownDataValue(values[index], "purpose", label), `${label}.purpose`);
    const capabilityDigest = assertDigest(
      ownDataValue(values[index], "capability_digest", label),
      `${label}.capability_digest`,
    );
    const ownerPrincipalId = assertToken(
      ownDataValue(values[index], "owner_principal_id", label),
      `${label}.owner_principal_id`,
      "principal",
    );
    if (fd <= priorFd || reflectApply(setHas, purposes, [purpose])
        || reflectApply(setHas, capabilities, [capabilityDigest])
        || ownerPrincipalId !== targetPrincipalId
        || ownDataValue(values[index], "one_shot", label) !== true
        || ownDataValue(values[index], "inherited_across_exec", label) !== true) {
      throw new Error("allowed descriptor set is not exact, unique, one-shot, and role-owned");
    }
    priorFd = fd;
    reflectApply(setAdd, purposes, [purpose]);
    reflectApply(setAdd, capabilities, [capabilityDigest]);
    descriptors[descriptors.length] = deepFreeze({
      fd,
      purpose,
      capability_digest: capabilityDigest,
      owner_principal_id: ownerPrincipalId,
      one_shot: true,
      inherited_across_exec: true,
    });
  }
  if (reflectApply(setSize, purposes, []) !== expectedPurposes.length) {
    throw new Error("role descriptor purpose set is incomplete");
  }
  for (let index = 0; index < expectedPurposes.length; index += 1) {
    const purpose = expectedPurposes[index];
    if (!reflectApply(setHas, purposes, [purpose])) {
      throw new Error("role descriptor purpose set is invalid");
    }
  }
  return deepFreeze(descriptors);
}

function normalizeDarwinLaunchPlan(input) {
  const label = "darwin_launch_plan";
  assertExactDataObject(input, label, PLAN_FIELDS);
  if (ownDataValue(input, "version", label) !== DARWIN_LAUNCHER_VERSION) {
    throw new Error(`${label}.version is invalid`);
  }
  const role = ownDataValue(input, "role", label);
  if (!reflectApply(setHas, ROLE_SET, [role])) throw new Error(`${label}.role is invalid`);
  const profile = ROLE_PROFILES[role];
  const targetPrincipalId = assertToken(
    ownDataValue(input, "target_principal_id", label),
    `${label}.target_principal_id`,
    "principal",
  );
  const authorizerPrincipalId = assertToken(
    ownDataValue(input, "authorizer_principal_id", label),
    `${label}.authorizer_principal_id`,
    "principal",
  );
  if (targetPrincipalId !== profile.target_principal_id
      || authorizerPrincipalId !== profile.authorizer_principal_id
      || ownDataValue(input, "launcher_principal_id", label) !== "principal:privileged-launcher") {
    throw new Error(`${label} role principal custody is invalid`);
  }
  if (ownDataValue(input, "execution_method", label) !== "darwin_execve_absolute_no_shell_v1"
      || ownDataValue(input, "shell_allowed", label) !== false
      || ownDataValue(input, "path_lookup_allowed", label) !== false) {
    throw new Error(`${label} must use absolute execve without shell or PATH lookup`);
  }
  const workingDirectory = assertAbsolutePath(
    ownDataValue(input, "working_directory", label),
    `${label}.working_directory`,
  );
  const executablePath = assertPathBelowRoot(
    ownDataValue(input, "executable_path", label),
    workingDirectory,
    `${label}.executable_path`,
  );
  const entrypointPath = assertPathBelowRoot(
    ownDataValue(input, "entrypoint_path", label),
    workingDirectory,
    `${label}.entrypoint_path`,
  );
  const configManifestPath = assertPathBelowRoot(
    ownDataValue(input, "config_manifest_path", label),
    workingDirectory,
    `${label}.config_manifest_path`,
  );
  const distinctPaths = new SetCtor();
  reflectApply(setAdd, distinctPaths, [executablePath]);
  reflectApply(setAdd, distinctPaths, [entrypointPath]);
  reflectApply(setAdd, distinctPaths, [configManifestPath]);
  if (reflectApply(setSize, distinctPaths, []) !== 3) {
    throw new Error(`${label} executable, entrypoint, and config paths must be distinct`);
  }
  const argv = denseArrayValues(ownDataValue(input, "argv", label), `${label}.argv`, 6, 6);
  const expectedArgv = [
    executablePath, entrypointPath, "--role", role, "--config", configManifestPath,
  ];
  for (let index = 0; index < expectedArgv.length; index += 1) {
    if (argv[index] !== expectedArgv[index]) throw new Error(`${label}.argv is not the closed worker argv`);
  }
  if (ownDataValue(input, "environment_policy", label) !== "empty_environment_v1") {
    throw new Error(`${label}.environment_policy is invalid`);
  }
  const environment = denseArrayValues(
    ownDataValue(input, "environment", label),
    `${label}.environment`,
    0,
    DARWIN_LAUNCH_ENV_ALLOWLIST.length,
  );
  if (environment.length !== 0) throw new Error(`${label}.environment must be empty`);
  if (ownDataValue(input, "stdio_policy", label) !== "dev_null_reopen_v1"
      || ownDataValue(input, "fd_enumeration_scheme", label)
        !== "darwin_proc_pidfdinfo_complete_v1"
      || ownDataValue(input, "fd_close_policy", label)
        !== "close_all_then_dup_enrolled_one_shot_v1"
      || ownDataValue(input, "all_unlisted_file_descriptors_closed", label) !== true) {
    throw new Error(`${label} descriptor closure policy is invalid`);
  }
  const principalMatrix = normalizePrincipalMatrix(ownDataValue(input, "principal_matrix", label));
  const selectedPrincipal = principalMatrix[reflectApply(arrayIndexOf, DARWIN_LAUNCH_ROLES, [role])];
  const realUid = assertInteger(ownDataValue(input, "real_uid", label), `${label}.real_uid`, 1, 2 ** 32 - 2);
  const effectiveUid = assertInteger(
    ownDataValue(input, "effective_uid", label), `${label}.effective_uid`, 1, 2 ** 32 - 2,
  );
  const savedUid = assertInteger(ownDataValue(input, "saved_uid", label), `${label}.saved_uid`, 1, 2 ** 32 - 2);
  const realGid = assertInteger(ownDataValue(input, "real_gid", label), `${label}.real_gid`, 1, 2 ** 32 - 2);
  const effectiveGid = assertInteger(
    ownDataValue(input, "effective_gid", label), `${label}.effective_gid`, 1, 2 ** 32 - 2,
  );
  const savedGid = assertInteger(ownDataValue(input, "saved_gid", label), `${label}.saved_gid`, 1, 2 ** 32 - 2);
  if (realUid !== effectiveUid || realUid !== savedUid || realUid !== selectedPrincipal.uid
      || realGid !== effectiveGid || realGid !== savedGid || realGid !== selectedPrincipal.gid) {
    throw new Error(`${label} real/effective/saved credentials do not match the selected role`);
  }
  const allowedFds = normalizeFileDescriptors(
    ownDataValue(input, "allowed_file_descriptors", label),
    role,
    targetPrincipalId,
  );
  const normalizedArgv = [];
  for (let index = 0; index < expectedArgv.length; index += 1) {
    normalizedArgv[index] = expectedArgv[index];
  }
  return deepFreeze({
    version: DARWIN_LAUNCHER_VERSION,
    plan_id: assertToken(ownDataValue(input, "plan_id", label), `${label}.plan_id`, "launch-plan"),
    role,
    bundle_id: assertToken(ownDataValue(input, "bundle_id", label), `${label}.bundle_id`, "worker-bundle"),
    launcher_principal_id: "principal:privileged-launcher",
    authorizer_principal_id: authorizerPrincipalId,
    target_principal_id: targetPrincipalId,
    execution_method: "darwin_execve_absolute_no_shell_v1",
    shell_allowed: false,
    path_lookup_allowed: false,
    working_directory: workingDirectory,
    executable_path: executablePath,
    entrypoint_path: entrypointPath,
    config_manifest_path: configManifestPath,
    argv: deepFreeze(normalizedArgv),
    environment_policy: "empty_environment_v1",
    environment: deepFreeze([]),
    stdio_policy: "dev_null_reopen_v1",
    fd_enumeration_scheme: "darwin_proc_pidfdinfo_complete_v1",
    fd_close_policy: "close_all_then_dup_enrolled_one_shot_v1",
    all_unlisted_file_descriptors_closed: true,
    allowed_file_descriptors: allowedFds,
    principal_matrix: principalMatrix,
    real_uid: realUid,
    effective_uid: effectiveUid,
    saved_uid: savedUid,
    real_gid: realGid,
    effective_gid: effectiveGid,
    saved_gid: savedGid,
  });
}

function darwinLaunchPlanDigest(input) {
  const plan = normalizeDarwinLaunchPlan(input);
  return safeHash({ domain: DARWIN_LAUNCH_PLAN_DOMAIN, version: DARWIN_LAUNCHER_VERSION, plan });
}

function darwinLauncherPathDigest(purpose, pathInput) {
  const pathPurpose = assertIdentifier(purpose, "darwin_launcher_path.purpose");
  const path = assertAbsolutePath(pathInput, "darwin_launcher_path.path");
  return safeHash({
    domain: DARWIN_LAUNCH_PATH_IDENTITY_DOMAIN,
    version: DARWIN_LAUNCHER_VERSION,
    purpose: pathPurpose,
    path,
  });
}

function darwinLaunchArgvDigest(planInput) {
  const plan = normalizeDarwinLaunchPlan(planInput);
  return safeHash({ domain: DARWIN_LAUNCH_ARGV_DOMAIN, version: DARWIN_LAUNCHER_VERSION, argv: plan.argv });
}

function darwinLaunchEnvironmentDigest(planInput) {
  const plan = normalizeDarwinLaunchPlan(planInput);
  return safeHash({
    domain: DARWIN_LAUNCH_ENVIRONMENT_DOMAIN,
    version: DARWIN_LAUNCHER_VERSION,
    policy: plan.environment_policy,
    environment: plan.environment,
  });
}

function darwinLaunchFdSetDigest(planInput) {
  const plan = normalizeDarwinLaunchPlan(planInput);
  return safeHash({
    domain: DARWIN_LAUNCH_FD_SET_DOMAIN,
    version: DARWIN_LAUNCHER_VERSION,
    stdio_policy: plan.stdio_policy,
    fd_enumeration_scheme: plan.fd_enumeration_scheme,
    fd_close_policy: plan.fd_close_policy,
    allowed_file_descriptors: plan.allowed_file_descriptors,
  });
}

function credentialPlanBasis(plan) {
  const selected = plan.principal_matrix[
    reflectApply(arrayIndexOf, DARWIN_LAUNCH_ROLES, [plan.role])
  ];
  return deepFreeze({
    role: plan.role,
    launcher_principal_id: plan.launcher_principal_id,
    authorizer_principal_id: plan.authorizer_principal_id,
    target_principal_id: plan.target_principal_id,
    real_uid: plan.real_uid,
    effective_uid: plan.effective_uid,
    saved_uid: plan.saved_uid,
    real_gid: plan.real_gid,
    effective_gid: plan.effective_gid,
    saved_gid: plan.saved_gid,
    supplementary_groups: selected.supplementary_groups,
    principal_matrix: plan.principal_matrix,
  });
}

function darwinLaunchCredentialPlanDigest(planInput) {
  const plan = normalizeDarwinLaunchPlan(planInput);
  return safeHash({
    domain: DARWIN_LAUNCH_CREDENTIAL_PLAN_DOMAIN,
    version: DARWIN_LAUNCHER_VERSION,
    credential_plan: credentialPlanBasis(plan),
  });
}

function normalizeLaunchBundleFields(input, label) {
  assertExactDataObject(input, label, LAUNCH_BUNDLE_FIELDS);
  const scheme = assertIdentifier(
    ownDataValue(input, "bundle_immutability_scheme", label),
    `${label}.bundle_immutability_scheme`,
  );
  if (ownDataValue(input, "bundle_immutability_complete", label) !== true) {
    throw new Error(`${label}.bundle_immutability_complete must be true`);
  }
  return deepFreeze({
    bundle_immutability_scheme: scheme,
    bundle_immutability_evidence_digest: assertDigest(
      ownDataValue(input, "bundle_immutability_evidence_digest", label),
      `${label}.bundle_immutability_evidence_digest`,
    ),
    bundle_immutability_complete: true,
    bundle_manifest_digest: assertDigest(
      ownDataValue(input, "bundle_manifest_digest", label),
      `${label}.bundle_manifest_digest`,
    ),
    entrypoint_digest: assertDigest(
      ownDataValue(input, "entrypoint_digest", label),
      `${label}.entrypoint_digest`,
    ),
    config_manifest_digest: assertDigest(
      ownDataValue(input, "config_manifest_digest", label),
      `${label}.config_manifest_digest`,
    ),
  });
}

function normalizeVerifiedWorkerBundleProjection(input) {
  const label = "verified_worker_bundle_projection";
  assertExactDataObject(input, label, WORKER_BUNDLE_PROJECTION_FIELDS);
  if (ownDataValue(input, "version", label) !== DARWIN_LAUNCHER_VERSION
      || ownDataValue(input, "assurance", label)
        !== "signed_double_live_resolved_reserved_conformance_only"
      || ownDataValue(input, "production_ready", label) !== false) {
    throw new Error(`${label} is not an accepted conformance projection`);
  }
  const launchFields = normalizeLaunchBundleFields(
    ownDataValue(input, "launch_attestation_bundle_fields", label),
    `${label}.launch_attestation_bundle_fields`,
  );
  const manifestDigest = assertDigest(
    ownDataValue(input, "manifest_digest", label),
    `${label}.manifest_digest`,
  );
  if (manifestDigest !== launchFields.bundle_manifest_digest) {
    throw new Error(`${label} manifest identity forked`);
  }
  return deepFreeze({
    version: DARWIN_LAUNCHER_VERSION,
    enrollment_digest: assertDigest(
      ownDataValue(input, "enrollment_digest", label),
      `${label}.enrollment_digest`,
    ),
    bundle_id: assertToken(ownDataValue(input, "bundle_id", label), `${label}.bundle_id`, "worker-bundle"),
    role: ownDataValue(input, "role", label),
    manifest_digest: manifestDigest,
    native_addon_set_digest: assertDigest(
      ownDataValue(input, "native_addon_set_digest", label),
      `${label}.native_addon_set_digest`,
    ),
    runtime_identity_digest: assertDigest(
      ownDataValue(input, "runtime_identity_digest", label),
      `${label}.runtime_identity_digest`,
    ),
    reservation_receipt_digest: assertDigest(
      ownDataValue(input, "reservation_receipt_digest", label),
      `${label}.reservation_receipt_digest`,
    ),
    live_snapshot_digest: assertDigest(
      ownDataValue(input, "live_snapshot_digest", label),
      `${label}.live_snapshot_digest`,
    ),
    launch_attestation_bundle_fields: launchFields,
    assurance: "signed_double_live_resolved_reserved_conformance_only",
    production_ready: false,
  });
}

function projectActuallyVerifiedWorkerBundle(value) {
  const verified = assertVerifiedWorkerBundleEnrollment(value);
  return normalizeVerifiedWorkerBundleProjection({
    version: verified.version,
    enrollment_digest: verified.enrollment_digest,
    bundle_id: verified.bundle_id,
    role: verified.role,
    manifest_digest: verified.manifest_digest,
    native_addon_set_digest: verified.native_addon_set_digest,
    runtime_identity_digest: verified.runtime_identity_digest,
    reservation_receipt_digest: verified.reservation_receipt_digest,
    live_snapshot_digest: verified.live_snapshot_digest,
    launch_attestation_bundle_fields: verified.launch_attestation_bundle_fields,
    assurance: verified.assurance,
    production_ready: verified.production_ready,
  });
}

function darwinWorkerBundleProjectionDigest(input) {
  const projection = normalizeVerifiedWorkerBundleProjection(input);
  if (!reflectApply(setHas, ROLE_SET, [projection.role])) {
    throw new Error("verified worker bundle role is invalid");
  }
  return safeHash({
    domain: DARWIN_LAUNCH_WORKER_BUNDLE_PROJECTION_DOMAIN,
    version: DARWIN_LAUNCHER_VERSION,
    projection,
  });
}

function credentialReadbackDigest(plan) {
  const selected = plan.principal_matrix[
    reflectApply(arrayIndexOf, DARWIN_LAUNCH_ROLES, [plan.role])
  ];
  return safeHash({
    domain: DARWIN_LAUNCH_CREDENTIAL_PLAN_DOMAIN,
    version: DARWIN_LAUNCHER_VERSION,
    kind: "native_credential_drop_readback",
    real_uid: plan.real_uid,
    effective_uid: plan.effective_uid,
    saved_uid: plan.saved_uid,
    real_gid: plan.real_gid,
    effective_gid: plan.effective_gid,
    saved_gid: plan.saved_gid,
    supplementary_groups: selected.supplementary_groups,
  });
}

function darwinCredentialDropReadbackDigest(planInput) {
  return credentialReadbackDigest(normalizeDarwinLaunchPlan(planInput));
}

function normalizeDarwinNativeLaunchEvidence(input, planInput, bundleProjectionInput) {
  const label = "darwin_native_launch_evidence";
  assertExactDataObject(input, label, NATIVE_EVIDENCE_FIELDS);
  const plan = normalizeDarwinLaunchPlan(planInput);
  const projection = normalizeVerifiedWorkerBundleProjection(bundleProjectionInput);
  if (ownDataValue(input, "version", label) !== DARWIN_LAUNCHER_VERSION
      || ownDataValue(input, "platform", label) !== "darwin"
      || ownDataValue(input, "architecture", label) !== "arm64") {
    throw new Error(`${label} platform, architecture, or version is invalid`);
  }
  if (plan.role !== projection.role || plan.bundle_id !== projection.bundle_id) {
    throw new Error(`${label} plan drifted from the verified worker bundle`);
  }
  const planDigest = darwinLaunchPlanDigest(plan);
  const projectionDigest = darwinWorkerBundleProjectionDigest(projection);
  const launchFields = projection.launch_attestation_bundle_fields;
  const selected = plan.principal_matrix[
    reflectApply(arrayIndexOf, DARWIN_LAUNCH_ROLES, [plan.role])
  ];
  const groups = normalizeGroups(
    ownDataValue(input, "supplementary_groups", label),
    `${label}.supplementary_groups`,
    ROLE_PROFILES[plan.role].supplementary_group_purposes,
  );
  if (safeCanonicalJson(groups) !== safeCanonicalJson(selected.supplementary_groups)) {
    throw new Error(`${label} supplementary-group readback drifted`);
  }
  const rootMode = assertInteger(ownDataValue(input, "root_mode", label), `${label}.root_mode`, 0, 0o555);
  if ((rootMode & 0o222) !== 0 || (rootMode & 0o500) !== 0o500) {
    throw new Error(`${label}.root_mode is not immutable owner-rx`);
  }
  const nativeCodeScheme = assertIdentifier(
    ownDataValue(input, "native_launcher_code_signing_scheme", label),
    `${label}.native_launcher_code_signing_scheme`,
  );
  if (nativeCodeScheme === "none" || nativeCodeScheme === "not_applicable"
      || ownDataValue(input, "native_launcher_code_signing_complete", label) !== true
      || ownDataValue(input, "static_code_identity_complete", label) !== true
      || ownDataValue(input, "all_path_components_openat_verified", label) !== true
      || ownDataValue(input, "all_bundle_objects_root_owned", label) !== true
      || ownDataValue(input, "all_bundle_objects_immutable", label) !== true
      || ownDataValue(input, "all_unlisted_fds_closed", label) !== true
      || ownDataValue(input, "stdio_reopened_dev_null", label) !== true
      || ownDataValue(input, "credential_drop_complete", label) !== true
      || ownDataValue(input, "snapshot_complete", label) !== true) {
    throw new Error(`${label} native closure evidence is incomplete`);
  }
  const expectedDigests = {
    plan_digest: planDigest,
    worker_bundle_projection_digest: projectionDigest,
    working_root_path_digest: darwinLauncherPathDigest("working_root", plan.working_directory),
    executable_path_digest: darwinLauncherPathDigest("executable", plan.executable_path),
    entrypoint_path_digest: darwinLauncherPathDigest("entrypoint", plan.entrypoint_path),
    config_manifest_path_digest: darwinLauncherPathDigest("config_manifest", plan.config_manifest_path),
    entrypoint_content_digest: launchFields.entrypoint_digest,
    config_manifest_content_digest: launchFields.config_manifest_digest,
    native_addon_set_digest: projection.native_addon_set_digest,
    runtime_identity_digest: projection.runtime_identity_digest,
    argv_digest: darwinLaunchArgvDigest(plan),
    environment_digest: darwinLaunchEnvironmentDigest(plan),
    allowed_fd_set_digest: darwinLaunchFdSetDigest(plan),
    credential_drop_readback_digest: credentialReadbackDigest(plan),
  };
  const expectedDigestEntries = reflectApply(objectEntries, Object, [expectedDigests]);
  for (let index = 0; index < expectedDigestEntries.length; index += 1) {
    const field = expectedDigestEntries[index][0];
    const expected = expectedDigestEntries[index][1];
    const actual = assertDigest(ownDataValue(input, field, label), `${label}.${field}`);
    if (actual !== expected) throw new Error(`${label} derived identity drifted`);
  }
  const realUid = assertInteger(ownDataValue(input, "real_uid", label), `${label}.real_uid`, 1, 2 ** 32 - 2);
  const effectiveUid = assertInteger(
    ownDataValue(input, "effective_uid", label), `${label}.effective_uid`, 1, 2 ** 32 - 2,
  );
  const savedUid = assertInteger(ownDataValue(input, "saved_uid", label), `${label}.saved_uid`, 1, 2 ** 32 - 2);
  const realGid = assertInteger(ownDataValue(input, "real_gid", label), `${label}.real_gid`, 1, 2 ** 32 - 2);
  const effectiveGid = assertInteger(
    ownDataValue(input, "effective_gid", label), `${label}.effective_gid`, 1, 2 ** 32 - 2,
  );
  const savedGid = assertInteger(ownDataValue(input, "saved_gid", label), `${label}.saved_gid`, 1, 2 ** 32 - 2);
  if (realUid !== plan.real_uid || effectiveUid !== plan.effective_uid || savedUid !== plan.saved_uid
      || realGid !== plan.real_gid || effectiveGid !== plan.effective_gid || savedGid !== plan.saved_gid
      || ownDataValue(input, "root_owner_uid", label) !== 0
      || ownDataValue(input, "root_owner_gid", label) !== 0) {
    throw new Error(`${label} root ownership or credential readback drifted`);
  }
  const normalized = {
    version: DARWIN_LAUNCHER_VERSION,
    platform: "darwin",
    architecture: "arm64",
    plan_digest: planDigest,
    worker_bundle_projection_digest: projectionDigest,
    native_resolver_implementation_digest: assertDigest(
      ownDataValue(input, "native_resolver_implementation_digest", label),
      `${label}.native_resolver_implementation_digest`,
    ),
    native_launcher_binary_digest: assertDigest(
      ownDataValue(input, "native_launcher_binary_digest", label),
      `${label}.native_launcher_binary_digest`,
    ),
    native_launcher_code_signing_scheme: nativeCodeScheme,
    native_launcher_code_signing_identity_digest: assertDigest(
      ownDataValue(input, "native_launcher_code_signing_identity_digest", label),
      `${label}.native_launcher_code_signing_identity_digest`,
    ),
    native_launcher_code_signing_complete: true,
    working_root_path_digest: expectedDigests.working_root_path_digest,
    executable_path_digest: expectedDigests.executable_path_digest,
    entrypoint_path_digest: expectedDigests.entrypoint_path_digest,
    config_manifest_path_digest: expectedDigests.config_manifest_path_digest,
    working_directory_identity_digest: assertDigest(
      ownDataValue(input, "working_directory_identity_digest", label),
      `${label}.working_directory_identity_digest`,
    ),
    root_owner_uid: 0,
    root_owner_gid: 0,
    root_mode: rootMode,
    root_nlink: assertInteger(ownDataValue(input, "root_nlink", label), `${label}.root_nlink`, 2, 2 ** 32 - 2),
    root_directory_identity_digest: assertDigest(
      ownDataValue(input, "root_directory_identity_digest", label),
      `${label}.root_directory_identity_digest`,
    ),
    mount_identity_digest: assertDigest(
      ownDataValue(input, "mount_identity_digest", label), `${label}.mount_identity_digest`,
    ),
    filesystem_identity_digest: assertDigest(
      ownDataValue(input, "filesystem_identity_digest", label), `${label}.filesystem_identity_digest`,
    ),
    immutable_flags_digest: assertDigest(
      ownDataValue(input, "immutable_flags_digest", label), `${label}.immutable_flags_digest`,
    ),
    openat_fstatat_walk_digest: assertDigest(
      ownDataValue(input, "openat_fstatat_walk_digest", label), `${label}.openat_fstatat_walk_digest`,
    ),
    all_path_components_openat_verified: true,
    all_bundle_objects_root_owned: true,
    all_bundle_objects_immutable: true,
    entrypoint_content_digest: expectedDigests.entrypoint_content_digest,
    config_manifest_content_digest: expectedDigests.config_manifest_content_digest,
    native_addon_set_digest: expectedDigests.native_addon_set_digest,
    runtime_identity_digest: expectedDigests.runtime_identity_digest,
    static_code_identity_digest: assertDigest(
      ownDataValue(input, "static_code_identity_digest", label), `${label}.static_code_identity_digest`,
    ),
    static_code_identity_complete: true,
    argv_digest: expectedDigests.argv_digest,
    environment_digest: expectedDigests.environment_digest,
    allowed_fd_set_digest: expectedDigests.allowed_fd_set_digest,
    fd_enumeration_digest: assertDigest(
      ownDataValue(input, "fd_enumeration_digest", label), `${label}.fd_enumeration_digest`,
    ),
    all_unlisted_fds_closed: true,
    stdio_reopened_dev_null: true,
    real_uid: realUid,
    effective_uid: effectiveUid,
    saved_uid: savedUid,
    real_gid: realGid,
    effective_gid: effectiveGid,
    saved_gid: savedGid,
    supplementary_groups: groups,
    credential_drop_readback_digest: expectedDigests.credential_drop_readback_digest,
    credential_drop_complete: true,
    snapshot_complete: true,
  };
  const domainDigests = [
    normalized.native_resolver_implementation_digest,
    normalized.native_launcher_binary_digest,
    normalized.native_launcher_code_signing_identity_digest,
    normalized.working_directory_identity_digest,
    normalized.root_directory_identity_digest,
    normalized.mount_identity_digest,
    normalized.filesystem_identity_digest,
    normalized.immutable_flags_digest,
    normalized.openat_fstatat_walk_digest,
    normalized.static_code_identity_digest,
    normalized.fd_enumeration_digest,
  ];
  const distinctDomainDigests = new SetCtor();
  for (let index = 0; index < domainDigests.length; index += 1) {
    reflectApply(setAdd, distinctDomainDigests, [domainDigests[index]]);
  }
  if (reflectApply(setSize, distinctDomainDigests, []) !== domainDigests.length) {
    throw new Error(`${label} independent native evidence domains must have distinct digests`);
  }
  return deepFreeze(normalized);
}

function darwinNativeLaunchEvidenceDigest(evidenceInput, planInput, bundleProjectionInput) {
  const evidence = normalizeDarwinNativeLaunchEvidence(
    evidenceInput,
    planInput,
    bundleProjectionInput,
  );
  return safeHash({
    domain: DARWIN_LAUNCH_NATIVE_EVIDENCE_DOMAIN,
    version: DARWIN_LAUNCHER_VERSION,
    evidence,
  });
}

function normalizeLiveSnapshot(input, resolverId, ticket, projection) {
  const label = "darwin_native_launch_snapshot";
  assertExactDataObject(input, label, LIVE_SNAPSHOT_FIELDS);
  if (ownDataValue(input, "version", label) !== DARWIN_LAUNCHER_VERSION
      || ownDataValue(input, "ticket_digest", label) !== ticket.ticket_digest) {
    throw new Error(`${label} version or ticket binding is invalid`);
  }
  const evidence = normalizeDarwinNativeLaunchEvidence(
    ownDataValue(input, "native_evidence", label),
    ticket.payload.launch_plan,
    projection,
  );
  const evidenceDigest = darwinNativeLaunchEvidenceDigest(
    evidence,
    ticket.payload.launch_plan,
    projection,
  );
  if (ownDataValue(input, "native_evidence_digest", label) !== evidenceDigest
      || evidenceDigest !== ticket.payload.expected_native_evidence_digest) {
    throw new Error(`${label} evidence digest is invalid`);
  }
  const basis = deepFreeze({
    version: DARWIN_LAUNCHER_VERSION,
    ticket_digest: ticket.ticket_digest,
    native_evidence: evidence,
    native_evidence_digest: evidenceDigest,
  });
  const expectedSnapshotDigest = safeHash({
    domain: DARWIN_LAUNCH_NATIVE_SNAPSHOT_DOMAIN,
    version: DARWIN_LAUNCHER_VERSION,
    resolver_id: resolverId,
    snapshot: basis,
  });
  if (ownDataValue(input, "snapshot_digest", label) !== expectedSnapshotDigest) {
    throw new Error(`${label}.snapshot_digest is invalid`);
  }
  return deepFreeze({ ...basis, snapshot_digest: expectedSnapshotDigest });
}

function darwinNativeLaunchSnapshotDigest(resolverId, ticketDigest, evidenceInput, planInput, projectionInput) {
  const portId = assertIdentifier(resolverId, "darwin_native_launch_snapshot.resolver_id");
  const digest = assertDigest(ticketDigest, "darwin_native_launch_snapshot.ticket_digest");
  const evidence = normalizeDarwinNativeLaunchEvidence(evidenceInput, planInput, projectionInput);
  const evidenceDigest = darwinNativeLaunchEvidenceDigest(evidence, planInput, projectionInput);
  return safeHash({
    domain: DARWIN_LAUNCH_NATIVE_SNAPSHOT_DOMAIN,
    version: DARWIN_LAUNCHER_VERSION,
    resolver_id: portId,
    snapshot: {
      version: DARWIN_LAUNCHER_VERSION,
      ticket_digest: digest,
      native_evidence: evidence,
      native_evidence_digest: evidenceDigest,
    },
  });
}

function authorityStateBasis(input, label) {
  return deepFreeze({
    authority_id: assertToken(
      ownDataValue(input, "authority_id", label), `${label}.authority_id`, "launcher-authority",
    ),
    authority_key_id: assertToken(
      ownDataValue(input, "authority_key_id", label), `${label}.authority_key_id`, "launcher-key",
    ),
    authority_public_key_digest: assertDigest(
      ownDataValue(input, "authority_public_key_digest", label),
      `${label}.authority_public_key_digest`,
    ),
    authority_trust_root_epoch: assertInteger(
      ownDataValue(input, "authority_trust_root_epoch", label),
      `${label}.authority_trust_root_epoch`,
      1,
    ),
    authority_epoch: assertInteger(
      ownDataValue(input, "authority_epoch", label), `${label}.authority_epoch`, 1,
    ),
    authority_generation: assertInteger(
      ownDataValue(input, "authority_generation", label), `${label}.authority_generation`, 1,
    ),
    revocation_generation: assertInteger(
      ownDataValue(input, "revocation_generation", label), `${label}.revocation_generation`, 0,
    ),
    revocation_state_digest: assertDigest(
      ownDataValue(input, "revocation_state_digest", label), `${label}.revocation_state_digest`,
    ),
    anchor_digest: assertDigest(ownDataValue(input, "anchor_digest", label), `${label}.anchor_digest`),
    trusted_clock_digest: assertDigest(
      ownDataValue(input, "trusted_clock_digest", label), `${label}.trusted_clock_digest`,
    ),
    runtime_epoch_digest: assertDigest(
      ownDataValue(input, "runtime_epoch_digest", label), `${label}.runtime_epoch_digest`,
    ),
    hil_qualification_digest: assertDigest(
      ownDataValue(input, "hil_qualification_digest", label), `${label}.hil_qualification_digest`,
    ),
  });
}

function darwinLaunchAuthorityStateDigest(input) {
  const authority = authorityStateBasis(input, "darwin_launch_authority_state");
  return safeHash({
    domain: DARWIN_LAUNCH_AUTHORITY_STATE_DOMAIN,
    version: DARWIN_LAUNCHER_VERSION,
    authority,
  });
}

function normalizeDarwinLaunchTicketPayload(input) {
  const label = "darwin_launch_ticket.payload";
  assertExactDataObject(input, label, TICKET_PAYLOAD_FIELDS);
  if (ownDataValue(input, "version", label) !== DARWIN_LAUNCHER_VERSION) {
    throw new Error(`${label}.version is invalid`);
  }
  const plan = normalizeDarwinLaunchPlan(ownDataValue(input, "launch_plan", label));
  const role = ownDataValue(input, "role", label);
  const bundleId = assertToken(ownDataValue(input, "bundle_id", label), `${label}.bundle_id`, "worker-bundle");
  if (role !== plan.role || bundleId !== plan.bundle_id) {
    throw new Error(`${label} role or bundle drifted from launch plan`);
  }
  if (ownDataValue(input, "attestation_assurance", label) !== "caller_injected_conformance_only"
      || ownDataValue(input, "production_attested", label) !== false
      || ownDataValue(input, "production_ready", label) !== false
      || ownDataValue(input, "separate_identity_authorized", label) !== false
      || ownDataValue(input, "hardware_authorized", label) !== false) {
    throw new Error(`${label} cannot claim production, identity, or hardware authority`);
  }
  const planDigest = darwinLaunchPlanDigest(plan);
  if (ownDataValue(input, "launch_plan_digest", label) !== planDigest) {
    throw new Error(`${label}.launch_plan_digest is invalid`);
  }
  const authority = authorityStateBasis(input, label);
  const authorityStateDigest = assertDigest(
    ownDataValue(input, "authority_state_digest", label), `${label}.authority_state_digest`,
  );
  if (authorityStateDigest !== darwinLaunchAuthorityStateDigest(authority)) {
    throw new Error(`${label}.authority_state_digest is invalid`);
  }
  const issuedAt = assertTimestamp(ownDataValue(input, "issued_at", label), `${label}.issued_at`);
  const expiresAt = assertTimestamp(ownDataValue(input, "expires_at", label), `${label}.expires_at`);
  const lifetime = reflectApply(dateParse, Date, [expiresAt]) - reflectApply(dateParse, Date, [issuedAt]);
  if (lifetime <= 0 || lifetime > DARWIN_LAUNCH_MAX_TICKET_LIFETIME_MS) {
    throw new Error(`${label} lifetime is outside its fixed bound`);
  }
  const normalized = deepFreeze({
    version: DARWIN_LAUNCHER_VERSION,
    ticket_id: assertToken(ownDataValue(input, "ticket_id", label), `${label}.ticket_id`, "launch-ticket"),
    role,
    bundle_id: bundleId,
    attestation_assurance: "caller_injected_conformance_only",
    production_attested: false,
    production_ready: false,
    separate_identity_authorized: false,
    hardware_authorized: false,
    worker_bundle_enrollment_digest: assertDigest(
      ownDataValue(input, "worker_bundle_enrollment_digest", label),
      `${label}.worker_bundle_enrollment_digest`,
    ),
    worker_bundle_projection_digest: assertDigest(
      ownDataValue(input, "worker_bundle_projection_digest", label),
      `${label}.worker_bundle_projection_digest`,
    ),
    worker_bundle_manifest_digest: assertDigest(
      ownDataValue(input, "worker_bundle_manifest_digest", label),
      `${label}.worker_bundle_manifest_digest`,
    ),
    worker_bundle_reservation_receipt_digest: assertDigest(
      ownDataValue(input, "worker_bundle_reservation_receipt_digest", label),
      `${label}.worker_bundle_reservation_receipt_digest`,
    ),
    worker_bundle_live_snapshot_digest: assertDigest(
      ownDataValue(input, "worker_bundle_live_snapshot_digest", label),
      `${label}.worker_bundle_live_snapshot_digest`,
    ),
    launch_plan: plan,
    launch_plan_digest: planDigest,
    expected_native_evidence_digest: assertDigest(
      ownDataValue(input, "expected_native_evidence_digest", label),
      `${label}.expected_native_evidence_digest`,
    ),
    ...authority,
    authority_state_digest: authorityStateDigest,
    issued_at: issuedAt,
    expires_at: expiresAt,
    nonce: assertNonce(ownDataValue(input, "nonce", label), `${label}.nonce`),
  });
  if (bufferByteLength(safeCanonicalJson(normalized), "utf8") > DARWIN_LAUNCH_MAX_TICKET_BYTES) {
    throw new Error(`${label} exceeds its fixed encoded-byte bound`);
  }
  return normalized;
}

function signatureMessage(payloadDigest) {
  return bufferFrom(
    `${DARWIN_LAUNCH_TICKET_SIGNATURE_DOMAIN}\0${assertDigest(payloadDigest, "payload_digest")}`,
    "utf8",
  );
}

function normalizeSignedDarwinLaunchTicket(input) {
  const label = "signed_darwin_launch_ticket";
  assertExactDataObject(input, label, SIGNED_TICKET_FIELDS);
  if (ownDataValue(input, "version", label) !== DARWIN_LAUNCHER_VERSION
      || ownDataValue(input, "kind", label) !== "darwin_privileged_launch_ticket"
      || ownDataValue(input, "domain", label) !== DARWIN_LAUNCH_TICKET_DOMAIN) {
    throw new Error(`${label} version, kind, or domain is invalid`);
  }
  const payload = normalizeDarwinLaunchTicketPayload(ownDataValue(input, "payload", label));
  const payloadDigest = safeHash(payload);
  if (ownDataValue(input, "payload_digest", label) !== payloadDigest) {
    throw new Error(`${label}.payload_digest is invalid`);
  }
  const authenticationInput = ownDataValue(input, "authentication", label);
  const authLabel = `${label}.authentication`;
  assertExactDataObject(authenticationInput, authLabel, AUTHENTICATION_FIELDS);
  const authentication = deepFreeze({
    scheme: ownDataValue(authenticationInput, "scheme", authLabel),
    key_usage: ownDataValue(authenticationInput, "key_usage", authLabel),
    authority_key_id: assertToken(
      ownDataValue(authenticationInput, "authority_key_id", authLabel),
      `${authLabel}.authority_key_id`,
      "launcher-key",
    ),
    authority_public_key_digest: assertDigest(
      ownDataValue(authenticationInput, "authority_public_key_digest", authLabel),
      `${authLabel}.authority_public_key_digest`,
    ),
    signed_payload_digest: assertDigest(
      ownDataValue(authenticationInput, "signed_payload_digest", authLabel),
      `${authLabel}.signed_payload_digest`,
    ),
    signature: assertSignature(
      ownDataValue(authenticationInput, "signature", authLabel), `${authLabel}.signature`,
    ),
  });
  if (authentication.scheme !== "ed25519"
      || authentication.key_usage !== DARWIN_LAUNCH_TICKET_KEY_USAGE
      || authentication.authority_key_id !== payload.authority_key_id
      || authentication.authority_public_key_digest !== payload.authority_public_key_digest
      || authentication.signed_payload_digest !== payloadDigest) {
    throw new Error(`${authLabel} is not bound to the ticket payload`);
  }
  const basis = deepFreeze({
    version: DARWIN_LAUNCHER_VERSION,
    kind: "darwin_privileged_launch_ticket",
    domain: DARWIN_LAUNCH_TICKET_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    authentication,
  });
  const ticketDigest = assertDigest(
    ownDataValue(input, "ticket_digest", label), `${label}.ticket_digest`,
  );
  if (ticketDigest !== safeHash(basis)) throw new Error(`${label}.ticket_digest is invalid`);
  return deepFreeze({ ...basis, ticket_digest: ticketDigest });
}

function conformanceProjection(kind, portId, extra = {}) {
  return deepFreeze({
    version: DARWIN_LAUNCHER_VERSION,
    port_kind: kind,
    port_id: portId,
    import_inert: true,
    activating: false,
    assurance: "caller_injected_conformance_only",
    production_attested: false,
    production_ready: false,
    separate_identity_authorized: false,
    hardware_authorized: false,
    production_blockers: PRODUCTION_BLOCKERS,
    ...extra,
  });
}

function createConformanceDarwinLaunchTicketSigner(input = {}) {
  const label = "conformance_darwin_launch_ticket_signer";
  assertExactDataObject(input, label, ["port_id", ...AUTHORITY_STATE_FIELDS, "authority_private_key"]);
  const privateKey = assertEd25519Key(
    ownDataValue(input, "authority_private_key", label),
    "private",
    `${label}.authority_private_key`,
  );
  const authority = authorityStateBasis(input, label);
  if (publicKeyDigest(privateKey) !== authority.authority_public_key_digest) {
    throw new Error(`${label} public-key digest is inconsistent`);
  }
  const port = conformanceProjection(
    "darwin_launch_ticket_signer",
    assertIdentifier(ownDataValue(input, "port_id", label), `${label}.port_id`),
    {
      authority_id: authority.authority_id,
      authority_state_digest: darwinLaunchAuthorityStateDigest(authority),
    },
  );
  reflectApply(weakSetAdd, SIGNER_PORTS, [port]);
  reflectApply(weakMapSet, SIGNER_PRIVATE, [
    port,
    objectFreeze({ authority, private_key: privateKey }),
  ]);
  return port;
}

function assertPrivatePort(port, ports, privatePorts, label) {
  if (port == null || typeof port !== "object"
      || reflectApply(utilIsProxy, utilTypes, [port])
      || !objectIsFrozen(port) || !reflectApply(weakSetHas, ports, [port])
      || !reflectApply(weakMapHas, privatePorts, [port])) {
    throw new Error(`${label} must be a privately branded conformance port`);
  }
  return port;
}

function assertConformanceDarwinLaunchTicketSigner(port) {
  return assertPrivatePort(port, SIGNER_PORTS, SIGNER_PRIVATE, "Darwin launch ticket signer");
}

function signDarwinLaunchTicket(port, payloadInput) {
  assertConformanceDarwinLaunchTicketSigner(port);
  const payload = normalizeDarwinLaunchTicketPayload(payloadInput);
  const state = reflectApply(weakMapGet, SIGNER_PRIVATE, [port]);
  if (safeHash(authorityStateBasis(payload, "darwin_launch_ticket.payload"))
        !== safeHash(state.authority)
      || payload.authority_state_digest !== port.authority_state_digest) {
    throw new Error("Darwin launch ticket drifted from signer authority state");
  }
  const payloadDigest = safeHash(payload);
  const authentication = deepFreeze({
    scheme: "ed25519",
    key_usage: DARWIN_LAUNCH_TICKET_KEY_USAGE,
    authority_key_id: payload.authority_key_id,
    authority_public_key_digest: payload.authority_public_key_digest,
    signed_payload_digest: payloadDigest,
    signature: reflectApply(bufferToString, reflectApply(cryptoSign, crypto, [
      null, signatureMessage(payloadDigest), state.private_key,
    ]), ["base64url"]),
  });
  const basis = deepFreeze({
    version: DARWIN_LAUNCHER_VERSION,
    kind: "darwin_privileged_launch_ticket",
    domain: DARWIN_LAUNCH_TICKET_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    authentication,
  });
  return deepFreeze({ ...basis, ticket_digest: safeHash(basis) });
}

function assertFunction(value, label) {
  if (typeof value !== "function" || reflectApply(utilIsProxy, utilTypes, [value])) {
    throw new Error(`${label} must be a non-Proxy function`);
  }
  return value;
}

function createCallbackPort(input, label, callbackField, kind, ports, privatePorts) {
  assertExactDataObject(input, label, ["port_id", callbackField]);
  const port = conformanceProjection(
    kind,
    assertIdentifier(ownDataValue(input, "port_id", label), `${label}.port_id`),
  );
  const callback = assertFunction(ownDataValue(input, callbackField, label), `${label}.${callbackField}`);
  reflectApply(weakSetAdd, ports, [port]);
  reflectApply(weakMapSet, privatePorts, [port, objectFreeze({ callback })]);
  return port;
}

function createConformanceDarwinLaunchAuthorityResolver(input = {}) {
  return createCallbackPort(
    input,
    "conformance_darwin_launch_authority_resolver",
    "resolve_current_authority",
    "darwin_launch_current_authority_resolver",
    AUTHORITY_PORTS,
    AUTHORITY_PRIVATE,
  );
}

function createConformanceDarwinNativeLaunchResolver(input = {}) {
  return createCallbackPort(
    input,
    "conformance_darwin_native_launch_resolver",
    "resolve_live_launch_boundary",
    "darwin_native_live_launch_resolver",
    NATIVE_RESOLVER_PORTS,
    NATIVE_RESOLVER_PRIVATE,
  );
}

function createConformanceDarwinLaunchReplayPort(input = {}) {
  return createCallbackPort(
    input,
    "conformance_darwin_launch_replay_port",
    "reserve_once",
    "darwin_launch_one_use_replay",
    REPLAY_PORTS,
    REPLAY_PRIVATE,
  );
}

function assertConformanceDarwinLaunchAuthorityResolver(port) {
  return assertPrivatePort(port, AUTHORITY_PORTS, AUTHORITY_PRIVATE, "Darwin launch authority resolver");
}

function assertConformanceDarwinNativeLaunchResolver(port) {
  return assertPrivatePort(port, NATIVE_RESOLVER_PORTS, NATIVE_RESOLVER_PRIVATE, "Darwin native launch resolver");
}

function assertConformanceDarwinLaunchReplayPort(port) {
  return assertPrivatePort(port, REPLAY_PORTS, REPLAY_PRIVATE, "Darwin launch replay port");
}

function callPort(port, privatePorts, query, label) {
  if (reflectApply(weakSetHas, ACTIVE_CALLBACKS, [port])) {
    throw new Error(`${label} cannot re-enter its port`);
  }
  reflectApply(weakSetAdd, ACTIVE_CALLBACKS, [port]);
  try {
    const state = reflectApply(weakMapGet, privatePorts, [port]);
    const result = reflectApply(state.callback, undefined, [deepFreeze(query)]);
    if (reflectApply(utilIsPromise, utilTypes, [result])
        || reflectApply(utilIsProxy, utilTypes, [result])) {
      throw new Error(`${label} must return synchronous non-Proxy data`);
    }
    return result;
  } finally {
    reflectApply(weakSetDelete, ACTIVE_CALLBACKS, [port]);
  }
}

function normalizeCurrentAuthority(input) {
  const label = "current_darwin_launch_authority";
  assertExactDataObject(input, label, CURRENT_AUTHORITY_FIELDS);
  if (ownDataValue(input, "version", label) !== DARWIN_LAUNCHER_VERSION
      || ownDataValue(input, "trusted", label) !== true
      || ownDataValue(input, "revoked", label) !== false) {
    throw new Error(`${label} is not trusted and active`);
  }
  const authority = authorityStateBasis(input, label);
  const key = assertEd25519Key(
    ownDataValue(input, "authority_public_key", label), "public", `${label}.authority_public_key`,
  );
  if (publicKeyDigest(key) !== authority.authority_public_key_digest) {
    throw new Error(`${label} public key is invalid`);
  }
  const stateDigest = assertDigest(
    ownDataValue(input, "authority_state_digest", label), `${label}.authority_state_digest`,
  );
  if (stateDigest !== darwinLaunchAuthorityStateDigest(authority)) {
    throw new Error(`${label} authority-state digest is invalid`);
  }
  return deepFreeze({
    version: DARWIN_LAUNCHER_VERSION,
    trusted: true,
    revoked: false,
    ...authority,
    authority_state_digest: stateDigest,
    authority_public_key: key,
    current_ticket_digest: assertDigest(
      ownDataValue(input, "current_ticket_digest", label), `${label}.current_ticket_digest`,
    ),
    current_launch_plan_digest: assertDigest(
      ownDataValue(input, "current_launch_plan_digest", label), `${label}.current_launch_plan_digest`,
    ),
    current_worker_bundle_projection_digest: assertDigest(
      ownDataValue(input, "current_worker_bundle_projection_digest", label),
      `${label}.current_worker_bundle_projection_digest`,
    ),
    current_native_evidence_digest: assertDigest(
      ownDataValue(input, "current_native_evidence_digest", label),
      `${label}.current_native_evidence_digest`,
    ),
    trusted_now: assertTimestamp(ownDataValue(input, "trusted_now", label), `${label}.trusted_now`),
  });
}

function assertTicketAuthorityBinding(ticket, current) {
  const payload = ticket.payload;
  for (let index = 0; index < AUTHORITY_STATE_FIELDS.length; index += 1) {
    const field = AUTHORITY_STATE_FIELDS[index];
    if (payload[field] !== current[field]) throw new Error("Darwin launch authority drifted");
  }
  if (payload.authority_state_digest !== current.authority_state_digest
      || ticket.ticket_digest !== current.current_ticket_digest
      || payload.launch_plan_digest !== current.current_launch_plan_digest
      || payload.worker_bundle_projection_digest
        !== current.current_worker_bundle_projection_digest
      || payload.expected_native_evidence_digest !== current.current_native_evidence_digest) {
    throw new Error("Darwin launch authority binding forked or drifted");
  }
}

function assertBundleBinding(ticket, projection) {
  const payload = ticket.payload;
  if (payload.role !== projection.role || payload.bundle_id !== projection.bundle_id
      || payload.worker_bundle_enrollment_digest !== projection.enrollment_digest
      || payload.worker_bundle_projection_digest !== darwinWorkerBundleProjectionDigest(projection)
      || payload.worker_bundle_manifest_digest !== projection.manifest_digest
      || payload.worker_bundle_reservation_receipt_digest !== projection.reservation_receipt_digest
      || payload.worker_bundle_live_snapshot_digest !== projection.live_snapshot_digest) {
    throw new Error("Darwin launch ticket drifted from verified worker bundle");
  }
}

function assertFresh(payload, trustedNow) {
  const now = reflectApply(dateParse, Date, [trustedNow]);
  const issued = reflectApply(dateParse, Date, [payload.issued_at]);
  const expires = reflectApply(dateParse, Date, [payload.expires_at]);
  if (issued > now + DARWIN_LAUNCH_MAX_CLOCK_SKEW_MS || now >= expires) {
    throw new Error("Darwin launch ticket is stale, expired, or future-dated");
  }
}

function replayClaim(ticket) {
  const payload = ticket.payload;
  const basis = deepFreeze({
    version: DARWIN_LAUNCHER_VERSION,
    ticket_digest: ticket.ticket_digest,
    payload_digest: ticket.payload_digest,
    launch_plan_digest: payload.launch_plan_digest,
    worker_bundle_projection_digest: payload.worker_bundle_projection_digest,
    expected_native_evidence_digest: payload.expected_native_evidence_digest,
    authority_state_digest: payload.authority_state_digest,
    authority_generation: payload.authority_generation,
    role: payload.role,
    nonce_digest: safeHash({ nonce: payload.nonce }),
    expires_at: payload.expires_at,
  });
  return deepFreeze({
    ...basis,
    claim_digest: safeHash({ domain: DARWIN_LAUNCH_REPLAY_CLAIM_DOMAIN, claim: basis }),
  });
}

function darwinLaunchReplayReceiptDigest(replayPortId, receiptBasisInput) {
  const portId = assertIdentifier(replayPortId, "darwin_launch_replay_receipt.port_id");
  const label = "darwin_launch_replay_receipt";
  assertExactDataObject(receiptBasisInput, label, [
    "version", "disposition", "claim_digest", "reservation_generation",
  ]);
  const basis = deepFreeze({
    version: ownDataValue(receiptBasisInput, "version", label),
    disposition: ownDataValue(receiptBasisInput, "disposition", label),
    claim_digest: assertDigest(
      ownDataValue(receiptBasisInput, "claim_digest", label), `${label}.claim_digest`,
    ),
    reservation_generation: assertInteger(
      ownDataValue(receiptBasisInput, "reservation_generation", label),
      `${label}.reservation_generation`,
      1,
    ),
  });
  if (basis.version !== DARWIN_LAUNCHER_VERSION
      || !reflectApply(arrayIncludes, ["reserved", "replay", "fork", "stale"], [
        basis.disposition,
      ])) {
    throw new Error(`${label} version or disposition is invalid`);
  }
  return safeHash({
    domain: DARWIN_LAUNCH_REPLAY_RECEIPT_DOMAIN,
    replay_port_id: portId,
    receipt: basis,
  });
}

function normalizeReplayReceipt(input, replayPort, claim) {
  const label = "darwin_launch_replay_receipt";
  assertExactDataObject(input, label, [
    "version", "disposition", "claim_digest", "reservation_generation", "receipt_digest",
  ]);
  const basis = {
    version: ownDataValue(input, "version", label),
    disposition: ownDataValue(input, "disposition", label),
    claim_digest: ownDataValue(input, "claim_digest", label),
    reservation_generation: ownDataValue(input, "reservation_generation", label),
  };
  const receiptDigest = darwinLaunchReplayReceiptDigest(replayPort.port_id, basis);
  if (ownDataValue(input, "receipt_digest", label) !== receiptDigest
      || basis.disposition !== "reserved" || basis.claim_digest !== claim.claim_digest) {
    throw new Error("Darwin launch ticket was not reserved exactly once");
  }
  return deepFreeze({ ...basis, receipt_digest: receiptDigest });
}

function rejectedError() {
  const error = new ErrorCtor("Darwin privileged launch plan was rejected");
  reflectApply(objectDefineProperty, Object, [error, "code", {
    value: "darwin_privileged_launch_rejected",
    enumerable: false,
    writable: false,
    configurable: false,
  }]);
  return error;
}

function verifyAndReserveDarwinLaunchTicket(input = {}) {
  try {
    const label = "darwin_privileged_launch_verification";
    assertExactDataObject(input, label, [
      "ticket",
      "verified_worker_bundle",
      "authority_resolver_port",
      "native_resolver_port",
      "replay_port",
    ]);
    const authorityPort = assertConformanceDarwinLaunchAuthorityResolver(
      ownDataValue(input, "authority_resolver_port", label),
    );
    const nativePort = assertConformanceDarwinNativeLaunchResolver(
      ownDataValue(input, "native_resolver_port", label),
    );
    const replayPort = assertConformanceDarwinLaunchReplayPort(
      ownDataValue(input, "replay_port", label),
    );
    const ticket = normalizeSignedDarwinLaunchTicket(ownDataValue(input, "ticket", label));
    const projection = projectActuallyVerifiedWorkerBundle(
      ownDataValue(input, "verified_worker_bundle", label),
    );
    assertBundleBinding(ticket, projection);
    const current = normalizeCurrentAuthority(callPort(
      authorityPort,
      AUTHORITY_PRIVATE,
      {
        version: DARWIN_LAUNCHER_VERSION,
        purpose: "resolve_exact_current_darwin_launch_authority",
        ticket_digest: ticket.ticket_digest,
      },
      "Darwin launch authority resolver",
    ));
    assertTicketAuthorityBinding(ticket, current);
    if (!reflectApply(cryptoVerify, crypto, [
      null,
      signatureMessage(ticket.payload_digest),
      current.authority_public_key,
      bufferFrom(ticket.authentication.signature, "base64url"),
    ])) throw new Error("Darwin launch ticket signature is invalid");
    assertFresh(ticket.payload, current.trusted_now);
    const liveQuery = deepFreeze({
      version: DARWIN_LAUNCHER_VERSION,
      purpose: "resolve_exact_live_darwin_launch_boundary",
      ticket_digest: ticket.ticket_digest,
      launch_plan_digest: ticket.payload.launch_plan_digest,
      worker_bundle_projection_digest: ticket.payload.worker_bundle_projection_digest,
      expected_native_evidence_digest: ticket.payload.expected_native_evidence_digest,
    });
    const liveBefore = normalizeLiveSnapshot(callPort(
      nativePort,
      NATIVE_RESOLVER_PRIVATE,
      liveQuery,
      "Darwin native launch resolver",
    ), nativePort.port_id, ticket, projection);
    const claim = replayClaim(ticket);
    let receipt = null;
    let replayRejected = false;
    try {
      receipt = normalizeReplayReceipt(callPort(
        replayPort,
        REPLAY_PRIVATE,
        claim,
        "Darwin launch replay reservation",
      ), replayPort, claim);
    } catch {
      replayRejected = true;
    }
    const currentAfter = normalizeCurrentAuthority(callPort(
      authorityPort,
      AUTHORITY_PRIVATE,
      {
        version: DARWIN_LAUNCHER_VERSION,
        purpose: "revalidate_exact_current_darwin_launch_authority_after_reservation",
        ticket_digest: ticket.ticket_digest,
        replay_claim_digest: claim.claim_digest,
        replay_receipt_digest: receipt == null ? null : receipt.receipt_digest,
      },
      "post-reservation Darwin launch authority resolver",
    ));
    assertTicketAuthorityBinding(ticket, currentAfter);
    if (reflectApply(dateParse, Date, [currentAfter.trusted_now])
        < reflectApply(dateParse, Date, [current.trusted_now])) {
      throw new Error("Darwin launch trusted time moved backwards");
    }
    assertFresh(ticket.payload, currentAfter.trusted_now);
    if (replayRejected || receipt == null) throw new Error("Darwin launch reservation was not confirmed");
    const liveAfter = normalizeLiveSnapshot(callPort(
      nativePort,
      NATIVE_RESOLVER_PRIVATE,
      liveQuery,
      "Darwin native launch resolver",
    ), nativePort.port_id, ticket, projection);
    if (liveBefore.snapshot_digest !== liveAfter.snapshot_digest
        || safeCanonicalJson(liveBefore) !== safeCanonicalJson(liveAfter)) {
      throw new Error("Darwin native launch evidence drifted during verification");
    }
    const verified = deepFreeze({
      version: DARWIN_LAUNCHER_VERSION,
      ticket_id: ticket.payload.ticket_id,
      ticket_digest: ticket.ticket_digest,
      role: ticket.payload.role,
      bundle_id: ticket.payload.bundle_id,
      target_principal_id: ticket.payload.launch_plan.target_principal_id,
      authorizer_principal_id: ticket.payload.launch_plan.authorizer_principal_id,
      worker_bundle_enrollment_digest: ticket.payload.worker_bundle_enrollment_digest,
      worker_bundle_projection_digest: ticket.payload.worker_bundle_projection_digest,
      launch_plan_digest: ticket.payload.launch_plan_digest,
      path_plan_digest: safeHash({
        working_root_path_digest: liveAfter.native_evidence.working_root_path_digest,
        executable_path_digest: liveAfter.native_evidence.executable_path_digest,
        entrypoint_path_digest: liveAfter.native_evidence.entrypoint_path_digest,
        config_manifest_path_digest: liveAfter.native_evidence.config_manifest_path_digest,
      }),
      argv_digest: liveAfter.native_evidence.argv_digest,
      environment_digest: liveAfter.native_evidence.environment_digest,
      fd_set_digest: liveAfter.native_evidence.allowed_fd_set_digest,
      credential_plan_digest: darwinLaunchCredentialPlanDigest(ticket.payload.launch_plan),
      native_evidence_digest: liveAfter.native_evidence_digest,
      native_snapshot_digest: liveAfter.snapshot_digest,
      replay_receipt_digest: receipt.receipt_digest,
      authority_state_digest: ticket.payload.authority_state_digest,
      authority_epoch: ticket.payload.authority_epoch,
      authority_generation: ticket.payload.authority_generation,
      assurance: "signed_bundle_bound_native_double_snapshot_reserved_conformance_only",
      import_inert: true,
      activating: false,
      production_attested: false,
      production_ready: false,
      separate_identity_authorized: false,
      hardware_authorized: false,
      production_blockers: PRODUCTION_BLOCKERS,
    });
    reflectApply(weakSetAdd, VERIFIED_PLANS, [verified]);
    reflectApply(weakMapSet, VERIFIED_PLAN_PRIVATE, [
      verified,
      objectFreeze({
        launch_plan: ticket.payload.launch_plan,
        worker_bundle_projection: projection,
        native_evidence: liveAfter.native_evidence,
      }),
    ]);
    return verified;
  } catch {
    throw rejectedError();
  }
}

function assertVerifiedDarwinLaunchPlan(value) {
  if (value == null || typeof value !== "object"
      || reflectApply(utilIsProxy, utilTypes, [value])
      || !objectIsFrozen(value) || !reflectApply(weakSetHas, VERIFIED_PLANS, [value])
      || !reflectApply(weakMapHas, VERIFIED_PLAN_PRIVATE, [value])) {
    throw new Error("verified Darwin launch plan must be a privately branded conformance result");
  }
  return value;
}

function bindDarwinNativeFixtureContractConsistency(recordInput, verifiedPlanInput) {
  try {
    const verifiedPlan = assertVerifiedDarwinLaunchPlan(verifiedPlanInput);
    const privatePlan = reflectApply(weakMapGet, VERIFIED_PLAN_PRIVATE, [verifiedPlan]);
    const nativeEvidence = privatePlan.native_evidence;
    const record = normalizeDarwinNativeFixtureContractRecord(recordInput);
    if (record.declared_launch_plan_digest !== verifiedPlan.launch_plan_digest
        || record.declared_worker_bundle_projection_digest
          !== verifiedPlan.worker_bundle_projection_digest
        || record.declared_native_evidence_digest !== verifiedPlan.native_evidence_digest
        || record.declared_path_plan_digest !== verifiedPlan.path_plan_digest
        || record.declared_argv_digest !== verifiedPlan.argv_digest
        || record.declared_environment_digest !== verifiedPlan.environment_digest
        || record.declared_fd_set_digest !== verifiedPlan.fd_set_digest
        || record.declared_credential_plan_digest !== verifiedPlan.credential_plan_digest
        || record.openat_fstatat_walk_digest
          !== nativeEvidence.openat_fstatat_walk_digest
        || record.fd_enumeration_digest !== nativeEvidence.fd_enumeration_digest) {
      throw new Error("Darwin native fixture contract record drifted from verified launch contract");
    }
    const consistency = deepFreeze({
      version: DARWIN_LAUNCHER_VERSION,
      kind: "darwin_native_fixture_contract_consistency",
      ticket_digest: verifiedPlan.ticket_digest,
      role: verifiedPlan.role,
      bundle_id: verifiedPlan.bundle_id,
      fixture_contract_record_checksum: record.contract_record_checksum,
      fixture_manifest_digest: record.fixture_manifest_digest,
      native_launcher_on_disk_path_object_sha256:
        record.native_launcher_on_disk_path_object_sha256,
      declared_launch_plan_digest: record.declared_launch_plan_digest,
      declared_worker_bundle_projection_digest:
        record.declared_worker_bundle_projection_digest,
      declared_native_evidence_digest: record.declared_native_evidence_digest,
      fixture_root_identity_digest: record.fixture_root_identity_digest,
      openat_fstatat_walk_digest: record.openat_fstatat_walk_digest,
      fd_enumeration_digest: record.fd_enumeration_digest,
      credential_observation_digest: record.credential_observation_digest,
      fixture_contract_consistent: true,
      native_evidence_digest_contract_consistent: true,
      openat_fstatat_walk_digest_contract_consistent: true,
      fd_enumeration_digest_contract_consistent: true,
      native_launcher_mapped_process_image_identity_bound: false,
      native_fixture_record_provenance_attested: false,
      child_process_custody_attested: false,
      report_channel_authenticated: false,
      credential_drop_executed: false,
      execve_executed: false,
      production_attested: false,
      production_ready: false,
      launch_contract_production_blockers: PRODUCTION_BLOCKERS,
      native_fixture_production_blockers: record.production_blockers,
      production_blockers: NATIVE_FIXTURE_CONSISTENCY_PRODUCTION_BLOCKERS,
    });
    reflectApply(weakSetAdd, VERIFIED_NATIVE_FIXTURE_CONSISTENCY_RESULTS, [consistency]);
    return consistency;
  } catch {
    throw rejectedError();
  }
}

function assertVerifiedDarwinNativeFixtureContractConsistency(value) {
  if (value == null || typeof value !== "object"
      || reflectApply(utilIsProxy, utilTypes, [value]) || !objectIsFrozen(value)
      || !reflectApply(weakSetHas, VERIFIED_NATIVE_FIXTURE_CONSISTENCY_RESULTS, [value])) {
    throw new Error("Darwin native fixture contract consistency must be a privately branded result");
  }
  return value;
}

module.exports = {
  DARWIN_LAUNCHER_VERSION,
  DARWIN_LAUNCH_ARGV_DOMAIN,
  DARWIN_LAUNCH_AUTHORITY_STATE_DOMAIN,
  DARWIN_LAUNCH_CREDENTIAL_PLAN_DOMAIN,
  DARWIN_LAUNCH_ENVIRONMENT_DOMAIN,
  DARWIN_LAUNCH_ENV_ALLOWLIST,
  DARWIN_LAUNCH_FD_SET_DOMAIN,
  DARWIN_LAUNCH_MAX_CLOCK_SKEW_MS,
  DARWIN_LAUNCH_MAX_FDS,
  DARWIN_LAUNCH_MAX_PATH_BYTES,
  DARWIN_LAUNCH_MAX_PATH_DEPTH,
  DARWIN_LAUNCH_MAX_TICKET_BYTES,
  DARWIN_LAUNCH_MAX_TICKET_LIFETIME_MS,
  DARWIN_LAUNCH_NATIVE_EVIDENCE_DOMAIN,
  DARWIN_LAUNCH_NATIVE_SNAPSHOT_DOMAIN,
  DARWIN_LAUNCH_PATH_IDENTITY_DOMAIN,
  DARWIN_LAUNCH_PLAN_DOMAIN,
  DARWIN_LAUNCH_REPLAY_CLAIM_DOMAIN,
  DARWIN_LAUNCH_REPLAY_RECEIPT_DOMAIN,
  DARWIN_LAUNCH_ROLES,
  DARWIN_LAUNCH_TICKET_DOMAIN,
  DARWIN_LAUNCH_TICKET_KEY_USAGE,
  DARWIN_LAUNCH_TICKET_SIGNATURE_DOMAIN,
  DARWIN_LAUNCH_WORKER_BUNDLE_PROJECTION_DOMAIN,
  assertConformanceDarwinLaunchAuthorityResolver,
  assertConformanceDarwinLaunchReplayPort,
  assertConformanceDarwinLaunchTicketSigner,
  assertConformanceDarwinNativeLaunchResolver,
  assertVerifiedDarwinNativeFixtureContractConsistency,
  assertVerifiedDarwinLaunchPlan,
  bindDarwinNativeFixtureContractConsistency,
  createConformanceDarwinLaunchAuthorityResolver,
  createConformanceDarwinLaunchReplayPort,
  createConformanceDarwinLaunchTicketSigner,
  createConformanceDarwinNativeLaunchResolver,
  darwinLaunchArgvDigest,
  darwinLaunchAuthorityStateDigest,
  darwinLaunchCredentialPlanDigest,
  darwinLaunchEnvironmentDigest,
  darwinLaunchFdSetDigest,
  darwinLaunchPlanDigest,
  darwinLaunchReplayReceiptDigest,
  darwinLauncherPathDigest,
  darwinCredentialDropReadbackDigest,
  darwinNativeLaunchEvidenceDigest,
  darwinNativeLaunchSnapshotDigest,
  darwinWorkerBundleProjectionDigest,
  normalizeDarwinLaunchPlan,
  normalizeDarwinLaunchTicketPayload,
  normalizeDarwinNativeLaunchEvidence,
  normalizeSignedDarwinLaunchTicket,
  normalizeVerifiedWorkerBundleProjection,
  signDarwinLaunchTicket,
  verifyAndReserveDarwinLaunchTicket,
};
