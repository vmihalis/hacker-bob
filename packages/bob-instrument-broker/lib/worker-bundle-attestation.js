"use strict";

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const WORKER_BUNDLE_ATTESTATION_VERSION = 1;
const WORKER_BUNDLE_MANIFEST_DOMAIN =
  "hacker-bob/instrument-broker-worker-bundle-manifest/v1";
const WORKER_BUNDLE_ENTRY_IDENTITY_DOMAIN =
  "hacker-bob/instrument-broker-worker-bundle-entry-identity/v1";
const WORKER_BUNDLE_NATIVE_ADDON_SET_DOMAIN =
  "hacker-bob/instrument-broker-worker-bundle-native-addon-set/v1";
const WORKER_BUNDLE_IMMUTABILITY_DOMAIN =
  "hacker-bob/instrument-broker-worker-bundle-immutability/v1";
const WORKER_BUNDLE_ENROLLMENT_DOMAIN =
  "hacker-bob/instrument-broker-worker-bundle-enrollment/v1";
const WORKER_BUNDLE_ENROLLMENT_SIGNATURE_DOMAIN =
  "hacker-bob/instrument-broker-worker-bundle-enrollment-signature/v1";
const WORKER_BUNDLE_AUTHORITY_STATE_DOMAIN =
  "hacker-bob/instrument-broker-worker-bundle-authority-state/v1";
const WORKER_BUNDLE_LIVE_SNAPSHOT_DOMAIN =
  "hacker-bob/instrument-broker-worker-bundle-live-snapshot/v1";
const WORKER_BUNDLE_RESERVATION_CLAIM_DOMAIN =
  "hacker-bob/instrument-broker-worker-bundle-reservation-claim/v1";
const WORKER_BUNDLE_RESERVATION_RECEIPT_DOMAIN =
  "hacker-bob/instrument-broker-worker-bundle-reservation-receipt/v1";
const WORKER_BUNDLE_ENROLLMENT_KEY_USAGE =
  "instrument_broker_worker_bundle_enrollment";
const WORKER_BUNDLE_IMMUTABILITY_SCHEME =
  "closed_manifest_double_live_snapshot_conformance_v1";

const WORKER_BUNDLE_MAX_ENTRIES = 512;
const WORKER_BUNDLE_MAX_NATIVE_ADDONS = 64;
const WORKER_BUNDLE_MAX_TOTAL_BYTES = 512 * 1024 * 1024;
const WORKER_BUNDLE_MAX_ENTRY_BYTES = 256 * 1024 * 1024;
const WORKER_BUNDLE_MAX_PATH_BYTES = 512;
const WORKER_BUNDLE_MAX_PATH_DEPTH = 16;
const WORKER_BUNDLE_MAX_MANIFEST_BYTES = 512 * 1024;
const WORKER_BUNDLE_MAX_ENROLLMENT_BYTES = 768 * 1024;
const WORKER_BUNDLE_MAX_LIFETIME_MS = 60_000;
const WORKER_BUNDLE_MAX_CLOCK_SKEW_MS = 5_000;

const WORKER_BUNDLE_ROLES = Object.freeze([
  "issuer_peer",
  "active_device_worker",
  "cleanup_only_worker",
  "safety_supervisor",
]);
const WORKER_BUNDLE_ENTRY_PURPOSES = Object.freeze([
  "entrypoint",
  "config_manifest",
  "native_addon",
  "runtime",
  "support_file",
]);
const ROLE_SET = new Set(WORKER_BUNDLE_ROLES);
const PURPOSE_SET = new Set(WORKER_BUNDLE_ENTRY_PURPOSES);

const MANIFEST_FIELDS = Object.freeze([
  "version",
  "bundle_id",
  "role",
  "entries",
]);
const ENTRY_FIELDS = Object.freeze([
  "path",
  "purpose",
  "file_type",
  "byte_size",
  "content_digest",
  "owner_uid",
  "owner_gid",
  "mode",
  "nlink",
  "object_identity_digest",
  "static_code_identity_applicable",
  "static_code_identity_scheme",
  "static_code_identity_digest",
  "static_code_identity_complete",
]);
const ROOT_EVIDENCE_FIELDS = Object.freeze([
  "version",
  "root_path_digest",
  "directory_type",
  "directory_identity_digest",
  "owner_uid",
  "owner_gid",
  "mode",
  "nlink",
  "mount_identity_scheme",
  "mount_identity_digest",
  "filesystem_identity_scheme",
  "filesystem_identity_digest",
  "immutability_scheme",
  "immutable_flags_digest",
  "immutable_flags_complete",
  "read_only_mount",
  "root_immutable",
  "native_resolution_complete",
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
const ENROLLMENT_PAYLOAD_FIELDS = Object.freeze([
  "version",
  "enrollment_id",
  "bundle_id",
  "role",
  "attestation_assurance",
  "production_ready",
  "separate_identity_authorized",
  "hardware_authorized",
  "manifest",
  "manifest_digest",
  "root_evidence",
  "bundle_immutability_scheme",
  "bundle_immutability_evidence_digest",
  "bundle_immutability_complete",
  "entrypoint_digest",
  "config_manifest_digest",
  "native_addon_set_digest",
  "runtime_identity_digest",
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
const SIGNED_ENROLLMENT_FIELDS = Object.freeze([
  "version",
  "kind",
  "domain",
  "payload",
  "payload_digest",
  "authentication",
  "enrollment_digest",
]);
const CURRENT_AUTHORITY_FIELDS = Object.freeze([
  "version",
  "trusted",
  "revoked",
  ...AUTHORITY_STATE_FIELDS,
  "authority_state_digest",
  "authority_public_key",
  "current_enrollment_digest",
  "current_manifest_digest",
  "current_bundle_immutability_evidence_digest",
  "trusted_now",
]);
const LIVE_SNAPSHOT_BASIS_FIELDS = Object.freeze([
  "version",
  "enrollment_digest",
  "bundle_id",
  "role",
  "manifest",
  "manifest_digest",
  "root_evidence",
  "bundle_immutability_scheme",
  "bundle_immutability_evidence_digest",
  "bundle_immutability_complete",
  "entrypoint_digest",
  "config_manifest_digest",
  "native_addon_set_digest",
  "runtime_identity_digest",
]);
const LIVE_SNAPSHOT_FIELDS = Object.freeze([
  ...LIVE_SNAPSHOT_BASIS_FIELDS,
  "snapshot_digest",
]);

const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectIsFrozen = Object.isFrozen;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const arrayIsArray = Array.isArray;
const arraySort = Array.prototype.sort;
const jsonStringify = JSON.stringify;
const dateParse = Date.parse;
const dateToISOString = Date.prototype.toISOString;
const bufferByteLength = Buffer.byteLength;
const bufferCompare = Buffer.compare;
const bufferFrom = Buffer.from;
const bufferToString = Buffer.prototype.toString;
const regexpTest = RegExp.prototype.test;
const arrayIncludes = Array.prototype.includes;
const mapGet = Map.prototype.get;
const mapSet = Map.prototype.set;
const setAdd = Set.prototype.add;
const setHas = Set.prototype.has;
const stringSplit = String.prototype.split;
const stringCharCodeAt = String.prototype.charCodeAt;
const stringIncludes = String.prototype.includes;
const stringStartsWith = String.prototype.startsWith;
const stringToLowerCase = String.prototype.toLowerCase;
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
const AUTHORITY_RESOLVER_PORTS = new WeakSet();
const AUTHORITY_RESOLVER_PRIVATE = new WeakMap();
const LIVE_RESOLVER_PORTS = new WeakSet();
const LIVE_RESOLVER_PRIVATE = new WeakMap();
const RESERVATION_PORTS = new WeakSet();
const RESERVATION_PRIVATE = new WeakMap();
const ACTIVE_CALLBACKS = new WeakSet();
const VERIFIED_ENROLLMENTS = new WeakSet();

const CONFORMANCE_BLOCKERS = Object.freeze([
  "native_openat_fstatat_walk_not_qualified",
  "native_file_flags_immutability_not_qualified",
  "native_static_code_identity_not_qualified",
  "native_live_snapshot_hil_missing",
  "root_owned_immutable_launcher_not_qualified",
]);

function safeHash(value) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [safeCanonicalJson(value), "utf8"]);
  return reflectApply(hashDigest, hash, ["hex"]);
}

function compareStrings(left, right) {
  return bufferCompare(bufferFrom(left, "utf8"), bufferFrom(right, "utf8"));
}

function sortedStrings(input) {
  const result = [];
  for (let index = 0; index < input.length; index += 1) result[index] = input[index];
  reflectApply(arraySort, result, [compareStrings]);
  return result;
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || utilTypes.isProxy(value)
      || arrayIsArray(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  for (const key of reflectOwnKeys(value)) {
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
  const actual = reflectOwnKeys(value);
  const expected = fields;
  if (actual.length !== expected.length) throw new Error(`${label} fields are not exact`);
  const expectedSet = new Set(expected);
  for (const field of actual) {
    if (!reflectApply(setHas, expectedSet, [field])) {
      throw new Error(`${label} fields are not exact`);
    }
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
  if (value == null || typeof value !== "object" || utilTypes.isProxy(value)
      || !arrayIsArray(value)) throw new Error(`${label} must be a dense non-Proxy array`);
  const lengthDescriptor = objectGetOwnPropertyDescriptor(value, "length");
  if (lengthDescriptor == null || !("value" in lengthDescriptor)
      || !Number.isSafeInteger(lengthDescriptor.value)
      || lengthDescriptor.value < minimum || lengthDescriptor.value > maximum) {
    throw new Error(`${label} is outside its fixed count bound`);
  }
  const length = lengthDescriptor.value;
  const keys = reflectOwnKeys(value);
  if (keys.length !== length + 1) throw new Error(`${label} must not contain holes or extra fields`);
  const result = new Array(length);
  for (let index = 0; index < length; index += 1) {
    const descriptor = objectGetOwnPropertyDescriptor(value, String(index));
    if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new Error(`${label} must contain enumerable own data entries only`);
    }
    result[index] = descriptor.value;
  }
  return result;
}

function safeCanonicalJson(value) {
  function encode(candidate) {
    if (candidate === null) return "null";
    if (candidate === true) return "true";
    if (candidate === false) return "false";
    if (typeof candidate === "string") return reflectApply(jsonStringify, JSON, [candidate]);
    if (typeof candidate === "number") {
      if (!Number.isSafeInteger(candidate) || Object.is(candidate, -0)) {
        throw new Error("canonical evidence contains an invalid number");
      }
      return `${candidate}`;
    }
    if (typeof candidate !== "object" || candidate == null || utilTypes.isProxy(candidate)) {
      throw new Error("canonical evidence contains an unsupported value");
    }
    if (arrayIsArray(candidate)) {
      const values = denseArrayValues(candidate, "canonical evidence array", 0, WORKER_BUNDLE_MAX_ENTRIES);
      let text = "[";
      for (let index = 0; index < values.length; index += 1) {
        if (index > 0) text += ",";
        text += encode(values[index]);
      }
      return `${text}]`;
    }
    if (!isPlainDataObject(candidate)) {
      throw new Error("canonical evidence must use plain own-data objects");
    }
    const keys = sortedStrings(reflectOwnKeys(candidate));
    let text = "{";
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (index > 0) text += ",";
      text += `${reflectApply(jsonStringify, JSON, [key])}:${encode(ownDataValue(
        candidate,
        key,
        "canonical evidence",
      ))}`;
    }
    return `${text}}`;
  }
  return encode(value);
}

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || objectIsFrozen(value)) return value;
  if (arrayIsArray(value)) {
    for (const child of denseArrayValues(value, "internal array", 0, WORKER_BUNDLE_MAX_ENTRIES)) {
      deepFreeze(child);
    }
    return objectFreeze(value);
  }
  if (!isPlainDataObject(value)) return value;
  for (const key of reflectOwnKeys(value)) deepFreeze(ownDataValue(value, key, "internal object"));
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

function assertToken(value, label, prefix) {
  if (typeof value !== "string" || !reflectApply(regexpTest, TOKEN_PATTERN, [value])
      || (prefix != null && !reflectApply(stringStartsWith, value, [`${prefix}:`]))) {
    throw new Error(`${label} must be a bounded opaque ${prefix || "token"}`);
  }
  return value;
}

function assertInteger(value, label, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} is outside its fixed integer bound`);
  }
  return value;
}

function assertBoolean(value, label) {
  if (value !== true && value !== false) throw new Error(`${label} must be boolean`);
  return value;
}

function assertCanonicalTimestamp(value, label) {
  if (typeof value !== "string") throw new Error(`${label} must be a canonical timestamp`);
  const milliseconds = reflectApply(dateParse, Date, [value]);
  if (!Number.isFinite(milliseconds)
      || reflectApply(dateToISOString, new Date(milliseconds), []) !== value) {
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

function assertEd25519Key(key, kind, label) {
  if (key == null || typeof key !== "object" || utilTypes.isProxy(key)
      || !(key instanceof crypto.KeyObject) || key.type !== kind
      || key.asymmetricKeyType !== "ed25519") {
    throw new Error(`${label} must be an Ed25519 ${kind} KeyObject`);
  }
  return key;
}

function publicKeyDigest(keyInput) {
  const key = keyInput.type === "private"
    ? reflectApply(cryptoCreatePublicKey, crypto, [keyInput])
    : keyInput;
  assertEd25519Key(key, "public", "worker_bundle_authority_public_key");
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [key.export({ type: "spki", format: "der" })]);
  return reflectApply(hashDigest, hash, ["hex"]);
}

const WORKER_BUNDLE_STATIC_CODE_NOT_APPLICABLE_DIGEST = safeHash({
  domain: WORKER_BUNDLE_ENTRY_IDENTITY_DOMAIN,
  version: WORKER_BUNDLE_ATTESTATION_VERSION,
  static_code_identity: "not_applicable",
});

function assertRelativePosixPath(value, label) {
  if (typeof value !== "string" || value.length === 0
      || bufferByteLength(value, "utf8") > WORKER_BUNDLE_MAX_PATH_BYTES
      || reflectApply(stringCharCodeAt, value, [0]) === 47
      || reflectApply(stringIncludes, value, ["\\"])
      || reflectApply(stringIncludes, value, ["//"])) {
    throw new Error(`${label} must be a bounded canonical relative POSIX path`);
  }
  const components = reflectApply(stringSplit, value, ["/"]);
  if (components.length < 1 || components.length > WORKER_BUNDLE_MAX_PATH_DEPTH) {
    throw new Error(`${label} exceeds the fixed path-depth bound`);
  }
  for (const component of components) {
    if (component === "." || component === ".."
        || !reflectApply(regexpTest, PATH_COMPONENT_PATTERN, [component])) {
      throw new Error(`${label} contains a non-canonical path component`);
    }
  }
  return value;
}

function normalizeEntry(input, index) {
  const label = `worker_bundle_manifest.entries[${index}]`;
  assertExactDataObject(input, label, ENTRY_FIELDS);
  const purpose = ownDataValue(input, "purpose", label);
  if (!reflectApply(setHas, PURPOSE_SET, [purpose])) {
    throw new Error(`${label}.purpose is invalid`);
  }
  const staticApplicable = assertBoolean(
    ownDataValue(input, "static_code_identity_applicable", label),
    `${label}.static_code_identity_applicable`,
  );
  const staticScheme = assertIdentifier(
    ownDataValue(input, "static_code_identity_scheme", label),
    `${label}.static_code_identity_scheme`,
  );
  const staticDigest = assertDigest(
    ownDataValue(input, "static_code_identity_digest", label),
    `${label}.static_code_identity_digest`,
  );
  const staticComplete = ownDataValue(input, "static_code_identity_complete", label);
  if (staticComplete !== true) throw new Error(`${label} static-code determination is incomplete`);
  if (staticApplicable) {
    if (staticScheme === "not_applicable"
        || staticDigest === WORKER_BUNDLE_STATIC_CODE_NOT_APPLICABLE_DIGEST) {
      throw new Error(`${label} applicable static-code identity is missing`);
    }
  } else if (staticScheme !== "not_applicable"
      || staticDigest !== WORKER_BUNDLE_STATIC_CODE_NOT_APPLICABLE_DIGEST) {
    throw new Error(`${label} non-applicable static-code identity is not canonical`);
  }
  if ((purpose === "runtime" || purpose === "native_addon") && !staticApplicable) {
    throw new Error(`${label} executable native code requires static-code identity`);
  }
  if (purpose === "config_manifest" && staticApplicable) {
    throw new Error(`${label} config data cannot claim static-code identity`);
  }
  const mode = assertInteger(ownDataValue(input, "mode", label), `${label}.mode`, 0, 0o777);
  if ((mode & 0o022) !== 0 || (mode & 0o400) === 0) {
    throw new Error(`${label}.mode must be owner-readable and not group/world writable`);
  }
  if (purpose === "runtime" && (mode & 0o100) === 0) {
    throw new Error(`${label} runtime must be owner executable`);
  }
  const byteSize = assertInteger(
    ownDataValue(input, "byte_size", label),
    `${label}.byte_size`,
    0,
    WORKER_BUNDLE_MAX_ENTRY_BYTES,
  );
  if ((purpose === "runtime" || purpose === "native_addon") && byteSize === 0) {
    throw new Error(`${label} native code cannot be empty`);
  }
  if (ownDataValue(input, "file_type", label) !== "regular_file") {
    throw new Error(`${label}.file_type must be regular_file`);
  }
  const nlink = assertInteger(ownDataValue(input, "nlink", label), `${label}.nlink`, 1, 1);
  return deepFreeze({
    path: assertRelativePosixPath(ownDataValue(input, "path", label), `${label}.path`),
    purpose,
    file_type: "regular_file",
    byte_size: byteSize,
    content_digest: assertDigest(
      ownDataValue(input, "content_digest", label),
      `${label}.content_digest`,
    ),
    owner_uid: assertInteger(ownDataValue(input, "owner_uid", label), `${label}.owner_uid`, 0, 2 ** 32 - 2),
    owner_gid: assertInteger(ownDataValue(input, "owner_gid", label), `${label}.owner_gid`, 0, 2 ** 32 - 2),
    mode,
    nlink,
    object_identity_digest: assertDigest(
      ownDataValue(input, "object_identity_digest", label),
      `${label}.object_identity_digest`,
    ),
    static_code_identity_applicable: staticApplicable,
    static_code_identity_scheme: staticScheme,
    static_code_identity_digest: staticDigest,
    static_code_identity_complete: true,
  });
}

function normalizeWorkerBundleManifest(input, label = "worker_bundle_manifest") {
  assertExactDataObject(input, label, MANIFEST_FIELDS);
  if (ownDataValue(input, "version", label) !== WORKER_BUNDLE_ATTESTATION_VERSION) {
    throw new Error(`${label}.version is invalid`);
  }
  const role = ownDataValue(input, "role", label);
  if (!reflectApply(setHas, ROLE_SET, [role])) throw new Error(`${label}.role is invalid`);
  const inputEntries = denseArrayValues(
    ownDataValue(input, "entries", label),
    `${label}.entries`,
    4,
    WORKER_BUNDLE_MAX_ENTRIES,
  );
  const entries = [];
  const paths = new Set();
  const foldedPaths = new Set();
  const objects = new Set();
  const purposeCounts = new Map();
  let totalBytes = 0;
  let priorPath = null;
  for (let index = 0; index < inputEntries.length; index += 1) {
    const entry = normalizeEntry(inputEntries[index], index);
    if (priorPath != null && compareStrings(priorPath, entry.path) >= 0) {
      throw new Error(`${label}.entries must be strictly sorted by canonical path`);
    }
    const foldedPath = reflectApply(stringToLowerCase, entry.path, []);
    if (reflectApply(setHas, paths, [entry.path])
        || reflectApply(setHas, foldedPaths, [foldedPath])
        || reflectApply(setHas, objects, [entry.object_identity_digest])) {
      throw new Error(`${label}.entries contain an alias or duplicate`);
    }
    for (const existingPath of paths) {
      if (reflectApply(stringStartsWith, entry.path, [`${existingPath}/`])
          || reflectApply(stringStartsWith, existingPath, [`${entry.path}/`])) {
        throw new Error(`${label}.entries contain a file-prefix alias`);
      }
    }
    reflectApply(setAdd, paths, [entry.path]);
    reflectApply(setAdd, foldedPaths, [foldedPath]);
    reflectApply(setAdd, objects, [entry.object_identity_digest]);
    reflectApply(mapSet, purposeCounts, [
      entry.purpose,
      (reflectApply(mapGet, purposeCounts, [entry.purpose]) || 0) + 1,
    ]);
    totalBytes += entry.byte_size;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > WORKER_BUNDLE_MAX_TOTAL_BYTES) {
      throw new Error(`${label}.entries exceed the fixed total-byte bound`);
    }
    entries[entries.length] = entry;
    priorPath = entry.path;
  }
  if (reflectApply(mapGet, purposeCounts, ["entrypoint"]) !== 1
      || reflectApply(mapGet, purposeCounts, ["config_manifest"]) !== 1
      || reflectApply(mapGet, purposeCounts, ["runtime"]) !== 1) {
    throw new Error(`${label} requires exactly one entrypoint, config manifest, and runtime`);
  }
  const nativeAddonCount = reflectApply(mapGet, purposeCounts, ["native_addon"]) || 0;
  if (nativeAddonCount < 1 || nativeAddonCount > WORKER_BUNDLE_MAX_NATIVE_ADDONS) {
    throw new Error(`${label} native-addon count is outside its fixed bound`);
  }
  const normalized = deepFreeze({
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    bundle_id: assertToken(ownDataValue(input, "bundle_id", label), `${label}.bundle_id`, "worker-bundle"),
    role,
    entries,
  });
  if (bufferByteLength(safeCanonicalJson(normalized), "utf8") > WORKER_BUNDLE_MAX_MANIFEST_BYTES) {
    throw new Error(`${label} exceeds the fixed encoded-byte bound`);
  }
  return normalized;
}

function normalizeRootEvidence(input, label = "worker_bundle_root_evidence") {
  assertExactDataObject(input, label, ROOT_EVIDENCE_FIELDS);
  if (ownDataValue(input, "version", label) !== WORKER_BUNDLE_ATTESTATION_VERSION
      || ownDataValue(input, "directory_type", label) !== "directory") {
    throw new Error(`${label} version or directory type is invalid`);
  }
  const mode = assertInteger(ownDataValue(input, "mode", label), `${label}.mode`, 0, 0o777);
  if ((mode & 0o022) !== 0 || (mode & 0o500) !== 0o500) {
    throw new Error(`${label}.mode must be owner-rx and not group/world writable`);
  }
  if (ownDataValue(input, "immutable_flags_complete", label) !== true
      || ownDataValue(input, "root_immutable", label) !== true
      || ownDataValue(input, "native_resolution_complete", label) !== true) {
    throw new Error(`${label} immutability and native resolution must be complete`);
  }
  return deepFreeze({
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    root_path_digest: assertDigest(ownDataValue(input, "root_path_digest", label), `${label}.root_path_digest`),
    directory_type: "directory",
    directory_identity_digest: assertDigest(
      ownDataValue(input, "directory_identity_digest", label),
      `${label}.directory_identity_digest`,
    ),
    owner_uid: assertInteger(ownDataValue(input, "owner_uid", label), `${label}.owner_uid`, 0, 2 ** 32 - 2),
    owner_gid: assertInteger(ownDataValue(input, "owner_gid", label), `${label}.owner_gid`, 0, 2 ** 32 - 2),
    mode,
    nlink: assertInteger(ownDataValue(input, "nlink", label), `${label}.nlink`, 2, 2 ** 32 - 2),
    mount_identity_scheme: assertIdentifier(
      ownDataValue(input, "mount_identity_scheme", label),
      `${label}.mount_identity_scheme`,
    ),
    mount_identity_digest: assertDigest(
      ownDataValue(input, "mount_identity_digest", label),
      `${label}.mount_identity_digest`,
    ),
    filesystem_identity_scheme: assertIdentifier(
      ownDataValue(input, "filesystem_identity_scheme", label),
      `${label}.filesystem_identity_scheme`,
    ),
    filesystem_identity_digest: assertDigest(
      ownDataValue(input, "filesystem_identity_digest", label),
      `${label}.filesystem_identity_digest`,
    ),
    immutability_scheme: assertIdentifier(
      ownDataValue(input, "immutability_scheme", label),
      `${label}.immutability_scheme`,
    ),
    immutable_flags_digest: assertDigest(
      ownDataValue(input, "immutable_flags_digest", label),
      `${label}.immutable_flags_digest`,
    ),
    immutable_flags_complete: true,
    read_only_mount: assertBoolean(ownDataValue(input, "read_only_mount", label), `${label}.read_only_mount`),
    root_immutable: true,
    native_resolution_complete: true,
  });
}

function manifestEntryForPurpose(manifest, purpose) {
  const matches = [];
  for (const entry of manifest.entries) {
    if (entry.purpose === purpose) matches[matches.length] = entry;
  }
  return matches;
}

function workerBundleEntryIdentityDigest(entryInput) {
  const entry = normalizeEntry(entryInput, 0);
  return safeHash({
    domain: WORKER_BUNDLE_ENTRY_IDENTITY_DOMAIN,
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    entry,
  });
}

function workerBundleManifestDigest(manifestInput) {
  const manifest = normalizeWorkerBundleManifest(manifestInput);
  return safeHash({
    domain: WORKER_BUNDLE_MANIFEST_DOMAIN,
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    manifest,
  });
}

function derivedManifestIdentities(manifest) {
  const entrypoint = manifestEntryForPurpose(manifest, "entrypoint")[0];
  const configManifest = manifestEntryForPurpose(manifest, "config_manifest")[0];
  const runtime = manifestEntryForPurpose(manifest, "runtime")[0];
  const nativeAddons = manifestEntryForPurpose(manifest, "native_addon");
  const nativeAddonIdentities = [];
  for (const entry of nativeAddons) {
    nativeAddonIdentities[nativeAddonIdentities.length] = workerBundleEntryIdentityDigest(entry);
  }
  return deepFreeze({
    entrypoint_digest: entrypoint.content_digest,
    config_manifest_digest: configManifest.content_digest,
    native_addon_set_digest: safeHash({
      domain: WORKER_BUNDLE_NATIVE_ADDON_SET_DOMAIN,
      version: WORKER_BUNDLE_ATTESTATION_VERSION,
      native_addon_entry_identity_digests: nativeAddonIdentities,
    }),
    runtime_identity_digest: workerBundleEntryIdentityDigest(runtime),
  });
}

function assertEntryOwnership(manifest, rootEvidence, label) {
  for (const entry of manifest.entries) {
    if (entry.owner_uid !== rootEvidence.owner_uid || entry.owner_gid !== rootEvidence.owner_gid) {
      throw new Error(`${label} entry ownership drifts from the bundle root`);
    }
  }
}

function workerBundleImmutabilityEvidenceDigest(manifestInput, rootEvidenceInput) {
  const manifest = normalizeWorkerBundleManifest(manifestInput);
  const rootEvidence = normalizeRootEvidence(rootEvidenceInput);
  assertEntryOwnership(manifest, rootEvidence, "worker_bundle_immutability");
  return safeHash({
    domain: WORKER_BUNDLE_IMMUTABILITY_DOMAIN,
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    manifest_digest: workerBundleManifestDigest(manifest),
    root_evidence: rootEvidence,
  });
}

function workerBundleLaunchFields(manifestInput, rootEvidenceInput) {
  const manifest = normalizeWorkerBundleManifest(manifestInput);
  const rootEvidence = normalizeRootEvidence(rootEvidenceInput);
  assertEntryOwnership(manifest, rootEvidence, "worker_bundle_launch_fields");
  const identities = derivedManifestIdentities(manifest);
  return deepFreeze({
    bundle_immutability_scheme: WORKER_BUNDLE_IMMUTABILITY_SCHEME,
    bundle_immutability_evidence_digest: workerBundleImmutabilityEvidenceDigest(
      manifest,
      rootEvidence,
    ),
    bundle_immutability_complete: true,
    bundle_manifest_digest: workerBundleManifestDigest(manifest),
    entrypoint_digest: identities.entrypoint_digest,
    config_manifest_digest: identities.config_manifest_digest,
  });
}

function authorityStateBasis(input, label) {
  return deepFreeze({
    authority_id: assertToken(ownDataValue(input, "authority_id", label), `${label}.authority_id`, "bundle-authority"),
    authority_key_id: assertToken(ownDataValue(input, "authority_key_id", label), `${label}.authority_key_id`, "bundle-key"),
    authority_public_key_digest: assertDigest(
      ownDataValue(input, "authority_public_key_digest", label),
      `${label}.authority_public_key_digest`,
    ),
    authority_trust_root_epoch: assertInteger(
      ownDataValue(input, "authority_trust_root_epoch", label),
      `${label}.authority_trust_root_epoch`,
      1,
    ),
    authority_epoch: assertInteger(ownDataValue(input, "authority_epoch", label), `${label}.authority_epoch`, 1),
    authority_generation: assertInteger(
      ownDataValue(input, "authority_generation", label),
      `${label}.authority_generation`,
      1,
    ),
    revocation_generation: assertInteger(
      ownDataValue(input, "revocation_generation", label),
      `${label}.revocation_generation`,
      0,
    ),
    revocation_state_digest: assertDigest(
      ownDataValue(input, "revocation_state_digest", label),
      `${label}.revocation_state_digest`,
    ),
    anchor_digest: assertDigest(ownDataValue(input, "anchor_digest", label), `${label}.anchor_digest`),
    trusted_clock_digest: assertDigest(
      ownDataValue(input, "trusted_clock_digest", label),
      `${label}.trusted_clock_digest`,
    ),
    runtime_epoch_digest: assertDigest(
      ownDataValue(input, "runtime_epoch_digest", label),
      `${label}.runtime_epoch_digest`,
    ),
    hil_qualification_digest: assertDigest(
      ownDataValue(input, "hil_qualification_digest", label),
      `${label}.hil_qualification_digest`,
    ),
  });
}

function workerBundleAuthorityStateDigest(input) {
  const authority = authorityStateBasis(input, "worker_bundle_authority_state");
  return safeHash({
    domain: WORKER_BUNDLE_AUTHORITY_STATE_DOMAIN,
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    authority,
  });
}

function normalizeWorkerBundleEnrollmentPayload(input, label = "worker_bundle_enrollment.payload") {
  assertExactDataObject(input, label, ENROLLMENT_PAYLOAD_FIELDS);
  if (ownDataValue(input, "version", label) !== WORKER_BUNDLE_ATTESTATION_VERSION) {
    throw new Error(`${label}.version is invalid`);
  }
  const manifest = normalizeWorkerBundleManifest(ownDataValue(input, "manifest", label), `${label}.manifest`);
  const rootEvidence = normalizeRootEvidence(ownDataValue(input, "root_evidence", label), `${label}.root_evidence`);
  assertEntryOwnership(manifest, rootEvidence, label);
  const bundleId = assertToken(ownDataValue(input, "bundle_id", label), `${label}.bundle_id`, "worker-bundle");
  const role = ownDataValue(input, "role", label);
  if (bundleId !== manifest.bundle_id || role !== manifest.role
      || !reflectApply(setHas, ROLE_SET, [role])) {
    throw new Error(`${label} bundle or role drifted from its manifest`);
  }
  const manifestDigest = workerBundleManifestDigest(manifest);
  const immutabilityDigest = workerBundleImmutabilityEvidenceDigest(manifest, rootEvidence);
  const identities = derivedManifestIdentities(manifest);
  const launchFields = workerBundleLaunchFields(manifest, rootEvidence);
  if (ownDataValue(input, "attestation_assurance", label) !== "caller_injected_conformance_only"
      || ownDataValue(input, "production_ready", label) !== false
      || ownDataValue(input, "separate_identity_authorized", label) !== false
      || ownDataValue(input, "hardware_authorized", label) !== false) {
    throw new Error(`${label} cannot claim production, separate-identity, or hardware authority`);
  }
  if (ownDataValue(input, "manifest_digest", label) !== manifestDigest
      || ownDataValue(input, "bundle_immutability_scheme", label) !== WORKER_BUNDLE_IMMUTABILITY_SCHEME
      || ownDataValue(input, "bundle_immutability_evidence_digest", label) !== immutabilityDigest
      || ownDataValue(input, "bundle_immutability_complete", label) !== true
      || ownDataValue(input, "entrypoint_digest", label) !== identities.entrypoint_digest
      || ownDataValue(input, "config_manifest_digest", label) !== identities.config_manifest_digest
      || ownDataValue(input, "native_addon_set_digest", label) !== identities.native_addon_set_digest
      || ownDataValue(input, "runtime_identity_digest", label) !== identities.runtime_identity_digest
      || launchFields.bundle_manifest_digest !== manifestDigest
      || launchFields.bundle_immutability_evidence_digest !== immutabilityDigest) {
    throw new Error(`${label} derived bundle identities are inconsistent`);
  }
  const authority = authorityStateBasis(input, label);
  const authorityStateDigest = assertDigest(
    ownDataValue(input, "authority_state_digest", label),
    `${label}.authority_state_digest`,
  );
  if (authorityStateDigest !== workerBundleAuthorityStateDigest(authority)) {
    throw new Error(`${label}.authority_state_digest is invalid`);
  }
  const issuedAt = assertCanonicalTimestamp(ownDataValue(input, "issued_at", label), `${label}.issued_at`);
  const expiresAt = assertCanonicalTimestamp(ownDataValue(input, "expires_at", label), `${label}.expires_at`);
  const lifetime = reflectApply(dateParse, Date, [expiresAt]) - reflectApply(dateParse, Date, [issuedAt]);
  if (lifetime <= 0 || lifetime > WORKER_BUNDLE_MAX_LIFETIME_MS) {
    throw new Error(`${label} lifetime is outside its fixed bound`);
  }
  const normalized = deepFreeze({
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    enrollment_id: assertToken(
      ownDataValue(input, "enrollment_id", label),
      `${label}.enrollment_id`,
      "bundle-enrollment",
    ),
    bundle_id: bundleId,
    role,
    attestation_assurance: "caller_injected_conformance_only",
    production_ready: false,
    separate_identity_authorized: false,
    hardware_authorized: false,
    manifest,
    manifest_digest: manifestDigest,
    root_evidence: rootEvidence,
    bundle_immutability_scheme: WORKER_BUNDLE_IMMUTABILITY_SCHEME,
    bundle_immutability_evidence_digest: immutabilityDigest,
    bundle_immutability_complete: true,
    ...identities,
    ...authority,
    authority_state_digest: authorityStateDigest,
    issued_at: issuedAt,
    expires_at: expiresAt,
    nonce: assertNonce(ownDataValue(input, "nonce", label), `${label}.nonce`),
  });
  if (bufferByteLength(safeCanonicalJson(normalized), "utf8") > WORKER_BUNDLE_MAX_ENROLLMENT_BYTES) {
    throw new Error(`${label} exceeds the fixed encoded-byte bound`);
  }
  return normalized;
}

function signatureMessage(payloadDigest) {
  return bufferFrom(
    `${WORKER_BUNDLE_ENROLLMENT_SIGNATURE_DOMAIN}\0${assertDigest(payloadDigest, "payload_digest")}`,
    "utf8",
  );
}

function normalizeAuthentication(input, payload) {
  const label = "signed_worker_bundle_enrollment.authentication";
  assertExactDataObject(input, label, AUTHENTICATION_FIELDS);
  const authentication = deepFreeze({
    scheme: ownDataValue(input, "scheme", label),
    key_usage: ownDataValue(input, "key_usage", label),
    authority_key_id: assertToken(
      ownDataValue(input, "authority_key_id", label),
      `${label}.authority_key_id`,
      "bundle-key",
    ),
    authority_public_key_digest: assertDigest(
      ownDataValue(input, "authority_public_key_digest", label),
      `${label}.authority_public_key_digest`,
    ),
    signed_payload_digest: assertDigest(
      ownDataValue(input, "signed_payload_digest", label),
      `${label}.signed_payload_digest`,
    ),
    signature: assertSignature(ownDataValue(input, "signature", label), `${label}.signature`),
  });
  if (authentication.scheme !== "ed25519"
      || authentication.key_usage !== WORKER_BUNDLE_ENROLLMENT_KEY_USAGE
      || authentication.authority_key_id !== payload.authority_key_id
      || authentication.authority_public_key_digest !== payload.authority_public_key_digest
      || authentication.signed_payload_digest !== safeHash(payload)) {
    throw new Error(`${label} is not bound to the enrollment authority and payload`);
  }
  return authentication;
}

function normalizeSignedWorkerBundleEnrollment(input) {
  const label = "signed_worker_bundle_enrollment";
  assertExactDataObject(input, label, SIGNED_ENROLLMENT_FIELDS);
  if (ownDataValue(input, "version", label) !== WORKER_BUNDLE_ATTESTATION_VERSION
      || ownDataValue(input, "kind", label) !== "worker_bundle_enrollment"
      || ownDataValue(input, "domain", label) !== WORKER_BUNDLE_ENROLLMENT_DOMAIN) {
    throw new Error(`${label} version, kind, or domain is invalid`);
  }
  const payload = normalizeWorkerBundleEnrollmentPayload(ownDataValue(input, "payload", label));
  const payloadDigest = safeHash(payload);
  if (ownDataValue(input, "payload_digest", label) !== payloadDigest) {
    throw new Error(`${label}.payload_digest is invalid`);
  }
  const authentication = normalizeAuthentication(ownDataValue(input, "authentication", label), payload);
  const basis = deepFreeze({
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    kind: "worker_bundle_enrollment",
    domain: WORKER_BUNDLE_ENROLLMENT_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    authentication,
  });
  const enrollmentDigest = assertDigest(
    ownDataValue(input, "enrollment_digest", label),
    `${label}.enrollment_digest`,
  );
  if (enrollmentDigest !== safeHash(basis)) throw new Error(`${label}.enrollment_digest is invalid`);
  return deepFreeze({ ...basis, enrollment_digest: enrollmentDigest });
}

function conformanceProjection(kind, portId, extra = {}) {
  return deepFreeze({
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
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

function createConformanceWorkerBundleEnrollmentSigner(input = {}) {
  const label = "conformance_worker_bundle_enrollment_signer";
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
    "worker_bundle_enrollment_signer",
    assertIdentifier(ownDataValue(input, "port_id", label), `${label}.port_id`),
    {
      authority_id: authority.authority_id,
      authority_state_digest: workerBundleAuthorityStateDigest(authority),
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
  if (port == null || typeof port !== "object" || utilTypes.isProxy(port)
      || !objectIsFrozen(port) || !reflectApply(weakSetHas, ports, [port])
      || !reflectApply(weakMapHas, privatePorts, [port])) {
    throw new Error(`${label} must be a privately branded conformance port`);
  }
  return port;
}

function assertConformanceWorkerBundleEnrollmentSigner(port) {
  return assertPrivatePort(port, SIGNER_PORTS, SIGNER_PRIVATE, "worker bundle enrollment signer");
}

function signWorkerBundleEnrollment(port, payloadInput) {
  assertConformanceWorkerBundleEnrollmentSigner(port);
  const payload = normalizeWorkerBundleEnrollmentPayload(payloadInput);
  const state = reflectApply(weakMapGet, SIGNER_PRIVATE, [port]);
  const authority = authorityStateBasis(payload, "worker_bundle_enrollment.payload");
  if (safeHash(authority) !== safeHash(state.authority)
      || payload.authority_state_digest !== port.authority_state_digest) {
    throw new Error("worker bundle enrollment drifted from signer authority state");
  }
  const payloadDigest = safeHash(payload);
  const authentication = deepFreeze({
    scheme: "ed25519",
    key_usage: WORKER_BUNDLE_ENROLLMENT_KEY_USAGE,
    authority_key_id: payload.authority_key_id,
    authority_public_key_digest: payload.authority_public_key_digest,
    signed_payload_digest: payloadDigest,
    signature: reflectApply(bufferToString, reflectApply(cryptoSign, crypto, [
      null,
      signatureMessage(payloadDigest),
      state.private_key,
    ]), ["base64url"]),
  });
  const basis = deepFreeze({
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    kind: "worker_bundle_enrollment",
    domain: WORKER_BUNDLE_ENROLLMENT_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    authentication,
  });
  return deepFreeze({ ...basis, enrollment_digest: safeHash(basis) });
}

function assertFunction(value, label) {
  if (typeof value !== "function" || utilTypes.isProxy(value)) {
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
  const callback = assertFunction(
    ownDataValue(input, callbackField, label),
    `${label}.${callbackField}`,
  );
  reflectApply(weakSetAdd, ports, [port]);
  reflectApply(weakMapSet, privatePorts, [port, objectFreeze({ callback })]);
  return port;
}

function createConformanceWorkerBundleAuthorityResolver(input = {}) {
  return createCallbackPort(
    input,
    "conformance_worker_bundle_authority_resolver",
    "resolve_current_authority",
    "worker_bundle_current_authority_resolver",
    AUTHORITY_RESOLVER_PORTS,
    AUTHORITY_RESOLVER_PRIVATE,
  );
}

function createConformanceWorkerBundleNativeSnapshotResolver(input = {}) {
  return createCallbackPort(
    input,
    "conformance_worker_bundle_native_snapshot_resolver",
    "resolve_live_bundle",
    "worker_bundle_native_live_snapshot_resolver",
    LIVE_RESOLVER_PORTS,
    LIVE_RESOLVER_PRIVATE,
  );
}

function createConformanceWorkerBundleReservationPort(input = {}) {
  return createCallbackPort(
    input,
    "conformance_worker_bundle_reservation_port",
    "reserve_once",
    "worker_bundle_one_use_reservation",
    RESERVATION_PORTS,
    RESERVATION_PRIVATE,
  );
}

function assertConformanceWorkerBundleAuthorityResolver(port) {
  return assertPrivatePort(
    port,
    AUTHORITY_RESOLVER_PORTS,
    AUTHORITY_RESOLVER_PRIVATE,
    "worker bundle authority resolver",
  );
}

function assertConformanceWorkerBundleNativeSnapshotResolver(port) {
  return assertPrivatePort(
    port,
    LIVE_RESOLVER_PORTS,
    LIVE_RESOLVER_PRIVATE,
    "worker bundle native snapshot resolver",
  );
}

function assertConformanceWorkerBundleReservationPort(port) {
  return assertPrivatePort(
    port,
    RESERVATION_PORTS,
    RESERVATION_PRIVATE,
    "worker bundle reservation port",
  );
}

function callPort(port, privatePorts, query, label) {
  if (reflectApply(weakSetHas, ACTIVE_CALLBACKS, [port])) {
    throw new Error(`${label} cannot re-enter its port`);
  }
  reflectApply(weakSetAdd, ACTIVE_CALLBACKS, [port]);
  try {
    const state = reflectApply(weakMapGet, privatePorts, [port]);
    const result = reflectApply(state.callback, undefined, [deepFreeze(query)]);
    if (utilTypes.isPromise(result) || utilTypes.isProxy(result)) {
      throw new Error(`${label} must return a synchronous own-data object`);
    }
    return result;
  } finally {
    reflectApply(weakSetDelete, ACTIVE_CALLBACKS, [port]);
  }
}

function normalizeCurrentAuthority(input) {
  const label = "current_worker_bundle_authority";
  assertExactDataObject(input, label, CURRENT_AUTHORITY_FIELDS);
  if (ownDataValue(input, "version", label) !== WORKER_BUNDLE_ATTESTATION_VERSION
      || ownDataValue(input, "trusted", label) !== true
      || ownDataValue(input, "revoked", label) !== false) {
    throw new Error(`${label} is not trusted and active`);
  }
  const authority = authorityStateBasis(input, label);
  const publicKey = assertEd25519Key(
    ownDataValue(input, "authority_public_key", label),
    "public",
    `${label}.authority_public_key`,
  );
  if (publicKeyDigest(publicKey) !== authority.authority_public_key_digest) {
    throw new Error(`${label} public key is invalid`);
  }
  const stateDigest = assertDigest(
    ownDataValue(input, "authority_state_digest", label),
    `${label}.authority_state_digest`,
  );
  if (stateDigest !== workerBundleAuthorityStateDigest(authority)) {
    throw new Error(`${label} state digest is invalid`);
  }
  return deepFreeze({
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    trusted: true,
    revoked: false,
    ...authority,
    authority_state_digest: stateDigest,
    authority_public_key: publicKey,
    current_enrollment_digest: assertDigest(
      ownDataValue(input, "current_enrollment_digest", label),
      `${label}.current_enrollment_digest`,
    ),
    current_manifest_digest: assertDigest(
      ownDataValue(input, "current_manifest_digest", label),
      `${label}.current_manifest_digest`,
    ),
    current_bundle_immutability_evidence_digest: assertDigest(
      ownDataValue(input, "current_bundle_immutability_evidence_digest", label),
      `${label}.current_bundle_immutability_evidence_digest`,
    ),
    trusted_now: assertCanonicalTimestamp(
      ownDataValue(input, "trusted_now", label),
      `${label}.trusted_now`,
    ),
  });
}

function normalizeLiveSnapshotBasis(input, label = "live_worker_bundle_snapshot") {
  assertExactDataObject(input, label, LIVE_SNAPSHOT_BASIS_FIELDS);
  if (ownDataValue(input, "version", label) !== WORKER_BUNDLE_ATTESTATION_VERSION) {
    throw new Error(`${label}.version is invalid`);
  }
  const manifest = normalizeWorkerBundleManifest(ownDataValue(input, "manifest", label), `${label}.manifest`);
  const rootEvidence = normalizeRootEvidence(ownDataValue(input, "root_evidence", label), `${label}.root_evidence`);
  assertEntryOwnership(manifest, rootEvidence, label);
  const identities = derivedManifestIdentities(manifest);
  const launchFields = workerBundleLaunchFields(manifest, rootEvidence);
  const bundleId = assertToken(ownDataValue(input, "bundle_id", label), `${label}.bundle_id`, "worker-bundle");
  const role = ownDataValue(input, "role", label);
  if (!reflectApply(setHas, ROLE_SET, [role])
      || role !== manifest.role || bundleId !== manifest.bundle_id) {
    throw new Error(`${label} role or bundle drifted from the manifest`);
  }
  if (ownDataValue(input, "manifest_digest", label) !== launchFields.bundle_manifest_digest
      || ownDataValue(input, "bundle_immutability_scheme", label) !== launchFields.bundle_immutability_scheme
      || ownDataValue(input, "bundle_immutability_evidence_digest", label)
        !== launchFields.bundle_immutability_evidence_digest
      || ownDataValue(input, "bundle_immutability_complete", label) !== true
      || ownDataValue(input, "entrypoint_digest", label) !== identities.entrypoint_digest
      || ownDataValue(input, "config_manifest_digest", label) !== identities.config_manifest_digest
      || ownDataValue(input, "native_addon_set_digest", label) !== identities.native_addon_set_digest
      || ownDataValue(input, "runtime_identity_digest", label) !== identities.runtime_identity_digest) {
    throw new Error(`${label} derived identities are inconsistent`);
  }
  return deepFreeze({
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    enrollment_digest: assertDigest(
      ownDataValue(input, "enrollment_digest", label),
      `${label}.enrollment_digest`,
    ),
    bundle_id: bundleId,
    role,
    manifest,
    manifest_digest: launchFields.bundle_manifest_digest,
    root_evidence: rootEvidence,
    bundle_immutability_scheme: launchFields.bundle_immutability_scheme,
    bundle_immutability_evidence_digest: launchFields.bundle_immutability_evidence_digest,
    bundle_immutability_complete: true,
    ...identities,
  });
}

function workerBundleLiveSnapshotDigest(resolverId, snapshotBasisInput) {
  const portId = assertIdentifier(resolverId, "worker_bundle_live_snapshot.resolver_id");
  const snapshot = normalizeLiveSnapshotBasis(snapshotBasisInput);
  return safeHash({
    domain: WORKER_BUNDLE_LIVE_SNAPSHOT_DOMAIN,
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    resolver_id: portId,
    snapshot,
  });
}

function normalizeLiveSnapshot(input, resolverId) {
  const label = "live_worker_bundle_snapshot";
  assertExactDataObject(input, label, LIVE_SNAPSHOT_FIELDS);
  const basisInput = {};
  for (const field of LIVE_SNAPSHOT_BASIS_FIELDS) {
    basisInput[field] = ownDataValue(input, field, label);
  }
  const basis = normalizeLiveSnapshotBasis(basisInput, label);
  const snapshotDigest = assertDigest(
    ownDataValue(input, "snapshot_digest", label),
    `${label}.snapshot_digest`,
  );
  if (snapshotDigest !== workerBundleLiveSnapshotDigest(resolverId, basis)) {
    throw new Error(`${label}.snapshot_digest is invalid`);
  }
  return deepFreeze({ ...basis, snapshot_digest: snapshotDigest });
}

function assertAuthorityBinding(enrollment, current) {
  const payload = enrollment.payload;
  for (const field of AUTHORITY_STATE_FIELDS) {
    if (payload[field] !== current[field]) throw new Error("worker bundle authority drifted");
  }
  if (payload.authority_state_digest !== current.authority_state_digest
      || enrollment.enrollment_digest !== current.current_enrollment_digest
      || payload.manifest_digest !== current.current_manifest_digest
      || payload.bundle_immutability_evidence_digest
        !== current.current_bundle_immutability_evidence_digest) {
    throw new Error("worker bundle authority binding forked or drifted");
  }
}

function assertLiveBinding(enrollment, snapshot) {
  const payload = enrollment.payload;
  if (snapshot.enrollment_digest !== enrollment.enrollment_digest
      || snapshot.bundle_id !== payload.bundle_id || snapshot.role !== payload.role
      || snapshot.manifest_digest !== payload.manifest_digest
      || snapshot.bundle_immutability_scheme !== payload.bundle_immutability_scheme
      || snapshot.bundle_immutability_evidence_digest
        !== payload.bundle_immutability_evidence_digest
      || snapshot.bundle_immutability_complete !== payload.bundle_immutability_complete
      || snapshot.entrypoint_digest !== payload.entrypoint_digest
      || snapshot.config_manifest_digest !== payload.config_manifest_digest
      || snapshot.native_addon_set_digest !== payload.native_addon_set_digest
      || snapshot.runtime_identity_digest !== payload.runtime_identity_digest
      || safeCanonicalJson(snapshot.manifest) !== safeCanonicalJson(payload.manifest)
      || safeCanonicalJson(snapshot.root_evidence) !== safeCanonicalJson(payload.root_evidence)) {
    throw new Error("live worker bundle drifted from enrollment");
  }
}

function assertFresh(payload, trustedNow) {
  const now = reflectApply(dateParse, Date, [trustedNow]);
  const issued = reflectApply(dateParse, Date, [payload.issued_at]);
  const expires = reflectApply(dateParse, Date, [payload.expires_at]);
  if (issued > now + WORKER_BUNDLE_MAX_CLOCK_SKEW_MS || now >= expires) {
    throw new Error("worker bundle enrollment is stale or future-dated");
  }
}

function workerBundleReservationClaim(enrollment) {
  const payload = enrollment.payload;
  const basis = deepFreeze({
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    enrollment_digest: enrollment.enrollment_digest,
    payload_digest: enrollment.payload_digest,
    bundle_id: payload.bundle_id,
    role: payload.role,
    manifest_digest: payload.manifest_digest,
    bundle_immutability_evidence_digest: payload.bundle_immutability_evidence_digest,
    authority_state_digest: payload.authority_state_digest,
    authority_generation: payload.authority_generation,
    nonce_digest: safeHash({ nonce: payload.nonce }),
    expires_at: payload.expires_at,
  });
  return deepFreeze({
    ...basis,
    claim_digest: safeHash({ domain: WORKER_BUNDLE_RESERVATION_CLAIM_DOMAIN, claim: basis }),
  });
}

function workerBundleReservationReceiptDigest(reservationPortId, receiptBasisInput) {
  const portId = assertIdentifier(reservationPortId, "worker_bundle_reservation_receipt.port_id");
  const label = "worker_bundle_reservation_receipt";
  assertExactDataObject(receiptBasisInput, label, [
    "version", "disposition", "claim_digest", "reservation_generation",
  ]);
  const basis = deepFreeze({
    version: ownDataValue(receiptBasisInput, "version", label),
    disposition: ownDataValue(receiptBasisInput, "disposition", label),
    claim_digest: assertDigest(
      ownDataValue(receiptBasisInput, "claim_digest", label),
      `${label}.claim_digest`,
    ),
    reservation_generation: assertInteger(
      ownDataValue(receiptBasisInput, "reservation_generation", label),
      `${label}.reservation_generation`,
      1,
    ),
  });
  if (basis.version !== WORKER_BUNDLE_ATTESTATION_VERSION
      || !reflectApply(arrayIncludes, ["reserved", "replay", "fork", "stale"], [
        basis.disposition,
      ])) {
    throw new Error(`${label} version or disposition is invalid`);
  }
  return safeHash({
    domain: WORKER_BUNDLE_RESERVATION_RECEIPT_DOMAIN,
    reservation_port_id: portId,
    receipt: basis,
  });
}

function normalizeReservationReceipt(input, reservationPort, claim) {
  const label = "worker_bundle_reservation_receipt";
  assertExactDataObject(input, label, [
    "version", "disposition", "claim_digest", "reservation_generation", "receipt_digest",
  ]);
  const basis = {
    version: ownDataValue(input, "version", label),
    disposition: ownDataValue(input, "disposition", label),
    claim_digest: ownDataValue(input, "claim_digest", label),
    reservation_generation: ownDataValue(input, "reservation_generation", label),
  };
  const expectedDigest = workerBundleReservationReceiptDigest(reservationPort.port_id, basis);
  if (ownDataValue(input, "receipt_digest", label) !== expectedDigest
      || basis.disposition !== "reserved" || basis.claim_digest !== claim.claim_digest) {
    throw new Error("worker bundle enrollment was not reserved exactly once");
  }
  return deepFreeze({ ...basis, receipt_digest: expectedDigest });
}

function workerBundleAttestationRejected() {
  const error = new Error("Worker bundle attestation was rejected");
  Object.defineProperty(error, "code", {
    value: "worker_bundle_attestation_rejected",
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return error;
}

function verifyAndReserveWorkerBundleEnrollment(input = {}) {
  try {
    const label = "worker_bundle_verification";
    assertExactDataObject(input, label, [
      "enrollment", "authority_resolver_port", "native_snapshot_resolver_port", "reservation_port",
    ]);
    const authorityPort = assertConformanceWorkerBundleAuthorityResolver(
      ownDataValue(input, "authority_resolver_port", label),
    );
    const livePort = assertConformanceWorkerBundleNativeSnapshotResolver(
      ownDataValue(input, "native_snapshot_resolver_port", label),
    );
    const reservationPort = assertConformanceWorkerBundleReservationPort(
      ownDataValue(input, "reservation_port", label),
    );
    const enrollment = normalizeSignedWorkerBundleEnrollment(ownDataValue(input, "enrollment", label));
    const liveQuery = deepFreeze({
      version: WORKER_BUNDLE_ATTESTATION_VERSION,
      purpose: "resolve_exact_live_worker_bundle",
      enrollment_digest: enrollment.enrollment_digest,
      manifest_digest: enrollment.payload.manifest_digest,
      bundle_id: enrollment.payload.bundle_id,
      role: enrollment.payload.role,
    });
    const liveBefore = normalizeLiveSnapshot(callPort(
      livePort,
      LIVE_RESOLVER_PRIVATE,
      liveQuery,
      "worker bundle native live resolver",
    ), livePort.port_id);
    assertLiveBinding(enrollment, liveBefore);
    const current = normalizeCurrentAuthority(callPort(
      authorityPort,
      AUTHORITY_RESOLVER_PRIVATE,
      {
        version: WORKER_BUNDLE_ATTESTATION_VERSION,
        purpose: "resolve_exact_current_worker_bundle_authority",
        enrollment_digest: enrollment.enrollment_digest,
      },
      "worker bundle authority resolver",
    ));
    assertAuthorityBinding(enrollment, current);
    if (!reflectApply(cryptoVerify, crypto, [
      null,
      signatureMessage(enrollment.payload_digest),
      current.authority_public_key,
      bufferFrom(enrollment.authentication.signature, "base64url"),
    ])) throw new Error("worker bundle enrollment signature is invalid");
    assertFresh(enrollment.payload, current.trusted_now);
    const claim = workerBundleReservationClaim(enrollment);
    let receipt = null;
    let reservationRejected = false;
    try {
      receipt = normalizeReservationReceipt(callPort(
        reservationPort,
        RESERVATION_PRIVATE,
        claim,
        "worker bundle one-use reservation",
      ), reservationPort, claim);
    } catch {
      // A reservation callback can commit before losing or corrupting its reply. The
      // current authority read-back below is mandatory after every invocation.
      reservationRejected = true;
    }
    const currentAfter = normalizeCurrentAuthority(callPort(
      authorityPort,
      AUTHORITY_RESOLVER_PRIVATE,
      {
        version: WORKER_BUNDLE_ATTESTATION_VERSION,
        purpose: "revalidate_exact_current_worker_bundle_authority_after_reservation",
        enrollment_digest: enrollment.enrollment_digest,
        reservation_claim_digest: claim.claim_digest,
        reservation_receipt_digest: receipt == null ? null : receipt.receipt_digest,
      },
      "post-reservation worker bundle authority resolver",
    ));
    assertAuthorityBinding(enrollment, currentAfter);
    if (reflectApply(dateParse, Date, [currentAfter.trusted_now])
        < reflectApply(dateParse, Date, [current.trusted_now])) {
      throw new Error("worker bundle trusted time moved backwards");
    }
    assertFresh(enrollment.payload, currentAfter.trusted_now);
    if (reservationRejected || receipt == null) {
      throw new Error("worker bundle one-use reservation was not confirmed");
    }
    const liveAfter = normalizeLiveSnapshot(callPort(
      livePort,
      LIVE_RESOLVER_PRIVATE,
      liveQuery,
      "worker bundle native live resolver",
    ), livePort.port_id);
    assertLiveBinding(enrollment, liveAfter);
    if (liveBefore.snapshot_digest !== liveAfter.snapshot_digest
        || safeCanonicalJson(liveBefore) !== safeCanonicalJson(liveAfter)) {
      throw new Error("live worker bundle changed while enrollment was verified");
    }
    const launchFields = workerBundleLaunchFields(
      enrollment.payload.manifest,
      enrollment.payload.root_evidence,
    );
    const verified = deepFreeze({
      version: WORKER_BUNDLE_ATTESTATION_VERSION,
      enrollment_id: enrollment.payload.enrollment_id,
      enrollment_digest: enrollment.enrollment_digest,
      bundle_id: enrollment.payload.bundle_id,
      role: enrollment.payload.role,
      manifest_digest: enrollment.payload.manifest_digest,
      native_addon_set_digest: enrollment.payload.native_addon_set_digest,
      runtime_identity_digest: enrollment.payload.runtime_identity_digest,
      authority_state_digest: enrollment.payload.authority_state_digest,
      authority_epoch: enrollment.payload.authority_epoch,
      authority_generation: enrollment.payload.authority_generation,
      reservation_receipt_digest: receipt.receipt_digest,
      live_snapshot_digest: liveAfter.snapshot_digest,
      launch_attestation_bundle_fields: launchFields,
      assurance: "signed_double_live_resolved_reserved_conformance_only",
      production_ready: false,
      separate_identity_authorized: false,
      hardware_authorized: false,
      production_blockers: CONFORMANCE_BLOCKERS,
    });
    reflectApply(weakSetAdd, VERIFIED_ENROLLMENTS, [verified]);
    return verified;
  } catch {
    throw workerBundleAttestationRejected();
  }
}

function assertVerifiedWorkerBundleEnrollment(value) {
  if (value == null || typeof value !== "object" || utilTypes.isProxy(value)
      || !objectIsFrozen(value)
      || !reflectApply(weakSetHas, VERIFIED_ENROLLMENTS, [value])) {
    throw new Error("verified worker bundle must be a privately branded conformance result");
  }
  return value;
}

module.exports = {
  WORKER_BUNDLE_ATTESTATION_VERSION,
  WORKER_BUNDLE_AUTHORITY_STATE_DOMAIN,
  WORKER_BUNDLE_ENROLLMENT_DOMAIN,
  WORKER_BUNDLE_ENROLLMENT_KEY_USAGE,
  WORKER_BUNDLE_ENROLLMENT_SIGNATURE_DOMAIN,
  WORKER_BUNDLE_ENTRY_IDENTITY_DOMAIN,
  WORKER_BUNDLE_ENTRY_PURPOSES,
  WORKER_BUNDLE_IMMUTABILITY_DOMAIN,
  WORKER_BUNDLE_IMMUTABILITY_SCHEME,
  WORKER_BUNDLE_LIVE_SNAPSHOT_DOMAIN,
  WORKER_BUNDLE_MANIFEST_DOMAIN,
  WORKER_BUNDLE_MAX_CLOCK_SKEW_MS,
  WORKER_BUNDLE_MAX_ENTRIES,
  WORKER_BUNDLE_MAX_ENROLLMENT_BYTES,
  WORKER_BUNDLE_MAX_ENTRY_BYTES,
  WORKER_BUNDLE_MAX_LIFETIME_MS,
  WORKER_BUNDLE_MAX_MANIFEST_BYTES,
  WORKER_BUNDLE_MAX_NATIVE_ADDONS,
  WORKER_BUNDLE_MAX_PATH_BYTES,
  WORKER_BUNDLE_MAX_PATH_DEPTH,
  WORKER_BUNDLE_MAX_TOTAL_BYTES,
  WORKER_BUNDLE_NATIVE_ADDON_SET_DOMAIN,
  WORKER_BUNDLE_RESERVATION_CLAIM_DOMAIN,
  WORKER_BUNDLE_RESERVATION_RECEIPT_DOMAIN,
  WORKER_BUNDLE_ROLES,
  WORKER_BUNDLE_STATIC_CODE_NOT_APPLICABLE_DIGEST,
  assertConformanceWorkerBundleAuthorityResolver,
  assertConformanceWorkerBundleEnrollmentSigner,
  assertConformanceWorkerBundleNativeSnapshotResolver,
  assertConformanceWorkerBundleReservationPort,
  assertVerifiedWorkerBundleEnrollment,
  createConformanceWorkerBundleAuthorityResolver,
  createConformanceWorkerBundleEnrollmentSigner,
  createConformanceWorkerBundleNativeSnapshotResolver,
  createConformanceWorkerBundleReservationPort,
  normalizeSignedWorkerBundleEnrollment,
  normalizeWorkerBundleEnrollmentPayload,
  normalizeWorkerBundleManifest,
  signWorkerBundleEnrollment,
  verifyAndReserveWorkerBundleEnrollment,
  workerBundleAuthorityStateDigest,
  workerBundleEntryIdentityDigest,
  workerBundleImmutabilityEvidenceDigest,
  workerBundleLaunchFields,
  workerBundleLiveSnapshotDigest,
  workerBundleManifestDigest,
  workerBundleReservationReceiptDigest,
};
