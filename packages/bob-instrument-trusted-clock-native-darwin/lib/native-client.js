"use strict";

const crypto = require("node:crypto");
const hostProcess = require("node:process");
const { types: utilTypes } = require("node:util");

const SafeBigInt = BigInt;
const SafeError = Error;
const arrayIsArray = Array.isArray;
const bufferAlloc = Buffer.alloc;
const bufferFrom = Buffer.from;
const bufferWriteBigUInt64BE = Buffer.prototype.writeBigUInt64BE;
const cryptoCreateHash = crypto.createHash;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regExpTest = RegExp.prototype.test;
const utilTypesIsProxy = utilTypes.isProxy;
const weakMapGet = WeakMap.prototype.get;
const weakMapSet = WeakMap.prototype.set;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;

const OBJECT_PROTOTYPE = Object.prototype;
const HASH_PROTOTYPE = objectGetPrototypeOf(cryptoCreateHash("sha256"));
const HASH_UPDATE = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "update").value;
const HASH_DIGEST = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "digest").value;
const NATIVE_CACHE = require.cache;
const LOADER_PATH = require.resolve("./native-binding-loader.js");
const DARWIN_TRUSTED_CLOCK_SOURCE_VERSION = 1;
const DARWIN_TRUSTED_CLOCK_PROFILE = "darwin_arm64_trusted_clock_source_v1";
const DARWIN_TRUSTED_CLOCK_MONOTONIC_PRIMITIVE = "mach_continuous_time_v1";
const DARWIN_TRUSTED_CLOCK_BLOCKER =
  "signed_immutable_trusted_clock_native_attestation_and_provisioning_missing";
const DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_ASSURANCE =
  "local_source_build_receipt_non_authorizing";
const NATIVE_CLIENT_MARK = Symbol.for(
  "hacker-bob.instrument-trusted-clock-native-darwin.client-opened.v1",
);
const CLIENTS = new WeakSet();
const CLIENT_STATE = new WeakMap();
const SAMPLES = new WeakSet();
const LOADER_CACHE_TOMBSTONES = new WeakSet();
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const REQUEST_ID_PATTERN = /^[a-f0-9]{32}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;
const UINT64_MAX = 0xffff_ffff_ffff_ffffn;
const SAMPLE_DIGEST_DOMAIN = bufferFrom(
  "hacker-bob/darwin-trusted-clock-source-sample/v1\0",
  "utf8",
);
const NATIVE_SAMPLE_FIELDS = objectFreeze([
  "version",
  "source",
  "monotonic_ns",
  "request_id",
  "challenge_digest",
  "boot_epoch_digest",
  "service_identity_digest",
  "client_identity_digest",
  "enrollment_digest",
  "source_sample_digest",
]);
const NATIVE_CLIENT_BLOCKERS = objectFreeze([
  DARWIN_TRUSTED_CLOCK_BLOCKER,
  "trusted_clock_native_release_envelope_v3_or_separate_missing",
  "trusted_clock_node_api_loaded_image_attestation_and_signed_delivery_missing",
  "trusted_clock_dedicated_principal_and_socket_acl_unproven",
  "trusted_clock_signer_custody_unproven",
  "trusted_clock_restart_sleep_reboot_hil_missing",
  "trusted_clock_local_source_build_not_release_authenticated",
  "trusted_clock_immutable_root_owned_installation_missing",
  "trusted_clock_same_process_preimport_runtime_integrity_unproven",
  "trusted_clock_native_client_same_process_capability_custody_not_isolated",
]);
let loaderState = null;
let authenticLoader = null;

function nativeClientError(reasonCode = "trusted_clock_native_client_rejected") {
  const error = new SafeError("Darwin trusted-clock native client was rejected");
  objectDefineProperty(error, "code", {
    value: "darwin_trusted_clock_native_client_rejected",
    enumerable: false,
    writable: false,
    configurable: false,
  });
  objectDefineProperty(error, "reason_code", {
    value: reasonCode,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return error;
}

function reject(reasonCode) {
  throw nativeClientError(reasonCode);
}

function rejectSerialization() {
  reject("trusted_clock_native_capability_not_serializable");
}

function own(value, field, reasonCode) {
  const descriptor = objectGetOwnPropertyDescriptor(value, field);
  if (descriptor == null || !objectHasOwn(descriptor, "value")
      || descriptor.enumerable !== true) reject(reasonCode);
  return descriptor.value;
}

function hashParts(parts) {
  const hash = cryptoCreateHash("sha256");
  for (let index = 0; index < parts.length; index += 1) {
    reflectApply(HASH_UPDATE, hash, [parts[index]]);
  }
  return reflectApply(HASH_DIGEST, hash, ["hex"]);
}

function uint64Bytes(value) {
  const output = bufferAlloc(8);
  reflectApply(bufferWriteBigUInt64BE, output, [value, 0]);
  return output;
}

function computeNativeSampleDigest(value, monotonic) {
  return hashParts([
    SAMPLE_DIGEST_DOMAIN,
    bufferFrom(value.request_id, "hex"),
    bufferFrom(value.challenge_digest, "hex"),
    uint64Bytes(monotonic),
    bufferFrom(value.boot_epoch_digest, "hex"),
    bufferFrom(value.service_identity_digest, "hex"),
    bufferFrom(value.client_identity_digest, "hex"),
    bufferFrom(value.enrollment_digest, "hex"),
  ]);
}

function createLoaderCacheTombstone() {
  const tombstone = objectCreate(null);
  const fields = [
    ["version", 1],
    ["kind", "darwin_trusted_clock_loader_private_cache_tombstone"],
    ["callable_surface_exposed", false],
    ["production_ready", false],
  ];
  for (let index = 0; index < fields.length; index += 1) {
    objectDefineProperty(tombstone, fields[index][0], {
      value: fields[index][1],
      writable: false,
      enumerable: true,
      configurable: false,
    });
  }
  objectFreeze(tombstone);
  reflectApply(weakSetAdd, LOADER_CACHE_TOMBSTONES, [tombstone]);
  return tombstone;
}

function assertLoaderCacheTombstone(value) {
  if (value == null || typeof value !== "object" || utilTypesIsProxy(value)
      || objectGetPrototypeOf(value) !== null || !objectIsFrozen(value)
      || !reflectApply(weakSetHas, LOADER_CACHE_TOMBSTONES, [value])) {
    reject("native_loader_cache_tombstone_invalid");
  }
  const keys = reflectOwnKeys(value);
  const expected = [
    "version", "kind", "callable_surface_exposed", "production_ready",
  ];
  if (keys.length !== expected.length) reject("native_loader_cache_tombstone_invalid");
  for (let index = 0; index < expected.length; index += 1) {
    if (keys[index] !== expected[index]) reject("native_loader_cache_tombstone_invalid");
    const descriptor = objectGetOwnPropertyDescriptor(value, expected[index]);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.writable !== false || descriptor.enumerable !== true
        || descriptor.configurable !== false) {
      reject("native_loader_cache_tombstone_invalid");
    }
  }
  if (value.version !== 1
      || value.kind !== "darwin_trusted_clock_loader_private_cache_tombstone"
      || value.callable_surface_exposed !== false
      || value.production_ready !== false) {
    reject("native_loader_cache_tombstone_invalid");
  }
  return value;
}

function getAuthenticLoader() {
  if (loaderState != null) {
    const descriptor = objectGetOwnPropertyDescriptor(NATIVE_CACHE, LOADER_PATH);
    if (descriptor?.value !== loaderState.module_record
        || descriptor.writable !== false || descriptor.enumerable !== true
        || descriptor.configurable !== false
        || loaderState.module_record.exports !== loaderState.cache_exports) {
      reject("native_loader_cache_drift");
    }
    assertLoaderCacheTombstone(loaderState.cache_exports);
    return loaderState.load;
  }
  if (objectGetOwnPropertyDescriptor(NATIVE_CACHE, LOADER_PATH) != null) {
    reject("native_loader_cache_prepopulated");
  }
  let exportsValue;
  try {
    exportsValue = require(LOADER_PATH);
  } catch {
    reject("native_loader_load_failed");
  }
  const keys = exportsValue == null || typeof exportsValue !== "object"
    ? []
    : reflectOwnKeys(exportsValue);
  const descriptor = objectGetOwnPropertyDescriptor(
    exportsValue,
    "loadDarwinTrustedClockNativeBindingOnce",
  );
  if (utilTypesIsProxy(exportsValue)
      || objectGetPrototypeOf(exportsValue) !== OBJECT_PROTOTYPE
      || !objectIsFrozen(exportsValue) || keys.length !== 1
      || keys[0] !== "loadDarwinTrustedClockNativeBindingOnce"
      || descriptor == null || !objectHasOwn(descriptor, "value")
      || typeof descriptor.value !== "function" || utilTypesIsProxy(descriptor.value)
      || descriptor.writable !== false || descriptor.enumerable !== true
      || descriptor.configurable !== false) reject("native_loader_surface_invalid");
  const cacheDescriptor = objectGetOwnPropertyDescriptor(NATIVE_CACHE, LOADER_PATH);
  const moduleRecord = cacheDescriptor?.value;
  if (moduleRecord == null || typeof moduleRecord !== "object") {
    reject("native_loader_cache_invalid");
  }
  const exportsDescriptor = objectGetOwnPropertyDescriptor(moduleRecord, "exports");
  if (exportsDescriptor?.value !== exportsValue) reject("native_loader_cache_invalid");
  objectFreeze(descriptor.value.prototype);
  objectFreeze(descriptor.value);
  const cacheExports = createLoaderCacheTombstone();
  objectDefineProperty(moduleRecord, "exports", {
    value: cacheExports,
    writable: false,
    enumerable: exportsDescriptor.enumerable,
    configurable: false,
  });
  objectDefineProperty(NATIVE_CACHE, LOADER_PATH, {
    value: moduleRecord,
    writable: false,
    enumerable: true,
    configurable: false,
  });
  loaderState = objectFreeze({
    module_record: moduleRecord,
    cache_exports: cacheExports,
    load: descriptor.value,
  });
  return loaderState.load;
}

// Capture and lock the fixed loader during the first authentic module import.
// This imports JavaScript only: native code and build artifacts remain untouched
// until explicit client construction. A module reload after a client was opened
// skips dependency loading and can only reach the process one-shot rejection.
if (objectGetOwnPropertyDescriptor(hostProcess, NATIVE_CLIENT_MARK) == null) {
  authenticLoader = getAuthenticLoader();
}

function assertExactNativeSample(value) {
  if (value == null || typeof value !== "object" || arrayIsArray(value)
      || utilTypesIsProxy(value) || objectGetPrototypeOf(value) !== OBJECT_PROTOTYPE
      || !objectIsFrozen(value)) reject("native_sample_shape_invalid");
  const keys = reflectOwnKeys(value);
  if (keys.length !== NATIVE_SAMPLE_FIELDS.length) reject("native_sample_shape_invalid");
  for (let index = 0; index < NATIVE_SAMPLE_FIELDS.length; index += 1) {
    if (keys[index] !== NATIVE_SAMPLE_FIELDS[index]) reject("native_sample_shape_invalid");
    own(value, keys[index], "native_sample_shape_invalid");
  }
  if (value.version !== DARWIN_TRUSTED_CLOCK_SOURCE_VERSION
      || value.source !== DARWIN_TRUSTED_CLOCK_MONOTONIC_PRIMITIVE
      || typeof value.monotonic_ns !== "string"
      || !reflectApply(regExpTest, DECIMAL_PATTERN, [value.monotonic_ns])
      || typeof value.request_id !== "string"
      || !reflectApply(regExpTest, REQUEST_ID_PATTERN, [value.request_id])) {
    reject("native_sample_value_invalid");
  }
  let monotonic;
  try {
    monotonic = SafeBigInt(value.monotonic_ns);
  } catch {
    reject("native_sample_value_invalid");
  }
  if (monotonic < 0n || monotonic > UINT64_MAX) reject("native_sample_value_invalid");
  const digests = [
    "challenge_digest", "boot_epoch_digest", "service_identity_digest",
    "client_identity_digest", "enrollment_digest", "source_sample_digest",
  ];
  for (let index = 0; index < digests.length; index += 1) {
    if (typeof value[digests[index]] !== "string"
        || !reflectApply(regExpTest, DIGEST_PATTERN, [value[digests[index]]])) {
      reject("native_sample_value_invalid");
    }
  }
  const expected = computeNativeSampleDigest(value, monotonic);
  if (value.source_sample_digest !== expected) reject("native_sample_digest_invalid");
  return value;
}

function assertProcessClientAvailable() {
  if (objectGetOwnPropertyDescriptor(hostProcess, NATIVE_CLIENT_MARK) != null) {
    reject("native_client_process_one_shot_consumed");
  }
}

function reserveProcessClient() {
  assertProcessClientAvailable();
  try {
    objectDefineProperty(hostProcess, NATIVE_CLIENT_MARK, {
      value: true,
      writable: false,
      enumerable: false,
      configurable: false,
    });
  } catch {
    reject("native_client_process_one_shot_unavailable");
  }
  const mark = objectGetOwnPropertyDescriptor(hostProcess, NATIVE_CLIENT_MARK);
  if (mark?.value !== true || mark.writable !== false
      || mark.enumerable !== false || mark.configurable !== false) {
    reject("native_client_process_one_shot_unavailable");
  }
}

function mapNativeFailure(error) {
  const codeDescriptor = error == null || typeof error !== "object"
    ? null
    : objectGetOwnPropertyDescriptor(error, "code");
  const code = codeDescriptor != null && objectHasOwn(codeDescriptor, "value")
    ? codeDescriptor.value
    : null;
  const known = {
    darwin_trusted_clock_native_unprovisioned: "native_enrollment_unprovisioned",
    darwin_trusted_clock_native_service_unavailable: "native_service_unavailable",
    darwin_trusted_clock_native_protocol_rejected: "native_protocol_rejected",
    darwin_trusted_clock_native_sample_consumed: "native_sample_consumed",
    darwin_trusted_clock_native_argument_injection: "native_argument_injection",
  };
  return objectHasOwn(known, code) ? known[code] : "native_sample_failed";
}

function sampleClient(client) {
  const state = reflectApply(weakMapGet, CLIENT_STATE, [client]);
  if (state == null || state.consumed) reject("native_client_sample_consumed");
  state.consumed = true;
  let raw;
  try {
    raw = reflectApply(state.native.sample, undefined, []);
  } catch (error) {
    reject(mapNativeFailure(error));
  }
  const verified = assertExactNativeSample(raw);
  const sample = objectFreeze({
    version: DARWIN_TRUSTED_CLOCK_SOURCE_VERSION,
    source: DARWIN_TRUSTED_CLOCK_MONOTONIC_PRIMITIVE,
    request_id: verified.request_id,
    monotonic_ns: verified.monotonic_ns,
    monotonic_epoch_id: verified.boot_epoch_digest,
    enrollment_digest: verified.enrollment_digest,
    source_sample_digest: verified.source_sample_digest,
    source_assurance: "native_fixed_ipc_local_build_non_authorizing",
    local_build_receipt_sha256: state.native.receipt_sha256,
    native_attested: false,
    signed_release_verified: false,
    immutable_installation_verified: false,
    provisioning_verified: false,
    hil_verified: false,
    authoritative: false,
    production_ready: false,
    blocker_code: DARWIN_TRUSTED_CLOCK_BLOCKER,
    toJSON: rejectSerialization,
  });
  reflectApply(weakSetAdd, SAMPLES, [sample]);
  return sample;
}

function createDarwinTrustedClockNativeClient() {
  if (arguments.length !== 0) reject("native_client_argument_injection");
  assertProcessClientAvailable();
  let native;
  try {
    native = reflectApply(authenticLoader, undefined, []);
  } catch {
    reject("native_binding_unavailable_or_untrusted");
  }
  reserveProcessClient();
  let client;
  client = objectFreeze({
    version: DARWIN_TRUSTED_CLOCK_SOURCE_VERSION,
    profile: DARWIN_TRUSTED_CLOCK_PROFILE,
    source: DARWIN_TRUSTED_CLOCK_MONOTONIC_PRIMITIVE,
    source_assurance: DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_ASSURANCE,
    native_measurement_scheme: native.measurement_scheme,
    local_build_receipt_sha256: native.receipt_sha256,
    local_source_set_sha256: native.source_set_sha256,
    native_client_artifact_sha256: native.node_api_client_sha256,
    native_service_artifact_sha256: native.service_sha256,
    fixed_endpoint: true,
    zero_configuration: true,
    one_shot: true,
    native_client_loaded: true,
    native_attested: false,
    signed_release_verified: false,
    immutable_installation_verified: false,
    provisioning_verified: false,
    hil_verified: false,
    authoritative: false,
    production_ready: false,
    production_blockers: NATIVE_CLIENT_BLOCKERS,
    sample() {
      if (arguments.length !== 0) {
        const state = reflectApply(weakMapGet, CLIENT_STATE, [client]);
        if (state != null) state.consumed = true;
        reject("native_sample_argument_injection");
      }
      return sampleClient(client);
    },
    toJSON: rejectSerialization,
  });
  reflectApply(weakSetAdd, CLIENTS, [client]);
  reflectApply(weakMapSet, CLIENT_STATE, [client, { native, consumed: false }]);
  return client;
}

function assertDarwinTrustedClockNativeClient(input) {
  if (arguments.length !== 1 || input == null || typeof input !== "object"
      || utilTypesIsProxy(input) || !objectIsFrozen(input)
      || !reflectApply(weakSetHas, CLIENTS, [input])
      || input.production_ready !== false || input.native_attested !== false
      || input.signed_release_verified !== false || input.hil_verified !== false
      || input.authoritative !== false) reject("native_client_brand_invalid");
  return input;
}

function assertDarwinTrustedClockNativeSample(input) {
  if (arguments.length !== 1 || input == null || typeof input !== "object"
      || utilTypesIsProxy(input) || !objectIsFrozen(input)
      || !reflectApply(weakSetHas, SAMPLES, [input])
      || input.production_ready !== false || input.native_attested !== false
      || input.signed_release_verified !== false || input.hil_verified !== false
      || input.authoritative !== false) reject("native_sample_brand_invalid");
  return input;
}

module.exports = objectFreeze({
  DARWIN_TRUSTED_CLOCK_NATIVE_CLIENT_BLOCKERS: NATIVE_CLIENT_BLOCKERS,
  assertDarwinTrustedClockNativeClient,
  assertDarwinTrustedClockNativeSample,
  createDarwinTrustedClockNativeClient,
});
