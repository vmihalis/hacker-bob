"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const hostProcess = require("node:process");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const SafeError = Error;
const SafeBigInt = BigInt;
const SafeString = String;
const bufferFill = Buffer.prototype.fill;
const cryptoCreateHash = crypto.createHash;
const fsCloseSync = fs.closeSync;
const fsFstatSync = fs.fstatSync;
const fsLstatSync = fs.lstatSync;
const fsOpenSync = fs.openSync;
const fsReadFileSync = fs.readFileSync;
const fsRealpathNative = fs.realpathSync.native;
const fsOpenCloseOnExec = fs.constants.O_CLOEXEC || 0;
const fsOpenNoFollow = fs.constants.O_NOFOLLOW || 0;
const fsOpenReadOnly = fs.constants.O_RDONLY;
const functionPrototype = Function.prototype;
const functionToString = Function.prototype.toString;
const numberIsSafeInteger = Number.isSafeInteger;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const pathJoin = path.join;
const pathResolve = path.resolve;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const stringStartsWith = String.prototype.startsWith;
const utilTypesIsProxy = utilTypes.isProxy;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;

const OBJECT_PROTOTYPE = Object.prototype;
const GLOBAL_THIS = globalThis;
const PACKAGE_ROOT = pathResolve(__dirname, "..");
const NATIVE_CACHE = require.cache;
const BUILD_CONTRACT_PATH = require.resolve("./native-build-contract.js");
const HOST_PROCESS = hostProcess;
const HOST_PROCESS_GLOBAL_DESCRIPTOR = objectGetOwnPropertyDescriptor(
  GLOBAL_THIS,
  "process",
);
const HOST_PLATFORM_DESCRIPTOR = objectGetOwnPropertyDescriptor(HOST_PROCESS, "platform");
const HOST_ARCH_DESCRIPTOR = objectGetOwnPropertyDescriptor(HOST_PROCESS, "arch");
const HOST_VERSIONS_DESCRIPTOR = objectGetOwnPropertyDescriptor(HOST_PROCESS, "versions");
const HOST_NODE_DESCRIPTOR = objectGetOwnPropertyDescriptor(
  HOST_VERSIONS_DESCRIPTOR?.value,
  "node",
);
const HOST_NAPI_DESCRIPTOR = objectGetOwnPropertyDescriptor(
  HOST_VERSIONS_DESCRIPTOR?.value,
  "napi",
);
const HOST_DLOPEN_DESCRIPTOR = objectGetOwnPropertyDescriptor(HOST_PROCESS, "dlopen");
const HOST_GETEUID_DESCRIPTOR = objectGetOwnPropertyDescriptor(HOST_PROCESS, "geteuid");
const HOST_OBJECT_IS_FROZEN_DESCRIPTOR = objectGetOwnPropertyDescriptor(
  Object,
  "isFrozen",
);
const HOST_ARRAY_JOIN_DESCRIPTOR = objectGetOwnPropertyDescriptor(
  Array.prototype,
  "join",
);
const HOST_ARRAY_PUSH_DESCRIPTOR = objectGetOwnPropertyDescriptor(
  Array.prototype,
  "push",
);
const HOST_ARRAY_SORT_DESCRIPTOR = objectGetOwnPropertyDescriptor(
  Array.prototype,
  "sort",
);
const HOST_BUFFER_ALLOC_DESCRIPTOR = objectGetOwnPropertyDescriptor(Buffer, "alloc");
const HOST_BUFFER_FROM_DESCRIPTOR = objectGetOwnPropertyDescriptor(Buffer, "from");
const HOST_BUFFER_FILL_DESCRIPTOR = objectGetOwnPropertyDescriptor(
  Buffer.prototype,
  "fill",
);
const HOST_BUFFER_TO_STRING_DESCRIPTOR = objectGetOwnPropertyDescriptor(
  Buffer.prototype,
  "toString",
);
const HOST_BUFFER_WRITE_UINT64_DESCRIPTOR = objectGetOwnPropertyDescriptor(
  Buffer.prototype,
  "writeBigUInt64BE",
);
const HOST_PATH_JOIN_DESCRIPTOR = objectGetOwnPropertyDescriptor(path, "join");
const HOST_PATH_RESOLVE_DESCRIPTOR = objectGetOwnPropertyDescriptor(path, "resolve");
const HASH_PROTOTYPE = objectGetPrototypeOf(cryptoCreateHash("sha256"));
const HASH_UPDATE = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "update").value;
const HASH_DIGEST = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "digest").value;
const BINDING_FUNCTION_NAME = "sampleTrustedClockNative";
const MAX_NATIVE_BINDING_BYTES = 64 * 1024 * 1024;
const PREBUILD_RELATIVE_PATHS = objectFreeze([
  "prebuilds/darwin-arm64/trusted_clock_client.node",
  "prebuilds/darwin-arm64/trusted_clock_service",
  "prebuilds/darwin-arm64/trusted-clock-native-release.json",
]);
const BRANDED_MODULE_RECORDS = new WeakSet();
const BRANDED_BINDINGS = new WeakSet();
const BRANDED_CACHE_TOMBSTONES = new WeakSet();
let loadedState = null;
let buildContractState = null;

function loaderError(reasonCode = "trusted_clock_native_binding_rejected") {
  const error = new SafeError("Darwin trusted-clock native binding was rejected");
  objectDefineProperty(error, "code", {
    value: "darwin_trusted_clock_native_binding_rejected",
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
  throw loaderError(reasonCode);
}

function sameDescriptor(actual, expected) {
  if (actual == null || expected == null) return false;
  const fields = ["value", "get", "set", "writable", "enumerable", "configurable"];
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    if (objectHasOwn(actual, field) !== objectHasOwn(expected, field)) return false;
    if (objectHasOwn(expected, field) && actual[field] !== expected[field]) return false;
  }
  return true;
}

function readGlobalProcess() {
  const current = objectGetOwnPropertyDescriptor(GLOBAL_THIS, "process");
  if (!sameDescriptor(current, HOST_PROCESS_GLOBAL_DESCRIPTOR)
      || typeof HOST_PROCESS_GLOBAL_DESCRIPTOR?.get !== "function") {
    reject("host_runtime_tampered");
  }
  let value;
  try {
    value = reflectApply(HOST_PROCESS_GLOBAL_DESCRIPTOR.get, GLOBAL_THIS, []);
  } catch {
    reject("host_runtime_tampered");
  }
  if (value !== HOST_PROCESS) reject("host_runtime_tampered");
}

function nativeFunctionSource(descriptor, expectedName) {
  if (typeof descriptor?.value !== "function" || utilTypesIsProxy(descriptor.value)) {
    return false;
  }
  let source;
  try {
    source = reflectApply(functionToString, descriptor.value, []);
  } catch {
    return false;
  }
  return source === `function ${expectedName}() { [native code] }`;
}

function assertHostRuntimeUntampered() {
  readGlobalProcess();
  const descriptors = [
    ["platform", HOST_PLATFORM_DESCRIPTOR],
    ["arch", HOST_ARCH_DESCRIPTOR],
    ["versions", HOST_VERSIONS_DESCRIPTOR],
    ["dlopen", HOST_DLOPEN_DESCRIPTOR],
    ["geteuid", HOST_GETEUID_DESCRIPTOR],
  ];
  for (let index = 0; index < descriptors.length; index += 1) {
    if (!sameDescriptor(
      objectGetOwnPropertyDescriptor(HOST_PROCESS, descriptors[index][0]),
      descriptors[index][1],
    )) reject("host_runtime_tampered");
  }
  if (HOST_PLATFORM_DESCRIPTOR?.value !== "darwin"
      || HOST_ARCH_DESCRIPTOR?.value !== "arm64"
      || typeof HOST_NODE_DESCRIPTOR?.value !== "string"
      || !reflectApply(stringStartsWith, HOST_NODE_DESCRIPTOR.value, ["20."])
      || HOST_NAPI_DESCRIPTOR?.value !== "9"
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(HOST_VERSIONS_DESCRIPTOR?.value, "node"),
        HOST_NODE_DESCRIPTOR,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(HOST_VERSIONS_DESCRIPTOR?.value, "napi"),
        HOST_NAPI_DESCRIPTOR,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(Object, "isFrozen"),
        HOST_OBJECT_IS_FROZEN_DESCRIPTOR,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(Array.prototype, "join"),
        HOST_ARRAY_JOIN_DESCRIPTOR,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(Array.prototype, "push"),
        HOST_ARRAY_PUSH_DESCRIPTOR,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(Array.prototype, "sort"),
        HOST_ARRAY_SORT_DESCRIPTOR,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(Buffer, "alloc"),
        HOST_BUFFER_ALLOC_DESCRIPTOR,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(Buffer, "from"),
        HOST_BUFFER_FROM_DESCRIPTOR,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(Buffer.prototype, "fill"),
        HOST_BUFFER_FILL_DESCRIPTOR,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(Buffer.prototype, "toString"),
        HOST_BUFFER_TO_STRING_DESCRIPTOR,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(Buffer.prototype, "writeBigUInt64BE"),
        HOST_BUFFER_WRITE_UINT64_DESCRIPTOR,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(path, "join"),
        HOST_PATH_JOIN_DESCRIPTOR,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(path, "resolve"),
        HOST_PATH_RESOLVE_DESCRIPTOR,
      )
      || !nativeFunctionSource(HOST_DLOPEN_DESCRIPTOR, "dlopen")
      || !nativeFunctionSource(HOST_GETEUID_DESCRIPTOR, "geteuid")) {
    reject("host_runtime_unsupported_or_tampered");
  }
}

function assertNoUnsignedPrebuildShadow() {
  for (let index = 0; index < PREBUILD_RELATIVE_PATHS.length; index += 1) {
    const candidate = pathJoin(PACKAGE_ROOT, PREBUILD_RELATIVE_PATHS[index]);
    try {
      fsLstatSync(candidate);
      reject("signed_prebuild_verifier_and_trust_root_missing");
    } catch (error) {
      if (error?.code === "darwin_trusted_clock_native_binding_rejected") throw error;
      if (error?.code !== "ENOENT") reject("prebuild_shadow_inspection_failed");
    }
  }
}

function getBuildVerifier() {
  if (buildContractState != null) {
    const descriptor = objectGetOwnPropertyDescriptor(
      NATIVE_CACHE,
      BUILD_CONTRACT_PATH,
    );
    if (descriptor?.value !== buildContractState.module_record
        || descriptor.writable !== false || descriptor.enumerable !== true
        || descriptor.configurable !== false
        || buildContractState.module_record.exports !== buildContractState.exports) {
      reject("build_contract_cache_drift");
    }
    return buildContractState.verify;
  }
  if (objectGetOwnPropertyDescriptor(NATIVE_CACHE, BUILD_CONTRACT_PATH) != null) {
    reject("build_contract_cache_prepopulated");
  }
  let contract;
  try {
    contract = require(BUILD_CONTRACT_PATH);
  } catch {
    reject("build_contract_load_failed");
  }
  const expectedKeys = [
    "DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_ARTIFACTS",
    "DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_ASSURANCE",
    "DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_BLOCKERS",
    "DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_RECEIPT_PATH",
    "DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_SOURCE_PATHS",
    "DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_TARGET",
    "DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_VERSION",
    "createDarwinTrustedClockLocalBuildReceipt",
    "verifyDarwinTrustedClockLocalBuild",
    "_canonicalJsonForBuildReceipt",
  ];
  const keys = contract == null || typeof contract !== "object"
    ? []
    : reflectOwnKeys(contract);
  if (utilTypesIsProxy(contract) || objectGetPrototypeOf(contract) !== OBJECT_PROTOTYPE
      || !objectIsFrozen(contract) || keys.length !== expectedKeys.length) {
    reject("build_contract_surface_invalid");
  }
  for (let index = 0; index < expectedKeys.length; index += 1) {
    if (keys[index] !== expectedKeys[index]) reject("build_contract_surface_invalid");
  }
  const verifyDescriptor = objectGetOwnPropertyDescriptor(
    contract,
    "verifyDarwinTrustedClockLocalBuild",
  );
  if (verifyDescriptor == null || !objectHasOwn(verifyDescriptor, "value")
      || typeof verifyDescriptor.value !== "function"
      || utilTypesIsProxy(verifyDescriptor.value)
      || verifyDescriptor.writable !== false || verifyDescriptor.enumerable !== true
      || verifyDescriptor.configurable !== false) {
    reject("build_contract_surface_invalid");
  }
  const cacheDescriptor = objectGetOwnPropertyDescriptor(
    NATIVE_CACHE,
    BUILD_CONTRACT_PATH,
  );
  const moduleRecord = cacheDescriptor?.value;
  if (moduleRecord == null || typeof moduleRecord !== "object") {
    reject("build_contract_cache_invalid");
  }
  const exportsDescriptor = objectGetOwnPropertyDescriptor(moduleRecord, "exports");
  if (exportsDescriptor?.value !== contract) {
    reject("build_contract_cache_invalid");
  }
  objectFreeze(verifyDescriptor.value.prototype);
  objectFreeze(verifyDescriptor.value);
  objectDefineProperty(moduleRecord, "exports", {
    value: contract,
    writable: false,
    enumerable: exportsDescriptor.enumerable,
    configurable: false,
  });
  objectDefineProperty(NATIVE_CACHE, BUILD_CONTRACT_PATH, {
    value: moduleRecord,
    writable: false,
    enumerable: true,
    configurable: false,
  });
  buildContractState = objectFreeze({
    module_record: moduleRecord,
    exports: contract,
    verify: verifyDescriptor.value,
  });
  return buildContractState.verify;
}

function verifyFixedLocalBuild() {
  const verifier = getBuildVerifier();
  let result;
  try {
    result = reflectApply(verifier, undefined, [PACKAGE_ROOT]);
  } catch {
    reject("local_build_receipt_rejected");
  }
  return result;
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.mode === right.mode && left.uid === right.uid
    && left.gid === right.gid && left.nlink === right.nlink
    && left.size === right.size && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function sha256(bytes) {
  const hash = cryptoCreateHash("sha256");
  reflectApply(HASH_UPDATE, hash, [bytes]);
  return reflectApply(HASH_DIGEST, hash, ["hex"]);
}

function measureBinding(candidate, expectedDigest) {
  let canonical;
  let descriptor = -1;
  try {
    canonical = fsRealpathNative(candidate);
    if (canonical !== candidate) reject("native_binding_path_invalid");
    descriptor = fsOpenSync(
      canonical,
      fsOpenReadOnly | fsOpenNoFollow | fsOpenCloseOnExec,
    );
    const before = fsFstatSync(descriptor, { bigint: true });
    const pathStatus = fsLstatSync(canonical, { bigint: true });
    if (!before.isFile() || !pathStatus.isFile()
        || !sameFileIdentity(before, pathStatus) || before.nlink !== 1n
        || before.uid !== SafeBigInt(reflectApply(
          HOST_GETEUID_DESCRIPTOR.value,
          HOST_PROCESS,
          [],
        ))
        || (before.mode & 0o022n) !== 0n || before.size < 1n
        || before.size > SafeBigInt(MAX_NATIVE_BINDING_BYTES)) {
      reject("native_binding_file_identity_invalid");
    }
    const bytes = fsReadFileSync(descriptor);
    try {
      const after = fsFstatSync(descriptor, { bigint: true });
      const digest = sha256(bytes);
      if (!sameFileIdentity(before, after)
          || SafeBigInt(bytes.length) !== before.size
          || digest !== expectedDigest) reject("native_binding_file_drift");
      return objectFreeze({
        path: canonical,
        digest,
        dev: SafeString(before.dev),
        ino: SafeString(before.ino),
        mode: SafeString(before.mode),
        uid: SafeString(before.uid),
        gid: SafeString(before.gid),
        nlink: SafeString(before.nlink),
        size: SafeString(before.size),
        mtime_ns: SafeString(before.mtimeNs),
        ctime_ns: SafeString(before.ctimeNs),
      });
    } finally {
      reflectApply(bufferFill, bytes, [0]);
    }
  } catch (error) {
    if (error?.code === "darwin_trusted_clock_native_binding_rejected") throw error;
    reject("native_binding_file_unavailable");
  } finally {
    if (descriptor >= 0) fsCloseSync(descriptor);
  }
}

function sameMeasurement(left, right) {
  const fields = [
    "path", "digest", "dev", "ino", "mode", "uid", "gid", "nlink", "size",
    "mtime_ns", "ctime_ns",
  ];
  for (let index = 0; index < fields.length; index += 1) {
    if (left[fields[index]] !== right[fields[index]]) return false;
  }
  return true;
}

function assertExactNativeFunction(value, frozenRequired) {
  if (typeof value !== "function" || utilTypesIsProxy(value)
      || objectGetPrototypeOf(value) !== functionPrototype) {
    reject("native_binding_surface_invalid");
  }
  const keys = reflectOwnKeys(value);
  const expected = ["length", "name", "arguments", "caller", "prototype"];
  if (keys.length !== expected.length) reject("native_binding_surface_invalid");
  for (let index = 0; index < expected.length; index += 1) {
    if (keys[index] !== expected[index]) reject("native_binding_surface_invalid");
  }
  const length = objectGetOwnPropertyDescriptor(value, "length");
  const name = objectGetOwnPropertyDescriptor(value, "name");
  const argumentsDescriptor = objectGetOwnPropertyDescriptor(value, "arguments");
  const caller = objectGetOwnPropertyDescriptor(value, "caller");
  const prototype = objectGetOwnPropertyDescriptor(value, "prototype");
  if (length?.value !== 0 || length.writable !== false || length.enumerable !== false
      || length.configurable !== !frozenRequired || name?.value !== BINDING_FUNCTION_NAME
      || name.writable !== false || name.enumerable !== false
      || name.configurable !== !frozenRequired || argumentsDescriptor?.value !== null
      || argumentsDescriptor.writable !== false
      || argumentsDescriptor.enumerable !== false
      || argumentsDescriptor.configurable !== false || caller?.value !== null
      || caller.writable !== false || caller.enumerable !== false
      || caller.configurable !== false || prototype == null
      || !objectHasOwn(prototype, "value") || prototype.writable !== !frozenRequired
      || prototype.enumerable !== false || prototype.configurable !== false
      || prototype.value == null || typeof prototype.value !== "object"
      || utilTypesIsProxy(prototype.value)
      || objectGetPrototypeOf(prototype.value) !== OBJECT_PROTOTYPE
      || reflectOwnKeys(prototype.value).length !== 1
      || reflectOwnKeys(prototype.value)[0] !== "constructor") {
    reject("native_binding_surface_invalid");
  }
}

function assertExactBinding(binding, frozenRequired) {
  if (binding == null || typeof binding !== "object" || utilTypesIsProxy(binding)
      || objectGetPrototypeOf(binding) !== null
      || (frozenRequired && !objectIsFrozen(binding))) {
    reject("native_binding_surface_invalid");
  }
  const keys = reflectOwnKeys(binding);
  if (keys.length !== 1 || keys[0] !== BINDING_FUNCTION_NAME) {
    reject("native_binding_surface_invalid");
  }
  const descriptor = objectGetOwnPropertyDescriptor(binding, BINDING_FUNCTION_NAME);
  if (descriptor == null || !objectHasOwn(descriptor, "value")
      || descriptor.writable !== false || descriptor.enumerable !== true
      || descriptor.configurable !== false) reject("native_binding_surface_invalid");
  assertExactNativeFunction(descriptor.value, frozenRequired);
  if (frozenRequired && (!objectIsFrozen(descriptor.value)
      || !objectIsFrozen(descriptor.value.prototype))) {
    reject("native_binding_surface_invalid");
  }
  return binding;
}

function createNativeBindingCacheTombstone() {
  const tombstone = objectCreate(null);
  const fields = [
    ["version", 1],
    ["kind", "darwin_trusted_clock_native_binding_private_cache_tombstone"],
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
  reflectApply(weakSetAdd, BRANDED_CACHE_TOMBSTONES, [tombstone]);
  return tombstone;
}

function assertNativeBindingCacheTombstone(value) {
  if (value == null || typeof value !== "object" || utilTypesIsProxy(value)
      || objectGetPrototypeOf(value) !== null || !objectIsFrozen(value)
      || !reflectApply(weakSetHas, BRANDED_CACHE_TOMBSTONES, [value])) {
    reject("native_binding_cache_tombstone_invalid");
  }
  const keys = reflectOwnKeys(value);
  const expected = [
    "version", "kind", "callable_surface_exposed", "production_ready",
  ];
  if (keys.length !== expected.length) reject("native_binding_cache_tombstone_invalid");
  for (let index = 0; index < expected.length; index += 1) {
    if (keys[index] !== expected[index]) reject("native_binding_cache_tombstone_invalid");
    const descriptor = objectGetOwnPropertyDescriptor(value, expected[index]);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.writable !== false || descriptor.enumerable !== true
        || descriptor.configurable !== false) {
      reject("native_binding_cache_tombstone_invalid");
    }
  }
  if (value.version !== 1
      || value.kind !== "darwin_trusted_clock_native_binding_private_cache_tombstone"
      || value.callable_surface_exposed !== false
      || value.production_ready !== false) {
    reject("native_binding_cache_tombstone_invalid");
  }
  return value;
}

function assertBrandedCacheEntry(state) {
  const descriptor = objectGetOwnPropertyDescriptor(NATIVE_CACHE, state.measurement.path);
  if (descriptor == null || descriptor.value !== state.module_record
      || descriptor.writable !== false || descriptor.enumerable !== true
      || descriptor.configurable !== false
      || !reflectApply(weakSetHas, BRANDED_MODULE_RECORDS, [state.module_record])
      || !reflectApply(weakSetHas, BRANDED_BINDINGS, [state.binding])
      || !objectIsFrozen(state.module_record) || !objectIsFrozen(state.binding)
      || state.module_record.exports !== state.cache_exports) {
    reject("native_binding_cache_drift");
  }
  assertNativeBindingCacheTombstone(state.cache_exports);
  assertExactBinding(state.binding, true);
}

function loadDarwinTrustedClockNativeBindingOnce() {
  if (arguments.length !== 0) reject("native_loader_argument_injection");
  assertHostRuntimeUntampered();
  assertNoUnsignedPrebuildShadow();
  if (loadedState != null) {
    assertBrandedCacheEntry(loadedState);
    const build = verifyFixedLocalBuild();
    const current = measureBinding(build.node_api_client_path,
      build.node_api_client_sha256);
    if (!sameMeasurement(current, loadedState.measurement)
        || build.receipt_sha256 !== loadedState.build.receipt_sha256
        || build.source_set_sha256 !== loadedState.build.source_set_sha256
        || build.service_sha256 !== loadedState.build.service_sha256) {
      reject("native_binding_or_build_drift");
    }
    return loadedState.port;
  }

  const buildBefore = verifyFixedLocalBuild();
  const measurement = measureBinding(
    buildBefore.node_api_client_path,
    buildBefore.node_api_client_sha256,
  );
  if (objectGetOwnPropertyDescriptor(NATIVE_CACHE, measurement.path) != null) {
    reject("native_binding_cache_prepopulated");
  }
  const nativeModule = objectCreate(null);
  objectDefineProperty(nativeModule, "id", {
    value: measurement.path,
    writable: false,
    enumerable: true,
    configurable: false,
  });
  objectDefineProperty(nativeModule, "filename", {
    value: measurement.path,
    writable: false,
    enumerable: true,
    configurable: false,
  });
  objectDefineProperty(nativeModule, "loaded", {
    value: false,
    writable: true,
    enumerable: true,
    configurable: false,
  });
  objectDefineProperty(nativeModule, "exports", {
    value: objectCreate(null),
    writable: true,
    enumerable: true,
    configurable: false,
  });
  try {
    reflectApply(HOST_DLOPEN_DESCRIPTOR.value, HOST_PROCESS, [
      nativeModule,
      measurement.path,
    ]);
  } catch {
    reject("native_binding_dlopen_failed");
  }
  const binding = assertExactBinding(nativeModule.exports, false);
  const buildAfter = verifyFixedLocalBuild();
  const after = measureBinding(buildAfter.node_api_client_path,
    buildAfter.node_api_client_sha256);
  if (!sameMeasurement(measurement, after)
      || buildBefore.receipt_sha256 !== buildAfter.receipt_sha256
      || buildBefore.source_set_sha256 !== buildAfter.source_set_sha256
      || buildBefore.service_sha256 !== buildAfter.service_sha256) {
    reject("native_binding_or_build_changed_during_load");
  }
  objectFreeze(binding[BINDING_FUNCTION_NAME].prototype);
  objectFreeze(binding[BINDING_FUNCTION_NAME]);
  objectFreeze(binding);
  const cacheExports = createNativeBindingCacheTombstone();
  objectDefineProperty(nativeModule, "loaded", {
    value: true,
    writable: false,
    enumerable: true,
    configurable: false,
  });
  objectDefineProperty(nativeModule, "exports", {
    value: cacheExports,
    writable: false,
    enumerable: true,
    configurable: false,
  });
  objectFreeze(nativeModule);
  reflectApply(weakSetAdd, BRANDED_BINDINGS, [binding]);
  reflectApply(weakSetAdd, BRANDED_MODULE_RECORDS, [nativeModule]);
  objectDefineProperty(NATIVE_CACHE, measurement.path, {
    value: nativeModule,
    writable: false,
    enumerable: true,
    configurable: false,
  });
  const port = objectFreeze({
    sample: binding[BINDING_FUNCTION_NAME],
    receipt_sha256: buildAfter.receipt_sha256,
    source_set_sha256: buildAfter.source_set_sha256,
    node_api_client_sha256: buildAfter.node_api_client_sha256,
    service_sha256: buildAfter.service_sha256,
    measurement_scheme:
      "darwin_local_source_receipt_file_sha256_before_after_direct_dlopen_v1",
    signed_release_verified: false,
    native_loaded_image_attested: false,
    immutable_installation_verified: false,
    provisioning_verified: false,
    hil_verified: false,
    production_ready: false,
  });
  loadedState = objectFreeze({
    measurement: after,
    build: buildAfter,
    module_record: nativeModule,
    binding,
    cache_exports: cacheExports,
    port,
  });
  assertBrandedCacheEntry(loadedState);
  return port;
}

// Load and lock the fixed JavaScript build-contract dependency while this
// authentic loader module is being evaluated. This performs no artifact read
// and no native load; it prevents a later caller from substituting the local
// verifier through CommonJS cache state between client import and construction.
getBuildVerifier();

module.exports = objectFreeze({
  loadDarwinTrustedClockNativeBindingOnce,
});
