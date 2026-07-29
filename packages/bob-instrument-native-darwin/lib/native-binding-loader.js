"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const hostProcess = require("node:process");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const SafeError = Error;
const arrayIsArray = Array.isArray;
const cryptoCreateHash = crypto.createHash;
const fsCloseSync = fs.closeSync;
const fsFstatSync = fs.fstatSync;
const fsLstatSync = fs.lstatSync;
const fsOpenSync = fs.openSync;
const fsReadFileSync = fs.readFileSync;
const fsRealpathNative = fs.realpathSync.native;
const functionPrototype = Function.prototype;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectPrototype = Object.prototype;
const numberIsInteger = Number.isInteger;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regExpTest = RegExp.prototype.test;
const safeString = String;
const stringStartsWith = String.prototype.startsWith;
const utilTypesIsProxy = utilTypes.isProxy;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;

const GLOBAL_THIS = globalThis;
const NATIVE_CACHE = require.cache;
const HOST_PROCESS = hostProcess;
const HOST_PROCESS_GLOBAL_DESCRIPTOR = objectGetOwnPropertyDescriptor(
  GLOBAL_THIS,
  "process",
);
const HOST_PID_DESCRIPTOR = objectGetOwnPropertyDescriptor(HOST_PROCESS, "pid");
const HOST_PLATFORM_DESCRIPTOR = objectGetOwnPropertyDescriptor(HOST_PROCESS, "platform");
const HOST_ARCH_DESCRIPTOR = objectGetOwnPropertyDescriptor(HOST_PROCESS, "arch");
const HOST_VERSIONS_DESCRIPTOR = objectGetOwnPropertyDescriptor(HOST_PROCESS, "versions");
const HOST_NODE_VERSION_DESCRIPTOR = objectGetOwnPropertyDescriptor(
  HOST_VERSIONS_DESCRIPTOR?.value,
  "node",
);
const HOST_NAPI_VERSION_DESCRIPTOR = objectGetOwnPropertyDescriptor(
  HOST_VERSIONS_DESCRIPTOR?.value,
  "napi",
);
const HOST_GETUID_DESCRIPTOR = objectGetOwnPropertyDescriptor(HOST_PROCESS, "getuid");
const HOST_GETEUID_DESCRIPTOR = objectGetOwnPropertyDescriptor(HOST_PROCESS, "geteuid");
const HOST_GETGID_DESCRIPTOR = objectGetOwnPropertyDescriptor(HOST_PROCESS, "getgid");
const HOST_GETEGID_DESCRIPTOR = objectGetOwnPropertyDescriptor(HOST_PROCESS, "getegid");
const MAX_NATIVE_BINDING_BYTES = 64 * 1024 * 1024;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;
const BINDING_FUNCTION_NAMES = objectFreeze([
  "registerUnixPeerDescriptor",
  "inspectRegisteredUnixPeer",
  "inspectLoadedImage",
  "inspectCurrentSelf",
  "createUnixAcceptor",
  "acceptUnixConnection",
  "readAcceptedConnectionIdentity",
  "writeAcceptedConnectionFrame",
  "readAcceptedConnectionFrame",
  "closeUnixAcceptor",
  "closeAcceptedConnection",
]);
const LOADED_IMAGE_SNAPSHOT_FIELDS = objectFreeze([
  "version",
  "primitive",
  "image_file_sha256",
  "image_identity_digest",
  "image_canonical_path_digest",
  "image_file_identity_digest",
  "image_lc_uuid_digest",
  "image_header_and_load_commands_digest",
  "image_executable_segments_digest",
  "image_executable_segment_count",
  "image_executable_file_bytes",
  "dyld_header_unique",
  "dladdr_base_matches_dyld",
  "dyld_snapshot_stable",
  "dyld_canonical_path_matches_dladdr",
  "callback_in_executable_segment",
  "header_and_load_commands_match_file",
  "executable_segments_match_file",
  "executable_pages_read_execute_only",
  "executable_segment_file_size_equals_vm_size",
  "non_executable_runtime_state_measured",
  "executable_image_identity_complete",
  "full_runtime_state_identity_complete",
]);
const LOADED_IMAGE_PRIMITIVE =
  "darwin_dladdr_dyld_macho_executable_segments_file_match_v1";
const SELF_INSPECTION_MARK = Symbol.for(
  "hacker-bob.instrument-native-darwin.current-self-inspected.v1",
);
const BRANDED_MODULE_RECORDS = new WeakSet();
const BRANDED_BINDINGS = new WeakSet();
let loadedState;
let hostDlopenDescriptor;
const HASH_PROTOTYPE = objectGetPrototypeOf(cryptoCreateHash("sha256"));
const HASH_UPDATE = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "update").value;
const HASH_DIGEST = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "digest").value;

function loaderError() {
  const error = new SafeError("Darwin native binding load was rejected");
  objectDefineProperty(error, "code", {
    value: "darwin_native_binding_load_rejected",
    writable: false,
    enumerable: false,
    configurable: false,
  });
  return error;
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

function readGlobalProcessWithoutAmbientGetter() {
  const current = objectGetOwnPropertyDescriptor(GLOBAL_THIS, "process");
  if (!sameDescriptor(current, HOST_PROCESS_GLOBAL_DESCRIPTOR)
      || typeof HOST_PROCESS_GLOBAL_DESCRIPTOR?.get !== "function") {
    throw loaderError();
  }
  let value;
  try {
    value = reflectApply(HOST_PROCESS_GLOBAL_DESCRIPTOR.get, GLOBAL_THIS, []);
  } catch {
    throw loaderError();
  }
  if (value !== HOST_PROCESS) throw loaderError();
}

function assertHostProcessUntampered() {
  readGlobalProcessWithoutAmbientGetter();
  const currentDlopen = objectGetOwnPropertyDescriptor(HOST_PROCESS, "dlopen");
  if (hostDlopenDescriptor == null) {
    const keys = typeof currentDlopen?.value === "function"
      && !utilTypesIsProxy(currentDlopen.value)
      ? reflectOwnKeys(currentDlopen.value)
      : [];
    const length = objectGetOwnPropertyDescriptor(currentDlopen?.value, "length");
    const name = objectGetOwnPropertyDescriptor(currentDlopen?.value, "name");
    if (keys.length !== 2 || keys[0] !== "length" || keys[1] !== "name"
        || objectGetPrototypeOf(currentDlopen.value) !== functionPrototype
        || length?.value !== 0 || length.writable !== false
        || length.enumerable !== false || length.configurable !== true
        || name?.value !== "dlopen" || name.writable !== false
        || name.enumerable !== false || name.configurable !== true) {
      throw loaderError();
    }
    hostDlopenDescriptor = currentDlopen;
  }
  const processDescriptors = [
    ["dlopen", hostDlopenDescriptor],
    ["pid", HOST_PID_DESCRIPTOR],
    ["platform", HOST_PLATFORM_DESCRIPTOR],
    ["arch", HOST_ARCH_DESCRIPTOR],
    ["versions", HOST_VERSIONS_DESCRIPTOR],
    ["getuid", HOST_GETUID_DESCRIPTOR],
    ["geteuid", HOST_GETEUID_DESCRIPTOR],
    ["getgid", HOST_GETGID_DESCRIPTOR],
    ["getegid", HOST_GETEGID_DESCRIPTOR],
  ];
  for (let index = 0; index < processDescriptors.length; index += 1) {
    const name = processDescriptors[index][0];
    const expected = processDescriptors[index][1];
    if (!sameDescriptor(objectGetOwnPropertyDescriptor(HOST_PROCESS, name), expected)) {
      throw loaderError();
    }
  }
  if (HOST_PLATFORM_DESCRIPTOR?.value !== "darwin"
      || HOST_ARCH_DESCRIPTOR?.value !== "arm64"
      || typeof HOST_PID_DESCRIPTOR?.value !== "number"
      || !numberIsInteger(HOST_PID_DESCRIPTOR.value)
      || HOST_PID_DESCRIPTOR.value <= 0
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(HOST_VERSIONS_DESCRIPTOR?.value, "node"),
        HOST_NODE_VERSION_DESCRIPTOR,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(HOST_VERSIONS_DESCRIPTOR?.value, "napi"),
        HOST_NAPI_VERSION_DESCRIPTOR,
      )
      || HOST_NAPI_VERSION_DESCRIPTOR?.value !== "9"
      || typeof HOST_NODE_VERSION_DESCRIPTOR?.value !== "string"
      || !reflectApply(stringStartsWith, HOST_NODE_VERSION_DESCRIPTOR.value, ["20."])
      || typeof hostDlopenDescriptor?.value !== "function") {
    throw loaderError();
  }
}

function callHostId(descriptor) {
  if (typeof descriptor?.value !== "function") throw loaderError();
  let value;
  try {
    value = reflectApply(descriptor.value, HOST_PROCESS, []);
  } catch {
    throw loaderError();
  }
  if (!numberIsInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw loaderError();
  }
  return value;
}

const HOST_IDENTITY = objectFreeze({
  pid: HOST_PID_DESCRIPTOR?.value,
  uid: callHostId(HOST_GETEUID_DESCRIPTOR),
  gid: callHostId(HOST_GETEGID_DESCRIPTOR),
  real_uid: callHostId(HOST_GETUID_DESCRIPTOR),
  real_gid: callHostId(HOST_GETGID_DESCRIPTOR),
});

function hashBytes(value) {
  const hash = cryptoCreateHash("sha256");
  reflectApply(HASH_UPDATE, hash, [value]);
  return reflectApply(HASH_DIGEST, hash, ["hex"]);
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function fileIdentity(stat) {
  return objectFreeze({
    dev: safeString(stat.dev),
    ino: safeString(stat.ino),
    mode: safeString(stat.mode),
    uid: safeString(stat.uid),
    gid: safeString(stat.gid),
    nlink: safeString(stat.nlink),
    size: safeString(stat.size),
    mtime_ns: safeString(stat.mtimeNs),
    ctime_ns: safeString(stat.ctimeNs),
  });
}

function measureNativeBindingFile(candidate) {
  const absolute = path.resolve(candidate);
  const canonical = fsRealpathNative(candidate);
  if (absolute !== canonical) throw loaderError();
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  const closeOnExec = fs.constants.O_CLOEXEC || 0;
  const fd = fsOpenSync(canonical, fs.constants.O_RDONLY | noFollow | closeOnExec);
  try {
    const descriptorStat = fsFstatSync(fd, { bigint: true });
    const pathStat = fsLstatSync(canonical, { bigint: true });
    if (!descriptorStat.isFile() || !pathStat.isFile()
        || !sameFileIdentity(descriptorStat, pathStat)
        || descriptorStat.nlink !== 1n
        || (descriptorStat.mode & 0o022n) !== 0n
        || descriptorStat.size <= 0n
        || descriptorStat.size > BigInt(MAX_NATIVE_BINDING_BYTES)) {
      throw loaderError();
    }
    const bytes = fsReadFileSync(fd);
    try {
      const afterRead = fsFstatSync(fd, { bigint: true });
      if (!sameFileIdentity(descriptorStat, afterRead)
          || BigInt(bytes.length) !== descriptorStat.size) throw loaderError();
      return objectFreeze({
        canonical_path: canonical,
        implementation_digest: hashBytes(bytes),
        file_identity: fileIdentity(descriptorStat),
      });
    } finally {
      bytes.fill(0);
    }
  } finally {
    fsCloseSync(fd);
  }
}

function sameMeasurement(left, right) {
  if (left.canonical_path !== right.canonical_path
      || left.implementation_digest !== right.implementation_digest) return false;
  const fields = reflectOwnKeys(left.file_identity);
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    if (left.file_identity[field] !== right.file_identity[field]) return false;
  }
  return true;
}

function assertExactNativeFunction(value, name) {
  if (typeof value !== "function" || utilTypesIsProxy(value)
      || objectGetPrototypeOf(value) !== functionPrototype) throw loaderError();
  const keys = reflectOwnKeys(value);
  const expectedKeys = ["length", "name", "arguments", "caller", "prototype"];
  if (keys.length !== expectedKeys.length) throw loaderError();
  for (let index = 0; index < expectedKeys.length; index += 1) {
    if (keys[index] !== expectedKeys[index]) throw loaderError();
  }
  const length = objectGetOwnPropertyDescriptor(value, "length");
  const functionName = objectGetOwnPropertyDescriptor(value, "name");
  const argumentsDescriptor = objectGetOwnPropertyDescriptor(value, "arguments");
  const caller = objectGetOwnPropertyDescriptor(value, "caller");
  const prototype = objectGetOwnPropertyDescriptor(value, "prototype");
  if (length?.value !== 0 || length.writable !== false || length.enumerable !== false
      || length.configurable !== true || functionName?.value !== name
      || functionName.writable !== false || functionName.enumerable !== false
      || functionName.configurable !== true || argumentsDescriptor?.value !== null
      || argumentsDescriptor.writable !== false || argumentsDescriptor.enumerable !== false
      || argumentsDescriptor.configurable !== false || caller?.value !== null
      || caller.writable !== false || caller.enumerable !== false
      || caller.configurable !== false || prototype == null
      || !objectHasOwn(prototype, "value") || prototype.writable !== true
      || prototype.enumerable !== false || prototype.configurable !== false
      || prototype.value == null || typeof prototype.value !== "object"
      || utilTypesIsProxy(prototype.value)
      || objectGetPrototypeOf(prototype.value) !== objectPrototype
      || reflectOwnKeys(prototype.value).length !== 1
      || reflectOwnKeys(prototype.value)[0] !== "constructor") {
    throw loaderError();
  }
}

function assertExactBinding(binding) {
  if (binding == null || typeof binding !== "object" || utilTypesIsProxy(binding)
      || objectGetPrototypeOf(binding) !== null) throw loaderError();
  const keys = reflectOwnKeys(binding);
  if (keys.length !== BINDING_FUNCTION_NAMES.length) throw loaderError();
  for (let index = 0; index < BINDING_FUNCTION_NAMES.length; index += 1) {
    const name = BINDING_FUNCTION_NAMES[index];
    if (keys[index] !== name) throw loaderError();
    const descriptor = objectGetOwnPropertyDescriptor(binding, name);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.writable !== false || descriptor.enumerable !== true
        || descriptor.configurable !== false) throw loaderError();
    assertExactNativeFunction(descriptor.value, name);
  }
}

function assertDigest(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, DIGEST_PATTERN, [value])) throw loaderError();
  return value;
}

function assertExactLoadedImageSnapshot(value) {
  if (value == null || typeof value !== "object" || utilTypesIsProxy(value)
      || objectGetPrototypeOf(value) !== objectPrototype) throw loaderError();
  const keys = reflectOwnKeys(value);
  if (keys.length !== LOADED_IMAGE_SNAPSHOT_FIELDS.length) throw loaderError();
  for (let index = 0; index < LOADED_IMAGE_SNAPSHOT_FIELDS.length; index += 1) {
    const field = LOADED_IMAGE_SNAPSHOT_FIELDS[index];
    if (keys[index] !== field) throw loaderError();
    const descriptor = objectGetOwnPropertyDescriptor(value, field);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.writable !== false || descriptor.enumerable !== true
        || descriptor.configurable !== false) throw loaderError();
  }
  if (value.version !== 1 || value.primitive !== LOADED_IMAGE_PRIMITIVE
      || !numberIsInteger(value.image_executable_segment_count)
      || value.image_executable_segment_count < 1
      || value.image_executable_segment_count > 32
      || typeof value.image_executable_file_bytes !== "string"
      || !reflectApply(regExpTest, DECIMAL_PATTERN, [value.image_executable_file_bytes])
      || value.image_executable_file_bytes === "0"
      || value.image_executable_file_bytes.length > 8
      || value.dyld_header_unique !== true
      || value.dladdr_base_matches_dyld !== true
      || value.dyld_snapshot_stable !== true
      || value.dyld_canonical_path_matches_dladdr !== true
      || value.callback_in_executable_segment !== true
      || value.header_and_load_commands_match_file !== true
      || value.executable_segments_match_file !== true
      || value.executable_pages_read_execute_only !== true
      || value.executable_segment_file_size_equals_vm_size !== true
      || value.non_executable_runtime_state_measured !== false
      || value.executable_image_identity_complete !== true
      || value.full_runtime_state_identity_complete !== false) {
    throw loaderError();
  }
  const digestFields = [
    "image_file_sha256",
    "image_identity_digest",
    "image_canonical_path_digest",
    "image_file_identity_digest",
    "image_lc_uuid_digest",
    "image_header_and_load_commands_digest",
    "image_executable_segments_digest",
  ];
  for (let index = 0; index < digestFields.length; index += 1) {
    assertDigest(value[digestFields[index]]);
  }
  return objectFreeze({
    measurement_scheme: value.primitive,
    file_sha256: value.image_file_sha256,
    identity_digest: value.image_identity_digest,
    canonical_path_digest: value.image_canonical_path_digest,
    file_identity_digest: value.image_file_identity_digest,
    lc_uuid_digest: value.image_lc_uuid_digest,
    header_and_load_commands_digest:
      value.image_header_and_load_commands_digest,
    executable_segments_digest: value.image_executable_segments_digest,
    executable_segment_count: value.image_executable_segment_count,
    executable_file_bytes: value.image_executable_file_bytes,
    dyld_header_unique: true,
    dladdr_base_matches_dyld: true,
    dyld_snapshot_stable: true,
    dyld_canonical_path_matches_dladdr: true,
    callback_in_executable_segment: true,
    header_and_load_commands_match_file: true,
    executable_segments_match_file: true,
    executable_pages_read_execute_only: true,
    executable_segment_file_size_equals_vm_size: true,
    non_executable_runtime_state_measured: false,
    executable_image_identity_complete: true,
    full_runtime_state_identity_complete: false,
  });
}

function measureLoadedImage(binding, fileMeasurement) {
  let raw;
  try {
    raw = reflectApply(binding.inspectLoadedImage, undefined, []);
  } catch {
    throw loaderError();
  }
  const measurement = assertExactLoadedImageSnapshot(raw);
  if (measurement.file_sha256 !== fileMeasurement.implementation_digest) {
    throw loaderError();
  }
  return measurement;
}

function sameLoadedImageMeasurement(left, right) {
  const fields = reflectOwnKeys(left);
  if (fields.length !== reflectOwnKeys(right).length) return false;
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    if (left[field] !== right[field]) return false;
  }
  return true;
}

function assertBrandedCacheEntry(state) {
  const descriptor = objectGetOwnPropertyDescriptor(NATIVE_CACHE, state.resolved);
  if (descriptor == null || !objectHasOwn(descriptor, "value")
      || descriptor.value !== state.module_record
      || descriptor.writable !== false || descriptor.enumerable !== true
      || descriptor.configurable !== false
      || !reflectApply(weakSetHas, BRANDED_MODULE_RECORDS, [state.module_record])
      || !reflectApply(weakSetHas, BRANDED_BINDINGS, [state.binding])
      || state.module_record.exports !== state.binding
      || !objectIsFrozen(state.module_record) || !objectIsFrozen(state.binding)) {
    throw loaderError();
  }
}

function loadNativeBindingOnce() {
  assertHostProcessUntampered();
  if (loadedState != null) {
    assertBrandedCacheEntry(loadedState);
    const current = measureNativeBindingFile(loadedState.resolved);
    const currentLoadedImage = measureLoadedImage(loadedState.binding, current);
    if (!sameMeasurement(current, loadedState.measurement)
        || !sameLoadedImageMeasurement(
          currentLoadedImage,
          loadedState.loaded_image_measurement,
        )) throw loaderError();
    return loadedState.port;
  }
  const candidates = [
    path.join(__dirname, "..", "prebuilds", "darwin-arm64", "peer_credentials.node"),
    path.join(__dirname, "..", "build", "Release", "peer_credentials.node"),
  ];
  let measurement;
  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = candidates[index];
    try {
      measurement = measureNativeBindingFile(candidate);
      break;
    } catch (error) {
      if (error?.code !== "ENOENT") throw loaderError();
    }
  }
  if (measurement == null) throw loaderError();
  const resolved = measurement.canonical_path;
  if (objectGetOwnPropertyDescriptor(NATIVE_CACHE, resolved) != null) {
    throw loaderError();
  }

  const nativeModule = objectCreate(null);
  objectDefineProperty(nativeModule, "id", {
    value: resolved,
    writable: false,
    enumerable: true,
    configurable: false,
  });
  objectDefineProperty(nativeModule, "filename", {
    value: resolved,
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
    reflectApply(hostDlopenDescriptor.value, HOST_PROCESS, [nativeModule, resolved]);
  } catch {
    throw loaderError();
  }
  const after = measureNativeBindingFile(resolved);
  if (!sameMeasurement(measurement, after)) throw loaderError();
  const binding = nativeModule.exports;
  assertExactBinding(binding);
  const loadedImageMeasurement = measureLoadedImage(binding, measurement);
  for (let index = 0; index < BINDING_FUNCTION_NAMES.length; index += 1) {
    const name = BINDING_FUNCTION_NAMES[index];
    const nativeFunction = binding[name];
    objectFreeze(nativeFunction.prototype);
    objectFreeze(nativeFunction);
  }
  objectFreeze(binding);
  objectDefineProperty(nativeModule, "loaded", {
    value: true,
    writable: false,
    enumerable: true,
    configurable: false,
  });
  objectDefineProperty(nativeModule, "exports", {
    value: binding,
    writable: false,
    enumerable: true,
    configurable: false,
  });
  objectFreeze(nativeModule);
  reflectApply(weakSetAdd, BRANDED_MODULE_RECORDS, [nativeModule]);
  reflectApply(weakSetAdd, BRANDED_BINDINGS, [binding]);
  objectDefineProperty(NATIVE_CACHE, resolved, {
    value: nativeModule,
    writable: false,
    enumerable: true,
    configurable: false,
  });
  const port = objectFreeze({
    registerUnixPeerDescriptor: binding.registerUnixPeerDescriptor,
    inspectRegisteredUnixPeer: binding.inspectRegisteredUnixPeer,
    inspectCurrentSelf: binding.inspectCurrentSelf,
    createUnixAcceptor: binding.createUnixAcceptor,
    acceptUnixConnection: binding.acceptUnixConnection,
    readAcceptedConnectionIdentity: binding.readAcceptedConnectionIdentity,
    writeAcceptedConnectionFrame: binding.writeAcceptedConnectionFrame,
    readAcceptedConnectionFrame: binding.readAcceptedConnectionFrame,
    closeUnixAcceptor: binding.closeUnixAcceptor,
    closeAcceptedConnection: binding.closeAcceptedConnection,
    implementation_digest: measurement.implementation_digest,
    measurement_scheme: "darwin_addon_file_sha256_before_after_direct_dlopen_v2",
    loaded_image_measurement_scheme:
      loadedImageMeasurement.measurement_scheme,
    loaded_image_file_sha256: loadedImageMeasurement.file_sha256,
    loaded_image_identity_digest: loadedImageMeasurement.identity_digest,
    loaded_image_canonical_path_digest:
      loadedImageMeasurement.canonical_path_digest,
    loaded_image_file_identity_digest:
      loadedImageMeasurement.file_identity_digest,
    loaded_image_lc_uuid_digest: loadedImageMeasurement.lc_uuid_digest,
    loaded_image_header_and_load_commands_digest:
      loadedImageMeasurement.header_and_load_commands_digest,
    loaded_image_executable_segments_digest:
      loadedImageMeasurement.executable_segments_digest,
    loaded_image_executable_segment_count:
      loadedImageMeasurement.executable_segment_count,
    loaded_image_executable_file_bytes:
      loadedImageMeasurement.executable_file_bytes,
    loaded_image_dyld_header_unique:
      loadedImageMeasurement.dyld_header_unique,
    loaded_image_dladdr_base_matches_dyld:
      loadedImageMeasurement.dladdr_base_matches_dyld,
    loaded_image_dyld_snapshot_stable:
      loadedImageMeasurement.dyld_snapshot_stable,
    loaded_image_dyld_canonical_path_matches_dladdr:
      loadedImageMeasurement.dyld_canonical_path_matches_dladdr,
    loaded_image_callback_in_executable_segment:
      loadedImageMeasurement.callback_in_executable_segment,
    loaded_image_header_and_load_commands_match_file:
      loadedImageMeasurement.header_and_load_commands_match_file,
    loaded_image_executable_segments_match_file:
      loadedImageMeasurement.executable_segments_match_file,
    loaded_image_executable_pages_read_execute_only:
      loadedImageMeasurement.executable_pages_read_execute_only,
    loaded_image_executable_segment_file_size_equals_vm_size:
      loadedImageMeasurement.executable_segment_file_size_equals_vm_size,
    loaded_image_non_executable_runtime_state_measured:
      loadedImageMeasurement.non_executable_runtime_state_measured,
    loaded_image_executable_identity_complete:
      loadedImageMeasurement.executable_image_identity_complete,
    loaded_image_full_runtime_state_identity_complete:
      loadedImageMeasurement.full_runtime_state_identity_complete,
  });
  loadedState = objectFreeze({
    resolved,
    measurement,
    module_record: nativeModule,
    binding,
    port,
    loaded_image_measurement: loadedImageMeasurement,
  });
  assertBrandedCacheEntry(loadedState);
  return port;
}

function getHostIdentity() {
  assertHostProcessUntampered();
  return HOST_IDENTITY;
}

function reserveSelfIdentityInspection() {
  assertHostProcessUntampered();
  if (objectGetOwnPropertyDescriptor(HOST_PROCESS, SELF_INSPECTION_MARK) != null) {
    throw loaderError();
  }
  try {
    objectDefineProperty(HOST_PROCESS, SELF_INSPECTION_MARK, {
      value: true,
      writable: false,
      enumerable: false,
      configurable: false,
    });
  } catch {
    throw loaderError();
  }
  const mark = objectGetOwnPropertyDescriptor(HOST_PROCESS, SELF_INSPECTION_MARK);
  if (mark == null || mark.value !== true || mark.writable !== false
      || mark.enumerable !== false || mark.configurable !== false) {
    throw loaderError();
  }
}

module.exports = {
  getHostIdentity,
  loadNativeBindingOnce,
  reserveSelfIdentityInspection,
};
