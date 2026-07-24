"use strict";

// Optional Darwin kernel serial-custody precursor. Import and construction are
// inert: native code is loaded only by the explicit fixture-only open call.
// Real device opens are refused before native loading because Darwin tty APIs
// cannot prove that DTR remained deasserted before/during open(2).

const crypto = require("node:crypto");
const fs = require("node:fs");
const hostProcess = require("node:process");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const SafeError = Error;
const globalObject = globalThis;
const functionToString = Function.prototype.toString;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const functionPrototype = Function.prototype;
const objectPrototype = Object.prototype;
const nativeBindingCache = require.cache;
const hostProcessGlobalDescriptor = objectGetOwnPropertyDescriptor(globalObject, "process");
const hostProcessDlopenDescriptor = objectGetOwnPropertyDescriptor(hostProcess, "dlopen");
const hostProcessPlatformDescriptor = objectGetOwnPropertyDescriptor(hostProcess, "platform");
const hostProcessArchDescriptor = objectGetOwnPropertyDescriptor(hostProcess, "arch");
const hostProcessVersionsDescriptor = objectGetOwnPropertyDescriptor(hostProcess, "versions");
const hostNodeVersionDescriptor = objectGetOwnPropertyDescriptor(
  hostProcessVersionsDescriptor?.value,
  "node",
);
const hostNapiVersionDescriptor = objectGetOwnPropertyDescriptor(
  hostProcessVersionsDescriptor?.value,
  "napi",
);
const processGetuid = hostProcess.getuid;
const processGeteuid = hostProcess.geteuid;
const processGetgid = hostProcess.getgid;
const processGetegid = hostProcess.getegid;
const fsCloseSync = fs.closeSync;
const fsFstatSync = fs.fstatSync;
const fsLstatSync = fs.lstatSync;
const fsOpenSync = fs.openSync;
const fsReadFileSync = fs.readFileSync;
const fsRealpathNative = fs.realpathSync.native;
const fsOpenReadOnly = fs.constants.O_RDONLY;
const fsOpenCloseOnExec = fs.constants.O_CLOEXEC || 0;
const fsOpenNoFollow = fs.constants.O_NOFOLLOW || 0;
const pathJoin = path.join;
const pathResolve = path.resolve;

const DARWIN_SERIAL_CUSTODY_VERSION = 1;
const DARWIN_SERIAL_CUSTODY_PRIMITIVE =
  "darwin_openat_tiocexcl_termios_exact_frame_v1";
const DARWIN_SERIAL_PREOPEN_DTR_BLOCKER =
  "darwin_tty_preopen_dtr_history_unprovable";
const DARWIN_SERIAL_CUSTODY_ASSURANCE = Object.freeze({
  version: DARWIN_SERIAL_CUSTODY_VERSION,
  primitive: DARWIN_SERIAL_CUSTODY_PRIMITIVE,
  production_ready: false,
  hil_proven: false,
  real_device_open_enabled: false,
  device_enumeration_exposed: false,
  raw_path_projection_exposed: false,
  raw_serial_projection_exposed: false,
  raw_fd_projection_exposed: false,
  generic_read_surface_exposed: false,
  generic_write_surface_exposed: false,
  pre_open_dtr_deassertion_guaranteed: false,
  transient_dtr_deassertion_guaranteed: false,
  post_open_tty_line_state_is_preopen_history_evidence: false,
  operator_device_identity_kernel_measurement_complete: false,
  device_acl_profile_match_is_policy_authorization: false,
  blocker_code: DARWIN_SERIAL_PREOPEN_DTR_BLOCKER,
  blocker_reason:
    "Darwin TIOCCDTR/TIOCMBIC require an open tty descriptor; O_NOCTTY does not configure modem lines",
  required_successor:
    "measured exclusive IOUSBHost/IOKit CDC ACM control-line provider or independent continuously timestamped DTR/RTS HIL witness",
});

const MAX_NATIVE_BINDING_BYTES = 16 * 1024 * 1024;
const MAX_ACL_PROFILE_BYTES = 64 * 1024;
const MAX_FRAME_BYTES = 16 * 1024;
const MAX_TIMEOUT_MS = 1000;
const SOF = 0x11;
const SOF_LRC = 0xef;
const FIXED_FRAME_BYTES = 10;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,128}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,39})$/u;
const SIGNED_DECIMAL_PATTERN = /^-?(?:0|[1-9][0-9]{0,39})$/u;
const DEVICE_COMPONENT_PATTERN = /^ttys[A-Za-z0-9._-]{1,120}$/u;
const NATIVE_BINDING_MEASUREMENT_MARK = Symbol.for(
  "hacker-bob.instrument-chameleon-native-darwin.binding-measurement.v1",
);
const NATIVE_BINDING_FUNCTIONS = Object.freeze([
  "abortExact", "closeExact", "openExact", "transactExact",
]);
const eventTargetAddEventListener = EventTarget.prototype.addEventListener;
const eventTargetRemoveEventListener = EventTarget.prototype.removeEventListener;
const DIRECTORY_STAT_FIELDS = Object.freeze([
  "ctime_ns", "dev", "gid", "ino", "mode", "nlink", "uid",
]);
const DEVICE_STAT_FIELDS = Object.freeze([
  "ctime_ns", "dev", "gid", "ino", "mode", "nlink", "rdev", "uid",
]);
const OPEN_ATTESTATION_FIELDS = Object.freeze([
  "acl_profile_digest",
  "close_on_exec",
  "connection_generation",
  "device_stat_digest",
  "directory_stat_digest",
  "dtr_preopen_guaranteed",
  "dtr_transient_guaranteed",
  "exclusive_open",
  "fixture_only",
  "no_controlling_tty",
  "no_follow",
  "operator_device_identity_digest",
  "post_open_dtr_state",
  "post_open_rts_state",
  "primitive",
  "production_ready",
  "raw_115200_8n1",
  "version",
  "worker_identity_digest",
]);

const PORTS = new WeakSet();
const PORT_STATE = new WeakMap();
const OPEN_GRANTS = new WeakSet();
const OPEN_GRANT_STATE = new WeakMap();
const HANDLES = new WeakSet();
const HANDLE_STATE = new WeakMap();
const TRANSACTION_GRANTS = new WeakSet();
const TRANSACTION_GRANT_STATE = new WeakMap();
const TRANSACTION_RESULTS = new WeakSet();
const TRANSACTION_RESULT_STATE = new WeakMap();
const BRANDED_NATIVE_MODULE_RECORDS = new WeakSet();
const BRANDED_NATIVE_BINDINGS = new WeakSet();
let measuredBinding = null;

function custodyError(code = "darwin_native_serial_custody_rejected") {
  const error = new SafeError("Darwin native serial custody was rejected");
  objectDefineProperty(error, "code", {
    value: code,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return error;
}

function sameDescriptor(actual, expected) {
  if (actual == null || expected == null) return false;
  for (const field of ["value", "get", "set", "writable", "enumerable", "configurable"]) {
    if (objectHasOwn(actual, field) !== objectHasOwn(expected, field)) return false;
    if (objectHasOwn(expected, field) && actual[field] !== expected[field]) return false;
  }
  return true;
}

function assertHostRuntimeUntampered() {
  const currentGlobalProcess = objectGetOwnPropertyDescriptor(globalObject, "process");
  if (!sameDescriptor(currentGlobalProcess, hostProcessGlobalDescriptor)
      || typeof hostProcessGlobalDescriptor?.get !== "function") {
    throw custodyError();
  }
  let currentProcess;
  try {
    currentProcess = reflectApply(hostProcessGlobalDescriptor.get, globalObject, []);
  } catch {
    throw custodyError();
  }
  if (currentProcess !== hostProcess
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(hostProcess, "dlopen"),
        hostProcessDlopenDescriptor,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(hostProcess, "platform"),
        hostProcessPlatformDescriptor,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(hostProcess, "arch"),
        hostProcessArchDescriptor,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(hostProcess, "versions"),
        hostProcessVersionsDescriptor,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(hostProcessVersionsDescriptor?.value, "node"),
        hostNodeVersionDescriptor,
      )
      || !sameDescriptor(
        objectGetOwnPropertyDescriptor(hostProcessVersionsDescriptor?.value, "napi"),
        hostNapiVersionDescriptor,
      )
      || hostProcessPlatformDescriptor?.value !== "darwin"
      || hostProcessArchDescriptor?.value !== "arm64"
      || typeof hostNodeVersionDescriptor?.value !== "string"
      || !hostNodeVersionDescriptor.value.startsWith("20.")
      || hostNapiVersionDescriptor?.value !== "9"
      || typeof hostProcessDlopenDescriptor?.value !== "function") {
    throw custodyError();
  }
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true) {
      return false;
    }
  }
  return true;
}

function assertExactObject(value, label, fields) {
  if (!isPlainDataObject(value)) throw custodyError();
  const keys = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (keys.length !== expected.length
      || keys.some((key, index) => key !== expected[index])) throw custodyError();
  return value;
}

function assertIdentifier(value) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) throw custodyError();
  return value;
}

function assertDigest(value) {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) throw custodyError();
  return value;
}

function assertNonce(value) {
  if (typeof value !== "string" || !NONCE_PATTERN.test(value)) throw custodyError();
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length < 16 || decoded.toString("base64url") !== value) throw custodyError();
  return value;
}

function assertInteger(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw custodyError();
  }
  return value;
}

function assertDecimal(value, signed = false) {
  if (typeof value !== "string"
      || !(signed ? SIGNED_DECIMAL_PATTERN : DECIMAL_PATTERN).test(value)
      || value === "-0") throw custodyError();
  return value;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  )).join(",")}}`;
}

function framedDigest(domain, fields) {
  const hash = crypto.createHash("sha256");
  hash.update(domain, "utf8");
  for (const field of fields) {
    const bytes = Buffer.isBuffer(field) ? field : Buffer.from(String(field), "utf8");
    const length = Buffer.allocUnsafe(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    hash.update(length);
    hash.update(bytes);
    length.fill(0);
  }
  return hash.digest("hex");
}

function deriveDarwinSerialAclProfileDigest(input) {
  assertExactObject(input, "darwin_serial_acl_profile", ["state", "bytes"]);
  if (input.state !== "absent" && input.state !== "present") throw custodyError();
  if (!Buffer.isBuffer(input.bytes) && !(input.bytes instanceof Uint8Array)) {
    throw custodyError();
  }
  const bytes = Buffer.from(input.bytes);
  try {
    if (bytes.length > MAX_ACL_PROFILE_BYTES
        || (input.state === "absent" && bytes.length !== 0)
        || (input.state === "present" && bytes.length === 0)) throw custodyError();
    return framedDigest(
      "hacker-bob/chameleon-darwin-device-acl-profile/v1",
      [input.state, bytes],
    );
  } finally {
    bytes.fill(0);
  }
}

function deriveDarwinSerialWorkerIdentityDigest(input) {
  assertExactObject(input, "darwin_serial_worker_identity", [
    "acl_profile_digest", "worker_gid", "worker_uid",
  ]);
  const uid = assertInteger(input.worker_uid, 0, 0xffff_fffe);
  const gid = assertInteger(input.worker_gid, 0, 0xffff_fffe);
  return framedDigest(
    "hacker-bob/chameleon-darwin-worker-device-authority/v1",
    [String(uid), String(gid), assertDigest(input.acl_profile_digest)],
  );
}

function normalizeStat(input, fields) {
  assertExactObject(input, "darwin_serial_expected_stat", fields);
  const output = {};
  for (const field of fields) {
    output[field] = assertDecimal(input[field], field === "dev" || field === "rdev");
  }
  return Object.freeze(output);
}

function statDigest(domain, value) {
  return crypto.createHash("sha256")
    .update(domain, "utf8")
    .update(Buffer.from([0]))
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function normalizePortInput(input, fixtureOnly) {
  assertExactObject(input, "darwin_serial_custody_port", [
    "acl_profile_bytes",
    "acl_profile_digest",
    "acl_profile_state",
    "custody_id",
    "device_name",
    "directory_path",
    "enrollment_id",
    "expected_device",
    "expected_directory",
    "operator_device_identity_digest",
    "version",
    "worker_gid",
    "worker_identity_digest",
    "worker_uid",
  ]);
  if (input.version !== DARWIN_SERIAL_CUSTODY_VERSION) throw custodyError();
  if (typeof input.directory_path !== "string" || !path.isAbsolute(input.directory_path)
      || input.directory_path.length < 1 || Buffer.byteLength(input.directory_path) > 4096
      || input.directory_path.includes("\0")) throw custodyError();
  if (typeof input.device_name !== "string" || input.device_name.length < 1
      || Buffer.byteLength(input.device_name) > 255 || input.device_name.includes("/")
      || input.device_name === "." || input.device_name === ".."
      || input.device_name.includes("\0")) throw custodyError();
  if (fixtureOnly && (input.directory_path !== "/dev"
      || !DEVICE_COMPONENT_PATTERN.test(input.device_name)
      || hostProcess.env.BOB_CHAMELEON_DARWIN_PTY_FIXTURE !== "1")) throw custodyError();
  if (!Buffer.isBuffer(input.acl_profile_bytes)
      && !(input.acl_profile_bytes instanceof Uint8Array)) throw custodyError();
  const aclBytes = Buffer.from(input.acl_profile_bytes);
  if (aclBytes.length > MAX_ACL_PROFILE_BYTES) {
    aclBytes.fill(0);
    throw custodyError();
  }
  const aclState = input.acl_profile_state;
  if (aclState !== "absent" && aclState !== "present") {
    aclBytes.fill(0);
    throw custodyError();
  }
  const aclDigest = deriveDarwinSerialAclProfileDigest({ state: aclState, bytes: aclBytes });
  const workerUid = assertInteger(input.worker_uid, 0, 0xffff_fffe);
  const workerGid = assertInteger(input.worker_gid, 0, 0xffff_fffe);
  if (typeof processGetuid !== "function" || typeof processGeteuid !== "function"
      || typeof processGetgid !== "function" || typeof processGetegid !== "function") {
    aclBytes.fill(0);
    throw custodyError();
  }
  const realUid = reflectApply(processGetuid, hostProcess, []);
  const effectiveUid = reflectApply(processGeteuid, hostProcess, []);
  const realGid = reflectApply(processGetgid, hostProcess, []);
  const effectiveGid = reflectApply(processGetegid, hostProcess, []);
  const workerDigest = deriveDarwinSerialWorkerIdentityDigest({
    worker_uid: workerUid,
    worker_gid: workerGid,
    acl_profile_digest: aclDigest,
  });
  if (input.acl_profile_digest !== aclDigest
      || input.worker_identity_digest !== workerDigest
      || realUid !== workerUid || effectiveUid !== workerUid || realUid !== effectiveUid
      || realGid !== workerGid || effectiveGid !== workerGid || realGid !== effectiveGid) {
    aclBytes.fill(0);
    throw custodyError();
  }
  const expectedDirectory = normalizeStat(input.expected_directory, DIRECTORY_STAT_FIELDS);
  const expectedDevice = normalizeStat(input.expected_device, DEVICE_STAT_FIELDS);
  // The type bits in st_mode must already name a character device. Darwin's
  // S_IFMT/S_IFCHR values are stable ABI constants (0170000/0020000 octal).
  if ((Number(BigInt(expectedDevice.mode) & 0o170000n)) !== 0o020000
      || expectedDevice.nlink !== "1") {
    aclBytes.fill(0);
    throw custodyError();
  }
  return {
    custody_id: assertIdentifier(input.custody_id),
    enrollment_id: assertIdentifier(input.enrollment_id),
    operator_device_identity_digest: assertDigest(input.operator_device_identity_digest),
    directory_path: input.directory_path,
    device_name: input.device_name,
    expected_directory: expectedDirectory,
    expected_device: expectedDevice,
    directory_stat_digest: statDigest(
      "hacker-bob/chameleon-darwin-directory-stat/v1",
      expectedDirectory,
    ),
    device_stat_digest: statDigest(
      "hacker-bob/chameleon-darwin-device-stat/v1",
      expectedDevice,
    ),
    acl_profile_state: aclState,
    acl_profile_bytes: aclBytes,
    acl_profile_digest: aclDigest,
    worker_uid: workerUid,
    worker_gid: workerGid,
    worker_identity_digest: workerDigest,
    fixture_only: fixtureOnly,
  };
}

function rejectSerialization() {
  throw custodyError("darwin_native_serial_capability_not_serializable");
}

function createPort(input, fixtureOnly) {
  const normalized = normalizePortInput(input, fixtureOnly);
  const port = Object.freeze({
    version: DARWIN_SERIAL_CUSTODY_VERSION,
    kind: "darwin_chameleon_serial_custody_port",
    custody_id: normalized.custody_id,
    enrollment_id: normalized.enrollment_id,
    operator_device_identity_digest: normalized.operator_device_identity_digest,
    fixture_only: fixtureOnly,
    production_ready: false,
    hil_proven: false,
    blocker_code: DARWIN_SERIAL_PREOPEN_DTR_BLOCKER,
    capability_id: `darwin-serial-custody:${crypto.randomBytes(18).toString("base64url")}`,
    toJSON: rejectSerialization,
  });
  PORTS.add(port);
  PORT_STATE.set(port, {
    ...normalized,
    phase: "closed",
    last_generation: 0,
    open_grant: null,
    handle: null,
    destroyed: false,
  });
  return port;
}

function createDarwinSerialCustodyPort(input) {
  return createPort(input, false);
}

function createDarwinSerialPtyFixtureCustodyPort(input) {
  return createPort(input, true);
}

function assertDarwinSerialCustodyPort(input) {
  const state = input == null ? null : PORT_STATE.get(input);
  if (!input || !PORTS.has(input) || !state || !Object.isFrozen(input)
      || input.version !== DARWIN_SERIAL_CUSTODY_VERSION
      || input.kind !== "darwin_chameleon_serial_custody_port"
      || input.custody_id !== state.custody_id
      || input.enrollment_id !== state.enrollment_id
      || input.operator_device_identity_digest !== state.operator_device_identity_digest
      || input.fixture_only !== state.fixture_only || input.production_ready !== false
      || input.hil_proven !== false || input.blocker_code !== DARWIN_SERIAL_PREOPEN_DTR_BLOCKER
      || Reflect.ownKeys(input).length !== 11) throw custodyError();
  return input;
}

function createDarwinSerialOpenGeneration(portInput, input) {
  const port = assertDarwinSerialCustodyPort(portInput);
  const state = PORT_STATE.get(port);
  assertExactObject(input, "darwin_serial_open_generation", [
    "connection_generation", "open_nonce", "version",
  ]);
  if (input.version !== DARWIN_SERIAL_CUSTODY_VERSION || state.destroyed
      || state.phase !== "closed"
      || state.handle != null || state.open_grant != null
      || input.connection_generation !== state.last_generation + 1) throw custodyError();
  const grant = Object.freeze({
    version: DARWIN_SERIAL_CUSTODY_VERSION,
    kind: "darwin_chameleon_serial_open_generation",
    custody_id: state.custody_id,
    enrollment_id: state.enrollment_id,
    connection_generation: assertInteger(input.connection_generation, 1, 0xffff_ffff),
    open_nonce: assertNonce(input.open_nonce),
    fixture_only: state.fixture_only,
    production_ready: false,
    capability_id: `darwin-serial-open:${crypto.randomBytes(18).toString("base64url")}`,
    toJSON: rejectSerialization,
  });
  OPEN_GRANTS.add(grant);
  OPEN_GRANT_STATE.set(grant, { port, port_state: state, consumed: false });
  state.open_grant = grant;
  return grant;
}

function terminallyQuarantinePort(state, phase) {
  try { state.acl_profile_bytes.fill(0); } catch {}
  state.directory_path = null;
  state.device_name = null;
  state.expected_directory = null;
  state.expected_device = null;
  state.directory_stat_digest = null;
  state.device_stat_digest = null;
  state.operator_device_identity_digest = null;
  state.acl_profile_state = null;
  state.acl_profile_digest = null;
  state.worker_uid = null;
  state.worker_gid = null;
  state.worker_identity_digest = null;
  state.open_grant = null;
  state.handle = null;
  state.destroyed = true;
  state.phase = phase;
}

function assertOpenGrant(grantInput, port, state) {
  const grantState = grantInput == null ? null : OPEN_GRANT_STATE.get(grantInput);
  if (!grantInput || !OPEN_GRANTS.has(grantInput) || !grantState
      || grantState.port !== port || grantState.port_state !== state || grantState.consumed
      || !Object.isFrozen(grantInput) || grantInput.version !== DARWIN_SERIAL_CUSTODY_VERSION
      || grantInput.kind !== "darwin_chameleon_serial_open_generation"
      || grantInput.custody_id !== state.custody_id
      || grantInput.enrollment_id !== state.enrollment_id
      || grantInput.connection_generation !== state.last_generation + 1
      || grantInput.fixture_only !== state.fixture_only || grantInput.production_ready !== false
      || Reflect.ownKeys(grantInput).length !== 10) throw custodyError();
  return grantState;
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode
    && left.uid === right.uid && left.gid === right.gid && left.nlink === right.nlink
    && left.size === right.size && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function measureNativeBinding(candidate) {
  const canonicalPath = fsRealpathNative(candidate);
  if (pathResolve(candidate) !== canonicalPath) throw custodyError();
  const fd = fsOpenSync(
    canonicalPath,
    fsOpenReadOnly | fsOpenCloseOnExec | fsOpenNoFollow,
  );
  try {
    const before = fsFstatSync(fd, { bigint: true });
    const pathBefore = fsLstatSync(canonicalPath, { bigint: true });
    if (!before.isFile() || !pathBefore.isFile() || !sameFileIdentity(before, pathBefore)
        || before.nlink !== 1n || (before.mode & 0o022n) !== 0n
        || before.size < 1n || before.size > BigInt(MAX_NATIVE_BINDING_BYTES)) {
      throw custodyError();
    }
    const bytes = fsReadFileSync(fd);
    try {
      const after = fsFstatSync(fd, { bigint: true });
      if (!sameFileIdentity(before, after) || BigInt(bytes.length) !== before.size) {
        throw custodyError();
      }
      return {
        digest: crypto.createHash("sha256").update(bytes).digest("hex"),
        canonical_path: canonicalPath,
        stat: before,
      };
    } finally {
      bytes.fill(0);
    }
  } finally {
    fsCloseSync(fd);
  }
}

function hasExactNativeBindingKeys(binding, marked) {
  const keys = reflectOwnKeys(binding);
  const expectedLength = NATIVE_BINDING_FUNCTIONS.length + (marked ? 1 : 0);
  if (keys.length !== expectedLength) return false;
  for (const name of NATIVE_BINDING_FUNCTIONS) {
    if (!keys.includes(name)) return false;
  }
  return !marked || keys.includes(NATIVE_BINDING_MEASUREMENT_MARK);
}

function assertExactNativeFunction(value, locked) {
  if (typeof value !== "function" || utilTypes.isProxy(value)
      || objectGetPrototypeOf(value) !== functionPrototype
      || reflectApply(functionToString, value, []) !== "function () { [native code] }") {
    throw custodyError();
  }
  const keys = reflectOwnKeys(value);
  const expectedKeys = ["length", "name", "arguments", "caller", "prototype"];
  if (keys.length !== expectedKeys.length
      || keys.some((key, index) => key !== expectedKeys[index])) throw custodyError();
  const length = objectGetOwnPropertyDescriptor(value, "length");
  const name = objectGetOwnPropertyDescriptor(value, "name");
  const argumentsDescriptor = objectGetOwnPropertyDescriptor(value, "arguments");
  const caller = objectGetOwnPropertyDescriptor(value, "caller");
  const prototype = objectGetOwnPropertyDescriptor(value, "prototype");
  if (length?.value !== 0 || length.writable !== false || length.enumerable !== false
      || length.configurable !== !locked || name?.value !== "" || name.writable !== false
      || name.enumerable !== false || name.configurable !== !locked
      || argumentsDescriptor?.value !== null || argumentsDescriptor.writable !== false
      || argumentsDescriptor.enumerable !== false
      || argumentsDescriptor.configurable !== false || caller?.value !== null
      || caller.writable !== false || caller.enumerable !== false
      || caller.configurable !== false || prototype == null
      || !objectHasOwn(prototype, "value") || prototype.writable !== !locked
      || prototype.enumerable !== false || prototype.configurable !== false
      || prototype.value == null || typeof prototype.value !== "object"
      || utilTypes.isProxy(prototype.value)
      || objectGetPrototypeOf(prototype.value) !== objectPrototype) {
    throw custodyError();
  }
}

function assertExactNativeBinding(binding, marked, expectedDigest) {
  if (binding == null || typeof binding !== "object" || utilTypes.isProxy(binding)
      || objectGetPrototypeOf(binding) !== objectPrototype
      || !hasExactNativeBindingKeys(binding, marked)) throw custodyError();
  for (const name of NATIVE_BINDING_FUNCTIONS) {
    const descriptor = objectGetOwnPropertyDescriptor(binding, name);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.writable !== false || descriptor.enumerable !== true
        || descriptor.configurable !== false) throw custodyError();
    assertExactNativeFunction(descriptor.value, marked);
    if (marked && (!objectIsFrozen(descriptor.value)
        || !objectIsFrozen(descriptor.value.prototype))) throw custodyError();
  }
  if (marked) {
    const mark = objectGetOwnPropertyDescriptor(binding, NATIVE_BINDING_MEASUREMENT_MARK);
    if (mark == null || !objectHasOwn(mark, "value") || mark.value !== expectedDigest
        || mark.writable !== false || mark.enumerable !== false
        || mark.configurable !== false || !objectIsFrozen(binding)) throw custodyError();
  }
}

function assertBrandedNativeCacheEntry(resolved, expectedDigest) {
  const cacheDescriptor = objectGetOwnPropertyDescriptor(nativeBindingCache, resolved);
  const moduleRecord = cacheDescriptor?.value;
  if (cacheDescriptor == null || !objectHasOwn(cacheDescriptor, "value")
      || cacheDescriptor.writable !== false || cacheDescriptor.enumerable !== true
      || cacheDescriptor.configurable !== false || moduleRecord == null
      || typeof moduleRecord !== "object" || !BRANDED_NATIVE_MODULE_RECORDS.has(moduleRecord)
      || !objectIsFrozen(moduleRecord) || objectGetPrototypeOf(moduleRecord) !== null
      || reflectOwnKeys(moduleRecord).length !== 4
      || reflectOwnKeys(moduleRecord)[0] !== "id"
      || reflectOwnKeys(moduleRecord)[1] !== "filename"
      || reflectOwnKeys(moduleRecord)[2] !== "loaded"
      || reflectOwnKeys(moduleRecord)[3] !== "exports") {
    throw custodyError();
  }
  const idDescriptor = objectGetOwnPropertyDescriptor(moduleRecord, "id");
  const filenameDescriptor = objectGetOwnPropertyDescriptor(moduleRecord, "filename");
  const loadedDescriptor = objectGetOwnPropertyDescriptor(moduleRecord, "loaded");
  if (idDescriptor?.value !== resolved || filenameDescriptor?.value !== resolved
      || loadedDescriptor?.value !== true || idDescriptor.writable !== false
      || filenameDescriptor.writable !== false || loadedDescriptor.writable !== false
      || idDescriptor.enumerable !== true || filenameDescriptor.enumerable !== true
      || loadedDescriptor.enumerable !== true || idDescriptor.configurable !== false
      || filenameDescriptor.configurable !== false || loadedDescriptor.configurable !== false) {
    throw custodyError();
  }
  const exportsDescriptor = objectGetOwnPropertyDescriptor(moduleRecord, "exports");
  const binding = exportsDescriptor?.value;
  if (exportsDescriptor == null || !objectHasOwn(exportsDescriptor, "value")
      || exportsDescriptor.value !== binding || exportsDescriptor.writable !== false
      || exportsDescriptor.enumerable !== true || exportsDescriptor.configurable !== false
      || !BRANDED_NATIVE_BINDINGS.has(binding)) {
    throw custodyError();
  }
  assertExactNativeBinding(binding, true, expectedDigest);
  return { moduleRecord, binding };
}

function loadNativeBinding() {
  try {
    assertHostRuntimeUntampered();
    const candidates = [
      pathJoin(__dirname, "..", "prebuilds", "darwin-arm64", "serial_custody.node"),
      pathJoin(__dirname, "..", "build", "Release", "serial_custody.node"),
    ];
    let selected = null;
    let before = null;
    for (const candidate of candidates) {
      try {
        before = measureNativeBinding(candidate);
        selected = before.canonical_path;
        break;
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
    }
    if (selected == null) throw custodyError();
    const resolved = selected;
    const cacheBefore = objectGetOwnPropertyDescriptor(nativeBindingCache, resolved);
    let moduleRecord;
    let binding;
    if (cacheBefore != null) {
      if (measuredBinding == null || measuredBinding.resolved !== resolved) {
        throw custodyError();
      }
      ({ moduleRecord, binding } = assertBrandedNativeCacheEntry(resolved, before.digest));
    } else {
      if (measuredBinding != null) throw custodyError();
      moduleRecord = objectCreate(null);
      objectDefineProperty(moduleRecord, "id", {
        value: resolved,
        writable: false,
        enumerable: true,
        configurable: false,
      });
      objectDefineProperty(moduleRecord, "filename", {
        value: resolved,
        writable: false,
        enumerable: true,
        configurable: false,
      });
      objectDefineProperty(moduleRecord, "loaded", {
        value: false,
        writable: true,
        enumerable: true,
        configurable: false,
      });
      objectDefineProperty(moduleRecord, "exports", {
        value: objectCreate(objectPrototype),
        writable: true,
        enumerable: true,
        configurable: false,
      });
      reflectApply(hostProcessDlopenDescriptor.value, hostProcess, [moduleRecord, resolved]);
      binding = moduleRecord.exports;
      assertExactNativeBinding(binding, false, before.digest);
    }
    const after = measureNativeBinding(selected);
    if (!sameFileIdentity(before.stat, after.stat) || before.digest !== after.digest
        || (measuredBinding != null && measuredBinding.digest !== after.digest)) {
      throw custodyError();
    }
    if (cacheBefore == null) {
      objectDefineProperty(binding, NATIVE_BINDING_MEASUREMENT_MARK, {
        value: after.digest,
        writable: false,
        enumerable: false,
        configurable: false,
      });
      for (const name of NATIVE_BINDING_FUNCTIONS) {
        objectFreeze(binding[name].prototype);
        objectFreeze(binding[name]);
      }
      objectFreeze(binding);
      objectDefineProperty(moduleRecord, "loaded", {
        value: true,
        writable: false,
        enumerable: true,
        configurable: false,
      });
      objectDefineProperty(moduleRecord, "exports", {
        value: binding,
        writable: false,
        enumerable: true,
        configurable: false,
      });
      objectFreeze(moduleRecord);
      BRANDED_NATIVE_BINDINGS.add(binding);
      BRANDED_NATIVE_MODULE_RECORDS.add(moduleRecord);
      objectDefineProperty(nativeBindingCache, resolved, {
        value: moduleRecord,
        writable: false,
        enumerable: true,
        configurable: false,
      });
    }
    assertBrandedNativeCacheEntry(resolved, after.digest);
    if (measuredBinding != null && measuredBinding.digest !== after.digest) throw custodyError();
    measuredBinding = objectFreeze({
      digest: after.digest,
      resolved,
      openExact: binding.openExact,
      transactExact: binding.transactExact,
      abortExact: binding.abortExact,
      closeExact: binding.closeExact,
    });
    return measuredBinding;
  } catch {
    throw custodyError("darwin_native_serial_binding_rejected");
  }
}

function nativeOpenConfig(state, generation) {
  return Object.freeze({
    version: DARWIN_SERIAL_CUSTODY_VERSION,
    fixture_only: state.fixture_only,
    directory_path: state.directory_path,
    final_component: state.device_name,
    expected_directory: state.expected_directory,
    expected_device: state.expected_device,
    directory_stat_digest: state.directory_stat_digest,
    device_stat_digest: state.device_stat_digest,
    operator_device_identity_digest: state.operator_device_identity_digest,
    worker_uid: state.worker_uid,
    worker_gid: state.worker_gid,
    worker_identity_digest: state.worker_identity_digest,
    acl_profile_state: state.acl_profile_state,
    acl_profile_bytes: Buffer.from(state.acl_profile_bytes),
    acl_profile_digest: state.acl_profile_digest,
    connection_generation: generation,
  });
}

function validateOpenAttestation(raw, state, generation) {
  assertExactObject(raw, "darwin_serial_native_open", ["attestation", "handle"]);
  if (raw.handle == null || typeof raw.handle !== "object") throw custodyError();
  const value = assertExactObject(
    raw.attestation,
    "darwin_serial_native_open_attestation",
    OPEN_ATTESTATION_FIELDS,
  );
  const exact = {
    version: DARWIN_SERIAL_CUSTODY_VERSION,
    primitive: DARWIN_SERIAL_CUSTODY_PRIMITIVE,
    fixture_only: true,
    operator_device_identity_digest: state.operator_device_identity_digest,
    directory_stat_digest: state.directory_stat_digest,
    device_stat_digest: state.device_stat_digest,
    worker_identity_digest: state.worker_identity_digest,
    acl_profile_digest: state.acl_profile_digest,
    connection_generation: generation,
    exclusive_open: true,
    close_on_exec: true,
    no_controlling_tty: true,
    no_follow: true,
    raw_115200_8n1: true,
    dtr_preopen_guaranteed: false,
    dtr_transient_guaranteed: false,
    production_ready: false,
  };
  for (const [field, expected] of Object.entries(exact)) {
    if (value[field] !== expected) throw custodyError();
  }
  if (![
    "deasserted_observed_after_open", "unobservable_pseudo_terminal",
  ].includes(value.post_open_dtr_state) || ![
    "deasserted_observed_after_open", "unobservable_pseudo_terminal",
  ].includes(value.post_open_rts_state)) throw custodyError();
  return raw.handle;
}

function openDarwinSerialGeneration(portInput, grantInput) {
  const port = assertDarwinSerialCustodyPort(portInput);
  const state = PORT_STATE.get(port);
  const grantState = assertOpenGrant(grantInput, port, state);
  // Consume before any native seam so reentry and failures cannot replay open.
  grantState.consumed = true;
  state.open_grant = null;
  state.last_generation = grantInput.connection_generation;
  if (!state.fixture_only) {
    terminallyQuarantinePort(state, "real_device_open_refused_terminal");
    throw custodyError(DARWIN_SERIAL_PREOPEN_DTR_BLOCKER);
  }
  let binding;
  let config;
  let raw;
  try {
    binding = loadNativeBinding();
    config = nativeOpenConfig(state, grantInput.connection_generation);
    raw = Reflect.apply(binding.openExact, undefined, [config]);
    const nativeHandle = validateOpenAttestation(raw, state, grantInput.connection_generation);
    const handle = Object.freeze({
      version: DARWIN_SERIAL_CUSTODY_VERSION,
      kind: "darwin_chameleon_serial_generation_handle",
      custody_id: state.custody_id,
      enrollment_id: state.enrollment_id,
      connection_generation: grantInput.connection_generation,
      fixture_only: true,
      production_ready: false,
      capability_id: `darwin-serial-handle:${crypto.randomBytes(18).toString("base64url")}`,
      toJSON: rejectSerialization,
    });
    HANDLES.add(handle);
    HANDLE_STATE.set(handle, {
      port,
      port_state: state,
      binding,
      native_handle: nativeHandle,
      phase: "open",
      next_transaction_sequence: 1,
      transaction_grant: null,
      transaction_promise: null,
    });
    state.handle = handle;
    state.phase = "open";
    return handle;
  } catch (error) {
    try {
      const handleDescriptor = raw == null
        ? null
        : Object.getOwnPropertyDescriptor(raw, "handle");
      if (handleDescriptor && "value" in handleDescriptor && binding != null) {
        Reflect.apply(binding.closeExact, undefined, [handleDescriptor.value]);
      }
    } catch {}
    terminallyQuarantinePort(state, "open_uncertain_terminal");
    throw error?.code === DARWIN_SERIAL_PREOPEN_DTR_BLOCKER
        || error?.code === "darwin_native_serial_binding_rejected"
      ? error
      : custodyError("darwin_native_serial_open_rejected");
  } finally {
    config?.acl_profile_bytes.fill(0);
  }
}

function assertDarwinSerialGenerationHandle(input) {
  const state = input == null ? null : HANDLE_STATE.get(input);
  if (!input || !HANDLES.has(input) || !state || !Object.isFrozen(input)
      || input.version !== DARWIN_SERIAL_CUSTODY_VERSION
      || input.kind !== "darwin_chameleon_serial_generation_handle"
      || input.custody_id !== state.port_state.custody_id
      || input.enrollment_id !== state.port_state.enrollment_id
      || input.connection_generation !== state.port_state.last_generation
      || input.fixture_only !== true || input.production_ready !== false
      || Reflect.ownKeys(input).length !== 9) throw custodyError();
  return input;
}

function calculateLrc(bytes) {
  let sum = 0;
  for (const byte of bytes) sum = (sum + byte) & 0xff;
  return (-sum) & 0xff;
}

function assertExactRequestFrame(input) {
  if (!Buffer.isBuffer(input) && !(input instanceof Uint8Array)) throw custodyError();
  const frame = Buffer.from(input);
  if (frame.length < FIXED_FRAME_BYTES || frame.length > MAX_FRAME_BYTES
      || frame[0] !== SOF || frame[1] !== SOF_LRC || frame.readUInt16BE(4) !== 0
      || calculateLrc(frame.subarray(2, 8)) !== frame[8]
      || frame.readUInt16BE(6) + FIXED_FRAME_BYTES !== frame.length
      || calculateLrc(frame.subarray(9, frame.length - 1)) !== frame[frame.length - 1]) {
    frame.fill(0);
    throw custodyError("darwin_native_serial_frame_rejected");
  }
  return frame;
}

function createDarwinSerialTransactionGrant(handleInput, input) {
  const handle = assertDarwinSerialGenerationHandle(handleInput);
  const state = HANDLE_STATE.get(handle);
  assertExactObject(input, "darwin_serial_transaction_grant", [
    "maximum_response_bytes",
    "request_bytes",
    "timeout_ms",
    "transaction_sequence",
    "version",
  ]);
  if (input.version !== DARWIN_SERIAL_CUSTODY_VERSION || state.phase !== "open"
      || state.transaction_grant != null
      || input.transaction_sequence !== state.next_transaction_sequence) throw custodyError();
  const request = assertExactRequestFrame(input.request_bytes);
  let maximumResponseBytes;
  let timeoutMs;
  let requestDigest;
  try {
    maximumResponseBytes = assertInteger(
      input.maximum_response_bytes,
      FIXED_FRAME_BYTES,
      MAX_FRAME_BYTES,
    );
    timeoutMs = assertInteger(input.timeout_ms, 1, MAX_TIMEOUT_MS);
    requestDigest = framedDigest(
      "hacker-bob/chameleon-darwin-exact-request/v1",
      [request],
    );
  } catch (error) {
    request.fill(0);
    throw error;
  }
  const grant = Object.freeze({
    version: DARWIN_SERIAL_CUSTODY_VERSION,
    kind: "darwin_chameleon_serial_transaction_grant",
    custody_id: state.port_state.custody_id,
    enrollment_id: state.port_state.enrollment_id,
    connection_generation: handle.connection_generation,
    transaction_sequence: input.transaction_sequence,
    request_digest: requestDigest,
    maximum_response_bytes: maximumResponseBytes,
    timeout_ms: timeoutMs,
    fixture_only: true,
    production_ready: false,
    capability_id: `darwin-serial-transaction:${crypto.randomBytes(18).toString("base64url")}`,
    toJSON: rejectSerialization,
  });
  TRANSACTION_GRANTS.add(grant);
  TRANSACTION_GRANT_STATE.set(grant, {
    handle,
    handle_state: state,
    request_bytes: request,
    consumed: false,
  });
  state.transaction_grant = grant;
  return grant;
}

function assertAbortSignal(input) {
  if (input == null || typeof input !== "object" || utilTypes.isProxy(input)
      || Object.getPrototypeOf(input) !== AbortSignal.prototype
      || typeof input.aborted !== "boolean") throw custodyError();
  return input;
}

function createTransactionResult(handle, grant, response) {
  const responseBytes = Buffer.from(response);
  const result = {
    version: DARWIN_SERIAL_CUSTODY_VERSION,
    kind: "darwin_chameleon_serial_transaction_result",
    custody_id: grant.custody_id,
    enrollment_id: grant.enrollment_id,
    connection_generation: grant.connection_generation,
    transaction_sequence: grant.transaction_sequence,
    request_digest: grant.request_digest,
    response_digest: framedDigest(
      "hacker-bob/chameleon-darwin-exact-response/v1",
      [responseBytes],
    ),
    fixture_only: true,
    production_ready: false,
    toJSON: rejectSerialization,
  };
  Object.defineProperty(result, "response_bytes", {
    value: responseBytes,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  Object.freeze(result);
  TRANSACTION_RESULTS.add(result);
  TRANSACTION_RESULT_STATE.set(result, { handle, response_bytes: responseBytes });
  return result;
}

function executeDarwinSerialTransaction(handleInput, grantInput, input) {
  const handle = assertDarwinSerialGenerationHandle(handleInput);
  const state = HANDLE_STATE.get(handle);
  const grantState = grantInput == null ? null : TRANSACTION_GRANT_STATE.get(grantInput);
  assertExactObject(input, "darwin_serial_transaction_execution", ["signal", "version"]);
  const signal = assertAbortSignal(input.signal);
  if (input.version !== DARWIN_SERIAL_CUSTODY_VERSION || !grantInput
      || !TRANSACTION_GRANTS.has(grantInput) || !grantState || grantState.handle !== handle
      || grantState.handle_state !== state || grantState.consumed
      || state.transaction_grant !== grantInput || state.phase !== "open"
      || grantInput.connection_generation !== handle.connection_generation
      || grantInput.transaction_sequence !== state.next_transaction_sequence
      || grantInput.request_digest !== framedDigest(
        "hacker-bob/chameleon-darwin-exact-request/v1",
        [grantState.request_bytes],
      )) throw custodyError();
  // Consume synchronously before AbortSignal or native interaction.
  grantState.consumed = true;
  state.transaction_grant = null;
  state.next_transaction_sequence += 1;
  state.phase = "transaction";
  if (signal.aborted) {
    grantState.request_bytes.fill(0);
    state.phase = "quarantined";
    try { Reflect.apply(state.binding.closeExact, undefined, [state.native_handle]); } catch {}
    return Promise.reject(custodyError("darwin_native_serial_transaction_ambiguous"));
  }
  const requestForNative = Buffer.from(grantState.request_bytes);
  grantState.request_bytes.fill(0);
  let nativePromise;
  const onAbort = () => {
    try {
      Reflect.apply(state.binding.abortExact, undefined, [
        state.native_handle,
        handle.connection_generation,
        grantInput.transaction_sequence,
      ]);
    } catch {}
  };
  try {
    Reflect.apply(eventTargetAddEventListener, signal, ["abort", onAbort, { once: true }]);
    if (signal.aborted) onAbort();
    nativePromise = Reflect.apply(state.binding.transactExact, undefined, [
      state.native_handle,
      handle.connection_generation,
      grantInput.transaction_sequence,
      requestForNative,
      grantInput.maximum_response_bytes,
      grantInput.timeout_ms,
    ]);
    if (nativePromise == null || typeof nativePromise.then !== "function") throw custodyError();
  } catch {
    Reflect.apply(eventTargetRemoveEventListener, signal, ["abort", onAbort]);
    requestForNative.fill(0);
    state.phase = "quarantined";
    try { Reflect.apply(state.binding.closeExact, undefined, [state.native_handle]); } catch {}
    return Promise.reject(custodyError("darwin_native_serial_transaction_ambiguous"));
  }
  const settled = Promise.resolve(nativePromise).then((rawResponse) => {
    if ((!Buffer.isBuffer(rawResponse) && !(rawResponse instanceof Uint8Array))
        || rawResponse.byteLength < FIXED_FRAME_BYTES
        || rawResponse.byteLength > grantInput.maximum_response_bytes) throw custodyError();
    const response = Buffer.from(rawResponse);
    try {
      if (response[0] !== SOF || response[1] !== SOF_LRC
          || response.readUInt16BE(2) !== requestForNative.readUInt16BE(2)
          || calculateLrc(response.subarray(2, 8)) !== response[8]
          || response.readUInt16BE(6) + FIXED_FRAME_BYTES !== response.length
          || calculateLrc(response.subarray(9, response.length - 1))
            !== response[response.length - 1] || signal.aborted) throw custodyError();
      state.phase = "open";
      return createTransactionResult(handle, grantInput, response);
    } finally {
      response.fill(0);
      try { rawResponse.fill(0); } catch {}
    }
  }, () => {
    throw custodyError();
  }).catch(() => {
    state.phase = "quarantined";
    try { Reflect.apply(state.binding.closeExact, undefined, [state.native_handle]); } catch {}
    throw custodyError("darwin_native_serial_transaction_ambiguous");
  }).finally(() => {
    try {
      Reflect.apply(eventTargetRemoveEventListener, signal, ["abort", onAbort]);
    } catch {}
    requestForNative.fill(0);
    state.transaction_promise = null;
  });
  state.transaction_promise = settled;
  return settled;
}

function assertDarwinSerialTransactionResult(input, handleInput) {
  const handle = assertDarwinSerialGenerationHandle(handleInput);
  const state = input == null ? null : TRANSACTION_RESULT_STATE.get(input);
  if (!input || !TRANSACTION_RESULTS.has(input) || !state || state.handle !== handle
      || !Object.isFrozen(input) || !Buffer.isBuffer(input.response_bytes)
      || input.version !== DARWIN_SERIAL_CUSTODY_VERSION
      || input.kind !== "darwin_chameleon_serial_transaction_result"
      || input.fixture_only !== true || input.production_ready !== false
      || input.response_digest !== framedDigest(
        "hacker-bob/chameleon-darwin-exact-response/v1",
        [input.response_bytes],
      ) || Reflect.ownKeys(input).length !== 12) throw custodyError();
  return input;
}

function consumeOutstandingTransactionGrant(state) {
  if (state.transaction_grant == null) return;
  const grantState = TRANSACTION_GRANT_STATE.get(state.transaction_grant);
  if (grantState) {
    grantState.consumed = true;
    grantState.request_bytes.fill(0);
  }
  state.transaction_grant = null;
}

function closeDarwinSerialGeneration(handleInput) {
  const handle = assertDarwinSerialGenerationHandle(handleInput);
  const state = HANDLE_STATE.get(handle);
  if (state.transaction_promise != null) throw custodyError();
  if (state.phase === "closed") return Object.freeze({ closed: true });
  // Revoke and zero an unexecuted request before entering the uncertain native
  // close seam; neither success nor failure may leave command bytes reusable.
  consumeOutstandingTransactionGrant(state);
  let closed;
  try {
    closed = Reflect.apply(state.binding.closeExact, undefined, [state.native_handle]);
  } catch {
    state.phase = "close_uncertain";
    terminallyQuarantinePort(state.port_state, "close_uncertain_terminal");
    throw custodyError("darwin_native_serial_close_uncertain");
  }
  if (closed !== true) {
    state.phase = "close_uncertain";
    terminallyQuarantinePort(state.port_state, "close_uncertain_terminal");
    throw custodyError("darwin_native_serial_close_uncertain");
  }
  state.phase = "closed";
  terminallyQuarantinePort(state.port_state, "closed_terminal");
  return Object.freeze({ closed: true });
}

module.exports = {
  DARWIN_SERIAL_CUSTODY_ASSURANCE,
  DARWIN_SERIAL_CUSTODY_PRIMITIVE,
  DARWIN_SERIAL_CUSTODY_VERSION,
  DARWIN_SERIAL_PREOPEN_DTR_BLOCKER,
  assertDarwinSerialCustodyPort,
  assertDarwinSerialGenerationHandle,
  assertDarwinSerialTransactionResult,
  closeDarwinSerialGeneration,
  createDarwinSerialCustodyPort,
  createDarwinSerialOpenGeneration,
  createDarwinSerialPtyFixtureCustodyPort,
  createDarwinSerialTransactionGrant,
  deriveDarwinSerialAclProfileDigest,
  deriveDarwinSerialWorkerIdentityDigest,
  executeDarwinSerialTransaction,
  openDarwinSerialGeneration,
};
