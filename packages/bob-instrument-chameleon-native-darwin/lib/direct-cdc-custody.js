"use strict";

// Optional IOUSBHost CDC ACM successor skeleton. Import and construction are
// inert. Real-device activation is refused before native loading; the native
// target currently exercises only an in-memory descriptor/state fixture.

const crypto = require("node:crypto");
const fs = require("node:fs");
const hostProcess = require("node:process");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const SafeError = Error;
const SafeBigInt = BigInt;
const SafeNumber = Number;
const SafeString = String;
const HostBuffer = Buffer;
const arrayIsArray = Array.isArray;
const bufferAlloc = HostBuffer.alloc;
const bufferAllocUnsafe = HostBuffer.allocUnsafe;
const bufferFrom = HostBuffer.from;
const hostBufferPrototype = HostBuffer.prototype;
const bufferEquals = HostBuffer.prototype.equals;
const bufferFill = HostBuffer.prototype.fill;
const bufferReadUInt16BE = HostBuffer.prototype.readUInt16BE;
const bufferReadUInt16LE = HostBuffer.prototype.readUInt16LE;
const bufferSubarray = HostBuffer.prototype.subarray;
const bufferToString = HostBuffer.prototype.toString;
const bufferWriteBigUInt64BE = HostBuffer.prototype.writeBigUInt64BE;
const bufferWriteUInt16LE = HostBuffer.prototype.writeUInt16LE;
const cryptoCreateHash = crypto.createHash;
const cryptoRandomBytes = crypto.randomBytes;
const functionToString = Function.prototype.toString;
const functionPrototype = Function.prototype;
const globalObject = globalThis;
const nativeBindingCache = require.cache;
const numberIsSafeInteger = Number.isSafeInteger;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectKeys = Object.keys;
const objectPrototype = Object.prototype;
const hostBufferGlobalDescriptor = objectGetOwnPropertyDescriptor(globalObject, "Buffer");
const hostBufferFromDescriptor = objectGetOwnPropertyDescriptor(HostBuffer, "from");
const hostBufferIsBufferDescriptor = objectGetOwnPropertyDescriptor(HostBuffer, "isBuffer");
const hostBufferAllocDescriptor = objectGetOwnPropertyDescriptor(HostBuffer, "alloc");
const hostBufferAllocUnsafeDescriptor = objectGetOwnPropertyDescriptor(HostBuffer, "allocUnsafe");
const regexpTest = RegExp.prototype.test;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const stringStartsWith = String.prototype.startsWith;
const utilIsProxy = utilTypes.isProxy;
const utilIsUint8Array = utilTypes.isUint8Array;
const weakMapGet = WeakMap.prototype.get;
const weakMapSet = WeakMap.prototype.set;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;
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
const fixtureEnvironmentGate =
  hostProcess.env.BOB_CHAMELEON_DARWIN_DIRECT_CDC_FIXTURE === "1";
const hashProbe = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
const hashPrototype = objectGetPrototypeOf(hashProbe);
const hashUpdate = hashPrototype.update;
const hashDigest = hashPrototype.digest;
reflectApply(hashDigest, hashProbe, []);

const DARWIN_DIRECT_CDC_VERSION = 1;
const DARWIN_DIRECT_CDC_PRIMITIVE = "darwin_iousbhost_cdc_acm_exact_v1";
const DARWIN_DIRECT_CDC_REAL_BLOCKER = "darwin_direct_cdc_real_open_disabled";
const DARWIN_DIRECT_CDC_ASSURANCE = objectFreeze({
  version: DARWIN_DIRECT_CDC_VERSION,
  primitive: DARWIN_DIRECT_CDC_PRIMITIVE,
  production_ready: false,
  hil_proven: false,
  real_device_open_enabled: false,
  import_and_construction_inert: true,
  device_enumeration_exposed: false,
  raw_io_service_exposed: false,
  raw_usb_pipe_exposed: false,
  raw_serial_projection_exposed: false,
  generic_read_surface_exposed: false,
  generic_write_surface_exposed: false,
  fixture_transport_frame_injection_exposed: true,
  fixture_response_bytes_projection_exposed: true,
  real_mode_caller_shaped_transport_exposed: false,
  device_capture_semantics:
    "terminates existing IOUSBHostDevice and associated interface clients/drivers",
  device_seize_semantics: "requests that the current owner close; it is not forced capture",
  control_line_request: "bmRequestType=0x21,bRequest=0x22,wValue=0,wLength=0",
  control_line_state_before_bulk_required: true,
  launch_ticket_verification: "digest_and_shape_only",
  launch_ticket_signature_verified: false,
  launch_ticket_nonce_replay_authority_verified: false,
  launch_ticket_expiry_authority_verified: false,
  entitlement_qualification_kernel_verified: false,
  io_service_authorization_kernel_verified: false,
  blocker_code: DARWIN_DIRECT_CDC_REAL_BLOCKER,
  production_blockers: objectFreeze([
    "real_iousbhost_activation_not_enabled",
    "signed_immutable_node20_arm64_prebuild_missing",
    "dedicated_principal_and_device_acl_unqualified",
    "vm_device_access_entitlement_qualification_missing",
    "privileged_launch_ticket_signature_and_expiry_verification_missing",
    "semantic_compiler_binding_missing",
    "raw_response_vault_routing_missing",
    "kernel_registry_identity_and_serial_hil_missing",
    "continuous_dtr_rts_hil_witness_missing",
    "real_chameleon_iousbhost_hil_missing",
  ]),
});

const MAX_NATIVE_BINDING_BYTES = 16 * 1024 * 1024;
const MAX_DESCRIPTOR_SET_BYTES = 4096;
const MAX_FRAME_BYTES = 16 * 1024;
const MAX_TIMEOUT_MS = 1000;
const FIXED_FRAME_BYTES = 10;
const SOF = 0x11;
const SOF_LRC = 0xef;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,128}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,39})$/u;
const CAPTURE_MODES = objectFreeze(["device_capture", "device_seize"]);
const AUTHORIZATION_MODES = objectFreeze([
  "entitlement_and_ioservice_authorize",
  "root",
]);
const NATIVE_BINDING_FUNCTIONS = objectFreeze([
  "abortDestroyExact",
  "destroyExact",
  "openFixtureExact",
  "transactFixtureExact",
]);
const NATIVE_BINDING_MEASUREMENT_MARK = Symbol.for(
  "hacker-bob.instrument-chameleon-native-darwin.direct-cdc-binding-measurement.v1",
);
const OPEN_ATTESTATION_FIELDS = objectFreeze([
  "bulk_in_address",
  "bulk_in_endpoint_descriptor_digest",
  "bulk_out_address",
  "bulk_out_endpoint_descriptor_digest",
  "capture_mode",
  "cdc_control_request_digest",
  "cdc_index",
  "cdc_length",
  "cdc_request",
  "cdc_request_type",
  "cdc_value",
  "connection_generation",
  "control_line_state_applied_before_bulk",
  "device_capture_terminates_clients_and_drivers",
  "device_seize_requests_owner_close",
  "enrollment_digest",
  "entitlement_required",
  "exclusive_ownership_required",
  "fixture_only",
  "interface_descriptor_digest",
  "io_service_authorize_required",
  "launch_ticket_digest",
  "phase",
  "primitive",
  "privilege_gate_mode",
  "production_ready",
  "root_qualified",
  "sdk_contract_compile_time_backed",
  "sdk_framework",
  "version",
  "vm_device_access_entitlement",
]);

const PLANS = new WeakSet();
const PLAN_STATE = new WeakMap();
const OPEN_GRANTS = new WeakSet();
const OPEN_GRANT_STATE = new WeakMap();
const HANDLES = new WeakSet();
const HANDLE_STATE = new WeakMap();
const TRANSACTION_GRANTS = new WeakSet();
const TRANSACTION_GRANT_STATE = new WeakMap();
const RESULTS = new WeakSet();
const RESULT_STATE = new WeakMap();
const BRANDED_NATIVE_MODULE_RECORDS = new WeakSet();
const BRANDED_NATIVE_BINDINGS = new WeakSet();
let measuredBinding = null;

function custodyError(code = "darwin_direct_cdc_custody_rejected") {
  const error = new SafeError("Darwin direct CDC custody was rejected");
  objectDefineProperty(error, "code", {
    value: code,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return error;
}

function rejectSerialization() {
  throw custodyError("darwin_direct_cdc_capability_not_serializable");
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || arrayIsArray(value)
      || utilIsProxy(value)) return false;
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
  if (!isPlainDataObject(value)) throw custodyError();
  const keys = objectKeys(value);
  if (keys.length !== fields.length) throw custodyError();
  for (let fieldIndex = 0; fieldIndex < fields.length; fieldIndex += 1) {
    let found = false;
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      if (keys[keyIndex] === fields[fieldIndex]) found = true;
    }
    if (!found) throw custodyError();
  }
  return value;
}

function assertInteger(value, minimum, maximum) {
  if (!reflectApply(numberIsSafeInteger, SafeNumber, [value])
      || value < minimum || value > maximum) {
    throw custodyError();
  }
  return value;
}

function assertIdentifier(value) {
  if (typeof value !== "string"
      || !reflectApply(regexpTest, IDENTIFIER_PATTERN, [value])) throw custodyError();
  return value;
}

function assertDigest(value) {
  if (typeof value !== "string"
      || !reflectApply(regexpTest, DIGEST_PATTERN, [value])) throw custodyError();
  return value;
}

function assertNonce(value) {
  if (typeof value !== "string"
      || !reflectApply(regexpTest, NONCE_PATTERN, [value])) throw custodyError();
  const bytes = reflectApply(bufferFrom, HostBuffer, [value, "base64url"]);
  if (bytes.length < 16
      || reflectApply(bufferToString, bytes, ["base64url"]) !== value) throw custodyError();
  return value;
}

function assertDecimal(value) {
  if (typeof value !== "string"
      || !reflectApply(regexpTest, DECIMAL_PATTERN, [value])
      || reflectApply(SafeBigInt, undefined, [value]) === 0n) {
    throw custodyError();
  }
  return value;
}

function assertBoolean(value) {
  if (value !== true && value !== false) throw custodyError();
  return value;
}

function containsExact(values, expected) {
  for (let index = 0; index < values.length; index += 1) {
    if (values[index] === expected) return true;
  }
  return false;
}

function isUint8ArrayInternal(value) {
  return value != null && !utilIsProxy(value)
    && reflectApply(utilIsUint8Array, utilTypes, [value]);
}

function isExactHostBuffer(value) {
  return isUint8ArrayInternal(value)
    && objectGetPrototypeOf(value) === hostBufferPrototype;
}

function copyExactBytes(value, minimum, maximum) {
  if (!isUint8ArrayInternal(value)) throw custodyError();
  const bytes = reflectApply(bufferFrom, HostBuffer, [value]);
  if (bytes.length < minimum || bytes.length > maximum) {
    reflectApply(bufferFill, bytes, [0]);
    throw custodyError();
  }
  return bytes;
}

function framedDigest(domain, fields) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [domain, "utf8"]);
  for (let fieldIndex = 0; fieldIndex < fields.length; fieldIndex += 1) {
    const field = fields[fieldIndex];
    const bytes = isUint8ArrayInternal(field)
      ? field
      : reflectApply(bufferFrom, HostBuffer, [
        reflectApply(SafeString, undefined, [field]), "utf8",
      ]);
    const length = reflectApply(bufferAllocUnsafe, HostBuffer, [8]);
    reflectApply(bufferWriteBigUInt64BE, length, [SafeBigInt(bytes.length)]);
    reflectApply(hashUpdate, hash, [length]);
    reflectApply(hashUpdate, hash, [bytes]);
    reflectApply(bufferFill, length, [0]);
  }
  return reflectApply(hashDigest, hash, ["hex"]);
}

function hashBytes(bytes) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [bytes]);
  return reflectApply(hashDigest, hash, ["hex"]);
}

function deriveDarwinDirectCdcLaunchTicketDigest(input) {
  assertExactObject(input, [
    "authorization_mode",
    "capture_mode",
    "dedicated_principal_digest",
    "expires_monotonic_ns",
    "io_service_authorized",
    "ticket_id",
    "ticket_nonce",
    "version",
    "vm_device_access_entitlement",
    "worker_code_identity_digest",
    "worker_gid",
    "worker_uid",
  ]);
  if (input.version !== DARWIN_DIRECT_CDC_VERSION
      || !containsExact(CAPTURE_MODES, input.capture_mode)
      || !containsExact(AUTHORIZATION_MODES, input.authorization_mode)) {
    throw custodyError();
  }
  return framedDigest("hacker-bob/chameleon-darwin-direct-cdc-launch-ticket/v1", [
    assertIdentifier(input.ticket_id),
    assertNonce(input.ticket_nonce),
    assertDecimal(input.expires_monotonic_ns),
    input.capture_mode,
    input.authorization_mode,
    reflectApply(SafeString, undefined, [assertInteger(input.worker_uid, 0, 0xffff_fffe)]),
    reflectApply(SafeString, undefined, [assertInteger(input.worker_gid, 0, 0xffff_fffe)]),
    reflectApply(SafeString, undefined, [assertBoolean(input.vm_device_access_entitlement)]),
    reflectApply(SafeString, undefined, [assertBoolean(input.io_service_authorized)]),
    assertDigest(input.dedicated_principal_digest),
    assertDigest(input.worker_code_identity_digest),
  ]);
}

function deriveDarwinDirectCdcInterfaceDescriptorDigest(input) {
  assertExactObject(input, ["descriptor_set_bytes", "version"]);
  if (input.version !== DARWIN_DIRECT_CDC_VERSION) throw custodyError();
  const bytes = copyExactBytes(input.descriptor_set_bytes, 9, MAX_DESCRIPTOR_SET_BYTES);
  try {
    return framedDigest(
      "hacker-bob/chameleon-darwin-direct-cdc-interface-descriptor-set/v1",
      [bytes],
    );
  } finally {
    reflectApply(bufferFill, bytes, [0]);
  }
}

function deriveDarwinDirectCdcEndpointDescriptorDigest(input) {
  assertExactObject(input, ["descriptor_bytes", "direction", "version"]);
  if (input.version !== DARWIN_DIRECT_CDC_VERSION
      || (input.direction !== "bulk_in" && input.direction !== "bulk_out")) {
    throw custodyError();
  }
  const bytes = copyExactBytes(input.descriptor_bytes, 7, 7);
  try {
    return framedDigest(
      `hacker-bob/chameleon-darwin-direct-cdc-${input.direction}-descriptor/v1`,
      [bytes],
    );
  } finally {
    reflectApply(bufferFill, bytes, [0]);
  }
}

function deriveDarwinDirectCdcEnrollmentDigest(input) {
  assertExactObject(input, [
    "bulk_in_endpoint_descriptor_digest",
    "bulk_out_endpoint_descriptor_digest",
    "configuration_value",
    "control_interface_number",
    "data_interface_number",
    "interface_descriptor_digest",
    "location_id",
    "product_id",
    "serial_number_digest",
    "vendor_id",
    "version",
  ]);
  if (input.version !== DARWIN_DIRECT_CDC_VERSION) throw custodyError();
  return framedDigest("hacker-bob/chameleon-darwin-direct-cdc-enrollment/v1", [
    reflectApply(SafeString, undefined, [assertInteger(input.vendor_id, 1, 0xffff)]),
    reflectApply(SafeString, undefined, [assertInteger(input.product_id, 1, 0xffff)]),
    reflectApply(SafeString, undefined, [assertInteger(input.location_id, 0, 0xffff_ffff)]),
    assertDigest(input.serial_number_digest),
    reflectApply(SafeString, undefined, [assertInteger(input.configuration_value, 1, 0xff)]),
    reflectApply(SafeString, undefined, [assertInteger(input.control_interface_number, 0, 0xff)]),
    reflectApply(SafeString, undefined, [assertInteger(input.data_interface_number, 0, 0xff)]),
    assertDigest(input.interface_descriptor_digest),
    assertDigest(input.bulk_out_endpoint_descriptor_digest),
    assertDigest(input.bulk_in_endpoint_descriptor_digest),
  ]);
}

function validateDeviceDescriptor(bytes, enrollment) {
  if (bytes.length !== 18 || bytes[0] !== 18 || bytes[1] !== 1
      || reflectApply(bufferReadUInt16LE, bytes, [8]) !== enrollment.vendor_id
      || reflectApply(bufferReadUInt16LE, bytes, [10]) !== enrollment.product_id
      || bytes[16] === 0 || bytes[17] === 0) throw custodyError();
}

function validateInterfaceDescriptor(bytes, number, control) {
  if (bytes.length !== 9 || bytes[0] !== 9 || bytes[1] !== 4
      || bytes[2] !== number || bytes[3] !== 0
      || (control && (bytes[5] !== 0x02 || bytes[6] !== 0x02))
      || (!control && (bytes[4] !== 2 || bytes[5] !== 0x0a))) throw custodyError();
}

function validateBulkEndpoint(bytes, direction) {
  const expectedDirection = direction === "bulk_in" ? 0x80 : 0;
  const address = bytes[2];
  const maximumPacket = reflectApply(bufferReadUInt16LE, bytes, [4]) & 0x07ff;
  if (bytes.length !== 7 || bytes[0] !== 7 || bytes[1] !== 5
      || (address & 0x80) !== expectedDirection || (address & 0x0f) === 0
      || (bytes[3] & 0x03) !== 0x02 || maximumPacket < 1 || maximumPacket > 1024) {
    throw custodyError();
  }
  return address;
}

function validateDescriptorSet(bytes, enrollment, descriptors) {
  if (bytes[0] !== 9 || bytes[1] !== 2
      || reflectApply(bufferReadUInt16LE, bytes, [2]) !== bytes.length
      || bytes[5] !== enrollment.configuration_value) throw custodyError();
  let offset = 0;
  let currentInterface = -1;
  let controlMatches = 0;
  let dataMatches = 0;
  let outMatches = 0;
  let inMatches = 0;
  while (offset < bytes.length) {
    const length = bytes[offset];
    if (length < 2 || offset + length > bytes.length) throw custodyError();
    const type = bytes[offset + 1];
    const descriptor = reflectApply(bufferSubarray, bytes, [offset, offset + length]);
    if (type === 4 && length === 9) {
      currentInterface = descriptor[2];
      if (reflectApply(bufferEquals, descriptor, [descriptors.control_interface])) {
        controlMatches += 1;
      }
      if (reflectApply(bufferEquals, descriptor, [descriptors.data_interface])) dataMatches += 1;
    } else if (type === 5 && length === 7
        && currentInterface === enrollment.data_interface_number) {
      const endpoint = reflectApply(bufferSubarray, descriptor, [0, 7]);
      if (reflectApply(bufferEquals, endpoint, [descriptors.bulk_out])) outMatches += 1;
      if (reflectApply(bufferEquals, endpoint, [descriptors.bulk_in])) inMatches += 1;
    }
    offset += length;
  }
  if (offset !== bytes.length || controlMatches !== 1 || dataMatches !== 1
      || outMatches !== 1 || inMatches !== 1) throw custodyError();
}

function normalizeLaunchTicket(input) {
  assertExactObject(input, [
    "authorization_mode",
    "capture_mode",
    "dedicated_principal_digest",
    "expires_monotonic_ns",
    "io_service_authorized",
    "ticket_digest",
    "ticket_id",
    "ticket_nonce",
    "version",
    "vm_device_access_entitlement",
    "worker_code_identity_digest",
    "worker_gid",
    "worker_uid",
  ]);
  const basis = {
    version: input.version,
    ticket_id: input.ticket_id,
    ticket_nonce: input.ticket_nonce,
    expires_monotonic_ns: input.expires_monotonic_ns,
    capture_mode: input.capture_mode,
    authorization_mode: input.authorization_mode,
    worker_uid: input.worker_uid,
    worker_gid: input.worker_gid,
    vm_device_access_entitlement: input.vm_device_access_entitlement,
    io_service_authorized: input.io_service_authorized,
    dedicated_principal_digest: input.dedicated_principal_digest,
    worker_code_identity_digest: input.worker_code_identity_digest,
  };
  const digest = deriveDarwinDirectCdcLaunchTicketDigest(basis);
  const uid = assertInteger(input.worker_uid, 0, 0xffff_fffe);
  const gid = assertInteger(input.worker_gid, 0, 0xffff_fffe);
  if (typeof processGetuid !== "function" || typeof processGeteuid !== "function"
      || typeof processGetgid !== "function" || typeof processGetegid !== "function") {
    throw custodyError();
  }
  const realUid = reflectApply(processGetuid, hostProcess, []);
  const effectiveUid = reflectApply(processGeteuid, hostProcess, []);
  const realGid = reflectApply(processGetgid, hostProcess, []);
  const effectiveGid = reflectApply(processGetegid, hostProcess, []);
  const entitlementMode = input.authorization_mode === "entitlement_and_ioservice_authorize";
  if (input.ticket_digest !== digest || realUid !== uid || effectiveUid !== uid
      || realUid !== effectiveUid || realGid !== gid || effectiveGid !== gid
      || realGid !== effectiveGid
      || (entitlementMode && (uid === 0 || input.vm_device_access_entitlement !== true
        || input.io_service_authorized !== true))
      || (!entitlementMode && (uid !== 0 || input.vm_device_access_entitlement !== false
        || input.io_service_authorized !== false))) throw custodyError();
  return objectFreeze({ ...basis, ticket_digest: digest });
}

function zeroDescriptors(value) {
  const fields = [
    "device_descriptor_bytes",
    "interface_descriptor_set_bytes",
    "control_interface_descriptor_bytes",
    "data_interface_descriptor_bytes",
    "bulk_out_endpoint_descriptor_bytes",
    "bulk_in_endpoint_descriptor_bytes",
  ];
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    try {
      if (value[field]) reflectApply(bufferFill, value[field], [0]);
    } catch {}
  }
}

function normalizeEnrollment(input) {
  assertExactObject(input, [
    "bulk_in_endpoint_descriptor_bytes",
    "bulk_in_endpoint_descriptor_digest",
    "bulk_out_endpoint_descriptor_bytes",
    "bulk_out_endpoint_descriptor_digest",
    "configuration_value",
    "control_interface_descriptor_bytes",
    "control_interface_number",
    "data_interface_descriptor_bytes",
    "data_interface_number",
    "device_descriptor_bytes",
    "enrollment_digest",
    "interface_descriptor_digest",
    "interface_descriptor_set_bytes",
    "location_id",
    "product_id",
    "serial_number_digest",
    "vendor_id",
    "version",
  ]);
  const output = {
    version: input.version,
    vendor_id: assertInteger(input.vendor_id, 1, 0xffff),
    product_id: assertInteger(input.product_id, 1, 0xffff),
    location_id: assertInteger(input.location_id, 0, 0xffff_ffff),
    serial_number_digest: assertDigest(input.serial_number_digest),
    configuration_value: assertInteger(input.configuration_value, 1, 0xff),
    control_interface_number: assertInteger(input.control_interface_number, 0, 0xff),
    data_interface_number: assertInteger(input.data_interface_number, 0, 0xff),
    device_descriptor_bytes: copyExactBytes(input.device_descriptor_bytes, 18, 18),
    interface_descriptor_set_bytes: copyExactBytes(
      input.interface_descriptor_set_bytes,
      9,
      MAX_DESCRIPTOR_SET_BYTES,
    ),
    control_interface_descriptor_bytes: copyExactBytes(
      input.control_interface_descriptor_bytes,
      9,
      9,
    ),
    data_interface_descriptor_bytes: copyExactBytes(input.data_interface_descriptor_bytes, 9, 9),
    bulk_out_endpoint_descriptor_bytes: copyExactBytes(
      input.bulk_out_endpoint_descriptor_bytes,
      7,
      7,
    ),
    bulk_in_endpoint_descriptor_bytes: copyExactBytes(
      input.bulk_in_endpoint_descriptor_bytes,
      7,
      7,
    ),
  };
  try {
    if (input.version !== DARWIN_DIRECT_CDC_VERSION
        || output.control_interface_number === output.data_interface_number) throw custodyError();
    validateDeviceDescriptor(output.device_descriptor_bytes, output);
    validateInterfaceDescriptor(
      output.control_interface_descriptor_bytes,
      output.control_interface_number,
      true,
    );
    validateInterfaceDescriptor(
      output.data_interface_descriptor_bytes,
      output.data_interface_number,
      false,
    );
    output.bulk_out_address = validateBulkEndpoint(
      output.bulk_out_endpoint_descriptor_bytes,
      "bulk_out",
    );
    output.bulk_in_address = validateBulkEndpoint(
      output.bulk_in_endpoint_descriptor_bytes,
      "bulk_in",
    );
    validateDescriptorSet(output.interface_descriptor_set_bytes, output, {
      control_interface: output.control_interface_descriptor_bytes,
      data_interface: output.data_interface_descriptor_bytes,
      bulk_out: output.bulk_out_endpoint_descriptor_bytes,
      bulk_in: output.bulk_in_endpoint_descriptor_bytes,
    });
    output.interface_descriptor_digest = deriveDarwinDirectCdcInterfaceDescriptorDigest({
      version: 1,
      descriptor_set_bytes: output.interface_descriptor_set_bytes,
    });
    output.bulk_out_endpoint_descriptor_digest =
      deriveDarwinDirectCdcEndpointDescriptorDigest({
        version: 1,
        direction: "bulk_out",
        descriptor_bytes: output.bulk_out_endpoint_descriptor_bytes,
      });
    output.bulk_in_endpoint_descriptor_digest =
      deriveDarwinDirectCdcEndpointDescriptorDigest({
        version: 1,
        direction: "bulk_in",
        descriptor_bytes: output.bulk_in_endpoint_descriptor_bytes,
      });
    output.enrollment_digest = deriveDarwinDirectCdcEnrollmentDigest({
      version: 1,
      vendor_id: output.vendor_id,
      product_id: output.product_id,
      location_id: output.location_id,
      serial_number_digest: output.serial_number_digest,
      configuration_value: output.configuration_value,
      control_interface_number: output.control_interface_number,
      data_interface_number: output.data_interface_number,
      interface_descriptor_digest: output.interface_descriptor_digest,
      bulk_out_endpoint_descriptor_digest: output.bulk_out_endpoint_descriptor_digest,
      bulk_in_endpoint_descriptor_digest: output.bulk_in_endpoint_descriptor_digest,
    });
    if (input.interface_descriptor_digest !== output.interface_descriptor_digest
        || input.bulk_out_endpoint_descriptor_digest
          !== output.bulk_out_endpoint_descriptor_digest
        || input.bulk_in_endpoint_descriptor_digest !== output.bulk_in_endpoint_descriptor_digest
        || input.enrollment_digest !== output.enrollment_digest) throw custodyError();
    return output;
  } catch (error) {
    zeroDescriptors(output);
    throw error;
  }
}

function createPlan(input, fixtureOnly) {
  assertExactObject(input, [
    "custody_id", "enrollment", "enrollment_id", "launch_ticket", "version",
  ]);
  if (input.version !== DARWIN_DIRECT_CDC_VERSION
      || (fixtureOnly
        && !fixtureEnvironmentGate)) {
    throw custodyError();
  }
  const custodyId = assertIdentifier(input.custody_id);
  const enrollmentId = assertIdentifier(input.enrollment_id);
  const ticket = normalizeLaunchTicket(input.launch_ticket);
  const enrollment = normalizeEnrollment(input.enrollment);
  try {
    const state = {
      custody_id: custodyId,
      enrollment_id: enrollmentId,
      launch_ticket: ticket,
      enrollment,
      fixture_only: fixtureOnly,
      phase: "closed",
      last_generation: 0,
      open_grant: null,
      handle: null,
      destroyed: false,
    };
    const plan = objectFreeze({
      version: DARWIN_DIRECT_CDC_VERSION,
      kind: "darwin_chameleon_direct_cdc_custody_plan",
      custody_id: state.custody_id,
      enrollment_id: state.enrollment_id,
      capture_mode: ticket.capture_mode,
      authorization_mode: ticket.authorization_mode,
      launch_ticket_digest: ticket.ticket_digest,
      enrollment_digest: enrollment.enrollment_digest,
      fixture_only: fixtureOnly,
      production_ready: false,
      blocker_code: DARWIN_DIRECT_CDC_REAL_BLOCKER,
      capability_id: `darwin-direct-cdc:${reflectApply(
        bufferToString,
        reflectApply(cryptoRandomBytes, crypto, [18]),
        ["base64url"],
      )}`,
      toJSON: rejectSerialization,
    });
    reflectApply(weakSetAdd, PLANS, [plan]);
    reflectApply(weakMapSet, PLAN_STATE, [plan, state]);
    return plan;
  } catch (error) {
    zeroDescriptors(enrollment);
    throw error;
  }
}

function createDarwinDirectCdcCustodyPlan(input) {
  return createPlan(input, false);
}

function createDarwinDirectCdcFixtureCustodyPlan(input) {
  return createPlan(input, true);
}

function assertDarwinDirectCdcCustodyPlan(input) {
  const state = input == null ? null : reflectApply(weakMapGet, PLAN_STATE, [input]);
  if (!input || !reflectApply(weakSetHas, PLANS, [input]) || !state
      || !objectIsFrozen(input)
      || input.version !== DARWIN_DIRECT_CDC_VERSION
      || input.kind !== "darwin_chameleon_direct_cdc_custody_plan"
      || input.custody_id !== state.custody_id || input.enrollment_id !== state.enrollment_id
      || input.capture_mode !== state.launch_ticket?.capture_mode
      || input.authorization_mode !== state.launch_ticket?.authorization_mode
      || input.launch_ticket_digest !== state.launch_ticket?.ticket_digest
      || input.enrollment_digest !== state.enrollment?.enrollment_digest
      || input.fixture_only !== state.fixture_only || input.production_ready !== false
      || input.blocker_code !== DARWIN_DIRECT_CDC_REAL_BLOCKER
      || reflectOwnKeys(input).length !== 13) throw custodyError();
  return input;
}

function terminallyDestroyPlan(state, phase) {
  if (state.enrollment) zeroDescriptors(state.enrollment);
  state.launch_ticket = null;
  state.enrollment = null;
  state.open_grant = null;
  state.handle = null;
  state.destroyed = true;
  state.phase = phase;
}

function createDarwinDirectCdcOpenGeneration(planInput, input) {
  const plan = assertDarwinDirectCdcCustodyPlan(planInput);
  const state = reflectApply(weakMapGet, PLAN_STATE, [plan]);
  assertExactObject(input, ["connection_generation", "open_nonce", "version"]);
  if (input.version !== DARWIN_DIRECT_CDC_VERSION || state.destroyed
      || state.phase !== "closed" || state.open_grant != null || state.handle != null
      || input.connection_generation !== state.last_generation + 1) throw custodyError();
  const grant = objectFreeze({
    version: DARWIN_DIRECT_CDC_VERSION,
    kind: "darwin_chameleon_direct_cdc_open_generation",
    custody_id: state.custody_id,
    enrollment_id: state.enrollment_id,
    connection_generation: assertInteger(input.connection_generation, 1, 0xffff_ffff),
    open_nonce: assertNonce(input.open_nonce),
    fixture_only: state.fixture_only,
    production_ready: false,
    capability_id: `darwin-direct-cdc-open:${reflectApply(
      bufferToString,
      reflectApply(cryptoRandomBytes, crypto, [18]),
      ["base64url"],
    )}`,
    toJSON: rejectSerialization,
  });
  reflectApply(weakSetAdd, OPEN_GRANTS, [grant]);
  reflectApply(weakMapSet, OPEN_GRANT_STATE, [
    grant, { plan, plan_state: state, consumed: false },
  ]);
  state.open_grant = grant;
  return grant;
}

function assertOpenGrant(grant, plan, state) {
  const grantState = grant == null
    ? null
    : reflectApply(weakMapGet, OPEN_GRANT_STATE, [grant]);
  if (!grant || !reflectApply(weakSetHas, OPEN_GRANTS, [grant]) || !grantState
      || grantState.plan !== plan
      || grantState.plan_state !== state || grantState.consumed || !objectIsFrozen(grant)
      || grant.connection_generation !== state.last_generation + 1
      || grant.fixture_only !== state.fixture_only || grant.production_ready !== false
      || reflectOwnKeys(grant).length !== 10) throw custodyError();
  return grantState;
}

function buildControlRequest(controlInterfaceNumber) {
  const request = reflectApply(bufferAlloc, HostBuffer, [8]);
  request[0] = 0x21;
  request[1] = 0x22;
  reflectApply(bufferWriteUInt16LE, request, [0, 2]);
  reflectApply(bufferWriteUInt16LE, request, [controlInterfaceNumber, 4]);
  reflectApply(bufferWriteUInt16LE, request, [0, 6]);
  return request;
}

function nativeOpenConfig(state, generation) {
  const ticket = state.launch_ticket;
  const enrollment = state.enrollment;
  return objectFreeze({
    version: 1,
    fixture_only: true,
    capture_mode: ticket.capture_mode,
    authorization_mode: ticket.authorization_mode,
    ticket_id: ticket.ticket_id,
    ticket_nonce: ticket.ticket_nonce,
    expires_monotonic_ns: ticket.expires_monotonic_ns,
    worker_uid: ticket.worker_uid,
    worker_gid: ticket.worker_gid,
    vm_device_access_entitlement: ticket.vm_device_access_entitlement,
    io_service_authorized: ticket.io_service_authorized,
    dedicated_principal_digest: ticket.dedicated_principal_digest,
    worker_code_identity_digest: ticket.worker_code_identity_digest,
    launch_ticket_digest: ticket.ticket_digest,
    vendor_id: enrollment.vendor_id,
    product_id: enrollment.product_id,
    location_id: enrollment.location_id,
    serial_number_digest: enrollment.serial_number_digest,
    configuration_value: enrollment.configuration_value,
    control_interface_number: enrollment.control_interface_number,
    data_interface_number: enrollment.data_interface_number,
    device_descriptor_bytes: reflectApply(bufferFrom, HostBuffer, [
      enrollment.device_descriptor_bytes,
    ]),
    interface_descriptor_set_bytes: reflectApply(bufferFrom, HostBuffer, [
      enrollment.interface_descriptor_set_bytes,
    ]),
    control_interface_descriptor_bytes: reflectApply(bufferFrom, HostBuffer, [
      enrollment.control_interface_descriptor_bytes,
    ]),
    data_interface_descriptor_bytes: reflectApply(bufferFrom, HostBuffer, [
      enrollment.data_interface_descriptor_bytes,
    ]),
    bulk_out_endpoint_descriptor_bytes: reflectApply(bufferFrom, HostBuffer, [
      enrollment.bulk_out_endpoint_descriptor_bytes,
    ]),
    bulk_in_endpoint_descriptor_bytes: reflectApply(bufferFrom, HostBuffer, [
      enrollment.bulk_in_endpoint_descriptor_bytes,
    ]),
    interface_descriptor_digest: enrollment.interface_descriptor_digest,
    bulk_out_endpoint_descriptor_digest: enrollment.bulk_out_endpoint_descriptor_digest,
    bulk_in_endpoint_descriptor_digest: enrollment.bulk_in_endpoint_descriptor_digest,
    enrollment_digest: enrollment.enrollment_digest,
    connection_generation: generation,
  });
}

function zeroNativeOpenConfig(config) {
  if (!config) return;
  const fields = [
    "device_descriptor_bytes",
    "interface_descriptor_set_bytes",
    "control_interface_descriptor_bytes",
    "data_interface_descriptor_bytes",
    "bulk_out_endpoint_descriptor_bytes",
    "bulk_in_endpoint_descriptor_bytes",
  ];
  for (let index = 0; index < fields.length; index += 1) {
    reflectApply(bufferFill, config[fields[index]], [0]);
  }
}

function validateOpenAttestation(raw, state, generation) {
  assertExactObject(raw, ["attestation", "handle"]);
  if (raw.handle == null || typeof raw.handle !== "object") throw custodyError();
  const value = assertExactObject(raw.attestation, OPEN_ATTESTATION_FIELDS);
  const ticket = state.launch_ticket;
  const enrollment = state.enrollment;
  const request = buildControlRequest(enrollment.control_interface_number);
  let requestDigest;
  try {
    requestDigest = framedDigest(
      "hacker-bob/chameleon-darwin-direct-cdc-control-request/v1",
      [request],
    );
  } finally {
    reflectApply(bufferFill, request, [0]);
  }
  const capture = ticket.capture_mode === "device_capture";
  const entitlement = ticket.authorization_mode === "entitlement_and_ioservice_authorize";
  const exact = {
    version: 1,
    primitive: DARWIN_DIRECT_CDC_PRIMITIVE,
    fixture_only: true,
    production_ready: false,
    sdk_framework: "IOUSBHost",
    sdk_contract_compile_time_backed: true,
    capture_mode: ticket.capture_mode,
    device_capture_terminates_clients_and_drivers: capture,
    device_seize_requests_owner_close: !capture,
    privilege_gate_mode: ticket.authorization_mode,
    entitlement_required: entitlement,
    io_service_authorize_required: entitlement,
    root_qualified: !entitlement,
    vm_device_access_entitlement: ticket.vm_device_access_entitlement,
    launch_ticket_digest: ticket.ticket_digest,
    enrollment_digest: enrollment.enrollment_digest,
    interface_descriptor_digest: enrollment.interface_descriptor_digest,
    bulk_out_endpoint_descriptor_digest: enrollment.bulk_out_endpoint_descriptor_digest,
    bulk_in_endpoint_descriptor_digest: enrollment.bulk_in_endpoint_descriptor_digest,
    connection_generation: generation,
    exclusive_ownership_required: true,
    cdc_request_type: 0x21,
    cdc_request: 0x22,
    cdc_value: 0,
    cdc_index: enrollment.control_interface_number,
    cdc_length: 0,
    cdc_control_request_digest: requestDigest,
    control_line_state_applied_before_bulk: true,
    bulk_out_address: enrollment.bulk_out_address,
    bulk_in_address: enrollment.bulk_in_address,
    phase: "bulk_endpoints_bound_after_control_line_low",
  };
  const exactFields = objectKeys(exact);
  for (let index = 0; index < exactFields.length; index += 1) {
    const field = exactFields[index];
    if (value[field] !== exact[field]) throw custodyError();
  }
  return raw.handle;
}

function openDarwinDirectCdcGeneration(planInput, grantInput) {
  const plan = assertDarwinDirectCdcCustodyPlan(planInput);
  const state = reflectApply(weakMapGet, PLAN_STATE, [plan]);
  const grantState = assertOpenGrant(grantInput, plan, state);
  grantState.consumed = true;
  state.open_grant = null;
  state.last_generation = grantInput.connection_generation;
  if (!state.fixture_only) {
    terminallyDestroyPlan(state, "real_open_refused_terminal");
    throw custodyError(DARWIN_DIRECT_CDC_REAL_BLOCKER);
  }
  let binding;
  let config;
  let raw;
  try {
    binding = loadNativeBinding();
    config = nativeOpenConfig(state, grantInput.connection_generation);
    raw = reflectApply(binding.openFixtureExact, undefined, [config]);
    const nativeHandle = validateOpenAttestation(raw, state, grantInput.connection_generation);
    const handle = objectFreeze({
      version: 1,
      kind: "darwin_chameleon_direct_cdc_generation_handle",
      custody_id: state.custody_id,
      enrollment_id: state.enrollment_id,
      connection_generation: grantInput.connection_generation,
      capture_mode: state.launch_ticket.capture_mode,
      control_request_digest: raw.attestation.cdc_control_request_digest,
      control_line_state_applied_before_bulk: true,
      bulk_endpoint_binding: "exact_enrolled_descriptors",
      sdk_contract_compile_time_backed: true,
      fixture_only: true,
      production_ready: false,
      capability_id: `darwin-direct-cdc-handle:${reflectApply(
        bufferToString,
        reflectApply(cryptoRandomBytes, crypto, [18]),
        ["base64url"],
      )}`,
      toJSON: rejectSerialization,
    });
    reflectApply(weakSetAdd, HANDLES, [handle]);
    reflectApply(weakMapSet, HANDLE_STATE, [handle, {
      plan,
      plan_state: state,
      binding,
      native_handle: nativeHandle,
      capture_mode: state.launch_ticket.capture_mode,
      phase: "open",
      transaction_grant: null,
    }]);
    state.handle = handle;
    state.phase = "open";
    return handle;
  } catch (error) {
    try {
      const descriptor = raw == null ? null : objectGetOwnPropertyDescriptor(raw, "handle");
      if (descriptor && objectHasOwn(descriptor, "value") && binding) {
        reflectApply(binding.abortDestroyExact, undefined, [
          descriptor.value,
          grantInput.connection_generation,
        ]);
      }
    } catch {}
    terminallyDestroyPlan(state, "open_uncertain_terminal");
    throw error?.code === "darwin_direct_cdc_binding_rejected"
      ? error
      : custodyError("darwin_direct_cdc_open_rejected");
  } finally {
    zeroNativeOpenConfig(config);
  }
}

function assertDarwinDirectCdcGenerationHandle(input) {
  const state = input == null ? null : reflectApply(weakMapGet, HANDLE_STATE, [input]);
  if (!input || !reflectApply(weakSetHas, HANDLES, [input]) || !state
      || !objectIsFrozen(input)
      || input.version !== 1 || input.kind !== "darwin_chameleon_direct_cdc_generation_handle"
      || input.custody_id !== state.plan_state.custody_id
      || input.enrollment_id !== state.plan_state.enrollment_id
      || input.connection_generation !== state.plan_state.last_generation
      || input.capture_mode !== state.capture_mode
      || input.control_line_state_applied_before_bulk !== true
      || input.bulk_endpoint_binding !== "exact_enrolled_descriptors"
      || input.sdk_contract_compile_time_backed !== true
      || input.fixture_only !== true || input.production_ready !== false
      || reflectOwnKeys(input).length !== 14) throw custodyError();
  return input;
}

function calculateLrc(bytes) {
  let sum = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    sum = (sum + bytes[index]) & 0xff;
  }
  return (-sum) & 0xff;
}

function assertExactFrame(input, request, maximumBytes = MAX_FRAME_BYTES) {
  const frame = copyExactBytes(input, FIXED_FRAME_BYTES, maximumBytes);
  if (frame[0] !== SOF || frame[1] !== SOF_LRC
      || (request && reflectApply(bufferReadUInt16BE, frame, [4]) !== 0)
      || calculateLrc(reflectApply(bufferSubarray, frame, [2, 8])) !== frame[8]
      || reflectApply(bufferReadUInt16BE, frame, [6]) + FIXED_FRAME_BYTES !== frame.length
      || calculateLrc(reflectApply(bufferSubarray, frame, [9, frame.length - 1]))
        !== frame[frame.length - 1]) {
    reflectApply(bufferFill, frame, [0]);
    throw custodyError("darwin_direct_cdc_frame_rejected");
  }
  return frame;
}

function createDarwinDirectCdcTransactionGrant(handleInput, input) {
  const handle = assertDarwinDirectCdcGenerationHandle(handleInput);
  const state = reflectApply(weakMapGet, HANDLE_STATE, [handle]);
  assertExactObject(input, [
    "maximum_response_bytes", "request_bytes", "timeout_ms", "transaction_sequence", "version",
  ]);
  if (input.version !== 1 || state.phase !== "open" || state.transaction_grant != null
      || input.transaction_sequence !== 1) throw custodyError();
  const request = assertExactFrame(input.request_bytes, true);
  let maximumResponseBytes;
  let timeoutMs;
  try {
    maximumResponseBytes = assertInteger(
      input.maximum_response_bytes,
      FIXED_FRAME_BYTES,
      MAX_FRAME_BYTES,
    );
    timeoutMs = assertInteger(input.timeout_ms, 1, MAX_TIMEOUT_MS);
  } catch (error) {
    reflectApply(bufferFill, request, [0]);
    throw error;
  }
  const grant = objectFreeze({
    version: 1,
    kind: "darwin_chameleon_direct_cdc_transaction_grant",
    custody_id: state.plan_state.custody_id,
    enrollment_id: state.plan_state.enrollment_id,
    connection_generation: handle.connection_generation,
    transaction_sequence: 1,
    request_digest: framedDigest(
      "hacker-bob/chameleon-darwin-direct-cdc-exact-request/v1",
      [request],
    ),
    maximum_response_bytes: maximumResponseBytes,
    timeout_ms: timeoutMs,
    fixture_only: true,
    production_ready: false,
    capability_id: `darwin-direct-cdc-transaction:${reflectApply(
      bufferToString,
      reflectApply(cryptoRandomBytes, crypto, [18]),
      ["base64url"],
    )}`,
    toJSON: rejectSerialization,
  });
  reflectApply(weakSetAdd, TRANSACTION_GRANTS, [grant]);
  reflectApply(weakMapSet, TRANSACTION_GRANT_STATE, [grant, {
    handle,
    handle_state: state,
    request_bytes: request,
    consumed: false,
  }]);
  state.transaction_grant = grant;
  return grant;
}

function createResult(handle, grant, response) {
  const responseBytes = reflectApply(bufferFrom, HostBuffer, [response]);
  const result = {
    version: 1,
    kind: "darwin_chameleon_direct_cdc_transaction_result",
    custody_id: grant.custody_id,
    enrollment_id: grant.enrollment_id,
    connection_generation: grant.connection_generation,
    transaction_sequence: 1,
    request_digest: grant.request_digest,
    response_digest: framedDigest(
      "hacker-bob/chameleon-darwin-direct-cdc-exact-response/v1",
      [responseBytes],
    ),
    fixture_only: true,
    production_ready: false,
    destroyed_after_transaction: true,
    toJSON: rejectSerialization,
  };
  objectDefineProperty(result, "response_bytes", {
    value: responseBytes,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  objectFreeze(result);
  reflectApply(weakSetAdd, RESULTS, [result]);
  reflectApply(weakMapSet, RESULT_STATE, [
    result, { handle, response_bytes: responseBytes },
  ]);
  return result;
}

function executeDarwinDirectCdcFixtureTransaction(handleInput, grantInput, input) {
  const handle = assertDarwinDirectCdcGenerationHandle(handleInput);
  const state = reflectApply(weakMapGet, HANDLE_STATE, [handle]);
  const grantState = grantInput == null
    ? null
    : reflectApply(weakMapGet, TRANSACTION_GRANT_STATE, [grantInput]);
  assertExactObject(input, ["fixture_response_bytes", "version"]);
  if (input.version !== 1 || !grantInput
      || !reflectApply(weakSetHas, TRANSACTION_GRANTS, [grantInput])
      || !grantState || grantState.handle !== handle || grantState.handle_state !== state
      || grantState.consumed || state.transaction_grant !== grantInput
      || state.phase !== "open" || grantInput.transaction_sequence !== 1) throw custodyError();
  // This fixture response is syntax-checked before redemption. A malformed
  // pre-redemption call cannot touch native state and leaves the grant usable;
  // once the checks below pass, every failure consumes and quarantines.
  let response;
  try {
    response = assertExactFrame(
      input.fixture_response_bytes,
      false,
      grantInput?.maximum_response_bytes ?? MAX_FRAME_BYTES,
    );
  } catch {
    throw custodyError("darwin_direct_cdc_pre_redemption_fixture_response_rejected");
  }
  grantState.consumed = true;
  state.transaction_grant = null;
  state.phase = "transaction";
  let rawResponse;
  try {
    if (reflectApply(bufferReadUInt16BE, response, [2])
        !== reflectApply(bufferReadUInt16BE, grantState.request_bytes, [2])) {
      throw custodyError();
    }
    rawResponse = reflectApply(state.binding.transactFixtureExact, undefined, [
      state.native_handle,
      handle.connection_generation,
      1,
      grantState.request_bytes,
      response,
      grantInput.maximum_response_bytes,
      grantInput.timeout_ms,
    ]);
    if (!isExactHostBuffer(rawResponse)
        || rawResponse.length !== response.length
        || !reflectApply(bufferEquals, rawResponse, [response])) throw custodyError();
    const destroyed = reflectApply(state.binding.destroyExact, undefined, [
      state.native_handle,
      handle.connection_generation,
    ]);
    if (destroyed !== true) throw custodyError();
    state.phase = "closed";
    terminallyDestroyPlan(state.plan_state, "transaction_complete_terminal");
    return createResult(handle, grantInput, rawResponse);
  } catch {
    try {
      reflectApply(state.binding.abortDestroyExact, undefined, [
        state.native_handle,
        handle.connection_generation,
      ]);
    } catch {}
    state.phase = "quarantined";
    terminallyDestroyPlan(state.plan_state, "transaction_ambiguous_terminal");
    throw custodyError("darwin_direct_cdc_transaction_ambiguous");
  } finally {
    reflectApply(bufferFill, grantState.request_bytes, [0]);
    reflectApply(bufferFill, response, [0]);
    try {
      if (rawResponse) reflectApply(bufferFill, rawResponse, [0]);
    } catch {}
  }
}

function abortAndDestroyDarwinDirectCdcGeneration(handleInput) {
  const handle = assertDarwinDirectCdcGenerationHandle(handleInput);
  const state = reflectApply(weakMapGet, HANDLE_STATE, [handle]);
  if (state.phase === "closed" || state.phase === "quarantined") {
    return objectFreeze({ destroyed: true, quarantined: state.phase === "quarantined" });
  }
  if (state.transaction_grant != null) {
    const grantState = reflectApply(
      weakMapGet,
      TRANSACTION_GRANT_STATE,
      [state.transaction_grant],
    );
    if (grantState) {
      grantState.consumed = true;
      reflectApply(bufferFill, grantState.request_bytes, [0]);
    }
    state.transaction_grant = null;
  }
  let destroyed;
  try {
    destroyed = reflectApply(state.binding.abortDestroyExact, undefined, [
      state.native_handle,
      handle.connection_generation,
    ]);
  } catch {
    destroyed = false;
  }
  state.phase = "quarantined";
  terminallyDestroyPlan(state.plan_state, "operator_abort_terminal");
  if (destroyed !== true) throw custodyError("darwin_direct_cdc_destroy_uncertain");
  return objectFreeze({ destroyed: true, quarantined: true });
}

function assertDarwinDirectCdcTransactionResult(input, handleInput) {
  const handle = assertDarwinDirectCdcGenerationHandle(handleInput);
  const state = input == null ? null : reflectApply(weakMapGet, RESULT_STATE, [input]);
  if (!input || !reflectApply(weakSetHas, RESULTS, [input]) || !state
      || state.handle !== handle
      || !objectIsFrozen(input)
      || !isExactHostBuffer(input.response_bytes)
      || input.kind !== "darwin_chameleon_direct_cdc_transaction_result"
      || input.destroyed_after_transaction !== true || input.production_ready !== false
      || input.response_digest !== framedDigest(
        "hacker-bob/chameleon-darwin-direct-cdc-exact-response/v1",
        [input.response_bytes],
      ) || reflectOwnKeys(input).length !== 13) throw custodyError();
  return input;
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

function assertHostRuntimeUntampered() {
  const currentGlobalProcess = objectGetOwnPropertyDescriptor(globalObject, "process");
  const currentGlobalBuffer = objectGetOwnPropertyDescriptor(globalObject, "Buffer");
  if (!sameDescriptor(currentGlobalBuffer, hostBufferGlobalDescriptor)
      || typeof hostBufferGlobalDescriptor?.get !== "function"
      || !sameDescriptor(objectGetOwnPropertyDescriptor(HostBuffer, "from"),
        hostBufferFromDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(HostBuffer, "isBuffer"),
        hostBufferIsBufferDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(HostBuffer, "alloc"),
        hostBufferAllocDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(HostBuffer, "allocUnsafe"),
        hostBufferAllocUnsafeDescriptor)
      || !sameDescriptor(currentGlobalProcess, hostProcessGlobalDescriptor)
      || typeof hostProcessGlobalDescriptor?.get !== "function") throw custodyError();
  let currentBuffer;
  let currentProcess;
  try {
    currentBuffer = reflectApply(hostBufferGlobalDescriptor.get, globalObject, []);
    currentProcess = reflectApply(hostProcessGlobalDescriptor.get, globalObject, []);
  } catch {
    throw custodyError();
  }
  if (currentBuffer !== HostBuffer || currentProcess !== hostProcess
      || !sameDescriptor(objectGetOwnPropertyDescriptor(hostProcess, "dlopen"),
        hostProcessDlopenDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(hostProcess, "platform"),
        hostProcessPlatformDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(hostProcess, "arch"),
        hostProcessArchDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(hostProcess, "versions"),
        hostProcessVersionsDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(
        hostProcessVersionsDescriptor?.value,
        "node",
      ), hostNodeVersionDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(
        hostProcessVersionsDescriptor?.value,
        "napi",
      ), hostNapiVersionDescriptor)
      || hostProcessPlatformDescriptor?.value !== "darwin"
      || hostProcessArchDescriptor?.value !== "arm64"
      || typeof hostNodeVersionDescriptor?.value !== "string"
      || !reflectApply(stringStartsWith, hostNodeVersionDescriptor.value, ["20."])
      || hostNapiVersionDescriptor?.value !== "9"
      || typeof hostProcessDlopenDescriptor?.value !== "function") throw custodyError();
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode
    && left.uid === right.uid && left.gid === right.gid && left.nlink === right.nlink
    && left.size === right.size && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function measureNativeBinding(candidate) {
  const absolute = pathResolve(candidate);
  const canonical = fsRealpathNative(candidate);
  if (absolute !== canonical) throw custodyError();
  const fd = fsOpenSync(
    canonical,
    fsOpenReadOnly | fsOpenCloseOnExec | fsOpenNoFollow,
  );
  try {
    const before = fsFstatSync(fd, { bigint: true });
    const pathBefore = fsLstatSync(canonical, { bigint: true });
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
        canonical_path: canonical,
        digest: hashBytes(bytes),
        stat: before,
      };
    } finally {
      reflectApply(bufferFill, bytes, [0]);
    }
  } finally {
    fsCloseSync(fd);
  }
}

function assertExactNativeFunction(value, locked) {
  if (typeof value !== "function" || reflectApply(utilIsProxy, utilTypes, [value])
      || objectGetPrototypeOf(value) !== functionPrototype
      || reflectApply(functionToString, value, []) !== "function () { [native code] }") {
    throw custodyError();
  }
  const keys = reflectOwnKeys(value);
  const expected = ["length", "name", "arguments", "caller", "prototype"];
  if (keys.length !== expected.length) throw custodyError();
  for (let index = 0; index < expected.length; index += 1) {
    if (keys[index] !== expected[index]) throw custodyError();
  }
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
      || reflectApply(utilIsProxy, utilTypes, [prototype.value])
      || objectGetPrototypeOf(prototype.value) !== objectPrototype) throw custodyError();
}

function assertExactNativeBinding(binding, marked, digest) {
  if (binding == null || typeof binding !== "object"
      || reflectApply(utilIsProxy, utilTypes, [binding])
      || objectGetPrototypeOf(binding) !== objectPrototype) throw custodyError();
  const keys = reflectOwnKeys(binding);
  if (keys.length !== NATIVE_BINDING_FUNCTIONS.length + (marked ? 1 : 0)) {
    throw custodyError();
  }
  for (let nameIndex = 0; nameIndex < NATIVE_BINDING_FUNCTIONS.length; nameIndex += 1) {
    const name = NATIVE_BINDING_FUNCTIONS[nameIndex];
    let found = false;
    for (let index = 0; index < keys.length; index += 1) {
      if (keys[index] === name) found = true;
    }
    if (!found) throw custodyError();
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
    if (mark?.value !== digest || mark.writable !== false || mark.enumerable !== false
        || mark.configurable !== false || !objectIsFrozen(binding)) throw custodyError();
  }
}

function assertBrandedCacheEntry(resolved, digest) {
  const cache = objectGetOwnPropertyDescriptor(nativeBindingCache, resolved);
  const moduleRecord = cache?.value;
  if (cache == null || cache.writable !== false || cache.enumerable !== true
      || cache.configurable !== false || moduleRecord == null
      || !reflectApply(weakSetHas, BRANDED_NATIVE_MODULE_RECORDS, [moduleRecord])
      || !objectIsFrozen(moduleRecord)
      || objectGetPrototypeOf(moduleRecord) !== null || reflectOwnKeys(moduleRecord).length !== 4) {
    throw custodyError();
  }
  const exportsDescriptor = objectGetOwnPropertyDescriptor(moduleRecord, "exports");
  const binding = exportsDescriptor?.value;
  if (objectGetOwnPropertyDescriptor(moduleRecord, "id")?.value !== resolved
      || objectGetOwnPropertyDescriptor(moduleRecord, "filename")?.value !== resolved
      || objectGetOwnPropertyDescriptor(moduleRecord, "loaded")?.value !== true
      || exportsDescriptor?.writable !== false || exportsDescriptor.enumerable !== true
      || exportsDescriptor.configurable !== false
      || !reflectApply(weakSetHas, BRANDED_NATIVE_BINDINGS, [binding])) {
    throw custodyError();
  }
  assertExactNativeBinding(binding, true, digest);
  return binding;
}

function loadNativeBinding() {
  try {
    assertHostRuntimeUntampered();
    const candidates = [
      pathJoin(__dirname, "..", "prebuilds", "darwin-arm64", "direct_cdc_custody.node"),
      pathJoin(__dirname, "..", "build", "Release", "direct_cdc_custody.node"),
    ];
    let before;
    for (let candidateIndex = 0; candidateIndex < candidates.length; candidateIndex += 1) {
      const candidate = candidates[candidateIndex];
      try {
        before = measureNativeBinding(candidate);
        break;
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
    }
    if (!before) throw custodyError();
    const resolved = before.canonical_path;
    const cacheBefore = objectGetOwnPropertyDescriptor(nativeBindingCache, resolved);
    let binding;
    let moduleRecord;
    if (cacheBefore != null) {
      if (measuredBinding == null || measuredBinding.resolved !== resolved) throw custodyError();
      binding = assertBrandedCacheEntry(resolved, before.digest);
    } else {
      if (measuredBinding != null) throw custodyError();
      moduleRecord = objectCreate(null);
      const moduleFields = [
        ["id", resolved, false],
        ["filename", resolved, false],
        ["loaded", false, true],
        ["exports", objectCreate(objectPrototype), true],
      ];
      for (let fieldIndex = 0; fieldIndex < moduleFields.length; fieldIndex += 1) {
        const name = moduleFields[fieldIndex][0];
        const value = moduleFields[fieldIndex][1];
        const writable = moduleFields[fieldIndex][2];
        objectDefineProperty(moduleRecord, name, {
          value,
          writable,
          enumerable: true,
          configurable: false,
        });
      }
      reflectApply(hostProcessDlopenDescriptor.value, hostProcess, [moduleRecord, resolved]);
      binding = moduleRecord.exports;
      assertExactNativeBinding(binding, false, before.digest);
    }
    const after = measureNativeBinding(resolved);
    if (!sameFileIdentity(before.stat, after.stat) || before.digest !== after.digest
        || (measuredBinding && measuredBinding.digest !== after.digest)) throw custodyError();
    if (cacheBefore == null) {
      objectDefineProperty(binding, NATIVE_BINDING_MEASUREMENT_MARK, {
        value: after.digest,
        writable: false,
        enumerable: false,
        configurable: false,
      });
      for (let nameIndex = 0; nameIndex < NATIVE_BINDING_FUNCTIONS.length;
        nameIndex += 1) {
        const name = NATIVE_BINDING_FUNCTIONS[nameIndex];
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
      reflectApply(weakSetAdd, BRANDED_NATIVE_BINDINGS, [binding]);
      reflectApply(weakSetAdd, BRANDED_NATIVE_MODULE_RECORDS, [moduleRecord]);
      objectDefineProperty(nativeBindingCache, resolved, {
        value: moduleRecord,
        writable: false,
        enumerable: true,
        configurable: false,
      });
    }
    binding = assertBrandedCacheEntry(resolved, after.digest);
    measuredBinding = objectFreeze({
      resolved,
      digest: after.digest,
      openFixtureExact: binding.openFixtureExact,
      transactFixtureExact: binding.transactFixtureExact,
      abortDestroyExact: binding.abortDestroyExact,
      destroyExact: binding.destroyExact,
    });
    return measuredBinding;
  } catch {
    throw custodyError("darwin_direct_cdc_binding_rejected");
  }
}

module.exports = {
  DARWIN_DIRECT_CDC_ASSURANCE,
  DARWIN_DIRECT_CDC_PRIMITIVE,
  DARWIN_DIRECT_CDC_REAL_BLOCKER,
  DARWIN_DIRECT_CDC_VERSION,
  abortAndDestroyDarwinDirectCdcGeneration,
  assertDarwinDirectCdcCustodyPlan,
  assertDarwinDirectCdcGenerationHandle,
  assertDarwinDirectCdcTransactionResult,
  createDarwinDirectCdcCustodyPlan,
  createDarwinDirectCdcFixtureCustodyPlan,
  createDarwinDirectCdcOpenGeneration,
  createDarwinDirectCdcTransactionGrant,
  deriveDarwinDirectCdcEndpointDescriptorDigest,
  deriveDarwinDirectCdcEnrollmentDigest,
  deriveDarwinDirectCdcInterfaceDescriptorDigest,
  deriveDarwinDirectCdcLaunchTicketDigest,
  executeDarwinDirectCdcFixtureTransaction,
  openDarwinDirectCdcGeneration,
};
