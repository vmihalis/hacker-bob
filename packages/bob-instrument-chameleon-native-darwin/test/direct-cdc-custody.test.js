"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const MODULE_PATH = path.join(__dirname, "..", "lib", "direct-cdc-custody.js");
const BINDING_PATH = path.join(
  __dirname,
  "..",
  "build",
  "Release",
  "direct_cdc_custody.node",
);

process.env.BOB_CHAMELEON_DARWIN_DIRECT_CDC_FIXTURE = "1";
const api = require(MODULE_PATH);

function nonce() {
  return crypto.randomBytes(16).toString("base64url");
}

function lrc(bytes) {
  let sum = 0;
  for (const byte of bytes) sum = (sum + byte) & 0xff;
  return (-sum) & 0xff;
}

function frame(command, payload = Buffer.alloc(0), status = 0) {
  const output = Buffer.alloc(10 + payload.length);
  output[0] = 0x11;
  output[1] = 0xef;
  output.writeUInt16BE(command, 2);
  output.writeUInt16BE(status, 4);
  output.writeUInt16BE(payload.length, 6);
  output[8] = lrc(output.subarray(2, 8));
  payload.copy(output, 9);
  output[output.length - 1] = lrc(payload);
  return output;
}

function fixtureInput(captureMode = "device_capture") {
  const vendorId = 0x1209;
  const productId = 0xcafe;
  const configurationValue = 1;
  const controlInterfaceNumber = 0;
  const dataInterfaceNumber = 1;
  const deviceDescriptor = Buffer.from([
    18, 1, 0x00, 0x02, 0, 0, 0, 64,
    vendorId & 0xff, vendorId >> 8,
    productId & 0xff, productId >> 8,
    0x00, 0x01, 1, 2, 3, 1,
  ]);
  const controlInterface = Buffer.from([9, 4, 0, 0, 1, 0x02, 0x02, 0x01, 0]);
  const dataInterface = Buffer.from([9, 4, 1, 0, 2, 0x0a, 0, 0, 0]);
  const bulkOut = Buffer.from([7, 5, 0x01, 0x02, 64, 0, 0]);
  const bulkIn = Buffer.from([7, 5, 0x82, 0x02, 64, 0, 0]);
  const descriptorParts = [
    Buffer.from([9, 2, 75, 0, 2, configurationValue, 0, 0x80, 50]),
    Buffer.from([8, 11, 0, 2, 0x02, 0x02, 0x01, 0]),
    controlInterface,
    Buffer.from([5, 0x24, 0x00, 0x10, 0x01]),
    Buffer.from([4, 0x24, 0x02, 0x02]),
    Buffer.from([5, 0x24, 0x06, 0, 1]),
    Buffer.from([5, 0x24, 0x01, 0, 1]),
    Buffer.from([7, 5, 0x83, 0x03, 16, 0, 16]),
    dataInterface,
    bulkOut,
    bulkIn,
  ];
  const descriptorSet = Buffer.concat(descriptorParts);
  assert.equal(descriptorSet.length, 75);
  const interfaceDescriptorDigest = api.deriveDarwinDirectCdcInterfaceDescriptorDigest({
    version: 1,
    descriptor_set_bytes: descriptorSet,
  });
  const bulkOutDigest = api.deriveDarwinDirectCdcEndpointDescriptorDigest({
    version: 1,
    direction: "bulk_out",
    descriptor_bytes: bulkOut,
  });
  const bulkInDigest = api.deriveDarwinDirectCdcEndpointDescriptorDigest({
    version: 1,
    direction: "bulk_in",
    descriptor_bytes: bulkIn,
  });
  const serialNumberDigest = crypto.createHash("sha256")
    .update("fixture-serial-never-projected", "utf8")
    .digest("hex");
  const enrollmentBasis = {
    version: 1,
    vendor_id: vendorId,
    product_id: productId,
    location_id: 0x01020304,
    serial_number_digest: serialNumberDigest,
    configuration_value: configurationValue,
    control_interface_number: controlInterfaceNumber,
    data_interface_number: dataInterfaceNumber,
    interface_descriptor_digest: interfaceDescriptorDigest,
    bulk_out_endpoint_descriptor_digest: bulkOutDigest,
    bulk_in_endpoint_descriptor_digest: bulkInDigest,
  };
  const authorizationMode = process.getuid() === 0
    ? "root"
    : "entitlement_and_ioservice_authorize";
  const launchTicketBasis = {
    version: 1,
    ticket_id: "fixture_privileged_launch",
    ticket_nonce: nonce(),
    expires_monotonic_ns: "999999999999999999",
    capture_mode: captureMode,
    authorization_mode: authorizationMode,
    worker_uid: process.getuid(),
    worker_gid: process.getgid(),
    vm_device_access_entitlement: authorizationMode !== "root",
    io_service_authorized: authorizationMode !== "root",
    dedicated_principal_digest: "b".repeat(64),
    worker_code_identity_digest: "c".repeat(64),
  };
  return {
    version: 1,
    custody_id: "darwin_direct_cdc_fixture",
    enrollment_id: "operator_enrolled_chameleon",
    launch_ticket: {
      ...launchTicketBasis,
      ticket_digest: api.deriveDarwinDirectCdcLaunchTicketDigest(launchTicketBasis),
    },
    enrollment: {
      ...enrollmentBasis,
      device_descriptor_bytes: deviceDescriptor,
      interface_descriptor_set_bytes: descriptorSet,
      control_interface_descriptor_bytes: controlInterface,
      data_interface_descriptor_bytes: dataInterface,
      bulk_out_endpoint_descriptor_bytes: bulkOut,
      bulk_in_endpoint_descriptor_bytes: bulkIn,
      enrollment_digest: api.deriveDarwinDirectCdcEnrollmentDigest(enrollmentBasis),
    },
  };
}

function assertSafeError(error, code = "darwin_direct_cdc_custody_rejected") {
  assert.equal(error?.code, code);
  assert.equal(error?.message, "Darwin direct CDC custody was rejected");
  assert.equal(Object.hasOwn(error, "path"), false);
  assert.equal(Object.hasOwn(error, "service"), false);
  assert.equal(Object.hasOwn(error, "pipe"), false);
  return true;
}

function createOpen(apiValue, input) {
  const plan = apiValue.createDarwinDirectCdcFixtureCustodyPlan(input);
  const grant = apiValue.createDarwinDirectCdcOpenGeneration(plan, {
    version: 1,
    connection_generation: 1,
    open_nonce: nonce(),
  });
  const handle = apiValue.openDarwinDirectCdcGeneration(plan, grant);
  return { plan, grant, handle };
}

function nativeConfig(input, generation = 1) {
  return {
    version: 1,
    fixture_only: true,
    capture_mode: input.launch_ticket.capture_mode,
    authorization_mode: input.launch_ticket.authorization_mode,
    ticket_id: input.launch_ticket.ticket_id,
    ticket_nonce: input.launch_ticket.ticket_nonce,
    expires_monotonic_ns: input.launch_ticket.expires_monotonic_ns,
    worker_uid: input.launch_ticket.worker_uid,
    worker_gid: input.launch_ticket.worker_gid,
    vm_device_access_entitlement: input.launch_ticket.vm_device_access_entitlement,
    io_service_authorized: input.launch_ticket.io_service_authorized,
    dedicated_principal_digest: input.launch_ticket.dedicated_principal_digest,
    worker_code_identity_digest: input.launch_ticket.worker_code_identity_digest,
    launch_ticket_digest: input.launch_ticket.ticket_digest,
    vendor_id: input.enrollment.vendor_id,
    product_id: input.enrollment.product_id,
    location_id: input.enrollment.location_id,
    serial_number_digest: input.enrollment.serial_number_digest,
    configuration_value: input.enrollment.configuration_value,
    control_interface_number: input.enrollment.control_interface_number,
    data_interface_number: input.enrollment.data_interface_number,
    device_descriptor_bytes: Buffer.from(input.enrollment.device_descriptor_bytes),
    interface_descriptor_set_bytes: Buffer.from(
      input.enrollment.interface_descriptor_set_bytes,
    ),
    control_interface_descriptor_bytes: Buffer.from(
      input.enrollment.control_interface_descriptor_bytes,
    ),
    data_interface_descriptor_bytes: Buffer.from(
      input.enrollment.data_interface_descriptor_bytes,
    ),
    bulk_out_endpoint_descriptor_bytes: Buffer.from(
      input.enrollment.bulk_out_endpoint_descriptor_bytes,
    ),
    bulk_in_endpoint_descriptor_bytes: Buffer.from(
      input.enrollment.bulk_in_endpoint_descriptor_bytes,
    ),
    interface_descriptor_digest: input.enrollment.interface_descriptor_digest,
    bulk_out_endpoint_descriptor_digest:
      input.enrollment.bulk_out_endpoint_descriptor_digest,
    bulk_in_endpoint_descriptor_digest:
      input.enrollment.bulk_in_endpoint_descriptor_digest,
    enrollment_digest: input.enrollment.enrollment_digest,
    connection_generation: generation,
  };
}

function encodeInput(input) {
  return Buffer.from(JSON.stringify(input), "utf8").toString("base64url");
}

const CHILD_REVIVER = String.raw`
function revive(_key, value) {
  if (value && value.type === "Buffer" && Array.isArray(value.data)) {
    return Buffer.from(value.data);
  }
  return value;
}
`;

test("direct CDC import/construction are inert and real activation refuses before native load", () => {
  const encoded = encodeInput(fixtureInput());
  const source = String.raw`
const fs = require("node:fs");
${CHILD_REVIVER}
const [modulePath, encoded] = process.argv.slice(1);
let dlopenCalls = 0;
let openCalls = 0;
let enumerationCalls = 0;
process.dlopen = () => { dlopenCalls += 1; throw new Error("native load"); };
fs.openSync = () => { openCalls += 1; throw new Error("filesystem open"); };
fs.readdirSync = () => { enumerationCalls += 1; throw new Error("enumeration"); };
const api = require(modulePath);
const input = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"), revive);
const plan = api.createDarwinDirectCdcCustodyPlan(input);
const grant = api.createDarwinDirectCdcOpenGeneration(plan, {
  version: 1,
  connection_generation: 1,
  open_nonce: require("node:crypto").randomBytes(16).toString("base64url"),
});
let rejected;
try { api.openDarwinDirectCdcGeneration(plan, grant); } catch (error) { rejected = error; }
if (rejected?.code !== "darwin_direct_cdc_real_open_disabled"
    || dlopenCalls !== 0 || openCalls !== 0 || enumerationCalls !== 0) {
  throw new Error("real activation crossed its inert refusal boundary");
}
`;
  const result = spawnSync(process.execPath, ["-e", source, MODULE_PATH, encoded], {
    encoding: "utf8",
    env: { ...process.env, BOB_CHAMELEON_DARWIN_DIRECT_CDC_FIXTURE: "1" },
    timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
  assert.equal(api.DARWIN_DIRECT_CDC_ASSURANCE.production_ready, false);
  assert.equal(api.DARWIN_DIRECT_CDC_ASSURANCE.launch_ticket_verification,
    "digest_and_shape_only");
});

test("capture fixture validates DTR-low-before-bulk and one exact Chameleon exchange", () => {
  const opened = createOpen(api, fixtureInput("device_capture"));
  assert.equal(api.assertDarwinDirectCdcCustodyPlan(opened.plan), opened.plan);
  assert.equal(api.assertDarwinDirectCdcGenerationHandle(opened.handle), opened.handle);
  assert.equal(opened.handle.capture_mode, "device_capture");
  assert.equal(opened.handle.control_line_state_applied_before_bulk, true);
  assert.equal(opened.handle.bulk_endpoint_binding, "exact_enrolled_descriptors");
  assert.match(opened.handle.control_request_digest, /^[a-f0-9]{64}$/u);
  assert.equal(Reflect.ownKeys(opened.handle).join(" ").includes("address"), false);
  assert.equal(Reflect.ownKeys(opened.handle).join(" ").includes("pipe"), false);
  assert.equal(Reflect.ownKeys(opened.handle).join(" ").includes("serial"), false);

  const request = frame(1017);
  const response = frame(1017, Buffer.from("fixture", "utf8"));
  const transaction = api.createDarwinDirectCdcTransactionGrant(opened.handle, {
    version: 1,
    transaction_sequence: 1,
    request_bytes: request,
    maximum_response_bytes: 128,
    timeout_ms: 250,
  });
  const result = api.executeDarwinDirectCdcFixtureTransaction(
    opened.handle,
    transaction,
    { version: 1, fixture_response_bytes: response },
  );
  assert.equal(api.assertDarwinDirectCdcTransactionResult(result, opened.handle), result);
  assert.equal(result.response_bytes.subarray(9, -1).toString("utf8"), "fixture");
  assert.throws(
    () => api.executeDarwinDirectCdcFixtureTransaction(opened.handle, transaction, {
      version: 1,
      fixture_response_bytes: response,
    }),
    assertSafeError,
  );
  assert.throws(
    () => api.createDarwinDirectCdcOpenGeneration(opened.plan, {
      version: 1,
      connection_generation: 2,
      open_nonce: nonce(),
    }),
    assertSafeError,
  );
});

test("descriptor mutation and incomplete privilege claims fail before native custody", () => {
  const descriptorMutation = fixtureInput();
  descriptorMutation.enrollment.bulk_in_endpoint_descriptor_bytes[2] = 0x02;
  assert.throws(
    () => api.createDarwinDirectCdcFixtureCustodyPlan(descriptorMutation),
    assertSafeError,
  );
  const privilegeMutation = fixtureInput();
  if (privilegeMutation.launch_ticket.authorization_mode
      === "entitlement_and_ioservice_authorize") {
    privilegeMutation.launch_ticket.io_service_authorized = false;
  } else {
    privilegeMutation.launch_ticket.vm_device_access_entitlement = true;
  }
  assert.throws(
    () => api.createDarwinDirectCdcFixtureCustodyPlan(privilegeMutation),
    assertSafeError,
  );
});

test("DeviceSeize remains owner-close semantics and synchronous abort terminally revokes work", () => {
  const opened = createOpen(api, fixtureInput("device_seize"));
  assert.equal(opened.handle.capture_mode, "device_seize");
  const grant = api.createDarwinDirectCdcTransactionGrant(opened.handle, {
    version: 1,
    transaction_sequence: 1,
    request_bytes: frame(1017),
    maximum_response_bytes: 128,
    timeout_ms: 250,
  });
  assert.deepEqual(api.abortAndDestroyDarwinDirectCdcGeneration(opened.handle), {
    destroyed: true,
    quarantined: true,
  });
  assert.throws(
    () => api.executeDarwinDirectCdcFixtureTransaction(opened.handle, grant, {
      version: 1,
      fixture_response_bytes: frame(1017),
    }),
    assertSafeError,
  );
  assert.throws(
    () => api.createDarwinDirectCdcOpenGeneration(opened.plan, {
      version: 1,
      connection_generation: 2,
      open_nonce: nonce(),
    }),
    assertSafeError,
  );
});

test("pre-redemption malformed fixture data is retryable, but every redeemed failure is terminal", () => {
  const opened = createOpen(api, fixtureInput());
  const grant = api.createDarwinDirectCdcTransactionGrant(opened.handle, {
    version: 1,
    transaction_sequence: 1,
    request_bytes: frame(1017),
    maximum_response_bytes: 128,
    timeout_ms: 250,
  });
  assert.throws(
    () => api.executeDarwinDirectCdcFixtureTransaction(opened.handle, grant, {
      version: 1,
      fixture_response_bytes: Buffer.alloc(10),
    }),
    (error) => assertSafeError(
      error,
      "darwin_direct_cdc_pre_redemption_fixture_response_rejected",
    ),
  );
  assert.throws(
    () => api.executeDarwinDirectCdcFixtureTransaction(opened.handle, grant, {
      version: 1,
      fixture_response_bytes: frame(1018),
    }),
    (error) => assertSafeError(error, "darwin_direct_cdc_transaction_ambiguous"),
  );
  assert.throws(
    () => api.executeDarwinDirectCdcFixtureTransaction(opened.handle, grant, {
      version: 1,
      fixture_response_bytes: frame(1017),
    }),
    assertSafeError,
  );
  assert.throws(
    () => api.createDarwinDirectCdcTransactionGrant(opened.handle, {
      version: 1,
      transaction_sequence: 1,
      request_bytes: frame(1017),
      maximum_response_bytes: 128,
      timeout_ms: 250,
    }),
    assertSafeError,
  );
  assert.throws(
    () => api.createDarwinDirectCdcOpenGeneration(opened.plan, {
      version: 1,
      connection_generation: 2,
      open_nonce: nonce(),
    }),
    assertSafeError,
  );
});

test("capabilities reject clones, proxies, and serialization", () => {
  const opened = createOpen(api, fixtureInput());
  assert.throws(() => api.assertDarwinDirectCdcCustodyPlan({ ...opened.plan }), assertSafeError);
  assert.throws(
    () => api.assertDarwinDirectCdcCustodyPlan(new Proxy(opened.plan, {})),
    assertSafeError,
  );
  assert.throws(
    () => JSON.stringify(opened.plan),
    (error) => assertSafeError(error, "darwin_direct_cdc_capability_not_serializable"),
  );
  assert.throws(
    () => api.assertDarwinDirectCdcGenerationHandle({ ...opened.handle }),
    assertSafeError,
  );
  assert.throws(
    () => JSON.stringify(opened.handle),
    (error) => assertSafeError(error, "darwin_direct_cdc_capability_not_serializable"),
  );
  api.abortAndDestroyDarwinDirectCdcGeneration(opened.handle);
});

test("a forged .node extension hook cannot supply direct CDC native evidence", () => {
  const encoded = encodeInput(fixtureInput());
  const source = String.raw`
const Module = require("node:module");
${CHILD_REVIVER}
const [modulePath, bindingPath, encoded] = process.argv.slice(1);
const api = require(modulePath);
const input = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"), revive);
const plan = api.createDarwinDirectCdcFixtureCustodyPlan(input);
const grant = api.createDarwinDirectCdcOpenGeneration(plan, {
  version: 1,
  connection_generation: 1,
  open_nonce: require("node:crypto").randomBytes(16).toString("base64url"),
});

let extensionCalls = 0;
const original = Module._extensions[".node"];
Module._extensions[".node"] = (module, filename) => {
  extensionCalls += 1;
  if (filename === bindingPath) throw new Error("forged extension invoked");
  return original(module, filename);
};
let handle;
try { handle = api.openDarwinDirectCdcGeneration(plan, grant); }
finally { Module._extensions[".node"] = original; }
if (!handle || extensionCalls !== 0) throw new Error("extension hook crossed direct dlopen");
api.abortAndDestroyDarwinDirectCdcGeneration(handle);
`;
  const result = spawnSync(
    process.execPath,
    ["-e", source, MODULE_PATH, BINDING_PATH, encoded],
    {
      encoding: "utf8",
      env: { ...process.env, BOB_CHAMELEON_DARWIN_DIRECT_CDC_FIXTURE: "1" },
      timeout: 5000,
    },
  );
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
});

test("captured intrinsics survive post-import callback mutation", () => {
  const encoded = encodeInput(fixtureInput());
  const source = String.raw`
${CHILD_REVIVER}
const [modulePath, encoded] = process.argv.slice(1);
const api = require(modulePath);
const input = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"), revive);
const warmPlan = api.createDarwinDirectCdcFixtureCustodyPlan(input);
const warmGrant = api.createDarwinDirectCdcOpenGeneration(warmPlan, {
  version: 1,
  connection_generation: 1,
  open_nonce: require("node:crypto").randomBytes(16).toString("base64url"),
});
api.abortAndDestroyDarwinDirectCdcGeneration(
  api.openDarwinDirectCdcGeneration(warmPlan, warmGrant),
);
const crypto = require("node:crypto");
const utilTypes = require("node:util").types;
const hashPrototype = Object.getPrototypeOf(crypto.createHash("sha256"));
const originals = {
  arrayIsArray: Array.isArray,
  includes: Array.prototype.includes,
  iterator: Array.prototype[Symbol.iterator],
  some: Array.prototype.some,
  sort: Array.prototype.sort,
  objectKeys: Object.keys,
  objectEntries: Object.entries,
  regexpTest: RegExp.prototype.test,
  bufferFrom: Buffer.from,
  bufferIsBuffer: Buffer.isBuffer,
  bufferAlloc: Buffer.alloc,
  bufferAllocUnsafe: Buffer.allocUnsafe,
  fill: Buffer.prototype.fill,
  equals: Buffer.prototype.equals,
  readBE: Buffer.prototype.readUInt16BE,
  readLE: Buffer.prototype.readUInt16LE,
  subarray: Buffer.prototype.subarray,
  toString: Buffer.prototype.toString,
  writeBig: Buffer.prototype.writeBigUInt64BE,
  writeLE: Buffer.prototype.writeUInt16LE,
  createHash: crypto.createHash,
  randomBytes: crypto.randomBytes,
  hashUpdate: hashPrototype.update,
  hashDigest: hashPrototype.digest,
  numberIsSafeInteger: Number.isSafeInteger,
  utilIsProxy: utilTypes.isProxy,
  utilIsUint8Array: utilTypes.isUint8Array,
  weakMapGet: WeakMap.prototype.get,
  weakMapSet: WeakMap.prototype.set,
  weakSetAdd: WeakSet.prototype.add,
  weakSetHas: WeakSet.prototype.has,
  uint8HasInstance: Object.getOwnPropertyDescriptor(Uint8Array, Symbol.hasInstance),
};
const poisoned = () => { throw new Error("ambient callback invoked"); };
Array.isArray = poisoned;
Array.prototype.includes = poisoned;
Array.prototype[Symbol.iterator] = poisoned;
Array.prototype.some = poisoned;
Array.prototype.sort = poisoned;
Object.keys = poisoned;
Object.entries = poisoned;
RegExp.prototype.test = poisoned;
Buffer.prototype.fill = poisoned;
Buffer.prototype.equals = poisoned;
Buffer.prototype.readUInt16BE = poisoned;
Buffer.prototype.readUInt16LE = poisoned;
Buffer.prototype.subarray = poisoned;
Buffer.prototype.toString = poisoned;
Buffer.prototype.writeBigUInt64BE = poisoned;
Buffer.prototype.writeUInt16LE = poisoned;
crypto.createHash = poisoned;
crypto.randomBytes = poisoned;
hashPrototype.update = poisoned;
hashPrototype.digest = poisoned;
Number.isSafeInteger = poisoned;
utilTypes.isProxy = poisoned;
utilTypes.isUint8Array = poisoned;
WeakMap.prototype.get = poisoned;
WeakMap.prototype.set = poisoned;
WeakSet.prototype.add = poisoned;
WeakSet.prototype.has = poisoned;
Object.defineProperty(Uint8Array, Symbol.hasInstance, {
  value: poisoned,
  writable: true,
  enumerable: false,
  configurable: true,
});
const plan = api.createDarwinDirectCdcFixtureCustodyPlan(input);
const grant = api.createDarwinDirectCdcOpenGeneration(plan, {
  version: 1,
  connection_generation: 1,
  open_nonce: "AAAAAAAAAAAAAAAAAAAAAA",
});
let handle;
try { handle = api.openDarwinDirectCdcGeneration(plan, grant); }
finally {
  Array.isArray = originals.arrayIsArray;
  Array.prototype.includes = originals.includes;
  Array.prototype[Symbol.iterator] = originals.iterator;
  Array.prototype.some = originals.some;
  Array.prototype.sort = originals.sort;
  Object.keys = originals.objectKeys;
  Object.entries = originals.objectEntries;
  RegExp.prototype.test = originals.regexpTest;
  Buffer.from = originals.bufferFrom;
  Buffer.isBuffer = originals.bufferIsBuffer;
  Buffer.alloc = originals.bufferAlloc;
  Buffer.allocUnsafe = originals.bufferAllocUnsafe;
  Buffer.prototype.fill = originals.fill;
  Buffer.prototype.equals = originals.equals;
  Buffer.prototype.readUInt16BE = originals.readBE;
  Buffer.prototype.readUInt16LE = originals.readLE;
  Buffer.prototype.subarray = originals.subarray;
  Buffer.prototype.toString = originals.toString;
  Buffer.prototype.writeBigUInt64BE = originals.writeBig;
  Buffer.prototype.writeUInt16LE = originals.writeLE;
  crypto.createHash = originals.createHash;
  crypto.randomBytes = originals.randomBytes;
  hashPrototype.update = originals.hashUpdate;
  hashPrototype.digest = originals.hashDigest;
  Number.isSafeInteger = originals.numberIsSafeInteger;
  utilTypes.isProxy = originals.utilIsProxy;
  utilTypes.isUint8Array = originals.utilIsUint8Array;
  WeakMap.prototype.get = originals.weakMapGet;
  WeakMap.prototype.set = originals.weakMapSet;
  WeakSet.prototype.add = originals.weakSetAdd;
  WeakSet.prototype.has = originals.weakSetHas;
  if (originals.uint8HasInstance) {
    Object.defineProperty(Uint8Array, Symbol.hasInstance, originals.uint8HasInstance);
  } else {
    delete Uint8Array[Symbol.hasInstance];
  }
}
if (!handle) throw new Error("captured intrinsic boundary did not open fixture");
api.abortAndDestroyDarwinDirectCdcGeneration(handle);
`;
  const result = spawnSync(process.execPath, ["-e", source, MODULE_PATH, encoded], {
    encoding: "utf8",
    env: { ...process.env, BOB_CHAMELEON_DARWIN_DIRECT_CDC_FIXTURE: "1" },
    timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
});

test("Buffer static substitution is an explicit terminal native-loader rejection", () => {
  const encoded = encodeInput(fixtureInput());
  const source = String.raw`
${CHILD_REVIVER}
const [modulePath, encoded, method] = process.argv.slice(1);
const api = require(modulePath);
const input = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"), revive);
const plan = api.createDarwinDirectCdcFixtureCustodyPlan(input);
const grant = api.createDarwinDirectCdcOpenGeneration(plan, {
  version: 1,
  connection_generation: 1,
  open_nonce: "AAAAAAAAAAAAAAAAAAAAAA",
});
const original = Buffer[method];
Buffer[method] = () => { throw new Error("ambient Buffer static invoked"); };
let rejected;
try { api.openDarwinDirectCdcGeneration(plan, grant); } catch (error) { rejected = error; }
Buffer[method] = original;
let remint;
try {
  api.createDarwinDirectCdcOpenGeneration(plan, {
    version: 1,
    connection_generation: 2,
    open_nonce: "BBBBBBBBBBBBBBBBBBBBBB",
  });
} catch (error) { remint = error; }
if (rejected?.code !== "darwin_direct_cdc_binding_rejected"
    || remint?.code !== "darwin_direct_cdc_custody_rejected") {
  throw new Error(method + " substitution did not fail closed and terminal");
}
`;
  for (const method of ["from", "isBuffer", "alloc", "allocUnsafe"]) {
    const result = spawnSync(
      process.execPath,
      ["-e", source, MODULE_PATH, encoded, method],
      {
        encoding: "utf8",
        env: { ...process.env, BOB_CHAMELEON_DARWIN_DIRECT_CDC_FIXTURE: "1" },
        timeout: 5000,
      },
    );
    assert.equal(
      result.status,
      0,
      `${method}: ${result.stderr || result.stdout || result.error?.message}`,
    );
  }
});

test("global process substitution rejects native loading and terminally consumes the generation", () => {
  const encoded = encodeInput(fixtureInput());
  const source = String.raw`
${CHILD_REVIVER}
const [modulePath, encoded] = process.argv.slice(1);
const api = require(modulePath);
const input = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"), revive);
const plan = api.createDarwinDirectCdcFixtureCustodyPlan(input);
const grant = api.createDarwinDirectCdcOpenGeneration(plan, {
  version: 1,
  connection_generation: 1,
  open_nonce: require("node:crypto").randomBytes(16).toString("base64url"),
});
Object.defineProperty(globalThis, "process", {
  value: Object.freeze({ platform: "darwin", arch: "arm64" }),
  writable: false,
  enumerable: false,
  configurable: true,
});
let rejected;
try { api.openDarwinDirectCdcGeneration(plan, grant); } catch (error) { rejected = error; }
let remint;
try {
  api.createDarwinDirectCdcOpenGeneration(plan, {
    version: 1,
    connection_generation: 2,
    open_nonce: "AAAAAAAAAAAAAAAAAAAAAA",
  });
} catch (error) { remint = error; }
if (rejected?.code !== "darwin_direct_cdc_binding_rejected"
    || remint?.code !== "darwin_direct_cdc_custody_rejected") {
  throw new Error("process substitution did not fail closed and terminal");
}
`;
  const result = spawnSync(process.execPath, ["-e", source, MODULE_PATH, encoded], {
    encoding: "utf8",
    env: { ...process.env, BOB_CHAMELEON_DARWIN_DIRECT_CDC_FIXTURE: "1" },
    timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
});

test("raw native real mode refuses before descriptor parsing", () => {
  const opened = createOpen(api, fixtureInput());
  const binding = require(BINDING_PATH);
  assert.throws(
    () => binding.openFixtureExact({ fixture_only: false }),
    (error) => error?.code === "darwin_direct_cdc_real_open_disabled",
  );
  api.abortAndDestroyDarwinDirectCdcGeneration(opened.handle);
});

test("raw native tokens reject coercion and every malformed redeemed call is terminal", () => {
  const opened = createOpen(api, fixtureInput());
  api.abortAndDestroyDarwinDirectCdcGeneration(opened.handle);
  const binding = require(BINDING_PATH);
  const input = fixtureInput();
  assert.throws(
    () => binding.openFixtureExact({ ...nativeConfig(input), version: 1.5 }),
    (error) => error?.code === "darwin_direct_cdc_open_rejected",
  );
  assert.throws(
    () => binding.openFixtureExact({
      ...nativeConfig(input),
      version: (2 ** 32) + 1,
    }),
    (error) => error?.code === "darwin_direct_cdc_open_rejected",
  );

  const wrongArity = binding.openFixtureExact(nativeConfig(input));
  assert.throws(
    () => binding.transactFixtureExact(wrongArity.handle),
    (error) => error?.code === "darwin_direct_cdc_transaction_ambiguous",
  );
  assert.throws(
    () => binding.transactFixtureExact(
      wrongArity.handle,
      1,
      1,
      frame(1017),
      frame(1017),
      128,
      250,
    ),
    (error) => error?.code === "darwin_direct_cdc_transaction_ambiguous",
    "wrong transaction arity must terminally quarantine the tagged token",
  );

  const wrongDestroyArity = binding.openFixtureExact(nativeConfig(input));
  assert.throws(
    () => binding.destroyExact(wrongDestroyArity.handle),
    (error) => error?.code === "darwin_direct_cdc_custody_rejected",
  );
  assert.throws(
    () => binding.transactFixtureExact(
      wrongDestroyArity.handle,
      1,
      1,
      frame(1017),
      frame(1017),
      128,
      250,
    ),
    (error) => error?.code === "darwin_direct_cdc_transaction_ambiguous",
    "wrong destroy arity must terminally quarantine the tagged token",
  );

  const fractionalGeneration = binding.openFixtureExact(nativeConfig(input));
  assert.throws(
    () => binding.transactFixtureExact(
      fractionalGeneration.handle,
      1.5,
      1,
      frame(1017),
      frame(1017),
      128,
      250,
    ),
    (error) => error?.code === "darwin_direct_cdc_transaction_ambiguous",
  );
  assert.throws(
    () => binding.transactFixtureExact(
      fractionalGeneration.handle,
      1,
      1,
      frame(1017),
      frame(1017),
      128,
      250,
    ),
    (error) => error?.code === "darwin_direct_cdc_transaction_ambiguous",
    "fractional generation must be rejected exactly and quarantine the token",
  );

  const raw = binding.openFixtureExact(nativeConfig(input));
  assert.throws(
    () => binding.transactFixtureExact(
      {},
      1,
      1,
      frame(1017),
      frame(1017),
      128,
      250,
    ),
    (error) => error?.code === "darwin_direct_cdc_transaction_ambiguous",
  );
  assert.throws(
    () => binding.transactFixtureExact(
      raw.handle,
      2,
      1,
      frame(1017),
      frame(1017),
      128,
      250,
    ),
    (error) => error?.code === "darwin_direct_cdc_transaction_ambiguous",
  );
  assert.throws(
    () => binding.transactFixtureExact(
      raw.handle,
      1,
      1,
      frame(1017),
      frame(1017),
      128,
      250,
    ),
    (error) => error?.code === "darwin_direct_cdc_transaction_ambiguous",
    "generation mismatch must terminally quarantine the valid tagged token",
  );
});
