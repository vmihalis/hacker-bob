"use strict";

// Optional native-worker boundary. Importing this module must not import
// `serialport`, enumerate a port, construct a native stream, or open hardware.
// The stock SerialPort open API cannot establish that DTR remained deasserted
// throughout open, so stock open is deliberately unavailable. An injected
// native atomic-open seam must return the exact proof-shaped result below. That
// JavaScript seam is useful for deterministic tests but remains HIL-unproven.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const {
  USB_CDC_CUSTODY_LIMITS,
  USB_CDC_CUSTODY_VERSION,
  USB_CDC_LINE_CONFIGURATION,
  createUsbCdcDriverPort,
} = require("@hacker-bob/instrument-chameleon-worker-runtime/usb-cdc-custody");
const {
  ABSOLUTE_MAX_FRAME_LENGTH,
  FIXED_FRAME_BYTES,
  SOF,
  SOF_LRC,
  calculateLrc,
} = require("@hacker-bob/instrument-chameleon-worker-runtime/codec");
// Anchor the terminal-field-off execution contract in the signed worker
// closure. The module is import-inert; no callback fixture or hardware action
// is constructed here.
require("@hacker-bob/instrument-chameleon-worker-runtime/rf-off-usb-execution-port");

const SERIALPORT_USB_CDC_DRIVER_VERSION = 1;
const SERIALPORT_VERSION = "13.0.0";
const SERIALPORT_DEPENDENCY_SURFACE_VERSION = 1;
const SERIALPORT_PACKAGE_RESOLVED =
  "https://registry.npmjs.org/serialport/-/serialport-13.0.0.tgz";
const SERIALPORT_PACKAGE_INTEGRITY =
  "sha512-PHpnTd8isMGPfFTZNCzOZp9m4mAJSNWle9Jxu6BPTcWq7YXl5qN7tp8Sgn0h+WIGcD6JFz5QDgixC2s4VW7vzg==";
const ATOMIC_OPEN_ATTESTATION_KIND = "serialport_native_atomic_dtr_off_open_v1";
const ATOMIC_OPEN_BLOCKER_CODE = "serialport_atomic_dtr_off_open_unproven";
const HARDWARE_IDENTITY_DOMAIN =
  "hacker-bob/chameleon-serialport-hardware-identity/v1";
const PATH_DIGEST_DOMAIN = "hacker-bob/chameleon-serialport-path/v1";
const LINE_CONFIGURATION_DIGEST_DOMAIN =
  "hacker-bob/chameleon-serialport-line-configuration/v1";
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const HEX_U16_PATTERN = /^(?:0x)?[a-f0-9]{1,4}$/iu;
const DEPENDENCY_FILE_PATTERN =
  /^node_modules\/serialport\/[A-Za-z0-9][A-Za-z0-9._+/-]{0,511}$/u;
const MAX_DEPENDENCY_FILES = 128;
const MAX_DEPENDENCY_FILE_BYTES = 8 * 1024 * 1024;
const MAX_DEPENDENCY_SURFACE_BYTES = 32 * 1024 * 1024;

const FIXTURE_DEPENDENCY_PORTS = new WeakSet();
const FIXTURE_DEPENDENCY_PRIVATE = new WeakMap();
const FIXTURE_SURFACE_QUALIFICATIONS = new WeakSet();
const FIXTURE_SURFACE_PRIVATE = new WeakMap();

const SERIALPORT_USB_CDC_DRIVER_ASSURANCE = Object.freeze({
  version: SERIALPORT_USB_CDC_DRIVER_VERSION,
  serialport_version: SERIALPORT_VERSION,
  production_ready: false,
  hil_proven: false,
  stock_serialport_atomic_dtr_off_open: false,
  atomic_open_blocker_code: ATOMIC_OPEN_BLOCKER_CODE,
  ambient_serialport_resolution: false,
  caller_loader_accepted: false,
  dependency_surface_authoritative: false,
  fixture_dependency_ports_only: true,
  execution_authority: false,
});

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = keys.filter((key) => !allowed.has(key)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}.${key} must be an enumerable data field`);
    }
  }
  return value;
}

function assertBoundedString(value, label, maximumBytes, { nullable = false } = {}) {
  if (nullable && value == null) return null;
  if (typeof value !== "string" || value.length < 1
      || Buffer.byteLength(value, "utf8") > maximumBytes) {
    throw new Error(`${label} must be a non-empty bounded string`);
  }
  return value;
}

function assertInteger(value, label, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  )).join(",")}}`;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function dependencySurfaceError() {
  return adapterError("serialport_dependency_surface_rejected");
}

function equalStringMap(actual, expected) {
  if (!isPlainObject(actual)) return false;
  const actualKeys = Object.keys(actual).sort();
  const expectedKeys = Object.keys(expected).sort();
  if (actualKeys.length !== expectedKeys.length) return false;
  for (let index = 0; index < actualKeys.length; index += 1) {
    const key = actualKeys[index];
    if (key !== expectedKeys[index] || actual[key] !== expected[key]) return false;
  }
  return true;
}

function readSingleLinkFile(filePath, maximumBytes) {
  let descriptor = null;
  try {
    const before = fs.lstatSync(filePath);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
        || before.size < 1 || before.size > maximumBytes) {
      throw dependencySurfaceError();
    }
    const noFollow = fs.constants.O_NOFOLLOW || 0;
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev
        || opened.ino !== before.ino || opened.size !== before.size) {
      throw dependencySurfaceError();
    }
    const contents = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size
        || after.mtimeMs !== opened.mtimeMs || contents.length !== opened.size) {
      throw dependencySurfaceError();
    }
    return Object.freeze({
      contents,
      byte_size: contents.length,
      mode: opened.mode & 0o777,
      sha256: sha256(contents),
      device: String(opened.dev),
      inode: String(opened.ino),
    });
  } catch (error) {
    if (error && error.code === "serialport_dependency_surface_rejected") throw error;
    throw dependencySurfaceError();
  } finally {
    if (descriptor != null) {
      try { fs.closeSync(descriptor); } catch { /* rejection already preserves no authority */ }
    }
  }
}

function parseDependencyJson(record) {
  try {
    const value = JSON.parse(record.contents.toString("utf8"));
    if (!isPlainObject(value)) throw dependencySurfaceError();
    return value;
  } catch (error) {
    if (error && error.code === "serialport_dependency_surface_rejected") throw error;
    throw dependencySurfaceError();
  }
}

function normalizeExpectedDependencyFiles(input) {
  if (!Array.isArray(input) || utilTypes.isProxy(input)
      || Object.getPrototypeOf(input) !== Array.prototype
      || input.length < 2 || input.length > MAX_DEPENDENCY_FILES) {
    throw dependencySurfaceError();
  }
  const records = [];
  let previous = null;
  let totalBytes = 0;
  for (let index = 0; index < input.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(input, index)) throw dependencySurfaceError();
    const record = input[index];
    assertClosedObject(record, `serialport_dependency_files[${index}]`, [
      "path", "byte_size", "sha256", "mode",
    ]);
    if (typeof record.path !== "string" || !DEPENDENCY_FILE_PATTERN.test(record.path)
        || record.path.includes("//") || record.path.includes("/../")
        || (previous != null && record.path <= previous)
        || !Number.isSafeInteger(record.byte_size) || record.byte_size < 1
        || record.byte_size > MAX_DEPENDENCY_FILE_BYTES
        || (record.mode !== 0o444 && record.mode !== 0o555)) {
      throw dependencySurfaceError();
    }
    assertDigest(record.sha256, `serialport_dependency_files[${index}].sha256`);
    totalBytes += record.byte_size;
    if (totalBytes > MAX_DEPENDENCY_SURFACE_BYTES) throw dependencySurfaceError();
    records.push(Object.freeze({
      path: record.path,
      byte_size: record.byte_size,
      sha256: record.sha256,
      mode: record.mode,
    }));
    previous = record.path;
  }
  if (!records.some((record) => record.path === "node_modules/serialport/package.json")
      || !records.some((record) => record.path === "node_modules/serialport/dist/index.js")) {
    throw dependencySurfaceError();
  }
  return Object.freeze(records);
}

function assertSafeDependencyDirectory(directoryPath) {
  const metadata = fs.lstatSync(directoryPath);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()
      || (metadata.mode & 0o022) !== 0) {
    throw dependencySurfaceError();
  }
  return metadata;
}

function verifyFixtureDependencySurface(rootAbs, expectedFiles) {
  try {
    if (typeof rootAbs !== "string" || !path.isAbsolute(rootAbs)
        || path.resolve(rootAbs) !== rootAbs) throw dependencySurfaceError();
    assertSafeDependencyDirectory(rootAbs);
    const rootManifestRecord = readSingleLinkFile(path.join(rootAbs, "package.json"), 256 * 1024);
    const lockRecord = readSingleLinkFile(path.join(rootAbs, "package-lock.json"), 512 * 1024);
    const rootManifest = parseDependencyJson(rootManifestRecord);
    const lock = parseDependencyJson(lockRecord);
    if (rootManifest.name !== "@hacker-bob/instrument-chameleon-worker-dependency-fixture"
        || rootManifest.version !== "0.0.0-development"
        || rootManifest.private !== true
        || !equalStringMap(rootManifest.dependencies, { serialport: SERIALPORT_VERSION })
        || lock.name !== rootManifest.name || lock.version !== rootManifest.version
        || lock.lockfileVersion !== 3 || lock.requires !== true
        || !isPlainObject(lock.packages)
        || !equalStringMap(lock.packages[""].dependencies, rootManifest.dependencies)) {
      throw dependencySurfaceError();
    }
    const lockKeys = Object.keys(lock.packages).sort();
    if (lockKeys.length !== 2 || lockKeys[0] !== ""
        || lockKeys[1] !== "node_modules/serialport") throw dependencySurfaceError();
    const lockedSerialPort = lock.packages["node_modules/serialport"];
    if (!isPlainObject(lockedSerialPort) || lockedSerialPort.version !== SERIALPORT_VERSION
        || lockedSerialPort.resolved !== SERIALPORT_PACKAGE_RESOLVED
        || lockedSerialPort.integrity !== SERIALPORT_PACKAGE_INTEGRITY
        || !equalStringMap(lockedSerialPort.dependencies, {})) {
      throw dependencySurfaceError();
    }

    const expected = new Map(expectedFiles.map((record) => [record.path, record]));
    const allowedDirectories = new Set(["node_modules", "node_modules/serialport"]);
    for (const record of expectedFiles) {
      let directory = path.posix.dirname(record.path);
      while (directory !== "." && directory.startsWith("node_modules/serialport")) {
        allowedDirectories.add(directory);
        directory = path.posix.dirname(directory);
      }
    }
    const seen = new Set();
    let totalBytes = 0;
    function walk(relativeDirectory) {
      const absoluteDirectory = path.join(rootAbs, ...relativeDirectory.split("/"));
      assertSafeDependencyDirectory(absoluteDirectory);
      const names = fs.readdirSync(absoluteDirectory).sort();
      for (const name of names) {
        if (!/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/u.test(name)) {
          throw dependencySurfaceError();
        }
        const relative = `${relativeDirectory}/${name}`;
        const absolute = path.join(rootAbs, ...relative.split("/"));
        const metadata = fs.lstatSync(absolute);
        if (metadata.isSymbolicLink()) throw dependencySurfaceError();
        if (metadata.isDirectory()) {
          if (!allowedDirectories.has(relative)) throw dependencySurfaceError();
          walk(relative);
          continue;
        }
        const expectedRecord = expected.get(relative);
        if (!expectedRecord) throw dependencySurfaceError();
        const actual = readSingleLinkFile(absolute, MAX_DEPENDENCY_FILE_BYTES);
        if (actual.byte_size !== expectedRecord.byte_size
            || actual.sha256 !== expectedRecord.sha256
            || actual.mode !== expectedRecord.mode) throw dependencySurfaceError();
        totalBytes += actual.byte_size;
        seen.add(relative);
      }
    }
    walk("node_modules");
    if (seen.size !== expected.size || totalBytes > MAX_DEPENDENCY_SURFACE_BYTES) {
      throw dependencySurfaceError();
    }
    const serialManifestRecord = readSingleLinkFile(
      path.join(rootAbs, "node_modules", "serialport", "package.json"),
      MAX_DEPENDENCY_FILE_BYTES,
    );
    const serialManifest = parseDependencyJson(serialManifestRecord);
    if (serialManifest.name !== "serialport" || serialManifest.version !== SERIALPORT_VERSION
        || serialManifest.main !== "./dist/index.js"
        || !equalStringMap(serialManifest.dependencies, lockedSerialPort.dependencies)) {
      throw dependencySurfaceError();
    }
    const basis = Object.freeze({
      version: SERIALPORT_DEPENDENCY_SURFACE_VERSION,
      kind: "serialport_dependency_surface_fixture_basis",
      serialport_version: SERIALPORT_VERSION,
      root_package_sha256: rootManifestRecord.sha256,
      package_lock_sha256: lockRecord.sha256,
      files: expectedFiles,
    });
    return Object.freeze({
      surface_digest: sha256(Buffer.from(canonicalJson(basis), "utf8")),
      file_count: seen.size,
      byte_count: totalBytes,
      root_package_sha256: rootManifestRecord.sha256,
      package_lock_sha256: lockRecord.sha256,
    });
  } catch (error) {
    if (error && error.code === "serialport_dependency_surface_rejected") throw error;
    throw dependencySurfaceError();
  }
}

function qualifyFixtureSerialPortDependencySurface(input) {
  assertClosedObject(input, "serialport_dependency_surface_fixture", [
    "version", "kind", "test_only", "root_abs", "files",
  ]);
  if (input.version !== SERIALPORT_DEPENDENCY_SURFACE_VERSION
      || input.kind !== "serialport_dependency_surface_fixture"
      || input.test_only !== true) throw dependencySurfaceError();
  const files = normalizeExpectedDependencyFiles(input.files);
  const verified = verifyFixtureDependencySurface(input.root_abs, files);
  const projection = Object.freeze({
    version: SERIALPORT_DEPENDENCY_SURFACE_VERSION,
    kind: "serialport_dependency_surface_fixture_qualification",
    serialport_version: SERIALPORT_VERSION,
    surface_digest: verified.surface_digest,
    file_count: verified.file_count,
    byte_count: verified.byte_count,
    fixture_only: true,
    caller_asserted_expected_files: true,
    module_loaded: false,
    authoritative: false,
    production_ready: false,
  });
  FIXTURE_SURFACE_QUALIFICATIONS.add(projection);
  FIXTURE_SURFACE_PRIVATE.set(projection, Object.freeze({
    root_abs: input.root_abs,
    files,
    verified,
  }));
  return projection;
}

function createFixtureSerialPortDependencyPort(input) {
  assertClosedObject(input, "serialport_dependency_fixture_port", [
    "version", "kind", "test_only", "serialport_constructor", "serialport_binding",
    "surface_qualification",
  ]);
  if (input.version !== SERIALPORT_DEPENDENCY_SURFACE_VERSION
      || input.kind !== "serialport_dependency_fixture_port" || input.test_only !== true
      || typeof input.serialport_constructor !== "function"
      || input.serialport_binding == null
      || (typeof input.serialport_binding !== "object"
        && typeof input.serialport_binding !== "function")) {
    throw dependencySurfaceError();
  }
  const qualification = input.surface_qualification;
  if (qualification != null && (!Object.isFrozen(qualification)
      || !FIXTURE_SURFACE_QUALIFICATIONS.has(qualification)
      || !FIXTURE_SURFACE_PRIVATE.has(qualification))) throw dependencySurfaceError();
  const port = Object.freeze({
    version: SERIALPORT_DEPENDENCY_SURFACE_VERSION,
    kind: "serialport_dependency_fixture_port",
    port_id: `serialport-dependency-fixture:${crypto.randomBytes(18).toString("base64url")}`,
    serialport_version: SERIALPORT_VERSION,
    surface_digest: qualification == null ? null : qualification.surface_digest,
    surface_qualified: qualification != null,
    fixture_only: true,
    authoritative: false,
    production_ready: false,
  });
  FIXTURE_DEPENDENCY_PORTS.add(port);
  FIXTURE_DEPENDENCY_PRIVATE.set(port, Object.freeze({
    SerialPort: input.serialport_constructor,
    binding: input.serialport_binding,
    qualification,
  }));
  return port;
}

function resolveFixtureSerialPortDependencyPort(port) {
  if (port == null || typeof port !== "object" || utilTypes.isProxy(port)
      || !Object.isFrozen(port) || !FIXTURE_DEPENDENCY_PORTS.has(port)
      || !FIXTURE_DEPENDENCY_PRIVATE.has(port)) throw dependencySurfaceError();
  const state = FIXTURE_DEPENDENCY_PRIVATE.get(port);
  if (state.qualification != null) {
    const privateSurface = FIXTURE_SURFACE_PRIVATE.get(state.qualification);
    const current = verifyFixtureDependencySurface(privateSurface.root_abs, privateSurface.files);
    if (current.surface_digest !== privateSurface.verified.surface_digest
        || current.root_package_sha256 !== privateSurface.verified.root_package_sha256
        || current.package_lock_sha256 !== privateSurface.verified.package_lock_sha256) {
      throw dependencySurfaceError();
    }
  }
  return state;
}

function digestDomain(domain, value) {
  return crypto.createHash("sha256")
    .update(domain, "utf8")
    .update(Buffer.from([0]))
    .update(typeof value === "string" ? value : canonicalJson(value), "utf8")
    .digest("hex");
}

function digestPrivateBytes(domain, value) {
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(value.length, 0);
  try {
    return crypto.createHash("sha256")
      .update(domain, "utf8")
      .update(Buffer.from([0]))
      .update(length)
      .update(value)
      .digest("hex");
  } finally {
    length.fill(0);
  }
}

function adapterError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function safeZero(value) {
  try {
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) value.fill(0);
  } catch {
    // Detached or hostile test buffers do not alter the fail-closed result.
  }
}

function normalizePrivateIdentity(value, label) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new Error(`${label} must be private byte material`);
  }
  const copy = Buffer.from(value);
  if (copy.length < USB_CDC_CUSTODY_LIMITS.min_hardware_identity_bytes
      || copy.length > USB_CDC_CUSTODY_LIMITS.max_hardware_identity_bytes) {
    copy.fill(0);
    throw new Error(`${label} has an invalid length`);
  }
  return copy;
}

function parseUsbIdentifier(value, label) {
  if (typeof value !== "string" || !HEX_U16_PATTERN.test(value)) {
    throw new Error(`${label} must be a hexadecimal USB identifier`);
  }
  return Number.parseInt(value.replace(/^0x/iu, ""), 16);
}

function optionalPortString(value, label, maximumBytes) {
  if (value == null || value === "") return null;
  return assertBoundedString(value, label, maximumBytes);
}

function lineConfigurationBasis(dtrAsserted) {
  return Object.freeze({
    baud_rate: USB_CDC_LINE_CONFIGURATION.baud_rate,
    data_bits: USB_CDC_LINE_CONFIGURATION.data_bits,
    stop_bits: USB_CDC_LINE_CONFIGURATION.stop_bits,
    parity: USB_CDC_LINE_CONFIGURATION.parity,
    dtr_asserted: dtrAsserted,
    exclusive_open: true,
    serial_lock: true,
    rts_cts: false,
    xon_xoff: false,
    generic_write_surface_exposed: false,
    brokered_exact_transaction_write_enabled: dtrAsserted,
    read_buffer_bytes: USB_CDC_CUSTODY_LIMITS.read_buffer_bytes,
    write_buffer_bytes: USB_CDC_CUSTODY_LIMITS.write_buffer_bytes,
    io_timeout_ms: USB_CDC_CUSTODY_LIMITS.io_timeout_ms,
  });
}

function transportGuarantees(dtrAsserted) {
  return { ...lineConfigurationBasis(dtrAsserted) };
}

function assertExpectedOptions(input, activated, timeoutField, label) {
  const basis = lineConfigurationBasis(activated);
  assertClosedObject(input, label, [...Object.keys(basis), timeoutField]);
  for (const [field, expected] of Object.entries(basis)) {
    if (input[field] !== expected) throw adapterError("serialport_transport_contract_rejected");
  }
  const expectedTimeout = timeoutField === "open_timeout_ms"
    ? USB_CDC_CUSTODY_LIMITS.open_timeout_ms
    : USB_CDC_CUSTODY_LIMITS.open_timeout_ms;
  if (input[timeoutField] !== expectedTimeout) {
    throw adapterError("serialport_transport_contract_rejected");
  }
}

function normalizeDependencies(input) {
  if (input == null) input = {};
  assertClosedObject(input, "serialport_usb_cdc_dependencies", [], [
    "serialport_dependency_port",
    "hardware_identity_resolver",
    "atomic_open",
    "platform",
  ]);
  for (const field of ["hardware_identity_resolver", "atomic_open"]) {
    if (Object.prototype.hasOwnProperty.call(input, field) && typeof input[field] !== "function") {
      throw new Error(`serialport_usb_cdc_dependencies.${field} must be a function`);
    }
  }
  const dependencyPort = Object.prototype.hasOwnProperty.call(input, "serialport_dependency_port")
    ? input.serialport_dependency_port : null;
  if (dependencyPort != null && (!Object.isFrozen(dependencyPort)
      || !FIXTURE_DEPENDENCY_PORTS.has(dependencyPort)
      || !FIXTURE_DEPENDENCY_PRIVATE.has(dependencyPort))) {
    throw dependencySurfaceError();
  }
  const platform = input.platform == null
    ? process.platform
    : assertBoundedString(input.platform, "serialport_usb_cdc_dependencies.platform", 64);
  return {
    dependency_port: dependencyPort,
    identity_resolver: input.hardware_identity_resolver || null,
    atomic_open: input.atomic_open || null,
    platform,
  };
}

function normalizePortInfo(raw, index, platform, identityResolver) {
  if (!isPlainObject(raw)) throw new Error("serialport list result must contain objects");
  const path = assertBoundedString(
    raw.path,
    `serialport_list[${index}].path`,
    USB_CDC_CUSTODY_LIMITS.max_path_bytes,
  );
  // Non-USB platform TTYs legitimately omit both IDs. They are outside this
  // driver's USB CDC surface and are ignored without opening.
  if (raw.vendorId == null && raw.productId == null) return null;
  const vendorId = parseUsbIdentifier(raw.vendorId, `serialport_list[${index}].vendorId`);
  const productId = parseUsbIdentifier(raw.productId, `serialport_list[${index}].productId`);
  const manufacturer = assertBoundedString(
    raw.manufacturer,
    `serialport_list[${index}].manufacturer`,
    USB_CDC_CUSTODY_LIMITS.max_model_bytes,
  );
  const serialNumber = optionalPortString(
    raw.serialNumber,
    `serialport_list[${index}].serialNumber`,
    USB_CDC_CUSTODY_LIMITS.max_serial_bytes,
  );
  const pnpId = optionalPortString(
    raw.pnpId,
    `serialport_list[${index}].pnpId`,
    USB_CDC_CUSTODY_LIMITS.max_path_bytes,
  );
  const locationId = optionalPortString(
    raw.locationId,
    `serialport_list[${index}].locationId`,
    USB_CDC_CUSTODY_LIMITS.max_path_bytes,
  );
  const privateBasis = Object.freeze({
    version: SERIALPORT_USB_CDC_DRIVER_VERSION,
    platform,
    vendor_id: vendorId,
    product_id: productId,
    model: manufacturer,
    path,
    serial_number: serialNumber,
    pnp_id: pnpId,
    location_id: locationId,
  });
  let resolverBytes = null;
  let identity = null;
  try {
    // Serial number, node path, VID/PID, and USB location are not automatically
    // high-entropy device identity. Hashing them would only disguise weak
    // provenance. An operator-owned resolver must map the private native facts
    // to the separately enrolled identity material used by custody.
    if (identityResolver == null) {
      throw adapterError("serialport_enrolled_identity_resolver_unavailable");
    }
    resolverBytes = identityResolver(privateBasis);
    if (resolverBytes && typeof resolverBytes.then === "function") {
      throw new Error("hardware identity resolver must be synchronous");
    }
    identity = normalizePrivateIdentity(resolverBytes, "serialport hardware identity");
  } finally {
    safeZero(resolverBytes);
  }
  return {
    vendor_id: vendorId,
    product_id: productId,
    model: manufacturer,
    path,
    serial_number: serialNumber,
    hardware_identity: identity,
  };
}

function samePrivateBytes(left, right) {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function sameCandidate(left, right) {
  return left.vendor_id === right.vendor_id
    && left.product_id === right.product_id
    && left.model === right.model
    && left.path === right.path
    && left.serial_number === right.serial_number
    && samePrivateBytes(left.hardware_identity, right.hardware_identity);
}

function clearDiscoveries(discoveries, except = null) {
  for (const discovery of discoveries) {
    if (discovery !== except) discovery.hardware_identity.fill(0);
  }
  discoveries.clear();
}

function assertSignal(signal, label) {
  if (!(signal instanceof AbortSignal)) throw new Error(`${label} must be an AbortSignal`);
  return signal;
}

function callbackPromise(invoke) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let invokeReturned = false;
    let callbackSeen = false;
    let pendingError = null;

    const settle = () => {
      if (settled || !invokeReturned || !callbackSeen) return;
      settled = true;
      if (pendingError != null) reject(adapterError("serialport_native_operation_failed"));
      else resolve();
    };
    const callback = (error) => {
      if (settled) return;
      if (callbackSeen) {
        pendingError = adapterError("serialport_native_operation_failed");
      } else {
        callbackSeen = true;
        pendingError = error ? adapterError("serialport_native_operation_failed") : null;
      }
      settle();
    };
    try {
      invoke(callback);
      invokeReturned = true;
      settle();
    } catch {
      invokeReturned = true;
      callbackSeen = true;
      pendingError = adapterError("serialport_native_operation_failed");
      settle();
    }
  });
}

function safeNativeClose(state) {
  if (state.close_promise != null) return state.close_promise;
  let resolveClose;
  let rejectClose;
  state.close_promise = new Promise((resolve, reject) => {
    resolveClose = resolve;
    rejectClose = reject;
  });
  void (async () => {
    const port = state.port;
    try {
      if (typeof port.set === "function" && port.isOpen === true) {
        try {
          await callbackPromise((callback) => port.set({ dtr: false, rts: false }, callback));
        } catch {
          // Closure is still mandatory when deassertion cannot be confirmed.
        }
      }
      if (port.isOpen === true) {
        if (typeof port.close !== "function") {
          throw adapterError("serialport_native_close_unavailable");
        }
        await callbackPromise((callback) => port.close(callback));
        if (port.isOpen !== false) {
          throw adapterError("serialport_native_close_unconfirmed");
        }
      }
      state.closed = true;
      state.activated = false;
    } catch {
      state.faulted = true;
      throw adapterError("serialport_native_close_failed");
    } finally {
      state.hardware_identity.fill(0);
    }
  })().then(resolveClose, rejectClose);
  return state.close_promise;
}

function extractPossiblePort(raw) {
  try {
    if (!isPlainObject(raw)) return null;
    const port = raw.port;
    if (port == null || (typeof port !== "object" && typeof port !== "function")) return null;
    return port;
  } catch {
    return null;
  }
}

function expectedAtomicAttestation(record, hardwareIdentity) {
  const lineConfigurationDigest = digestDomain(
    LINE_CONFIGURATION_DIGEST_DOMAIN,
    lineConfigurationBasis(false),
  );
  return Object.freeze({
    version: SERIALPORT_USB_CDC_DRIVER_VERSION,
    kind: ATOMIC_OPEN_ATTESTATION_KIND,
    path_digest: digestDomain(PATH_DIGEST_DOMAIN, record.path),
    hardware_identity_digest: digestPrivateBytes(
      HARDWARE_IDENTITY_DOMAIN,
      hardwareIdentity,
    ),
    line_configuration_digest: lineConfigurationDigest,
    exclusive_open: true,
    serial_lock: true,
    dtr_never_asserted: true,
    dtr_asserted: false,
  });
}

function zeroAtomicOpenIdentity(raw) {
  try {
    if (!isPlainObject(raw)) return;
    const descriptor = Object.getOwnPropertyDescriptor(raw, "opened_hardware_identity");
    if (descriptor && "value" in descriptor) safeZero(descriptor.value);
  } catch {
    // A hostile result cannot prevent fail-closed parsing.
  }
}

function assertAtomicOpenResult(raw, expected, enrolledHardwareIdentity) {
  let openedHardwareIdentity = null;
  try {
    assertClosedObject(raw, "serialport_atomic_open_result", [
      "port", "opened_hardware_identity", "attestation",
    ]);
    if (raw.port == null || (typeof raw.port !== "object" && typeof raw.port !== "function")) {
      throw adapterError("serialport_atomic_open_attestation_rejected");
    }
    openedHardwareIdentity = normalizePrivateIdentity(
      raw.opened_hardware_identity,
      "serialport_atomic_open_result.opened_hardware_identity",
    );
    if (!samePrivateBytes(openedHardwareIdentity, enrolledHardwareIdentity)) {
      throw adapterError("serialport_atomic_open_identity_rejected");
    }
    assertClosedObject(raw.attestation, "serialport_atomic_open_attestation", [
      ...Object.keys(expected),
      "native_proof_digest",
    ]);
    for (const [field, value] of Object.entries(expected)) {
      if (raw.attestation[field] !== value) {
        throw adapterError("serialport_atomic_open_attestation_rejected");
      }
    }
    assertDigest(
      raw.attestation.native_proof_digest,
      "serialport_atomic_open_attestation.native_proof_digest",
    );
    if (raw.port.isOpen !== true) {
      throw adapterError("serialport_atomic_open_attestation_rejected");
    }
    return {
      port: raw.port,
      opened_hardware_identity: openedHardwareIdentity,
    };
  } catch (error) {
    openedHardwareIdentity?.fill(0);
    throw error;
  } finally {
    zeroAtomicOpenIdentity(raw);
  }
}

function assertExactChameleonFrame(input, maximumLength, label) {
  if (!Buffer.isBuffer(input) && !(input instanceof Uint8Array)) {
    throw adapterError("serialport_transaction_frame_rejected");
  }
  const frame = Buffer.from(input);
  try {
    if (frame.length < FIXED_FRAME_BYTES || frame.length > maximumLength
        || frame[0] !== SOF || frame[1] !== SOF_LRC
        || frame.readUInt16BE(4) !== 0
        || calculateLrc(frame.subarray(2, 8)) !== frame[8]) {
      throw adapterError("serialport_transaction_frame_rejected");
    }
    const dataLength = frame.readUInt16BE(6);
    if (dataLength + FIXED_FRAME_BYTES !== frame.length
        || calculateLrc(frame.subarray(9, 9 + dataLength)) !== frame[9 + dataLength]) {
      throw adapterError("serialport_transaction_frame_rejected");
    }
    return frame;
  } catch (error) {
    frame.fill(0);
    if (error?.code === "serialport_transaction_frame_rejected") throw error;
    throw adapterError(`${label}_rejected`);
  }
}

function assertCandidateQuery(input) {
  assertClosedObject(input, "serialport_open_candidate_query", [
    "version", "candidate", "options", "signal",
  ]);
  if (input.version !== USB_CDC_CUSTODY_VERSION) {
    throw adapterError("serialport_transport_contract_rejected");
  }
  assertSignal(input.signal, "serialport_open_candidate_query.signal");
  assertClosedObject(input.candidate, "serialport_open_candidate_query.candidate", [
    "vendor_id", "product_id", "model", "path", "serial_number", "hardware_identity",
  ]);
  const candidate = {
    vendor_id: assertInteger(input.candidate.vendor_id, "candidate.vendor_id", 0, 0xffff),
    product_id: assertInteger(input.candidate.product_id, "candidate.product_id", 0, 0xffff),
    model: assertBoundedString(
      input.candidate.model,
      "candidate.model",
      USB_CDC_CUSTODY_LIMITS.max_model_bytes,
    ),
    path: assertBoundedString(
      input.candidate.path,
      "candidate.path",
      USB_CDC_CUSTODY_LIMITS.max_path_bytes,
    ),
    serial_number: assertBoundedString(
      input.candidate.serial_number,
      "candidate.serial_number",
      USB_CDC_CUSTODY_LIMITS.max_serial_bytes,
      { nullable: true },
    ),
    hardware_identity: normalizePrivateIdentity(
      input.candidate.hardware_identity,
      "candidate.hardware_identity",
    ),
  };
  assertExpectedOptions(input.options, false, "open_timeout_ms", "serialport_open_options");
  return candidate;
}

function createSerialPortUsbCdcDriverPort(
  input,
  enrollment,
  workerAuthority,
  dependencyInput,
) {
  if (arguments.length < 3 || arguments.length > 4) {
    throw new Error("serialport USB CDC driver creation requires three or four arguments");
  }
  assertClosedObject(input, "serialport_usb_cdc_driver", [
    "version",
    "custody_id",
    "driver_id",
    "driver_implementation_digest",
    "driver_binary_digest",
    "execution_principal_id",
    "worker_uid",
    "provider_descriptor_digest",
    "transport_digest",
  ]);
  if (input.version !== USB_CDC_CUSTODY_VERSION) {
    throw new Error(`serialport_usb_cdc_driver.version must be ${USB_CDC_CUSTODY_VERSION}`);
  }
  const dependencies = normalizeDependencies(dependencyInput);
  let native = null;
  let discoveries = new Set();
  let discoveryInFlight = false;
  const handles = new WeakSet();
  const handleStates = new WeakMap();

  function resolveNative() {
    let SerialPort;
    let binding;
    try {
      const resolved = resolveFixtureSerialPortDependencyPort(dependencies.dependency_port);
      SerialPort = resolved.SerialPort;
      binding = resolved.binding;
      if (typeof SerialPort !== "function" || binding == null
          || typeof binding.list !== "function") {
        throw new Error("serialport module shape mismatch");
      }
    } catch {
      throw adapterError("serialport_native_dependency_unavailable");
    }
    if (native != null && (native.SerialPort !== SerialPort || native.binding !== binding)) {
      throw adapterError("serialport_native_dependency_unavailable");
    }
    native = native || Object.freeze({ SerialPort, binding });
    return native;
  }

  function assertHandle(handle) {
    const state = handle == null ? null : handleStates.get(handle);
    if (!handle || !handles.has(handle) || !state || !Object.isFrozen(handle)
        || Reflect.ownKeys(handle).length !== 3
        || handle.version !== SERIALPORT_USB_CDC_DRIVER_VERSION
        || handle.kind !== "serialport_usb_cdc_private_handle"
        || typeof handle.handle_id !== "string") {
      throw adapterError("serialport_private_handle_rejected");
    }
    return state;
  }

  async function enumerateCandidates(query) {
    let ownsDiscovery = false;
    const candidates = [];
    try {
      assertClosedObject(query, "serialport_enumeration_query", [
        "version", "signal", "max_candidates", "discovery_timeout_ms",
      ]);
      if (query.version !== USB_CDC_CUSTODY_VERSION
          || query.max_candidates !== USB_CDC_CUSTODY_LIMITS.max_candidates
          || query.discovery_timeout_ms !== USB_CDC_CUSTODY_LIMITS.discovery_timeout_ms) {
        throw new Error("enumeration contract mismatch");
      }
      assertSignal(query.signal, "serialport_enumeration_query.signal");
      if (query.signal.aborted) throw adapterError("serialport_discovery_aborted");
      if (discoveryInFlight) throw adapterError("serialport_discovery_already_in_flight");
      discoveryInFlight = true;
      ownsDiscovery = true;
      const resolved = resolveNative();
      const raw = await resolved.binding.list.call(resolved.binding);
      if (query.signal.aborted) throw adapterError("serialport_discovery_aborted");
      if (!Array.isArray(raw) || raw.length > query.max_candidates) {
        throw new Error("serialport list exceeded candidate limit");
      }
      clearDiscoveries(discoveries);
      discoveries = new Set();
      for (let index = 0; index < raw.length; index += 1) {
        if (!Object.prototype.hasOwnProperty.call(raw, index)) {
          throw new Error("serialport list cannot be sparse");
        }
        const candidate = normalizePortInfo(
          raw[index],
          index,
          dependencies.platform,
          dependencies.identity_resolver,
        );
        if (candidate == null) continue;
        discoveries.add(candidate);
        candidates.push({
          ...candidate,
          hardware_identity: Buffer.from(candidate.hardware_identity),
        });
      }
      const discoveryRecords = discoveries;
      // The custody controller copies the returned identities in the Promise
      // continuation before the next event-loop phase. Erase those transfer
      // buffers afterward, and also expire records when custody rejects the
      // whole candidate set without calling open_candidate. A synchronously
      // started open detaches its selected record before this cleanup runs.
      setImmediate(() => {
        for (const candidate of candidates) candidate.hardware_identity.fill(0);
        if (discoveries === discoveryRecords) {
          clearDiscoveries(discoveryRecords);
          discoveries = new Set();
        }
      });
      return candidates;
    } catch {
      for (const candidate of candidates) candidate.hardware_identity.fill(0);
      clearDiscoveries(discoveries);
      discoveries = new Set();
      throw adapterError("serialport_usb_cdc_discovery_failed");
    } finally {
      if (ownsDiscovery) discoveryInFlight = false;
    }
  }

  async function openCandidate(query) {
    let candidate = null;
    let record = null;
    let rawOpen = null;
    let unattachedOpenedIdentity = null;
    try {
      candidate = assertCandidateQuery(query);
      if (query.signal.aborted) throw adapterError("serialport_open_aborted");
      for (const item of discoveries) {
        if (sameCandidate(item, candidate)) {
          if (record != null) throw adapterError("serialport_open_candidate_ambiguous");
          record = item;
        }
      }
      if (record == null) throw adapterError("serialport_open_candidate_not_enumerated");
      // Stock SerialPort can only call set({dtr:false}) after open and cannot
      // prove there was no transient assertion. Refuse before constructing or
      // opening a port unless a separate native atomic-open seam owns it.
      if (dependencies.atomic_open == null) throw adapterError(ATOMIC_OPEN_BLOCKER_CODE);
      clearDiscoveries(discoveries, record);
      discoveries = new Set();
      const resolved = resolveNative();
      const expectedAttestation = expectedAtomicAttestation(
        record,
        candidate.hardware_identity,
      );
      const serialOptions = Object.freeze({
        path: record.path,
        baudRate: USB_CDC_LINE_CONFIGURATION.baud_rate,
        dataBits: USB_CDC_LINE_CONFIGURATION.data_bits,
        stopBits: USB_CDC_LINE_CONFIGURATION.stop_bits,
        parity: USB_CDC_LINE_CONFIGURATION.parity,
        rtscts: false,
        xon: false,
        xoff: false,
        xany: false,
        lock: true,
        autoOpen: false,
        highWaterMark: Math.max(
          USB_CDC_CUSTODY_LIMITS.read_buffer_bytes,
          USB_CDC_CUSTODY_LIMITS.write_buffer_bytes,
        ),
        binding: resolved.binding,
      });
      rawOpen = await dependencies.atomic_open(Object.freeze({
        version: SERIALPORT_USB_CDC_DRIVER_VERSION,
        SerialPort: resolved.SerialPort,
        binding: resolved.binding,
        serial_options: serialOptions,
        expected_attestation: expectedAttestation,
        signal: query.signal,
      }));
      const opened = assertAtomicOpenResult(
        rawOpen,
        expectedAttestation,
        candidate.hardware_identity,
      );
      const port = opened.port;
      unattachedOpenedIdentity = opened.opened_hardware_identity;
      if (query.signal.aborted) {
        const abortedState = {
          port,
          hardware_identity: unattachedOpenedIdentity,
          activated: false,
          closed: false,
          faulted: false,
          close_promise: null,
          transaction_active: false,
        };
        unattachedOpenedIdentity = null;
        await safeNativeClose(abortedState);
        throw adapterError("serialport_open_aborted");
      }
      const handle = Object.freeze({
        version: SERIALPORT_USB_CDC_DRIVER_VERSION,
        kind: "serialport_usb_cdc_private_handle",
        handle_id: `serialport-handle:${crypto.randomBytes(18).toString("base64url")}`,
      });
      const state = {
        port,
        hardware_identity: unattachedOpenedIdentity,
        activated: false,
        closed: false,
        faulted: false,
        close_promise: null,
        transaction_active: false,
      };
      unattachedOpenedIdentity = null;
      if (typeof port.on !== "function" || typeof port.removeListener !== "function") {
        await safeNativeClose(state);
        throw adapterError("serialport_atomic_open_attestation_rejected");
      }
      try {
        port.on("error", () => {
          state.faulted = true;
          state.hardware_identity.fill(0);
          void safeNativeClose(state).catch(() => undefined);
        });
        if (state.faulted || state.closed || port.isOpen !== true) {
          throw adapterError("serialport_atomic_open_attestation_rejected");
        }
        port.on("close", () => {
          state.closed = true;
          state.activated = false;
          state.hardware_identity.fill(0);
        });
        if (state.faulted || state.closed || port.isOpen !== true) {
          throw adapterError("serialport_atomic_open_attestation_rejected");
        }
      } catch {
        await safeNativeClose(state);
        throw adapterError("serialport_atomic_open_attestation_rejected");
      }
      handles.add(handle);
      handleStates.set(handle, state);
      return {
        handle,
        opened_hardware_identity: Buffer.from(state.hardware_identity),
        transport_guarantees: transportGuarantees(false),
      };
    } catch {
      unattachedOpenedIdentity?.fill(0);
      zeroAtomicOpenIdentity(rawOpen);
      const possiblePort = extractPossiblePort(rawOpen);
      if (possiblePort != null && possiblePort.isOpen === true) {
        const cleanupState = {
          port: possiblePort,
          hardware_identity: record == null
            ? Buffer.alloc(USB_CDC_CUSTODY_LIMITS.min_hardware_identity_bytes)
            : Buffer.from(record.hardware_identity),
          activated: false,
          closed: false,
          faulted: false,
          close_promise: null,
          transaction_active: false,
        };
        try { await safeNativeClose(cleanupState); } catch { /* uncertainty stays external */ }
      }
      throw adapterError("serialport_usb_cdc_open_failed");
    } finally {
      candidate?.hardware_identity.fill(0);
      if (record != null) record.hardware_identity.fill(0);
    }
  }

  async function activateHandle(query) {
    try {
      assertClosedObject(query, "serialport_activation_query", [
        "version", "handle", "options", "signal",
      ]);
      if (query.version !== USB_CDC_CUSTODY_VERSION) {
        throw adapterError("serialport_transport_contract_rejected");
      }
      assertSignal(query.signal, "serialport_activation_query.signal");
      assertExpectedOptions(
        query.options,
        true,
        "activation_timeout_ms",
        "serialport_activation_options",
      );
      const state = assertHandle(query.handle);
      if (query.signal.aborted || state.closed || state.faulted || state.port.isOpen !== true
          || state.activated || typeof state.port.set !== "function") {
        throw adapterError("serialport_activation_rejected");
      }
      await callbackPromise((callback) => state.port.set({ dtr: true, rts: false }, callback));
      if (query.signal.aborted || state.closed || state.faulted || state.port.isOpen !== true) {
        throw adapterError("serialport_activation_ambiguous");
      }
      state.activated = true;
      const openedHardwareIdentity = Buffer.from(state.hardware_identity);
      // The enrolled identity is needed only across open -> activation. The
      // active transaction and close paths are already bound to the private
      // handle, so retaining raw identity for the connection lifetime adds no
      // authority and unnecessarily extends secret lifetime.
      state.hardware_identity.fill(0);
      return {
        activated: true,
        opened_hardware_identity: openedHardwareIdentity,
        transport_guarantees: transportGuarantees(true),
      };
    } catch {
      throw adapterError("serialport_usb_cdc_activation_failed");
    }
  }

  async function closeHandle(query) {
    try {
      assertClosedObject(query, "serialport_close_query", [
        "version", "handle", "signal", "close_timeout_ms",
      ]);
      if (query.version !== USB_CDC_CUSTODY_VERSION
          || query.close_timeout_ms !== USB_CDC_CUSTODY_LIMITS.close_timeout_ms) {
        throw adapterError("serialport_transport_contract_rejected");
      }
      assertSignal(query.signal, "serialport_close_query.signal");
      const state = assertHandle(query.handle);
      if (state.transaction_active) throw adapterError("serialport_close_while_transaction_active");
      await safeNativeClose(state);
      return { closed: true };
    } catch {
      throw adapterError("serialport_usb_cdc_close_failed");
    }
  }

  function transactHandle(query) {
    let state;
    let request = null;
    try {
      assertClosedObject(query, "serialport_transaction_query", [
        "version",
        "handle",
        "transaction_id",
        "connection_generation",
        "request_bytes",
        "maximum_response_bytes",
        "timeout_ms",
        "signal",
      ]);
      if (query.version !== USB_CDC_CUSTODY_VERSION) {
        throw adapterError("serialport_transport_contract_rejected");
      }
      assertSignal(query.signal, "serialport_transaction_query.signal");
      assertBoundedString(query.transaction_id, "serialport_transaction_id", 256);
      assertInteger(query.connection_generation, "connection_generation", 1);
      assertInteger(
        query.maximum_response_bytes,
        "maximum_response_bytes",
        FIXED_FRAME_BYTES,
        Math.min(USB_CDC_CUSTODY_LIMITS.read_buffer_bytes, ABSOLUTE_MAX_FRAME_LENGTH),
      );
      assertInteger(
        query.timeout_ms,
        "timeout_ms",
        1,
        USB_CDC_CUSTODY_LIMITS.io_timeout_ms,
      );
      state = assertHandle(query.handle);
      request = assertExactChameleonFrame(
        query.request_bytes,
        Math.min(USB_CDC_CUSTODY_LIMITS.write_buffer_bytes, ABSOLUTE_MAX_FRAME_LENGTH),
        "serialport_transaction_request_frame",
      );
      if (query.signal.aborted || state.closed || state.faulted || !state.activated
          || state.port.isOpen !== true || state.transaction_active
          || typeof state.port.write !== "function" || typeof state.port.drain !== "function"
          || typeof state.port.on !== "function" || typeof state.port.removeListener !== "function"
          || (Number.isSafeInteger(state.port.readableLength)
            && state.port.readableLength !== 0)) {
        throw adapterError("serialport_transaction_state_rejected");
      }
    } catch {
      request?.fill(0);
      return Promise.reject(adapterError("serialport_usb_cdc_transaction_failed"));
    }

    state.transaction_active = true;
    return new Promise((resolve, reject) => {
      const port = state.port;
      let settled = false;
      let failureRequested = false;
      let responseBuffer = Buffer.alloc(0);
      let response = null;
      let expectedLength = null;
      let writeCompleted = false;
      let drainCompleted = false;
      let writeInvoked = false;
      let writeCallbackSeen = false;
      let drainCallbackSeen = false;
      let completionImmediate = null;
      let abortListenerAttached = false;
      let dataListenerAttached = false;
      let errorListenerAttached = false;
      let closeListenerAttached = false;
      const requestCommand = request.readUInt16BE(2);

      function cleanup() {
        if (completionImmediate != null) {
          clearImmediate(completionImmediate);
          completionImmediate = null;
        }
        try {
          if (abortListenerAttached) query.signal.removeEventListener("abort", onAbort);
        } catch { /* fail-closed settlement must still erase private bytes */ }
        try {
          if (dataListenerAttached) port.removeListener("data", onData);
        } catch { /* fail-closed settlement must still erase private bytes */ }
        try {
          if (errorListenerAttached) port.removeListener("error", onError);
        } catch { /* fail-closed settlement must still erase private bytes */ }
        try {
          if (closeListenerAttached) port.removeListener("close", onClose);
        } catch { /* fail-closed settlement must still erase private bytes */ }
        state.transaction_active = false;
        request.fill(0);
        responseBuffer.fill(0);
        responseBuffer = Buffer.alloc(0);
      }

      function finishFailure() {
        if (settled) return;
        settled = true;
        response?.fill(0);
        response = null;
        cleanup();
        reject(adapterError("serialport_usb_cdc_transaction_failed"));
      }

      function requestFailure() {
        if (settled) return;
        failureRequested = true;
        response?.fill(0);
        response = null;
        if (completionImmediate != null) {
          clearImmediate(completionImmediate);
          completionImmediate = null;
        }
        // Before the native write callback, the binding may still retain the
        // caller's request buffer. Start native quarantine and keep this
        // Promise pending until either that callback or close settlement makes
        // erasure safe. Custody therefore cannot mistake AbortSignal delivery
        // for actual native-operation settlement.
        if (writeInvoked && !writeCallbackSeen && !state.closed) {
          void safeNativeClose(state).then(finishFailure, finishFailure);
          return;
        }
        finishFailure();
      }

      function maybeSucceed() {
        if (settled || failureRequested || response == null
            || !writeCompleted || !drainCompleted || completionImmediate != null) return;
        // Do not settle inside a native callback or the first complete data
        // event. One event-loop barrier keeps listeners active for another
        // already-queued chunk, so split trailing frames cannot be mistaken for
        // a single exact response merely because the stream chunked them.
        completionImmediate = setImmediate(() => {
          completionImmediate = null;
          if (settled || failureRequested) return;
          try {
            if (query.signal.aborted || state.closed || state.faulted
                || state.port.isOpen !== true
                || (Number.isSafeInteger(state.port.readableLength)
                  && state.port.readableLength !== 0)) {
              requestFailure();
              return;
            }
          } catch {
            requestFailure();
            return;
          }
          settled = true;
          const transferred = response;
          response = null;
          cleanup();
          resolve({ response_bytes: transferred });
        });
      }

      function onAbort() { requestFailure(); }
      function onError() { state.faulted = true; requestFailure(); }
      function onClose() {
        state.closed = true;
        state.activated = false;
        requestFailure();
      }

      function onData(chunk) {
        if (settled) {
          safeZero(chunk);
          return;
        }
        let chunkCopy = null;
        let nextBuffer = null;
        try {
          if ((!Buffer.isBuffer(chunk) && !(chunk instanceof Uint8Array))
              || chunk.byteLength < 1
              || responseBuffer.length + chunk.byteLength > query.maximum_response_bytes
              || responseBuffer.length + chunk.byteLength > ABSOLUTE_MAX_FRAME_LENGTH) {
            requestFailure();
            return;
          }
          chunkCopy = Buffer.from(chunk);
          nextBuffer = Buffer.concat(
            [responseBuffer, chunkCopy],
            responseBuffer.length + chunkCopy.length,
          );
          responseBuffer.fill(0);
          responseBuffer = nextBuffer;
          nextBuffer = null;
          if ((responseBuffer.length >= 1 && responseBuffer[0] !== SOF)
              || (responseBuffer.length >= 2 && responseBuffer[1] !== SOF_LRC)) {
            requestFailure();
            return;
          }
          if (responseBuffer.length >= 9) {
            if (responseBuffer.readUInt16BE(2) !== requestCommand
                || calculateLrc(responseBuffer.subarray(2, 8)) !== responseBuffer[8]) {
              requestFailure();
              return;
            }
            const candidateLength = responseBuffer.readUInt16BE(6) + FIXED_FRAME_BYTES;
            if (candidateLength > query.maximum_response_bytes
                || candidateLength > ABSOLUTE_MAX_FRAME_LENGTH) {
              requestFailure();
              return;
            }
            expectedLength = candidateLength;
          }
          if (expectedLength == null || responseBuffer.length < expectedLength) return;
          if (responseBuffer.length !== expectedLength
              || calculateLrc(responseBuffer.subarray(9, expectedLength - 1))
                !== responseBuffer[expectedLength - 1]) {
            requestFailure();
            return;
          }
          response = Buffer.from(responseBuffer);
          maybeSucceed();
        } catch {
          requestFailure();
        } finally {
          chunkCopy?.fill(0);
          nextBuffer?.fill(0);
          safeZero(chunk);
        }
      }

      try {
        query.signal.addEventListener("abort", onAbort, { once: true });
        abortListenerAttached = true;
        if (query.signal.aborted) { requestFailure(); return; }
        port.on("data", onData);
        dataListenerAttached = true;
        if (settled || failureRequested) return;
        port.on("error", onError);
        errorListenerAttached = true;
        if (settled || failureRequested) return;
        port.on("close", onClose);
        closeListenerAttached = true;
        if (settled || failureRequested) return;
        // Exactly one write call is permitted. Failure, abort, timeout, close,
        // or malformed response is handed back to custody as ambiguous; this
        // adapter never retries or reconnects a command.
        writeInvoked = true;
        port.write(request, (writeError) => {
          if (settled) return;
          if (writeCallbackSeen) { requestFailure(); return; }
          writeCallbackSeen = true;
          if (failureRequested) { finishFailure(); return; }
          if (writeError) { requestFailure(); return; }
          writeCompleted = true;
          try {
            port.drain((drainError) => {
              if (settled) return;
              if (drainCallbackSeen) { requestFailure(); return; }
              drainCallbackSeen = true;
              if (failureRequested || drainError) { requestFailure(); return; }
              drainCompleted = true;
              maybeSucceed();
            });
          } catch {
            requestFailure();
          }
        });
      } catch {
        requestFailure();
      }
    });
  }

  return createUsbCdcDriverPort({
    ...input,
    enumerate_candidates: enumerateCandidates,
    open_candidate: openCandidate,
    activate_handle: activateHandle,
    close_handle: closeHandle,
    transact_handle: transactHandle,
  }, enrollment, workerAuthority);
}

module.exports = {
  SERIALPORT_DEPENDENCY_SURFACE_VERSION,
  SERIALPORT_USB_CDC_DRIVER_ASSURANCE,
  SERIALPORT_USB_CDC_DRIVER_VERSION,
  createFixtureSerialPortDependencyPort,
  createSerialPortUsbCdcDriverPort,
  qualifyFixtureSerialPortDependencySurface,
};
