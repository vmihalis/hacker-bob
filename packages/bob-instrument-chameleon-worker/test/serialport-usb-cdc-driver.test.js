"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { EventEmitter } = require("node:events");
const Module = require("node:module");
const { spawnSync } = require("node:child_process");

const {
  SERIALPORT_DEPENDENCY_SURFACE_VERSION,
  SERIALPORT_USB_CDC_DRIVER_ASSURANCE,
  SERIALPORT_USB_CDC_DRIVER_VERSION,
  createFixtureSerialPortDependencyPort,
  createSerialPortUsbCdcDriverPort,
  qualifyFixtureSerialPortDependencySurface,
} = require("../lib/serialport-usb-cdc-driver.js");
const {
  USB_CDC_CUSTODY_LIMITS,
  USB_CDC_CUSTODY_VERSION,
  USB_CDC_HARDWARE_IDENTITY_DOMAIN,
  USB_CDC_WORKER_AUTHORITY_DOMAIN,
  USB_CDC_WORKER_AUTHORITY_SIGNING_DOMAIN,
  createUsbCdcOpenAuthorityPort,
  createUsbCdcWorkerAuthorityPort,
  createWorkerUsbCdcConnectionGenerationHandoff,
  createWorkerUsbCdcCustody,
  createWorkerUsbCdcTransactionPort,
  enrollOperatorUsbCdcDevice,
  executeWorkerUsbCdcTransaction,
} = require("@hacker-bob/instrument-chameleon-worker-runtime/usb-cdc-custody");
const {
  compileHf14aProbe,
  encodeCompiledHf14aProbeForProviderWorker,
} = require("@hacker-bob/instrument-chameleon-worker-runtime/hf14a-probe-compiler");
const {
  FIXED_FRAME_BYTES,
  SOF,
  SOF_LRC,
  calculateLrc,
} = require("@hacker-bob/instrument-chameleon-worker-runtime/codec");

const PACKAGE_ROOT = path.resolve(__dirname, "..");
const RUNTIME_PACKAGE_ROOT = path.resolve(PACKAGE_ROOT, "../bob-instrument-chameleon-worker-runtime");
const IDENTITY_A = Buffer.alloc(32, 0x41);
const IDENTITY_B = Buffer.alloc(32, 0x42);
const PRIVATE_PATH_A = "/dev/PRIVATE-CHAMELEON-A";
const PRIVATE_PATH_B = "/dev/PRIVATE-CHAMELEON-B";
const PRIVATE_SERIAL_A = "PRIVATE-SERIAL-A";
const HF14A_RAW_COMMAND_ID = 2010;
const FILTERS = Object.freeze({
  vendor_id: 0x6868,
  product_id: 0x8686,
  model: "rf-lab-device",
});
const WORKER_UID = process.getuid();

function digest(label) {
  return crypto.createHash("sha256").update(label, "utf8").digest("hex");
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  )).join(",")}}`;
}

function digestCanonical(value) {
  return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function identityDigest(identity) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(identity.length, 0);
  return crypto.createHash("sha256")
    .update(USB_CDC_HARDWARE_IDENTITY_DOMAIN, "utf8")
    .update(Buffer.from([0]))
    .update(length)
    .update(identity)
    .digest("hex");
}

const DRIVER_BINDING = Object.freeze({
  custody_id: "worker_cdc_custody_01",
  driver_id: "serialport_usb_cdc_driver",
  driver_implementation_digest: digest("serialport-worker-implementation"),
  driver_binary_digest: digest("serialport-worker-binary"),
  execution_principal_id: "principal:chameleon-worker",
  worker_uid: WORKER_UID,
  provider_descriptor_digest: digest("chameleon-provider-descriptor"),
  transport_digest: digest("chameleon-serialport-usb-cdc-transport"),
});

function signWorkerAuthority(payload, privateKey) {
  const payloadDigest = digestCanonical(payload);
  const signature = crypto.sign(
    null,
    Buffer.from(`${USB_CDC_WORKER_AUTHORITY_SIGNING_DOMAIN}\0${payloadDigest}`, "utf8"),
    privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: USB_CDC_WORKER_AUTHORITY_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  return { ...basis, signed_authority_digest: digestCanonical(basis) };
}

function authorityFixture(identity = IDENTITY_A) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyDigest = crypto.createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  const workerCurrent = {
    version: 1,
    authority_id: "hotel_lab_usb_worker_authority",
    trust_root_id: "hotel_lab_usb_worker_root",
    trust_root_epoch: 1,
    authority_epoch: 1,
    revocation_generation: 0,
    signer_key_id: "hotel_lab_usb_worker_key",
    signer_public_key_digest: publicKeyDigest,
    trusted: true,
    revoked: false,
    custody_allowed: true,
    enrollment_id: "operator_device_01",
    hardware_identity_digest: identityDigest(identity),
    ...DRIVER_BINDING,
  };
  const workerPort = createUsbCdcWorkerAuthorityPort({
    version: 1,
    authority_id: workerCurrent.authority_id,
    trust_root_id: workerCurrent.trust_root_id,
    signer_key_id: workerCurrent.signer_key_id,
    signer_public_key: publicKey,
    minimum_trust_root_epoch: 1,
    minimum_authority_epoch: 1,
    minimum_revocation_generation: 0,
    resolve_current_worker_authority() {
      return signWorkerAuthority({ ...workerCurrent }, privateKey);
    },
  });
  const openCurrent = {
    version: 1,
    authority_id: "hotel_lab_usb_authority",
    authority_epoch: 1,
    enrollment_id: workerCurrent.enrollment_id,
    alias: "front_desk_research_unit",
    trusted: true,
    revoked: false,
    open_allowed: true,
    candidate_filters: { ...FILTERS },
    hardware_identity: Buffer.from(identity),
    hardware_identity_provenance: "operator_enrolled_high_entropy",
  };
  const openPort = createUsbCdcOpenAuthorityPort({
    version: 1,
    authority_id: openCurrent.authority_id,
    worker_authority_port: workerPort,
    resolve_current_enrollment() {
      return {
        ...openCurrent,
        candidate_filters: { ...openCurrent.candidate_filters },
        hardware_identity: Buffer.from(openCurrent.hardware_identity),
      };
    },
  });
  const enrollment = enrollOperatorUsbCdcDevice({
    version: 1,
    enrollment_id: openCurrent.enrollment_id,
    alias: openCurrent.alias,
    authority_id: openCurrent.authority_id,
  }, openPort);
  return { enrollment, openPort, workerPort };
}

function makeFrame(command, status = 0, dataInput = Buffer.alloc(0)) {
  const data = Buffer.from(dataInput);
  const frame = Buffer.alloc(FIXED_FRAME_BYTES + data.length);
  frame[0] = SOF;
  frame[1] = SOF_LRC;
  frame.writeUInt16BE(command, 2);
  frame.writeUInt16BE(status, 4);
  frame.writeUInt16BE(data.length, 6);
  frame[8] = calculateLrc(frame.subarray(2, 8));
  data.copy(frame, 9);
  frame[9 + data.length] = calculateLrc(data);
  data.fill(0);
  return frame;
}

function compiledWorkerCommand(schemaId = "iso14443a.requa_atqa_v1") {
  return encodeCompiledHf14aProbeForProviderWorker(compileHf14aProbe({
    version: 1,
    schema_id: schemaId,
  }));
}

function expectedRequaRequestFrame() {
  return Buffer.from("11ef07da0000000619c00064000726af", "hex");
}

function portInfo({
  pathValue = PRIVATE_PATH_A,
  serialNumber = PRIVATE_SERIAL_A,
} = {}) {
  return {
    path: pathValue,
    manufacturer: FILTERS.model,
    serialNumber,
    pnpId: `usb-${serialNumber}`,
    locationId: pathValue === PRIVATE_PATH_A ? "20-1" : "20-2",
    vendorId: FILTERS.vendor_id.toString(16),
    productId: FILTERS.product_id.toString(16),
  };
}

function fakeNative(options = {}) {
  const stats = {
    lists: 0,
    constructors: 0,
    atomic_opens: 0,
    opens: 0,
    sets: [],
    writes: [],
    drains: 0,
    closes: 0,
    constructor_options: [],
    emitted_chunks: [],
    instances: [],
    opened_identities: [],
    write_argument: null,
    write_argument_at_close: null,
  };
  const binding = {
    async list() {
      stats.lists += 1;
      if (options.listError) throw new Error(`native list leaked ${PRIVATE_PATH_A}`);
      return (options.ports || [portInfo()]).map((entry) => ({ ...entry }));
    },
  };
  class FakeSerialPort extends EventEmitter {
    constructor(serialOptions) {
      super();
      stats.constructors += 1;
      stats.constructor_options.push(serialOptions);
      this.options = serialOptions;
      this.isOpen = false;
      this.readableLength = options.staleReadableBytes || 0;
      stats.instances.push(this);
    }

    open(callback) {
      stats.opens += 1;
      this.isOpen = true;
      queueMicrotask(() => callback(options.openError ? new Error("private open failure") : null));
    }

    set(value, callback) {
      stats.sets.push({ ...value });
      if (options.setCallbackThenThrow && value.dtr === true) {
        callback(null);
        throw new Error("private post-callback set failure");
      }
      queueMicrotask(() => callback(options.setError ? new Error("private set failure") : null));
    }

    write(value, callback) {
      stats.writes.push(Buffer.from(value));
      stats.write_argument = value;
      const complete = () => {
        callback(options.writeError ? new Error("private write failure") : null);
        if (options.writeError || options.noResponse) return;
        const chunks = options.responseChunks || [makeFrame(HF14A_RAW_COMMAND_ID)];
        for (const chunk of chunks) {
          const emitChunk = () => {
          const emitted = Buffer.from(chunk);
          stats.emitted_chunks.push(emitted);
          this.emit("data", emitted);
          };
          if (options.synchronousResponse) emitChunk();
          else queueMicrotask(emitChunk);
        }
      };
      if (options.writeCallbackThenThrow) {
        complete();
        throw new Error("private post-callback write failure");
      }
      if (options.writeCallbackDelayMs) setTimeout(complete, options.writeCallbackDelayMs);
      else queueMicrotask(complete);
      return true;
    }

    drain(callback) {
      stats.drains += 1;
      queueMicrotask(() => callback(options.drainError ? new Error("private drain failure") : null));
    }

    close(callback) {
      stats.closes += 1;
      stats.write_argument_at_close = stats.write_argument == null
        ? null
        : Buffer.from(stats.write_argument);
      if (!options.closeStaysOpen) this.isOpen = false;
      queueMicrotask(() => {
        if (!options.closeStaysOpen) this.emit("close");
        callback(options.closeError ? new Error("private close failure") : null);
      });
    }

    on(eventName, listener) {
      if (options.throwOnListenerEvent === eventName) {
        throw new Error(`private ${eventName} listener failure`);
      }
      return super.on(eventName, listener);
    }

    removeListener(eventName, listener) {
      if (options.throwOnRemoveListenerEvent === eventName) {
        throw new Error(`private ${eventName} remove-listener failure`);
      }
      return super.removeListener(eventName, listener);
    }
  }
  FakeSerialPort.binding = binding;

  function dependencies({
    withAtomicOpen = true,
    attestationMutator = null,
    surfaceQualification = null,
    identityForPath = (pathValue) => (
      pathValue === PRIVATE_PATH_A ? IDENTITY_A : IDENTITY_B
    ),
  } = {}) {
    const result = {
      serialport_dependency_port: createFixtureSerialPortDependencyPort({
        version: SERIALPORT_DEPENDENCY_SURFACE_VERSION,
        kind: "serialport_dependency_fixture_port",
        test_only: true,
        serialport_constructor: FakeSerialPort,
        serialport_binding: binding,
        surface_qualification: surfaceQualification,
      }),
      platform: "fixture-platform",
      hardware_identity_resolver(privateBasis) {
        return Buffer.from(identityForPath(privateBasis.path));
      },
    };
    if (withAtomicOpen) {
      result.atomic_open = async function atomicOpen(query) {
        stats.atomic_opens += 1;
        const port = new query.SerialPort(query.serial_options);
        await new Promise((resolve, reject) => {
          port.open((error) => (error ? reject(error) : resolve()));
        });
        if (options.lateOpenReturnMs) {
          await new Promise((resolve) => setTimeout(resolve, options.lateOpenReturnMs));
        }
        const attestation = {
          ...query.expected_attestation,
          native_proof_digest: digest("fixture-native-atomic-open-proof"),
        };
        if (typeof attestationMutator === "function") attestationMutator(attestation);
        const openedHardwareIdentity = Buffer.from(
          options.openedIdentity || identityForPath(query.serial_options.path),
        );
        stats.opened_identities.push(openedHardwareIdentity);
        return {
          port,
          opened_hardware_identity: openedHardwareIdentity,
          attestation,
        };
      };
    }
    return result;
  }
  return { binding, dependencies, FakeSerialPort, stats };
}

function setup(native, dependencyOptions = {}) {
  const authority = authorityFixture();
  const dependencies = dependencyOptions.direct_dependencies
    || native.dependencies(dependencyOptions);
  const driverPort = createSerialPortUsbCdcDriverPort({
    version: USB_CDC_CUSTODY_VERSION,
    ...DRIVER_BINDING,
  }, authority.enrollment, authority.workerPort, dependencies);
  const custody = createWorkerUsbCdcCustody({
    version: USB_CDC_CUSTODY_VERSION,
    custody_id: DRIVER_BINDING.custody_id,
    enrollment: authority.enrollment,
    driver_port: driverPort,
    open_authority_port: authority.openPort,
    worker_authority_port: authority.workerPort,
  });
  return { authority, custody, driverPort };
}

function assertSafe(value) {
  const serialized = JSON.stringify(value);
  assert.doesNotMatch(serialized, /PRIVATE-CHAMELEON|PRIVATE-SERIAL/u);
  assert.doesNotMatch(serialized, /hardware_identity|request_bytes|response_bytes/u);
}

function assertZeroed(value, label = "private byte buffer") {
  assert.ok(Buffer.from(value).every((byte) => byte === 0), `${label} must be zeroed`);
}

async function waitFor(predicate, timeoutMs = 1000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("fixture wait timed out");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function writeFixtureFile(root, relative, contents) {
  const target = path.join(root, ...relative.split("/"));
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
  fs.writeFileSync(target, contents);
  fs.chmodSync(target, 0o444);
  return target;
}

function dependencyFileRecord(root, relative) {
  const target = path.join(root, ...relative.split("/"));
  const contents = fs.readFileSync(target);
  const metadata = fs.statSync(target);
  return {
    path: relative,
    byte_size: contents.length,
    sha256: crypto.createHash("sha256").update(contents).digest("hex"),
    mode: metadata.mode & 0o777,
  };
}

function dependencySurfaceFixture(t, label) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `bob-serialport-${label}-`));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const rootManifest = {
    name: "@hacker-bob/instrument-chameleon-worker-dependency-fixture",
    version: "0.0.0-development",
    private: true,
    dependencies: { serialport: "13.0.0" },
  };
  const lock = {
    name: rootManifest.name,
    version: rootManifest.version,
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": {
        name: rootManifest.name,
        version: rootManifest.version,
        dependencies: { ...rootManifest.dependencies },
      },
      "node_modules/serialport": {
        version: "13.0.0",
        resolved: "https://registry.npmjs.org/serialport/-/serialport-13.0.0.tgz",
        integrity: "sha512-PHpnTd8isMGPfFTZNCzOZp9m4mAJSNWle9Jxu6BPTcWq7YXl5qN7tp8Sgn0h+WIGcD6JFz5QDgixC2s4VW7vzg==",
        dependencies: {},
      },
    },
  };
  writeFixtureFile(root, "package.json", `${JSON.stringify(rootManifest, null, 2)}\n`);
  writeFixtureFile(root, "package-lock.json", `${JSON.stringify(lock, null, 2)}\n`);
  writeFixtureFile(root, "node_modules/serialport/package.json", `${JSON.stringify({
    name: "serialport",
    version: "13.0.0",
    main: "./dist/index.js",
    dependencies: {},
  }, null, 2)}\n`);
  writeFixtureFile(root, "node_modules/serialport/dist/index.js",
    '"use strict"; module.exports = Object.freeze({ fixture: true });\n');
  const files = [
    "node_modules/serialport/dist/index.js",
    "node_modules/serialport/package.json",
  ].map((relative) => dependencyFileRecord(root, relative));
  return {
    root,
    files,
    input: {
      version: SERIALPORT_DEPENDENCY_SURFACE_VERSION,
      kind: "serialport_dependency_surface_fixture",
      test_only: true,
      root_abs: root,
      files,
    },
  };
}

test("package boundary is inert and preserves the closed provider-neutral runtime", () => {
  const child = spawnSync(process.execPath, ["-e", `
    const Module = require("node:module");
    const original = Module._load;
    Module._load = function(request, parent, isMain) {
      if (request === "serialport") throw new Error("serialport loaded during import");
      return original.call(this, request, parent, isMain);
    };
    const loaded = require(${JSON.stringify(path.join(PACKAGE_ROOT, "lib/serialport-usb-cdc-driver.js"))});
    process.stdout.write(JSON.stringify(Object.keys(loaded).sort()));
  `], { encoding: "utf8", cwd: PACKAGE_ROOT });
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), [
    "SERIALPORT_DEPENDENCY_SURFACE_VERSION",
    "SERIALPORT_USB_CDC_DRIVER_ASSURANCE",
    "SERIALPORT_USB_CDC_DRIVER_VERSION",
    "createFixtureSerialPortDependencyPort",
    "createSerialPortUsbCdcDriverPort",
    "qualifyFixtureSerialPortDependencySurface",
  ]);
  assert.deepEqual(SERIALPORT_USB_CDC_DRIVER_ASSURANCE, {
    version: 1,
    serialport_version: "13.0.0",
    production_ready: false,
    hil_proven: false,
    stock_serialport_atomic_dtr_off_open: false,
    atomic_open_blocker_code: "serialport_atomic_dtr_off_open_unproven",
    ambient_serialport_resolution: false,
    caller_loader_accepted: false,
    dependency_surface_authoritative: false,
    fixture_dependency_ports_only: true,
    execution_authority: false,
  });
  assert.equal(SERIALPORT_DEPENDENCY_SURFACE_VERSION, 1);
  assert.equal(SERIALPORT_USB_CDC_DRIVER_VERSION, 1);
  const workerPackage = JSON.parse(fs.readFileSync(path.join(PACKAGE_ROOT, "package.json")));
  const runtimePackage = JSON.parse(fs.readFileSync(path.join(RUNTIME_PACKAGE_ROOT, "package.json")));
  assert.equal(workerPackage.private, true);
  assert.deepEqual(workerPackage.files, ["lib/**/*.js", "README.md"]);
  assert.deepEqual(workerPackage.engines, { node: ">=20 <21" });
  assert.deepEqual(workerPackage.dependencies, {
    "@hacker-bob/instrument-chameleon-worker-runtime": "0.0.0-development",
  });
  assert.equal(Object.prototype.hasOwnProperty.call(workerPackage.dependencies, "serialport"), false);
  assert.equal(fs.existsSync(path.join(PACKAGE_ROOT, "package-lock.json")), false);
  assert.deepEqual(runtimePackage.dependencies, {});
  assert.equal(Object.prototype.hasOwnProperty.call(runtimePackage.dependencies, "serialport"), false);
});

test("dependency qualification is exact, closed, fixture-only, and non-authoritative", async (t) => {
  const fixture = dependencySurfaceFixture(t, "qualified");
  const qualification = qualifyFixtureSerialPortDependencySurface(fixture.input);
  assert.ok(Object.isFrozen(qualification));
  assert.deepEqual({
    version: qualification.version,
    serialport_version: qualification.serialport_version,
    file_count: qualification.file_count,
    fixture_only: qualification.fixture_only,
    caller_asserted_expected_files: qualification.caller_asserted_expected_files,
    module_loaded: qualification.module_loaded,
    authoritative: qualification.authoritative,
    production_ready: qualification.production_ready,
  }, {
    version: 1,
    serialport_version: "13.0.0",
    file_count: 2,
    fixture_only: true,
    caller_asserted_expected_files: true,
    module_loaded: false,
    authoritative: false,
    production_ready: false,
  });
  assert.equal(typeof qualification.surface_digest, "string");
  assert.equal(JSON.stringify(qualification).includes(fixture.root), false);

  const native = fakeNative();
  const dependencies = native.dependencies({ surfaceQualification: qualification });
  assert.ok(Object.isFrozen(dependencies.serialport_dependency_port));
  assert.equal(dependencies.serialport_dependency_port.surface_qualified, true);
  assert.equal(dependencies.serialport_dependency_port.authoritative, false);
  assert.equal(dependencies.serialport_dependency_port.production_ready, false);
  const { custody } = setup(native, { direct_dependencies: dependencies });
  assert.equal(native.stats.lists, 0, "construction must not reread or load the dependency");
  await custody.connect();
  assert.equal(native.stats.lists, 1);
  await custody.disconnect();
});

test("dependency surface rejects symlink, hardlink, extra, missing, mode, byte, and lock drift", async (t) => {
  const attacks = [
    {
      name: "symlink",
      mutate(fixture) {
        const target = path.join(fixture.root, "node_modules", "serialport", "dist", "index.js");
        const outside = path.join(fixture.root, "outside.js");
        fs.writeFileSync(outside, "outside\n");
        fs.unlinkSync(target);
        fs.symlinkSync(outside, target);
      },
    },
    {
      name: "hardlink",
      mutate(fixture) {
        fs.linkSync(
          path.join(fixture.root, "node_modules", "serialport", "dist", "index.js"),
          path.join(fixture.root, "outside-hardlink.js"),
        );
      },
    },
    {
      name: "extra",
      mutate(fixture) {
        writeFixtureFile(fixture.root, "node_modules/serialport/dist/extra.js", "extra\n");
      },
    },
    {
      name: "missing",
      mutate(fixture) {
        fs.unlinkSync(path.join(fixture.root, "node_modules", "serialport", "dist", "index.js"));
      },
    },
    {
      name: "mode",
      mutate(fixture) {
        fs.chmodSync(path.join(fixture.root, "node_modules", "serialport", "dist", "index.js"),
          0o555);
      },
    },
    {
      name: "bytes",
      mutate(fixture) {
        const target = path.join(fixture.root, "node_modules", "serialport", "dist", "index.js");
        fs.chmodSync(target, 0o644);
        fs.writeFileSync(target, "drifted dependency bytes\n");
        fs.chmodSync(target, 0o444);
      },
    },
    {
      name: "lock",
      mutate(fixture) {
        const target = path.join(fixture.root, "package-lock.json");
        const lock = JSON.parse(fs.readFileSync(target, "utf8"));
        lock.packages["node_modules/serialport"].version = "13.0.1";
        fs.chmodSync(target, 0o644);
        fs.writeFileSync(target, `${JSON.stringify(lock, null, 2)}\n`);
        fs.chmodSync(target, 0o444);
      },
    },
    {
      name: "package",
      mutate(fixture) {
        const target = path.join(fixture.root, "node_modules", "serialport", "package.json");
        const manifest = JSON.parse(fs.readFileSync(target, "utf8"));
        manifest.version = "13.0.1";
        fs.chmodSync(target, 0o644);
        fs.writeFileSync(target, `${JSON.stringify(manifest, null, 2)}\n`);
        fs.chmodSync(target, 0o444);
      },
    },
  ];
  for (const attack of attacks) {
    await t.test(attack.name, (st) => {
      const fixture = dependencySurfaceFixture(st, attack.name);
      attack.mutate(fixture);
      assert.throws(
        () => qualifyFixtureSerialPortDependencySurface(fixture.input),
        (error) => error.code === "serialport_dependency_surface_rejected",
      );
    });
  }
});

test("ancestor resolution and injected dependency lookalikes never become runtime authority", async () => {
  const native = fakeNative();
  let ambientLoads = 0;
  const originalLoad = Module._load;
  Module._load = function hostileAncestorLoad(request, parent, isMain) {
    if (request === "serialport" || request === "serialport/package.json") {
      ambientLoads += 1;
      return { SerialPort: native.FakeSerialPort, version: "13.0.0" };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    const { custody } = setup(native, {
      direct_dependencies: {
        platform: "fixture-platform",
        hardware_identity_resolver() { return Buffer.from(IDENTITY_A); },
      },
    });
    await assert.rejects(custody.connect(), /usb_cdc_discovery_failed/u);
  } finally {
    Module._load = originalLoad;
  }
  assert.equal(ambientLoads, 0);
  assert.equal(native.stats.lists, 0);
  assert.equal(native.stats.constructors, 0);

  const genuine = native.dependencies().serialport_dependency_port;
  for (const lookalike of [
    Object.freeze({ ...genuine }),
    new Proxy(genuine, {}),
  ]) {
    assert.throws(() => setup(native, {
      direct_dependencies: {
        serialport_dependency_port: lookalike,
        platform: "fixture-platform",
        hardware_identity_resolver() { return Buffer.from(IDENTITY_A); },
      },
    }), (error) => error.code === "serialport_dependency_surface_rejected");
  }
  for (const legacyDependency of [
    { serialport_loader: () => ({ SerialPort: native.FakeSerialPort }) },
    { serialport_constructor: native.FakeSerialPort },
    { serialport_binding: native.binding },
  ]) {
    assert.throws(() => setup(native, {
      direct_dependencies: {
        ...legacyDependency,
        platform: "fixture-platform",
        hardware_identity_resolver() { return Buffer.from(IDENTITY_A); },
      },
    }), /unknown fields/u);
  }
});

test("post-qualification dependency replacement fails before enumeration or open", async (t) => {
  const fixture = dependencySurfaceFixture(t, "post-qualification-replacement");
  const qualification = qualifyFixtureSerialPortDependencySurface(fixture.input);
  const native = fakeNative();
  const { custody } = setup(native, {
    direct_dependencies: native.dependencies({ surfaceQualification: qualification }),
  });
  const target = path.join(fixture.root, "node_modules", "serialport", "dist", "index.js");
  fs.chmodSync(target, 0o644);
  fs.writeFileSync(target, "replacement after qualification\n");
  fs.chmodSync(target, 0o444);
  await assert.rejects(custody.connect(), /usb_cdc_discovery_failed/u);
  assert.equal(native.stats.lists, 0);
  assert.equal(native.stats.constructors, 0);
  assert.equal(native.stats.atomic_opens, 0);
});

test("construction is inert and a fixture dependency port cannot bypass atomic-open refusal", async () => {
  const native = fakeNative();
  const { custody, driverPort } = setup(native, {
    direct_dependencies: {
      serialport_dependency_port: createFixtureSerialPortDependencyPort({
        version: SERIALPORT_DEPENDENCY_SURFACE_VERSION,
        kind: "serialport_dependency_fixture_port",
        test_only: true,
        serialport_constructor: native.FakeSerialPort,
        serialport_binding: native.binding,
        surface_qualification: null,
      }),
      platform: "fixture-platform",
      hardware_identity_resolver() { return Buffer.from(IDENTITY_A); },
    },
  });
  assert.equal(native.stats.lists, 0);
  assert.equal(native.stats.constructors, 0);
  assertSafe(driverPort);
  await assert.rejects(custody.connect(), (error) => {
    assert.equal(error.code, "usb_cdc_open_failed");
    assertSafe(error);
    return true;
  });
  assert.equal(native.stats.lists, 1);
  assert.equal(native.stats.constructors, 0);
  assert.equal(native.stats.opens, 0);
  assert.equal(native.stats.atomic_opens, 0);
  assert.equal(custody.snapshot().state, "open_uncertain");
  assertSafe(custody.snapshot());
});

test("atomic-open seam selects exact enrolled identity and fixes 115200 8N1 before activation", async () => {
  const response = makeFrame(HF14A_RAW_COMMAND_ID, 0x0068, Buffer.from([0x01, 0x02]));
  const native = fakeNative({
    ports: [
      portInfo({ pathValue: PRIVATE_PATH_B, serialNumber: "PRIVATE-SERIAL-B" }),
      portInfo(),
      { path: "/dev/non-usb-tty", manufacturer: "ignored" },
    ],
    responseChunks: [response.subarray(0, 3), response.subarray(3, 9), response.subarray(9)],
  });
  const { custody } = setup(native);
  const connected = await custody.connect();
  assert.equal(connected.state, "connected");
  assert.equal(native.stats.lists, 1);
  assert.equal(native.stats.atomic_opens, 1);
  assert.equal(native.stats.constructors, 1);
  assert.equal(native.stats.opens, 1);
  assert.equal(native.stats.opened_identities.length, 1);
  assertZeroed(native.stats.opened_identities[0], "transferred native-open identity");
  const serialOptions = native.stats.constructor_options[0];
  assert.equal(serialOptions.path, PRIVATE_PATH_A);
  assert.deepEqual({
    baudRate: serialOptions.baudRate,
    dataBits: serialOptions.dataBits,
    stopBits: serialOptions.stopBits,
    parity: serialOptions.parity,
    rtscts: serialOptions.rtscts,
    xon: serialOptions.xon,
    xoff: serialOptions.xoff,
    xany: serialOptions.xany,
    lock: serialOptions.lock,
    autoOpen: serialOptions.autoOpen,
    highWaterMark: serialOptions.highWaterMark,
  }, {
    baudRate: 115200,
    dataBits: 8,
    stopBits: 1,
    parity: "none",
    rtscts: false,
    xon: false,
    xoff: false,
    xany: false,
    lock: true,
    autoOpen: false,
    highWaterMark: USB_CDC_CUSTODY_LIMITS.read_buffer_bytes,
  });
  assert.deepEqual(native.stats.sets, [{ dtr: true, rts: false }]);
  assertSafe(connected);

  const command = compiledWorkerCommand();
  const expectedRequest = expectedRequaRequestFrame();
  const transactionPort = createWorkerUsbCdcTransactionPort(custody);
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  const result = await executeWorkerUsbCdcTransaction(transactionPort, handoff, command);
  assert.equal(native.stats.writes.length, 1);
  assert.deepEqual(native.stats.writes[0], expectedRequest);
  assert.equal(native.stats.drains, 1);
  assert.deepEqual(result.response_bytes, response);
  assert.equal(native.stats.emitted_chunks.length, 3);
  for (const chunk of native.stats.emitted_chunks) {
    assertZeroed(chunk, "native response chunk");
  }
  assert.equal(native.stats.instances[0].listenerCount("data"), 0);
  assert.equal(native.stats.instances[0].listenerCount("error"), 1);
  assert.equal(native.stats.instances[0].listenerCount("close"), 1);
  assert.deepEqual(Object.keys(result), [
    "version",
    "kind",
    "transaction_id",
    "custody_id",
    "enrollment_id",
    "connection_generation",
    "compiled_command_id",
    "provider_id",
    "compiler_id",
    "compiler_manifest_digest",
    "compiler_registry_digest",
    "source_profile_digest",
    "operation_id",
    "capability_id",
    "variant_id",
    "parameter_selector_id",
    "canonical_command_digest",
    "compiled_operation_digest",
    "compiled_command_capability_digest",
    "request_digest",
    "response_digest",
    "toJSON",
  ]);
  for (const field of [
    "compiled_command_id",
    "provider_id",
    "compiler_id",
    "compiler_manifest_digest",
    "compiler_registry_digest",
    "source_profile_digest",
    "operation_id",
    "capability_id",
    "variant_id",
    "parameter_selector_id",
    "canonical_command_digest",
    "compiled_operation_digest",
    "compiled_command_capability_digest",
  ]) {
    assert.equal(result[field], command[field]);
  }
  assert.throws(() => JSON.stringify(result), /transaction_result_not_serializable/u);
  assert.doesNotMatch(Object.keys(result).join(","), /request_bytes|response_bytes/u);

  const disconnected = await custody.disconnect();
  assert.equal(disconnected.state, "disconnected");
  assert.equal(native.stats.closes, 1);
  assert.deepEqual(native.stats.sets, [
    { dtr: true, rts: false },
    { dtr: false, rts: false },
  ]);
  expectedRequest.fill(0);
  response.fill(0);
});

test("native atomic open must transfer the independently opened identity and closes a path swap", async () => {
  const native = fakeNative({ openedIdentity: IDENTITY_B });
  const { custody } = setup(native);
  await assert.rejects(custody.connect(), (error) => {
    assert.equal(error.code, "usb_cdc_open_failed");
    assertSafe(error);
    return true;
  });
  assert.equal(native.stats.atomic_opens, 1);
  assert.equal(native.stats.opens, 1);
  assert.equal(native.stats.closes, 1);
  assert.equal(native.stats.sets.some((entry) => entry.dtr === true), false);
  assert.equal(native.stats.opened_identities.length, 1);
  assertZeroed(native.stats.opened_identities[0], "mismatched native-open identity");
});

test("forged atomic DTR-off attestation is rejected and the possible port is closed", async () => {
  const native = fakeNative();
  const { custody } = setup(native, {
    attestationMutator(attestation) { attestation.dtr_never_asserted = false; },
  });
  await assert.rejects(custody.connect(), (error) => {
    assert.equal(error.code, "usb_cdc_open_failed");
    assertSafe(error);
    return true;
  });
  assert.equal(native.stats.atomic_opens, 1);
  assert.equal(native.stats.opens, 1);
  assert.equal(native.stats.closes, 1);
  assert.deepEqual(native.stats.sets, [{ dtr: false, rts: false }]);
});

test("late atomic open after custody timeout is closed and never becomes a handle", async () => {
  const native = fakeNative({ lateOpenReturnMs: USB_CDC_CUSTODY_LIMITS.open_timeout_ms + 50 });
  const { custody } = setup(native);
  await assert.rejects(custody.connect(), (error) => {
    assert.equal(error.code, "usb_cdc_open_timeout");
    assertSafe(error);
    return true;
  });
  assert.equal(custody.snapshot().state, "open_uncertain");
  await waitFor(() => native.stats.closes === 1, 1000);
  assert.equal(native.stats.opens, 1);
  assert.equal(native.stats.closes, 1);
  assert.equal(custody.snapshot().active_handle, true);
});

test("trailing second frame is protocol ambiguity, quarantines once, and is never retried", async () => {
  const response = makeFrame(HF14A_RAW_COMMAND_ID);
  const native = fakeNative({ responseChunks: [Buffer.concat([response, response])] });
  const { custody } = setup(native);
  await custody.connect();
  const transactionPort = createWorkerUsbCdcTransactionPort(custody);
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  await assert.rejects(
    executeWorkerUsbCdcTransaction(transactionPort, handoff, compiledWorkerCommand()),
    (error) => {
      assert.equal(error.code, "usb_cdc_transaction_failed_ambiguous");
      assertSafe(error);
      return true;
    },
  );
  assert.equal(native.stats.writes.length, 1);
  assert.equal(native.stats.closes, 1);
  assert.equal(custody.snapshot().state, "disconnected");
  await custody.reconnect();
  assert.equal(native.stats.writes.length, 1);
  response.fill(0);
});

test("a trailing frame split into a later data event cannot pass the exact-response boundary", async () => {
  const response = makeFrame(HF14A_RAW_COMMAND_ID);
  const native = fakeNative({ responseChunks: [response, response] });
  const { custody } = setup(native);
  await custody.connect();
  const transactionPort = createWorkerUsbCdcTransactionPort(custody);
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  await assert.rejects(
    executeWorkerUsbCdcTransaction(transactionPort, handoff, compiledWorkerCommand()),
    (error) => {
      assert.equal(error.code, "usb_cdc_transaction_failed_ambiguous");
      assertSafe(error);
      return true;
    },
  );
  assert.equal(native.stats.writes.length, 1);
  assert.equal(native.stats.emitted_chunks.length, 2);
  for (const chunk of native.stats.emitted_chunks) assertZeroed(chunk);
  assert.equal(native.stats.closes, 1);
  assert.equal(custody.snapshot().state, "disconnected");
  response.fill(0);
});

test("a valid frame for another command is ambiguous and never correlated to the request", async () => {
  const wrongResponse = makeFrame(HF14A_RAW_COMMAND_ID + 1);
  const native = fakeNative({ responseChunks: [wrongResponse] });
  const { custody } = setup(native);
  await custody.connect();
  const transactionPort = createWorkerUsbCdcTransactionPort(custody);
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  await assert.rejects(
    executeWorkerUsbCdcTransaction(transactionPort, handoff, compiledWorkerCommand()),
    (error) => {
      assert.equal(error.code, "usb_cdc_transaction_failed_ambiguous");
      assertSafe(error);
      return true;
    },
  );
  assert.equal(native.stats.writes.length, 1);
  assert.equal(native.stats.closes, 1);
  assertZeroed(native.stats.emitted_chunks[0]);
  wrongResponse.fill(0);
});

test("raw request objects are refused before the single native write seam", async () => {
  const invalidRequest = makeFrame(HF14A_RAW_COMMAND_ID, 0x0068);
  const native = fakeNative();
  const { custody } = setup(native);
  await custody.connect();
  const transactionPort = createWorkerUsbCdcTransactionPort(custody);
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  assert.throws(
    () => executeWorkerUsbCdcTransaction(transactionPort, handoff, {
      version: 1,
      request_bytes: invalidRequest,
      maximum_response_bytes: FIXED_FRAME_BYTES,
      timeout_ms: 100,
    }),
    /compiled_provider_command_untrusted/u,
  );
  assert.equal(native.stats.writes.length, 0);
  assert.equal(native.stats.closes, 0);
  assert.equal(custody.snapshot().state, "connected");
  await custody.disconnect();
  assert.equal(native.stats.closes, 1);
  invalidRequest.fill(0);
});

test("transaction timeout aborts into custody ambiguity, quarantines, and never resends", async () => {
  const native = fakeNative({ noResponse: true });
  const { custody } = setup(native);
  await custody.connect();
  const transactionPort = createWorkerUsbCdcTransactionPort(custody);
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  await assert.rejects(
    executeWorkerUsbCdcTransaction(transactionPort, handoff, compiledWorkerCommand()),
    (error) => {
      assert.equal(error.code, "usb_cdc_transaction_timeout_ambiguous");
      assertSafe(error);
      return true;
    },
  );
  await waitFor(() => native.stats.closes === 1);
  assert.equal(native.stats.writes.length, 1);
  assert.equal(native.stats.closes, 1);
  assert.equal(custody.snapshot().state, "disconnected");
});

test("timeout does not erase a request retained by native write until close settles", async () => {
  const expectedRequest = expectedRequaRequestFrame();
  const native = fakeNative({ noResponse: true, writeCallbackDelayMs: 150 });
  const { custody } = setup(native);
  await custody.connect();
  const transactionPort = createWorkerUsbCdcTransactionPort(custody);
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  await assert.rejects(
    executeWorkerUsbCdcTransaction(transactionPort, handoff, compiledWorkerCommand()),
    /usb_cdc_transaction_timeout_ambiguous/u,
  );
  assert.equal(native.stats.closes, 1);
  assert.deepEqual(native.stats.write_argument_at_close, expectedRequest);
  assertZeroed(native.stats.write_argument, "native-retained request after close settlement");
  await new Promise((resolve) => setTimeout(resolve, 160));
  assert.equal(native.stats.closes, 1);
  native.stats.write_argument_at_close.fill(0);
  expectedRequest.fill(0);
});

test("listener installation failure cannot strand transaction custody or private bytes", async () => {
  const native = fakeNative({ throwOnListenerEvent: "data" });
  const { custody } = setup(native);
  await custody.connect();
  const transactionPort = createWorkerUsbCdcTransactionPort(custody);
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  await assert.rejects(
    executeWorkerUsbCdcTransaction(transactionPort, handoff, compiledWorkerCommand()),
    /usb_cdc_transaction_failed_ambiguous/u,
  );
  assert.equal(native.stats.writes.length, 0);
  assert.equal(native.stats.closes, 1);
  assert.equal(custody.snapshot().state, "disconnected");
});

test("native callback success followed by throw is ambiguous, never a false transaction success", async () => {
  const native = fakeNative({ writeCallbackThenThrow: true, synchronousResponse: true });
  const { custody } = setup(native);
  await custody.connect();
  const transactionPort = createWorkerUsbCdcTransactionPort(custody);
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  await assert.rejects(
    executeWorkerUsbCdcTransaction(transactionPort, handoff, compiledWorkerCommand()),
    /usb_cdc_transaction_failed_ambiguous/u,
  );
  assert.equal(native.stats.writes.length, 1);
  assert.equal(native.stats.closes, 1);
  assert.equal(custody.snapshot().state, "disconnected");
});

test("native activation callback success followed by throw is rejected and quarantined", async () => {
  const native = fakeNative({ setCallbackThenThrow: true });
  const { custody } = setup(native);
  await assert.rejects(custody.connect(), /usb_cdc_activation_failed/u);
  assert.equal(native.stats.opens, 1);
  assert.equal(native.stats.closes, 1);
  assert.equal(custody.snapshot().state, "disconnected");
});

test("close callback cannot attest closure while the native port still reports open", async () => {
  const native = fakeNative({ closeStaysOpen: true });
  const { custody } = setup(native);
  await custody.connect();
  await assert.rejects(custody.disconnect(), (error) => {
    assert.equal(error.code, "usb_cdc_close_failed");
    assertSafe(error);
    return true;
  });
  assert.equal(native.stats.closes, 1);
  assert.equal(custody.snapshot().state, "close_uncertain");
});

test("arbitrary oversized raw frames cannot cross compiled-command custody", async () => {
  const oversized = makeFrame(HF14A_RAW_COMMAND_ID, 0, Buffer.alloc(5000, 0x61));
  const native = fakeNative();
  const { custody } = setup(native);
  await custody.connect();
  const transactionPort = createWorkerUsbCdcTransactionPort(custody);
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  assert.throws(
    () => executeWorkerUsbCdcTransaction(transactionPort, handoff, {
      version: 1,
      request_bytes: oversized,
      maximum_response_bytes: FIXED_FRAME_BYTES,
      timeout_ms: 100,
    }),
    /compiled_provider_command_untrusted/u,
  );
  assert.equal(native.stats.writes.length, 0);
  assert.equal(native.stats.closes, 0);
  assert.equal(custody.snapshot().state, "connected");
  await custody.disconnect();
  assert.equal(native.stats.closes, 1);
  oversized.fill(0);
});

test("native discovery errors collapse to secret-free custody errors", async () => {
  const native = fakeNative({ listError: true });
  const { custody } = setup(native);
  await assert.rejects(custody.connect(), (error) => {
    assert.equal(error.code, "usb_cdc_discovery_failed");
    assert.equal(error.message, "usb_cdc_discovery_failed");
    assertSafe(error);
    return true;
  });
  assert.equal(native.stats.constructors, 0);
  assert.equal(native.stats.opens, 0);
});
