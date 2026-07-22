"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const custodyModule = require("../lib/usb-cdc-custody.js");
const {
  compileHf14aProbe,
  encodeCompiledHf14aProbeForProviderWorker,
} = require("../lib/hf14a-probe-compiler.js");
const {
  USB_CDC_CUSTODY_LIMITS,
  USB_CDC_CUSTODY_VERSION,
  USB_CDC_HARDWARE_IDENTITY_DOMAIN,
  USB_CDC_LINE_CONFIGURATION,
  USB_CDC_STATE_VALUES,
  USB_CDC_WORKER_AUTHORITY_DOMAIN,
  USB_CDC_WORKER_AUTHORITY_SIGNING_DOMAIN,
  assertOperatorUsbCdcEnrollment,
  assertUsbCdcDriverPort,
  assertUsbCdcOpenAuthorityPort,
  assertUsbCdcWorkerAuthorityPort,
  assertWorkerUsbCdcConnectionGenerationHandoff,
  assertWorkerUsbCdcCustody,
  assertWorkerUsbCdcTransactionPort,
  assertWorkerUsbCdcTransactionResult,
  createUsbCdcDriverPort,
  createUsbCdcOpenAuthorityPort,
  createUsbCdcWorkerAuthorityPort,
  createWorkerUsbCdcConnectionGenerationHandoff,
  createWorkerUsbCdcCustody,
  createWorkerUsbCdcTransactionPort,
  enrollOperatorUsbCdcDevice,
  executeWorkerUsbCdcTransaction,
} = custodyModule;

const IDENTITY_A = Buffer.alloc(32, 0x41);
const IDENTITY_B = Buffer.alloc(32, 0x42);
const FILTERS = Object.freeze({
  vendor_id: 0x6868,
  product_id: 0x8686,
  model: "rf-lab-device",
});
const GUARANTEES = Object.freeze({
  ...USB_CDC_LINE_CONFIGURATION,
  read_buffer_bytes: USB_CDC_CUSTODY_LIMITS.read_buffer_bytes,
  write_buffer_bytes: USB_CDC_CUSTODY_LIMITS.write_buffer_bytes,
  io_timeout_ms: USB_CDC_CUSTODY_LIMITS.io_timeout_ms,
});
const PRE_ACTIVATION_GUARANTEES = Object.freeze({
  ...GUARANTEES,
  dtr_asserted: false,
  brokered_exact_transaction_write_enabled: false,
});
const WORKER_UID = process.getuid();

function digest(label) {
  return crypto.createHash("sha256").update(label, "utf8").digest("hex");
}

function compiledCommand(schemaId = "iso14443a.requa_atqa_v1") {
  return encodeCompiledHf14aProbeForProviderWorker(compileHf14aProbe({
    version: 1,
    schema_id: schemaId,
  }));
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
  driver_id: "fake_usb_cdc_driver",
  driver_implementation_digest: digest("fake-usb-cdc-driver-implementation"),
  driver_binary_digest: digest("fake-usb-cdc-driver-binary"),
  execution_principal_id: "principal:chameleon-worker",
  worker_uid: WORKER_UID,
  provider_descriptor_digest: digest("chameleon-provider-descriptor"),
  transport_digest: digest("chameleon-usb-cdc-transport"),
});

function signWorkerAuthority(payload, privateKey, { tamperSignature = false } = {}) {
  const payloadDigest = digestCanonical(payload);
  let signature = crypto.sign(
    null,
    Buffer.from(`${USB_CDC_WORKER_AUTHORITY_SIGNING_DOMAIN}\0${payloadDigest}`, "utf8"),
    privateKey,
  ).toString("base64url");
  if (tamperSignature) {
    signature = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  }
  const basis = {
    version: 1,
    domain: USB_CDC_WORKER_AUTHORITY_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  return {
    ...basis,
    signed_authority_digest: digestCanonical(basis),
  };
}

function workerAuthorityFixture({
  enrollmentId = "operator_device_01",
  identity = IDENTITY_A,
  binding = DRIVER_BINDING,
} = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const calls = [];
  const current = {
    version: 1,
    authority_id: "hotel_lab_usb_worker_authority",
    trust_root_id: "hotel_lab_usb_worker_root",
    trust_root_epoch: 1,
    authority_epoch: 1,
    revocation_generation: 0,
    signer_key_id: "hotel_lab_usb_worker_key",
    signer_public_key_digest: crypto.createHash("sha256")
      .update(publicKey.export({ type: "spki", format: "der" }))
      .digest("hex"),
    trusted: true,
    revoked: false,
    custody_allowed: true,
    enrollment_id: enrollmentId,
    hardware_identity_digest: identityDigest(identity),
    ...binding,
    behavior: "normal",
  };
  const signedPayload = () => {
    const { behavior, ...payload } = current;
    if (behavior === "throw") throw new Error("worker authority leaked PRIVATE-SERIAL-001");
    if (behavior === "async") return Promise.resolve({});
    if (behavior === "malformed") return { raw_identity: Buffer.from(identity) };
    return signWorkerAuthority(payload, privateKey, {
      tamperSignature: behavior === "bad_signature",
    });
  };
  const port = createUsbCdcWorkerAuthorityPort({
    version: 1,
    authority_id: current.authority_id,
    trust_root_id: current.trust_root_id,
    signer_key_id: current.signer_key_id,
    signer_public_key: publicKey,
    minimum_trust_root_epoch: 1,
    minimum_authority_epoch: 1,
    minimum_revocation_generation: 0,
    resolve_current_worker_authority(query) {
      calls.push(query);
      return signedPayload();
    },
  });
  return { calls, current, port, privateKey, publicKey, signedPayload };
}

function candidate({
  identity = IDENTITY_A,
  vendorId = FILTERS.vendor_id,
  productId = FILTERS.product_id,
  model = FILTERS.model,
  rawPath = "/dev/private-cdc-path",
  rawSerial = "PRIVATE-SERIAL-001",
} = {}) {
  return {
    vendor_id: vendorId,
    product_id: productId,
    model,
    path: rawPath,
    serial_number: rawSerial,
    hardware_identity: Buffer.from(identity),
  };
}

function authorityFixture() {
  const calls = [];
  const current = {
    version: USB_CDC_CUSTODY_VERSION,
    authority_id: "hotel_lab_usb_authority",
    authority_epoch: 1,
    enrollment_id: "operator_device_01",
    alias: "front_desk_research_unit",
    trusted: true,
    revoked: false,
    open_allowed: true,
    candidate_filters: { ...FILTERS },
    hardware_identity: Buffer.from(IDENTITY_A),
    hardware_identity_provenance: "operator_enrolled_high_entropy",
    behavior: "normal",
  };
  const worker = workerAuthorityFixture({
    enrollmentId: current.enrollment_id,
    identity: current.hardware_identity,
  });
  const port = createUsbCdcOpenAuthorityPort({
    version: USB_CDC_CUSTODY_VERSION,
    authority_id: current.authority_id,
    worker_authority_port: worker.port,
    resolve_current_enrollment(query) {
      calls.push(query);
      if (typeof current.onResolve === "function") current.onResolve(query);
      if (current.behavior === "throw") {
        throw new Error("authority backend leaked PRIVATE-SERIAL-001");
      }
      if (current.behavior === "async") return Promise.resolve({});
      if (current.behavior === "malformed") return { raw_path: "/dev/private-cdc-path" };
      return {
        version: current.version,
        authority_id: current.authority_id,
        authority_epoch: current.authority_epoch,
        enrollment_id: current.enrollment_id,
        alias: current.alias,
        trusted: current.trusted,
        revoked: current.revoked,
        open_allowed: current.open_allowed,
        candidate_filters: { ...current.candidate_filters },
        hardware_identity: Buffer.from(current.hardware_identity),
        hardware_identity_provenance: current.hardware_identity_provenance,
      };
    },
  });
  const enrollment = enrollOperatorUsbCdcDevice({
    version: USB_CDC_CUSTODY_VERSION,
    enrollment_id: current.enrollment_id,
    alias: current.alias,
    authority_id: current.authority_id,
  }, port);
  return { calls, current, enrollment, port, worker };
}

function driverFixture(options = {}) {
  const stats = {
    enumerations: 0,
    opens: 0,
    activations: 0,
    closes: 0,
    transactions: 0,
    enumeration_queries: [],
    open_queries: [],
    activation_queries: [],
    close_queries: [],
    transaction_queries: [],
  };
  const handles = [];
  const binding = {
    ...DRIVER_BINDING,
    ...(options.binding || {}),
    driver_id: options.driverId || options.binding?.driver_id || DRIVER_BINDING.driver_id,
  };
  const callbacks = {
    async enumerate_candidates(query) {
      stats.enumerations += 1;
      stats.enumeration_queries.push(query);
      if (options.enumerate) return options.enumerate(query, stats);
      return (options.candidates || [candidate()]).map((entry) => ({
        ...entry,
        hardware_identity: Buffer.from(entry.hardware_identity),
      }));
    },
    async open_candidate(query) {
      stats.opens += 1;
      stats.open_queries.push(query);
      if (options.open) return options.open(query, stats);
      const handle = Object.freeze({ fake_handle_id: `handle-${stats.opens}` });
      handles.push(handle);
      return {
        handle,
        opened_hardware_identity: Buffer.from(query.candidate.hardware_identity),
        transport_guarantees: { ...PRE_ACTIVATION_GUARANTEES },
      };
    },
    async activate_handle(query) {
      stats.activations += 1;
      stats.activation_queries.push(query);
      if (options.activate) return options.activate(query, stats);
      return {
        activated: true,
        opened_hardware_identity: Buffer.from(IDENTITY_A),
        transport_guarantees: { ...GUARANTEES },
      };
    },
    async close_handle(query) {
      stats.closes += 1;
      stats.close_queries.push(query);
      if (options.close) return options.close(query, stats);
      return { closed: true };
    },
  };
  if (options.withTransaction || typeof options.transaction === "function") {
    callbacks.transact_handle = async function transactHandle(query) {
      stats.transactions += 1;
      stats.transaction_queries.push(query);
      if (typeof options.transaction === "function") {
        return options.transaction(query, stats);
      }
      return { response_bytes: Buffer.from([0x10, 0x20, 0x30]) };
    };
  }
  const fixture = {
    handles,
    port: null,
    stats,
    binding,
    bind(authority, custodyId = binding.custody_id) {
      if (fixture.port != null) return fixture.port;
      binding.custody_id = custodyId;
      Object.assign(authority.worker.current, binding);
      fixture.port = createUsbCdcDriverPort({
        version: USB_CDC_CUSTODY_VERSION,
        ...binding,
        ...callbacks,
      }, authority.enrollment, authority.worker.port);
      return fixture.port;
    },
  };
  return fixture;
}

function setup(options = {}) {
  const authority = options.authority || authorityFixture();
  const driver = options.driver || driverFixture(options.driverOptions);
  const custodyId = options.custodyId || "worker_cdc_custody_01";
  driver.bind(authority, custodyId);
  const custody = createWorkerUsbCdcCustody({
    version: USB_CDC_CUSTODY_VERSION,
    custody_id: custodyId,
    enrollment: authority.enrollment,
    driver_port: driver.port,
    open_authority_port: authority.port,
    worker_authority_port: authority.worker.port,
  });
  return { authority, custody, driver };
}

function assertSafeError(error, code) {
  assert.equal(error.code, code);
  assert.equal(error.message, code);
  assert.doesNotMatch(error.stack, /PRIVATE-SERIAL|private-cdc-path/u);
  assert.doesNotMatch(JSON.stringify(error), /PRIVATE-SERIAL|private-cdc-path/u);
  return true;
}

function assertNoRawTransportData(value) {
  const json = JSON.stringify(value);
  assert.doesNotMatch(json, /PRIVATE-SERIAL|private-cdc-path/u);
  assert.doesNotMatch(json, /hardware_identity|serial_number|path/u);
}

function spoofedDriverTimeout(code) {
  const error = new Error("failed /dev/private-cdc-path PRIVATE-SERIAL-001");
  error.code = code;
  return error;
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

function inertDriverInput(binding = DRIVER_BINDING) {
  return {
    version: 1,
    ...binding,
    enumerate_candidates() { throw new Error("must not enumerate"); },
    open_candidate() { throw new Error("must not open"); },
    activate_handle() { throw new Error("must not activate"); },
    close_handle() { throw new Error("must not close"); },
  };
}

test("module load is inert, native-driver-free, and exports no generic raw transport API", () => {
  assert.deepEqual(Object.keys(custodyModule).sort(), [
    "USB_CDC_CUSTODY_LIMITS",
    "USB_CDC_CUSTODY_VERSION",
    "USB_CDC_HARDWARE_IDENTITY_DOMAIN",
    "USB_CDC_LINE_CONFIGURATION",
    "USB_CDC_STATE_VALUES",
    "USB_CDC_WORKER_AUTHORITY_DOMAIN",
    "USB_CDC_WORKER_AUTHORITY_SIGNING_DOMAIN",
    "assertOperatorUsbCdcEnrollment",
    "assertUsbCdcDriverPort",
    "assertUsbCdcOpenAuthorityPort",
    "assertUsbCdcWorkerAuthorityPort",
    "assertWorkerUsbCdcConnectionGenerationHandoff",
    "assertWorkerUsbCdcCustody",
    "assertWorkerUsbCdcTransactionPort",
    "assertWorkerUsbCdcTransactionResult",
    "createUsbCdcDriverPort",
    "createUsbCdcOpenAuthorityPort",
    "createUsbCdcWorkerAuthorityPort",
    "createWorkerUsbCdcConnectionGenerationHandoff",
    "createWorkerUsbCdcCustody",
    "createWorkerUsbCdcTransactionPort",
    "enrollOperatorUsbCdcDevice",
    "executeWorkerUsbCdcTransaction",
  ].sort());
  for (const forbidden of [
    "read", "write", "transact", "sendRaw", "evaluate", "enumerate", "open", "serialport",
  ]) {
    assert.equal(Object.prototype.hasOwnProperty.call(custodyModule, forbidden), false);
  }
  assert.deepEqual(USB_CDC_STATE_VALUES, [
    "disconnected",
    "connecting",
    "connected",
    "disconnecting",
    "open_uncertain",
    "close_uncertain",
    "closed",
  ]);
  assert.equal(Object.isFrozen(USB_CDC_CUSTODY_LIMITS), true);
  assert.equal(Object.isFrozen(USB_CDC_LINE_CONFIGURATION), true);
  assert.equal(USB_CDC_CUSTODY_LIMITS.min_hardware_identity_bytes, 32);

  const runtimeRoot = path.join(__dirname, "../../bob-instrument-chameleon-worker-runtime");
  const source = fs.readFileSync(path.join(runtimeRoot, "lib/usb-cdc-custody.js"), "utf8");
  const packageDocument = JSON.parse(fs.readFileSync(path.join(runtimeRoot, "package.json"), "utf8"));
  assert.doesNotMatch(source, /require\(["']serialport["']\)|import\s+.*serialport/u);
  assert.match(source, /USB_CDC_HARDWARE_IDENTITY_DOMAIN/u);
  assert.doesNotMatch(
    source,
    /\.update\s*\(\s*(?:candidate\.)?(?:path|serial_number)/u,
    "identity digest must never derive from a path or serial number",
  );
  assert.match(source, /ambiguous_write\/reconcile-required/u);
  assert.equal(packageDocument.dependencies?.serialport, undefined);
  assert.equal(packageDocument.optionalDependencies?.serialport, undefined);
  assert.throws(() => createUsbCdcDriverPort({
    version: 1,
    driver_id: "raw_escape_driver",
    enumerate_candidates() { return []; },
    open_candidate() { return null; },
    activate_handle() { return null; },
    close_handle() { return { closed: true }; },
    write_bytes() { throw new Error("must never be enrolled"); },
  }), /unknown fields: write_bytes/u);
});

test("driver, authorities, enrollment, and custody objects are private branded safe projections", () => {
  const { authority, custody, driver } = setup();
  assert.equal(assertUsbCdcDriverPort(driver.port), driver.port);
  assert.equal(assertUsbCdcOpenAuthorityPort(authority.port), authority.port);
  assert.equal(assertUsbCdcWorkerAuthorityPort(authority.worker.port), authority.worker.port);
  assert.equal(assertOperatorUsbCdcEnrollment(authority.enrollment), authority.enrollment);
  assert.equal(assertWorkerUsbCdcCustody(custody), custody);
  for (const [assertion, clone] of [
    [assertUsbCdcDriverPort, { ...driver.port }],
    [assertUsbCdcOpenAuthorityPort, { ...authority.port }],
    [assertUsbCdcWorkerAuthorityPort, { ...authority.worker.port }],
    [assertOperatorUsbCdcEnrollment, { ...authority.enrollment }],
    [assertWorkerUsbCdcCustody, { ...custody }],
  ]) {
    assert.throws(() => assertion(clone), /private branded/u);
  }
  for (const projection of [
    driver.port,
    authority.port,
    authority.worker.port,
    authority.enrollment,
    custody,
    custody.snapshot(),
  ]) {
    assert.equal(Object.isFrozen(projection), true);
    assertNoRawTransportData(projection);
  }
  assert.deepEqual(custody.snapshot(), {
    version: 1,
    custody_id: "worker_cdc_custody_01",
    enrollment_id: "operator_device_01",
    alias: "front_desk_research_unit",
    state: "disconnected",
    connection_generation: 0,
    active_handle: false,
    transition_code: "custody_created",
  });
});

test("VID, PID, and model only filter candidates; exact private identity selects the enrollment", async () => {
  const driver = driverFixture({
    candidates: [
      candidate({ identity: IDENTITY_B, rawSerial: "PRIVATE-SERIAL-WRONG" }),
      candidate({ identity: IDENTITY_A, rawPath: "/dev/private-cdc-path-exact" }),
      candidate({ identity: IDENTITY_A, vendorId: 0x1111 }),
    ],
  });
  const { custody } = setup({ driver });
  const connected = await custody.connect();
  assert.equal(connected.state, "connected");
  assert.equal(driver.stats.opens, 1);
  assert.equal(driver.stats.open_queries[0].candidate.path, "/dev/private-cdc-path-exact");
  assertNoRawTransportData(connected);
});

test("zero exact matches refuse without opening, even when serial and candidate filters match", async () => {
  const driver = driverFixture({
    candidates: [candidate({ identity: IDENTITY_B, rawSerial: "PRIVATE-SERIAL-001" })],
  });
  const { custody } = setup({ driver });
  await assert.rejects(
    custody.connect(),
    (error) => assertSafeError(error, "usb_cdc_candidate_not_found"),
  );
  assert.equal(driver.stats.opens, 0);
  assert.equal(custody.snapshot().state, "disconnected");
});

test("duplicate exact matches are ambiguous and never opened", async () => {
  const driver = driverFixture({
    candidates: [
      candidate({ rawPath: "/dev/private-cdc-path-a" }),
      candidate({ rawPath: "/dev/private-cdc-path-b", rawSerial: "PRIVATE-SERIAL-002" }),
    ],
  });
  const { custody } = setup({ driver });
  await assert.rejects(
    custody.connect(),
    (error) => assertSafeError(error, "usb_cdc_candidate_ambiguous"),
  );
  assert.equal(driver.stats.opens, 0);
});

test("successful lifecycle fixes line settings, asserts DTR and locks, and retains one handle", async () => {
  const { authority, custody, driver } = setup();
  const connected = await custody.connect();
  assert.equal(connected.state, "connected");
  assert.equal(connected.connection_generation, 1);
  assert.equal(connected.active_handle, true);
  assert.equal(driver.stats.opens, 1);
  assert.equal(driver.stats.activations, 1);
  assert.deepEqual(driver.stats.open_queries[0].options, {
    baud_rate: 115200,
    data_bits: 8,
    stop_bits: 1,
    parity: "none",
    dtr_asserted: false,
    exclusive_open: true,
    serial_lock: true,
    rts_cts: false,
    xon_xoff: false,
    generic_write_surface_exposed: false,
    brokered_exact_transaction_write_enabled: false,
    read_buffer_bytes: USB_CDC_CUSTODY_LIMITS.read_buffer_bytes,
    write_buffer_bytes: USB_CDC_CUSTODY_LIMITS.write_buffer_bytes,
    io_timeout_ms: USB_CDC_CUSTODY_LIMITS.io_timeout_ms,
    open_timeout_ms: USB_CDC_CUSTODY_LIMITS.open_timeout_ms,
  });
  assert.deepEqual(driver.stats.activation_queries[0].options, {
    baud_rate: 115200,
    data_bits: 8,
    stop_bits: 1,
    parity: "none",
    dtr_asserted: true,
    exclusive_open: true,
    serial_lock: true,
    rts_cts: false,
    xon_xoff: false,
    generic_write_surface_exposed: false,
    brokered_exact_transaction_write_enabled: true,
    read_buffer_bytes: USB_CDC_CUSTODY_LIMITS.read_buffer_bytes,
    write_buffer_bytes: USB_CDC_CUSTODY_LIMITS.write_buffer_bytes,
    io_timeout_ms: USB_CDC_CUSTODY_LIMITS.io_timeout_ms,
    activation_timeout_ms: USB_CDC_CUSTODY_LIMITS.open_timeout_ms,
  });
  assert.equal(Object.isFrozen(driver.stats.open_queries[0].options), true);
  assert.equal(Object.isFrozen(driver.stats.activation_queries[0].options), true);
  assert.deepEqual(await custody.connect(), connected);
  assert.equal(driver.stats.opens, 1, "an idempotent connect must not create a second handle");
  assert.deepEqual(authority.calls.map((call) => call.purpose), [
    "enrollment",
    "pre_discovery",
    "pre_open",
    "post_open_identity",
    "post_activate",
  ]);

  const disconnected = await custody.disconnect();
  assert.equal(disconnected.state, "disconnected");
  assert.equal(disconnected.active_handle, false);
  assert.equal(driver.stats.closes, 1);
  const reconnected = await custody.reconnect();
  assert.equal(reconnected.state, "connected");
  assert.equal(reconnected.connection_generation, 2);
  assert.equal(driver.stats.opens, 2);
  assert.equal(driver.stats.activations, 2);
  assert.equal(driver.stats.closes, 1);
  const closed = await custody.close();
  assert.equal(closed.state, "closed");
  assert.equal(closed.active_handle, false);
  assert.equal(driver.stats.closes, 2);
  assert.equal((await custody.close()).state, "closed");
  await assert.rejects(custody.reconnect(), /usb_cdc_custody_closed/u);
});

test("connection-generation handoffs are private, one-shot, exact, and non-serializable", async () => {
  const first = setup();
  const second = setup({ custodyId: "worker_cdc_custody_02" });
  assert.throws(
    () => createWorkerUsbCdcConnectionGenerationHandoff(first.custody),
    /requires_stable_connected_custody/u,
  );
  const firstConnected = await first.custody.connect();
  await second.custody.connect();
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(first.custody);
  assert.deepEqual(Object.keys(handoff), [
    "version",
    "kind",
    "custody_id",
    "enrollment_id",
    "connection_generation",
    "handoff_id",
    "production_ready",
    "execution_authority",
    "lifecycle_authority",
    "toJSON",
  ]);
  assert.equal(Object.isFrozen(handoff), true);
  assert.equal(handoff.connection_generation, firstConnected.connection_generation);
  assert.equal(handoff.production_ready, false);
  assert.equal(handoff.execution_authority, false);
  assert.equal(handoff.lifecycle_authority, false);
  assert.equal(Object.hasOwn(handoff, "handle"), false);
  for (const field of ["read", "write", "transact", "callback", "handle"]) {
    assert.equal(Object.hasOwn(handoff, field), false);
  }
  assert.throws(
    () => JSON.stringify(handoff),
    /usb_cdc_connection_generation_handoff_not_serializable/u,
  );
  assert.throws(() => structuredClone(handoff));
  assert.throws(
    () => assertWorkerUsbCdcConnectionGenerationHandoff(
      { ...handoff }, first.custody, handoff.connection_generation,
    ),
    /private branded in-memory capability/u,
  );
  assert.throws(
    () => assertWorkerUsbCdcConnectionGenerationHandoff(
      handoff, { ...first.custody }, handoff.connection_generation,
    ),
    /private branded custody capability/u,
  );
  assert.throws(
    () => assertWorkerUsbCdcConnectionGenerationHandoff(
      handoff, first.custody, handoff.connection_generation + 1,
    ),
    /usb_cdc_connection_generation_handoff_generation_mismatch/u,
  );
  assert.throws(
    () => assertWorkerUsbCdcConnectionGenerationHandoff(
      handoff, second.custody, handoff.connection_generation,
    ),
    /usb_cdc_connection_generation_handoff_crosswired/u,
  );

  let callbackCalls = 0;
  const asserted = assertWorkerUsbCdcConnectionGenerationHandoff(
    handoff,
    first.custody,
    handoff.connection_generation,
  );
  // This is the future ABI-v3 integration shape: assertion and already-private
  // callback invocation are synchronous with no intervening await.
  ((generationProof) => {
    callbackCalls += 1;
    assert.equal(generationProof, handoff);
  })(asserted);
  assert.equal(callbackCalls, 1);
  assert.throws(
    () => assertWorkerUsbCdcConnectionGenerationHandoff(
      handoff, first.custody, handoff.connection_generation,
    ),
    /usb_cdc_connection_generation_handoff_consumed/u,
  );
  await first.custody.close();
  await second.custody.close();
});

test("disconnect and reconnect invalidate outstanding exact-generation handoffs immediately", async () => {
  const { custody } = setup();
  await custody.connect();
  const generationOne = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  const disconnecting = custody.disconnect();
  assert.throws(
    () => assertWorkerUsbCdcConnectionGenerationHandoff(generationOne, custody, 1),
    /usb_cdc_connection_generation_handoff_stale/u,
  );
  await disconnecting;
  assert.throws(
    () => createWorkerUsbCdcConnectionGenerationHandoff(custody),
    /requires_stable_connected_custody/u,
  );

  const reconnected = await custody.reconnect();
  assert.equal(reconnected.connection_generation, 2);
  const generationTwo = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  const reconnecting = custody.reconnect();
  assert.throws(
    () => assertWorkerUsbCdcConnectionGenerationHandoff(generationTwo, custody, 2),
    /usb_cdc_connection_generation_handoff_stale/u,
  );
  const generationThreeSnapshot = await reconnecting;
  assert.equal(generationThreeSnapshot.connection_generation, 3);
  const generationThree = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  assert.throws(
    () => assertWorkerUsbCdcConnectionGenerationHandoff(generationThree, custody, 2),
    /usb_cdc_connection_generation_handoff_generation_mismatch/u,
  );
  assert.equal(
    assertWorkerUsbCdcConnectionGenerationHandoff(generationThree, custody, 3),
    generationThree,
  );
  await custody.close();
});

test("live worker-authority failure invalidates a generation handoff before future I/O", async () => {
  const { authority, custody } = setup();
  await custody.connect();
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  authority.worker.current.revoked = true;
  assert.throws(
    () => assertWorkerUsbCdcConnectionGenerationHandoff(handoff, custody, 1),
    /usb_cdc_worker_authority_rejected/u,
  );
  assert.throws(
    () => assertWorkerUsbCdcConnectionGenerationHandoff(handoff, custody, 1),
    /usb_cdc_connection_generation_handoff_stale/u,
  );
  await custody.close();
});

test("transaction ports exist only for explicitly enrolled callbacks and cannot be cloned or crosswired", async () => {
  const withoutTransaction = setup();
  assert.throws(
    () => createWorkerUsbCdcTransactionPort(withoutTransaction.custody),
    (error) => assertSafeError(error, "usb_cdc_transaction_driver_unavailable"),
  );

  const first = setup({ driverOptions: { withTransaction: true } });
  const second = setup({
    custodyId: "worker_cdc_custody_02",
    driverOptions: { withTransaction: true },
  });
  const port = createWorkerUsbCdcTransactionPort(first.custody);
  assert.equal(createWorkerUsbCdcTransactionPort(first.custody), port);
  assert.equal(assertWorkerUsbCdcTransactionPort(port), port);
  assert.deepEqual(Object.keys(port), [
    "version",
    "kind",
    "custody_id",
    "enrollment_id",
    "capability_id",
    "production_ready",
    "toJSON",
  ]);
  assert.equal(port.production_ready, false);
  assert.equal(Object.isFrozen(port), true);
  for (const forbidden of [
    "handle", "path", "serial_number", "hardware_identity", "transact_handle", "execute",
  ]) {
    assert.equal(Object.hasOwn(port, forbidden), false);
  }
  assert.throws(() => JSON.stringify(port), /usb_cdc_transaction_port_not_serializable/u);
  assert.throws(() => structuredClone(port));
  assert.throws(
    () => assertWorkerUsbCdcTransactionPort({ ...port }),
    /private branded capability/u,
  );

  await first.custody.connect();
  await second.custody.connect();
  const crosswired = createWorkerUsbCdcConnectionGenerationHandoff(second.custody);
  const command = compiledCommand();
  assert.throws(
    () => executeWorkerUsbCdcTransaction(port, crosswired, command),
    /usb_cdc_connection_generation_handoff_crosswired/u,
  );
  assert.throws(
    () => executeWorkerUsbCdcTransaction(
      port,
      createWorkerUsbCdcConnectionGenerationHandoff(first.custody),
      command,
    ),
    /compiled_provider_command_stale/u,
  );
  assert.equal(first.driver.stats.transactions, 0);
  await withoutTransaction.custody.close();
  await first.custody.close();
  await second.custody.close();
});

test("a transaction synchronously reserves exact custody through native settlement and returns only branded lineage bytes", async () => {
  const native = deferred();
  const rawResponse = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  let lifecycleAttempt;
  let custody;
  const driver = driverFixture({
    transaction(query) {
      lifecycleAttempt = custody.disconnect();
      return native.promise;
    },
  });
  ({ custody } = setup({ driver }));
  await custody.connect();
  const port = createWorkerUsbCdcTransactionPort(custody);
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  const command = compiledCommand();
  const expectedRequest = Buffer.from("11ef07da0000000619c00064000726af", "hex");
  const transaction = executeWorkerUsbCdcTransaction(port, handoff, command);

  assert.equal(driver.stats.transactions, 1, "the native callback is invoked synchronously");
  await assert.rejects(lifecycleAttempt, /usb_cdc_lifecycle_busy/u);
  await assert.rejects(custody.reconnect(), /usb_cdc_lifecycle_busy/u);
  assert.throws(
    () => assertWorkerUsbCdcConnectionGenerationHandoff(handoff, custody, 1),
    /usb_cdc_connection_generation_handoff_consumed/u,
  );
  const query = driver.stats.transaction_queries[0];
  assert.deepEqual(Object.keys(query), [
    "version",
    "handle",
    "transaction_id",
    "connection_generation",
    "request_bytes",
    "maximum_response_bytes",
    "timeout_ms",
    "signal",
  ]);
  assert.equal(query.handle, driver.handles[0]);
  assert.equal(query.connection_generation, 1);
  assert.deepEqual(query.request_bytes, expectedRequest);
  assert.equal(query.maximum_response_bytes, 64);
  assert.equal(query.timeout_ms, 100);
  assert.equal(query.signal instanceof AbortSignal, true);
  assert.equal(query.signal.aborted, false);
  assert.doesNotMatch(JSON.stringify(Object.keys(query)), /path|serial_number|hardware_identity/u);

  native.resolve({ response_bytes: rawResponse });
  const result = await transaction;
  assert.equal(assertWorkerUsbCdcTransactionResult(result, port), result);
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(result.response_bytes, Buffer.from([0xde, 0xad, 0xbe, 0xef]));
  assert.equal(Object.prototype.propertyIsEnumerable.call(result, "response_bytes"), false);
  assert.match(result.request_digest, /^[a-f0-9]{64}$/u);
  assert.match(result.response_digest, /^[a-f0-9]{64}$/u);
  assert.equal(result.connection_generation, 1);
  assert.equal(result.compiled_command_id, command.compiled_command_id);
  assert.equal(result.provider_id, command.provider_id);
  assert.equal(result.compiler_id, command.compiler_id);
  assert.equal(result.compiler_manifest_digest, command.compiler_manifest_digest);
  assert.equal(result.compiler_registry_digest, command.compiler_registry_digest);
  assert.equal(result.source_profile_digest, command.source_profile_digest);
  assert.equal(result.operation_id, command.operation_id);
  assert.equal(result.capability_id, command.capability_id);
  assert.equal(result.variant_id, command.variant_id);
  assert.equal(result.parameter_selector_id, command.parameter_selector_id);
  assert.equal(result.canonical_command_digest, command.canonical_command_digest);
  assert.equal(result.compiled_operation_digest, command.compiled_operation_digest);
  assert.equal(
    result.compiled_command_capability_digest,
    command.compiled_command_capability_digest,
  );
  assert.equal(Object.hasOwn(result, "handle"), false);
  assert.equal(Object.hasOwn(result, "path"), false);
  assert.throws(() => JSON.stringify(result), /usb_cdc_transaction_result_not_serializable/u);
  assert.throws(() => structuredClone(result));
  assert.throws(
    () => assertWorkerUsbCdcTransactionResult({ ...result }, port),
    /private intact result/u,
  );
  assert.deepEqual(expectedRequest, Buffer.from("11ef07da0000000619c00064000726af", "hex"));
  assert.deepEqual(
    query.request_bytes,
    Buffer.alloc(expectedRequest.length),
    "the claimed compiled-command request copy is zeroed",
  );
  assert.deepEqual(rawResponse, Buffer.alloc(4), "driver-transferred response bytes are zeroed");
  assert.equal(custody.snapshot().state, "connected");
  assert.equal(custody.snapshot().transition_code, "transport_transaction_succeeded");
  await custody.close();
});

test("compiled-command authority and response bounds fail closed without native retries", async (t) => {
  await t.test("raw, lookalike, async, cross-manifest, and proxy forms never reach native I/O", async () => {
    const { custody, driver } = setup({ driverOptions: { withTransaction: true } });
    await custody.connect();
    const port = createWorkerUsbCdcTransactionPort(custody);
    const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
    const command = compiledCommand();
    assert.throws(
      () => executeWorkerUsbCdcTransaction(port, handoff, {
        version: 1,
        request_bytes: Buffer.alloc(USB_CDC_CUSTODY_LIMITS.write_buffer_bytes + 1),
        maximum_response_bytes: 32,
        timeout_ms: 100,
      }),
      /compiled_provider_command_untrusted/u,
    );
    assert.throws(
      () => executeWorkerUsbCdcTransaction(port, handoff, Buffer.from([0x01])),
      /compiled_provider_command_untrusted/u,
    );
    assert.throws(
      () => executeWorkerUsbCdcTransaction(port, handoff, { ...command }),
      /compiled_provider_command_untrusted/u,
    );
    assert.throws(
      () => executeWorkerUsbCdcTransaction(port, handoff, {
        ...command,
        compiler_manifest_digest: "0".repeat(64),
      }),
      /compiled_provider_command_cross_manifest/u,
    );
    assert.throws(
      () => executeWorkerUsbCdcTransaction(port, handoff, Promise.resolve(command)),
      /compiled_provider_command_async/u,
    );
    let thenGetterCalls = 0;
    const hostileThenable = {};
    Object.defineProperty(hostileThenable, "then", {
      enumerable: true,
      get() {
        thenGetterCalls += 1;
        throw new Error("must not invoke an async-form getter");
      },
    });
    assert.throws(
      () => executeWorkerUsbCdcTransaction(port, handoff, hostileThenable),
      /compiled_provider_command_async/u,
    );
    assert.equal(thenGetterCalls, 0);
    let proxyTrapCalls = 0;
    const proxy = new Proxy(command, {
      get() {
        proxyTrapCalls += 1;
        throw new Error("must not inspect proxy fields");
      },
    });
    assert.throws(
      () => executeWorkerUsbCdcTransaction(port, handoff, proxy),
      /compiled_provider_command_proxy/u,
    );
    assert.equal(driver.stats.transactions, 0);
    assert.equal(proxyTrapCalls, 0);
    const result = await executeWorkerUsbCdcTransaction(port, handoff, command);
    assert.equal(result.connection_generation, 1);
    assert.equal(driver.stats.transactions, 1);
    assert.throws(
      () => executeWorkerUsbCdcTransaction(
        port,
        createWorkerUsbCdcConnectionGenerationHandoff(custody),
        command,
      ),
      /compiled_provider_command_replayed/u,
    );
    assert.equal(driver.stats.transactions, 1);
    await custody.close();
  });

  await t.test("an oversized native response is ambiguous and quarantines the generation", async () => {
    const rawResponse = Buffer.alloc(65, 0x55);
    const driver = driverFixture({
      transaction() {
        return { response_bytes: rawResponse };
      },
    });
    const { custody } = setup({ driver });
    await custody.connect();
    const port = createWorkerUsbCdcTransactionPort(custody);
    const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
    await assert.rejects(
      executeWorkerUsbCdcTransaction(port, handoff, compiledCommand()),
      (error) => assertSafeError(error, "usb_cdc_transaction_response_ambiguous"),
    );
    assert.equal(driver.stats.transactions, 1);
    assert.equal(driver.stats.closes, 1);
    assert.deepEqual(rawResponse, Buffer.alloc(65));
    assert.equal(custody.snapshot().state, "disconnected");
    assert.match(custody.snapshot().transition_code, /response_ambiguous_quarantined/u);
    await custody.close();
  });
});

test("a transaction timeout stays reserved until late native settlement, discards late success, and quarantines", async () => {
  const native = deferred();
  const quarantined = deferred();
  let nativeSignal;
  const lateResponse = Buffer.from([0xaa, 0xbb]);
  const driver = driverFixture({
    transaction(query) {
      nativeSignal = query.signal;
      return native.promise;
    },
    close() {
      quarantined.resolve();
      return { closed: true };
    },
  });
  const { custody } = setup({ driver });
  await custody.connect();
  const port = createWorkerUsbCdcTransactionPort(custody);
  const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  await assert.rejects(
    executeWorkerUsbCdcTransaction(port, handoff, compiledCommand()),
    (error) => assertSafeError(error, "usb_cdc_transaction_timeout_ambiguous"),
  );
  assert.equal(nativeSignal.aborted, true);
  assert.equal(driver.stats.transactions, 1);
  assert.equal(driver.stats.closes, 0, "the handle cannot close while native I/O is unsettled");
  assert.equal(custody.snapshot().state, "close_uncertain");
  await assert.rejects(custody.disconnect(), /usb_cdc_lifecycle_busy/u);
  await assert.rejects(custody.close(), /usb_cdc_lifecycle_busy/u);

  native.resolve({ response_bytes: lateResponse });
  await quarantined.promise;
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(lateResponse, Buffer.alloc(2));
  assert.equal(driver.stats.transactions, 1, "late completion is never retried or promoted");
  assert.equal(driver.stats.closes, 1);
  assert.equal(custody.snapshot().state, "disconnected");
  assert.match(custody.snapshot().transition_code, /timeout_ambiguous_quarantined/u);
  const reconnected = await custody.reconnect();
  assert.equal(reconnected.connection_generation, 2);
  assert.equal(driver.stats.transactions, 1);
  await custody.close();
});

test("a synchronous native callback that returns after its deadline is still timeout-ambiguous", async () => {
  const rawResponse = Buffer.from([0x90, 0x00]);
  const driver = driverFixture({
    transaction() {
      const deadline = process.hrtime.bigint() + 125_000_000n;
      while (process.hrtime.bigint() < deadline) {
        // Simulate a misbehaving native shim blocking beyond its contract.
      }
      return { response_bytes: rawResponse };
    },
  });
  const { custody } = setup({ driver });
  await custody.connect();
  const port = createWorkerUsbCdcTransactionPort(custody);
  await assert.rejects(
    executeWorkerUsbCdcTransaction(
      port,
      createWorkerUsbCdcConnectionGenerationHandoff(custody),
      compiledCommand(),
    ),
    (error) => assertSafeError(error, "usb_cdc_transaction_timeout_ambiguous"),
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(rawResponse, Buffer.alloc(2));
  assert.equal(driver.stats.transactions, 1);
  assert.equal(driver.stats.closes, 1);
  assert.equal(custody.snapshot().state, "disconnected");
  await custody.close();
});

test("native rejection and post-effect authority failure are sanitized, ambiguous, and one-shot", async (t) => {
  await t.test("native disconnect-style rejection", async () => {
    const driver = driverFixture({
      transaction() {
        throw new Error("disconnect /dev/private-cdc-path PRIVATE-SERIAL-001");
      },
    });
    const { custody } = setup({ driver });
    await custody.connect();
    const port = createWorkerUsbCdcTransactionPort(custody);
    const handoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
    await assert.rejects(
      executeWorkerUsbCdcTransaction(port, handoff, compiledCommand()),
      (error) => assertSafeError(error, "usb_cdc_transaction_failed_ambiguous"),
    );
    assert.equal(driver.stats.transactions, 1);
    assert.equal(driver.stats.closes, 1);
    assert.throws(
      () => assertWorkerUsbCdcConnectionGenerationHandoff(handoff, custody, 1),
      /usb_cdc_connection_generation_handoff_consumed/u,
    );
    await custody.close();
  });

  await t.test("authority revoked after native success", async () => {
    const authority = authorityFixture();
    const rawResponse = Buffer.from([0x90, 0x00]);
    const driver = driverFixture({
      transaction() {
        authority.worker.current.revoked = true;
        return { response_bytes: rawResponse };
      },
    });
    const { custody } = setup({ authority, driver });
    await custody.connect();
    const port = createWorkerUsbCdcTransactionPort(custody);
    await assert.rejects(
      executeWorkerUsbCdcTransaction(
        port,
        createWorkerUsbCdcConnectionGenerationHandoff(custody),
        compiledCommand(),
      ),
      (error) => assertSafeError(error, "usb_cdc_transaction_authority_ambiguous"),
    );
    assert.deepEqual(rawResponse, Buffer.alloc(2));
    assert.equal(driver.stats.transactions, 1);
    assert.equal(driver.stats.closes, 1);
    assert.equal(custody.snapshot().state, "disconnected");
    await custody.close();
  });
});

test("concurrent transaction and lifecycle attempts cannot cross the exact reserved generation", async () => {
  const native = deferred();
  const driver = driverFixture({ transaction() { return native.promise; } });
  const { custody } = setup({ driver });
  await custody.connect();
  const port = createWorkerUsbCdcTransactionPort(custody);
  const firstHandoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  const secondHandoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  const secondCommand = compiledCommand("iso14443a.wupa_atqa_v1");
  const first = executeWorkerUsbCdcTransaction(port, firstHandoff, compiledCommand());
  assert.throws(
    () => executeWorkerUsbCdcTransaction(port, secondHandoff, secondCommand),
    /usb_cdc_transaction_busy/u,
  );
  await assert.rejects(custody.reconnect(), /usb_cdc_lifecycle_busy/u);
  native.resolve({ response_bytes: Buffer.from([0x90, 0x00]) });
  await first;
  assert.equal(driver.stats.transactions, 1);
  assert.throws(
    () => assertWorkerUsbCdcConnectionGenerationHandoff(secondHandoff, custody, 1),
    /usb_cdc_connection_generation_handoff_stale/u,
  );
  assert.throws(
    () => executeWorkerUsbCdcTransaction(
      port,
      createWorkerUsbCdcConnectionGenerationHandoff(custody),
      secondCommand,
    ),
    /compiled_provider_command_stale/u,
  );
  await custody.close();
});

test("authority-resolver reentry cannot invalidate a handoff and let the outer transaction invoke anyway", async () => {
  const authority = authorityFixture();
  const driver = driverFixture({ withTransaction: true });
  const { custody } = setup({ authority, driver });
  await custody.connect();
  const port = createWorkerUsbCdcTransactionPort(custody);
  const outerHandoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  const reentrantHandoff = createWorkerUsbCdcConnectionGenerationHandoff(custody);
  const outerCommand = compiledCommand();
  const reentrantCommand = compiledCommand("iso14443a.wupa_atqa_v1");
  let reentrantError;
  authority.current.onResolve = () => {
    authority.current.onResolve = null;
    try {
      executeWorkerUsbCdcTransaction(port, reentrantHandoff, reentrantCommand);
    } catch (error) {
      reentrantError = error;
    }
  };
  assert.throws(
    () => executeWorkerUsbCdcTransaction(port, outerHandoff, outerCommand),
    /usb_cdc_connection_generation_handoff_stale/u,
  );
  assert.equal(reentrantError?.code, "usb_cdc_transaction_busy");
  assert.equal(driver.stats.transactions, 0);
  assert.equal(custody.snapshot().state, "connected");
  assert.throws(
    () => assertWorkerUsbCdcConnectionGenerationHandoff(reentrantHandoff, custody, 1),
    /usb_cdc_connection_generation_handoff_stale/u,
  );
  await custody.close();
});

test("authority is live-revalidated before discovery, before open, and after open", async () => {
  const authority = authorityFixture();
  const driver = driverFixture({
    open(query) {
      authority.current.revoked = true;
      return {
        handle: Object.freeze({ fake_handle_id: "revoked-after-open" }),
        opened_hardware_identity: Buffer.from(query.candidate.hardware_identity),
        transport_guarantees: { ...PRE_ACTIVATION_GUARANTEES },
      };
    },
  });
  const { custody } = setup({ authority, driver });
  await assert.rejects(
    custody.connect(),
    (error) => assertSafeError(error, "usb_cdc_open_authority_rejected"),
  );
  assert.equal(driver.stats.opens, 1);
  assert.equal(driver.stats.activations, 0);
  assert.equal(driver.stats.closes, 1, "post-open revocation must quarantine and close the handle");
  assert.equal(custody.snapshot().state, "disconnected");
  assert.deepEqual(authority.calls.map((call) => call.purpose), [
    "enrollment", "pre_discovery", "pre_open", "post_open_identity",
  ]);
});

test("pre-open revocation prevents the driver open seam", async () => {
  const authority = authorityFixture();
  const originalResolver = authority.port;
  assert.equal(assertUsbCdcOpenAuthorityPort(originalResolver), originalResolver);
  let preOpenSeen = false;
  const worker = workerAuthorityFixture({
    enrollmentId: "dynamic_device_01",
    identity: IDENTITY_A,
    binding: { ...DRIVER_BINDING, custody_id: "dynamic_custody" },
  });
  const dynamicAuthority = createUsbCdcOpenAuthorityPort({
    version: 1,
    authority_id: "dynamic_usb_authority",
    worker_authority_port: worker.port,
    resolve_current_enrollment(query) {
      if (query.purpose === "pre_open") preOpenSeen = true;
      return {
        version: 1,
        authority_id: "dynamic_usb_authority",
        authority_epoch: 1,
        enrollment_id: "dynamic_device_01",
        alias: "dynamic_research_unit",
        trusted: true,
        revoked: preOpenSeen,
        open_allowed: true,
        candidate_filters: { ...FILTERS },
        hardware_identity: Buffer.from(IDENTITY_A),
        hardware_identity_provenance: "operator_enrolled_high_entropy",
      };
    },
  });
  const enrollment = enrollOperatorUsbCdcDevice({
    version: 1,
    enrollment_id: "dynamic_device_01",
    alias: "dynamic_research_unit",
    authority_id: "dynamic_usb_authority",
  }, dynamicAuthority);
  const driver = driverFixture();
  driver.bind({ enrollment, worker }, "dynamic_custody");
  const custody = createWorkerUsbCdcCustody({
    version: 1,
    custody_id: "dynamic_custody",
    enrollment,
    driver_port: driver.port,
    open_authority_port: dynamicAuthority,
    worker_authority_port: worker.port,
  });
  await assert.rejects(custody.connect(), /usb_cdc_open_authority_rejected/u);
  assert.equal(driver.stats.enumerations, 1);
  assert.equal(driver.stats.opens, 0);
});

test("authority outage, malformed state, async state, revocation, drift, and epoch rollback fail closed", async (t) => {
  const cases = [
    ["outage", (current) => { current.behavior = "throw"; }],
    ["malformed", (current) => { current.behavior = "malformed"; }],
    ["async", (current) => { current.behavior = "async"; }],
    ["revoked", (current) => { current.revoked = true; }],
    ["not trusted", (current) => { current.trusted = false; }],
    ["opening disabled", (current) => { current.open_allowed = false; }],
    ["identity drift", (current) => { current.hardware_identity = Buffer.from(IDENTITY_B); }],
    ["undersized identity", (current) => { current.hardware_identity = Buffer.alloc(16); }],
    ["serial-derived provenance", (current) => {
      current.hardware_identity_provenance = "serial_path_sha256";
    }],
    ["filter drift", (current) => { current.candidate_filters.model = "different-model"; }],
    ["alias drift", (current) => { current.alias = "other_alias"; }],
    ["epoch rollback", (current) => { current.authority_epoch = 0; }],
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      const authority = authorityFixture();
      mutate(authority.current);
      const driver = driverFixture();
      const { custody } = setup({ authority, driver });
      await assert.rejects(
        custody.connect(),
        (error) => assertSafeError(error, "usb_cdc_open_authority_rejected"),
      );
      assert.equal(driver.stats.enumerations, 0);
      assert.equal(driver.stats.opens, 0);
    });
  }
});

test("authority epochs may advance for the same exact enrollment but may never roll back", async () => {
  const authority = authorityFixture();
  const driver = driverFixture();
  const { custody } = setup({ authority, driver });
  authority.current.authority_epoch = 2;
  await custody.connect();
  await custody.disconnect();
  authority.current.authority_epoch = 1;
  await assert.rejects(custody.reconnect(), /usb_cdc_open_authority_rejected/u);
  assert.equal(driver.stats.opens, 1);
});

test("reconnect rediscovers the same enrolled identity and refuses substitution", async () => {
  let discoveryRound = 0;
  const driver = driverFixture({
    enumerate() {
      discoveryRound += 1;
      return [candidate({ identity: discoveryRound === 1 ? IDENTITY_A : IDENTITY_B })];
    },
  });
  const { custody } = setup({ driver });
  await custody.connect();
  await assert.rejects(custody.reconnect(), /usb_cdc_candidate_not_found/u);
  assert.equal(driver.stats.closes, 1);
  assert.equal(driver.stats.opens, 1);
  assert.equal(driver.stats.enumerations, 2);
  assert.equal(custody.snapshot().state, "disconnected");
});

test("opened-device identity attestation closes a path-swap result", async () => {
  const driver = driverFixture({
    open() {
      return {
        handle: Object.freeze({ fake_handle_id: "swapped-path-handle" }),
        opened_hardware_identity: Buffer.from(IDENTITY_B),
        transport_guarantees: { ...PRE_ACTIVATION_GUARANTEES },
      };
    },
  });
  const { custody } = setup({ driver });
  await assert.rejects(custody.connect(), /usb_cdc_opened_identity_mismatch/u);
  assert.equal(driver.stats.closes, 1);
  assert.equal(custody.snapshot().state, "disconnected");
});

test("pre-activation open requires DTR-off, write-disabled, locked bounded custody", async (t) => {
  for (const [field, badValue] of [
    ["baud_rate", 9600],
    ["data_bits", 7],
    ["stop_bits", 2],
    ["parity", "even"],
    ["dtr_asserted", true],
    ["exclusive_open", false],
    ["serial_lock", false],
    ["rts_cts", true],
    ["xon_xoff", true],
    ["generic_write_surface_exposed", true],
    ["brokered_exact_transaction_write_enabled", true],
    ["read_buffer_bytes", USB_CDC_CUSTODY_LIMITS.read_buffer_bytes + 1],
    ["write_buffer_bytes", USB_CDC_CUSTODY_LIMITS.write_buffer_bytes + 1],
    ["io_timeout_ms", USB_CDC_CUSTODY_LIMITS.io_timeout_ms + 1],
  ]) {
    await t.test(field, async () => {
      const driver = driverFixture({
        open(query) {
          return {
            handle: Object.freeze({ fake_handle_id: `bad-${field}` }),
            opened_hardware_identity: Buffer.from(query.candidate.hardware_identity),
            transport_guarantees: { ...PRE_ACTIVATION_GUARANTEES, [field]: badValue },
          };
        },
      });
      const { custody } = setup({ driver });
      await assert.rejects(custody.connect(), /usb_cdc_open_attestation_rejected/u);
      assert.equal(driver.stats.closes, 1);
      assert.notEqual(custody.snapshot().state, "connected");
    });
  }
});

test("DTR activation re-attests the same identity and every final transport guarantee", async (t) => {
  for (const [field, badValue] of [
    ["baud_rate", 9600],
    ["data_bits", 7],
    ["stop_bits", 2],
    ["parity", "even"],
    ["dtr_asserted", false],
    ["exclusive_open", false],
    ["serial_lock", false],
    ["rts_cts", true],
    ["xon_xoff", true],
    ["generic_write_surface_exposed", true],
    ["brokered_exact_transaction_write_enabled", false],
    ["read_buffer_bytes", USB_CDC_CUSTODY_LIMITS.read_buffer_bytes + 1],
    ["write_buffer_bytes", USB_CDC_CUSTODY_LIMITS.write_buffer_bytes + 1],
    ["io_timeout_ms", USB_CDC_CUSTODY_LIMITS.io_timeout_ms + 1],
  ]) {
    await t.test(field, async () => {
      const driver = driverFixture({
        activate() {
          return {
            activated: true,
            opened_hardware_identity: Buffer.from(IDENTITY_A),
            transport_guarantees: { ...GUARANTEES, [field]: badValue },
          };
        },
      });
      const { custody } = setup({ driver });
      await assert.rejects(custody.connect(), /usb_cdc_activation_attestation_rejected/u);
      assert.equal(driver.stats.opens, 1);
      assert.equal(driver.stats.activations, 1);
      assert.equal(driver.stats.closes, 1);
      assert.notEqual(custody.snapshot().state, "connected");
    });
  }
});

test("DTR activation identity substitution is quarantined before connected state", async () => {
  const driver = driverFixture({
    activate() {
      return {
        activated: true,
        opened_hardware_identity: Buffer.from(IDENTITY_B),
        transport_guarantees: { ...GUARANTEES },
      };
    },
  });
  const { custody } = setup({ driver });
  await assert.rejects(custody.connect(), /usb_cdc_activation_identity_mismatch/u);
  assert.equal(driver.stats.closes, 1);
  assert.equal(custody.snapshot().state, "disconnected");
});

test("authority revocation during DTR activation closes the handle before connected state", async () => {
  const authority = authorityFixture();
  const driver = driverFixture({
    activate() {
      authority.current.revoked = true;
      return {
        activated: true,
        opened_hardware_identity: Buffer.from(IDENTITY_A),
        transport_guarantees: { ...GUARANTEES },
      };
    },
  });
  const { custody } = setup({ authority, driver });
  await assert.rejects(custody.connect(), /usb_cdc_open_authority_rejected/u);
  assert.equal(driver.stats.activations, 1);
  assert.equal(driver.stats.closes, 1);
  assert.equal(custody.snapshot().state, "disconnected");
  assert.equal(authority.calls.at(-1).purpose, "post_activate");
});

test("raw driver failures are replaced with stable non-sensitive errors", async (t) => {
  await t.test("discovery", async () => {
    const driver = driverFixture({
      enumerate() { throw spoofedDriverTimeout("usb_cdc_discovery_timeout"); },
    });
    const { custody } = setup({ driver });
    await assert.rejects(
      custody.connect(),
      (error) => assertSafeError(error, "usb_cdc_discovery_failed"),
    );
  });
  await t.test("open", async () => {
    const driver = driverFixture({
      open() { throw spoofedDriverTimeout("usb_cdc_open_timeout"); },
    });
    const { custody } = setup({ driver });
    await assert.rejects(
      custody.connect(),
      (error) => assertSafeError(error, "usb_cdc_open_failed"),
    );
  });
  await t.test("activation", async () => {
    const driver = driverFixture({
      activate() { throw spoofedDriverTimeout("usb_cdc_activation_timeout"); },
    });
    const { custody } = setup({ driver });
    await assert.rejects(
      custody.connect(),
      (error) => assertSafeError(error, "usb_cdc_activation_failed"),
    );
    assert.equal(driver.stats.closes, 1);
  });
  await t.test("close", async () => {
    const driver = driverFixture({
      close() { throw spoofedDriverTimeout("usb_cdc_close_timeout"); },
    });
    const { custody } = setup({ driver });
    await custody.connect();
    await assert.rejects(
      custody.disconnect(),
      (error) => assertSafeError(error, "usb_cdc_close_failed"),
    );
    assert.equal(custody.snapshot().state, "close_uncertain");
  });
});

test("enumeration and lifecycle concurrency are bounded before any second open", async () => {
  let releaseEnumeration;
  const pendingEnumeration = new Promise((resolve) => { releaseEnumeration = resolve; });
  const driver = driverFixture({ enumerate: () => pendingEnumeration });
  const { custody } = setup({ driver });
  const first = custody.connect();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(custody.snapshot().state, "connecting");
  await assert.rejects(custody.connect(), /usb_cdc_lifecycle_busy/u);
  releaseEnumeration([candidate()]);
  await first;
  assert.equal(driver.stats.opens, 1);
});

test("candidate count is bounded and malformed inventories never reach open", async () => {
  const driver = driverFixture({
    enumerate: () => Array.from(
      { length: USB_CDC_CUSTODY_LIMITS.max_candidates + 1 },
      (_, index) => candidate({ rawPath: `/dev/private-cdc-path-${index}` }),
    ),
  });
  const { custody } = setup({ driver });
  await assert.rejects(custody.connect(), /usb_cdc_discovery_failed/u);
  assert.equal(driver.stats.opens, 0);
  assert.equal(driver.stats.enumeration_queries[0].max_candidates, 64);
  assert.equal(
    driver.stats.enumeration_queries[0].discovery_timeout_ms,
    USB_CDC_CUSTODY_LIMITS.discovery_timeout_ms,
  );
});

test("sparse candidate inventories fail with a sanitized discovery error", async () => {
  const driver = driverFixture({ enumerate: () => new Array(1) });
  const { custody } = setup({ driver });
  await assert.rejects(
    custody.connect(),
    (error) => assertSafeError(error, "usb_cdc_discovery_failed"),
  );
  assert.equal(driver.stats.opens, 0);
  assert.equal(custody.snapshot().state, "disconnected");
});

test("open timeout enters an uncertainty fence and late handles are closed before terminal close", async () => {
  let releaseOpen;
  let openQuery;
  const pendingOpen = new Promise((resolve) => { releaseOpen = resolve; });
  const driver = driverFixture({
    open(query) {
      openQuery = query;
      return pendingOpen;
    },
  });
  const { custody } = setup({ driver });
  await assert.rejects(
    custody.connect(),
    (error) => assertSafeError(error, "usb_cdc_open_timeout"),
  );
  assert.equal(custody.snapshot().state, "open_uncertain");
  assert.equal(custody.snapshot().active_handle, true);
  await assert.rejects(custody.connect(), /usb_cdc_transport_state_uncertain/u);
  await assert.rejects(custody.close(), /usb_cdc_open_resolution_pending/u);
  releaseOpen({
    handle: Object.freeze({ fake_handle_id: "late-handle" }),
    opened_hardware_identity: Buffer.from(IDENTITY_A),
    transport_guarantees: { ...PRE_ACTIVATION_GUARANTEES },
  });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(openQuery.signal.aborted, true);
  assert.equal(driver.stats.closes, 1);
  assert.equal(custody.snapshot().state, "closed");
  assert.equal(custody.snapshot().active_handle, false);
});

test("a timed-out open stays fenced when late settlement cannot prove that no handle was acquired", async (t) => {
  for (const [name, settleLateOpen] of [
    ["rejection", (resolve, reject) => reject(new Error("native open failed after acquisition"))],
    ["malformed result", (resolve) => resolve({ opened: true })],
  ]) {
    await t.test(name, async () => {
      let resolveOpen;
      let rejectOpen;
      const pendingOpen = new Promise((resolve, reject) => {
        resolveOpen = resolve;
        rejectOpen = reject;
      });
      const driver = driverFixture({ open: () => pendingOpen });
      const { custody } = setup({ driver });

      await assert.rejects(
        custody.connect(),
        (error) => assertSafeError(error, "usb_cdc_open_timeout"),
      );
      settleLateOpen(resolveOpen, rejectOpen);
      await new Promise((resolve) => setImmediate(resolve));
      await new Promise((resolve) => setImmediate(resolve));

      assert.deepEqual(custody.snapshot(), {
        version: 1,
        custody_id: "worker_cdc_custody_01",
        enrollment_id: "operator_device_01",
        alias: "front_desk_research_unit",
        state: "open_uncertain",
        connection_generation: 0,
        active_handle: true,
        transition_code: "transport_open_timed_out_unresolved",
      });
      assert.equal(driver.stats.closes, 0);
      await assert.rejects(custody.connect(), /usb_cdc_transport_state_uncertain/u);
      await assert.rejects(custody.reconnect(), /usb_cdc_transport_state_uncertain/u);
    });
  }
});

test("DTR activation timeout never connects or replays and closes the late activation handle", async () => {
  let releaseActivation;
  let activationQuery;
  const pendingActivation = new Promise((resolve) => { releaseActivation = resolve; });
  const driver = driverFixture({
    activate(query) {
      activationQuery = query;
      return pendingActivation;
    },
  });
  const { custody } = setup({ driver });
  await assert.rejects(
    custody.connect(),
    (error) => assertSafeError(error, "usb_cdc_activation_timeout"),
  );
  assert.equal(custody.snapshot().state, "open_uncertain");
  assert.equal(custody.snapshot().active_handle, true);
  assert.equal(driver.stats.opens, 1);
  assert.equal(driver.stats.activations, 1);
  await assert.rejects(custody.reconnect(), /usb_cdc_transport_state_uncertain/u);
  assert.equal(driver.stats.opens, 1, "custody recovery must never auto-open or replay after ambiguity");
  await assert.rejects(custody.close(), /usb_cdc_open_resolution_pending/u);
  releaseActivation({
    activated: true,
    opened_hardware_identity: Buffer.from(IDENTITY_A),
    transport_guarantees: { ...GUARANTEES },
  });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(activationQuery.signal.aborted, true);
  assert.equal(driver.stats.closes, 1);
  assert.equal(custody.snapshot().state, "closed");
  assert.equal(custody.snapshot().active_handle, false);
});

test("discovery timeout aborts the fake operation and returns to a safe disconnected state", async () => {
  let discoverySignal;
  const driver = driverFixture({
    enumerate(query) {
      discoverySignal = query.signal;
      return new Promise(() => {});
    },
  });
  const { custody } = setup({ driver });
  await assert.rejects(
    custody.connect(),
    (error) => assertSafeError(error, "usb_cdc_discovery_timeout"),
  );
  assert.equal(discoverySignal.aborted, true);
  assert.equal(custody.snapshot().state, "disconnected");
  assert.equal(driver.stats.opens, 0);
});

test("unconfirmed close fences reopening until the same retained handle is confirmed closed", async () => {
  const driver = driverFixture({
    close(query, stats) {
      if (stats.closes === 1) return { closed: false };
      return { closed: true };
    },
  });
  const { custody } = setup({ driver });
  await custody.connect();
  await assert.rejects(custody.disconnect(), /usb_cdc_close_unconfirmed/u);
  assert.equal(custody.snapshot().state, "close_uncertain");
  await assert.rejects(custody.connect(), /usb_cdc_transport_state_uncertain/u);
  const disconnected = await custody.disconnect();
  assert.equal(disconnected.state, "disconnected");
  assert.equal(driver.stats.closes, 2);
  assert.equal(driver.stats.close_queries[0].handle, driver.stats.close_queries[1].handle);
});

test("an enrollment cannot be rebound to a cloned or different open authority", () => {
  const authority = authorityFixture();
  const driver = driverFixture();
  driver.bind(authority, "single_owner_custody");
  const otherAuthority = createUsbCdcOpenAuthorityPort({
    version: 1,
    authority_id: authority.current.authority_id,
    worker_authority_port: authority.worker.port,
    resolve_current_enrollment() { throw new Error("must not be called"); },
  });
  assert.throws(() => createWorkerUsbCdcCustody({
    version: 1,
    custody_id: "wrong_authority_custody",
    enrollment: authority.enrollment,
    driver_port: driver.port,
    open_authority_port: otherAuthority,
    worker_authority_port: authority.worker.port,
  }), /does not own the enrollment/u);
  assert.throws(() => createWorkerUsbCdcCustody({
    version: 1,
    custody_id: "cloned_authority_custody",
    enrollment: authority.enrollment,
    driver_port: driver.port,
    open_authority_port: { ...authority.port },
    worker_authority_port: authority.worker.port,
  }), /private branded authority/u);

  const first = createWorkerUsbCdcCustody({
    version: 1,
    custody_id: "single_owner_custody",
    enrollment: authority.enrollment,
    driver_port: driver.port,
    open_authority_port: authority.port,
    worker_authority_port: authority.worker.port,
  });
  assert.equal(assertWorkerUsbCdcCustody(first), first);
  assert.throws(() => createWorkerUsbCdcCustody({
    version: 1,
    custody_id: "single_owner_custody",
    enrollment: authority.enrollment,
    driver_port: driver.port,
    open_authority_port: authority.port,
    worker_authority_port: authority.worker.port,
  }), /already bound to a custody controller/u);
});

test("a driver capability requires the exact private enrollment and signed worker authority", () => {
  const authority = authorityFixture();
  assert.throws(() => createUsbCdcDriverPort(
    inertDriverInput(),
    { ...authority.enrollment },
    authority.worker.port,
  ), /private branded enrollment/u);
  assert.throws(() => createUsbCdcDriverPort(
    inertDriverInput(),
    authority.enrollment,
    { ...authority.worker.port },
  ), /private branded authority/u);

  const port = createUsbCdcDriverPort(
    inertDriverInput(),
    authority.enrollment,
    authority.worker.port,
  );
  assert.equal(assertUsbCdcDriverPort(port), port);
  assert.throws(() => createUsbCdcDriverPort(
    inertDriverInput(),
    authority.enrollment,
    authority.worker.port,
  ), /already bound to a driver capability/u);
  assertNoRawTransportData(port);
});

test("driver authority cannot cross devices, worker authorities, or custody instances", () => {
  const firstAuthority = authorityFixture();
  const secondAuthority = authorityFixture();
  const driver = driverFixture();
  driver.bind(firstAuthority);

  assert.throws(() => createWorkerUsbCdcCustody({
    version: 1,
    custody_id: DRIVER_BINDING.custody_id,
    enrollment: secondAuthority.enrollment,
    driver_port: driver.port,
    open_authority_port: secondAuthority.port,
    worker_authority_port: firstAuthority.worker.port,
  }), /driver authority binding does not match/u);

  const otherWorker = workerAuthorityFixture();
  assert.throws(() => createWorkerUsbCdcCustody({
    version: 1,
    custody_id: DRIVER_BINDING.custody_id,
    enrollment: firstAuthority.enrollment,
    driver_port: driver.port,
    open_authority_port: firstAuthority.port,
    worker_authority_port: otherWorker.port,
  }), /driver authority binding does not match/u);

  assert.throws(() => createWorkerUsbCdcCustody({
    version: 1,
    custody_id: "substituted_custody_instance",
    enrollment: firstAuthority.enrollment,
    driver_port: driver.port,
    open_authority_port: firstAuthority.port,
    worker_authority_port: firstAuthority.worker.port,
  }), /driver authority binding does not match/u);
});

test("signed worker authority rejects signature spoofing and never leaks raw authority material", async () => {
  const { authority, custody, driver } = setup();
  authority.worker.current.behavior = "bad_signature";
  await assert.rejects(
    custody.connect(),
    (error) => assertSafeError(error, "usb_cdc_worker_authority_rejected"),
  );
  assert.equal(driver.stats.enumerations, 0);
  assertNoRawTransportData(custody.snapshot());

  authority.worker.current.behavior = "malformed";
  await assert.rejects(
    custody.connect(),
    (error) => {
      assertSafeError(error, "usb_cdc_worker_authority_rejected");
      assert.doesNotMatch(JSON.stringify(error), /"data":\[65,65,65/u);
      return true;
    },
  );
});

test("signed worker authority epochs advance and rollback stays fenced", async () => {
  const { authority, custody, driver } = setup();
  authority.worker.current.trust_root_epoch = 2;
  authority.worker.current.authority_epoch = 2;
  authority.worker.current.revocation_generation = 1;
  await custody.connect();
  await custody.disconnect();
  authority.worker.current.trust_root_epoch = 1;
  authority.worker.current.authority_epoch = 1;
  authority.worker.current.revocation_generation = 0;
  await assert.rejects(
    custody.reconnect(),
    (error) => assertSafeError(error, "usb_cdc_worker_authority_rejected"),
  );
  assert.equal(driver.stats.opens, 1);
  assert.equal(driver.stats.enumerations, 1);
});

test("driver, principal, device, provider, and transport drift revoke the exact port", async (t) => {
  const cases = [
    ["device identity", "hardware_identity_digest", digest("replacement-device-identity")],
    ["driver implementation", "driver_implementation_digest", digest("replacement-driver-impl")],
    ["driver binary", "driver_binary_digest", digest("replacement-driver-binary")],
    ["execution principal", "execution_principal_id", "principal:replacement-worker"],
    ["worker uid", "worker_uid", WORKER_UID === 0 ? 1 : WORKER_UID - 1],
    ["provider descriptor", "provider_descriptor_digest", digest("replacement-provider")],
    ["transport", "transport_digest", digest("replacement-transport")],
  ];
  for (const [name, field, replacement] of cases) {
    await t.test(name, async () => {
      const { authority, custody, driver } = setup();
      authority.worker.current.authority_epoch += 1;
      authority.worker.current[field] = replacement;
      await assert.rejects(
        custody.connect(),
        (error) => assertSafeError(error, "usb_cdc_worker_authority_rejected"),
      );
      assert.equal(driver.stats.enumerations, 0);
      assert.equal(driver.stats.opens, 0);
    });
  }
});

test("the worker UID is checked against the live process before a driver port exists", () => {
  const authority = authorityFixture();
  const wrongUid = WORKER_UID === 0 ? 1 : WORKER_UID - 1;
  authority.worker.current.worker_uid = wrongUid;
  assert.throws(() => createUsbCdcDriverPort(
    inertDriverInput({ ...DRIVER_BINDING, worker_uid: wrongUid }),
    authority.enrollment,
    authority.worker.port,
  ), (error) => assertSafeError(error, "usb_cdc_worker_principal_rejected"));
});

test("live revocation on an idempotent connect quarantines the single retained handle", async () => {
  const { authority, custody, driver } = setup();
  await custody.connect();
  authority.worker.current.authority_epoch += 1;
  authority.worker.current.revoked = true;
  await assert.rejects(
    custody.connect(),
    (error) => assertSafeError(error, "usb_cdc_worker_authority_rejected"),
  );
  assert.equal(driver.stats.opens, 1);
  assert.equal(driver.stats.closes, 1);
  assert.equal(custody.snapshot().state, "disconnected");
  assert.equal(custody.snapshot().active_handle, false);
});

test("signed revocation and epoch rollback are enforced at every open seam", async (t) => {
  const seams = [
    "pre_discovery",
    "pre_open",
    "post_open_identity",
    "post_activate",
    "connected_revalidation",
  ];
  const dispositions = ["revocation", "epoch_rollback"];
  for (const disposition of dispositions) {
    for (const seam of seams) {
      await t.test(`${disposition} at ${seam}`, async () => {
        const authority = authorityFixture();
        if (disposition === "epoch_rollback") {
          authority.worker.current.trust_root_epoch = 2;
          authority.worker.current.authority_epoch = 2;
          authority.worker.current.revocation_generation = 1;
        }
        let mutated = false;
        const mutate = () => {
          if (mutated) return;
          mutated = true;
          if (disposition === "revocation") {
            authority.worker.current.authority_epoch += 1;
            authority.worker.current.revocation_generation += 1;
            authority.worker.current.revoked = true;
          } else {
            authority.worker.current.trust_root_epoch = 1;
            authority.worker.current.authority_epoch = 1;
            authority.worker.current.revocation_generation = 0;
          }
        };
        const driver = driverFixture({
          enumerate() {
            if (seam === "pre_open") mutate();
            return [candidate()];
          },
          open(query) {
            if (seam === "post_open_identity") mutate();
            return {
              handle: Object.freeze({ fake_handle_id: `${disposition}-${seam}` }),
              opened_hardware_identity: Buffer.from(query.candidate.hardware_identity),
              transport_guarantees: { ...PRE_ACTIVATION_GUARANTEES },
            };
          },
          activate() {
            if (seam === "post_activate") mutate();
            return {
              activated: true,
              opened_hardware_identity: Buffer.from(IDENTITY_A),
              transport_guarantees: { ...GUARANTEES },
            };
          },
        });
        const { custody } = setup({ authority, driver });
        if (seam === "pre_discovery") mutate();
        if (seam === "connected_revalidation") {
          await custody.connect();
          mutate();
        }
        await assert.rejects(
          custody.connect(),
          (error) => assertSafeError(error, "usb_cdc_worker_authority_rejected"),
        );
        const expected = {
          pre_discovery: [0, 0, 0, 0],
          pre_open: [1, 0, 0, 0],
          post_open_identity: [1, 1, 0, 1],
          post_activate: [1, 1, 1, 1],
          connected_revalidation: [1, 1, 1, 1],
        }[seam];
        assert.deepEqual([
          driver.stats.enumerations,
          driver.stats.opens,
          driver.stats.activations,
          driver.stats.closes,
        ], expected);
        assert.notEqual(custody.snapshot().state, "connected");
        await assert.rejects(
          custody.connect(),
          (error) => assertSafeError(error, "usb_cdc_worker_authority_rejected"),
          "a revoked or rollback-invalidated capability must never become reusable",
        );
        assert.equal(driver.stats.opens, expected[1]);
      });
    }
  }
});

test("public projections expose neither signed authority payloads nor reusable driver callbacks", async () => {
  const { authority, custody, driver } = setup();
  const connected = await custody.connect();
  assert.deepEqual(Object.keys(authority.worker.port), [
    "version", "authority_id", "capability_id",
  ]);
  assert.deepEqual(Object.keys(driver.port), [
    "version", "driver_id", "authority_id", "capability_id",
  ]);
  for (const forbidden of [
    "payload",
    "payload_digest",
    "signature",
    "signed_authority_digest",
    "hardware_identity_digest",
    "driver_binary_digest",
    "driver_implementation_digest",
    "enumerate_candidates",
    "open_candidate",
    "activate_handle",
    "close_handle",
  ]) {
    assert.equal(Object.prototype.hasOwnProperty.call(authority.worker.port, forbidden), false);
    assert.equal(Object.prototype.hasOwnProperty.call(driver.port, forbidden), false);
  }
  for (const projection of [
    authority.worker.port,
    driver.port,
    custody.snapshot(),
    connected,
    custody.toJSON(),
  ]) {
    const json = JSON.stringify(projection);
    assert.doesNotMatch(
      json,
      /payload|signature|hardware_identity|driver_binary|driver_implementation|"data":\[/u,
    );
    assertNoRawTransportData(projection);
  }
  assert.throws(() => createWorkerUsbCdcCustody({
    version: 1,
    custody_id: DRIVER_BINDING.custody_id,
    enrollment: authority.enrollment,
    driver_port: driver.port,
    open_authority_port: authority.port,
    worker_authority_port: authority.worker.port,
  }), /already bound to a custody controller/u);
  await custody.close();
});
