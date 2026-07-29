"use strict";

const crypto = require("node:crypto");
const timers = require("node:timers");
const { types: utilTypes } = require("node:util");

const {
  normalizeSignedIpcDispatchRequest,
  verifyIpcDispatchRequestSignature,
} = require("./ipc-contract.js");
const {
  IPC_CHANNEL_BINDING_PROTOCOL,
  IPC_CHANNEL_BINDING_VERSION,
  IPC_CHANNEL_TEST_ONLY_DISPATCH_BOUNDARY_KIND,
  IPC_CHANNEL_TEST_ONLY_DISPATCH_DEADLINE_ENFORCEMENT,
  IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SOURCE,
  IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS,
  IPC_CHANNEL_TEST_ONLY_PROVIDER_ID,
  decodeIpcChannelBody,
  encodeIpcChannelFrame,
  normalizeSignedIpcChannelChallenge,
  normalizeSignedIpcChannelProof,
  normalizeSignedIpcChannelResponse,
  publicKeyDigest,
  signIpcChannelChallenge,
  signIpcChannelProof,
  signIpcChannelResponse,
  verifyIpcChannelChallenge,
  verifyIpcChannelProof,
  verifyIpcChannelResponse,
  _internals: {
    assertClosedObject,
    assertSelectedCdhash,
    assertDigest,
    assertNonce,
    assertSafeErrorCode,
    assertTimestamp,
    assertToken,
    assertUint,
    deepFreeze,
    hashClosed,
  },
} = require("./ipc-channel-binding-contract.js");

const SafeError = Error;
const SafeDate = Date;
const SafePromise = Promise;
const SafeAbortController = AbortController;
const bufferToString = Buffer.prototype.toString;
const cryptoRandomBytes = crypto.randomBytes;
const cryptoCreatePublicKey = crypto.createPublicKey;
const dateParse = Date.parse;
const dateNow = Date.now;
const dateGetTime = Date.prototype.getTime;
const dateToISOString = Date.prototype.toISOString;
const numberIsFinite = Number.isFinite;
const numberIsSafeInteger = Number.isSafeInteger;
const promiseRace = Promise.race;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectKeys = Object.keys;
const objectPrototype = Object.prototype;
const abortControllerAbort = AbortController.prototype.abort;
const abortControllerSignal = objectGetOwnPropertyDescriptor(
  AbortController.prototype,
  "signal",
).get;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regExpTest = RegExp.prototype.test;
const stringEndsWith = String.prototype.endsWith;
const stringSlice = String.prototype.slice;
const timersClearTimeout = timers.clearTimeout;
const timersSetTimeout = timers.setTimeout;
const utilTypesIsProxy = utilTypes.isProxy;
const utilTypesIsKeyObject = utilTypes.isKeyObject;
const weakMapGet = WeakMap.prototype.get;
const weakMapHas = WeakMap.prototype.has;
const weakMapSet = WeakMap.prototype.set;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;

const IPC_CHANNEL_PORT_VERSION = 1;
const IPC_CHANNEL_RESERVATION_PORT_VERSION = 2;
const IPC_CHANNEL_AUTHORITY_PORT_VERSION = 1;
const IPC_CHANNEL_TEST_ONLY_DISPATCH_PORT_VERSION = 1;
const IPC_CHANNEL_SERVER_VERSION = 1;
const IPC_CHANNEL_DEFAULT_LIFETIME_MS = 5_000;
const IPC_CHANNEL_MAX_LIFETIME_MS = 30_000;
const IPC_CHANNEL_DEFAULT_IO_TIMEOUT_MS = 5_000;
const IPC_REQUEST_REPLAY_IDENTITY_DOMAIN =
  "hacker-bob/instrument-broker-ipc-request-replay-identity/v1";
const IPC_CHANNEL_RESERVATION_DOMAIN =
  "hacker-bob/instrument-broker-ipc-channel-reservation/v2";
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;

const CHANNEL_PORTS = new WeakSet();
const CLAIMED_CHANNEL_PORTS = new WeakSet();
const DISPATCH_TIMEOUT_ERRORS = new WeakSet();
const CHANNEL_STATE = new WeakMap();
const RESERVATION_PORTS = new WeakSet();
const RESERVATION_STATE = new WeakMap();
const AUTHORITY_PORTS = new WeakSet();
const AUTHORITY_STATE = new WeakMap();
const TEST_ONLY_DISPATCH_PORTS = new WeakSet();

const CHANNEL_EVIDENCE_FIELDS = objectFreeze([
  "version",
  "connection_identity_digest",
  "descriptor_registration_nonce",
  "descriptor_registration_token_digest",
  "descriptor_binding_scheme_digest",
  "socket_root_identity_digest",
  "socket_identity_digest",
  "listener_identity_digest",
  "acceptor_instance_digest",
  "connection_generation",
  "peer_euid",
  "peer_egid",
  "peer_ruid",
  "peer_rgid",
  "peer_pid",
  "peer_pidversion",
  "peer_audit_token_digest",
  "peer_process_start_token_digest",
  "peer_executable_path_digest",
  "peer_selected_cdhash",
  "peer_selected_cdhash_algorithm",
  "peer_code_directory_hashes_digest",
  "peer_code_signing_identity_digest",
  "peer_code_dynamic_status_digest",
  "peer_mapped_code_identity_digest",
  "native_acceptor_implementation_digest",
  "native_loaded_image_identity_digest",
  "accepted_and_registered_before_javascript",
  "javascript_descriptor_handoff_used",
  "descriptor_provenance_complete",
  "production_ready",
]);
const DESCRIPTOR_READBACK_FIELDS = objectFreeze([
  "version",
  "connection_identity_digest",
  "descriptor_registration_token_digest",
  "peer_audit_token_digest",
  "peer_process_start_token_digest",
  "peer_mapped_code_identity_digest",
  "descriptor_readback_digest",
  "native_loaded_image_identity_digest",
  "descriptor_provenance_complete",
  "production_ready",
]);
const AUTHORITY_RECORD_FIELDS = objectFreeze([
  "version",
  "authority_id",
  "authority_epoch",
  "authority_digest",
  "server_bundle_identity_digest",
  "server_launch_attestation_digest",
  "server_process_start_token_digest",
  "trusted_monotonic_coordinate",
  "trusted",
  "revoked",
]);
const RESERVATION_RECORD_FIELDS = objectFreeze([
  "version",
  "reservation_id",
  "reservation_kind",
  "reservation_identity_digest",
  "claim_digest",
  "reservation_attempt_nonce",
  "disposition",
  "one_use",
  "reservation_receipt_digest",
]);
const SERVER_INPUT_FIELDS = objectFreeze([
  "channel_port",
  "reservation_port",
  "authority_port",
  "server_identity",
  "expected_request_identity",
  "client_attestation",
  "non_hardware_test_only_dispatch_port",
  "now",
  "challenge_lifetime_ms",
  "io_timeout_ms",
]);

function channelBindingError() {
  const error = new SafeError("IPC native channel binding was rejected");
  objectDefineProperty(error, "code", {
    value: "ipc_channel_binding_rejected",
    writable: false,
    enumerable: false,
    configurable: false,
  });
  return error;
}

function admittedOutcomeAmbiguousError() {
  const error = new SafeError(
    "IPC native channel outcome is ambiguous and must not be retried",
  );
  objectDefineProperty(error, "code", {
    value: "ipc_channel_binding_admitted_outcome_ambiguous",
    writable: false,
    enumerable: false,
    configurable: false,
  });
  objectDefineProperty(error, "non_retryable", {
    value: true,
    writable: false,
    enumerable: false,
    configurable: false,
  });
  return error;
}

function dispatchTimeoutError() {
  const error = new SafeError("IPC dispatch exceeded its signed deadline");
  reflectApply(weakSetAdd, DISPATCH_TIMEOUT_ERRORS, [error]);
  return error;
}

function isDispatchTimeoutError(error) {
  return error != null && typeof error === "object"
    && reflectApply(weakSetHas, DISPATCH_TIMEOUT_ERRORS, [error]);
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || utilTypesIsProxy(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== objectPrototype && prototype !== null) return false;
  const keys = reflectOwnKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    if (typeof keys[index] !== "string") return false;
    const descriptor = objectGetOwnPropertyDescriptor(value, keys[index]);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true) return false;
  }
  return true;
}

function assertExactDataObject(value, fields) {
  if (!isPlainDataObject(value)) throw channelBindingError();
  const keys = objectKeys(value);
  if (keys.length !== fields.length) throw channelBindingError();
  for (let fieldIndex = 0; fieldIndex < fields.length; fieldIndex += 1) {
    let found = false;
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      if (fields[fieldIndex] === keys[keyIndex]) found = true;
    }
    if (!found) throw channelBindingError();
  }
  return value;
}

function assertFunction(value) {
  if (typeof value !== "function" || utilTypesIsProxy(value)) throw channelBindingError();
  return value;
}

function assertChannelEvidence(input) {
  assertExactDataObject(input, CHANNEL_EVIDENCE_FIELDS);
  if (input.version !== 1
      || input.accepted_and_registered_before_javascript !== true
      || input.javascript_descriptor_handoff_used !== false
      || input.descriptor_provenance_complete !== true
      || input.production_ready !== false) throw channelBindingError();
  for (let index = 1; index < CHANNEL_EVIDENCE_FIELDS.length; index += 1) {
    const field = CHANNEL_EVIDENCE_FIELDS[index];
    if (reflectApply(stringEndsWith, field, ["_digest"])) {
      assertDigest(input[field]);
    }
  }
  assertUint(input.peer_selected_cdhash_algorithm, 0xffff_ffff);
  assertSelectedCdhash(
    input.peer_selected_cdhash,
    input.peer_selected_cdhash_algorithm,
  );
  assertNonce(input.descriptor_registration_nonce);
  if (typeof input.connection_generation !== "string"
      || !reflectApply(regExpTest, DECIMAL_PATTERN,
        [input.connection_generation])) {
    throw channelBindingError();
  }
  const integerFields = [
    "peer_euid", "peer_egid", "peer_ruid", "peer_rgid", "peer_pid", "peer_pidversion",
  ];
  for (let index = 0; index < integerFields.length; index += 1) {
    assertUint(input[integerFields[index]], 0xffff_ffff);
  }
  return deepFreeze({ ...input });
}

function createIpcNativeAcceptedChannelPort(input) {
  assertExactDataObject(input, [
    "channel_id",
    "evidence",
    "write_challenge",
    "read_request_and_proof",
    "read_descriptor_identity",
    "write_response",
    "close",
  ]);
  const evidence = assertChannelEvidence(input.evidence);
  const port = deepFreeze({
    version: IPC_CHANNEL_PORT_VERSION,
    channel_id: assertToken(input.channel_id),
    evidence,
    production_ready: false,
    readiness_blockers: objectFreeze([
      "signed_immutable_native_prebuild_missing",
      "privileged_launcher_channel_custody_missing",
      "native_channel_hil_missing",
    ]),
  });
  reflectApply(weakSetAdd, CHANNEL_PORTS, [port]);
  reflectApply(weakMapSet, CHANNEL_STATE, [port, objectFreeze({
    write_challenge: assertFunction(input.write_challenge),
    read_request: assertFunction(input.read_request_and_proof),
    read_identity: assertFunction(input.read_descriptor_identity),
    write_response: assertFunction(input.write_response),
    close: assertFunction(input.close),
  })]);
  return port;
}

function assertChannelPort(port) {
  if (port == null || typeof port !== "object" || utilTypesIsProxy(port)
      || !objectIsFrozen(port)
      || !reflectApply(weakSetHas, CHANNEL_PORTS, [port])
      || !reflectApply(weakMapHas, CHANNEL_STATE, [port])) throw channelBindingError();
  return port;
}

function createIpcTestOnlyDeterministicMockCooperativeDispatchPort(input) {
  assertExactDataObject(input, [
    "provider_descriptor_digest",
    "provider_implementation_digest",
    "fixture_script",
  ]);
  const fixtureScript = assertTestOnlyFixtureScript(input.fixture_script);
  const port = deepFreeze({
    version: IPC_CHANNEL_TEST_ONLY_DISPATCH_PORT_VERSION,
    kind: IPC_CHANNEL_TEST_ONLY_DISPATCH_BOUNDARY_KIND,
    provider_id: IPC_CHANNEL_TEST_ONLY_PROVIDER_ID,
    provider_descriptor_digest: assertDigest(input.provider_descriptor_digest),
    provider_implementation_digest: assertDigest(input.provider_implementation_digest),
    fixture_source: IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SOURCE,
    fixture_script: fixtureScript,
    deadline_enforcement: IPC_CHANNEL_TEST_ONLY_DISPATCH_DEADLINE_ENFORCEMENT,
    same_event_loop_cooperative: true,
    separate_identity: false,
    independently_preemptible: false,
    worker_trusted_deadline_recheck: false,
    hardware_authority: false,
    production_ready: false,
    readiness_blockers: objectFreeze([
      "test_only_deterministic_mock_dispatch",
      "independent_preemptible_dispatch_boundary_missing",
      "worker_trusted_deadline_recheck_missing",
      "hardware_dispatch_forbidden",
    ]),
  });
  reflectApply(weakSetAdd, TEST_ONLY_DISPATCH_PORTS, [port]);
  return port;
}

function assertTestOnlyFixtureScript(value) {
  if (value !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.complete
      && value !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.reject
      && value !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.invalid_error_code
      && value !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.unavailable
      && value !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.never_settle
      && value
        !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS
          .busy_loop_300ms_then_complete) {
    throw channelBindingError();
  }
  return value;
}

function assertTestOnlyDispatchPort(port) {
  if (port == null || typeof port !== "object" || utilTypesIsProxy(port)
      || !objectIsFrozen(port)
      || !reflectApply(weakSetHas, TEST_ONLY_DISPATCH_PORTS, [port])
      || port.version !== IPC_CHANNEL_TEST_ONLY_DISPATCH_PORT_VERSION
      || port.kind !== IPC_CHANNEL_TEST_ONLY_DISPATCH_BOUNDARY_KIND
      || port.provider_id !== IPC_CHANNEL_TEST_ONLY_PROVIDER_ID
      || port.fixture_source !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SOURCE
      || assertTestOnlyFixtureScript(port.fixture_script) !== port.fixture_script
      || port.deadline_enforcement
        !== IPC_CHANNEL_TEST_ONLY_DISPATCH_DEADLINE_ENFORCEMENT
      || port.same_event_loop_cooperative !== true
      || port.separate_identity !== false
      || port.independently_preemptible !== false
      || port.worker_trusted_deadline_recheck !== false
      || port.hardware_authority !== false
      || port.production_ready !== false) {
    throw channelBindingError();
  }
  return port;
}

function deterministicMockResult(projection, fixtureScript, status, errorCode) {
  return objectFreeze({
    status,
    error_code: errorCode,
    operation_result_digest: hashClosed(
      "hacker-bob/instrument-broker-ipc-test-only-deterministic-mock/v1",
      "fixture_operation_result",
      objectFreeze({
        version: 1,
        fixture_script: fixtureScript,
        dispatch_projection: projection,
        status,
        error_code: errorCode,
      }),
    ),
  });
}

function executeClosedDeterministicMockFixture(fixtureScript, projection) {
  if (fixtureScript
      === IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.never_settle) {
    return new SafePromise(() => {});
  }
  if (fixtureScript
      === IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.unavailable) {
    throw channelBindingError();
  }
  if (fixtureScript
      === IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS
        .busy_loop_300ms_then_complete) {
    const stop = reflectApply(dateNow, SafeDate, []) + 300;
    while (reflectApply(dateNow, SafeDate, []) < stop) {}
  }
  if (fixtureScript
      === IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.reject) {
    return deterministicMockResult(
      projection,
      fixtureScript,
      "rejected",
      "dispatch_rejected",
    );
  }
  if (fixtureScript
      === IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.invalid_error_code) {
    return deterministicMockResult(
      projection,
      fixtureScript,
      "rejected",
      "operator_secret_marker",
    );
  }
  return deterministicMockResult(projection, fixtureScript, "completed", null);
}

function createIpcChannelReservationPort(input) {
  assertExactDataObject(input, [
    "reservation_port_id", "reserve_reservation", "read_reservation",
  ]);
  const port = deepFreeze({
    version: IPC_CHANNEL_RESERVATION_PORT_VERSION,
    reservation_port_id: assertToken(input.reservation_port_id),
    durable_store_required: true,
    one_use_required: true,
    production_ready: false,
  });
  reflectApply(weakSetAdd, RESERVATION_PORTS, [port]);
  reflectApply(weakMapSet, RESERVATION_STATE, [port, objectFreeze({
    reserve: assertFunction(input.reserve_reservation),
    read: assertFunction(input.read_reservation),
  })]);
  return port;
}

function assertReservationPort(port) {
  if (port == null || typeof port !== "object" || utilTypesIsProxy(port)
      || !objectIsFrozen(port)
      || !reflectApply(weakSetHas, RESERVATION_PORTS, [port])
      || !reflectApply(weakMapHas, RESERVATION_STATE, [port])) {
    throw channelBindingError();
  }
  return port;
}

function createIpcChannelAuthorityPort(input) {
  assertExactDataObject(input, ["authority_id", "read_current_authority"]);
  const port = deepFreeze({
    version: IPC_CHANNEL_AUTHORITY_PORT_VERSION,
    authority_id: assertToken(input.authority_id),
    production_ready: false,
  });
  reflectApply(weakSetAdd, AUTHORITY_PORTS, [port]);
  reflectApply(weakMapSet, AUTHORITY_STATE, [port, objectFreeze({
    read: assertFunction(input.read_current_authority),
  })]);
  return port;
}

function assertAuthorityPort(port) {
  if (port == null || typeof port !== "object" || utilTypesIsProxy(port)
      || !objectIsFrozen(port)
      || !reflectApply(weakSetHas, AUTHORITY_PORTS, [port])
      || !reflectApply(weakMapHas, AUTHORITY_STATE, [port])) {
    throw channelBindingError();
  }
  return port;
}

function normalizeAuthorityRecord(input, authorityPort) {
  assertExactDataObject(input, AUTHORITY_RECORD_FIELDS);
  if (input.version !== IPC_CHANNEL_AUTHORITY_PORT_VERSION
      || input.authority_id !== authorityPort.authority_id
      || input.trusted !== true || input.revoked !== false) throw channelBindingError();
  assertUint(input.authority_epoch);
  assertDigest(input.authority_digest);
  assertDigest(input.server_bundle_identity_digest);
  assertDigest(input.server_launch_attestation_digest);
  assertDigest(input.server_process_start_token_digest);
  if (typeof input.trusted_monotonic_coordinate !== "string"
      || !reflectApply(regExpTest, DECIMAL_PATTERN,
        [input.trusted_monotonic_coordinate])) {
    throw channelBindingError();
  }
  return deepFreeze({ ...input });
}

async function readAuthority(port) {
  assertAuthorityPort(port);
  let value;
  try {
    value = await reflectApply(
      reflectApply(weakMapGet, AUTHORITY_STATE, [port]).read,
      undefined,
      [objectFreeze({ version: 1, purpose: "ipc_channel_authority_readback" })],
    );
    return normalizeAuthorityRecord(value, port);
  } catch {
    throw channelBindingError();
  }
}

function sameAuthority(left, right) {
  const fields = AUTHORITY_RECORD_FIELDS;
  for (let index = 0; index < fields.length; index += 1) {
    if (left[fields[index]] !== right[fields[index]]) return false;
  }
  return true;
}

function readDescriptor(port) {
  assertChannelPort(port);
  let value;
  try {
    value = reflectApply(
      reflectApply(weakMapGet, CHANNEL_STATE, [port]).read_identity,
      undefined,
      [],
    );
    assertExactDataObject(value, DESCRIPTOR_READBACK_FIELDS);
    if (value.version !== 1 || value.descriptor_provenance_complete !== true
        || value.production_ready !== false
        || value.connection_identity_digest !== port.evidence.connection_identity_digest
        || value.descriptor_registration_token_digest
          !== port.evidence.descriptor_registration_token_digest
        || value.peer_audit_token_digest !== port.evidence.peer_audit_token_digest
        || value.peer_process_start_token_digest
          !== port.evidence.peer_process_start_token_digest
        || value.peer_mapped_code_identity_digest
          !== port.evidence.peer_mapped_code_identity_digest
        || value.native_loaded_image_identity_digest
          !== port.evidence.native_loaded_image_identity_digest) {
      throw channelBindingError();
    }
    for (let index = 1; index <= 7; index += 1) {
      assertDigest(value[DESCRIPTOR_READBACK_FIELDS[index]]);
    }
    return deepFreeze({ ...value });
  } catch {
    throw channelBindingError();
  }
}

function sameDescriptor(left, right) {
  const fields = DESCRIPTOR_READBACK_FIELDS;
  for (let index = 0; index < fields.length; index += 1) {
    if (left[fields[index]] !== right[fields[index]]) return false;
  }
  return true;
}

function reservationId(kind, claimDigest) {
  return `ipc-reservation:${kind}:${reflectApply(stringSlice, claimDigest, [0, 48])}`;
}

function normalizeReservationRecord(input, query) {
  assertExactDataObject(input, RESERVATION_RECORD_FIELDS);
  if (input.version !== IPC_CHANNEL_RESERVATION_PORT_VERSION
      || input.reservation_id !== query.reservation_id
      || input.reservation_kind !== query.reservation_kind
      || input.reservation_identity_digest !== query.reservation_identity_digest
      || input.claim_digest !== query.claim_digest
      || input.reservation_attempt_nonce !== query.reservation_attempt_nonce
      || input.disposition !== "created" || input.one_use !== true) {
    throw channelBindingError();
  }
  assertDigest(input.reservation_identity_digest);
  assertDigest(input.claim_digest);
  assertNonce(input.reservation_attempt_nonce);
  const receiptBasis = deepFreeze({
    version: input.version,
    reservation_id: input.reservation_id,
    reservation_kind: input.reservation_kind,
    reservation_identity_digest: input.reservation_identity_digest,
    claim_digest: input.claim_digest,
    reservation_attempt_nonce: input.reservation_attempt_nonce,
    disposition: input.disposition,
    one_use: input.one_use,
  });
  const expectedReceipt = hashClosed(
    IPC_CHANNEL_RESERVATION_DOMAIN,
    "reservation_receipt",
    receiptBasis,
  );
  if (assertDigest(input.reservation_receipt_digest) !== expectedReceipt) {
    throw channelBindingError();
  }
  return deepFreeze({ ...receiptBasis, reservation_receipt_digest: expectedReceipt });
}

async function reserveDurably(port, kind, claim, reservationIdentity = null) {
  assertReservationPort(port);
  const claimDigest = hashClosed(
    IPC_CHANNEL_RESERVATION_DOMAIN,
    `${kind}_claim`,
    claim,
  );
  const reservationIdentityDigest = reservationIdentity == null
    ? claimDigest
    : hashClosed(
      IPC_CHANNEL_RESERVATION_DOMAIN,
      `${kind}_reservation_identity`,
      reservationIdentity,
    );
  const query = deepFreeze({
    version: IPC_CHANNEL_RESERVATION_PORT_VERSION,
    reservation_id: reservationId(kind, reservationIdentityDigest),
    reservation_kind: kind,
    reservation_identity_digest: reservationIdentityDigest,
    claim_digest: claimDigest,
    reservation_attempt_nonce: randomNonce(),
  });
  const state = reflectApply(weakMapGet, RESERVATION_STATE, [port]);
  try {
    // The reserve reply is intentionally not trusted. The exact durable record
    // is always read, including after a thrown, lost, or malformed reply.
    try {
      await reflectApply(state.reserve, undefined, [deepFreeze({ ...query, claim })]);
    } catch {}
    const readback = await reflectApply(state.read, undefined, [query]);
    return normalizeReservationRecord(readback, query);
  } catch {
    throw channelBindingError();
  }
}

function nowValue(now) {
  let value;
  try {
    value = reflectApply(now, undefined, []);
  } catch {
    throw channelBindingError();
  }
  let milliseconds;
  try {
    milliseconds = typeof value === "number"
      ? value
      : reflectApply(dateGetTime, value, []);
  } catch {
    throw channelBindingError();
  }
  if (!numberIsFinite(milliseconds)) throw channelBindingError();
  return new SafeDate(milliseconds);
}

function timestampMilliseconds(value) {
  const milliseconds = reflectApply(dateParse, SafeDate, [value]);
  if (!numberIsFinite(milliseconds)) throw channelBindingError();
  return milliseconds;
}

function assertAdmissionWindow(now, challengeOrBase, pair, previousMilliseconds) {
  const current = nowValue(now);
  const currentMilliseconds = reflectApply(dateGetTime, current, []);
  const payload = challengeOrBase.payload || challengeOrBase;
  if (currentMilliseconds < previousMilliseconds
      || timestampMilliseconds(payload.expires_at) <= currentMilliseconds) {
    throw channelBindingError();
  }
  if (pair != null
      && (timestampMilliseconds(pair.proof.payload.proof_deadline)
          <= currentMilliseconds
        || timestampMilliseconds(pair.request.payload.deadline)
          <= currentMilliseconds
        || timestampMilliseconds(pair.request.payload.issued_at)
          > currentMilliseconds)) {
    throw channelBindingError();
  }
  return objectFreeze({ current, currentMilliseconds });
}

function signedDispatchDeadlineMilliseconds(challenge, pair) {
  let deadline = timestampMilliseconds(challenge.payload.expires_at);
  const requestDeadline = timestampMilliseconds(pair.request.payload.deadline);
  const proofDeadline = timestampMilliseconds(pair.proof.payload.proof_deadline);
  if (requestDeadline < deadline) deadline = requestDeadline;
  if (proofDeadline < deadline) deadline = proofDeadline;
  return deadline;
}

function abortDispatch(controller, reason) {
  try {
    reflectApply(abortControllerAbort, controller, [reason]);
  } catch {}
}

async function invokeTestOnlyCooperativeDispatchWithinDeadline(
  dispatchPort,
  projection,
  deadlineMilliseconds,
  currentMilliseconds,
) {
  assertTestOnlyDispatchPort(dispatchPort);
  const remaining = deadlineMilliseconds - currentMilliseconds;
  if (!numberIsFinite(remaining) || remaining <= 0) throw dispatchTimeoutError();
  const controller = new SafeAbortController();
  const signal = reflectApply(abortControllerSignal, controller, []);
  const timeoutError = dispatchTimeoutError();
  let timer = null;
  // This timer is a fixture liveness backstop, not an independently preemptible
  // authorization boundary. The closed busy-loop fixture can stall this event
  // loop. The
  // post-dispatch signed-deadline fence therefore converts every overrun to an
  // ambiguous, non-retryable result, and every signed projection says that this
  // exact deterministic-mock seam has no hardware or production authority.
  const timeoutPromise = new SafePromise((_resolve, reject) => {
    timer = reflectApply(timersSetTimeout, timers, [() => {
      abortDispatch(controller, timeoutError);
      reject(timeoutError);
    }, remaining]);
  });
  const callPromise = new SafePromise((resolve, reject) => {
    try {
      resolve(executeClosedDeterministicMockFixture(
        dispatchPort.fixture_script,
        projection,
      ));
    } catch (error) {
      reject(error);
    }
  });
  try {
    const result = await reflectApply(promiseRace, SafePromise, [[
      callPromise,
      timeoutPromise,
    ]]);
    return { controller, result, signal };
  } catch (error) {
    abortDispatch(controller, error);
    throw error;
  } finally {
    if (timer != null) reflectApply(timersClearTimeout, timers, [timer]);
  }
}

function randomNonce() {
  return reflectApply(bufferToString,
    reflectApply(cryptoRandomBytes, crypto, [24]), ["base64url"]);
}

function normalizeServerInput(input) {
  assertExactDataObject(input, SERVER_INPUT_FIELDS);
  assertChannelPort(input.channel_port);
  assertReservationPort(input.reservation_port);
  assertAuthorityPort(input.authority_port);
  const dispatchPort = assertTestOnlyDispatchPort(
    input.non_hardware_test_only_dispatch_port,
  );
  assertExactDataObject(input.server_identity, [
    "server_principal_id", "response_key_id", "response_public_key_digest", "private_key",
  ]);
  assertExactDataObject(input.expected_request_identity, [
    "request_key_id", "request_public_key_digest", "request_public_key",
    "ipc_peer_principal_id", "execution_principal_id", "provider_id",
    "provider_descriptor_digest", "provider_implementation_digest",
  ]);
  assertExactDataObject(input.client_attestation, [
    "client_bundle_identity_digest", "client_launch_attestation_digest",
  ]);
  const responseDigest = publicKeyDigest(input.server_identity.private_key);
  const requestDigest = publicKeyDigest(input.expected_request_identity.request_public_key);
  const providerId = assertToken(input.expected_request_identity.provider_id);
  const providerDescriptorDigest = assertDigest(
    input.expected_request_identity.provider_descriptor_digest,
  );
  const providerImplementationDigest = assertDigest(
    input.expected_request_identity.provider_implementation_digest,
  );
  if (assertDigest(input.server_identity.response_public_key_digest) !== responseDigest
      || assertDigest(input.expected_request_identity.request_public_key_digest)
        !== requestDigest
      || responseDigest === requestDigest
      || input.server_identity.response_key_id
        === input.expected_request_identity.request_key_id
      || providerId !== IPC_CHANNEL_TEST_ONLY_PROVIDER_ID
      || providerId !== dispatchPort.provider_id
      || providerDescriptorDigest !== dispatchPort.provider_descriptor_digest
      || providerImplementationDigest
        !== dispatchPort.provider_implementation_digest) throw channelBindingError();
  const lifetime = input.challenge_lifetime_ms == null
    ? IPC_CHANNEL_DEFAULT_LIFETIME_MS : input.challenge_lifetime_ms;
  const ioTimeout = input.io_timeout_ms == null
    ? IPC_CHANNEL_DEFAULT_IO_TIMEOUT_MS : input.io_timeout_ms;
  if (!numberIsSafeInteger(lifetime) || lifetime < 1
      || lifetime > IPC_CHANNEL_MAX_LIFETIME_MS
      || !numberIsSafeInteger(ioTimeout) || ioTimeout < 1
      || ioTimeout > IPC_CHANNEL_MAX_LIFETIME_MS) throw channelBindingError();
  return objectFreeze({
    channel: input.channel_port,
    reservation: input.reservation_port,
    authority: input.authority_port,
    server: objectFreeze({
      server_principal_id: assertToken(input.server_identity.server_principal_id, "principal"),
      response_key_id: assertToken(input.server_identity.response_key_id, "ipc-key"),
      response_public_key_digest: responseDigest,
      private_key: input.server_identity.private_key,
    }),
    request: objectFreeze({
      request_key_id: assertToken(input.expected_request_identity.request_key_id, "ipc-key"),
      request_public_key_digest: requestDigest,
      request_public_key: input.expected_request_identity.request_public_key,
      ipc_peer_principal_id: assertToken(
        input.expected_request_identity.ipc_peer_principal_id, "principal",
      ),
      execution_principal_id: assertToken(
        input.expected_request_identity.execution_principal_id, "principal",
      ),
      provider_id: providerId,
      provider_descriptor_digest: providerDescriptorDigest,
      provider_implementation_digest: providerImplementationDigest,
    }),
    client: objectFreeze({
      client_bundle_identity_digest: assertDigest(
        input.client_attestation.client_bundle_identity_digest,
      ),
      client_launch_attestation_digest: assertDigest(
        input.client_attestation.client_launch_attestation_digest,
      ),
    }),
    dispatch: dispatchPort,
    now: assertFunction(input.now),
    lifetime,
    io_timeout: ioTimeout,
  });
}

function challengeBase(config, authority, descriptor, issuedAt, expiresAt) {
  const evidence = config.channel.evidence;
  return deepFreeze({
    version: IPC_CHANNEL_BINDING_VERSION,
    protocol: IPC_CHANNEL_BINDING_PROTOCOL,
    challenge_nonce: randomNonce(),
    listener_identity_digest: evidence.listener_identity_digest,
    socket_root_identity_digest: evidence.socket_root_identity_digest,
    socket_identity_digest: evidence.socket_identity_digest,
    connection_generation: evidence.connection_generation,
    acceptor_instance_digest: evidence.acceptor_instance_digest,
    native_acceptor_implementation_digest:
      evidence.native_acceptor_implementation_digest,
    connection_identity_digest: evidence.connection_identity_digest,
    descriptor_registration_nonce: evidence.descriptor_registration_nonce,
    descriptor_registration_token_digest:
      evidence.descriptor_registration_token_digest,
    descriptor_binding_scheme_digest: evidence.descriptor_binding_scheme_digest,
    peer_euid: evidence.peer_euid,
    peer_egid: evidence.peer_egid,
    peer_ruid: evidence.peer_ruid,
    peer_rgid: evidence.peer_rgid,
    peer_pid: evidence.peer_pid,
    peer_pidversion: evidence.peer_pidversion,
    peer_audit_token_digest: evidence.peer_audit_token_digest,
    peer_process_start_token_digest: evidence.peer_process_start_token_digest,
    peer_executable_path_digest: evidence.peer_executable_path_digest,
    peer_selected_cdhash: evidence.peer_selected_cdhash,
    peer_selected_cdhash_algorithm:
      evidence.peer_selected_cdhash_algorithm,
    peer_code_directory_hashes_digest:
      evidence.peer_code_directory_hashes_digest,
    peer_code_signing_identity_digest: evidence.peer_code_signing_identity_digest,
    peer_code_dynamic_status_digest: evidence.peer_code_dynamic_status_digest,
    peer_mapped_code_identity_digest: evidence.peer_mapped_code_identity_digest,
    native_loaded_image_identity_digest: evidence.native_loaded_image_identity_digest,
    server_principal_id: config.server.server_principal_id,
    server_bundle_identity_digest: authority.server_bundle_identity_digest,
    server_launch_attestation_digest: authority.server_launch_attestation_digest,
    server_process_start_token_digest: authority.server_process_start_token_digest,
    expected_request_key_id: config.request.request_key_id,
    expected_request_public_key_digest: config.request.request_public_key_digest,
    ipc_peer_principal_id: config.request.ipc_peer_principal_id,
    execution_principal_id: config.request.execution_principal_id,
    provider_id: config.request.provider_id,
    provider_descriptor_digest: config.request.provider_descriptor_digest,
    provider_implementation_digest: config.request.provider_implementation_digest,
    dispatch_boundary_kind: config.dispatch.kind,
    dispatch_fixture_source: config.dispatch.fixture_source,
    dispatch_fixture_script: config.dispatch.fixture_script,
    dispatch_deadline_enforcement: config.dispatch.deadline_enforcement,
    dispatch_separate_identity: config.dispatch.separate_identity,
    dispatch_independently_preemptible: config.dispatch.independently_preemptible,
    dispatch_worker_trusted_deadline_recheck:
      config.dispatch.worker_trusted_deadline_recheck,
    dispatch_hardware_authority: config.dispatch.hardware_authority,
    dispatch_production_ready: config.dispatch.production_ready,
    startup_authority_digest: authority.authority_digest,
    authority_epoch: authority.authority_epoch,
    trusted_monotonic_coordinate: authority.trusted_monotonic_coordinate,
    issued_at: issuedAt,
    expires_at: expiresAt,
    descriptor_initial_readback_digest: descriptor.descriptor_readback_digest,
  });
}

function validateRequestAndProof(body, challenge, config, current) {
  const decoded = decodeIpcChannelBody(body);
  assertClosedObject(decoded, ["version", "kind", "request", "proof"]);
  if (decoded.version !== IPC_CHANNEL_BINDING_VERSION
      || decoded.kind !== "instrument_channel_request_and_proof") {
    throw channelBindingError();
  }
  const request = normalizeSignedIpcDispatchRequest(decoded.request);
  const proof = normalizeSignedIpcChannelProof(decoded.proof);
  if (request.authentication.key_id !== config.request.request_key_id
      || request.authentication.public_key_digest
        !== config.request.request_public_key_digest
      || !verifyIpcDispatchRequestSignature(request, config.request.request_public_key)
      || proof.authentication.key_id !== config.request.request_key_id
      || proof.authentication.public_key_digest !== config.request.request_public_key_digest
      || !verifyIpcChannelProof(proof, config.request.request_public_key)
      || proof.payload.challenge_digest !== challenge.challenge_digest
      || proof.payload.signed_request_digest !== request.request_digest
      || proof.payload.request_nonce !== request.payload.nonce
      || proof.payload.request_sequence !== request.payload.sequence
      || proof.payload.request_key_id !== config.request.request_key_id
      || proof.payload.request_public_key_digest
        !== config.request.request_public_key_digest
      || proof.payload.ipc_peer_principal_id !== config.request.ipc_peer_principal_id
      || proof.payload.execution_principal_id !== config.request.execution_principal_id
      || proof.payload.provider_id !== config.request.provider_id
      || proof.payload.provider_descriptor_digest
        !== config.request.provider_descriptor_digest
      || proof.payload.provider_implementation_digest
        !== config.request.provider_implementation_digest
      || proof.payload.client_bundle_identity_digest
        !== config.client.client_bundle_identity_digest
      || proof.payload.client_launch_attestation_digest
        !== config.client.client_launch_attestation_digest
      || request.payload.ipc_peer_principal_id !== config.request.ipc_peer_principal_id
      || request.payload.execution_principal_id !== config.request.execution_principal_id
      || request.payload.provider_id !== config.request.provider_id
      || request.payload.provider_descriptor_digest
        !== config.request.provider_descriptor_digest
      || challenge.payload.provider_implementation_digest
        !== config.request.provider_implementation_digest
      || reflectApply(dateParse, SafeDate, [proof.payload.proof_deadline])
        <= reflectApply(dateGetTime, current, [])
      || reflectApply(dateParse, SafeDate, [request.payload.deadline])
        <= reflectApply(dateGetTime, current, [])
      || reflectApply(dateParse, SafeDate, [request.payload.issued_at])
        > reflectApply(dateGetTime, current, [])
      || reflectApply(dateParse, SafeDate, [challenge.payload.expires_at])
        <= reflectApply(dateGetTime, current, [])) {
    throw channelBindingError();
  }
  return objectFreeze({ request, proof });
}

async function executeIpcChannelBindingServerConnection(input) {
  let config = null;
  let claimedChannel = null;
  let admitted = false;
  try {
    if (input == null || typeof input !== "object" || utilTypesIsProxy(input)) {
      throw channelBindingError();
    }
    const channelDescriptor = objectGetOwnPropertyDescriptor(input, "channel_port");
    if (channelDescriptor == null || !objectHasOwn(channelDescriptor, "value")) {
      throw channelBindingError();
    }
    const candidateChannel = assertChannelPort(channelDescriptor.value);
    if (reflectApply(weakSetHas, CLAIMED_CHANNEL_PORTS, [candidateChannel])) {
      throw channelBindingError();
    }
    reflectApply(weakSetAdd, CLAIMED_CHANNEL_PORTS, [candidateChannel]);
    claimedChannel = candidateChannel;
    config = normalizeServerInput(input);
    const channelState = reflectApply(weakMapGet, CHANNEL_STATE, [config.channel]);
    const authorityBefore = await readAuthority(config.authority);
    const descriptorBefore = readDescriptor(config.channel);
    const issued = nowValue(config.now);
    let lastNowMilliseconds = reflectApply(dateGetTime, issued, []);
    const expires = new SafeDate(
      lastNowMilliseconds + config.lifetime,
    );
    const base = challengeBase(
      config,
      authorityBefore,
      descriptorBefore,
      reflectApply(dateToISOString, issued, []),
      reflectApply(dateToISOString, expires, []),
    );
    const challengeClaim = deepFreeze({
      version: 1,
      reservation_kind: "challenge",
      channel_id: config.channel.channel_id,
      connection_identity_digest: base.connection_identity_digest,
      descriptor_registration_token_digest:
        base.descriptor_registration_token_digest,
      challenge_nonce: base.challenge_nonce,
      expected_request_key_id: base.expected_request_key_id,
      expected_request_public_key_digest:
        base.expected_request_public_key_digest,
      provider_id: base.provider_id,
      provider_descriptor_digest: base.provider_descriptor_digest,
      provider_implementation_digest: base.provider_implementation_digest,
      dispatch_boundary_kind: base.dispatch_boundary_kind,
      dispatch_fixture_source: base.dispatch_fixture_source,
      dispatch_fixture_script: base.dispatch_fixture_script,
      dispatch_deadline_enforcement: base.dispatch_deadline_enforcement,
      dispatch_hardware_authority: base.dispatch_hardware_authority,
      dispatch_production_ready: base.dispatch_production_ready,
      peer_process_start_token_digest: base.peer_process_start_token_digest,
      startup_authority_digest: base.startup_authority_digest,
      authority_epoch: base.authority_epoch,
      descriptor_initial_readback_digest:
        base.descriptor_initial_readback_digest,
    });
    let challengeReservation;
    let challengeReservationError = null;
    try {
      challengeReservation = await reserveDurably(
        config.reservation,
        "challenge",
        challengeClaim,
      );
    } catch (error) {
      challengeReservationError = error;
    }
    let window = assertAdmissionWindow(
      config.now,
      base,
      null,
      lastNowMilliseconds,
    );
    lastNowMilliseconds = window.currentMilliseconds;
    const authorityAfterChallenge = await readAuthority(config.authority);
    window = assertAdmissionWindow(config.now, base, null, lastNowMilliseconds);
    lastNowMilliseconds = window.currentMilliseconds;
    const descriptorAfterChallenge = readDescriptor(config.channel);
    if (challengeReservationError != null
        || !sameAuthority(authorityBefore, authorityAfterChallenge)
        || !sameDescriptor(descriptorBefore, descriptorAfterChallenge)) {
      throw channelBindingError();
    }
    const challenge = signIpcChannelChallenge({
      ...base,
      challenge_reservation_receipt_digest:
        challengeReservation.reservation_receipt_digest,
    }, {
      key_id: config.server.response_key_id,
      public_key_digest: config.server.response_public_key_digest,
      private_key: config.server.private_key,
    });
    await reflectApply(channelState.write_challenge, undefined,
      [encodeIpcChannelFrame(challenge), config.io_timeout]);
    window = assertAdmissionWindow(config.now, challenge, null, lastNowMilliseconds);
    lastNowMilliseconds = window.currentMilliseconds;
    const requestBody = await reflectApply(channelState.read_request, undefined,
      [config.io_timeout]);
    window = assertAdmissionWindow(config.now, challenge, null, lastNowMilliseconds);
    lastNowMilliseconds = window.currentMilliseconds;
    const pair = validateRequestAndProof(
      requestBody,
      challenge,
      config,
      window.current,
    );
    const requestReplayIdentity = deepFreeze({
      version: 1,
      domain: IPC_REQUEST_REPLAY_IDENTITY_DOMAIN,
      request_key_id: config.request.request_key_id,
      request_public_key_digest: config.request.request_public_key_digest,
      ipc_peer_principal_id: config.request.ipc_peer_principal_id,
      execution_principal_id: config.request.execution_principal_id,
      provider_id: config.request.provider_id,
      provider_descriptor_digest: config.request.provider_descriptor_digest,
      provider_implementation_digest: config.request.provider_implementation_digest,
      request_nonce: pair.request.payload.nonce,
      request_sequence: pair.request.payload.sequence,
    });
    const requestClaim = deepFreeze({
      version: 1,
      domain: "hacker-bob/instrument-broker-ipc-request-reservation-claim/v1",
      reservation_kind: "request",
      signed_request_version: pair.request.version,
      signed_request_kind: pair.request.kind,
      signed_request_domain: pair.request.domain,
      request_digest: pair.request.request_digest,
      request_id: pair.request.payload.request_id,
      request_nonce: pair.request.payload.nonce,
      request_sequence: pair.request.payload.sequence,
      request_key_id: config.request.request_key_id,
      request_public_key_digest: config.request.request_public_key_digest,
      ipc_peer_principal_id: config.request.ipc_peer_principal_id,
      execution_principal_id: config.request.execution_principal_id,
      provider_id: config.request.provider_id,
      provider_descriptor_digest: config.request.provider_descriptor_digest,
      provider_implementation_digest: config.request.provider_implementation_digest,
      dispatch_boundary_kind: config.dispatch.kind,
      dispatch_fixture_source: config.dispatch.fixture_source,
      dispatch_fixture_script: config.dispatch.fixture_script,
      dispatch_deadline_enforcement: config.dispatch.deadline_enforcement,
      dispatch_hardware_authority: config.dispatch.hardware_authority,
      dispatch_production_ready: config.dispatch.production_ready,
      operation_id: pair.request.payload.operation_id,
      operation_payload_digest: pair.request.payload.operation_payload_digest,
    });
    let requestReservation;
    let requestReservationError = null;
    try {
      requestReservation = await reserveDurably(
        config.reservation,
        "request",
        requestClaim,
        requestReplayIdentity,
      );
    } catch (error) {
      requestReservationError = error;
    }
    window = assertAdmissionWindow(
      config.now,
      challenge,
      pair,
      lastNowMilliseconds,
    );
    lastNowMilliseconds = window.currentMilliseconds;
    const authorityAfterRequest = await readAuthority(config.authority);
    window = assertAdmissionWindow(
      config.now,
      challenge,
      pair,
      lastNowMilliseconds,
    );
    lastNowMilliseconds = window.currentMilliseconds;
    const descriptorAfterRequest = readDescriptor(config.channel);
    if (requestReservationError != null
        || !sameAuthority(authorityBefore, authorityAfterRequest)
        || !sameDescriptor(descriptorBefore, descriptorAfterRequest)) {
      throw channelBindingError();
    }
    const proofClaim = deepFreeze({
      version: 1,
      reservation_kind: "proof",
      channel_id: config.channel.channel_id,
      connection_identity_digest: base.connection_identity_digest,
      descriptor_registration_token_digest:
        base.descriptor_registration_token_digest,
      challenge_digest: challenge.challenge_digest,
      request_digest: pair.request.request_digest,
      proof_digest: pair.proof.proof_digest,
      request_reservation_receipt_digest:
        requestReservation.reservation_receipt_digest,
      request_key_id: config.request.request_key_id,
      request_public_key_digest: config.request.request_public_key_digest,
      provider_id: config.request.provider_id,
      provider_descriptor_digest: config.request.provider_descriptor_digest,
      provider_implementation_digest: config.request.provider_implementation_digest,
      dispatch_boundary_kind: config.dispatch.kind,
      dispatch_fixture_source: config.dispatch.fixture_source,
      dispatch_fixture_script: config.dispatch.fixture_script,
      dispatch_deadline_enforcement: config.dispatch.deadline_enforcement,
      dispatch_hardware_authority: config.dispatch.hardware_authority,
      dispatch_production_ready: config.dispatch.production_ready,
      peer_process_start_token_digest: base.peer_process_start_token_digest,
      startup_authority_digest: base.startup_authority_digest,
      authority_epoch: base.authority_epoch,
      descriptor_post_request_reservation_readback_digest:
        descriptorAfterRequest.descriptor_readback_digest,
    });
    let proofReservation;
    let proofReservationError = null;
    try {
      proofReservation = await reserveDurably(config.reservation, "proof", proofClaim);
    } catch (error) {
      proofReservationError = error;
    }
    window = assertAdmissionWindow(
      config.now,
      challenge,
      pair,
      lastNowMilliseconds,
    );
    lastNowMilliseconds = window.currentMilliseconds;
    // These are mandatory even if reserve returned malformed data, threw after
    // commit, or its response was lost. Only exact durable readback can admit.
    const authorityAfterProof = await readAuthority(config.authority);
    window = assertAdmissionWindow(
      config.now,
      challenge,
      pair,
      lastNowMilliseconds,
    );
    lastNowMilliseconds = window.currentMilliseconds;
    const descriptorAfterProof = readDescriptor(config.channel);
    if (proofReservationError != null
        || !sameAuthority(authorityBefore, authorityAfterProof)
        || !sameDescriptor(descriptorBefore, descriptorAfterProof)) {
      throw channelBindingError();
    }
    window = assertAdmissionWindow(
      config.now,
      challenge,
      pair,
      lastNowMilliseconds,
    );
    lastNowMilliseconds = window.currentMilliseconds;
    admitted = true;
    let dispatchResult;
    try {
      const dispatchProjection = deepFreeze({
        version: 1,
        challenge_digest: challenge.challenge_digest,
        request_digest: pair.request.request_digest,
        proof_digest: pair.proof.proof_digest,
        request_reservation_receipt_digest:
          requestReservation.reservation_receipt_digest,
        proof_reservation_receipt_digest:
          proofReservation.reservation_receipt_digest,
        descriptor_post_reservation_readback_digest:
          descriptorAfterProof.descriptor_readback_digest,
        startup_authority_digest: authorityAfterProof.authority_digest,
        provider_id: config.request.provider_id,
        provider_descriptor_digest: config.request.provider_descriptor_digest,
        provider_implementation_digest: config.request.provider_implementation_digest,
        dispatch_boundary_kind: config.dispatch.kind,
        dispatch_fixture_source: config.dispatch.fixture_source,
        dispatch_fixture_script: config.dispatch.fixture_script,
        dispatch_deadline_enforcement: config.dispatch.deadline_enforcement,
        dispatch_separate_identity: config.dispatch.separate_identity,
        dispatch_independently_preemptible:
          config.dispatch.independently_preemptible,
        dispatch_worker_trusted_deadline_recheck:
          config.dispatch.worker_trusted_deadline_recheck,
        dispatch_hardware_authority: config.dispatch.hardware_authority,
        dispatch_production_ready: config.dispatch.production_ready,
        operation_id: pair.request.payload.operation_id,
        operation_payload_digest: pair.request.payload.operation_payload_digest,
        operation_payload: pair.request.payload.operation_payload,
        challenge_expires_at: challenge.payload.expires_at,
        request_deadline: pair.request.payload.deadline,
        proof_deadline: pair.proof.payload.proof_deadline,
        dispatch_deadline: reflectApply(dateToISOString, new SafeDate(
          signedDispatchDeadlineMilliseconds(challenge, pair),
        ), []),
      });
      const dispatchInvocation = await invokeTestOnlyCooperativeDispatchWithinDeadline(
        config.dispatch,
        dispatchProjection,
        signedDispatchDeadlineMilliseconds(challenge, pair),
        lastNowMilliseconds,
      );
      try {
        window = assertAdmissionWindow(
          config.now,
          challenge,
          pair,
          lastNowMilliseconds,
        );
        lastNowMilliseconds = window.currentMilliseconds;
      } catch {
        const timeout = dispatchTimeoutError();
        abortDispatch(dispatchInvocation.controller, timeout);
        throw timeout;
      }
      dispatchResult = dispatchInvocation.result;
      assertExactDataObject(dispatchResult, [
        "status", "error_code", "operation_result_digest",
      ]);
      if (dispatchResult.status !== "completed" && dispatchResult.status !== "rejected") {
        throw channelBindingError();
      }
      if ((dispatchResult.status === "completed" && dispatchResult.error_code !== null)
          || (dispatchResult.status === "rejected"
            && dispatchResult.error_code === null)) {
        throw channelBindingError();
      }
      if (dispatchResult.error_code !== null) {
        assertSafeErrorCode(dispatchResult.error_code);
      }
      assertDigest(dispatchResult.operation_result_digest);
    } catch (error) {
      const timedOut = isDispatchTimeoutError(error);
      dispatchResult = objectFreeze({
        status: "ambiguous",
        error_code: timedOut ? "dispatch_timeout" : "dispatch_unavailable",
        operation_result_digest: hashClosed(
          "hacker-bob/instrument-broker-ipc-channel-response/v1",
          timedOut ? "timed_out_operation_result" : "ambiguous_operation_result",
          null,
        ),
      });
    }
    const responded = nowValue(config.now);
    const response = signIpcChannelResponse({
      version: IPC_CHANNEL_BINDING_VERSION,
      protocol: IPC_CHANNEL_BINDING_PROTOCOL,
      challenge_digest: challenge.challenge_digest,
      proof_digest: pair.proof.proof_digest,
      request_digest: pair.request.request_digest,
      request_id: pair.request.payload.request_id,
      request_nonce: pair.request.payload.nonce,
      request_sequence: pair.request.payload.sequence,
      server_principal_id: config.server.server_principal_id,
      provider_id: config.request.provider_id,
      provider_descriptor_digest: config.request.provider_descriptor_digest,
      provider_implementation_digest: config.request.provider_implementation_digest,
      dispatch_boundary_kind: config.dispatch.kind,
      dispatch_fixture_source: config.dispatch.fixture_source,
      dispatch_fixture_script: config.dispatch.fixture_script,
      dispatch_deadline_enforcement: config.dispatch.deadline_enforcement,
      dispatch_separate_identity: config.dispatch.separate_identity,
      dispatch_independently_preemptible: config.dispatch.independently_preemptible,
      dispatch_worker_trusted_deadline_recheck:
        config.dispatch.worker_trusted_deadline_recheck,
      dispatch_hardware_authority: config.dispatch.hardware_authority,
      dispatch_production_ready: config.dispatch.production_ready,
      status: dispatchResult.status,
      error_code: dispatchResult.error_code,
      operation_result_digest: dispatchResult.operation_result_digest,
      request_reservation_receipt_digest:
        requestReservation.reservation_receipt_digest,
      proof_reservation_receipt_digest:
        proofReservation.reservation_receipt_digest,
      descriptor_post_reservation_readback_digest:
        descriptorAfterProof.descriptor_readback_digest,
      startup_authority_digest: authorityAfterProof.authority_digest,
      responded_at: reflectApply(dateToISOString, responded, []),
    }, {
      key_id: config.server.response_key_id,
      public_key_digest: config.server.response_public_key_digest,
      private_key: config.server.private_key,
    });
    await reflectApply(channelState.write_response, undefined,
      [encodeIpcChannelFrame(response), config.io_timeout]);
    return deepFreeze({
      version: IPC_CHANNEL_SERVER_VERSION,
      status: response.payload.status,
      error_code: response.payload.error_code,
      challenge_digest: challenge.challenge_digest,
      request_digest: pair.request.request_digest,
      proof_digest: pair.proof.proof_digest,
      response_digest: response.response_digest,
      request_reservation_receipt_digest:
        requestReservation.reservation_receipt_digest,
      proof_reservation_receipt_digest:
        proofReservation.reservation_receipt_digest,
      descriptor_post_reservation_readback_digest:
        descriptorAfterProof.descriptor_readback_digest,
      startup_authority_digest: authorityAfterProof.authority_digest,
      provider_id: response.payload.provider_id,
      provider_descriptor_digest: response.payload.provider_descriptor_digest,
      provider_implementation_digest: response.payload.provider_implementation_digest,
      dispatch_boundary_kind: response.payload.dispatch_boundary_kind,
      dispatch_fixture_source: response.payload.dispatch_fixture_source,
      dispatch_fixture_script: response.payload.dispatch_fixture_script,
      dispatch_deadline_enforcement: response.payload.dispatch_deadline_enforcement,
      dispatch_separate_identity: response.payload.dispatch_separate_identity,
      dispatch_independently_preemptible:
        response.payload.dispatch_independently_preemptible,
      dispatch_worker_trusted_deadline_recheck:
        response.payload.dispatch_worker_trusted_deadline_recheck,
      dispatch_hardware_authority: response.payload.dispatch_hardware_authority,
      dispatch_production_ready: response.payload.dispatch_production_ready,
      descriptor_provenance_complete: true,
      response_binding_complete: true,
      non_retryable: response.payload.status === "ambiguous",
      production_ready: false,
      production_attested: false,
      readiness_blockers: objectFreeze([
        "signed_immutable_native_prebuild_missing",
        "privileged_launcher_channel_custody_missing",
        "durable_external_reservation_store_not_qualified",
        "test_only_deterministic_mock_dispatch",
        "independent_preemptible_dispatch_boundary_missing",
        "worker_trusted_deadline_recheck_missing",
        "hardware_dispatch_forbidden",
        "ipc_channel_binding_hil_missing",
      ]),
    });
  } catch {
    if (admitted) throw admittedOutcomeAmbiguousError();
    throw channelBindingError();
  } finally {
    if (claimedChannel != null) {
      try {
        await reflectApply(
          reflectApply(weakMapGet, CHANNEL_STATE, [claimedChannel]).close,
          undefined,
          [],
        );
      } catch {
        if (admitted) throw admittedOutcomeAmbiguousError();
        throw channelBindingError();
      }
    }
  }
}

function createIpcChannelRequestAndProof(input) {
  assertExactDataObject(input, [
    "challenge",
    "trusted_server",
    "request_envelope",
    "request_signer",
    "client_attestation",
    "proof_nonce",
    "proof_deadline",
  ]);
  const challenge = normalizeSignedIpcChannelChallenge(input.challenge);
  assertExactDataObject(input.trusted_server, [
    "server_principal_id", "response_key_id", "response_public_key_digest", "public_key",
  ]);
  if (challenge.authentication.key_id !== input.trusted_server.response_key_id
      || challenge.authentication.public_key_digest
        !== input.trusted_server.response_public_key_digest
      || challenge.payload.server_principal_id
        !== input.trusted_server.server_principal_id
      || !verifyIpcChannelChallenge(challenge, input.trusted_server.public_key)) {
    throw channelBindingError();
  }
  const request = normalizeSignedIpcDispatchRequest(input.request_envelope);
  assertExactDataObject(input.request_signer, [
    "request_key_id", "request_public_key_digest", "private_key",
  ]);
  const requestKeyDigest = publicKeyDigest(input.request_signer.private_key);
  const requestPublicKey = utilTypesIsKeyObject(input.request_signer.private_key)
    ? reflectApply(cryptoCreatePublicKey, crypto, [input.request_signer.private_key])
    : null;
  if (request.authentication.key_id !== input.request_signer.request_key_id
      || request.authentication.public_key_digest !== requestKeyDigest
      || requestPublicKey == null
      || !verifyIpcDispatchRequestSignature(request, requestPublicKey)
      || request.authentication.key_id !== challenge.payload.expected_request_key_id
      || request.authentication.public_key_digest
        !== challenge.payload.expected_request_public_key_digest
      || request.payload.provider_id !== challenge.payload.provider_id
      || request.payload.provider_descriptor_digest
        !== challenge.payload.provider_descriptor_digest
      || input.trusted_server.response_key_id === input.request_signer.request_key_id
      || input.trusted_server.response_public_key_digest === requestKeyDigest) {
    throw channelBindingError();
  }
  assertExactDataObject(input.client_attestation, [
    "client_bundle_identity_digest", "client_launch_attestation_digest",
  ]);
  const proof = signIpcChannelProof({
    version: IPC_CHANNEL_BINDING_VERSION,
    protocol: IPC_CHANNEL_BINDING_PROTOCOL,
    challenge_digest: challenge.challenge_digest,
    signed_request_digest: request.request_digest,
    request_nonce: request.payload.nonce,
    request_sequence: request.payload.sequence,
    request_key_id: request.authentication.key_id,
    request_public_key_digest: request.authentication.public_key_digest,
    ipc_peer_principal_id: request.payload.ipc_peer_principal_id,
    execution_principal_id: request.payload.execution_principal_id,
    provider_id: request.payload.provider_id,
    provider_descriptor_digest: request.payload.provider_descriptor_digest,
    provider_implementation_digest: challenge.payload.provider_implementation_digest,
    client_bundle_identity_digest: assertDigest(
      input.client_attestation.client_bundle_identity_digest,
    ),
    client_launch_attestation_digest: assertDigest(
      input.client_attestation.client_launch_attestation_digest,
    ),
    proof_nonce: assertNonce(input.proof_nonce),
    proof_deadline: assertTimestamp(input.proof_deadline),
  }, {
    key_id: assertToken(input.request_signer.request_key_id, "ipc-key"),
    public_key_digest: assertDigest(input.request_signer.request_public_key_digest),
    private_key: input.request_signer.private_key,
  });
  return deepFreeze({
    version: IPC_CHANNEL_BINDING_VERSION,
    kind: "instrument_channel_request_and_proof",
    request,
    proof,
  });
}

function validateIpcChannelResponse(input) {
  assertExactDataObject(input, [
    "response", "challenge", "proof", "request", "trusted_server",
  ]);
  const response = normalizeSignedIpcChannelResponse(input.response);
  const challenge = normalizeSignedIpcChannelChallenge(input.challenge);
  const proof = normalizeSignedIpcChannelProof(input.proof);
  const request = normalizeSignedIpcDispatchRequest(input.request);
  assertExactDataObject(input.trusted_server, [
    "server_principal_id", "response_key_id", "response_public_key_digest", "public_key",
  ]);
  const trustedKeyDigest = publicKeyDigest(input.trusted_server.public_key);
  if (assertToken(input.trusted_server.server_principal_id, "principal")
        !== response.payload.server_principal_id
      || assertToken(input.trusted_server.response_key_id, "ipc-key")
        !== response.authentication.key_id
      || assertDigest(input.trusted_server.response_public_key_digest)
        !== trustedKeyDigest
      || response.authentication.public_key_digest !== trustedKeyDigest
      || challenge.authentication.key_id !== input.trusted_server.response_key_id
      || challenge.authentication.public_key_digest !== trustedKeyDigest
      || !verifyIpcChannelChallenge(challenge, input.trusted_server.public_key)
      || !verifyIpcChannelResponse(response, input.trusted_server.public_key)
      || response.authentication.key_id !== input.trusted_server.response_key_id
      || response.authentication.public_key_digest
        !== input.trusted_server.response_public_key_digest
      || response.payload.challenge_digest !== challenge.challenge_digest
      || response.payload.proof_digest !== proof.proof_digest
      || response.payload.request_digest !== request.request_digest
      || response.payload.request_id !== request.payload.request_id
      || response.payload.request_nonce !== request.payload.nonce
      || response.payload.request_sequence !== request.payload.sequence
      || response.payload.provider_id !== challenge.payload.provider_id
      || response.payload.provider_id !== request.payload.provider_id
      || response.payload.provider_descriptor_digest
        !== challenge.payload.provider_descriptor_digest
      || response.payload.provider_descriptor_digest
        !== request.payload.provider_descriptor_digest
      || response.payload.provider_implementation_digest
        !== challenge.payload.provider_implementation_digest
      || response.payload.dispatch_boundary_kind
        !== challenge.payload.dispatch_boundary_kind
      || response.payload.dispatch_fixture_source
        !== challenge.payload.dispatch_fixture_source
      || response.payload.dispatch_fixture_script
        !== challenge.payload.dispatch_fixture_script
      || response.payload.dispatch_deadline_enforcement
        !== challenge.payload.dispatch_deadline_enforcement
      || response.payload.dispatch_separate_identity
        !== challenge.payload.dispatch_separate_identity
      || response.payload.dispatch_independently_preemptible
        !== challenge.payload.dispatch_independently_preemptible
      || response.payload.dispatch_worker_trusted_deadline_recheck
        !== challenge.payload.dispatch_worker_trusted_deadline_recheck
      || response.payload.dispatch_hardware_authority
        !== challenge.payload.dispatch_hardware_authority
      || response.payload.dispatch_production_ready
        !== challenge.payload.dispatch_production_ready
      || proof.payload.challenge_digest !== challenge.challenge_digest
      || proof.payload.signed_request_digest !== request.request_digest
      || proof.payload.request_nonce !== request.payload.nonce
      || proof.payload.request_sequence !== request.payload.sequence
      || proof.payload.provider_id !== challenge.payload.provider_id
      || proof.payload.provider_id !== request.payload.provider_id
      || proof.payload.provider_descriptor_digest
        !== challenge.payload.provider_descriptor_digest
      || proof.payload.provider_descriptor_digest
        !== request.payload.provider_descriptor_digest
      || proof.payload.provider_implementation_digest
        !== challenge.payload.provider_implementation_digest) {
    throw channelBindingError();
  }
  return deepFreeze({
    version: IPC_CHANNEL_BINDING_VERSION,
    status: response.payload.status,
    error_code: response.payload.error_code,
    challenge_digest: response.payload.challenge_digest,
    proof_digest: response.payload.proof_digest,
    request_digest: response.payload.request_digest,
    response_digest: response.response_digest,
    provider_id: response.payload.provider_id,
    provider_descriptor_digest: response.payload.provider_descriptor_digest,
    provider_implementation_digest: response.payload.provider_implementation_digest,
    dispatch_boundary_kind: response.payload.dispatch_boundary_kind,
    dispatch_fixture_source: response.payload.dispatch_fixture_source,
    dispatch_fixture_script: response.payload.dispatch_fixture_script,
    dispatch_deadline_enforcement: response.payload.dispatch_deadline_enforcement,
    dispatch_separate_identity: response.payload.dispatch_separate_identity,
    dispatch_independently_preemptible:
      response.payload.dispatch_independently_preemptible,
    dispatch_worker_trusted_deadline_recheck:
      response.payload.dispatch_worker_trusted_deadline_recheck,
    dispatch_hardware_authority: response.payload.dispatch_hardware_authority,
    dispatch_production_ready: response.payload.dispatch_production_ready,
    request_reservation_receipt_digest:
      response.payload.request_reservation_receipt_digest,
    proof_reservation_receipt_digest:
      response.payload.proof_reservation_receipt_digest,
    response_binding_complete: true,
    non_retryable: response.payload.status === "ambiguous",
    production_ready: false,
  });
}

module.exports = objectFreeze({
  IPC_CHANNEL_AUTHORITY_PORT_VERSION,
  IPC_CHANNEL_PORT_VERSION,
  IPC_CHANNEL_RESERVATION_PORT_VERSION,
  IPC_CHANNEL_SERVER_VERSION,
  IPC_CHANNEL_TEST_ONLY_DISPATCH_PORT_VERSION,
  createIpcChannelAuthorityPort,
  createIpcChannelRequestAndProof,
  createIpcChannelReservationPort,
  createIpcNativeAcceptedChannelPort,
  createIpcTestOnlyDeterministicMockCooperativeDispatchPort,
  executeIpcChannelBindingServerConnection,
  validateIpcChannelResponse,
  _internals: objectFreeze({
    normalizeReservationRecord,
    reserveDurably,
  }),
});
