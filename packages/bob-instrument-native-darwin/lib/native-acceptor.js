"use strict";

const crypto = require("node:crypto");
const path = require("node:path");
const { types: utilTypes } = require("node:util");
const { loadNativeBindingOnce } = require("./native-binding-loader.js");

const SafeError = Error;
const SafeBuffer = Buffer;
const bufferFrom = Buffer.from;
const bufferIsBuffer = Buffer.isBuffer;
const bufferToString = Buffer.prototype.toString;
const cryptoCreateHash = crypto.createHash;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectKeys = Object.keys;
const objectPrototype = Object.prototype;
const numberIsInteger = Number.isInteger;
const pathBasename = path.basename;
const pathIsAbsolute = path.isAbsolute;
const pathResolve = path.resolve;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regExpTest = RegExp.prototype.test;
const utilTypesIsProxy = utilTypes.isProxy;
const weakMapGet = WeakMap.prototype.get;
const weakMapHas = WeakMap.prototype.has;
const weakMapSet = WeakMap.prototype.set;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;

const HASH_PROTOTYPE = objectGetPrototypeOf(cryptoCreateHash("sha256"));
const HASH_UPDATE = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "update").value;
const HASH_DIGEST = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "digest").value;

const DARWIN_NATIVE_ACCEPTOR_VERSION = 1;
const DARWIN_NATIVE_ACCEPTOR_PRIMITIVE =
  "darwin_native_unix_acceptor_opaque_channel_v1";
const DARWIN_NATIVE_ACCEPTED_CONNECTION_PRIMITIVE =
  "darwin_native_accepted_unix_connection_v1";
const DARWIN_NATIVE_ACCEPTED_READBACK_PRIMITIVE =
  "darwin_native_accepted_connection_readback_v1";
const DARWIN_NATIVE_DESCRIPTOR_BINDING_SCHEME =
  "darwin_native_accept_duplicate_registration_before_javascript_v1";
const MAX_FRAME_BYTES = 65_536 + 4;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const CODE_DIRECTORY_CDHASH_PATTERN = /^[a-f0-9]{40}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;
const TOKEN_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,128}$/u;
const SOCKET_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\.sock$/u;

const CONFIG_PORTS = new WeakSet();
const CONFIG_STATE = new WeakMap();
const LISTENER_PORTS = new WeakSet();
const LISTENER_STATE = new WeakMap();
const CONNECTION_PORTS = new WeakSet();
const CONNECTION_STATE = new WeakMap();

const RAW_PEER_FIELDS = objectFreeze([
  "descriptor_registration_token_digest",
  "kernel_snapshot_stable",
  "peer_audit_token_digest",
  "peer_code_certificate_chain_digest",
  "peer_code_certificate_chain_state",
  "peer_code_certificate_count",
  "peer_code_designated_requirement_digest",
  "peer_code_directory_hash",
  "peer_code_directory_hash_algorithm",
  "peer_code_directory_hashes_digest",
  "peer_code_dynamic_status_digest",
  "peer_code_dynamic_validity",
  "peer_code_dynamic_validity_scheme",
  "peer_code_identity_audit_token_bound",
  "peer_code_identity_completeness",
  "peer_code_identity_scheme",
  "peer_code_identity_stable",
  "peer_code_signature_class",
  "peer_code_signer_identity_complete",
  "peer_code_signing_identifier_digest",
  "peer_code_signing_identity_digest",
  "peer_code_static_flags_digest",
  "peer_code_team_identifier_digest",
  "peer_code_team_identifier_state",
  "peer_egid",
  "peer_euid",
  "peer_executable_path_digest",
  "peer_mapped_code_identity_digest",
  "peer_pid",
  "peer_pidversion",
  "peer_process_start_token_digest",
  "peer_process_start_tvsec",
  "peer_process_start_tvusec",
  "peer_rgid",
  "peer_ruid",
  "primitive",
  "version",
]);
const RAW_ACCEPTOR_SNAPSHOT_FIELDS = objectFreeze([
  "version",
  "primitive",
  "socket_root_identity_digest",
  "socket_identity_digest",
  "listener_identity_digest",
  "acceptor_instance_digest",
  "native_listener_created",
  "javascript_descriptor_handoff_used",
]);
const RAW_CONNECTION_SNAPSHOT_FIELDS = objectFreeze([
  "version",
  "primitive",
  "connection_identity_digest",
  "descriptor_registration_token_digest",
  "socket_root_identity_digest",
  "socket_identity_digest",
  "listener_identity_digest",
  "acceptor_instance_digest",
  "connection_generation",
  "accepted_and_registered_before_javascript",
  "javascript_descriptor_handoff_used",
]);
const RAW_READBACK_FIELDS = objectFreeze([
  "version",
  "primitive",
  "connection_identity_digest",
  "descriptor_registration_token_digest",
  "socket_root_identity_digest",
  "socket_identity_digest",
  "listener_identity_digest",
  "acceptor_instance_digest",
  "connection_generation",
  "peer_audit_token_digest",
  "peer_process_start_token_digest",
  "peer_mapped_code_identity_digest",
  "descriptor_readback_digest",
  "kernel_snapshot_stable",
]);

function channelError() {
  const error = new SafeError("Darwin native IPC channel was rejected");
  objectDefineProperty(error, "code", {
    value: "darwin_native_channel_rejected",
    writable: false,
    enumerable: false,
    configurable: false,
  });
  return error;
}

function hashText(domain, value) {
  const hash = cryptoCreateHash("sha256");
  reflectApply(HASH_UPDATE, hash, [`${domain}\u0000${value}`]);
  return reflectApply(HASH_DIGEST, hash, ["hex"]);
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || utilTypesIsProxy(value)) return false;
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

function assertExactDataObject(value, fields) {
  if (!isPlainDataObject(value)) throw channelError();
  const keys = objectKeys(value);
  if (keys.length !== fields.length) throw channelError();
  for (let index = 0; index < fields.length; index += 1) {
    if (keys[index] !== fields[index]) throw channelError();
    const descriptor = objectGetOwnPropertyDescriptor(value, fields[index]);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true) throw channelError();
  }
  return value;
}

function assertExactFrozenNativeObject(value, fields) {
  assertExactDataObject(value, fields);
  if (objectGetPrototypeOf(value) !== objectPrototype || !objectIsFrozen(value)) {
    throw channelError();
  }
  for (let index = 0; index < fields.length; index += 1) {
    const descriptor = objectGetOwnPropertyDescriptor(value, fields[index]);
    if (descriptor.writable !== false || descriptor.configurable !== false) {
      throw channelError();
    }
  }
  return value;
}

function assertExactClosedNativeObjectUnordered(value, fields) {
  if (value == null || typeof value !== "object" || utilTypesIsProxy(value)
      || objectGetPrototypeOf(value) !== objectPrototype) throw channelError();
  const keys = reflectOwnKeys(value);
  if (keys.length !== fields.length) throw channelError();
  for (let index = 0; index < fields.length; index += 1) {
    const descriptor = objectGetOwnPropertyDescriptor(value, fields[index]);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true || descriptor.writable !== false
        || descriptor.configurable !== false) throw channelError();
  }
  return value;
}

function assertDigest(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, DIGEST_PATTERN, [value])) throw channelError();
  return value;
}

function assertSelectedCdhash(value, algorithm) {
  if ((algorithm !== 1 && algorithm !== 2 && algorithm !== 3)
      || typeof value !== "string"
      || !reflectApply(regExpTest, CODE_DIRECTORY_CDHASH_PATTERN, [value])) {
    throw channelError();
  }
  return value;
}

function assertUint32(value) {
  if (!numberIsInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw channelError();
  }
  return value;
}

function assertDecimal(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, DECIMAL_PATTERN, [value])) throw channelError();
  return value;
}

function assertOpaqueNativeToken(value) {
  if (value == null || typeof value !== "object" || utilTypesIsProxy(value)
      || objectGetPrototypeOf(value) !== objectPrototype || !objectIsFrozen(value)
      || reflectOwnKeys(value).length !== 0) throw channelError();
  return value;
}

function normalizeNonce(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, NONCE_PATTERN, [value])) throw channelError();
  const bytes = reflectApply(bufferFrom, SafeBuffer, [value, "base64url"]);
  if (bytes.length < 16
      || reflectApply(bufferToString, bytes, ["base64url"]) !== value) {
    throw channelError();
  }
  return value;
}

function assertConfigPort(port) {
  if (port == null || typeof port !== "object" || utilTypesIsProxy(port)
      || !objectIsFrozen(port)
      || !reflectApply(weakSetHas, CONFIG_PORTS, [port])
      || !reflectApply(weakMapHas, CONFIG_STATE, [port])) throw channelError();
  return port;
}

function assertListenerPort(port) {
  if (port == null || typeof port !== "object" || utilTypesIsProxy(port)
      || !objectIsFrozen(port)
      || !reflectApply(weakSetHas, LISTENER_PORTS, [port])
      || !reflectApply(weakMapHas, LISTENER_STATE, [port])) throw channelError();
  return port;
}

function assertConnectionPort(port) {
  if (port == null || typeof port !== "object" || utilTypesIsProxy(port)
      || !objectIsFrozen(port)
      || !reflectApply(weakSetHas, CONNECTION_PORTS, [port])
      || !reflectApply(weakMapHas, CONNECTION_STATE, [port])) throw channelError();
  return port;
}

function rejectConnectionState(state) {
  if (state == null || state.closed) return;
  state.phase = "rejected_closed";
  state.closed = true;
  state.registrationToken = null;
  try {
    reflectApply(state.native.closeAcceptedConnection, undefined,
      [state.connectionToken]);
  } catch {}
}

function createDarwinNativeUnixAcceptor(input) {
  if (arguments.length !== 1) throw channelError();
  assertExactDataObject(input, ["adapter_id", "socket_path"]);
  if (typeof input.adapter_id !== "string"
      || !reflectApply(regExpTest, TOKEN_PATTERN, [input.adapter_id])
      || typeof input.socket_path !== "string"
      || !reflectApply(pathIsAbsolute, path, [input.socket_path])
      || reflectApply(pathResolve, path, [input.socket_path]) !== input.socket_path
      || !reflectApply(regExpTest, SOCKET_NAME_PATTERN,
        [reflectApply(pathBasename, path, [input.socket_path])])) {
    throw channelError();
  }
  const port = objectFreeze({
    version: DARWIN_NATIVE_ACCEPTOR_VERSION,
    adapter_id: input.adapter_id,
    transport: "unix",
    socket_path_digest: hashText(
      "hacker-bob/darwin-native-acceptor-config-path/v1",
      input.socket_path,
    ),
    construction_inert: true,
    production_ready: false,
  });
  reflectApply(weakSetAdd, CONFIG_PORTS, [port]);
  reflectApply(weakMapSet, CONFIG_STATE, [port, {
    socket_path: input.socket_path,
    opened: false,
  }]);
  return port;
}

function openDarwinNativeUnixAcceptor(configPort) {
  if (arguments.length !== 1) throw channelError();
  assertConfigPort(configPort);
  const config = reflectApply(weakMapGet, CONFIG_STATE, [configPort]);
  if (config.opened) throw channelError();
  let native;
  let raw;
  try {
    native = loadNativeBindingOnce();
    raw = reflectApply(native.createUnixAcceptor, undefined, [config.socket_path]);
  } catch {
    throw channelError();
  }
  config.opened = true;
  try {
    assertExactFrozenNativeObject(raw, ["acceptor_token", "snapshot"]);
    assertOpaqueNativeToken(raw.acceptor_token);
    const snapshot = assertExactFrozenNativeObject(
      raw.snapshot,
      RAW_ACCEPTOR_SNAPSHOT_FIELDS,
    );
    if (snapshot.version !== DARWIN_NATIVE_ACCEPTOR_VERSION
        || snapshot.primitive !== DARWIN_NATIVE_ACCEPTOR_PRIMITIVE
        || snapshot.native_listener_created !== true
        || snapshot.javascript_descriptor_handoff_used !== false) throw channelError();
    for (let index = 2; index <= 5; index += 1) {
      assertDigest(snapshot[RAW_ACCEPTOR_SNAPSHOT_FIELDS[index]]);
    }
    const port = objectFreeze({
      version: DARWIN_NATIVE_ACCEPTOR_VERSION,
      adapter_id: configPort.adapter_id,
      transport: "unix",
      socket_path_digest: configPort.socket_path_digest,
      socket_root_identity_digest: snapshot.socket_root_identity_digest,
      socket_identity_digest: snapshot.socket_identity_digest,
      listener_identity_digest: snapshot.listener_identity_digest,
      acceptor_instance_digest: snapshot.acceptor_instance_digest,
      native_binding_implementation_digest: native.implementation_digest,
      native_loaded_image_identity_digest: native.loaded_image_identity_digest,
      native_listener_created: true,
      javascript_descriptor_handoff_used: false,
      production_ready: false,
      readiness_blockers: objectFreeze([
        "signed_immutable_native_prebuild_missing",
        "privileged_launcher_listener_custody_missing",
        "native_acceptor_hil_missing",
      ]),
    });
    reflectApply(weakSetAdd, LISTENER_PORTS, [port]);
    reflectApply(weakMapSet, LISTENER_STATE, [port, {
      native,
      token: raw.acceptor_token,
      closed: false,
    }]);
    return port;
  } catch {
    try {
      reflectApply(native.closeUnixAcceptor, undefined, [raw?.acceptor_token]);
    } catch {}
    throw channelError();
  }
}

async function acceptDarwinNativeUnixConnection(listenerPort) {
  if (arguments.length !== 1) throw channelError();
  assertListenerPort(listenerPort);
  const listener = reflectApply(weakMapGet, LISTENER_STATE, [listenerPort]);
  if (listener.closed) throw channelError();
  let raw;
  try {
    raw = await reflectApply(listener.native.acceptUnixConnection, undefined,
      [listener.token]);
    assertExactFrozenNativeObject(raw, [
      "connection_token", "registration_token", "snapshot",
    ]);
    assertOpaqueNativeToken(raw.connection_token);
    const registrationKeys = reflectOwnKeys(raw.registration_token);
    if (raw.registration_token == null || typeof raw.registration_token !== "object"
        || utilTypesIsProxy(raw.registration_token)
        || objectGetPrototypeOf(raw.registration_token) !== objectPrototype
        || !objectIsFrozen(raw.registration_token)
        || registrationKeys.length !== 1
        || registrationKeys[0] !== "registration_token_digest") throw channelError();
    const tokenDescriptor = objectGetOwnPropertyDescriptor(
      raw.registration_token,
      "registration_token_digest",
    );
    if (tokenDescriptor == null || !objectHasOwn(tokenDescriptor, "value")
        || tokenDescriptor.enumerable !== false || tokenDescriptor.writable !== false
        || tokenDescriptor.configurable !== false) throw channelError();
    const snapshot = assertExactFrozenNativeObject(
      raw.snapshot,
      RAW_CONNECTION_SNAPSHOT_FIELDS,
    );
    if (snapshot.version !== DARWIN_NATIVE_ACCEPTOR_VERSION
        || snapshot.primitive !== DARWIN_NATIVE_ACCEPTED_CONNECTION_PRIMITIVE
        || snapshot.accepted_and_registered_before_javascript !== true
        || snapshot.javascript_descriptor_handoff_used !== false
        || snapshot.socket_root_identity_digest !== listenerPort.socket_root_identity_digest
        || snapshot.socket_identity_digest !== listenerPort.socket_identity_digest
        || snapshot.listener_identity_digest !== listenerPort.listener_identity_digest
        || snapshot.acceptor_instance_digest !== listenerPort.acceptor_instance_digest
        || snapshot.descriptor_registration_token_digest !== tokenDescriptor.value) {
      throw channelError();
    }
    for (let index = 2; index <= 7; index += 1) {
      assertDigest(snapshot[RAW_CONNECTION_SNAPSHOT_FIELDS[index]]);
    }
    assertDecimal(snapshot.connection_generation);
    const port = objectFreeze({
      version: DARWIN_NATIVE_ACCEPTOR_VERSION,
      adapter_id: listenerPort.adapter_id,
      transport: "unix",
      connection_identity_digest: snapshot.connection_identity_digest,
      descriptor_registration_token_digest:
        snapshot.descriptor_registration_token_digest,
      descriptor_binding_scheme_digest: hashText(
        "hacker-bob/darwin-native-descriptor-binding-scheme/v1",
        DARWIN_NATIVE_DESCRIPTOR_BINDING_SCHEME,
      ),
      socket_root_identity_digest: snapshot.socket_root_identity_digest,
      socket_identity_digest: snapshot.socket_identity_digest,
      listener_identity_digest: snapshot.listener_identity_digest,
      acceptor_instance_digest: snapshot.acceptor_instance_digest,
      connection_generation: snapshot.connection_generation,
      native_binding_implementation_digest:
        listenerPort.native_binding_implementation_digest,
      native_loaded_image_identity_digest:
        listenerPort.native_loaded_image_identity_digest,
      accepted_and_registered_before_javascript: true,
      javascript_descriptor_handoff_used: false,
      descriptor_provenance_complete: true,
      production_ready: false,
    });
    reflectApply(weakSetAdd, CONNECTION_PORTS, [port]);
    reflectApply(weakMapSet, CONNECTION_STATE, [port, {
      native: listener.native,
      connectionToken: raw.connection_token,
      registrationToken: raw.registration_token,
      phase: "accepted_native",
      peer: null,
      closed: false,
    }]);
    return port;
  } catch {
    try {
      reflectApply(listener.native.closeAcceptedConnection, undefined,
        [raw?.connection_token]);
    } catch {}
    throw channelError();
  }
}

function inspectDarwinNativeAcceptedConnectionPeer(connectionPort, registrationNonce) {
  if (arguments.length !== 2) throw channelError();
  assertConnectionPort(connectionPort);
  const nonce = normalizeNonce(registrationNonce);
  const state = reflectApply(weakMapGet, CONNECTION_STATE, [connectionPort]);
  if (state.closed || state.phase !== "accepted_native") {
    rejectConnectionState(state);
    throw channelError();
  }
  state.phase = "peer_inspecting";
  try {
    const raw = reflectApply(state.native.inspectRegisteredUnixPeer, undefined,
      [state.registrationToken]);
    state.registrationToken = null;
    assertExactClosedNativeObjectUnordered(raw, RAW_PEER_FIELDS);
    if (raw.version !== 2
        || raw.primitive !== "darwin_local_peertoken_seccode_dynamic_identity_v2"
        || raw.descriptor_registration_token_digest
          !== connectionPort.descriptor_registration_token_digest
        || raw.kernel_snapshot_stable !== true
        || raw.peer_code_identity_audit_token_bound !== true
        || raw.peer_code_identity_stable !== true) throw channelError();
    const digestFields = [
      "descriptor_registration_token_digest",
      "peer_audit_token_digest",
      "peer_process_start_token_digest",
      "peer_executable_path_digest",
      "peer_code_directory_hashes_digest",
      "peer_code_signing_identity_digest",
      "peer_code_dynamic_status_digest",
      "peer_mapped_code_identity_digest",
    ];
    for (let index = 0; index < digestFields.length; index += 1) {
      assertDigest(raw[digestFields[index]]);
    }
    const codeDirectoryHashAlgorithm = assertUint32(
      raw.peer_code_directory_hash_algorithm,
    );
    assertSelectedCdhash(
      raw.peer_code_directory_hash,
      codeDirectoryHashAlgorithm,
    );
    const peer = objectFreeze({
      version: 1,
      primitive: DARWIN_NATIVE_ACCEPTED_CONNECTION_PRIMITIVE,
      descriptor_registration_nonce: nonce,
      descriptor_registration_token_digest:
        raw.descriptor_registration_token_digest,
      descriptor_binding_scheme_digest:
        connectionPort.descriptor_binding_scheme_digest,
      connection_identity_digest: connectionPort.connection_identity_digest,
      socket_root_identity_digest: connectionPort.socket_root_identity_digest,
      socket_identity_digest: connectionPort.socket_identity_digest,
      listener_identity_digest: connectionPort.listener_identity_digest,
      acceptor_instance_digest: connectionPort.acceptor_instance_digest,
      connection_generation: connectionPort.connection_generation,
      peer_euid: raw.peer_euid,
      peer_egid: raw.peer_egid,
      peer_ruid: raw.peer_ruid,
      peer_rgid: raw.peer_rgid,
      peer_pid: raw.peer_pid,
      peer_pidversion: raw.peer_pidversion,
      peer_audit_token_digest: raw.peer_audit_token_digest,
      peer_process_start_token_digest: raw.peer_process_start_token_digest,
      peer_executable_path_digest: raw.peer_executable_path_digest,
      peer_selected_cdhash: raw.peer_code_directory_hash,
      peer_selected_cdhash_algorithm:
        codeDirectoryHashAlgorithm,
      peer_code_directory_hashes_digest:
        raw.peer_code_directory_hashes_digest,
      peer_code_signing_identity_digest: raw.peer_code_signing_identity_digest,
      peer_code_dynamic_status_digest: raw.peer_code_dynamic_status_digest,
      peer_mapped_code_identity_digest: raw.peer_mapped_code_identity_digest,
      native_binding_implementation_digest:
        connectionPort.native_binding_implementation_digest,
      native_loaded_image_identity_digest:
        connectionPort.native_loaded_image_identity_digest,
      accepted_and_registered_before_javascript: true,
      javascript_descriptor_handoff_used: false,
      descriptor_provenance_complete: true,
      production_ready: false,
    });
    state.peer = peer;
    state.phase = "peer_snapshot_stable";
    return peer;
  } catch {
    rejectConnectionState(state);
    throw channelError();
  }
}

function readDarwinNativeAcceptedConnectionIdentity(connectionPort) {
  if (arguments.length !== 1) throw channelError();
  assertConnectionPort(connectionPort);
  const state = reflectApply(weakMapGet, CONNECTION_STATE, [connectionPort]);
  if (state.closed || state.peer == null) throw channelError();
  try {
    const raw = reflectApply(state.native.readAcceptedConnectionIdentity,
      undefined, [state.connectionToken]);
    assertExactFrozenNativeObject(raw, RAW_READBACK_FIELDS);
    if (raw.version !== 1
        || raw.primitive !== DARWIN_NATIVE_ACCEPTED_READBACK_PRIMITIVE
        || raw.connection_identity_digest !== connectionPort.connection_identity_digest
        || raw.descriptor_registration_token_digest
          !== connectionPort.descriptor_registration_token_digest
        || raw.socket_root_identity_digest !== connectionPort.socket_root_identity_digest
        || raw.socket_identity_digest !== connectionPort.socket_identity_digest
        || raw.listener_identity_digest !== connectionPort.listener_identity_digest
        || raw.acceptor_instance_digest !== connectionPort.acceptor_instance_digest
        || raw.connection_generation !== connectionPort.connection_generation
        || raw.peer_audit_token_digest !== state.peer.peer_audit_token_digest
        || raw.peer_process_start_token_digest
          !== state.peer.peer_process_start_token_digest
        || raw.peer_mapped_code_identity_digest
          !== state.peer.peer_mapped_code_identity_digest
        || raw.kernel_snapshot_stable !== true) throw channelError();
    for (let index = 2; index <= 12; index += 1) {
      const field = RAW_READBACK_FIELDS[index];
      if (field === "connection_generation") assertDecimal(raw[field]);
      else assertDigest(raw[field]);
    }
    return objectFreeze({
      version: 1,
      connection_identity_digest: raw.connection_identity_digest,
      descriptor_registration_token_digest:
        raw.descriptor_registration_token_digest,
      peer_audit_token_digest: raw.peer_audit_token_digest,
      peer_process_start_token_digest: raw.peer_process_start_token_digest,
      peer_mapped_code_identity_digest: raw.peer_mapped_code_identity_digest,
      descriptor_readback_digest: raw.descriptor_readback_digest,
      native_loaded_image_identity_digest:
        connectionPort.native_loaded_image_identity_digest,
      descriptor_provenance_complete: true,
      production_ready: false,
    });
  } catch {
    rejectConnectionState(state);
    throw channelError();
  }
}

function assertFrame(frame) {
  if (!bufferIsBuffer(frame) || utilTypesIsProxy(frame)
      || frame.length < 5 || frame.length > MAX_FRAME_BYTES) throw channelError();
  return frame;
}

function assertTimeout(value) {
  if (!numberIsInteger(value) || value < 1 || value > 10_000) throw channelError();
  return value;
}

async function runWrite(connectionPort, frame, timeoutMs, expectedPhase, nextPhase) {
  assertConnectionPort(connectionPort);
  const state = reflectApply(weakMapGet, CONNECTION_STATE, [connectionPort]);
  if (state.closed || state.phase !== expectedPhase) {
    rejectConnectionState(state);
    throw channelError();
  }
  try {
    assertFrame(frame);
    assertTimeout(timeoutMs);
  } catch {
    rejectConnectionState(state);
    throw channelError();
  }
  state.phase = `${expectedPhase}_writing`;
  try {
    const result = await reflectApply(state.native.writeAcceptedConnectionFrame,
      undefined, [state.connectionToken, frame, timeoutMs]);
    assertExactFrozenNativeObject(result, [
      "version", "operation", "frame_sha256", "frame_bytes",
    ]);
    if (result.version !== 1
        || result.operation !== (expectedPhase === "peer_snapshot_stable"
          ? "challenge_written" : "response_written")
        || !reflectApply(regExpTest, DIGEST_PATTERN, [result.frame_sha256])
        || !reflectApply(regExpTest, DECIMAL_PATTERN, [result.frame_bytes])) {
      throw channelError();
    }
    state.phase = nextPhase;
    return result;
  } catch {
    rejectConnectionState(state);
    throw channelError();
  }
}

async function writeDarwinNativeAcceptedConnectionChallenge(connectionPort, frame, timeoutMs) {
  if (arguments.length !== 3) throw channelError();
  return runWrite(connectionPort, frame, timeoutMs,
    "peer_snapshot_stable", "challenge_sent");
}

async function readDarwinNativeAcceptedConnectionRequest(connectionPort, timeoutMs) {
  if (arguments.length !== 2) throw channelError();
  assertConnectionPort(connectionPort);
  const state = reflectApply(weakMapGet, CONNECTION_STATE, [connectionPort]);
  if (state.closed || state.phase !== "challenge_sent") {
    rejectConnectionState(state);
    throw channelError();
  }
  try {
    assertTimeout(timeoutMs);
  } catch {
    rejectConnectionState(state);
    throw channelError();
  }
  state.phase = "request_reading";
  try {
    const body = await reflectApply(state.native.readAcceptedConnectionFrame,
      undefined, [state.connectionToken, timeoutMs]);
    if (!bufferIsBuffer(body) || utilTypesIsProxy(body)
        || body.length < 1 || body.length > 65_536) throw channelError();
    state.phase = "request_and_proof_received";
    return body;
  } catch {
    rejectConnectionState(state);
    throw channelError();
  }
}

async function writeDarwinNativeAcceptedConnectionResponse(connectionPort, frame, timeoutMs) {
  if (arguments.length !== 3) throw channelError();
  return runWrite(connectionPort, frame, timeoutMs,
    "request_and_proof_received", "response_sent");
}

function closeDarwinNativeUnixAcceptor(listenerPort) {
  if (arguments.length !== 1) throw channelError();
  assertListenerPort(listenerPort);
  const state = reflectApply(weakMapGet, LISTENER_STATE, [listenerPort]);
  if (state.closed) return;
  state.closed = true;
  try {
    reflectApply(state.native.closeUnixAcceptor, undefined, [state.token]);
  } catch {
    throw channelError();
  }
}

function closeDarwinNativeAcceptedConnection(connectionPort) {
  if (arguments.length !== 1) throw channelError();
  assertConnectionPort(connectionPort);
  const state = reflectApply(weakMapGet, CONNECTION_STATE, [connectionPort]);
  if (state.closed) return;
  state.closed = true;
  state.phase = "closed";
  state.registrationToken = null;
  try {
    reflectApply(state.native.closeAcceptedConnection, undefined,
      [state.connectionToken]);
  } catch {
    throw channelError();
  }
}

module.exports = objectFreeze({
  DARWIN_NATIVE_ACCEPTOR_PRIMITIVE,
  DARWIN_NATIVE_ACCEPTOR_VERSION,
  DARWIN_NATIVE_DESCRIPTOR_BINDING_SCHEME,
  acceptDarwinNativeUnixConnection,
  closeDarwinNativeAcceptedConnection,
  closeDarwinNativeUnixAcceptor,
  createDarwinNativeUnixAcceptor,
  inspectDarwinNativeAcceptedConnectionPeer,
  openDarwinNativeUnixAcceptor,
  readDarwinNativeAcceptedConnectionIdentity,
  readDarwinNativeAcceptedConnectionRequest,
  writeDarwinNativeAcceptedConnectionChallenge,
  writeDarwinNativeAcceptedConnectionResponse,
});
