"use strict";

const net = require("node:net");

const {
  hashCanonicalJson,
} = require("../../../mcp/lib/verification-contracts.js");
const {
  _internals: {
    assertClosedObject,
    assertDigest,
    assertIdentifier,
    assertInteger,
    deepFreeze,
  },
} = require("./ipc-contract.js");

const NATIVE_IPC_PEER_CREDENTIAL_ADAPTER_VERSION = 1;
const NATIVE_IPC_PEER_CREDENTIAL_SNAPSHOT_VERSION = 1;
const NATIVE_IPC_PEER_CREDENTIAL_SNAPSHOT_DOMAIN =
  "hacker-bob/instrument-broker-native-peer-credential-snapshot/v1";

const PLATFORM_PROFILES = Object.freeze({
  darwin: Object.freeze({
    primitive: "darwin_getpeereid_local_peerpid",
    executable_measurement_scheme:
      "darwin_proc_pidpath_sha256_process_start_token_v1",
  }),
  linux: Object.freeze({
    primitive: "linux_so_peercred",
    executable_measurement_scheme:
      "linux_procfs_exe_sha256_process_start_token_v1",
  }),
});

const CONFORMANCE_ADAPTERS = new WeakSet();
const CONFORMANCE_ADAPTER_STATE = new WeakMap();

function assertBindingNonce(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22,128}$/.test(value)) {
    throw new Error(`${label} must be a canonical 128-bit-or-stronger base64url nonce`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < 16 || bytes.toString("base64url") !== value) {
    throw new Error(`${label} must use canonical 128-bit-or-stronger base64url encoding`);
  }
  return value;
}

function platformProfile(platform, label = "platform") {
  if (typeof platform !== "string" || !Object.hasOwn(PLATFORM_PROFILES, platform)) {
    throw new Error(`${label} must be darwin or linux`);
  }
  return PLATFORM_PROFILES[platform];
}

function normalizeNativeIpcPeerCredentialSnapshot(
  input,
  expected,
  label = "native_ipc_peer_credential_snapshot",
) {
  assertClosedObject(input, label, [
    "version",
    "credential_source",
    "platform",
    "primitive",
    "socket_binding_nonce",
    "peer_uid",
    "peer_gid",
    "peer_pid",
    "peer_process_start_token_digest",
    "peer_executable_measurement_scheme",
    "peer_executable_measurement_digest",
    "snapshot_digest",
  ]);
  assertClosedObject(expected, `${label}_expectation`, [
    "platform",
    "primitive",
    "socket_binding_nonce",
    "peer_executable_measurement_scheme",
  ]);
  const profile = platformProfile(expected.platform, `${label}_expectation.platform`);
  if (expected.primitive !== profile.primitive
      || expected.peer_executable_measurement_scheme
        !== profile.executable_measurement_scheme) {
    throw new Error(`${label}_expectation does not use the closed platform profile`);
  }
  if (input.version !== NATIVE_IPC_PEER_CREDENTIAL_SNAPSHOT_VERSION
      || input.credential_source !== "native_os_socket"
      || input.platform !== expected.platform
      || input.primitive !== expected.primitive
      || input.socket_binding_nonce !== expected.socket_binding_nonce
      || input.peer_executable_measurement_scheme
        !== expected.peer_executable_measurement_scheme) {
    throw new Error(`${label} is not bound to the accepted socket and platform profile`);
  }
  const basis = deepFreeze({
    version: NATIVE_IPC_PEER_CREDENTIAL_SNAPSHOT_VERSION,
    credential_source: "native_os_socket",
    platform: expected.platform,
    primitive: expected.primitive,
    socket_binding_nonce: assertBindingNonce(
      input.socket_binding_nonce,
      `${label}.socket_binding_nonce`,
    ),
    peer_uid: assertInteger(input.peer_uid, `${label}.peer_uid`, 0, 2 ** 32 - 2),
    peer_gid: assertInteger(input.peer_gid, `${label}.peer_gid`, 0, 2 ** 32 - 2),
    peer_pid: assertInteger(input.peer_pid, `${label}.peer_pid`, 1, 2 ** 31 - 1),
    peer_process_start_token_digest: assertDigest(
      input.peer_process_start_token_digest,
      `${label}.peer_process_start_token_digest`,
    ),
    peer_executable_measurement_scheme: expected.peer_executable_measurement_scheme,
    peer_executable_measurement_digest: assertDigest(
      input.peer_executable_measurement_digest,
      `${label}.peer_executable_measurement_digest`,
    ),
  });
  const snapshotDigest = hashCanonicalJson({
    domain: NATIVE_IPC_PEER_CREDENTIAL_SNAPSHOT_DOMAIN,
    snapshot: basis,
  });
  if (assertDigest(input.snapshot_digest, `${label}.snapshot_digest`) !== snapshotDigest) {
    throw new Error(`${label}.snapshot_digest does not bind the closed snapshot`);
  }
  return deepFreeze({ ...basis, snapshot_digest: snapshotDigest });
}

function createConformanceNativeIpcPeerCredentialAdapter(input = {}) {
  assertClosedObject(input, "conformance_native_ipc_peer_credential_adapter", [
    "adapter_id",
    "platform",
    "primitive",
    "executable_measurement_scheme",
    "native_binding_implementation_digest",
    "inspect_accepted_socket",
  ]);
  const adapterId = assertIdentifier(
    input.adapter_id,
    "conformance_native_ipc_peer_credential_adapter.adapter_id",
  );
  const profile = platformProfile(
    input.platform,
    "conformance_native_ipc_peer_credential_adapter.platform",
  );
  if (input.platform !== process.platform
      || input.primitive !== profile.primitive
      || input.executable_measurement_scheme !== profile.executable_measurement_scheme) {
    throw new Error("conformance native peer adapter does not match the running platform profile");
  }
  const implementationDigest = assertDigest(
    input.native_binding_implementation_digest,
    "conformance_native_ipc_peer_credential_adapter.native_binding_implementation_digest",
  );
  if (typeof input.inspect_accepted_socket !== "function") {
    throw new Error(
      "conformance_native_ipc_peer_credential_adapter.inspect_accepted_socket must be a function",
    );
  }
  const port = deepFreeze({
    version: NATIVE_IPC_PEER_CREDENTIAL_ADAPTER_VERSION,
    adapter_id: adapterId,
    platform: input.platform,
    primitive: profile.primitive,
    executable_measurement_scheme: profile.executable_measurement_scheme,
    native_binding_implementation_digest: implementationDigest,
    credential_source: "native_kernel_adapter_conformance",
    production_attested: false,
  });
  CONFORMANCE_ADAPTERS.add(port);
  CONFORMANCE_ADAPTER_STATE.set(port, Object.freeze({
    inspect: input.inspect_accepted_socket,
  }));
  return port;
}

function assertConformanceNativeIpcPeerCredentialAdapter(port) {
  if (!port || typeof port !== "object" || !Object.isFrozen(port)
      || !CONFORMANCE_ADAPTERS.has(port) || !CONFORMANCE_ADAPTER_STATE.has(port)) {
    throw new Error(
      "native_ipc_peer_credential_adapter must be a privately branded conformance adapter",
    );
  }
  return port;
}

function inspectAcceptedSocketWithConformanceAdapter(port, socket, socketBindingNonce) {
  assertConformanceNativeIpcPeerCredentialAdapter(port);
  if (!(socket instanceof net.Socket) || socket.destroyed || socket.connecting) {
    throw new Error("native peer inspection requires the live accepted net.Socket");
  }
  const bindingNonce = assertBindingNonce(
    socketBindingNonce,
    "native_peer_inspection.socket_binding_nonce",
  );
  const request = Object.freeze({
    version: NATIVE_IPC_PEER_CREDENTIAL_ADAPTER_VERSION,
    purpose: "inspect_live_accepted_unix_stream_peer",
    platform: port.platform,
    required_primitive: port.primitive,
    required_executable_measurement_scheme: port.executable_measurement_scheme,
    socket_binding_nonce: bindingNonce,
    socket,
  });
  const state = CONFORMANCE_ADAPTER_STATE.get(port);
  const raw = state.inspect(request);
  if (raw && typeof raw.then === "function") {
    throw new Error("native peer credential inspection must be synchronous and one-shot");
  }
  return normalizeNativeIpcPeerCredentialSnapshot(raw, {
    platform: port.platform,
    primitive: port.primitive,
    socket_binding_nonce: bindingNonce,
    peer_executable_measurement_scheme: port.executable_measurement_scheme,
  });
}

module.exports = {
  NATIVE_IPC_PEER_CREDENTIAL_ADAPTER_VERSION,
  NATIVE_IPC_PEER_CREDENTIAL_SNAPSHOT_DOMAIN,
  NATIVE_IPC_PEER_CREDENTIAL_SNAPSHOT_VERSION,
  PLATFORM_PROFILES,
  assertConformanceNativeIpcPeerCredentialAdapter,
  createConformanceNativeIpcPeerCredentialAdapter,
  inspectAcceptedSocketWithConformanceAdapter,
  normalizeNativeIpcPeerCredentialSnapshot,
};
