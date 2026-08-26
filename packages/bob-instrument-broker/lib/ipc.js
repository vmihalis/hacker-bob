"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");

const {
  IPC_MAX_CONNECTION_TIMEOUT_MS,
  IPC_MAX_FRAME_BYTES,
  IPC_PEER_CREDENTIAL_EVIDENCE_DOMAIN,
  IPC_PROTOCOL_VERSION,
  IPC_SAFE_ERROR_CODES,
  decodeCanonicalIpcFrameBody,
  encodeIpcFrame,
  normalizeSignedIpcPeerCredentialEvidence,
  normalizeSignedIpcDispatchRequest,
  normalizeSignedIpcDispatchResponse,
  publicKeyDigest,
  signIpcDispatchResponse,
  verifyIpcDispatchRequestSignature,
  verifyIpcDispatchResponseSignature,
  verifyIpcPeerCredentialEvidenceSignature,
  _internals: {
    assertClosedObject,
    assertDigest,
    assertEd25519Key,
    assertIdentifier,
    assertInteger,
    assertToken,
    deepFreeze,
  },
} = require("./ipc-contract.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");
const {
  assertConformanceNativeIpcPeerCredentialAdapter,
  inspectAcceptedSocketWithConformanceAdapter,
} = require("./ipc-native-peer-credentials.js");

const IPC_REPLAY_PORT_VERSION = 1;
const IPC_PEER_CREDENTIAL_RESOLVER_VERSION = 1;
const IPC_STARTUP_PROVIDER_AUTHORITY_VERSION = 1;
const IPC_SERVER_VERSION = 1;
const IPC_CLIENT_VERSION = 1;
const IPC_MAX_ACTIVE_CONNECTIONS = 32;
const IPC_MAX_SOCKET_PATH_BYTES = 100;
const IPC_DEFAULT_CONNECTION_TIMEOUT_MS = 5_000;
const IPC_DEFAULT_HANDLER_TIMEOUT_MS = 5_000;
const IPC_REPLAY_DOMAIN = "hacker-bob/instrument-broker-ipc-replay/v1";
const IPC_STARTUP_PROVIDER_AUTHORITY_DOMAIN = "hacker-bob/instrument-broker-ipc-startup-provider/v1";

const REPLAY_PORTS = new WeakSet();
const REPLAY_PORT_STATE = new WeakMap();
const PEER_RESOLVER_PORTS = new WeakSet();
const PEER_RESOLVER_STATE = new WeakMap();
const ACCEPTED_SOCKET_CREDENTIAL_STATE = new WeakMap();
const STARTUP_PROVIDER_AUTHORITY_PORTS = new WeakSet();
const STARTUP_PROVIDER_AUTHORITY_STATE = new WeakMap();

const SAFE_LOCAL_ERROR_MESSAGES = Object.freeze({
  ipc_authentication_failed: "IPC authentication failed",
  ipc_connection_closed: "IPC connection closed before a complete response",
  ipc_connection_failed: "IPC connection failed",
  ipc_handler_timeout: "IPC dispatch handler exceeded its deadline",
  ipc_invalid_configuration: "IPC configuration is invalid",
  ipc_peer_rejected: "IPC peer identity was rejected",
  ipc_protocol_rejected: "IPC protocol message was rejected",
  ipc_replay_rejected: "IPC request replay or sequence was rejected",
  ipc_response_timeout: "IPC response exceeded its deadline",
  ipc_socket_path_insecure: "IPC socket path failed security validation",
  ipc_startup_mode_rejected: "IPC startup identity mode was rejected",
  ipc_transport_group_unavailable: "Separate-identity IPC requires a pre-enrolled shared-GID transport root",
});

function ipcError(code, cause = null) {
  const safeCode = Object.prototype.hasOwnProperty.call(SAFE_LOCAL_ERROR_MESSAGES, code)
    ? code
    : "ipc_protocol_rejected";
  const error = new Error(SAFE_LOCAL_ERROR_MESSAGES[safeCode]);
  error.code = safeCode;
  if (cause) Object.defineProperty(error, "cause", { value: cause });
  return error;
}

function normalizeNow(now, label = "trusted_now") {
  const value = now();
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(date.getTime())) throw ipcError("ipc_invalid_configuration");
  return date;
}

function createIpcReplayPort(input = {}) {
  assertClosedObject(input, "ipc_replay_port", ["replay_port_id", "reserve_replay"]);
  const replayPortId = assertIdentifier(input.replay_port_id, "ipc_replay_port.replay_port_id");
  if (typeof input.reserve_replay !== "function") {
    throw new Error("ipc_replay_port.reserve_replay must be a function");
  }
  const port = deepFreeze({
    version: IPC_REPLAY_PORT_VERSION,
    replay_port_id: replayPortId,
  });
  REPLAY_PORTS.add(port);
  REPLAY_PORT_STATE.set(port, Object.freeze({ reserve: input.reserve_replay }));
  return port;
}

function assertIpcReplayPort(port) {
  if (!port || typeof port !== "object" || !REPLAY_PORTS.has(port)
      || !REPLAY_PORT_STATE.has(port) || !Object.isFrozen(port)) {
    throw new Error("ipc_replay_port must be a privately branded replay port");
  }
  return port;
}

function createAdvisoryIpcPeerCredentialResolver(input = {}) {
  assertClosedObject(input, "advisory_ipc_peer_credential_resolver", [
    "resolver_id", "resolve_peer",
  ]);
  const resolverId = assertIdentifier(
    input.resolver_id,
    "advisory_ipc_peer_credential_resolver.resolver_id",
  );
  if (typeof input.resolve_peer !== "function") {
    throw new Error("advisory_ipc_peer_credential_resolver.resolve_peer must be a function");
  }
  const port = deepFreeze({
    version: IPC_PEER_CREDENTIAL_RESOLVER_VERSION,
    resolver_id: resolverId,
    credential_source: "advisory_deterministic_fixture",
    native_binding_implementation_digest: null,
    evidence_public_key_digest: null,
    evidence_epoch: null,
    production_attested: false,
  });
  PEER_RESOLVER_PORTS.add(port);
  PEER_RESOLVER_STATE.set(port, Object.freeze({
    assurance: "advisory_deterministic_fixture",
    resolve: input.resolve_peer,
  }));
  return port;
}

function createNativeEvidenceConformanceIpcPeerCredentialResolver(input = {}) {
  assertClosedObject(input, "native_evidence_conformance_ipc_peer_credential_resolver", [
    "resolver_id",
    "native_binding_implementation_digest",
    "evidence_key_id",
    "evidence_epoch",
    "evidence_public_key_digest",
    "evidence_public_key",
    "resolve_peer",
  ]);
  const resolverId = assertIdentifier(
    input.resolver_id,
    "native_evidence_conformance_ipc_peer_credential_resolver.resolver_id",
  );
  const implementationDigest = assertDigest(
    input.native_binding_implementation_digest,
    "native_evidence_conformance_ipc_peer_credential_resolver.native_binding_implementation_digest",
  );
  const evidenceKeyId = assertToken(
    input.evidence_key_id,
    "native_evidence_conformance_ipc_peer_credential_resolver.evidence_key_id",
    "ipc-key",
  );
  const evidenceEpoch = assertInteger(
    input.evidence_epoch,
    "native_evidence_conformance_ipc_peer_credential_resolver.evidence_epoch",
    1,
  );
  const evidencePublicKey = assertEd25519Key(
    input.evidence_public_key,
    "public",
    "native_evidence_conformance_ipc_peer_credential_resolver.evidence_public_key",
  );
  const evidencePublicKeyDigest = publicKeyDigest(evidencePublicKey);
  if (assertDigest(
    input.evidence_public_key_digest,
    "native_evidence_conformance_ipc_peer_credential_resolver.evidence_public_key_digest",
  ) !== evidencePublicKeyDigest) {
    throw new Error(
      "native_evidence_conformance_ipc_peer_credential_resolver.evidence_public_key_digest does not match evidence_public_key",
    );
  }
  if (typeof input.resolve_peer !== "function") {
    throw new Error(
      "native_evidence_conformance_ipc_peer_credential_resolver.resolve_peer must be a function",
    );
  }
  const port = deepFreeze({
    version: IPC_PEER_CREDENTIAL_RESOLVER_VERSION,
    resolver_id: resolverId,
    credential_source: "native_evidence_conformance",
    native_binding_implementation_digest: implementationDigest,
    evidence_public_key_digest: evidencePublicKeyDigest,
    evidence_epoch: evidenceEpoch,
    production_attested: false,
  });
  PEER_RESOLVER_PORTS.add(port);
  PEER_RESOLVER_STATE.set(port, Object.freeze({
    assurance: "native_evidence_conformance",
    implementation_digest: implementationDigest,
    evidence_key_id: evidenceKeyId,
    evidence_epoch: evidenceEpoch,
    evidence_public_key_digest: evidencePublicKeyDigest,
    evidence_public_key: evidencePublicKey,
    resolve: input.resolve_peer,
  }));
  return port;
}

function createNativeKernelAdapterConformanceIpcPeerCredentialResolver(input = {}) {
  assertClosedObject(input, "native_kernel_adapter_conformance_ipc_peer_credential_resolver", [
    "resolver_id",
    "native_adapter",
    "expected_peer_uid",
    "expected_peer_gid",
    "expected_peer_pid",
    "expected_peer_process_start_token_digest",
    "expected_peer_executable_measurement_digest",
    "ipc_peer_principal_id",
    "execution_principal_id",
    "request_key_id",
    "request_public_key",
  ]);
  const resolverId = assertIdentifier(
    input.resolver_id,
    "native_kernel_adapter_conformance_ipc_peer_credential_resolver.resolver_id",
  );
  const adapter = assertConformanceNativeIpcPeerCredentialAdapter(input.native_adapter);
  const requestPublicKey = assertEd25519Key(
    input.request_public_key,
    "public",
    "native_kernel_adapter_conformance_ipc_peer_credential_resolver.request_public_key",
  );
  const enrollment = deepFreeze({
    version: IPC_PEER_CREDENTIAL_RESOLVER_VERSION,
    adapter_id: adapter.adapter_id,
    platform: adapter.platform,
    primitive: adapter.primitive,
    native_binding_implementation_digest: adapter.native_binding_implementation_digest,
    peer_uid: assertInteger(
      input.expected_peer_uid,
      "native_kernel_adapter_conformance_ipc_peer_credential_resolver.expected_peer_uid",
      0,
      2 ** 32 - 2,
    ),
    peer_gid: assertInteger(
      input.expected_peer_gid,
      "native_kernel_adapter_conformance_ipc_peer_credential_resolver.expected_peer_gid",
      0,
      2 ** 32 - 2,
    ),
    peer_pid: assertInteger(
      input.expected_peer_pid,
      "native_kernel_adapter_conformance_ipc_peer_credential_resolver.expected_peer_pid",
      1,
      2 ** 31 - 1,
    ),
    peer_process_start_token_digest: assertDigest(
      input.expected_peer_process_start_token_digest,
      "native_kernel_adapter_conformance_ipc_peer_credential_resolver.expected_peer_process_start_token_digest",
    ),
    peer_executable_measurement_scheme: adapter.executable_measurement_scheme,
    peer_executable_measurement_digest: assertDigest(
      input.expected_peer_executable_measurement_digest,
      "native_kernel_adapter_conformance_ipc_peer_credential_resolver.expected_peer_executable_measurement_digest",
    ),
    ipc_peer_principal_id: assertToken(
      input.ipc_peer_principal_id,
      "native_kernel_adapter_conformance_ipc_peer_credential_resolver.ipc_peer_principal_id",
      "principal",
    ),
    execution_principal_id: assertToken(
      input.execution_principal_id,
      "native_kernel_adapter_conformance_ipc_peer_credential_resolver.execution_principal_id",
      "principal",
    ),
    request_key_id: assertToken(
      input.request_key_id,
      "native_kernel_adapter_conformance_ipc_peer_credential_resolver.request_key_id",
      "ipc-key",
    ),
    request_public_key_digest: publicKeyDigest(requestPublicKey),
  });
  const enrollmentDigest = hashCanonicalJson({
    domain: "hacker-bob/instrument-broker-native-peer-enrollment/v1",
    resolver_id: resolverId,
    enrollment,
  });
  const port = deepFreeze({
    version: IPC_PEER_CREDENTIAL_RESOLVER_VERSION,
    resolver_id: resolverId,
    credential_source: "native_kernel_adapter_conformance",
    native_binding_implementation_digest: adapter.native_binding_implementation_digest,
    native_platform: adapter.platform,
    native_primitive: adapter.primitive,
    executable_measurement_scheme: adapter.executable_measurement_scheme,
    peer_enrollment_digest: enrollmentDigest,
    evidence_public_key_digest: null,
    evidence_epoch: null,
    production_attested: false,
  });
  PEER_RESOLVER_PORTS.add(port);
  PEER_RESOLVER_STATE.set(port, Object.freeze({
    assurance: "native_kernel_adapter_conformance",
    adapter,
    enrollment,
    enrollment_digest: enrollmentDigest,
    request_public_key: requestPublicKey,
  }));
  return port;
}

function assertIpcPeerCredentialResolver(port) {
  if (!port || typeof port !== "object" || !PEER_RESOLVER_PORTS.has(port)
      || !PEER_RESOLVER_STATE.has(port) || !Object.isFrozen(port)) {
    throw new Error("peer_credential_resolver must be a privately branded resolver");
  }
  return port;
}

function createIpcStartupProviderAuthority(input = {}) {
  assertClosedObject(input, "ipc_startup_provider_authority", [
    "authority_id", "resolve_current_provider",
  ]);
  const authorityId = assertIdentifier(
    input.authority_id,
    "ipc_startup_provider_authority.authority_id",
  );
  if (typeof input.resolve_current_provider !== "function") {
    throw new Error("ipc_startup_provider_authority.resolve_current_provider must be a function");
  }
  const port = deepFreeze({
    version: IPC_STARTUP_PROVIDER_AUTHORITY_VERSION,
    authority_id: authorityId,
  });
  STARTUP_PROVIDER_AUTHORITY_PORTS.add(port);
  STARTUP_PROVIDER_AUTHORITY_STATE.set(port, Object.freeze({
    resolve: input.resolve_current_provider,
  }));
  return port;
}

function assertIpcStartupProviderAuthority(port) {
  if (!port || typeof port !== "object" || !STARTUP_PROVIDER_AUTHORITY_PORTS.has(port)
      || !STARTUP_PROVIDER_AUTHORITY_STATE.has(port) || !Object.isFrozen(port)) {
    throw new Error("startup_provider_authority must be a privately branded authority port");
  }
  return port;
}

function normalizeIpcStartupMode(input, label = "ipc_startup_mode") {
  assertClosedObject(input, label, [
    "version",
    "identity_mode",
    "issuer_uid",
    "worker_uid",
    "transport_gid",
    "provider_id",
    "provider_descriptor_digest",
    "provider_implementation_digest",
    "provider_kind",
  ]);
  if (input.version !== IPC_PROTOCOL_VERSION) throw new Error(`${label}.version must be 1`);
  if (!["separate_identity", "same_uid_deterministic_mock"].includes(input.identity_mode)) {
    throw new Error(`${label}.identity_mode is invalid`);
  }
  if (!["hardware", "deterministic_mock"].includes(input.provider_kind)) {
    throw new Error(`${label}.provider_kind is invalid`);
  }
  const normalized = {
    version: IPC_PROTOCOL_VERSION,
    identity_mode: input.identity_mode,
    issuer_uid: assertInteger(input.issuer_uid, `${label}.issuer_uid`, 0, 2 ** 32 - 2),
    worker_uid: assertInteger(input.worker_uid, `${label}.worker_uid`, 0, 2 ** 32 - 2),
    transport_gid: assertInteger(input.transport_gid, `${label}.transport_gid`, 0, 2 ** 32 - 2),
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    provider_implementation_digest: assertDigest(
      input.provider_implementation_digest,
      `${label}.provider_implementation_digest`,
    ),
    provider_kind: input.provider_kind,
  };
  if (normalized.identity_mode === "separate_identity") {
    if (normalized.issuer_uid === normalized.worker_uid) {
      throw ipcError("ipc_startup_mode_rejected");
    }
  } else {
    if (normalized.issuer_uid !== normalized.worker_uid
        || normalized.provider_kind !== "deterministic_mock"
        || !normalized.provider_id.startsWith("deterministic_")) {
      throw ipcError("ipc_startup_mode_rejected");
    }
  }
  return deepFreeze(normalized);
}

async function assertCurrentStartupProviderAuthority(port, startup) {
  assertIpcStartupProviderAuthority(port);
  let current;
  try {
    // The resolver receives no requested provider fields. Its current
    // enrollment must come from independent trusted custody, not by echoing the
    // startup declaration it is meant to verify.
    current = await STARTUP_PROVIDER_AUTHORITY_STATE.get(port).resolve(Object.freeze({
      version: IPC_STARTUP_PROVIDER_AUTHORITY_VERSION,
      purpose: "startup_provider_attestation",
    }));
    assertClosedObject(current, "current_ipc_startup_provider_authority", [
      "version",
      "provider_id",
      "provider_descriptor_digest",
      "provider_implementation_digest",
      "provider_kind",
      "authority_epoch",
      "trusted",
      "revoked",
      "authority_digest",
    ]);
    if (current.version !== IPC_STARTUP_PROVIDER_AUTHORITY_VERSION
        || current.provider_id !== startup.provider_id
        || current.provider_descriptor_digest !== startup.provider_descriptor_digest
        || current.provider_implementation_digest !== startup.provider_implementation_digest
        || current.provider_kind !== startup.provider_kind
        || current.trusted !== true || current.revoked !== false) {
      throw new Error("startup provider authority is not current");
    }
    const basis = {
      version: current.version,
      provider_id: current.provider_id,
      provider_descriptor_digest: current.provider_descriptor_digest,
      provider_implementation_digest: current.provider_implementation_digest,
      provider_kind: current.provider_kind,
      authority_epoch: assertInteger(current.authority_epoch, "authority_epoch", 1),
      trusted: current.trusted,
      revoked: current.revoked,
    };
    if (assertDigest(current.authority_digest, "authority_digest") !== hashCanonicalJson({
      domain: IPC_STARTUP_PROVIDER_AUTHORITY_DOMAIN,
      authority_id: port.authority_id,
      enrollment: basis,
    })) {
      throw new Error("startup provider authority digest drift");
    }
  } catch (cause) {
    throw ipcError("ipc_startup_mode_rejected", cause);
  }
  return deepFreeze({
    version: IPC_STARTUP_PROVIDER_AUTHORITY_VERSION,
    authority_id: port.authority_id,
    authority_epoch: current.authority_epoch,
    authority_digest: current.authority_digest,
  });
}

function normalizeAdvisoryPeerCredential(input, label = "resolved_peer_credential") {
  assertClosedObject(input, label, [
    "version",
    "uid",
    "gid",
    "pid",
    "ipc_peer_principal_id",
    "execution_principal_id",
    "request_key_id",
    "request_public_key",
  ]);
  if (input.version !== IPC_PEER_CREDENTIAL_RESOLVER_VERSION) {
    throw new Error(`${label}.version must be ${IPC_PEER_CREDENTIAL_RESOLVER_VERSION}`);
  }
  const publicKey = assertEd25519Key(
    input.request_public_key,
    "public",
    `${label}.request_public_key`,
  );
  return Object.freeze({
    version: IPC_PEER_CREDENTIAL_RESOLVER_VERSION,
    uid: assertInteger(input.uid, `${label}.uid`, 0, 2 ** 32 - 2),
    gid: assertInteger(input.gid, `${label}.gid`, 0, 2 ** 32 - 2),
    pid: assertInteger(input.pid, `${label}.pid`, 1, 2 ** 31 - 1),
    ipc_peer_principal_id: assertToken(
      input.ipc_peer_principal_id,
      `${label}.ipc_peer_principal_id`,
      "principal",
    ),
    execution_principal_id: assertToken(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      "principal",
    ),
    request_key_id: assertToken(input.request_key_id, `${label}.request_key_id`, "ipc-key"),
    request_public_key: publicKey,
    request_public_key_digest: publicKeyDigest(publicKey),
    credential_source: "advisory_deterministic_fixture",
    native_binding_implementation_digest: null,
    credential_evidence_digest: null,
    credential_evidence_key_id: null,
    evidence_epoch: null,
  });
}

function conformancePeerCredentialFromNativeEvidence(input, resolverState, socketState) {
  assertClosedObject(input, "resolved_native_peer_credential", [
    "evidence", "request_public_key",
  ]);
  const evidence = normalizeSignedIpcPeerCredentialEvidence(input.evidence);
  const payload = evidence.payload;
  const requestPublicKey = assertEd25519Key(
    input.request_public_key,
    "public",
    "resolved_native_peer_credential.request_public_key",
  );
  const requestPublicKeyDigest = publicKeyDigest(requestPublicKey);
  if (payload.resolver_id !== socketState.resolver_id
      || payload.socket_binding_nonce !== socketState.binding_nonce
      || payload.credential_source !== "native_os_socket"
      || payload.platform !== process.platform
      || payload.native_binding_implementation_digest !== resolverState.implementation_digest
      || payload.request_public_key_digest !== requestPublicKeyDigest
      || payload.evidence_epoch !== resolverState.evidence_epoch
      || evidence.authentication.key_id !== resolverState.evidence_key_id
      || evidence.authentication.public_key_digest !== resolverState.evidence_public_key_digest
      || payload.request_key_id === resolverState.evidence_key_id
      || requestPublicKeyDigest === resolverState.evidence_public_key_digest
      || !verifyIpcPeerCredentialEvidenceSignature(evidence, resolverState.evidence_public_key)) {
    throw new Error("native peer credential evidence is absent, untrusted, or socket-unbound");
  }
  return Object.freeze({
    version: IPC_PEER_CREDENTIAL_RESOLVER_VERSION,
    uid: payload.peer_uid,
    gid: payload.peer_gid,
    pid: payload.peer_pid,
    ipc_peer_principal_id: payload.ipc_peer_principal_id,
    execution_principal_id: payload.execution_principal_id,
    request_key_id: payload.request_key_id,
    request_public_key: requestPublicKey,
    request_public_key_digest: requestPublicKeyDigest,
    credential_source: "native_evidence_conformance",
    native_binding_implementation_digest: resolverState.implementation_digest,
    credential_evidence_digest: evidence.evidence_digest,
    credential_evidence_key_id: resolverState.evidence_key_id,
    evidence_epoch: payload.evidence_epoch,
  });
}

function conformancePeerCredentialFromNativeKernelAdapter(resolverState, socketState, socket) {
  const snapshot = inspectAcceptedSocketWithConformanceAdapter(
    resolverState.adapter,
    socket,
    socketState.binding_nonce,
  );
  const expected = resolverState.enrollment;
  if (snapshot.platform !== expected.platform
      || snapshot.primitive !== expected.primitive
      || snapshot.peer_uid !== expected.peer_uid
      || snapshot.peer_gid !== expected.peer_gid
      || snapshot.peer_pid !== expected.peer_pid
      || snapshot.peer_process_start_token_digest
        !== expected.peer_process_start_token_digest
      || snapshot.peer_executable_measurement_scheme
        !== expected.peer_executable_measurement_scheme
      || snapshot.peer_executable_measurement_digest
        !== expected.peer_executable_measurement_digest) {
    throw new Error("native kernel peer snapshot does not match exact enrolled process identity");
  }
  return Object.freeze({
    version: IPC_PEER_CREDENTIAL_RESOLVER_VERSION,
    uid: snapshot.peer_uid,
    gid: snapshot.peer_gid,
    pid: snapshot.peer_pid,
    ipc_peer_principal_id: expected.ipc_peer_principal_id,
    execution_principal_id: expected.execution_principal_id,
    request_key_id: expected.request_key_id,
    request_public_key: resolverState.request_public_key,
    request_public_key_digest: expected.request_public_key_digest,
    credential_source: "native_kernel_adapter_conformance",
    native_binding_implementation_digest: expected.native_binding_implementation_digest,
    credential_evidence_digest: snapshot.snapshot_digest,
    credential_evidence_key_id: null,
    evidence_epoch: null,
    peer_enrollment_digest: resolverState.enrollment_digest,
    peer_process_start_token_digest: snapshot.peer_process_start_token_digest,
    peer_executable_measurement_digest: snapshot.peer_executable_measurement_digest,
  });
}

async function resolvePeerCredential(port, socket) {
  assertIpcPeerCredentialResolver(port);
  const state = PEER_RESOLVER_STATE.get(port);
  const socketState = ACCEPTED_SOCKET_CREDENTIAL_STATE.get(socket);
  if (!socketState || socketState.consumed || socketState.resolver_id !== port.resolver_id) {
    throw ipcError("ipc_peer_rejected");
  }
  socketState.consumed = true;
  let resolved;
  try {
    const resolutionRequest = state.assurance === "native_evidence_conformance"
      ? Object.freeze({
        version: IPC_PEER_CREDENTIAL_RESOLVER_VERSION,
        transport: "unix",
        credential_source: "native_evidence_conformance",
        socket_binding_nonce: socketState.binding_nonce,
        evidence_domain: IPC_PEER_CREDENTIAL_EVIDENCE_DOMAIN,
        socket,
      })
      : state.assurance === "advisory_deterministic_fixture" ? Object.freeze({
        version: IPC_PEER_CREDENTIAL_RESOLVER_VERSION,
        transport: "unix",
        credential_source: "advisory_deterministic_fixture",
        purpose: "deterministic_protocol_conformance_only",
      }) : null;
    if (state.assurance === "native_kernel_adapter_conformance") {
      resolved = conformancePeerCredentialFromNativeKernelAdapter(state, socketState, socket);
    } else {
      resolved = state.resolve(resolutionRequest);
      if (resolved && typeof resolved.then === "function") {
        throw new Error("peer credential resolution must be synchronous and one-shot");
      }
    }
  } catch (cause) {
    throw ipcError("ipc_peer_rejected", cause);
  }
  try {
    return state.assurance === "native_evidence_conformance"
      ? conformancePeerCredentialFromNativeEvidence(resolved, state, socketState)
      : state.assurance === "native_kernel_adapter_conformance"
        ? resolved
      : normalizeAdvisoryPeerCredential(resolved);
  } catch (cause) {
    throw ipcError("ipc_peer_rejected", cause);
  }
}

function replayClaim(request, peer) {
  return deepFreeze({
    version: IPC_REPLAY_PORT_VERSION,
    domain: IPC_REPLAY_DOMAIN,
    request_digest: request.request_digest,
    ipc_peer_principal_id: peer.ipc_peer_principal_id,
    execution_principal_id: peer.execution_principal_id,
    peer_uid: peer.uid,
    peer_gid: peer.gid,
    peer_pid: peer.pid,
    request_key_id: peer.request_key_id,
    request_public_key_digest: peer.request_public_key_digest,
    nonce: request.payload.nonce,
    sequence: request.payload.sequence,
  });
}

async function reserveReplay(port, request, peer) {
  assertIpcReplayPort(port);
  const claim = replayClaim(request, peer);
  let result;
  try {
    result = await REPLAY_PORT_STATE.get(port).reserve(claim);
    assertClosedObject(result, "ipc_replay_reservation", [
      "version",
      "disposition",
      "previous_sequence",
      "accepted_sequence",
      "nonce",
      "claim_digest",
      "receipt_digest",
    ]);
    if (result.version !== IPC_REPLAY_PORT_VERSION) throw new Error("replay version drift");
    if (!["created", "replay", "sequence_mismatch", "nonce_reuse"].includes(result.disposition)) {
      throw new Error("replay disposition drift");
    }
    assertInteger(result.previous_sequence, "previous_sequence", 0);
    if (result.accepted_sequence !== null) {
      assertInteger(result.accepted_sequence, "accepted_sequence", 1);
    }
    if (result.nonce !== claim.nonce) throw new Error("replay nonce drift");
    if (assertDigest(result.claim_digest, "claim_digest") !== hashCanonicalJson(claim)) {
      throw new Error("replay claim digest drift");
    }
    const receiptBasis = {
      version: result.version,
      disposition: result.disposition,
      previous_sequence: result.previous_sequence,
      accepted_sequence: result.accepted_sequence,
      nonce: result.nonce,
      claim_digest: result.claim_digest,
    };
    if (assertDigest(result.receipt_digest, "receipt_digest") !== hashCanonicalJson(receiptBasis)) {
      throw new Error("replay receipt digest drift");
    }
    if (result.disposition !== "created"
        || result.previous_sequence !== claim.sequence - 1
        || result.accepted_sequence !== claim.sequence) {
      throw new Error("replay or non-contiguous sequence");
    }
  } catch (cause) {
    throw ipcError("ipc_replay_rejected", cause);
  }
  return deepFreeze({
    version: IPC_REPLAY_PORT_VERSION,
    replay_port_id: port.replay_port_id,
    receipt_digest: result.receipt_digest,
  });
}

function normalizeServerIdentity(input) {
  assertClosedObject(input, "ipc_server_identity", [
    "server_principal_id", "response_key_id", "public_key_digest", "private_key",
  ]);
  const privateKey = assertEd25519Key(
    input.private_key,
    "private",
    "ipc_server_identity.private_key",
  );
  const derivedDigest = publicKeyDigest(privateKey);
  if (assertDigest(input.public_key_digest, "ipc_server_identity.public_key_digest")
      !== derivedDigest) {
    throw new Error("ipc_server_identity.public_key_digest does not match private_key");
  }
  return Object.freeze({
    server_principal_id: assertToken(
      input.server_principal_id,
      "ipc_server_identity.server_principal_id",
      "principal",
    ),
    response_key_id: assertToken(
      input.response_key_id,
      "ipc_server_identity.response_key_id",
      "ipc-key",
    ),
    public_key_digest: derivedDigest,
    private_key: privateKey,
  });
}

function normalizeTrustedServer(input) {
  assertClosedObject(input, "trusted_ipc_server", [
    "server_principal_id", "response_key_id", "public_key_digest", "public_key",
  ]);
  const publicKey = assertEd25519Key(
    input.public_key,
    "public",
    "trusted_ipc_server.public_key",
  );
  const derivedDigest = publicKeyDigest(publicKey);
  if (assertDigest(input.public_key_digest, "trusted_ipc_server.public_key_digest")
      !== derivedDigest) {
    throw new Error("trusted_ipc_server.public_key_digest does not match public_key");
  }
  return Object.freeze({
    server_principal_id: assertToken(
      input.server_principal_id,
      "trusted_ipc_server.server_principal_id",
      "principal",
    ),
    response_key_id: assertToken(
      input.response_key_id,
      "trusted_ipc_server.response_key_id",
      "ipc-key",
    ),
    public_key_digest: derivedDigest,
    public_key: publicKey,
  });
}

function assertNoSymlinkComponents(absolutePath) {
  const parsed = path.parse(absolutePath);
  let current = parsed.root;
  for (const component of absolutePath.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) throw ipcError("ipc_socket_path_insecure");
  }
}

function rootModeForStartup(startup) {
  return startup.identity_mode === "separate_identity" ? 0o710 : 0o700;
}

function socketModeForStartup(startup) {
  return startup.identity_mode === "separate_identity" ? 0o660 : 0o600;
}

function assertSecureSocketLocation(socketRootInput, socketPathInput, startup) {
  if (process.platform === "win32" || typeof process.getuid !== "function") {
    throw ipcError("ipc_socket_path_insecure");
  }
  if (process.getuid() !== startup.worker_uid || typeof process.getgid !== "function") {
    throw ipcError("ipc_startup_mode_rejected");
  }
  if (process.getgid() !== startup.transport_gid) {
    throw ipcError("ipc_transport_group_unavailable");
  }
  if (typeof socketRootInput !== "string" || !path.isAbsolute(socketRootInput)
      || path.resolve(socketRootInput) !== socketRootInput) {
    throw ipcError("ipc_socket_path_insecure");
  }
  if (typeof socketPathInput !== "string" || !path.isAbsolute(socketPathInput)
      || path.resolve(socketPathInput) !== socketPathInput
      || path.dirname(socketPathInput) !== socketRootInput
      || Buffer.byteLength(socketPathInput, "utf8") > IPC_MAX_SOCKET_PATH_BYTES
      || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\.sock$/.test(path.basename(socketPathInput))) {
    throw ipcError("ipc_socket_path_insecure");
  }
  try {
    assertNoSymlinkComponents(socketRootInput);
    const rootStat = fs.lstatSync(socketRootInput);
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink()
        || fs.realpathSync.native(socketRootInput) !== socketRootInput) {
      throw ipcError("ipc_socket_path_insecure");
    }
    if (rootStat.uid !== startup.worker_uid || rootStat.gid !== startup.transport_gid
        || (rootStat.mode & 0o777) !== rootModeForStartup(startup)) {
      throw startup.identity_mode === "separate_identity"
        ? ipcError("ipc_transport_group_unavailable")
        : ipcError("ipc_socket_path_insecure");
    }
    try {
      fs.lstatSync(socketPathInput);
      throw ipcError("ipc_socket_path_insecure");
    } catch (cause) {
      if (cause && cause.code !== "ENOENT") throw cause;
    }
    return Object.freeze({ dev: rootStat.dev, ino: rootStat.ino });
  } catch (cause) {
    if (cause && ["ipc_socket_path_insecure", "ipc_transport_group_unavailable"].includes(cause.code)) throw cause;
    throw ipcError("ipc_socket_path_insecure", cause);
  }
}

function assertRootIdentity(socketRoot, expected, startup) {
  try {
    const stat = fs.lstatSync(socketRoot);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.dev !== expected.dev
        || stat.ino !== expected.ino) {
      throw ipcError("ipc_socket_path_insecure");
    }
    if (stat.uid !== startup.worker_uid || stat.gid !== startup.transport_gid
        || (stat.mode & 0o777) !== rootModeForStartup(startup)) {
      throw startup.identity_mode === "separate_identity"
        ? ipcError("ipc_transport_group_unavailable")
        : ipcError("ipc_socket_path_insecure");
    }
  } catch (cause) {
    if (cause && ["ipc_socket_path_insecure", "ipc_transport_group_unavailable"].includes(cause.code)) throw cause;
    throw ipcError("ipc_socket_path_insecure", cause);
  }
}

function assertCreatedSocket(socketPath, startup) {
  try {
    fs.chmodSync(socketPath, socketModeForStartup(startup));
    const stat = fs.lstatSync(socketPath);
    if (!stat.isSocket() || stat.isSymbolicLink()) {
      throw ipcError("ipc_socket_path_insecure");
    }
    if (stat.uid !== startup.worker_uid || stat.gid !== startup.transport_gid
        || (stat.mode & 0o777) !== socketModeForStartup(startup)) {
      throw startup.identity_mode === "separate_identity"
        ? ipcError("ipc_transport_group_unavailable")
        : ipcError("ipc_socket_path_insecure");
    }
    return Object.freeze({ dev: stat.dev, ino: stat.ino });
  } catch (cause) {
    if (cause && ["ipc_socket_path_insecure", "ipc_transport_group_unavailable"].includes(cause.code)) throw cause;
    throw ipcError("ipc_socket_path_insecure", cause);
  }
}

function assertSocketIdentity(socketPath, expected, startup) {
  try {
    const stat = fs.lstatSync(socketPath);
    if (!stat.isSocket() || stat.isSymbolicLink() || stat.dev !== expected.dev
        || stat.ino !== expected.ino) {
      throw ipcError("ipc_socket_path_insecure");
    }
    if (stat.uid !== startup.worker_uid || stat.gid !== startup.transport_gid
        || (stat.mode & 0o777) !== socketModeForStartup(startup)) {
      throw startup.identity_mode === "separate_identity"
        ? ipcError("ipc_transport_group_unavailable")
        : ipcError("ipc_socket_path_insecure");
    }
  } catch (cause) {
    if (cause && ["ipc_socket_path_insecure", "ipc_transport_group_unavailable"].includes(cause.code)) throw cause;
    throw ipcError("ipc_socket_path_insecure", cause);
  }
}

function frameCollector(socket, onComplete) {
  let bytes = 0;
  let expected = null;
  const chunks = [];
  let rejected = false;
  socket.on("data", (chunk) => {
    if (rejected) return;
    bytes += chunk.length;
    if (bytes > IPC_MAX_FRAME_BYTES + 4) {
      rejected = true;
      socket.destroy();
      return;
    }
    chunks.push(chunk);
    const combined = Buffer.concat(chunks, bytes);
    if (expected == null && combined.length >= 4) {
      expected = combined.readUInt32BE(0);
      if (expected < 1 || expected > IPC_MAX_FRAME_BYTES) {
        rejected = true;
        socket.destroy();
        return;
      }
    }
    if (expected != null && combined.length > expected + 4) {
      rejected = true;
      socket.destroy();
    }
  });
  socket.on("end", () => {
    if (rejected) return;
    const combined = Buffer.concat(chunks, bytes);
    if (expected == null || combined.length !== expected + 4) {
      rejected = true;
      socket.destroy();
      return;
    }
    onComplete(combined.subarray(4));
  });
  return () => rejected;
}

function assertRequestCurrent(request, now) {
  const current = now.getTime();
  const issued = Date.parse(request.payload.issued_at);
  const deadline = Date.parse(request.payload.deadline);
  if (issued > current || current > deadline) {
    throw ipcError("ipc_protocol_rejected");
  }
}

function assertPeerMatchesRequest(peer, request, startup, serverIdentity, resolverAssurance) {
  const payload = request.payload;
  if (peer.uid !== startup.issuer_uid
      || peer.gid !== startup.transport_gid
      || peer.credential_source !== resolverAssurance
      || peer.ipc_peer_principal_id !== payload.ipc_peer_principal_id
      || peer.execution_principal_id !== payload.execution_principal_id
      || peer.execution_principal_id !== serverIdentity.server_principal_id
      || peer.request_key_id !== request.authentication.key_id
      || peer.request_key_id === serverIdentity.response_key_id
      || peer.request_public_key_digest !== request.authentication.public_key_digest
      || peer.request_public_key_digest === serverIdentity.public_key_digest) {
    throw ipcError("ipc_peer_rejected");
  }
  if (!verifyIpcDispatchRequestSignature(request, peer.request_public_key)) {
    throw ipcError("ipc_authentication_failed");
  }
}

function normalizeHandlerResult(input) {
  assertClosedObject(input, "ipc_dispatch_handler_result", [
    "status", "error_code", "operation_result",
  ]);
  if (!["completed", "rejected", "ambiguous"].includes(input.status)) {
    throw new Error("ipc_dispatch_handler_result.status is invalid");
  }
  if (input.status === "completed") {
    if (input.error_code !== null) throw new Error("completed result must have null error_code");
  } else if (!IPC_SAFE_ERROR_CODES.includes(input.error_code)) {
    throw new Error("handler error_code is not safe");
  }
  return Object.freeze({
    status: input.status,
    error_code: input.error_code,
    // The response contract performs the bounded JSON clone. Retaining the
    // original here makes unsupported values fail instead of being silently
    // erased by a stringify/parse coercion.
    operation_result: input.operation_result,
  });
}

async function listenUnix(server, socketPath) {
  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(socketPath);
  });
}

async function closeNetServer(server, sockets) {
  for (const socket of sockets) socket.destroy();
  await new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close(() => resolve());
  });
}

async function createInstrumentBrokerIpcServer(input = {}) {
  assertClosedObject(input, "instrument_broker_ipc_server", [
    "socket_root",
    "socket_path",
    "startup_mode",
    "startup_provider_authority",
    "peer_credential_resolver",
    "replay_port",
    "server_identity",
    "dispatch_handler",
  ], ["now", "connection_timeout_ms", "handler_timeout_ms"]);
  const startup = normalizeIpcStartupMode(input.startup_mode);
  // The package currently ships no non-JavaScript capability that can prove
  // native peer credentials or OS/HIL custody. Refuse unsupported execution
  // modes before invoking any caller-supplied authority or resolver callback.
  if (startup.provider_kind === "hardware" || startup.identity_mode === "separate_identity") {
    throw ipcError("ipc_startup_mode_rejected");
  }
  assertIpcStartupProviderAuthority(input.startup_provider_authority);
  const startupAuthority = await assertCurrentStartupProviderAuthority(
    input.startup_provider_authority,
    startup,
  );
  assertIpcPeerCredentialResolver(input.peer_credential_resolver);
  const peerResolverState = PEER_RESOLVER_STATE.get(input.peer_credential_resolver);
  // No reviewed native/platform adapter or HIL-qualified production capability
  // exists in this package. Exported JavaScript factories are conformance
  // surfaces only and can never authorize hardware or separate-identity mode.
  if (!["advisory_deterministic_fixture", "native_evidence_conformance",
    "native_kernel_adapter_conformance"].includes(
    peerResolverState.assurance,
  )) {
    throw ipcError("ipc_startup_mode_rejected");
  }
  assertIpcReplayPort(input.replay_port);
  const identity = normalizeServerIdentity(input.server_identity);
  if (peerResolverState.assurance === "native_evidence_conformance"
      && (peerResolverState.evidence_public_key_digest === identity.public_key_digest
        || peerResolverState.evidence_key_id === identity.response_key_id)) {
    throw ipcError("ipc_startup_mode_rejected");
  }
  if (typeof input.dispatch_handler !== "function") {
    throw new Error("instrument_broker_ipc_server.dispatch_handler must be a function");
  }
  const now = input.now == null ? () => new Date() : input.now;
  if (typeof now !== "function") throw new Error("instrument_broker_ipc_server.now must be a function");
  const connectionTimeoutMs = input.connection_timeout_ms == null
    ? IPC_DEFAULT_CONNECTION_TIMEOUT_MS
    : assertInteger(
      input.connection_timeout_ms,
      "instrument_broker_ipc_server.connection_timeout_ms",
      1,
      IPC_MAX_CONNECTION_TIMEOUT_MS,
    );
  const handlerTimeoutMs = input.handler_timeout_ms == null
    ? IPC_DEFAULT_HANDLER_TIMEOUT_MS
    : assertInteger(
      input.handler_timeout_ms,
      "instrument_broker_ipc_server.handler_timeout_ms",
      1,
      IPC_MAX_CONNECTION_TIMEOUT_MS,
    );
  const rootIdentity = assertSecureSocketLocation(
    input.socket_root,
    input.socket_path,
    startup,
  );

  const sockets = new Set();
  let activeConnections = 0;
  let outstandingCallbacks = 0;
  let closing = false;
  let ready = false;
  let socketIdentity = null;
  function reserveCallbackSlot() {
    if (outstandingCallbacks >= IPC_MAX_ACTIVE_CONNECTIONS) {
      throw ipcError("ipc_protocol_rejected");
    }
    outstandingCallbacks += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      outstandingCallbacks -= 1;
    };
  }

  function trackCallbackPromise(promise, release) {
    promise.then(release, release);
    return promise;
  }

  const server = net.createServer({ allowHalfOpen: true }, (socket) => {
    if (closing || !ready || activeConnections >= IPC_MAX_ACTIVE_CONNECTIONS
        || outstandingCallbacks >= IPC_MAX_ACTIVE_CONNECTIONS) {
      socket.destroy();
      return;
    }
    try {
      assertRootIdentity(input.socket_root, rootIdentity, startup);
      assertSocketIdentity(input.socket_path, socketIdentity, startup);
    } catch {
      socket.destroy();
      return;
    }
    activeConnections += 1;
    sockets.add(socket);
    ACCEPTED_SOCKET_CREDENTIAL_STATE.set(socket, {
      resolver_id: input.peer_credential_resolver.resolver_id,
      binding_nonce: crypto.randomBytes(24).toString("base64url"),
      consumed: false,
    });
    socket.setTimeout(connectionTimeoutMs, () => socket.destroy());
    socket.once("close", () => {
      activeConnections -= 1;
      sockets.delete(socket);
    });
    frameCollector(socket, async (body) => {
      let request;
      let admitted = false;
      try {
        const decoded = decodeCanonicalIpcFrameBody(body);
        request = normalizeSignedIpcDispatchRequest(decoded);
        assertRequestCurrent(request, normalizeNow(now));
        if (request.payload.provider_id !== startup.provider_id
            || request.payload.provider_descriptor_digest !== startup.provider_descriptor_digest) {
          throw ipcError("ipc_peer_rejected");
        }
        const peer = await resolvePeerCredential(input.peer_credential_resolver, socket);
        if (socket.destroyed || closing) return;
        assertPeerMatchesRequest(peer, request, startup, identity, peerResolverState.assurance);
        const releaseReplaySlot = reserveCallbackSlot();
        const replayPromise = trackCallbackPromise(
          reserveReplay(input.replay_port, request, peer),
          releaseReplaySlot,
        );
        const replayReservation = await replayPromise;
        admitted = true;
        if (socket.destroyed || closing) return;

        const abortController = new AbortController();
        const onClose = () => abortController.abort();
        socket.once("close", onClose);
        const current = normalizeNow(now);
        const remaining = Date.parse(request.payload.deadline) - current.getTime();
        if (remaining <= 0) throw ipcError("ipc_handler_timeout");
        const timeout = Math.min(handlerTimeoutMs, remaining);
        let timeoutId;
        const timeoutPromise = new Promise((_, reject) => {
          timeoutId = setTimeout(() => {
            abortController.abort();
            reject(ipcError("ipc_handler_timeout"));
          }, timeout);
          timeoutId.unref?.();
        });
        const dispatchContext = deepFreeze({
          version: IPC_PROTOCOL_VERSION,
          request_digest: request.request_digest,
          ipc_peer_principal_id: request.payload.ipc_peer_principal_id,
          execution_principal_id: request.payload.execution_principal_id,
          provider_id: request.payload.provider_id,
          provider_descriptor_digest: request.payload.provider_descriptor_digest,
          provider_implementation_digest: startup.provider_implementation_digest,
          startup_provider_authority_id: startupAuthority.authority_id,
          startup_provider_authority_epoch: startupAuthority.authority_epoch,
          startup_provider_authority_digest: startupAuthority.authority_digest,
          operation_id: request.payload.operation_id,
          operation_payload_digest: request.payload.operation_payload_digest,
          operation_payload: request.payload.operation_payload,
          deadline: request.payload.deadline,
          replay_receipt_reserved: true,
          replay_port_id: replayReservation.replay_port_id,
          replay_receipt_digest: replayReservation.receipt_digest,
          peer_credential_source: peer.credential_source,
          peer_credential_evidence_digest: peer.credential_evidence_digest,
          peer_credential_evidence_epoch: peer.evidence_epoch,
          peer_credential_enrollment_digest: peer.peer_enrollment_digest || null,
          peer_executable_measurement_digest:
            peer.peer_executable_measurement_digest || null,
        });
        let handlerResult;
        try {
          const releaseHandlerSlot = reserveCallbackSlot();
          let handlerPromise;
          try {
            handlerPromise = Promise.resolve(
              input.dispatch_handler(dispatchContext, abortController.signal),
            );
          } catch (cause) {
            releaseHandlerSlot();
            throw cause;
          }
          trackCallbackPromise(handlerPromise, releaseHandlerSlot);
          handlerResult = await Promise.race([
            handlerPromise,
            timeoutPromise,
          ]);
        } finally {
          clearTimeout(timeoutId);
          socket.off("close", onClose);
        }
        if (socket.destroyed || closing || abortController.signal.aborted) return;
        const normalizedResult = normalizeHandlerResult(handlerResult);
        const respondedAt = normalizeNow(now);
        if (respondedAt.getTime() > Date.parse(request.payload.deadline)) {
          throw ipcError("ipc_handler_timeout");
        }
        const response = signIpcDispatchResponse({
          version: IPC_PROTOCOL_VERSION,
          request_digest: request.request_digest,
          request_id: request.payload.request_id,
          request_nonce: request.payload.nonce,
          request_sequence: request.payload.sequence,
          server_principal_id: identity.server_principal_id,
          status: normalizedResult.status,
          error_code: normalizedResult.error_code,
          operation_result_digest: hashCanonicalJson(normalizedResult.operation_result),
          operation_result: normalizedResult.operation_result,
          responded_at: respondedAt.toISOString(),
        }, {
          key_id: identity.response_key_id,
          public_key_digest: identity.public_key_digest,
          private_key: identity.private_key,
        });
        socket.end(encodeIpcFrame(response));
      } catch (cause) {
        if (!admitted || !request || socket.destroyed || closing) {
          socket.destroy();
          return;
        }
        if (cause && cause.code === "ipc_handler_timeout") {
          socket.destroy();
          return;
        }
        try {
          const respondedAt = normalizeNow(now);
          if (respondedAt.getTime() > Date.parse(request.payload.deadline)) {
            socket.destroy();
            return;
          }
          const response = signIpcDispatchResponse({
            version: IPC_PROTOCOL_VERSION,
            request_digest: request.request_digest,
            request_id: request.payload.request_id,
            request_nonce: request.payload.nonce,
            request_sequence: request.payload.sequence,
            server_principal_id: identity.server_principal_id,
            status: "ambiguous",
            error_code: "dispatch_unavailable",
            operation_result_digest: hashCanonicalJson(null),
            operation_result: null,
            responded_at: respondedAt.toISOString(),
          }, {
            key_id: identity.response_key_id,
            public_key_digest: identity.public_key_digest,
            private_key: identity.private_key,
          });
          socket.end(encodeIpcFrame(response));
        } catch {
          socket.destroy();
        }
      }
    });
  });
  // Runtime listener errors are intentionally reduced to connection failure at
  // the transport boundary; no path, credential, key, or payload is logged.
  server.on("error", () => {});
  server.maxConnections = IPC_MAX_ACTIVE_CONNECTIONS;
  try {
    await listenUnix(server, input.socket_path);
    assertRootIdentity(input.socket_root, rootIdentity, startup);
    socketIdentity = assertCreatedSocket(input.socket_path, startup);
    assertRootIdentity(input.socket_root, rootIdentity, startup);
    assertSocketIdentity(input.socket_path, socketIdentity, startup);
    ready = true;
  } catch (cause) {
    await closeNetServer(server, sockets);
    throw cause && ["ipc_socket_path_insecure", "ipc_transport_group_unavailable"].includes(cause.code)
      ? cause
      : ipcError("ipc_socket_path_insecure", cause);
  }

  const projection = deepFreeze({
    version: IPC_SERVER_VERSION,
    transport: "unix",
    identity_mode: startup.identity_mode,
    issuer_uid: startup.issuer_uid,
    worker_uid: startup.worker_uid,
    transport_gid: startup.transport_gid,
    provider_id: startup.provider_id,
    provider_descriptor_digest: startup.provider_descriptor_digest,
    provider_implementation_digest: startup.provider_implementation_digest,
    provider_kind: startup.provider_kind,
    peer_credential_source: input.peer_credential_resolver.credential_source,
    peer_credential_conformance_implementation_digest:
      input.peer_credential_resolver.native_binding_implementation_digest,
    peer_credential_evidence_public_key_digest:
      input.peer_credential_resolver.evidence_public_key_digest,
    peer_credential_evidence_epoch: input.peer_credential_resolver.evidence_epoch || null,
    peer_credential_native_platform:
      input.peer_credential_resolver.native_platform || null,
    peer_credential_native_primitive:
      input.peer_credential_resolver.native_primitive || null,
    peer_credential_executable_measurement_scheme:
      input.peer_credential_resolver.executable_measurement_scheme || null,
    peer_credential_enrollment_digest:
      input.peer_credential_resolver.peer_enrollment_digest || null,
    startup_provider_authority_id: startupAuthority.authority_id,
    startup_provider_authority_epoch: startupAuthority.authority_epoch,
    startup_provider_authority_digest: startupAuthority.authority_digest,
    server_principal_id: identity.server_principal_id,
    response_public_key_digest: identity.public_key_digest,
    max_frame_bytes: IPC_MAX_FRAME_BYTES,
    max_messages_per_connection: 1,
    max_active_connections: IPC_MAX_ACTIVE_CONNECTIONS,
    connection_timeout_ms: connectionTimeoutMs,
    handler_timeout_ms: handlerTimeoutMs,
    production_ready: false,
    production_attested: false,
    readiness_blockers: Object.freeze([
      "native_peer_credential_adapter_requires_operator_hil_qualification",
      "unix_pathname_checks_do_not_replace_native_openat_custody",
      "pure_ipc_conformance_tests_do_not_prove_os_principal_or_device_acl_separation",
    ]),
  });
  let closePromise = null;
  const port = {
    version: IPC_SERVER_VERSION,
    transport: "unix",
    projection: () => projection,
    close: () => {
      if (closePromise) return closePromise;
      closing = true;
      closePromise = (async () => {
        let custodyError = null;
        try {
          assertRootIdentity(input.socket_root, rootIdentity, startup);
          assertSocketIdentity(input.socket_path, socketIdentity, startup);
        } catch (cause) {
          custodyError = cause;
        }
        await closeNetServer(server, sockets);
        if (custodyError) throw custodyError;
      })();
      return closePromise;
    },
  };
  return Object.freeze(port);
}

function validateClientResponse(response, request, trusted) {
  if (response.payload.request_digest !== request.request_digest
      || response.payload.request_id !== request.payload.request_id
      || response.payload.request_nonce !== request.payload.nonce
      || response.payload.request_sequence !== request.payload.sequence
      || response.payload.server_principal_id !== trusted.server_principal_id
      || response.authentication.key_id !== trusted.response_key_id
      || response.authentication.public_key_digest !== trusted.public_key_digest
      || !verifyIpcDispatchResponseSignature(response, trusted.public_key)) {
    throw ipcError("ipc_authentication_failed");
  }
  const responded = Date.parse(response.payload.responded_at);
  if (responded < Date.parse(request.payload.issued_at)
      || responded > Date.parse(request.payload.deadline)) {
    throw ipcError("ipc_protocol_rejected");
  }
}

async function sendInstrumentBrokerIpcRequest(input = {}) {
  assertClosedObject(input, "instrument_broker_ipc_client", [
    "socket_path", "request_envelope", "trusted_server",
  ], ["timeout_ms"]);
  if (typeof input.socket_path !== "string" || !path.isAbsolute(input.socket_path)) {
    throw ipcError("ipc_invalid_configuration");
  }
  const request = normalizeSignedIpcDispatchRequest(input.request_envelope);
  const trusted = normalizeTrustedServer(input.trusted_server);
  const timeoutMs = input.timeout_ms == null
    ? IPC_DEFAULT_CONNECTION_TIMEOUT_MS
    : assertInteger(input.timeout_ms, "instrument_broker_ipc_client.timeout_ms", 1,
      IPC_MAX_CONNECTION_TIMEOUT_MS);
  const outbound = encodeIpcFrame(request);

  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: input.socket_path, allowHalfOpen: true });
    let settled = false;
    let ended = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };
    const succeed = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    socket.setTimeout(timeoutMs, () => fail(ipcError("ipc_response_timeout")));
    socket.once("connect", () => socket.end(outbound));
    socket.once("error", (cause) => fail(ipcError("ipc_connection_failed", cause)));
    frameCollector(socket, (body) => {
      ended = true;
      try {
        const decoded = decodeCanonicalIpcFrameBody(body);
        const response = normalizeSignedIpcDispatchResponse(decoded);
        validateClientResponse(response, request, trusted);
        succeed(deepFreeze({
          version: IPC_CLIENT_VERSION,
          status: response.payload.status,
          error_code: response.payload.error_code,
          operation_result: response.payload.operation_result,
          operation_result_digest: response.payload.operation_result_digest,
          request_digest: response.payload.request_digest,
          response_digest: response.response_digest,
        }));
      } catch (cause) {
        fail(cause && SAFE_LOCAL_ERROR_MESSAGES[cause.code]
          ? cause
          : ipcError("ipc_protocol_rejected", cause));
      }
    });
    socket.once("close", () => {
      if (!settled && !ended) fail(ipcError("ipc_connection_closed"));
    });
  });
}

module.exports = {
  IPC_CLIENT_VERSION,
  IPC_MAX_ACTIVE_CONNECTIONS,
  IPC_PEER_CREDENTIAL_RESOLVER_VERSION,
  IPC_REPLAY_DOMAIN,
  IPC_REPLAY_PORT_VERSION,
  IPC_SERVER_VERSION,
  IPC_STARTUP_PROVIDER_AUTHORITY_VERSION,
  IPC_STARTUP_PROVIDER_AUTHORITY_DOMAIN,
  assertIpcReplayPort,
  assertIpcStartupProviderAuthority,
  assertIpcPeerCredentialResolver,
  createAdvisoryIpcPeerCredentialResolver,
  createInstrumentBrokerIpcServer,
  createNativeEvidenceConformanceIpcPeerCredentialResolver,
  createNativeKernelAdapterConformanceIpcPeerCredentialResolver,
  createIpcReplayPort,
  createIpcStartupProviderAuthority,
  normalizeIpcStartupMode,
  sendInstrumentBrokerIpcRequest,
};
