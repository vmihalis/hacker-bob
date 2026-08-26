"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");

const {
  IPC_MAX_FRAME_BYTES,
  IPC_PEER_CREDENTIAL_EVIDENCE_DOMAIN,
  IPC_REQUEST_DOMAIN,
  encodeIpcFrame,
  normalizeSignedIpcDispatchRequest,
  projectIpcDispatchRequest,
  publicKeyDigest,
  signIpcDispatchRequest,
  signIpcPeerCredentialEvidence,
} = require("../lib/ipc-contract.js");
const {
  assertIpcReplayPort,
  assertIpcStartupProviderAuthority,
  assertIpcPeerCredentialResolver,
  createAdvisoryIpcPeerCredentialResolver,
  createInstrumentBrokerIpcServer,
  createNativeEvidenceConformanceIpcPeerCredentialResolver,
  createNativeKernelAdapterConformanceIpcPeerCredentialResolver,
  createIpcReplayPort,
  createIpcStartupProviderAuthority,
  IPC_STARTUP_PROVIDER_AUTHORITY_DOMAIN,
  normalizeIpcStartupMode,
  sendInstrumentBrokerIpcRequest,
} = require("../lib/ipc.js");
const {
  NATIVE_IPC_PEER_CREDENTIAL_SNAPSHOT_DOMAIN,
  PLATFORM_PROFILES,
  createConformanceNativeIpcPeerCredentialAdapter,
} = require("../lib/ipc-native-peer-credentials.js");
const {
  canonicalJson,
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const FIXED_NOW = "2026-07-18T09:00:00.100Z";

function clone(value) {
  return structuredClone(value);
}

function digest(label) {
  return hashCanonicalJson({ label });
}

function nonce() {
  return crypto.randomBytes(18).toString("base64url");
}

// Anchored to the repository, not to process.cwd(). A Unix socket path is
// capped (IPC_MAX_SOCKET_PATH_BYTES = 100) and the caller's working directory
// decided how much of that budget was already spent, so the same code passed
// or failed on where it was invoked from: `npm test --prefix <pkg>` runs the
// script from the repo root under one bundled npm and from the package
// directory under another, and the deeper cwd pushed every socket path past
// the cap. Keep it out of os.tmpdir() too — that is a symlink on macOS and
// the location check requires a path equal to its own realpath.
const REPOSITORY_ROOT = path.resolve(__dirname, "..", "..", "..");

function secureTempRoot(mode = 0o700) {
  const root = fs.mkdtempSync(path.join(REPOSITORY_ROOT, ".bob-ipc-test-"));
  fs.chmodSync(root, mode);
  return root;
}

function startupProviderAuthority(enrollment, options = {}) {
  const authorityId = options.authority_id || "test_startup_provider_authority";
  const enrolled = Object.freeze({
    provider_id: enrollment.provider_id,
    provider_descriptor_digest: enrollment.provider_descriptor_digest,
    provider_implementation_digest: enrollment.provider_implementation_digest,
    provider_kind: enrollment.provider_kind,
  });
  return createIpcStartupProviderAuthority({
    authority_id: authorityId,
    resolve_current_provider: () => {
      if (options.outage) throw new Error("authority unavailable");
      const basis = {
        version: 1,
        ...enrolled,
        authority_epoch: 7,
        trusted: options.trusted !== false,
        revoked: options.revoked === true,
      };
      return Object.freeze({
        ...basis,
        authority_digest: hashCanonicalJson({
          domain: IPC_STARTUP_PROVIDER_AUTHORITY_DOMAIN,
          authority_id: authorityId,
          enrollment: basis,
        }),
      });
    },
  });
}

function replayPort() {
  const state = new Map();
  return createIpcReplayPort({
    replay_port_id: "deterministic_ipc_replay",
    reserve_replay: (claim) => {
      const key = [
        claim.peer_uid,
        claim.ipc_peer_principal_id,
        claim.execution_principal_id,
        claim.request_key_id,
      ].join("\0");
      const current = state.get(key) || { sequence: 0, nonces: new Set() };
      let disposition = "created";
      let acceptedSequence = claim.sequence;
      if (current.nonces.has(claim.nonce)) {
        disposition = "nonce_reuse";
        acceptedSequence = null;
      } else if (claim.sequence !== current.sequence + 1) {
        disposition = "sequence_mismatch";
        acceptedSequence = null;
      } else {
        current.nonces.add(claim.nonce);
        current.sequence = claim.sequence;
        state.set(key, current);
      }
      const basis = {
        version: 1,
        disposition,
        previous_sequence: disposition === "created" ? claim.sequence - 1 : current.sequence,
        accepted_sequence: acceptedSequence,
        nonce: claim.nonce,
        claim_digest: hashCanonicalJson(claim),
      };
      return Object.freeze({ ...basis, receipt_digest: hashCanonicalJson(basis) });
    },
  });
}

async function fixture(t, options = {}) {
  const workerUid = process.getuid();
  const transportGid = process.getgid();
  const startupMode = options.startup_mode || {
    version: 1,
    identity_mode: "same_uid_deterministic_mock",
    issuer_uid: workerUid,
    worker_uid: workerUid,
    transport_gid: transportGid,
    provider_id: "deterministic_fixture",
    provider_descriptor_digest: digest("deterministic-provider-descriptor"),
    provider_implementation_digest: digest("deterministic-provider-implementation"),
    provider_kind: "deterministic_mock",
  };
  const issuerUid = startupMode.issuer_uid;
  const root = options.root || secureTempRoot(
    startupMode.identity_mode === "separate_identity" ? 0o710 : 0o700,
  );
  const socketPath = path.join(root, "broker.sock");
  const requestKeys = crypto.generateKeyPairSync("ed25519");
  const responseKeys = crypto.generateKeyPairSync("ed25519");
  const nativeEvidenceKeys = crypto.generateKeyPairSync("ed25519");
  const untrustedNativeEvidenceKeys = crypto.generateKeyPairSync("ed25519");
  const peer = {
    version: 1,
    uid: issuerUid,
    gid: typeof process.getgid === "function" ? process.getgid() : 20,
    pid: process.pid,
    ipc_peer_principal_id: "principal:ipc-broker-issuer",
    execution_principal_id: "principal:ipc-provider-worker",
    request_key_id: "ipc-key:broker-request-v1",
    request_public_key: requestKeys.publicKey,
  };
  let peerTransform = options.peer_transform || ((value) => value);
  let handlerCalls = 0;
  let lastDispatch = null;
  let server;
  try {
    const peerCredentialResolver = options.peer_credential_resolver
      || (options.peer_credential_mode === "native_kernel_adapter_conformance"
        ? (() => {
          const profile = PLATFORM_PROFILES[process.platform];
          if (!profile) throw new Error("test platform has no native peer credential profile");
          const processStartTokenDigest = digest("test-issuer-process-start-token");
          const executableMeasurementDigest = digest("test-issuer-executable-measurement");
          const adapter = createConformanceNativeIpcPeerCredentialAdapter({
            adapter_id: "native_kernel_test_adapter",
            platform: process.platform,
            primitive: profile.primitive,
            executable_measurement_scheme: profile.executable_measurement_scheme,
            native_binding_implementation_digest: digest("native-kernel-test-adapter"),
            inspect_accepted_socket: (resolution) => {
              options.on_native_kernel_inspection?.(resolution);
              const resolvedPeer = peerTransform({ ...peer });
              const basisInput = {
                version: 1,
                credential_source: "native_os_socket",
                platform: process.platform,
                primitive: profile.primitive,
                socket_binding_nonce: resolution.socket_binding_nonce,
                peer_uid: resolvedPeer.uid,
                peer_gid: resolvedPeer.gid,
                peer_pid: resolvedPeer.pid,
                peer_process_start_token_digest: processStartTokenDigest,
                peer_executable_measurement_scheme: profile.executable_measurement_scheme,
                peer_executable_measurement_digest: executableMeasurementDigest,
              };
              const basis = options.native_kernel_snapshot_transform
                ? options.native_kernel_snapshot_transform(basisInput, resolution)
                : basisInput;
              const result = {
                ...basis,
                snapshot_digest: hashCanonicalJson({
                  domain: NATIVE_IPC_PEER_CREDENTIAL_SNAPSHOT_DOMAIN,
                  snapshot: basis,
                }),
              };
              return options.native_kernel_result_transform
                ? options.native_kernel_result_transform(result, resolution)
                : result;
            },
          });
          return createNativeKernelAdapterConformanceIpcPeerCredentialResolver({
            resolver_id: "native_kernel_test_resolver",
            native_adapter: adapter,
            expected_peer_uid: peer.uid,
            expected_peer_gid: peer.gid,
            expected_peer_pid: peer.pid,
            expected_peer_process_start_token_digest: processStartTokenDigest,
            expected_peer_executable_measurement_digest: executableMeasurementDigest,
            ipc_peer_principal_id: peer.ipc_peer_principal_id,
            execution_principal_id: peer.execution_principal_id,
            request_key_id: peer.request_key_id,
            request_public_key: peer.request_public_key,
          });
        })()
        : options.peer_credential_mode === "native_evidence_conformance"
        ? createNativeEvidenceConformanceIpcPeerCredentialResolver({
          resolver_id: "native_test_peer_resolver",
          native_binding_implementation_digest: digest("native-test-binding-implementation"),
          evidence_key_id: "ipc-key:native-peer-evidence-v1",
          evidence_epoch: 1,
          evidence_public_key_digest: publicKeyDigest(nativeEvidenceKeys.publicKey),
          evidence_public_key: nativeEvidenceKeys.publicKey,
          resolve_peer: (resolution) => {
            options.on_native_resolution?.();
            assert.equal(Object.isFrozen(resolution), true);
            assert.equal(resolution.evidence_domain, IPC_PEER_CREDENTIAL_EVIDENCE_DOMAIN);
            assert.ok(resolution.socket instanceof net.Socket);
            const resolvedPeer = peerTransform({ ...peer });
            const payloadInput = {
              version: 1,
              resolver_id: "native_test_peer_resolver",
              socket_binding_nonce: resolution.socket_binding_nonce,
              credential_source: "native_os_socket",
              platform: process.platform,
              native_binding_implementation_digest: digest("native-test-binding-implementation"),
              peer_uid: resolvedPeer.uid,
              peer_gid: resolvedPeer.gid,
              peer_pid: resolvedPeer.pid,
              ipc_peer_principal_id: resolvedPeer.ipc_peer_principal_id,
              execution_principal_id: resolvedPeer.execution_principal_id,
              request_key_id: resolvedPeer.request_key_id,
              request_public_key_digest: publicKeyDigest(resolvedPeer.request_public_key),
              evidence_epoch: 1,
            };
            const payload = options.native_evidence_payload_transform
              ? options.native_evidence_payload_transform(payloadInput, resolution)
              : payloadInput;
            const signerKeys = options.untrusted_native_evidence
              ? untrustedNativeEvidenceKeys
              : nativeEvidenceKeys;
            const result = {
              evidence: signIpcPeerCredentialEvidence(payload, {
                key_id: "ipc-key:native-peer-evidence-v1",
                public_key_digest: publicKeyDigest(signerKeys.publicKey),
                private_key: signerKeys.privateKey,
              }),
              request_public_key: resolvedPeer.request_public_key,
            };
            return options.native_evidence_result_transform
              ? options.native_evidence_result_transform(result, resolution)
              : result;
          },
        })
        : createAdvisoryIpcPeerCredentialResolver({
          resolver_id: "advisory_test_peer_resolver",
          resolve_peer: () => peerTransform({ ...peer }),
        }));
    server = await createInstrumentBrokerIpcServer({
      socket_root: root,
      socket_path: socketPath,
      startup_mode: startupMode,
      startup_provider_authority: options.startup_provider_authority
        || startupProviderAuthority(startupMode),
      peer_credential_resolver: peerCredentialResolver,
      replay_port: options.replay_port || replayPort(),
      server_identity: {
        server_principal_id: "principal:ipc-provider-worker",
        response_key_id: "ipc-key:provider-response-v1",
        public_key_digest: publicKeyDigest(responseKeys.publicKey),
        private_key: responseKeys.privateKey,
      },
      dispatch_handler: options.dispatch_handler || ((dispatch) => {
        handlerCalls += 1;
        lastDispatch = dispatch;
        return {
          status: "completed",
          error_code: null,
          operation_result: { observed_request_digest: dispatch.request_digest },
        };
      }),
      now: () => new Date(FIXED_NOW),
      connection_timeout_ms: options.connection_timeout_ms || 250,
      handler_timeout_ms: options.handler_timeout_ms || 200,
    });
  } catch (error) {
    if (!options.root) fs.rmSync(root, { recursive: true, force: true });
    throw error;
  }
  t.after(async () => {
    await server.close();
    if (!options.root) fs.rmSync(root, { recursive: true, force: true });
  });

  function request(overrides = {}, signer = null) {
    const operationPayload = Object.prototype.hasOwnProperty.call(overrides, "operation_payload")
      ? overrides.operation_payload
      : { opaque_dispatch_ref: "dispatch:ipc-test-0001" };
    const payload = {
      version: 1,
      request_id: `ipc-request:${nonce()}`,
      ipc_peer_principal_id: peer.ipc_peer_principal_id,
      execution_principal_id: peer.execution_principal_id,
      provider_id: startupMode.provider_id,
      provider_descriptor_digest: startupMode.provider_descriptor_digest,
      operation_id: "instrument.inventory",
      operation_payload_digest: hashCanonicalJson(operationPayload),
      operation_payload: operationPayload,
      nonce: nonce(),
      sequence: 1,
      issued_at: "2026-07-18T09:00:00.000Z",
      deadline: "2026-07-18T09:00:10.000Z",
      ...overrides,
    };
    if (Object.prototype.hasOwnProperty.call(overrides, "operation_payload")
        && !Object.prototype.hasOwnProperty.call(overrides, "operation_payload_digest")) {
      payload.operation_payload_digest = hashCanonicalJson(payload.operation_payload);
    }
    const signing = signer || {
      key_id: peer.request_key_id,
      public_key_digest: publicKeyDigest(requestKeys.publicKey),
      private_key: requestKeys.privateKey,
    };
    return signIpcDispatchRequest(payload, signing);
  }

  return {
    root,
    socketPath,
    peer,
    requestKeys,
    responseKeys,
    server,
    request,
    trustedServer: {
      server_principal_id: "principal:ipc-provider-worker",
      response_key_id: "ipc-key:provider-response-v1",
      public_key_digest: publicKeyDigest(responseKeys.publicKey),
      public_key: responseKeys.publicKey,
    },
    client: (requestEnvelope, timeoutMs = 500) => sendInstrumentBrokerIpcRequest({
      socket_path: socketPath,
      request_envelope: requestEnvelope,
      trusted_server: {
        server_principal_id: "principal:ipc-provider-worker",
        response_key_id: "ipc-key:provider-response-v1",
        public_key_digest: publicKeyDigest(responseKeys.publicKey),
        public_key: responseKeys.publicKey,
      },
      timeout_ms: timeoutMs,
    }),
    handlerCalls: () => handlerCalls,
    lastDispatch: () => lastDispatch,
    setPeerTransform: (transform) => { peerTransform = transform; },
  };
}

async function rawSend(socketPath, bytes, { destroy = false } = {}) {
  await new Promise((resolve) => {
    const socket = net.createConnection({ path: socketPath, allowHalfOpen: true });
    const timer = setTimeout(() => socket.destroy(), 500);
    socket.once("connect", () => {
      socket.write(bytes);
      if (destroy) socket.destroy();
      else socket.end();
    });
    socket.once("error", () => {});
    socket.once("close", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

test("IPC request contract is closed, domain-separated, canonical, and digest-bound", () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const operationPayload = { exact_dispatch_ref: "dispatch:opaque-contract" };
  const signed = signIpcDispatchRequest({
    version: 1,
    request_id: `ipc-request:${nonce()}`,
    ipc_peer_principal_id: "principal:contract-peer",
    execution_principal_id: "principal:contract-worker",
    provider_id: "deterministic_contract",
    provider_descriptor_digest: digest("contract-provider"),
    operation_id: "instrument.inventory",
    operation_payload_digest: hashCanonicalJson(operationPayload),
    operation_payload: operationPayload,
    nonce: nonce(),
    sequence: 1,
    issued_at: "2026-07-18T09:00:00.000Z",
    deadline: "2026-07-18T09:00:10.000Z",
  }, {
    key_id: "ipc-key:contract-request",
    public_key_digest: publicKeyDigest(keys.publicKey),
    private_key: keys.privateKey,
  });

  assert.equal(signed.domain, IPC_REQUEST_DOMAIN);
  assert.deepEqual(normalizeSignedIpcDispatchRequest(signed), signed);
  const projectionText = JSON.stringify(projectIpcDispatchRequest(signed));
  assert.doesNotMatch(projectionText, /signature|authentication|operation_payload"/);
  assert.doesNotMatch(projectionText, /BEGIN (?:PUBLIC|PRIVATE) KEY/);

  const unknown = clone(signed);
  unknown.payload.agent_callable_effect = true;
  assert.throws(() => normalizeSignedIpcDispatchRequest(unknown), /unknown fields/);

  const callerAssertedOsIdentity = clone(signed);
  callerAssertedOsIdentity.payload.peer_uid = 0;
  assert.throws(
    () => normalizeSignedIpcDispatchRequest(callerAssertedOsIdentity),
    /unknown fields: peer_uid/,
  );

  const drift = clone(signed);
  drift.payload.operation_payload.exact_dispatch_ref = "dispatch:drift";
  assert.throws(() => normalizeSignedIpcDispatchRequest(drift), /does not bind operation_payload/);

  const wrongDomain = clone(signed);
  wrongDomain.domain = "hacker-bob/instrument-broker-ipc-response/v1";
  assert.throws(() => normalizeSignedIpcDispatchRequest(wrongDomain), /domain is invalid/);
});

test("startup modes require identity separation for hardware and constrain same-UID mocks", () => {
  const uid = process.getuid();
  assert.throws(() => normalizeIpcStartupMode({
    version: 1,
    identity_mode: "same_uid_deterministic_mock",
    issuer_uid: uid,
    worker_uid: uid,
    transport_gid: process.getgid(),
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: digest("startup-chameleon"),
    provider_implementation_digest: digest("startup-chameleon-implementation"),
    provider_kind: "hardware",
  }), (error) => error.code === "ipc_startup_mode_rejected");
  assert.throws(() => normalizeIpcStartupMode({
    version: 1,
    identity_mode: "same_uid_deterministic_mock",
    issuer_uid: uid,
    worker_uid: uid,
    transport_gid: process.getgid(),
    provider_id: "mock_provider",
    provider_descriptor_digest: digest("startup-mock"),
    provider_implementation_digest: digest("startup-mock-implementation"),
    provider_kind: "deterministic_mock",
  }), (error) => error.code === "ipc_startup_mode_rejected");
  assert.throws(() => normalizeIpcStartupMode({
    version: 1,
    identity_mode: "separate_identity",
    issuer_uid: uid,
    worker_uid: uid,
    transport_gid: process.getgid(),
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: digest("startup-chameleon"),
    provider_implementation_digest: digest("startup-chameleon-implementation"),
    provider_kind: "hardware",
  }), (error) => error.code === "ipc_startup_mode_rejected");
  assert.equal(normalizeIpcStartupMode({
    version: 1,
    identity_mode: "same_uid_deterministic_mock",
    issuer_uid: uid,
    worker_uid: uid,
    transport_gid: process.getgid(),
    provider_id: "deterministic_fixture",
    provider_descriptor_digest: digest("startup-deterministic"),
    provider_implementation_digest: digest("startup-deterministic-implementation"),
    provider_kind: "deterministic_mock",
  }).provider_id, "deterministic_fixture");
});

test("replay, advisory peer credentials, and provider authority remain privately branded", () => {
  const replay = createIpcReplayPort({
    replay_port_id: "private_replay_port",
    reserve_replay: () => { throw new Error("not invoked"); },
  });
  const resolver = createAdvisoryIpcPeerCredentialResolver({
    resolver_id: "private_advisory_peer_resolver",
    resolve_peer: () => { throw new Error("not invoked"); },
  });
  const authority = startupProviderAuthority({
    provider_id: "deterministic_private",
    provider_descriptor_digest: digest("private-descriptor"),
    provider_implementation_digest: digest("private-implementation"),
    provider_kind: "deterministic_mock",
  });
  assert.equal(Object.isFrozen(replay), true);
  assert.equal(Object.isFrozen(resolver), true);
  assert.equal(Object.isFrozen(authority), true);
  assert.doesNotMatch(JSON.stringify(replay), /reserve|function/);
  assert.doesNotMatch(JSON.stringify(resolver), /resolve_peer|function/);
  assert.doesNotMatch(JSON.stringify(authority), /resolve_current_provider|function/);
  assert.throws(() => assertIpcReplayPort({ ...replay }), /privately branded/);
  assert.throws(
    () => assertIpcPeerCredentialResolver({ ...resolver }),
    /privately branded/,
  );
  assert.throws(
    () => assertIpcStartupProviderAuthority({ ...authority }),
    /privately branded/,
  );
  assert.throws(() => { authority.authority_id = "mutated"; }, TypeError);
});

test("hardware startup refuses advisory same-process peer identity", async (t) => {
  const workerUid = process.getuid();
  const hardware = {
    version: 1,
    identity_mode: "separate_identity",
    issuer_uid: workerUid === 2 ** 32 - 2 ? workerUid - 1 : workerUid + 1,
    worker_uid: workerUid,
    transport_gid: process.getgid(),
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: digest("hardware-advisory-refusal-descriptor"),
    provider_implementation_digest: digest("hardware-advisory-refusal-implementation"),
    provider_kind: "hardware",
  };
  await assert.rejects(
    fixture(t, { startup_mode: hardware }),
    (error) => error.code === "ipc_startup_mode_rejected",
  );
});

test("self-signed native-evidence conformance cannot authorize hardware startup", async (t) => {
  assert.equal(
    Object.hasOwn(require("../lib/ipc.js"), "createNativeIpcPeerCredentialResolver"),
    false,
  );
  const workerUid = process.getuid();
  const hardware = {
    version: 1,
    identity_mode: "separate_identity",
    issuer_uid: workerUid === 2 ** 32 - 2 ? workerUid - 1 : workerUid + 1,
    worker_uid: workerUid,
    transport_gid: process.getgid(),
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: digest("native-evidence-chameleon-descriptor"),
    provider_implementation_digest: digest("native-evidence-chameleon-implementation"),
    provider_kind: "hardware",
  };
  let resolverCalls = 0;
  let handlerCalls = 0;
  let authorityCalls = 0;
  const unreachableAuthority = createIpcStartupProviderAuthority({
    authority_id: "unreachable_hardware_authority",
    resolve_current_provider: () => {
      authorityCalls += 1;
      throw new Error("unsupported hardware startup must not invoke authority callbacks");
    },
  });
  await assert.rejects(fixture(t, {
    startup_mode: hardware,
    startup_provider_authority: unreachableAuthority,
    peer_credential_mode: "native_evidence_conformance",
    on_native_resolution: () => { resolverCalls += 1; },
    dispatch_handler: () => {
      handlerCalls += 1;
      return { status: "completed", error_code: null, operation_result: null };
    },
  }), (error) => error.code === "ipc_startup_mode_rejected");
  assert.equal(resolverCalls, 0);
  assert.equal(handlerCalls, 0);
  assert.equal(authorityCalls, 0);

  await assert.rejects(fixture(t, {
    startup_mode: {
      ...hardware,
      provider_id: "deterministic_forged_separate_identity",
      provider_descriptor_digest: digest("forged-separate-mock-descriptor"),
      provider_implementation_digest: digest("forged-separate-mock-implementation"),
      provider_kind: "deterministic_mock",
    },
    startup_provider_authority: unreachableAuthority,
    peer_credential_mode: "native_evidence_conformance",
    on_native_resolution: () => { resolverCalls += 1; },
    dispatch_handler: () => {
      handlerCalls += 1;
      return { status: "completed", error_code: null, operation_result: null };
    },
  }), (error) => error.code === "ipc_startup_mode_rejected");
  assert.equal(resolverCalls, 0);
  assert.equal(handlerCalls, 0);
  assert.equal(authorityCalls, 0);
});

test("signed native-evidence conformance is socket-bound only for deterministic mock IPC", async (t) => {
  const f = await fixture(t, {
    peer_credential_mode: "native_evidence_conformance",
  });
  const request = f.request();
  assert.equal((await f.client(request)).status, "completed");
  assert.equal(f.handlerCalls(), 1);
  assert.equal(
    f.lastDispatch().provider_implementation_digest,
    digest("deterministic-provider-implementation"),
  );
  assert.match(f.lastDispatch().peer_credential_evidence_digest, /^[a-f0-9]{64}$/);
  assert.equal(f.lastDispatch().peer_credential_evidence_epoch, 1);
  const projection = f.server.projection();
  assert.equal(projection.provider_kind, "deterministic_mock");
  assert.equal(projection.identity_mode, "same_uid_deterministic_mock");
  assert.equal(projection.peer_credential_source, "native_evidence_conformance");
  assert.equal(
    projection.peer_credential_conformance_implementation_digest,
    digest("native-test-binding-implementation"),
  );
  assert.equal(projection.production_ready, false);
  assert.equal(projection.production_attested, false);
});

test("kernel-adapter conformance binds the accepted socket to exact process enrollment", {
  skip: !PLATFORM_PROFILES[process.platform],
}, async (t) => {
  let inspections = 0;
  const f = await fixture(t, {
    peer_credential_mode: "native_kernel_adapter_conformance",
    on_native_kernel_inspection: (resolution) => {
      inspections += 1;
      assert.equal(Object.isFrozen(resolution), true);
      assert.equal(resolution.purpose, "inspect_live_accepted_unix_stream_peer");
      assert.equal(resolution.platform, process.platform);
      assert.equal(
        resolution.required_primitive,
        PLATFORM_PROFILES[process.platform].primitive,
      );
      assert.ok(resolution.socket instanceof net.Socket);
      assert.equal(Object.hasOwn(resolution, "socket_path"), false);
      assert.equal(Object.hasOwn(resolution, "claimed_pid"), false);
    },
  });
  assert.equal(inspections, 0);
  assert.equal((await f.client(f.request())).status, "completed");
  assert.equal(inspections, 1);
  assert.equal(f.handlerCalls(), 1);
  assert.equal(
    f.lastDispatch().peer_credential_source,
    "native_kernel_adapter_conformance",
  );
  assert.match(f.lastDispatch().peer_credential_evidence_digest, /^[a-f0-9]{64}$/);
  assert.match(f.lastDispatch().peer_credential_enrollment_digest, /^[a-f0-9]{64}$/);
  assert.equal(
    f.lastDispatch().peer_executable_measurement_digest,
    digest("test-issuer-executable-measurement"),
  );

  const projection = f.server.projection();
  assert.equal(projection.peer_credential_source, "native_kernel_adapter_conformance");
  assert.equal(projection.peer_credential_native_platform, process.platform);
  assert.equal(
    projection.peer_credential_native_primitive,
    PLATFORM_PROFILES[process.platform].primitive,
  );
  assert.equal(
    projection.peer_credential_executable_measurement_scheme,
    PLATFORM_PROFILES[process.platform].executable_measurement_scheme,
  );
  assert.match(projection.peer_credential_enrollment_digest, /^[a-f0-9]{64}$/);
  assert.equal(projection.production_ready, false);
  assert.equal(projection.production_attested, false);
});

test("kernel-adapter conformance rejects peer, process, measurement, socket, and shape drift", {
  skip: !PLATFORM_PROFILES[process.platform],
}, async (t) => {
  const cases = [
    ["kernel uid", { peer_transform: (peer) => ({ ...peer, uid: peer.uid + 1 }) }],
    ["kernel gid", { peer_transform: (peer) => ({ ...peer, gid: peer.gid + 1 }) }],
    ["kernel pid", { peer_transform: (peer) => ({ ...peer, pid: peer.pid + 1 }) }],
    ["process start token", {
      native_kernel_snapshot_transform: (snapshot) => ({
        ...snapshot,
        peer_process_start_token_digest: digest("substituted-process-start-token"),
      }),
    }],
    ["executable measurement", {
      native_kernel_snapshot_transform: (snapshot) => ({
        ...snapshot,
        peer_executable_measurement_digest: digest("substituted-executable"),
      }),
    }],
    ["platform primitive", {
      native_kernel_snapshot_transform: (snapshot) => ({
        ...snapshot,
        primitive: "advisory_process_lookup",
      }),
    }],
    ["socket binding nonce", {
      native_kernel_snapshot_transform: (snapshot) => ({
        ...snapshot,
        socket_binding_nonce: nonce(),
      }),
    }],
    ["advisory pathname field", {
      native_kernel_result_transform: (result) => ({
        ...result,
        socket_path: "/tmp/caller-asserted.sock",
      }),
    }],
    ["advisory process field", {
      native_kernel_result_transform: (result) => ({
        ...result,
        process_claim: { pid: process.pid },
      }),
    }],
    ["asynchronous adapter", {
      native_kernel_result_transform: (result) => Promise.resolve(result),
    }],
  ];
  for (const [label, options] of cases) {
    await t.test(label, async (st) => {
      const f = await fixture(st, {
        peer_credential_mode: "native_kernel_adapter_conformance",
        ...options,
      });
      await assert.rejects(f.client(f.request()), (error) => [
        "ipc_connection_closed", "ipc_connection_failed",
      ].includes(error.code));
      assert.equal(f.handlerCalls(), 0);
    });
  }
});

test("injectable kernel-adapter conformance cannot authorize hardware or separate identity", {
  skip: !PLATFORM_PROFILES[process.platform],
}, async (t) => {
  const workerUid = process.getuid();
  let inspections = 0;
  await assert.rejects(fixture(t, {
    startup_mode: {
      version: 1,
      identity_mode: "separate_identity",
      issuer_uid: workerUid === 2 ** 32 - 2 ? workerUid - 1 : workerUid + 1,
      worker_uid: workerUid,
      transport_gid: process.getgid(),
      provider_id: "chameleon_ultra",
      provider_descriptor_digest: digest("kernel-conformance-hardware-descriptor"),
      provider_implementation_digest: digest("kernel-conformance-hardware-implementation"),
      provider_kind: "hardware",
    },
    peer_credential_mode: "native_kernel_adapter_conformance",
    on_native_kernel_inspection: () => { inspections += 1; },
  }), (error) => error.code === "ipc_startup_mode_rejected");
  assert.equal(inspections, 0);
});

test("absent, untrusted, stale, and asynchronous conformance evidence fail closed", async (t) => {
  const cases = [
    ["absent evidence", { native_evidence_result_transform: () => ({}) }],
    ["untrusted signer", { untrusted_native_evidence: true }],
    ["stale socket nonce", {
      native_evidence_payload_transform: (payload) => ({
        ...payload,
        socket_binding_nonce: nonce(),
      }),
    }],
    ["implementation drift", {
      native_evidence_payload_transform: (payload) => ({
        ...payload,
        native_binding_implementation_digest: digest("substituted-native-binding"),
      }),
    }],
    ["evidence epoch drift", {
      native_evidence_payload_transform: (payload) => ({
        ...payload,
        evidence_epoch: payload.evidence_epoch + 1,
      }),
    }],
    ["native uid enrollment drift", {
      peer_transform: (peer) => ({ ...peer, uid: peer.uid + 1 }),
    }],
    ["native gid enrollment drift", {
      peer_transform: (peer) => ({ ...peer, gid: peer.gid + 1 }),
    }],
    ["asynchronous resolver", {
      native_evidence_result_transform: (result) => Promise.resolve(result),
    }],
  ];
  for (const [label, options] of cases) {
    await t.test(label, async (st) => {
      const f = await fixture(st, {
        peer_credential_mode: "native_evidence_conformance",
        ...options,
      });
      await assert.rejects(f.client(f.request()), (error) => [
        "ipc_connection_closed", "ipc_connection_failed",
      ].includes(error.code));
      assert.equal(f.handlerCalls(), 0);
    });
  }
});

test("same-UID startup requires a current exact deterministic implementation enrollment", async (t) => {
  const uid = process.getuid();
  const enrolled = {
    version: 1,
    identity_mode: "same_uid_deterministic_mock",
    issuer_uid: uid,
    worker_uid: uid,
    transport_gid: process.getgid(),
    provider_id: "deterministic_fixture",
    provider_descriptor_digest: digest("enrolled-deterministic-descriptor"),
    provider_implementation_digest: digest("enrolled-deterministic-implementation"),
    provider_kind: "deterministic_mock",
  };
  const exactAuthority = startupProviderAuthority(enrolled);
  const allowed = await fixture(t, {
    startup_mode: enrolled,
    startup_provider_authority: exactAuthority,
  });
  assert.equal(allowed.server.projection().provider_id, "deterministic_fixture");
  assert.equal(fs.lstatSync(allowed.socketPath).mode & 0o777, 0o600);
  const cases = [
    ["invented deterministic prefix", {
      ...enrolled,
      provider_id: "deterministic_invented",
    }, exactAuthority, "ipc_startup_mode_rejected"],
    ["descriptor drift", {
      ...enrolled,
      provider_descriptor_digest: digest("invented-descriptor"),
    }, exactAuthority, "ipc_startup_mode_rejected"],
    ["implementation drift", {
      ...enrolled,
      provider_implementation_digest: digest("invented-implementation"),
    }, exactAuthority, "ipc_startup_mode_rejected"],
    ["cloned authority", enrolled, { ...exactAuthority }, null],
    ["revoked authority", enrolled, startupProviderAuthority(enrolled, { revoked: true }),
      "ipc_startup_mode_rejected"],
    ["authority outage", enrolled, startupProviderAuthority(enrolled, { outage: true }),
      "ipc_startup_mode_rejected"],
  ];
  for (const [label, startupMode, authority, expectedCode] of cases) {
    await t.test(label, async (st) => {
      await assert.rejects(
        fixture(st, {
          startup_mode: startupMode,
          startup_provider_authority: authority,
        }),
        (error) => expectedCode == null
          ? /privately branded/.test(error.message)
          : error.code === expectedCode,
      );
    });
  }
});

test("real Unix socket deterministic conformance round trip remains explicitly non-production", async (t) => {
  const f = await fixture(t);
  const request = f.request();
  const result = await f.client(request);
  assert.equal(result.status, "completed");
  assert.equal(result.error_code, null);
  assert.equal(result.operation_result.observed_request_digest, request.request_digest);
  assert.equal(f.handlerCalls(), 1);
  assert.equal(f.lastDispatch().operation_payload_digest, request.payload.operation_payload_digest);
  assert.deepEqual(f.lastDispatch().operation_payload, request.payload.operation_payload);
  assert.equal(f.lastDispatch().replay_receipt_reserved, true);
  assert.match(f.lastDispatch().replay_receipt_digest, /^[a-f0-9]{64}$/);
  assert.equal(f.lastDispatch().peer_credential_source, "advisory_deterministic_fixture");
  assert.equal(f.lastDispatch().peer_credential_evidence_digest, null);

  const projection = f.server.projection();
  assert.equal(projection.provider_kind, "deterministic_mock");
  assert.equal(projection.peer_credential_source, "advisory_deterministic_fixture");
  assert.equal(projection.production_ready, false);
  assert.equal(projection.production_attested, false);
  assert.ok(projection.readiness_blockers.includes(
    "native_peer_credential_adapter_requires_operator_hil_qualification",
  ));
  assert.equal(projection.max_messages_per_connection, 1);
  assert.equal(projection.issuer_uid, projection.worker_uid);
  const rootStat = fs.lstatSync(f.root);
  const socketStat = fs.lstatSync(f.socketPath);
  assert.equal(rootStat.uid, projection.worker_uid);
  assert.equal(rootStat.gid, projection.transport_gid);
  assert.equal(rootStat.mode & 0o777, 0o700);
  assert.equal(rootStat.mode & 0o070, 0, "same-UID mock root has no group access");
  assert.equal(rootStat.mode & 0o007, 0, "unrelated identities have no root access");
  assert.equal(socketStat.uid, projection.worker_uid);
  assert.equal(socketStat.gid, projection.transport_gid);
  assert.equal(socketStat.mode & 0o777, 0o600);
  assert.equal(socketStat.mode & 0o060, 0, "same-UID mock socket has no group access");
  assert.equal(socketStat.mode & 0o007, 0, "unrelated identities have no socket access");
  assert.equal(Object.prototype.hasOwnProperty.call(projection, "socket_path"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(f.server, "socket_path"), false);
  const projectionText = JSON.stringify(projection);
  assert.doesNotMatch(projectionText, /signature|private_key|BEGIN (?:PUBLIC|PRIVATE) KEY/);
});

test("framing refuses partial, oversized, noncanonical, and multiple-message streams", async (t) => {
  const f = await fixture(t);
  const signed = f.request();
  const frame = encodeIpcFrame(signed);

  await rawSend(f.socketPath, frame.subarray(0, 12), { destroy: true });

  const oversize = Buffer.alloc(4);
  oversize.writeUInt32BE(IPC_MAX_FRAME_BYTES + 1);
  await rawSend(f.socketPath, oversize);

  const noncanonicalBody = Buffer.from(` ${canonicalJson(signed)}`, "utf8");
  const noncanonicalHeader = Buffer.alloc(4);
  noncanonicalHeader.writeUInt32BE(noncanonicalBody.length);
  await rawSend(f.socketPath, Buffer.concat([noncanonicalHeader, noncanonicalBody]));

  await rawSend(f.socketPath, Buffer.concat([frame, frame]));
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(f.handlerCalls(), 0);
});

test("nonce replay and non-contiguous sequences are rejected before dispatch", async (t) => {
  const f = await fixture(t);
  const first = f.request({ sequence: 1 });
  assert.equal((await f.client(first)).status, "completed");
  await assert.rejects(f.client(first), (error) => [
    "ipc_connection_closed", "ipc_connection_failed",
  ].includes(error.code));
  assert.equal(f.handlerCalls(), 1);

  const third = f.request({ sequence: 3 });
  await assert.rejects(f.client(third), (error) => [
    "ipc_connection_closed", "ipc_connection_failed",
  ].includes(error.code));
  assert.equal(f.handlerCalls(), 1);

  const second = f.request({ sequence: 2 });
  assert.equal((await f.client(second)).status, "completed");
  assert.equal(f.handlerCalls(), 2);
});

test("unsettled replay custody remains one-shot and globally bounded after socket timeout", async (t) => {
  let replayCalls = 0;
  const neverSettles = createIpcReplayPort({
    replay_port_id: "bounded_unsettled_replay",
    reserve_replay: () => {
      replayCalls += 1;
      return new Promise(() => {});
    },
  });
  const f = await fixture(t, {
    replay_port: neverSettles,
    connection_timeout_ms: 20,
  });
  const attempts = Array.from({ length: 48 }, () => f.client(f.request(), 80));
  await Promise.allSettled(attempts);
  assert.ok(replayCalls > 0);
  assert.ok(replayCalls <= 32, `unsettled replay callbacks exceeded the cap: ${replayCalls}`);
  const callsAtCap = replayCalls;
  await assert.rejects(f.client(f.request(), 80));
  // The property is the global cap, not that 48 concurrent attempts happened
  // to saturate it. On a slower host only 31 of the 48 land before the socket
  // timeout, so the extra request takes the one free slot and reaches 32 —
  // still within the cap, but the old equality read that as unbounded work.
  // Assert the cap directly, and keep the one-shot check where it is
  // meaningful: once saturated, nothing further may be admitted.
  assert.ok(
    replayCalls <= 32,
    `timed-out replay callbacks cannot admit unbounded work: ${replayCalls}`,
  );
  if (callsAtCap === 32) {
    assert.equal(replayCalls, callsAtCap, "a saturated replay cap admits no further work");
  }
  assert.equal(f.handlerCalls(), 0);
});

test("unsettled handlers remain globally bounded after their abort deadlines", async (t) => {
  const permissiveReplay = createIpcReplayPort({
    replay_port_id: "bounded_handler_replay_fixture",
    reserve_replay: (claim) => {
      const basis = {
        version: 1,
        disposition: "created",
        previous_sequence: claim.sequence - 1,
        accepted_sequence: claim.sequence,
        nonce: claim.nonce,
        claim_digest: hashCanonicalJson(claim),
      };
      return { ...basis, receipt_digest: hashCanonicalJson(basis) };
    },
  });
  let handlerCalls = 0;
  const f = await fixture(t, {
    replay_port: permissiveReplay,
    handler_timeout_ms: 10,
    dispatch_handler: () => {
      handlerCalls += 1;
      return new Promise(() => {});
    },
  });
  await Promise.allSettled(
    Array.from({ length: 48 }, () => f.client(f.request(), 80)),
  );
  assert.ok(handlerCalls > 0);
  assert.ok(handlerCalls <= 32, `unsettled handlers exceeded the cap: ${handlerCalls}`);
  const callsAtCap = handlerCalls;
  await assert.rejects(f.client(f.request(), 80));
  // Same shape as the replay cap above: bound the total, and only require
  // strict one-shot behaviour once the cap was actually reached.
  assert.ok(
    handlerCalls <= 32,
    `abandoned handlers cannot admit unbounded work: ${handlerCalls}`,
  );
  if (callsAtCap === 32) {
    assert.equal(handlerCalls, callsAtCap, "a saturated handler cap admits no further work");
  }
});

test("peer credential, authenticated key, and principal drift fail before dispatch", async (t) => {
  const cases = [
    ["resolver uid", (f) => {
      f.setPeerTransform((peer) => ({ ...peer, uid: peer.uid + 1 }));
      return f.request();
    }],
    ["resolver gid", (f) => {
      f.setPeerTransform((peer) => ({ ...peer, gid: peer.gid + 1 }));
      return f.request();
    }],
    ["peer principal", (f) => f.request({ ipc_peer_principal_id: "principal:drift-peer" })],
    ["execution principal", (f) => f.request({ execution_principal_id: "principal:drift-worker" })],
    ["provider descriptor", (f) => f.request({
      provider_descriptor_digest: digest("drift-provider-descriptor"),
    })],
    ["authenticated key", (f) => {
      const other = crypto.generateKeyPairSync("ed25519");
      return f.request({}, {
        key_id: "ipc-key:other-request",
        public_key_digest: publicKeyDigest(other.publicKey),
        private_key: other.privateKey,
      });
    }],
    ["request signature", (f) => {
      const request = clone(f.request());
      request.authentication.signature = crypto.sign(
        null,
        Buffer.alloc(32, 0x5a),
        f.requestKeys.privateKey,
      ).toString("base64url");
      const basis = {
        version: request.version,
        kind: request.kind,
        domain: request.domain,
        payload: request.payload,
        authentication: request.authentication,
      };
      request.request_digest = hashCanonicalJson(basis);
      return request;
    }],
  ];
  for (const [label, build] of cases) {
    await t.test(label, async (st) => {
      const f = await fixture(st);
      await assert.rejects(f.client(build(f)), (error) => [
        "ipc_connection_closed", "ipc_connection_failed",
      ].includes(error.code));
      assert.equal(f.handlerCalls(), 0);
    });
  }
  await t.test("resolver and request cannot agree on a different worker principal", async (st) => {
    const f = await fixture(st);
    f.setPeerTransform((peer) => ({
      ...peer,
      execution_principal_id: "principal:colluding-drift-worker",
    }));
    const request = f.request({
      execution_principal_id: "principal:colluding-drift-worker",
    });
    await assert.rejects(f.client(request), (error) => [
      "ipc_connection_closed", "ipc_connection_failed",
    ].includes(error.code));
    assert.equal(f.handlerCalls(), 0);
  });
});

test("client rejects response signer drift", async (t) => {
  const f = await fixture(t);
  const other = crypto.generateKeyPairSync("ed25519");
  await assert.rejects(sendInstrumentBrokerIpcRequest({
    socket_path: f.socketPath,
    request_envelope: f.request(),
    trusted_server: {
      server_principal_id: "principal:ipc-provider-worker",
      response_key_id: "ipc-key:provider-response-v1",
      public_key_digest: publicKeyDigest(other.publicKey),
      public_key: other.publicKey,
    },
    timeout_ms: 500,
  }), (error) => error.code === "ipc_authentication_failed");
  assert.equal(f.handlerCalls(), 1);
});

test("handler failures cross the socket only as fixed safe codes", async (t) => {
  const f = await fixture(t, {
    dispatch_handler: () => {
      throw new Error("never expose credential=hotel-master-secret");
    },
  });
  const result = await f.client(f.request());
  assert.equal(result.status, "ambiguous");
  assert.equal(result.error_code, "dispatch_unavailable");
  assert.equal(result.operation_result, null);
  assert.doesNotMatch(JSON.stringify(result), /hotel-master-secret|credential=/);
});

test("handler timeout and client disconnect close safely", async (t) => {
  let aborted = false;
  const f = await fixture(t, {
    handler_timeout_ms: 20,
    dispatch_handler: (_dispatch, signal) => new Promise(() => {
      signal.addEventListener("abort", () => { aborted = true; }, { once: true });
    }),
  });
  await assert.rejects(f.client(f.request(), 250), (error) => [
    "ipc_connection_closed", "ipc_connection_failed", "ipc_response_timeout",
  ].includes(error.code));
  assert.equal(aborted, true);

  const partial = encodeIpcFrame(f.request({ sequence: 2 })).subarray(0, 16);
  await rawSend(f.socketPath, partial, { destroy: true });
});

test("socket root permissions, symlinks, occupied paths, and traversal fail closed", async (t) => {
  const uid = process.getuid();
  const requestKeys = crypto.generateKeyPairSync("ed25519");
  const responseKeys = crypto.generateKeyPairSync("ed25519");
  const base = secureTempRoot(0o700);
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));

  function config(root, socketPath) {
    const startupMode = {
      version: 1,
      identity_mode: "same_uid_deterministic_mock",
      issuer_uid: uid,
      worker_uid: uid,
      transport_gid: process.getgid(),
      provider_id: "deterministic_path_fixture",
      provider_descriptor_digest: digest("deterministic-path-provider-descriptor"),
      provider_implementation_digest: digest("deterministic-path-provider-implementation"),
      provider_kind: "deterministic_mock",
    };
    return {
      socket_root: root,
      socket_path: socketPath,
      startup_mode: startupMode,
      startup_provider_authority: startupProviderAuthority(startupMode),
      peer_credential_resolver: createAdvisoryIpcPeerCredentialResolver({
        resolver_id: "path_test_advisory_resolver",
        resolve_peer: () => ({
          version: 1,
          uid,
          gid: process.getgid(),
          pid: process.pid,
          ipc_peer_principal_id: "principal:path-peer",
          execution_principal_id: "principal:path-worker",
          request_key_id: "ipc-key:path-request",
          request_public_key: requestKeys.publicKey,
        }),
      }),
      replay_port: replayPort(),
      server_identity: {
        server_principal_id: "principal:path-worker",
        response_key_id: "ipc-key:path-response",
        public_key_digest: publicKeyDigest(responseKeys.publicKey),
        private_key: responseKeys.privateKey,
      },
      dispatch_handler: () => ({ status: "completed", error_code: null, operation_result: null }),
    };
  }

  fs.chmodSync(base, 0o755);
  await assert.rejects(
    createInstrumentBrokerIpcServer(config(base, path.join(base, "mode.sock"))),
    (error) => error.code === "ipc_socket_path_insecure",
  );
  fs.chmodSync(base, 0o700);

  const target = path.join(base, "target");
  fs.mkdirSync(target, { mode: 0o700 });
  const link = path.join(path.dirname(base), `${path.basename(base)}-link`);
  fs.symlinkSync(target, link);
  t.after(() => fs.rmSync(link, { force: true }));
  await assert.rejects(
    createInstrumentBrokerIpcServer(config(link, path.join(link, "link.sock"))),
    (error) => error.code === "ipc_socket_path_insecure",
  );

  const occupied = path.join(base, "occupied.sock");
  fs.symlinkSync(path.join(base, "missing"), occupied);
  await assert.rejects(
    createInstrumentBrokerIpcServer(config(base, occupied)),
    (error) => error.code === "ipc_socket_path_insecure",
  );

  const occupiedRegular = path.join(base, "regular.sock");
  fs.writeFileSync(occupiedRegular, "not a socket", { mode: 0o600 });
  await assert.rejects(
    createInstrumentBrokerIpcServer(config(base, occupiedRegular)),
    (error) => error.code === "ipc_socket_path_insecure",
  );

  const nonDirectoryRoot = path.join(path.dirname(base), `${path.basename(base)}-regular-root`);
  fs.writeFileSync(nonDirectoryRoot, "not a directory", { mode: 0o700 });
  t.after(() => fs.rmSync(nonDirectoryRoot, { force: true }));
  await assert.rejects(
    createInstrumentBrokerIpcServer(config(
      nonDirectoryRoot,
      path.join(nonDirectoryRoot, "type.sock"),
    )),
    (error) => error.code === "ipc_socket_path_insecure",
  );

  await assert.rejects(
    createInstrumentBrokerIpcServer(config(base, path.join(base, "..", "escape.sock"))),
    (error) => error.code === "ipc_socket_path_insecure",
  );
});
