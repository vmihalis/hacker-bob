"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const { hashCanonicalJson } = require("../../../mcp/lib/verification-contracts.js");
const {
  publicKeyDigest: requestPublicKeyDigest,
  signIpcDispatchRequest,
} = require("../lib/ipc-contract.js");
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
  publicKeyDigest,
  signIpcChannelProof,
  _internals: { assertSelectedCdhash, hashClosed },
} = require("../lib/ipc-channel-binding-contract.js");
const {
  createIpcChannelAuthorityPort,
  createIpcChannelRequestAndProof,
  createIpcChannelReservationPort,
  createIpcNativeAcceptedChannelPort,
  createIpcTestOnlyDeterministicMockCooperativeDispatchPort,
  executeIpcChannelBindingServerConnection,
  validateIpcChannelResponse,
  _internals: { reserveDurably },
} = require("../lib/ipc-channel-binding.js");

const FIXED_NOW = "2026-07-19T02:00:00.000Z";

function digest(label) {
  return crypto.createHash("sha256").update(label).digest("hex");
}

function nonce() {
  return crypto.randomBytes(18).toString("base64url");
}

function frameValue(frame) {
  assert.equal(Buffer.isBuffer(frame), true);
  assert.equal(frame.readUInt32BE(0), frame.length - 4);
  return decodeIpcChannelBody(frame.subarray(4));
}

function assertSafeRejection(error) {
  assert.equal(error?.code, "ipc_channel_binding_rejected");
  assert.equal(error?.message, "IPC native channel binding was rejected");
  assert.equal(Object.hasOwn(error, "cause"), false);
  return true;
}

function descriptorRecord(evidence, suffix = "stable") {
  return Object.freeze({
    version: 1,
    connection_identity_digest: evidence.connection_identity_digest,
    descriptor_registration_token_digest:
      evidence.descriptor_registration_token_digest,
    peer_audit_token_digest: evidence.peer_audit_token_digest,
    peer_process_start_token_digest: evidence.peer_process_start_token_digest,
    peer_mapped_code_identity_digest: evidence.peer_mapped_code_identity_digest,
    descriptor_readback_digest: digest(`descriptor-readback:${suffix}`),
    native_loaded_image_identity_digest:
      evidence.native_loaded_image_identity_digest,
    descriptor_provenance_complete: true,
    production_ready: false,
  });
}

function channelEvidence(label = "") {
  const suffix = label === "" ? "" : `:${label}`;
  return Object.freeze({
    version: 1,
    connection_identity_digest: digest(`connection${suffix}`),
    descriptor_registration_nonce: nonce(),
    descriptor_registration_token_digest: digest(`registration-token${suffix}`),
    descriptor_binding_scheme_digest: digest("descriptor-binding-scheme"),
    socket_root_identity_digest: digest("socket-root"),
    socket_identity_digest: digest(`socket-inode${suffix}`),
    listener_identity_digest: digest(`listener${suffix}`),
    acceptor_instance_digest: digest(`acceptor-instance${suffix}`),
    connection_generation: "1",
    peer_euid: 501,
    peer_egid: 20,
    peer_ruid: 501,
    peer_rgid: 20,
    peer_pid: 12345,
    peer_pidversion: 7,
    peer_audit_token_digest: digest("peer-audit-token"),
    peer_process_start_token_digest: digest("peer-process-start"),
    peer_executable_path_digest: digest("peer-executable-path"),
    peer_selected_cdhash: digest("peer-cdhash").slice(0, 40),
    peer_selected_cdhash_algorithm: 2,
    peer_code_directory_hashes_digest: digest("peer-cdhash-set"),
    peer_code_signing_identity_digest: digest("peer-signing-identity"),
    peer_code_dynamic_status_digest: digest("peer-dynamic-status"),
    peer_mapped_code_identity_digest: digest("peer-mapped-code"),
    native_acceptor_implementation_digest: digest("native-acceptor-image"),
    native_loaded_image_identity_digest: digest("native-loaded-image"),
    accepted_and_registered_before_javascript: true,
    javascript_descriptor_handoff_used: false,
    descriptor_provenance_complete: true,
    production_ready: false,
  });
}

function reservationRecord(query) {
  const basis = Object.freeze({
    version: query.version,
    reservation_id: query.reservation_id,
    reservation_kind: query.reservation_kind,
    reservation_identity_digest: query.reservation_identity_digest,
    claim_digest: query.claim_digest,
    reservation_attempt_nonce: query.reservation_attempt_nonce,
    disposition: "created",
    one_use: true,
  });
  return Object.freeze({
    ...basis,
    reservation_receipt_digest: hashClosed(
      "hacker-bob/instrument-broker-ipc-channel-reservation/v2",
      "reservation_receipt",
      basis,
    ),
  });
}

function makeReservationPort(options = {}) {
  const records = new Map();
  const stats = { reserves: 0, reads: 0 };
  const port = createIpcChannelReservationPort({
    reservation_port_id: options.id || "ipc_channel_reservation_fixture",
    reserve_reservation: async (input) => {
      stats.reserves += 1;
      const { claim: _claim, ...query } = input;
      if (options.mode === "no_commit") throw new Error("store unavailable");
      if (!records.has(query.reservation_id)) {
        records.set(query.reservation_id, reservationRecord(query));
      }
      options.on_reserve?.(query, stats.reserves, records);
      if (options.mode === "lost") throw new Error("committed response lost");
      if (options.mode === "malformed") return Object.freeze({ malformed: true });
      return records.get(query.reservation_id);
    },
    read_reservation: async (query) => {
      stats.reads += 1;
      options.on_read?.(query, stats.reads, records);
      return records.get(query.reservation_id);
    },
  });
  return { port, records, stats };
}

function makeAuthorityPort(options = {}) {
  const stats = { reads: 0 };
  const authorityId = options.id || "ipc_channel_authority_fixture";
  const stable = Object.freeze({
    version: 1,
    authority_id: authorityId,
    authority_epoch: 11,
    authority_digest: digest("startup-authority"),
    server_bundle_identity_digest: digest("server-bundle"),
    server_launch_attestation_digest: digest("server-launch"),
    server_process_start_token_digest: digest("server-process-start"),
    trusted_monotonic_coordinate: "9001",
    trusted: true,
    revoked: false,
  });
  const port = createIpcChannelAuthorityPort({
    authority_id: authorityId,
    read_current_authority: async () => {
      stats.reads += 1;
      return options.transform?.(stable, stats.reads) || stable;
    },
  });
  return { port, stable, stats };
}

function signedRequest(requestKeys, values = {}) {
  const payload = values.operation_payload || Object.freeze({ mode: "fixture" });
  return signIpcDispatchRequest({
    version: 1,
    request_id: values.request_id || "ipc-request:channel-fixture-1",
    ipc_peer_principal_id: values.ipc_peer_principal_id
      || "principal:ipc-channel-client",
    execution_principal_id: values.execution_principal_id
      || "principal:ipc-channel-worker",
    provider_id: values.provider_id || IPC_CHANNEL_TEST_ONLY_PROVIDER_ID,
    provider_descriptor_digest: values.provider_descriptor_digest
      || digest("provider-descriptor"),
    operation_id: values.operation_id || "fixture_operation",
    operation_payload_digest: hashCanonicalJson(payload),
    operation_payload: payload,
    nonce: values.nonce || nonce(),
    sequence: values.sequence || 1,
    issued_at: values.issued_at || FIXED_NOW,
    deadline: values.deadline || "2026-07-19T02:00:04.000Z",
  }, {
    key_id: values.key_id || "ipc-key:channel-request-v1",
    public_key_digest: requestPublicKeyDigest(requestKeys.publicKey),
    private_key: requestKeys.privateKey,
  });
}

function testOnlyDispatchPort(
  fixtureScript = IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.complete,
  options = {},
) {
  return createIpcTestOnlyDeterministicMockCooperativeDispatchPort({
    provider_descriptor_digest: options.provider_descriptor_digest
      || digest("provider-descriptor"),
    provider_implementation_digest: options.provider_implementation_digest
      || digest("deterministic-mock-implementation"),
    fixture_script: fixtureScript,
  });
}

function makeFixture(options = {}) {
  const requestKeys = options.request_keys || crypto.generateKeyPairSync("ed25519");
  const responseKeys = options.response_keys || crypto.generateKeyPairSync("ed25519");
  const request = options.request || signedRequest(requestKeys, options.request_values);
  const evidence = options.evidence || channelEvidence(options.evidence_label || "");
  const initialDescriptor = descriptorRecord(evidence);
  const authority = options.authority_fixture || makeAuthorityPort(options.authority || {});
  const reservation = options.reservation_fixture
    || makeReservationPort(options.reservation || {});
  const providerDescriptorDigest = options.provider_descriptor_digest
    || digest("provider-descriptor");
  const providerImplementationDigest = options.provider_implementation_digest
    || digest("deterministic-mock-implementation");
  const stats = {
    challenge_writes: 0,
    request_reads: 0,
    response_writes: 0,
    descriptor_reads: 0,
    closes: 0,
    dispatches: 0,
  };
  const captured = { challenge: null, pair: null, response: null };
  const trustedServer = Object.freeze({
    server_principal_id: "principal:ipc-channel-server",
    response_key_id: "ipc-key:channel-response-v1",
    response_public_key_digest: publicKeyDigest(responseKeys.publicKey),
    public_key: responseKeys.publicKey,
  });
  const channelInput = {
    channel_id: options.channel_id || "ipc_channel_fixture",
    evidence,
    write_challenge: async (frame, timeout) => {
      stats.challenge_writes += 1;
      assert.equal(timeout, 1_000);
      captured.challenge = frameValue(frame);
      let pair = createIpcChannelRequestAndProof({
        challenge: captured.challenge,
        trusted_server: trustedServer,
        request_envelope: request,
        request_signer: {
          request_key_id: "ipc-key:channel-request-v1",
          request_public_key_digest: publicKeyDigest(requestKeys.publicKey),
          private_key: requestKeys.privateKey,
        },
        client_attestation: {
          client_bundle_identity_digest: digest("client-bundle"),
          client_launch_attestation_digest: digest("client-launch"),
        },
        proof_nonce: nonce(),
        proof_deadline: options.proof_deadline || "2026-07-19T02:00:04.000Z",
      });
      pair = options.pair_transform?.(pair, captured.challenge, {
        requestKeys, responseKeys, trustedServer,
      }) || pair;
      captured.pair = pair;
    },
    read_request_and_proof: async (timeout) => {
      stats.request_reads += 1;
      assert.equal(timeout, 1_000);
      return encodeIpcChannelFrame(captured.pair).subarray(4);
    },
    read_descriptor_identity: () => {
      stats.descriptor_reads += 1;
      return options.descriptor_transform?.(
        initialDescriptor,
        stats.descriptor_reads,
      ) || initialDescriptor;
    },
    write_response: async (frame, timeout) => {
      stats.dispatches += 1;
      stats.response_writes += 1;
      assert.equal(timeout, 1_000);
      captured.response = frameValue(frame);
    },
    close: () => { stats.closes += 1; },
  };
  const channel = createIpcNativeAcceptedChannelPort(channelInput);
  const dispatchPort = options.dispatch_port
    || testOnlyDispatchPort(
      options.fixture_script,
      {
        provider_descriptor_digest: providerDescriptorDigest,
        provider_implementation_digest: providerImplementationDigest,
      },
    );
  const serverInput = {
    channel_port: channel,
    reservation_port: reservation.port,
    authority_port: authority.port,
    server_identity: {
      server_principal_id: trustedServer.server_principal_id,
      response_key_id: trustedServer.response_key_id,
      response_public_key_digest: trustedServer.response_public_key_digest,
      private_key: responseKeys.privateKey,
    },
    expected_request_identity: {
      request_key_id: "ipc-key:channel-request-v1",
      request_public_key_digest: publicKeyDigest(requestKeys.publicKey),
      request_public_key: requestKeys.publicKey,
      ipc_peer_principal_id: "principal:ipc-channel-client",
      execution_principal_id: "principal:ipc-channel-worker",
      provider_id: IPC_CHANNEL_TEST_ONLY_PROVIDER_ID,
      provider_descriptor_digest: providerDescriptorDigest,
      provider_implementation_digest: providerImplementationDigest,
    },
    client_attestation: {
      client_bundle_identity_digest: digest("client-bundle"),
      client_launch_attestation_digest: digest("client-launch"),
    },
    non_hardware_test_only_dispatch_port: dispatchPort,
    now: options.now || (() => new Date(FIXED_NOW)),
    challenge_lifetime_ms: options.challenge_lifetime_ms || 5_000,
    io_timeout_ms: 1_000,
  };
  return {
    authority,
    captured,
    channel,
    channelInput,
    dispatchPort,
    evidence,
    initialDescriptor,
    request,
    requestKeys,
    reservation,
    responseKeys,
    serverInput,
    stats,
    trustedServer,
  };
}

function assertNoRawCustody(value) {
  const forbidden = new Set([
    "fd", "descriptor", "socket_path", "executable_path", "audit_token",
    "acceptor_token", "connection_token", "registration_token", "private_key",
  ]);
  const pending = [value];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current == null || typeof current !== "object") continue;
    for (const key of Object.keys(current)) {
      assert.equal(forbidden.has(key), false, `forbidden raw field ${key}`);
      pending.push(current[key]);
    }
  }
}

test("imports and closed deterministic port construction are inert", async () => {
  let redirectedCalls = 0;
  const fixture = makeFixture();
  assert.equal(fixture.stats.challenge_writes, 0);
  assert.equal(fixture.stats.descriptor_reads, 0);
  assert.equal(fixture.reservation.stats.reserves, 0);
  assert.equal(fixture.authority.stats.reads, 0);
  assert.equal(fixture.dispatchPort.kind, IPC_CHANNEL_TEST_ONLY_DISPATCH_BOUNDARY_KIND);
  assert.equal(
    fixture.dispatchPort.fixture_source,
    IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SOURCE,
  );
  assert.equal(
    fixture.dispatchPort.deadline_enforcement,
    IPC_CHANNEL_TEST_ONLY_DISPATCH_DEADLINE_ENFORCEMENT,
  );
  assert.equal(fixture.dispatchPort.provider_id, IPC_CHANNEL_TEST_ONLY_PROVIDER_ID);
  assert.equal(
    fixture.dispatchPort.fixture_script,
    IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.complete,
  );
  assert.equal(fixture.dispatchPort.separate_identity, false);
  assert.equal(fixture.dispatchPort.independently_preemptible, false);
  assert.equal(fixture.dispatchPort.worker_trusted_deadline_recheck, false);
  assert.equal(fixture.dispatchPort.hardware_authority, false);
  assert.equal(fixture.dispatchPort.production_ready, false);
  fixture.channelInput.write_challenge = () => { redirectedCalls += 1; };
  await executeIpcChannelBindingServerConnection(fixture.serverInput);
  assert.equal(redirectedCalls, 0);
  assert.equal(fixture.stats.challenge_writes, 1);
  assert.equal(fixture.stats.dispatches, 1);
  assert.equal(fixture.stats.closes, 1);

  assert.throws(
    () => createIpcTestOnlyDeterministicMockCooperativeDispatchPort({
      provider_descriptor_digest: digest("provider-descriptor"),
      provider_implementation_digest: digest("deterministic-mock-implementation"),
      dispatch_fixture: () => {},
    }),
    assertSafeRejection,
  );
});

test("CDHash algorithms have closed exact digest lengths", () => {
  const sha1 = "a".repeat(40);
  const sha256Cdhash = "b".repeat(40);
  const fullSha256 = "b".repeat(64);
  assert.equal(assertSelectedCdhash(sha1, 1), sha1);
  assert.equal(assertSelectedCdhash(sha256Cdhash, 2), sha256Cdhash);
  assert.equal(assertSelectedCdhash(sha1, 3), sha1);
  assert.throws(() => assertSelectedCdhash(fullSha256, 1));
  assert.throws(() => assertSelectedCdhash(fullSha256, 2));
  assert.throws(() => assertSelectedCdhash(fullSha256, 3));
  assert.throws(() => assertSelectedCdhash(sha256Cdhash, 4));

  const callbacks = {
    channel_id: "cdhash_length_fixture",
    write_challenge: async () => {},
    read_request_and_proof: async () => Buffer.from("{}"),
    read_descriptor_identity: () => ({}),
    write_response: async () => {},
    close: () => {},
  };
  assert.throws(
    () => createIpcNativeAcceptedChannelPort({
      ...callbacks,
      evidence: {
        ...channelEvidence(),
        peer_selected_cdhash: fullSha256,
        peer_selected_cdhash_algorithm: 1,
      },
    }),
  );
  assert.throws(
    () => createIpcNativeAcceptedChannelPort({
      ...callbacks,
      evidence: {
        ...channelEvidence(),
        peer_selected_cdhash: fullSha256,
        peer_selected_cdhash_algorithm: 2,
      },
    }),
  );
});

test("two-flight admission signs exact descriptor, request, proof, and response bindings", async () => {
  const fixture = makeFixture();
  const result = await executeIpcChannelBindingServerConnection(fixture.serverInput);
  assert.equal(result.status, "completed");
  assert.equal(result.production_ready, false);
  assert.equal(result.production_attested, false);
  assert.equal(result.descriptor_provenance_complete, true);
  assert.equal(result.response_binding_complete, true);
  assert.equal(result.dispatch_fixture_source, IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SOURCE);
  assert.equal(
    result.dispatch_fixture_script,
    IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.complete,
  );
  assert.equal(result.dispatch_separate_identity, false);
  assert.equal(result.dispatch_independently_preemptible, false);
  assert.equal(result.dispatch_worker_trusted_deadline_recheck, false);
  assert.equal(result.dispatch_hardware_authority, false);
  assert.equal(result.dispatch_production_ready, false);
  assert.equal(fixture.stats.dispatches, 1);
  assert.equal(fixture.stats.closes, 1);
  assert.equal(fixture.stats.descriptor_reads, 4);
  assert.equal(fixture.authority.stats.reads, 4);
  assert.equal(fixture.reservation.stats.reserves, 3);
  assert.equal(fixture.reservation.stats.reads, 3);
  assert.equal(
    fixture.captured.challenge.payload.descriptor_initial_readback_digest,
    fixture.initialDescriptor.descriptor_readback_digest,
  );
  assert.equal(
    fixture.captured.challenge.payload.peer_code_directory_hashes_digest,
    fixture.evidence.peer_code_directory_hashes_digest,
  );
  assert.equal(
    fixture.captured.challenge.payload.dispatch_boundary_kind,
    IPC_CHANNEL_TEST_ONLY_DISPATCH_BOUNDARY_KIND,
  );
  assert.equal(fixture.captured.challenge.payload.dispatch_hardware_authority, false);
  assert.equal(fixture.captured.challenge.payload.dispatch_production_ready, false);
  const substitutedFixtureScript = structuredClone(fixture.captured.challenge);
  substitutedFixtureScript.payload.dispatch_fixture_script = "open_hardware";
  assert.throws(
    () => normalizeSignedIpcChannelChallenge(substitutedFixtureScript),
    /IPC channel binding message was rejected/u,
  );
  const substitutedAlgorithm = structuredClone(fixture.captured.challenge);
  substitutedAlgorithm.payload.peer_selected_cdhash_algorithm = 1;
  assert.throws(
    () => normalizeSignedIpcChannelChallenge(substitutedAlgorithm),
    /IPC channel binding message was rejected/u,
  );
  const substitutedHashSet = structuredClone(fixture.captured.challenge);
  substitutedHashSet.payload.peer_code_directory_hashes_digest = digest(
    "substituted-cdhash-set",
  );
  assert.throws(
    () => normalizeSignedIpcChannelChallenge(substitutedHashSet),
    /IPC channel binding message was rejected/u,
  );
  const projection = validateIpcChannelResponse({
    response: fixture.captured.response,
    challenge: fixture.captured.challenge,
    proof: fixture.captured.pair.proof,
    request: fixture.captured.pair.request,
    trusted_server: fixture.trustedServer,
  });
  assert.equal(projection.response_digest, result.response_digest);
  assert.equal(projection.challenge_digest, result.challenge_digest);
  assert.equal(projection.proof_digest, result.proof_digest);
  assert.equal(projection.request_digest, result.request_digest);
  assert.equal(projection.dispatch_fixture_source, IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SOURCE);
  assert.equal(
    projection.dispatch_fixture_script,
    IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.complete,
  );
  assert.equal(projection.dispatch_hardware_authority, false);
  assert.equal(projection.dispatch_production_ready, false);
  assert.equal(
    projection.request_reservation_receipt_digest,
    result.request_reservation_receipt_digest,
  );
  assertNoRawCustody(fixture.captured.challenge);
  assertNoRawCustody(projection);
});

test("unapproved dispatch error strings cannot enter a signed response", async () => {
  const fixture = makeFixture();
  const channel = createIpcNativeAcceptedChannelPort({
    ...fixture.channelInput,
    channel_id: "ipc_channel_safe_error_fixture",
  });
  const result = await executeIpcChannelBindingServerConnection({
    ...fixture.serverInput,
    channel_port: channel,
    non_hardware_test_only_dispatch_port: testOnlyDispatchPort(
      IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.invalid_error_code,
    ),
  });
  assert.equal(result.status, "ambiguous");
  assert.equal(result.error_code, "dispatch_unavailable");
  assert.equal(fixture.captured.response.payload.error_code, "dispatch_unavailable");
  assert.equal(JSON.stringify(fixture.captured.response).includes("secret_marker"), false);
});

test("lost and malformed reservation replies admit only through exact durable readback", async (t) => {
  for (const mode of ["lost", "malformed"]) {
    await t.test(mode, async () => {
      const fixture = makeFixture({ reservation: { mode } });
      const result = await executeIpcChannelBindingServerConnection(fixture.serverInput);
      assert.equal(result.status, "completed");
      assert.equal(fixture.reservation.stats.reserves, 3);
      assert.equal(fixture.reservation.stats.reads, 3);
      assert.equal(fixture.stats.dispatches, 1);
    });
  }
});

test("reservation attempt nonce makes an existing durable claim a replay", async () => {
  const reservation = makeReservationPort();
  const claim = Object.freeze({ version: 1, tuple: digest("one-use-tuple") });
  const first = await reserveDurably(reservation.port, "proof", claim);
  assert.equal(first.disposition, "created");
  await assert.rejects(
    reserveDurably(reservation.port, "proof", claim),
    assertSafeRejection,
  );
  assert.equal(reservation.stats.reserves, 2);
  assert.equal(reservation.stats.reads, 2);
});

test("reservation schema v2 rejects a durable v1 record", async () => {
  const legacy = createIpcChannelReservationPort({
    reservation_port_id: "ipc_legacy_v1_reservation_fixture",
    reserve_reservation: async () => {},
    read_reservation: async (query) => {
      const legacyBasis = Object.freeze({
        version: 1,
        reservation_id: query.reservation_id,
        reservation_kind: query.reservation_kind,
        claim_digest: query.claim_digest,
        reservation_attempt_nonce: query.reservation_attempt_nonce,
        disposition: "created",
        one_use: true,
      });
      return Object.freeze({
        ...legacyBasis,
        reservation_receipt_digest: hashClosed(
          "hacker-bob/instrument-broker-ipc-channel-reservation/v1",
          "reservation_receipt",
          legacyBasis,
        ),
      });
    },
  });
  assert.equal(legacy.version, 2);
  await assert.rejects(
    reserveDurably(legacy, "proof", Object.freeze({ version: 1 })),
    assertSafeRejection,
  );
});

test("one channel port can execute only once even with a fresh reservation claim", async () => {
  const fixture = makeFixture();
  await executeIpcChannelBindingServerConnection(fixture.serverInput);
  await assert.rejects(
    executeIpcChannelBindingServerConnection(fixture.serverInput),
    assertSafeRejection,
  );
  assert.equal(fixture.stats.challenge_writes, 1);
  assert.equal(fixture.stats.dispatches, 1);
  assert.equal(fixture.stats.closes, 1);
});

test("a signed request is globally one-use across distinct private channels", async () => {
  const requestKeys = crypto.generateKeyPairSync("ed25519");
  const responseKeys = crypto.generateKeyPairSync("ed25519");
  const request = signedRequest(requestKeys);
  const reservation = makeReservationPort({ id: "ipc_global_request_store" });
  const authority = makeAuthorityPort({ id: "ipc_global_request_authority" });
  const first = makeFixture({
    request_keys: requestKeys,
    response_keys: responseKeys,
    request,
    reservation_fixture: reservation,
    authority_fixture: authority,
    channel_id: "ipc_global_request_channel_one",
    evidence_label: "global-one",
  });
  const second = makeFixture({
    request_keys: requestKeys,
    response_keys: responseKeys,
    request,
    reservation_fixture: reservation,
    authority_fixture: authority,
    channel_id: "ipc_global_request_channel_two",
    evidence_label: "global-two",
  });
  assert.notEqual(first.channel, second.channel);
  await executeIpcChannelBindingServerConnection(first.serverInput);
  await assert.rejects(
    executeIpcChannelBindingServerConnection(second.serverInput),
    assertSafeRejection,
  );
  assert.equal(first.stats.dispatches, 1);
  assert.equal(second.stats.dispatches, 0);
  assert.equal(first.stats.closes, 1);
  assert.equal(second.stats.closes, 1);
  assert.equal(reservation.stats.reserves, 5);
  assert.equal(reservation.stats.reads, 5);
});

test("a forked signed request cannot reuse one closed replay identity", async () => {
  const requestKeys = crypto.generateKeyPairSync("ed25519");
  const responseKeys = crypto.generateKeyPairSync("ed25519");
  const replayNonce = nonce();
  const firstRequest = signedRequest(requestKeys, {
    request_id: "ipc-request:closed-replay-first",
    nonce: replayNonce,
    sequence: 19,
    operation_id: "first_operation",
    operation_payload: Object.freeze({ fork: "first" }),
  });
  const secondRequest = signedRequest(requestKeys, {
    request_id: "ipc-request:closed-replay-second",
    nonce: replayNonce,
    sequence: 19,
    operation_id: "second_operation",
    operation_payload: Object.freeze({ fork: "second" }),
  });
  assert.notEqual(firstRequest.request_digest, secondRequest.request_digest);
  const requestQueries = [];
  const reservation = makeReservationPort({
    id: "ipc_closed_replay_store",
    on_reserve: (query) => {
      if (query.reservation_kind === "request") requestQueries.push(query);
    },
  });
  const authority = makeAuthorityPort({ id: "ipc_closed_replay_authority" });
  const first = makeFixture({
    request_keys: requestKeys,
    response_keys: responseKeys,
    request: firstRequest,
    reservation_fixture: reservation,
    authority_fixture: authority,
    channel_id: "ipc_closed_replay_channel_one",
    evidence_label: "closed-replay-one",
  });
  const second = makeFixture({
    request_keys: requestKeys,
    response_keys: responseKeys,
    request: secondRequest,
    reservation_fixture: reservation,
    authority_fixture: authority,
    channel_id: "ipc_closed_replay_channel_two",
    evidence_label: "closed-replay-two",
  });
  await executeIpcChannelBindingServerConnection(first.serverInput);
  await assert.rejects(
    executeIpcChannelBindingServerConnection(second.serverInput),
    assertSafeRejection,
  );
  assert.equal(first.stats.dispatches, 1);
  assert.equal(second.stats.dispatches, 0);
  assert.equal(first.stats.closes, 1);
  assert.equal(second.stats.closes, 1);
  assert.equal(requestQueries.length, 2);
  assert.equal(requestQueries[0].reservation_id, requestQueries[1].reservation_id);
  assert.equal(
    requestQueries[0].reservation_identity_digest,
    requestQueries[1].reservation_identity_digest,
  );
  assert.notEqual(requestQueries[0].claim_digest, requestQueries[1].claim_digest);
  assert.equal(reservation.stats.reserves, 5);
  assert.equal(reservation.stats.reads, 5);
});

test("a genuine channel is owned and closed before server config normalization", async () => {
  const fixture = makeFixture();
  const malformed = {
    ...fixture.serverInput,
    server_identity: {
      ...fixture.serverInput.server_identity,
      response_public_key_digest: digest("wrong-response-key"),
    },
  };
  await assert.rejects(
    executeIpcChannelBindingServerConnection(malformed),
    assertSafeRejection,
  );
  assert.equal(fixture.stats.challenge_writes, 0);
  assert.equal(fixture.stats.dispatches, 0);
  assert.equal(fixture.stats.closes, 1);
  await assert.rejects(
    executeIpcChannelBindingServerConnection(fixture.serverInput),
    assertSafeRejection,
  );
  assert.equal(fixture.stats.closes, 1);
});

test("raw callbacks and forged production dispatch ports fail before durable admission", async (t) => {
  await t.test("legacy raw callback", async () => {
    const fixture = makeFixture();
    let effectCount = 0;
    const {
      non_hardware_test_only_dispatch_port: _dispatchPort,
      ...withoutDispatchPort
    } = fixture.serverInput;
    await assert.rejects(
      executeIpcChannelBindingServerConnection({
        ...withoutDispatchPort,
        dispatch_handler: () => {
          effectCount += 1;
        },
      }),
      assertSafeRejection,
    );
    assert.equal(effectCount, 0);
    assert.equal(fixture.authority.stats.reads, 0);
    assert.equal(fixture.reservation.stats.reserves, 0);
    assert.equal(fixture.stats.descriptor_reads, 0);
    assert.equal(fixture.stats.challenge_writes, 0);
    assert.equal(fixture.stats.closes, 1);
  });

  await t.test("forged production port cannot reach its 300ms effect", async () => {
    const fixture = makeFixture();
    let effectCount = 0;
    const forged = Object.freeze({
      version: 1,
      kind: "separate_identity_native_custodian_v1",
      provider_id: "chameleon_ultra",
      provider_descriptor_digest: digest("forged-provider-descriptor"),
      provider_implementation_digest: digest("forged-provider-implementation"),
      fixture_source: false,
      deadline_enforcement: "independent_worker_trusted_deadline_v1",
      same_event_loop_cooperative: false,
      separate_identity: true,
      independently_preemptible: true,
      worker_trusted_deadline_recheck: true,
      hardware_authority: true,
      production_ready: true,
      dispatch_fixture: () => {
        const stop = Date.now() + 300;
        while (Date.now() < stop) {}
        effectCount += 1;
      },
    });
    await assert.rejects(
      executeIpcChannelBindingServerConnection({
        ...fixture.serverInput,
        non_hardware_test_only_dispatch_port: forged,
      }),
      assertSafeRejection,
    );
    assert.equal(effectCount, 0);
    assert.equal(fixture.authority.stats.reads, 0);
    assert.equal(fixture.reservation.stats.reserves, 0);
    assert.equal(fixture.stats.descriptor_reads, 0);
    assert.equal(fixture.stats.challenge_writes, 0);
    assert.equal(fixture.stats.closes, 1);
  });

  await t.test("genuine test port binding drift", async () => {
    const driftedPort = testOnlyDispatchPort(
      IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.complete,
      {
      provider_descriptor_digest: digest("other-deterministic-descriptor"),
      },
    );
    const fixture = makeFixture({ dispatch_port: driftedPort });
    await assert.rejects(
      executeIpcChannelBindingServerConnection(fixture.serverInput),
      assertSafeRejection,
    );
    assert.equal(fixture.authority.stats.reads, 0);
    assert.equal(fixture.reservation.stats.reserves, 0);
    assert.equal(fixture.stats.challenge_writes, 0);
    assert.equal(fixture.stats.closes, 1);
  });
});

test("authority and descriptor drift after either reservation reject before dispatch", async (t) => {
  await t.test("authority after challenge reservation", async () => {
    const fixture = makeFixture({
      authority: {
        transform: (record, read) => read === 2
          ? Object.freeze({ ...record, authority_epoch: record.authority_epoch + 1 })
          : record,
      },
    });
    await assert.rejects(
      executeIpcChannelBindingServerConnection(fixture.serverInput),
      assertSafeRejection,
    );
    assert.equal(fixture.stats.challenge_writes, 0);
    assert.equal(fixture.stats.dispatches, 0);
    assert.equal(fixture.stats.closes, 1);
  });

  await t.test("descriptor after proof reservation", async () => {
    const fixture = makeFixture({
      descriptor_transform: (record, read) => read === 4
        ? descriptorRecord(fixture.evidence, "substituted")
        : record,
    });
    await assert.rejects(
      executeIpcChannelBindingServerConnection(fixture.serverInput),
      assertSafeRejection,
    );
    assert.equal(fixture.stats.request_reads, 1);
    assert.equal(fixture.stats.dispatches, 0);
    assert.equal(fixture.stats.closes, 1);
  });
});

test("post-reservation authority and descriptor reads occur after store failure", async () => {
  const fixture = makeFixture({ reservation: { mode: "no_commit" } });
  await assert.rejects(
    executeIpcChannelBindingServerConnection(fixture.serverInput),
    assertSafeRejection,
  );
  assert.equal(fixture.authority.stats.reads, 2);
  assert.equal(fixture.stats.descriptor_reads, 2);
  assert.equal(fixture.stats.dispatches, 0);
  assert.equal(fixture.stats.closes, 1);
});

test("deadline expiry during proof reservation readback rejects before dispatch", async () => {
  let nowMilliseconds = Date.parse(FIXED_NOW);
  const deadlineMilliseconds = Date.parse("2026-07-19T02:00:04.000Z");
  const fixture = makeFixture({
    now: () => new Date(nowMilliseconds),
    reservation: {
      on_read: (query) => {
        if (query.reservation_kind === "proof") {
          nowMilliseconds = deadlineMilliseconds;
        }
      },
    },
  });
  await assert.rejects(
    executeIpcChannelBindingServerConnection(fixture.serverInput),
    assertSafeRejection,
  );
  assert.equal(fixture.reservation.stats.reserves, 3);
  assert.equal(fixture.stats.dispatches, 0);
  assert.equal(fixture.stats.response_writes, 0);
  assert.equal(fixture.stats.closes, 1);
});

test("a closed never-settling fixture is cancelled at the signed deadline", async () => {
  const started = Date.now();
  const issuedAt = new Date(started).toISOString();
  const deadline = new Date(started + 300).toISOString();
  const fixture = makeFixture({
    request_values: { issued_at: issuedAt, deadline },
    proof_deadline: deadline,
    now: () => new Date(),
    challenge_lifetime_ms: 300,
    fixture_script: IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.never_settle,
  });
  const result = await executeIpcChannelBindingServerConnection(fixture.serverInput);
  const elapsed = Date.now() - started;
  assert.equal(result.status, "ambiguous");
  assert.equal(result.error_code, "dispatch_timeout");
  assert.equal(result.non_retryable, true);
  assert.equal(fixture.captured.response.payload.status, "ambiguous");
  assert.equal(fixture.captured.response.payload.error_code, "dispatch_timeout");
  assert.equal(
    fixture.captured.response.payload.dispatch_fixture_script,
    IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.never_settle,
  );
  assert.equal(fixture.stats.dispatches, 1);
  assert.equal(fixture.stats.closes, 1);
  assert.ok(elapsed >= 150, `dispatch returned too early after ${elapsed}ms`);
  assert.ok(elapsed < 2_000, `dispatch remained open for ${elapsed}ms`);
});

test("a closed 300ms blocking fixture is post-fenced without hardware claims", async () => {
  const started = Date.now();
  const issuedAt = new Date(started).toISOString();
  const deadline = new Date(started + 200).toISOString();
  const fixture = makeFixture({
    request_values: { issued_at: issuedAt, deadline },
    proof_deadline: deadline,
    now: () => new Date(),
    challenge_lifetime_ms: 200,
    fixture_script:
      IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS
        .busy_loop_300ms_then_complete,
  });
  const result = await executeIpcChannelBindingServerConnection(fixture.serverInput);
  const elapsed = Date.now() - started;
  assert.equal(result.status, "ambiguous");
  assert.equal(result.error_code, "dispatch_timeout");
  assert.equal(result.non_retryable, true);
  assert.equal(result.dispatch_hardware_authority, false);
  assert.equal(result.dispatch_production_ready, false);
  assert.equal(
    result.dispatch_fixture_script,
    IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS
      .busy_loop_300ms_then_complete,
  );
  assert.equal(fixture.captured.response.payload.status, "ambiguous");
  assert.equal(fixture.captured.response.payload.dispatch_hardware_authority, false);
  assert.equal(fixture.captured.response.payload.dispatch_production_ready, false);
  assert.equal(fixture.stats.dispatches, 1);
  assert.equal(fixture.stats.closes, 1);
  assert.ok(elapsed >= 300, `closed blocking fixture ran for only ${elapsed}ms`);
  assert.ok(elapsed < 2_000, `closed blocking fixture remained open for ${elapsed}ms`);
});

test("an ambiguous admitted request is globally non-replayable", async () => {
  const requestKeys = crypto.generateKeyPairSync("ed25519");
  const responseKeys = crypto.generateKeyPairSync("ed25519");
  const request = signedRequest(requestKeys);
  const reservation = makeReservationPort({ id: "ipc_ambiguous_replay_store" });
  const authority = makeAuthorityPort({ id: "ipc_ambiguous_replay_authority" });
  const first = makeFixture({
    request_keys: requestKeys,
    response_keys: responseKeys,
    request,
    reservation_fixture: reservation,
    authority_fixture: authority,
    channel_id: "ipc_ambiguous_replay_channel_one",
    evidence_label: "ambiguous-replay-one",
    fixture_script: IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.unavailable,
  });
  const second = makeFixture({
    request_keys: requestKeys,
    response_keys: responseKeys,
    request,
    reservation_fixture: reservation,
    authority_fixture: authority,
    channel_id: "ipc_ambiguous_replay_channel_two",
    evidence_label: "ambiguous-replay-two",
  });
  const firstResult = await executeIpcChannelBindingServerConnection(first.serverInput);
  assert.equal(firstResult.status, "ambiguous");
  assert.equal(firstResult.error_code, "dispatch_unavailable");
  assert.equal(firstResult.non_retryable, true);
  await assert.rejects(
    executeIpcChannelBindingServerConnection(second.serverInput),
    assertSafeRejection,
  );
  assert.equal(first.stats.dispatches, 1);
  assert.equal(second.stats.dispatches, 0);
  assert.equal(first.stats.closes, 1);
  assert.equal(second.stats.closes, 1);
});

test("response loss after durable admission is non-retryable and closes", async () => {
  const failing = makeFixture();
  const originalInput = failing.serverInput;
  const channel = createIpcNativeAcceptedChannelPort({
    ...failing.channelInput,
    write_response: async () => {
      failing.stats.dispatches += 1;
      failing.stats.response_writes += 1;
      throw new Error("response transport lost");
    },
  });
  await assert.rejects(
    executeIpcChannelBindingServerConnection({
      ...originalInput,
      channel_port: channel,
    }),
    (error) => {
      assert.equal(
        error?.code,
        "ipc_channel_binding_admitted_outcome_ambiguous",
      );
      assert.equal(
        error?.message,
        "IPC native channel outcome is ambiguous and must not be retried",
      );
      assert.equal(error?.non_retryable, true);
      assert.equal(Object.hasOwn(error, "cause"), false);
      return true;
    },
  );
  assert.equal(failing.stats.dispatches, 1);
  assert.equal(failing.stats.closes, 1);
});

test("request substitution and challenge-proof transplant reject before dispatch", async (t) => {
  await t.test("request substitution", async () => {
    const fixture = makeFixture({
      pair_transform: (pair, _challenge, context) => ({
        ...pair,
        request: signedRequest(context.requestKeys, {
          request_id: "ipc-request:channel-fixture-2",
          nonce: nonce(),
          sequence: 2,
        }),
      }),
    });
    await assert.rejects(
      executeIpcChannelBindingServerConnection(fixture.serverInput),
      assertSafeRejection,
    );
    assert.equal(fixture.stats.dispatches, 0);
  });

  await t.test("proof transplant", async () => {
    const fixture = makeFixture({
      pair_transform: (pair, _challenge, context) => ({
        ...pair,
        proof: signIpcChannelProof({
          ...pair.proof.payload,
          challenge_digest: digest("different-challenge"),
        }, {
          key_id: "ipc-key:channel-request-v1",
          public_key_digest: publicKeyDigest(context.requestKeys.publicKey),
          private_key: context.requestKeys.privateKey,
        }),
      }),
    });
    await assert.rejects(
      executeIpcChannelBindingServerConnection(fixture.serverInput),
      assertSafeRejection,
    );
    assert.equal(fixture.stats.dispatches, 0);
  });
});

test("request-key substitution rejects independently signed request and proof", async () => {
  const alternate = crypto.generateKeyPairSync("ed25519");
  const fixture = makeFixture({
    pair_transform: (pair, _challenge) => {
      const request = signedRequest(alternate, {
        key_id: "ipc-key:alternate-request-v1",
      });
      const proof = signIpcChannelProof({
        ...pair.proof.payload,
        signed_request_digest: request.request_digest,
        request_nonce: request.payload.nonce,
        request_sequence: request.payload.sequence,
        request_key_id: request.authentication.key_id,
        request_public_key_digest: request.authentication.public_key_digest,
      }, {
        key_id: request.authentication.key_id,
        public_key_digest: request.authentication.public_key_digest,
        private_key: alternate.privateKey,
      });
      return { ...pair, request, proof };
    },
  });
  await assert.rejects(
    executeIpcChannelBindingServerConnection(fixture.serverInput),
    assertSafeRejection,
  );
  assert.equal(fixture.stats.dispatches, 0);
});

test("response validation rejects substituted transcript components", async () => {
  const fixture = makeFixture();
  await executeIpcChannelBindingServerConnection(fixture.serverInput);
  const otherRequest = signedRequest(fixture.requestKeys, {
    request_id: "ipc-request:channel-fixture-other",
    nonce: nonce(),
    sequence: 2,
  });
  await assert.rejects(async () => validateIpcChannelResponse({
    response: fixture.captured.response,
    challenge: fixture.captured.challenge,
    proof: fixture.captured.pair.proof,
    request: otherRequest,
    trusted_server: fixture.trustedServer,
  }), assertSafeRejection);
});

test("contract framing is bounded and closed", () => {
  const frame = encodeIpcChannelFrame(Object.freeze({
    version: IPC_CHANNEL_BINDING_VERSION,
    protocol: IPC_CHANNEL_BINDING_PROTOCOL,
  }));
  assert.deepEqual(frameValue(frame), {
    version: IPC_CHANNEL_BINDING_VERSION,
    protocol: IPC_CHANNEL_BINDING_PROTOCOL,
  });
  assert.throws(
    () => encodeIpcChannelFrame({ body: "x".repeat(65_537) }),
    /IPC channel binding message was rejected/u,
  );
});
