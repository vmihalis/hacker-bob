"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { once } = require("node:events");

const { hashCanonicalJson } = require("../../../mcp/lib/verification-contracts.js");
const {
  signIpcDispatchRequest,
} = require("../../bob-instrument-broker/lib/ipc-contract.js");
const {
  decodeIpcChannelBody,
  encodeIpcChannelFrame,
  IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS,
  IPC_CHANNEL_TEST_ONLY_PROVIDER_ID,
  publicKeyDigest,
  _internals: { hashClosed },
} = require("../../bob-instrument-broker/lib/ipc-channel-binding-contract.js");
const {
  createIpcChannelAuthorityPort,
  createIpcChannelRequestAndProof,
  createIpcChannelReservationPort,
  createIpcNativeAcceptedChannelPort,
  createIpcTestOnlyDeterministicMockCooperativeDispatchPort,
  executeIpcChannelBindingServerConnection,
  validateIpcChannelResponse,
} = require("../../bob-instrument-broker/lib/ipc-channel-binding.js");

const MODULE_PATH = path.join(__dirname, "..", "lib", "native-acceptor.js");

function nonce() {
  return crypto.randomBytes(18).toString("base64url");
}

function frame(body) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const output = Buffer.allocUnsafe(payload.length + 4);
  output.writeUInt32BE(payload.length, 0);
  payload.copy(output, 4);
  return output;
}

function digest(label) {
  return crypto.createHash("sha256").update(label).digest("hex");
}

function assertSafeChannelRejection(error) {
  assert.equal(error?.code, "darwin_native_channel_rejected");
  assert.equal(error?.message, "Darwin native IPC channel was rejected");
  assert.equal(Object.hasOwn(error, "cause"), false);
  return true;
}

async function readClientFrame(socket) {
  let buffered = Buffer.alloc(0);
  while (buffered.length < 4) {
    const [chunk] = await once(socket, "data");
    buffered = Buffer.concat([buffered, chunk]);
  }
  const length = buffered.readUInt32BE(0);
  while (buffered.length < length + 4) {
    const [chunk] = await once(socket, "data");
    buffered = Buffer.concat([buffered, chunk]);
  }
  assert.equal(buffered.length, length + 4);
  return buffered.subarray(4);
}

async function connectionFixture(t) {
  const native = require(MODULE_PATH);
  const createdRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-native-acceptor-"));
  const root = fs.realpathSync.native(createdRoot);
  fs.chmodSync(root, 0o700);
  const socketPath = path.join(root, "broker.sock");
  const config = native.createDarwinNativeUnixAcceptor({
    adapter_id: "native_acceptor_fixture",
    socket_path: socketPath,
  });
  assert.equal(fs.existsSync(socketPath), false);
  const listener = native.openDarwinNativeUnixAcceptor(config);
  const accepted = native.acceptDarwinNativeUnixConnection(listener);
  const client = net.createConnection({ path: socketPath, allowHalfOpen: true });
  await once(client, "connect");
  const connection = await accepted;
  t.after(async () => {
    try { native.closeDarwinNativeAcceptedConnection(connection); } catch {}
    try { native.closeDarwinNativeUnixAcceptor(listener); } catch {}
    client.destroy();
    await Promise.race([
      once(client, "close"),
      new Promise((resolve) => setTimeout(resolve, 250)),
    ]);
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { native, root, socketPath, config, listener, connection, client };
}

test("import and configuration are inert and expose no socket path or descriptor", () => {
  const originalDlopen = process.dlopen;
  let loads = 0;
  process.dlopen = () => {
    loads += 1;
    throw new Error("native load during inert configuration");
  };
  try {
    delete require.cache[require.resolve(MODULE_PATH)];
    const native = require(MODULE_PATH);
    const socketPath = path.join(os.tmpdir(), "inert-native-acceptor.sock");
    const port = native.createDarwinNativeUnixAcceptor({
      adapter_id: "inert_native_acceptor",
      socket_path: socketPath,
    });
    assert.equal(loads, 0);
    assert.equal(fs.existsSync(socketPath), false);
    assert.equal(Object.hasOwn(port, "socket_path"), false);
    assert.equal(JSON.stringify(port).includes(socketPath), false);
    assert.equal(port.construction_inert, true);
    assert.equal(port.production_ready, false);
  } finally {
    process.dlopen = originalDlopen;
  }
});

test("native acceptor rejects a group-writable socket root", (t) => {
  const native = require(MODULE_PATH);
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "bob-native-root-mode-")),
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.chmodSync(root, 0o770);
  const config = native.createDarwinNativeUnixAcceptor({
    adapter_id: "native_acceptor_group_writable_fixture",
    socket_path: path.join(root, "broker.sock"),
  });
  assert.throws(
    () => native.openDarwinNativeUnixAcceptor(config),
    assertSafeChannelRejection,
  );
});

test("closing a listener cancels a pending native accept", async (t) => {
  const native = require(MODULE_PATH);
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "bob-native-accept-cancel-")),
  );
  const config = native.createDarwinNativeUnixAcceptor({
    adapter_id: "native_acceptor_cancel_fixture",
    socket_path: path.join(root, "broker.sock"),
  });
  const listener = native.openDarwinNativeUnixAcceptor(config);
  t.after(() => {
    try { native.closeDarwinNativeUnixAcceptor(listener); } catch {}
    fs.rmSync(root, { recursive: true, force: true });
  });
  const pending = native.acceptDarwinNativeUnixConnection(listener);
  native.closeDarwinNativeUnixAcceptor(listener);
  let timeout;
  try {
    await assert.rejects(
      Promise.race([
        pending,
        new Promise((_, reject) => {
          timeout = setTimeout(
            () => reject(new Error("pending native accept did not cancel")),
            1_000,
          );
        }),
      ]),
      assertSafeChannelRejection,
    );
  } finally {
    clearTimeout(timeout);
  }
});

test("detached accept ownership cannot shut down a forced reused descriptor", (t) => {
  const buildRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-accept-fd-owner-"));
  t.after(() => fs.rmSync(buildRoot, { recursive: true, force: true }));
  const source = path.join(
    __dirname,
    "fixtures",
    "tracked-accept-operation-fd.test.cc",
  );
  const executable = path.join(buildRoot, "tracked-accept-operation-fd-test");
  const compiled = spawnSync(process.env.CXX || "clang++", [
    "-std=c++17",
    "-pthread",
    "-I",
    path.join(__dirname, "..", "native"),
    source,
    "-o",
    executable,
  ], { encoding: "utf8" });
  assert.equal(compiled.status, 0, compiled.stderr);
  const executed = spawnSync(executable, [], { encoding: "utf8" });
  assert.equal(executed.status, 0, executed.stderr);
});

test("pool saturation cannot defer accept cancellation or native I/O deadlines", () => {
  const fixture = path.join(
    __dirname,
    "fixtures",
    "native-pool-saturation.js",
  );
  const child = spawnSync(process.execPath, [fixture], {
    encoding: "utf8",
    env: { ...process.env, UV_THREADPOOL_SIZE: "4" },
    timeout: 20_000,
  });
  assert.equal(child.status, 0, child.stderr);
  const result = JSON.parse(child.stdout);
  for (const operation of [result.accept, result.read, result.response]) {
    assert.equal(operation.code, "darwin_native_channel_rejected");
    assert.equal(operation.blockers_completed_at_rejection, 0);
    assert.ok(
      operation.elapsed_ms < 250,
      `deadline/cancellation waited ${operation.elapsed_ms}ms for the shared pool`,
    );
  }
  assert.equal(result.response.response_bytes, 0);
});

test("native accept precedes JavaScript bytes and brackets the two-flight channel", async (t) => {
  const fixture = await connectionFixture(t);
  const { native, connection, client, socketPath } = fixture;
  assert.equal(connection.accepted_and_registered_before_javascript, true);
  assert.equal(connection.javascript_descriptor_handoff_used, false);
  assert.equal(connection.descriptor_provenance_complete, true);
  assert.equal(connection.production_ready, false);
  for (const forbidden of [
    "fd", "socket_path", "acceptor_token", "connection_token", "registration_token",
  ]) assert.equal(Object.hasOwn(connection, forbidden), false, forbidden);
  assert.equal(JSON.stringify(connection).includes(socketPath), false);

  const peer = native.inspectDarwinNativeAcceptedConnectionPeer(connection, nonce());
  assert.equal(peer.peer_pid, process.pid);
  assert.equal(peer.connection_identity_digest, connection.connection_identity_digest);
  assert.equal(peer.descriptor_provenance_complete, true);
  const before = native.readDarwinNativeAcceptedConnectionIdentity(connection);

  const challengeBody = Buffer.from('{"flight":"challenge"}');
  const challengeWrite = native.writeDarwinNativeAcceptedConnectionChallenge(
    connection,
    frame(challengeBody),
    1_000,
  );
  assert.deepEqual(await readClientFrame(client), challengeBody);
  const challengeReceipt = await challengeWrite;
  assert.equal(challengeReceipt.operation, "challenge_written");

  const requestBody = Buffer.from('{"flight":"request_and_proof"}');
  client.write(frame(requestBody));
  assert.deepEqual(
    await native.readDarwinNativeAcceptedConnectionRequest(connection, 1_000),
    requestBody,
  );
  const after = native.readDarwinNativeAcceptedConnectionIdentity(connection);
  assert.equal(after.descriptor_readback_digest, before.descriptor_readback_digest);

  const responseBody = Buffer.from('{"flight":"response"}');
  const responseWrite = native.writeDarwinNativeAcceptedConnectionResponse(
    connection,
    frame(responseBody),
    1_000,
  );
  assert.deepEqual(await readClientFrame(client), responseBody);
  assert.equal((await responseWrite).operation, "response_written");
});

test("broker two-flight admission runs end to end over the native accepted channel", async (t) => {
  const fixture = await connectionFixture(t);
  const { native, connection, client } = fixture;
  const requestKeys = crypto.generateKeyPairSync("ed25519");
  const responseKeys = crypto.generateKeyPairSync("ed25519");
  const peer = native.inspectDarwinNativeAcceptedConnectionPeer(connection, nonce());
  const evidence = Object.freeze({
    version: 1,
    connection_identity_digest: peer.connection_identity_digest,
    descriptor_registration_nonce: peer.descriptor_registration_nonce,
    descriptor_registration_token_digest:
      peer.descriptor_registration_token_digest,
    descriptor_binding_scheme_digest: peer.descriptor_binding_scheme_digest,
    socket_root_identity_digest: peer.socket_root_identity_digest,
    socket_identity_digest: peer.socket_identity_digest,
    listener_identity_digest: peer.listener_identity_digest,
    acceptor_instance_digest: peer.acceptor_instance_digest,
    connection_generation: peer.connection_generation,
    peer_euid: peer.peer_euid,
    peer_egid: peer.peer_egid,
    peer_ruid: peer.peer_ruid,
    peer_rgid: peer.peer_rgid,
    peer_pid: peer.peer_pid,
    peer_pidversion: peer.peer_pidversion,
    peer_audit_token_digest: peer.peer_audit_token_digest,
    peer_process_start_token_digest: peer.peer_process_start_token_digest,
    peer_executable_path_digest: peer.peer_executable_path_digest,
    peer_selected_cdhash: peer.peer_selected_cdhash,
    peer_selected_cdhash_algorithm: peer.peer_selected_cdhash_algorithm,
    peer_code_directory_hashes_digest: peer.peer_code_directory_hashes_digest,
    peer_code_signing_identity_digest: peer.peer_code_signing_identity_digest,
    peer_code_dynamic_status_digest: peer.peer_code_dynamic_status_digest,
    peer_mapped_code_identity_digest: peer.peer_mapped_code_identity_digest,
    native_acceptor_implementation_digest:
      peer.native_binding_implementation_digest,
    native_loaded_image_identity_digest:
      peer.native_loaded_image_identity_digest,
    accepted_and_registered_before_javascript: true,
    javascript_descriptor_handoff_used: false,
    descriptor_provenance_complete: true,
    production_ready: false,
  });
  for (const [field, value] of Object.entries(evidence)) {
    if (field.endsWith("_digest")) {
      assert.match(value, /^[a-f0-9]{64}$/u, field);
    }
  }
  assert.ok([1, 2, 3].includes(evidence.peer_selected_cdhash_algorithm));
  assert.match(evidence.peer_selected_cdhash, /^[a-f0-9]{40}$/u);
  const channel = createIpcNativeAcceptedChannelPort({
    channel_id: "native_darwin_e2e_channel",
    evidence,
    write_challenge: (challengeFrame, timeout) =>
      native.writeDarwinNativeAcceptedConnectionChallenge(
        connection, challengeFrame, timeout,
      ),
    read_request_and_proof: (timeout) =>
      native.readDarwinNativeAcceptedConnectionRequest(connection, timeout),
    read_descriptor_identity: () =>
      native.readDarwinNativeAcceptedConnectionIdentity(connection),
    write_response: (responseFrame, timeout) =>
      native.writeDarwinNativeAcceptedConnectionResponse(
        connection, responseFrame, timeout,
      ),
    close: () => native.closeDarwinNativeAcceptedConnection(connection),
  });
  const reservationRecords = new Map();
  const reservation = createIpcChannelReservationPort({
    reservation_port_id: "native_darwin_e2e_reservations",
    reserve_reservation: ({ claim: _claim, ...query }) => {
      if (!reservationRecords.has(query.reservation_id)) {
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
        reservationRecords.set(query.reservation_id, Object.freeze({
          ...basis,
          reservation_receipt_digest: hashClosed(
            "hacker-bob/instrument-broker-ipc-channel-reservation/v2",
            "reservation_receipt",
            basis,
          ),
        }));
      }
      return reservationRecords.get(query.reservation_id);
    },
    read_reservation: (query) => reservationRecords.get(query.reservation_id),
  });
  const authorityRecord = Object.freeze({
    version: 1,
    authority_id: "native_darwin_e2e_authority",
    authority_epoch: 1,
    authority_digest: digest("e2e-authority"),
    server_bundle_identity_digest: digest("e2e-server-bundle"),
    server_launch_attestation_digest: digest("e2e-server-launch"),
    server_process_start_token_digest: digest("e2e-server-start"),
    trusted_monotonic_coordinate: "1",
    trusted: true,
    revoked: false,
  });
  const authority = createIpcChannelAuthorityPort({
    authority_id: authorityRecord.authority_id,
    read_current_authority: () => authorityRecord,
  });
  const operationPayload = Object.freeze({ mode: "native_e2e" });
  const request = signIpcDispatchRequest({
    version: 1,
    request_id: "ipc-request:native-darwin-e2e",
    ipc_peer_principal_id: "principal:native-e2e-client",
    execution_principal_id: "principal:native-e2e-worker",
    provider_id: IPC_CHANNEL_TEST_ONLY_PROVIDER_ID,
    provider_descriptor_digest: digest("e2e-provider-descriptor"),
    operation_id: "native_e2e_operation",
    operation_payload_digest: hashCanonicalJson(operationPayload),
    operation_payload: operationPayload,
    nonce: nonce(),
    sequence: 1,
    issued_at: "2026-07-19T02:00:00.000Z",
    deadline: "2026-07-19T02:00:04.000Z",
  }, {
    key_id: "ipc-key:native-e2e-request-v1",
    public_key_digest: publicKeyDigest(requestKeys.publicKey),
    private_key: requestKeys.privateKey,
  });
  const server = executeIpcChannelBindingServerConnection({
    channel_port: channel,
    reservation_port: reservation,
    authority_port: authority,
    server_identity: {
      server_principal_id: "principal:native-e2e-server",
      response_key_id: "ipc-key:native-e2e-response-v1",
      response_public_key_digest: publicKeyDigest(responseKeys.publicKey),
      private_key: responseKeys.privateKey,
    },
    expected_request_identity: {
      request_key_id: "ipc-key:native-e2e-request-v1",
      request_public_key_digest: publicKeyDigest(requestKeys.publicKey),
      request_public_key: requestKeys.publicKey,
      ipc_peer_principal_id: "principal:native-e2e-client",
      execution_principal_id: "principal:native-e2e-worker",
      provider_id: IPC_CHANNEL_TEST_ONLY_PROVIDER_ID,
      provider_descriptor_digest: digest("e2e-provider-descriptor"),
      provider_implementation_digest: digest("e2e-provider-implementation"),
    },
    client_attestation: {
      client_bundle_identity_digest: digest("e2e-client-bundle"),
      client_launch_attestation_digest: digest("e2e-client-launch"),
    },
    non_hardware_test_only_dispatch_port:
      createIpcTestOnlyDeterministicMockCooperativeDispatchPort({
        provider_descriptor_digest: digest("e2e-provider-descriptor"),
        provider_implementation_digest: digest("e2e-provider-implementation"),
        fixture_script: IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.complete,
      }),
    now: () => new Date("2026-07-19T02:00:00.000Z"),
    challenge_lifetime_ms: 5_000,
    io_timeout_ms: 1_000,
  });

  const challenge = decodeIpcChannelBody(await readClientFrame(client));
  const trustedServer = Object.freeze({
    server_principal_id: "principal:native-e2e-server",
    response_key_id: "ipc-key:native-e2e-response-v1",
    response_public_key_digest: publicKeyDigest(responseKeys.publicKey),
    public_key: responseKeys.publicKey,
  });
  const pair = createIpcChannelRequestAndProof({
    challenge,
    trusted_server: trustedServer,
    request_envelope: request,
    request_signer: {
      request_key_id: "ipc-key:native-e2e-request-v1",
      request_public_key_digest: publicKeyDigest(requestKeys.publicKey),
      private_key: requestKeys.privateKey,
    },
    client_attestation: {
      client_bundle_identity_digest: digest("e2e-client-bundle"),
      client_launch_attestation_digest: digest("e2e-client-launch"),
    },
    proof_nonce: nonce(),
    proof_deadline: "2026-07-19T02:00:04.000Z",
  });
  client.write(encodeIpcChannelFrame(pair));
  const response = decodeIpcChannelBody(await readClientFrame(client));
  const result = await server;
  assert.equal(result.status, "completed");
  assert.equal(result.production_attested, false);
  const projection = validateIpcChannelResponse({
    response,
    challenge,
    proof: pair.proof,
    request: pair.request,
    trusted_server: trustedServer,
  });
  assert.equal(projection.response_digest, result.response_digest);
  assert.throws(
    () => native.readDarwinNativeAcceptedConnectionIdentity(connection),
    assertSafeChannelRejection,
  );
});

test("out-of-order read, timeout, extra frame, and half-close reject terminally", async (t) => {
  await t.test("out-of-order read", async (t) => {
    const { native, connection } = await connectionFixture(t);
    native.inspectDarwinNativeAcceptedConnectionPeer(connection, nonce());
    await assert.rejects(
      native.readDarwinNativeAcceptedConnectionRequest(connection, 100),
      assertSafeChannelRejection,
    );
    await assert.rejects(
      native.writeDarwinNativeAcceptedConnectionChallenge(
        connection,
        frame("late"),
        100,
      ),
      assertSafeChannelRejection,
    );
  });

  await t.test("timeout", async (t) => {
    const { native, connection, client } = await connectionFixture(t);
    native.inspectDarwinNativeAcceptedConnectionPeer(connection, nonce());
    const written = native.writeDarwinNativeAcceptedConnectionChallenge(
      connection,
      frame("challenge"),
      1_000,
    );
    await readClientFrame(client);
    await written;
    await assert.rejects(
      native.readDarwinNativeAcceptedConnectionRequest(connection, 20),
      assertSafeChannelRejection,
    );
  });

  await t.test("extra frame", async (t) => {
    const { native, connection, client } = await connectionFixture(t);
    native.inspectDarwinNativeAcceptedConnectionPeer(connection, nonce());
    const written = native.writeDarwinNativeAcceptedConnectionChallenge(
      connection,
      frame("challenge"),
      1_000,
    );
    await readClientFrame(client);
    await written;
    client.write(Buffer.concat([frame("request"), frame("second")]));
    await assert.rejects(
      native.readDarwinNativeAcceptedConnectionRequest(connection, 1_000),
      assertSafeChannelRejection,
    );
  });

  await t.test("half-close", async (t) => {
    const { native, connection, client } = await connectionFixture(t);
    native.inspectDarwinNativeAcceptedConnectionPeer(connection, nonce());
    const written = native.writeDarwinNativeAcceptedConnectionChallenge(
      connection,
      frame("challenge"),
      1_000,
    );
    await readClientFrame(client);
    await written;
    const finished = once(client, "finish");
    client.end(frame("request"));
    await finished;
    await assert.rejects(
      native.readDarwinNativeAcceptedConnectionRequest(connection, 1_000),
      assertSafeChannelRejection,
    );
    await assert.rejects(
      native.writeDarwinNativeAcceptedConnectionResponse(
        connection,
        frame("response-after-half-close"),
        1_000,
      ),
      assertSafeChannelRejection,
    );
  });
});

test("an already-observable local half-close rejects deterministically", async (t) => {
  for (let iteration = 0; iteration < 16; iteration += 1) {
    await t.test(`iteration ${iteration + 1}`, async (t) => {
      const { native, connection, client } = await connectionFixture(t);
      native.inspectDarwinNativeAcceptedConnectionPeer(connection, nonce());
      const written = native.writeDarwinNativeAcceptedConnectionChallenge(
        connection,
        frame("challenge"),
        1_000,
      );
      await readClientFrame(client);
      await written;
      const finished = once(client, "finish");
      client.end(frame(`request-${iteration}`));
      await finished;
      await assert.rejects(
        native.readDarwinNativeAcceptedConnectionRequest(connection, 1_000),
        assertSafeChannelRejection,
      );
      await assert.rejects(
        native.writeDarwinNativeAcceptedConnectionResponse(
          connection,
          frame("terminal-response"),
          1_000,
        ),
        assertSafeChannelRejection,
      );
    });
  }
});
