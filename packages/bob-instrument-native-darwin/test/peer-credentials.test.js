"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const { once } = require("node:events");

const MODULE_PATH = path.join(__dirname, "..", "lib", "peer-credentials.js");
const BINDING_PATH = path.join(__dirname, "..", "build", "Release", "peer_credentials.node");
const SNAPSHOT_DOMAIN = "hacker-bob/darwin-native-peer-credential-snapshot/v3";
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const CODE_DIRECTORY_HASH_PATTERN = /^(?:[a-f0-9]{2}){16,64}$/u;
const RAW_NATIVE_SNAPSHOT_FIELDS = Object.freeze([
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
const RAW_LOADED_IMAGE_FIELDS = Object.freeze([
  "version",
  "primitive",
  "image_file_sha256",
  "image_identity_digest",
  "image_canonical_path_digest",
  "image_file_identity_digest",
  "image_lc_uuid_digest",
  "image_header_and_load_commands_digest",
  "image_executable_segments_digest",
  "image_executable_segment_count",
  "image_executable_file_bytes",
  "dyld_header_unique",
  "dladdr_base_matches_dyld",
  "dyld_snapshot_stable",
  "dyld_canonical_path_matches_dladdr",
  "callback_in_executable_segment",
  "header_and_load_commands_match_file",
  "executable_segments_match_file",
  "executable_pages_read_execute_only",
  "executable_segment_file_size_equals_vm_size",
  "non_executable_runtime_state_measured",
  "executable_image_identity_complete",
  "full_runtime_state_identity_complete",
]);

function nonce() {
  return crypto.randomBytes(16).toString("base64url");
}

function independentSnapshotDigest(domain, snapshot) {
  const basis = Object.create(null);
  for (const key of Object.keys(snapshot)) {
    if (key !== "snapshot_digest") basis[key] = snapshot[key];
  }
  const serialized = `{"domain":${JSON.stringify(domain)},"snapshot":${
    JSON.stringify(basis)}}`;
  return crypto.createHash("sha256").update(serialized).digest("hex");
}

function assertSafeRejection(error) {
  assert.equal(error?.code, "darwin_native_peer_rejected");
  assert.equal(error?.message, "Darwin native peer identity was rejected");
  assert.equal(Object.hasOwn(error, "cause"), false);
  return true;
}

function assertNativeRejection(error) {
  assert.equal(error?.code, "darwin_native_peer_inspection_failed");
  assert.equal(error?.message, "Darwin native peer inspection failed");
  return true;
}

function assertLoadedImageRejection(error) {
  assert.equal(error?.code, "darwin_native_loaded_image_inspection_failed");
  assert.equal(error?.message, "Darwin native loaded image inspection failed");
  return true;
}

function nativeSocketHandle(socket) {
  const descriptor = Object.getOwnPropertyDescriptor(net.Socket.prototype, "_handle");
  return Reflect.apply(descriptor.get, socket, []);
}

function nativeFdGetter(handle) {
  let prototype = Object.getPrototypeOf(handle);
  while (prototype != null) {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, "fd");
    if (descriptor != null) return descriptor.get;
    prototype = Object.getPrototypeOf(prototype);
  }
  throw new Error("native fd getter unavailable");
}

function nativeSocketFd(socket) {
  const handle = nativeSocketHandle(socket);
  return Reflect.apply(nativeFdGetter(handle), handle, []);
}

async function unixChildFixture(t) {
  const root = fs.mkdtempSync("/tmp/bob-native-peer-");
  const socketPath = path.join(root, "broker.sock");
  const server = net.createServer();
  server.listen(socketPath);
  await once(server, "listening");
  const acceptedPromise = once(server, "connection").then(([socket]) => socket);
  const childSource = [
    'const net = require("node:net");',
    "const socket = net.createConnection(process.argv[1]);",
    'socket.once("connect", () => socket.write("x"));',
    'socket.on("error", () => process.exit(2));',
    "setInterval(() => {}, 1000);",
  ].join("");
  const child = spawn(process.execPath, ["-e", childSource, socketPath], {
    stdio: ["ignore", "ignore", "ignore"],
  });
  const accepted = await acceptedPromise;
  await once(accepted, "data");
  t.after(async () => {
    accepted.destroy();
    child.kill("SIGKILL");
    await Promise.race([
      once(child, "exit"),
      new Promise((resolve) => setTimeout(resolve, 1000)),
    ]);
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { accepted, child, server, socketPath };
}

async function tcpFixture(t) {
  const server = net.createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const acceptedPromise = once(server, "connection").then(([socket]) => socket);
  const address = server.address();
  const client = net.createConnection(address.port, "127.0.0.1");
  await once(client, "connect");
  const accepted = await acceptedPromise;
  t.after(async () => {
    client.destroy();
    accepted.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return accepted;
}

test("package import is inert and exposes no accepted-socket claim", () => {
  const originalDlopen = process.dlopen;
  let loads = 0;
  process.dlopen = () => {
    loads += 1;
    throw new Error("native load during inert import");
  };
  try {
    delete require.cache[require.resolve(MODULE_PATH)];
    const imported = require(MODULE_PATH);
    assert.deepEqual(Object.keys(imported).sort(), [
      "DARWIN_NATIVE_PEER_CREDENTIAL_DOMAIN",
      "DARWIN_NATIVE_PEER_CREDENTIAL_PRIMITIVE",
      "DARWIN_NATIVE_PEER_CREDENTIAL_VERSION",
      "assertDarwinNativePeerCredentialInspector",
      "createDarwinNativePeerCredentialInspector",
      "inspectRegisteredDarwinUnixPeer",
      "registerDarwinUnixPeerDescriptor",
    ]);
    assert.equal(Object.hasOwn(imported, "inspectAcceptedDarwinUnixPeer"), false);
    assert.equal(loads, 0);
  } finally {
    process.dlopen = originalDlopen;
  }
});

test("native load failures are redacted and carry no attempted binary path", (t) => {
  const root = fs.mkdtempSync("/tmp/bob-native-missing-");
  const isolatedLib = path.join(root, "lib");
  const isolatedModule = path.join(isolatedLib, "peer-credentials.js");
  fs.mkdirSync(isolatedLib);
  fs.copyFileSync(MODULE_PATH, isolatedModule);
  for (const filename of ["canonical-snapshot.js", "native-binding-loader.js"]) {
    fs.copyFileSync(
      path.join(__dirname, "..", "lib", filename),
      path.join(isolatedLib, filename),
    );
  }
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const isolated = require(isolatedModule);
  assert.throws(
    () => isolated.createDarwinNativePeerCredentialInspector({ adapter_id: "missing_native" }),
    (error) => {
      assertSafeRejection(error);
      assert.equal(error.message.includes(root), false);
      assert.equal(error.message.includes("peer_credentials.node"), false);
      assert.equal(error.message.includes("prebuilds"), false);
      return true;
    },
  );
});

test("one registered Unix descriptor yields one exact stable audit-token snapshot", async (t) => {
  const peer = require(MODULE_PATH);
  const { accepted, child, socketPath } = await unixChildFixture(t);
  const inspector = peer.createDarwinNativePeerCredentialInspector({
    adapter_id: "darwin_registered_peer_v3",
  });
  assert.equal(peer.assertDarwinNativePeerCredentialInspector(inspector), inspector);
  assert.throws(
    () => peer.assertDarwinNativePeerCredentialInspector(structuredClone(inspector)),
    assertSafeRejection,
  );
  const utilTypes = require("node:util").types;
  const originalIsProxy = utilTypes.isProxy;
  let portProxyTraps = 0;
  try {
    utilTypes.isProxy = () => false;
    const portProxy = new Proxy(inspector, {
      isExtensible() {
        portProxyTraps += 1;
        throw new Error("proxy trap invoked");
      },
    });
    assert.throws(
      () => peer.assertDarwinNativePeerCredentialInspector(portProxy),
      assertSafeRejection,
    );
    assert.equal(portProxyTraps, 0);
  } finally {
    utilTypes.isProxy = originalIsProxy;
  }
  assert.ok(inspector.production_blockers.includes("js_socket_to_fd_custody_unproven"));
  assert.ok(inspector.production_blockers.includes(
    "descriptor_evidence_to_ipc_handshake_binding_missing",
  ));

  const registrationNonce = nonce();
  const registration = peer.registerDarwinUnixPeerDescriptor(
    inspector,
    nativeSocketFd(accepted),
    registrationNonce,
  );
  assert.equal(Object.isFrozen(registration), true);
  assert.equal(registration.descriptor_binding_scope,
    "exact_native_duplicate_of_supplied_descriptor_at_registration");
  assert.match(registration.descriptor_registration_token_digest, DIGEST_PATTERN);
  assert.equal(registration.native_loaded_image_identity_digest,
    inspector.native_loaded_image_identity_digest);
  assert.equal(registration.accepted_socket_object_binding_complete, false);
  assert.equal(registration.native_acceptor_registration_handoff_complete, false);
  assert.equal(registration.descriptor_provenance_complete, false);
  assert.equal(registration.descriptor_reregistration_prevented, false);
  assert.equal(registration.descriptor_evidence_ipc_handshake_binding_complete, false);
  assert.throws(
    () => peer.inspectRegisteredDarwinUnixPeer(
      peer.createDarwinNativePeerCredentialInspector({ adapter_id: "wrong_port" }),
      registration,
    ),
    assertSafeRejection,
  );
  assert.throws(
    () => peer.inspectRegisteredDarwinUnixPeer(inspector, structuredClone(registration)),
    assertSafeRejection,
  );
  let proxyReads = 0;
  const registrationProxy = new Proxy(registration, {
    get(target, property, receiver) {
      proxyReads += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  assert.throws(
    () => peer.inspectRegisteredDarwinUnixPeer(inspector, registrationProxy),
    assertSafeRejection,
  );
  assert.equal(proxyReads, 0);

  delete require.cache[require.resolve(MODULE_PATH)];
  const freshPeer = require(MODULE_PATH);
  const freshInspector = freshPeer.createDarwinNativePeerCredentialInspector({
    adapter_id: "reloaded_port",
  });
  assert.throws(
    () => freshPeer.inspectRegisteredDarwinUnixPeer(freshInspector, registration),
    assertSafeRejection,
  );

  const originalToJSON = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  let inheritedToJSONCalls = 0;
  let projection;
  try {
    Object.defineProperty(Object.prototype, "toJSON", {
      configurable: true,
      enumerable: false,
      get() {
        inheritedToJSONCalls += 1;
        return () => ({ forged: true });
      },
    });
    projection = peer.inspectRegisteredDarwinUnixPeer(inspector, registration);
  } finally {
    if (originalToJSON == null) delete Object.prototype.toJSON;
    else Object.defineProperty(Object.prototype, "toJSON", originalToJSON);
  }
  assert.equal(inheritedToJSONCalls, 0);
  assert.equal(projection.snapshot_digest, independentSnapshotDigest(SNAPSHOT_DOMAIN, projection));
  assert.equal(projection.version, 3);
  assert.equal(projection.adapter_id, "darwin_registered_peer_v3");
  assert.equal(projection.peer_pid, child.pid);
  assert.equal(projection.peer_uid, process.getuid());
  assert.equal(projection.peer_gid, process.getgid());
  assert.equal(projection.production_ready, false);
  assert.equal(projection.descriptor_registration_nonce, registrationNonce);
  assert.equal(
    projection.descriptor_registration_token_digest,
    registration.descriptor_registration_token_digest,
  );
  assert.equal(projection.descriptor_binding_scheme,
    "darwin_f_dupfd_cloexec_native_registration_token_v1");
  assert.equal(projection.descriptor_binding_scope,
    "exact_native_duplicate_of_supplied_descriptor_at_registration");
  assert.equal(projection.accepted_socket_object_binding_complete, false);
  assert.equal(projection.native_acceptor_registration_handoff_complete, false);
  assert.equal(projection.descriptor_provenance_complete, false);
  assert.equal(projection.descriptor_reregistration_prevented, false);
  assert.equal(projection.descriptor_evidence_ipc_handshake_binding_complete, false);
  assert.equal(projection.primitive,
    "darwin_registered_descriptor_peertoken_seccode_dynamic_identity_v3");
  assert.equal(projection.native_peer_measurement_version, 2);
  assert.equal(projection.native_peer_measurement_primitive,
    "darwin_local_peertoken_seccode_dynamic_identity_v2");
  assert.equal(projection.peer_executable_path_measurement_complete, true);
  assert.equal(projection.peer_executable_bytes_measurement_complete, false);
  assert.equal(projection.peer_executable_bytes_measurement_scheme, "unavailable");
  assert.equal(projection.native_binding_measurement_scheme,
    "darwin_addon_file_sha256_before_after_direct_dlopen_v2");
  assert.equal(projection.native_loaded_image_measurement_scheme,
    "darwin_dladdr_dyld_macho_executable_segments_file_match_v1");
  assert.equal(
    projection.native_loaded_image_file_sha256,
    projection.native_binding_implementation_digest,
  );
  assert.equal(projection.native_loaded_image_dyld_header_unique, true);
  assert.equal(projection.native_loaded_image_dladdr_base_matches_dyld, true);
  assert.equal(projection.native_loaded_image_dyld_snapshot_stable, true);
  assert.equal(
    projection.native_loaded_image_dyld_canonical_path_matches_dladdr,
    true,
  );
  assert.equal(projection.native_loaded_image_callback_in_executable_segment, true);
  assert.equal(
    projection.native_loaded_image_header_and_load_commands_match_file,
    true,
  );
  assert.equal(projection.native_loaded_image_executable_segments_match_file, true);
  assert.equal(
    projection.native_loaded_image_executable_pages_read_execute_only,
    true,
  );
  assert.equal(
    projection.native_loaded_image_executable_segment_file_size_equals_vm_size,
    true,
  );
  assert.equal(
    projection.native_loaded_image_non_executable_runtime_state_measured,
    false,
  );
  assert.equal(projection.native_loaded_image_executable_identity_complete, true);
  assert.equal(
    projection.native_loaded_image_full_runtime_state_identity_complete,
    false,
  );
  assert.equal(projection.native_loaded_image_signed_immutable_delivery_verified, false);
  assert.equal(projection.peer_code_identity_scheme,
    "darwin_seccode_guest_audit_token_dynamic_cdhash_v1");
  assert.equal(projection.peer_code_identity_completeness,
    "dynamic_seccode_identity_complete");
  assert.equal(projection.peer_code_identity_audit_token_bound, true);
  assert.equal(projection.peer_code_identity_stable, true);
  assert.equal(projection.peer_code_dynamic_validity, "valid");
  assert.match(projection.peer_code_directory_hash, CODE_DIRECTORY_HASH_PATTERN);
  assert.ok(projection.peer_code_directory_hash_algorithm > 0);
  for (const field of [
    "peer_audit_token_digest",
    "descriptor_registration_token_digest",
    "native_loaded_image_identity_digest",
    "native_loaded_image_canonical_path_digest",
    "native_loaded_image_file_identity_digest",
    "native_loaded_image_lc_uuid_digest",
    "native_loaded_image_header_and_load_commands_digest",
    "native_loaded_image_executable_segments_digest",
    "peer_process_start_token_digest",
    "peer_executable_path_digest",
    "peer_code_directory_hashes_digest",
    "peer_code_signing_identifier_digest",
    "peer_code_team_identifier_digest",
    "peer_code_certificate_chain_digest",
    "peer_code_designated_requirement_digest",
    "peer_code_static_flags_digest",
    "peer_code_dynamic_status_digest",
    "peer_code_signing_identity_digest",
    "peer_mapped_code_identity_digest",
    "snapshot_digest",
  ]) assert.match(projection[field], DIGEST_PATTERN, field);
  assert.equal(
    projection.peer_code_certificate_chain_state === "present",
    projection.peer_code_certificate_count > 0,
  );
  assert.equal(
    projection.peer_code_signer_identity_complete,
    projection.peer_code_signature_class === "certificate_signed"
      && projection.peer_code_team_identifier_state === "present",
  );
  assert.equal(Object.isFrozen(projection), true);
  const serialized = JSON.stringify(projection);
  assert.equal(serialized.includes(socketPath), false);
  assert.equal(serialized.includes(process.execPath), false);
  assert.throws(
    () => peer.inspectRegisteredDarwinUnixPeer(inspector, registration),
    assertSafeRejection,
  );
});

test("static signing identity is stable while mapped identity stays audit-token specific", async (t) => {
  const peer = require(MODULE_PATH);
  const first = await unixChildFixture(t);
  const second = await unixChildFixture(t);
  const inspector = peer.createDarwinNativePeerCredentialInspector({
    adapter_id: "darwin_registered_identity_stability",
  });
  const inspect = (fixture) => peer.inspectRegisteredDarwinUnixPeer(
    inspector,
    peer.registerDarwinUnixPeerDescriptor(
      inspector,
      nativeSocketFd(fixture.accepted),
      nonce(),
    ),
  );
  const firstProjection = inspect(first);
  const secondProjection = inspect(second);
  for (const field of [
    "peer_code_directory_hash",
    "peer_code_directory_hash_algorithm",
    "peer_code_directory_hashes_digest",
    "peer_code_signing_identifier_digest",
    "peer_code_team_identifier_state",
    "peer_code_team_identifier_digest",
    "peer_code_certificate_chain_state",
    "peer_code_certificate_count",
    "peer_code_certificate_chain_digest",
    "peer_code_designated_requirement_digest",
    "peer_code_static_flags_digest",
    "peer_code_signing_identity_digest",
  ]) assert.equal(firstProjection[field], secondProjection[field], field);
  assert.notEqual(firstProjection.peer_audit_token_digest,
    secondProjection.peer_audit_token_digest);
  assert.notEqual(
    firstProjection.descriptor_registration_token_digest,
    secondProjection.descriptor_registration_token_digest,
  );
  assert.notEqual(firstProjection.peer_mapped_code_identity_digest,
    secondProjection.peer_mapped_code_identity_digest);
});

test("prototype fd substitution cannot silently mislabel a registered descriptor", async (t) => {
  const peer = require(MODULE_PATH);
  const first = await unixChildFixture(t);
  const second = await unixChildFixture(t);
  const firstHandle = nativeSocketHandle(first.accepted);
  const secondHandle = nativeSocketHandle(second.accepted);
  const firstFd = nativeSocketFd(first.accepted);
  const secondFd = nativeSocketFd(second.accepted);
  assert.notEqual(first.child.pid, second.child.pid);
  assert.notEqual(firstFd, secondFd);
  const inspector = peer.createDarwinNativePeerCredentialInspector({
    adapter_id: "registered_descriptor_substitution_regression",
  });
  const firstRegistration = peer.registerDarwinUnixPeerDescriptor(
    inspector,
    firstFd,
    nonce(),
  );
  const originalPrototype = Object.getPrototypeOf(firstHandle);
  const forgedPrototype = Object.create(originalPrototype);
  Object.defineProperty(forgedPrototype, "fd", {
    get: nativeFdGetter(secondHandle).bind(secondHandle),
    set: undefined,
    enumerable: false,
    configurable: false,
  });
  try {
    Object.setPrototypeOf(firstHandle, forgedPrototype);
    assert.equal(nativeSocketFd(first.accepted), secondFd);
    assert.equal(Object.hasOwn(peer, "inspectAcceptedDarwinUnixPeer"), false);

    const firstProjection = peer.inspectRegisteredDarwinUnixPeer(
      inspector,
      firstRegistration,
    );
    assert.equal(firstProjection.peer_pid, first.child.pid);
    assert.equal(firstProjection.accepted_socket_object_binding_complete, false);

    const spoofedNumericRegistration = peer.registerDarwinUnixPeerDescriptor(
      inspector,
      nativeSocketFd(first.accepted),
      nonce(),
    );
    const transparentSecondProjection = peer.inspectRegisteredDarwinUnixPeer(
      inspector,
      spoofedNumericRegistration,
    );
    assert.equal(transparentSecondProjection.peer_pid, second.child.pid);
    assert.equal(transparentSecondProjection.descriptor_binding_scope,
      "exact_native_duplicate_of_supplied_descriptor_at_registration");
    assert.equal(transparentSecondProjection.descriptor_provenance_complete, false);
    assert.equal(
      transparentSecondProjection.descriptor_evidence_ipc_handshake_binding_complete,
      false,
    );
  } finally {
    Object.setPrototypeOf(firstHandle, originalPrototype);
  }
});

test("native registration tokens expose only a closed evidence digest and are one-use", async (t) => {
  const fixture = await unixChildFixture(t);
  const binding = require(BINDING_PATH);
  let setterCalls = 0;
  const originals = new Map();
  for (const property of ["peer_pid", "peer_code_directory_hash", "code"]) {
    originals.set(property, Object.getOwnPropertyDescriptor(Object.prototype, property));
    Object.defineProperty(Object.prototype, property, {
      configurable: true,
      set() { setterCalls += 1; },
    });
  }
  try {
    const token = binding.registerUnixPeerDescriptor(nativeSocketFd(fixture.accepted));
    assert.equal(Object.isFrozen(token), true);
    assert.deepEqual(Reflect.ownKeys(token), ["registration_token_digest"]);
    assert.deepEqual(Object.keys(token), []);
    const tokenDigestDescriptor = Object.getOwnPropertyDescriptor(
      token,
      "registration_token_digest",
    );
    assert.equal(tokenDigestDescriptor.writable, false);
    assert.equal(tokenDigestDescriptor.enumerable, false);
    assert.equal(tokenDigestDescriptor.configurable, false);
    assert.match(tokenDigestDescriptor.value, DIGEST_PATTERN);
    const raw = binding.inspectRegisteredUnixPeer(token);
    assert.equal(raw.peer_pid, fixture.child.pid);
    assert.equal(raw.descriptor_registration_token_digest,
      tokenDigestDescriptor.value);
    assert.deepEqual(Object.keys(raw).sort(), RAW_NATIVE_SNAPSHOT_FIELDS);
    for (const field of RAW_NATIVE_SNAPSHOT_FIELDS) {
      const descriptor = Object.getOwnPropertyDescriptor(raw, field);
      assert.equal(descriptor.writable, false, field);
      assert.equal(descriptor.configurable, false, field);
      assert.equal(descriptor.enumerable, true, field);
      assert.equal(Object.hasOwn(descriptor, "get"), false, field);
    }
    assert.throws(() => binding.inspectRegisteredUnixPeer(token), assertNativeRejection);
    assert.throws(
      () => binding.inspectRegisteredUnixPeer(structuredClone(token)),
      assertNativeRejection,
    );
    assert.equal(setterCalls, 0);
  } finally {
    for (const [property, descriptor] of originals) {
      if (descriptor == null) delete Object.prototype[property];
      else Object.defineProperty(Object.prototype, property, descriptor);
    }
  }
});

test("native loaded-image evidence binds mapped executable pages to the measured addon file", () => {
  const binding = require(BINDING_PATH);
  const first = binding.inspectLoadedImage();
  const second = binding.inspectLoadedImage();
  assert.deepEqual(Reflect.ownKeys(first), RAW_LOADED_IMAGE_FIELDS);
  assert.deepEqual(second, first);
  for (const field of RAW_LOADED_IMAGE_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(first, field);
    assert.equal(descriptor.writable, false, field);
    assert.equal(descriptor.configurable, false, field);
    assert.equal(descriptor.enumerable, true, field);
    assert.equal(Object.hasOwn(descriptor, "get"), false, field);
  }
  assert.equal(first.image_file_sha256,
    crypto.createHash("sha256").update(fs.readFileSync(BINDING_PATH)).digest("hex"));
  for (const field of [
    "image_file_sha256",
    "image_identity_digest",
    "image_canonical_path_digest",
    "image_file_identity_digest",
    "image_lc_uuid_digest",
    "image_header_and_load_commands_digest",
    "image_executable_segments_digest",
  ]) assert.match(first[field], DIGEST_PATTERN, field);
  assert.equal(first.dyld_header_unique, true);
  assert.equal(first.dladdr_base_matches_dyld, true);
  assert.equal(first.dyld_snapshot_stable, true);
  assert.equal(first.dyld_canonical_path_matches_dladdr, true);
  assert.equal(first.callback_in_executable_segment, true);
  assert.equal(first.header_and_load_commands_match_file, true);
  assert.equal(first.executable_segments_match_file, true);
  assert.equal(first.executable_pages_read_execute_only, true);
  assert.equal(first.executable_segment_file_size_equals_vm_size, true);
  assert.equal(first.executable_image_identity_complete, true);
  assert.equal(first.non_executable_runtime_state_measured, false);
  assert.equal(first.full_runtime_state_identity_complete, false);
  assert.ok(first.image_executable_segment_count > 0);
  assert.match(first.image_executable_file_bytes, /^[1-9][0-9]{0,7}$/u);
  assert.equal(JSON.stringify(first).includes(BINDING_PATH), false);
  assert.throws(() => binding.inspectLoadedImage(1), assertLoadedImageRejection);
});

test("loader rejects on-disk addon drift after loaded-image identity is established", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-native-image-drift-"));
  const isolatedLib = path.join(root, "lib");
  const isolatedRelease = path.join(root, "build", "Release");
  const isolatedModule = path.join(isolatedLib, "peer-credentials.js");
  const isolatedBinding = path.join(isolatedRelease, "peer_credentials.node");
  fs.mkdirSync(isolatedLib, { recursive: true });
  fs.mkdirSync(isolatedRelease, { recursive: true });
  for (const filename of [
    "canonical-snapshot.js",
    "native-binding-loader.js",
    "peer-credentials.js",
  ]) {
    fs.copyFileSync(path.join(__dirname, "..", "lib", filename), path.join(isolatedLib, filename));
  }
  fs.copyFileSync(BINDING_PATH, isolatedBinding);
  fs.chmodSync(isolatedBinding, 0o500);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const childSource = [
    '"use strict";',
    'const fs = require("node:fs");',
    "const modulePath = process.argv[1];",
    "const bindingPath = process.argv[2];",
    "const peer = require(modulePath);",
    "peer.createDarwinNativePeerCredentialInspector({adapter_id:'before_image_drift'});",
    "const replacementPath = `${bindingPath}.replacement`;",
    "const replacement = fs.readFileSync(bindingPath);",
    "replacement[replacement.length - 1] ^= 1;",
    "fs.writeFileSync(replacementPath, replacement, {mode:0o500});",
    "fs.renameSync(replacementPath, bindingPath);",
    "let code = null;",
    "let message = null;",
    "let cause = false;",
    "try { peer.createDarwinNativePeerCredentialInspector({adapter_id:'after_image_drift'}); }",
    "catch (error) { code = error && error.code; message = error && error.message; cause = Object.hasOwn(error, 'cause'); }",
    "process.stdout.write(JSON.stringify({code,message,cause}));",
  ].join("");
  const result = spawnSync(
    process.execPath,
    ["-e", childSource, isolatedModule, isolatedBinding],
    { encoding: "utf8", maxBuffer: 1024 * 1024 },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    code: "darwin_native_peer_rejected",
    message: "Darwin native peer identity was rejected",
    cause: false,
  });
});

test("native success, registration failure, and abandoned-token paths close duplicates", async (t) => {
  const fixture = await unixChildFixture(t);
  const binding = require(BINDING_PATH);
  const socketFd = nativeSocketFd(fixture.accepted);
  const regularFileFd = fs.openSync(__filename, "r");
  t.after(() => fs.closeSync(regularFileFd));
  const openFdCount = () => fs.readdirSync("/dev/fd")
    .filter((name) => /^[0-9]+$/u.test(name)).length;
  const before = openFdCount();
  for (let index = 0; index < 32; index += 1) {
    const token = binding.registerUnixPeerDescriptor(socketFd);
    binding.inspectRegisteredUnixPeer(token);
    assert.throws(
      () => binding.registerUnixPeerDescriptor(regularFileFd),
      assertNativeRejection,
    );
  }
  assert.ok(openFdCount() <= before + 1);

  const gcSource = [
    '"use strict";',
    "const fs = require('node:fs');",
    "const binding = require(process.argv[1]);",
    "const count = () => fs.readdirSync('/dev/fd').filter((name) => /^[0-9]+$/.test(name)).length;",
    "const before = count();",
    "function abandon() { for (let index = 0; index < 64; index += 1) binding.registerUnixPeerDescriptor(3); }",
    "abandon();",
    "for (let index = 0; index < 8; index += 1) global.gc();",
    "setImmediate(() => { global.gc(); process.stdout.write(JSON.stringify({before,after:count()})); });",
  ].join("");
  const result = spawnSync(
    process.execPath,
    ["--expose-gc", "-e", gcSource, BINDING_PATH],
    {
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe", socketFd],
    },
  );
  assert.equal(result.status, 0, result.stderr);
  const counts = JSON.parse(result.stdout);
  assert.ok(counts.after <= counts.before + 2, JSON.stringify(counts));
});

test("TCP, closed, invalid, forged, and malformed registrations fail closed", async (t) => {
  const peer = require(MODULE_PATH);
  const inspector = peer.createDarwinNativePeerCredentialInspector({
    adapter_id: "registered_descriptor_negatives",
  });
  const tcp = await tcpFixture(t);
  assert.throws(
    () => peer.registerDarwinUnixPeerDescriptor(inspector, nativeSocketFd(tcp), nonce()),
    assertSafeRejection,
  );

  const closedFixture = await unixChildFixture(t);
  const closedFd = nativeSocketFd(closedFixture.accepted);
  const closed = once(closedFixture.accepted, "close");
  closedFixture.accepted.destroy();
  await closed;
  assert.throws(
    () => peer.registerDarwinUnixPeerDescriptor(inspector, closedFd, nonce()),
    assertSafeRejection,
  );

  const binding = require(BINDING_PATH);
  assert.equal(Object.isFrozen(binding), true);
  assert.throws(() => { binding.registerUnixPeerDescriptor = () => null; }, TypeError);
  assert.throws(() => { binding.inspectRegisteredUnixPeer = () => null; }, TypeError);
  const regularFileFd = fs.openSync(__filename, "r");
  t.after(() => fs.closeSync(regularFileFd));
  for (const fd of [
    -1,
    regularFileFd,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    0x8000_0000,
    "1",
    1n,
    null,
    undefined,
  ]) assert.throws(() => binding.registerUnixPeerDescriptor(fd), assertNativeRejection);
  assert.throws(() => binding.registerUnixPeerDescriptor(), assertNativeRejection);
  assert.throws(
    () => binding.registerUnixPeerDescriptor(nativeSocketFd(tcp), 1),
    assertNativeRejection,
  );
  for (const token of [{}, Object.freeze({}), null, undefined, 1, "token"]) {
    assert.throws(() => binding.inspectRegisteredUnixPeer(token), assertNativeRejection);
  }
  assert.throws(() => binding.inspectRegisteredUnixPeer(), assertNativeRejection);
  assert.throws(
    () => binding.inspectRegisteredUnixPeer(Object.freeze({}), 1),
    assertNativeRejection,
  );

  assert.throws(
    () => peer.registerDarwinUnixPeerDescriptor(inspector, regularFileFd, nonce()),
    assertSafeRejection,
  );
  assert.throws(
    () => peer.registerDarwinUnixPeerDescriptor(inspector, nativeSocketFd(tcp)),
    assertSafeRejection,
  );
  assert.throws(
    () => peer.registerDarwinUnixPeerDescriptor(inspector, nativeSocketFd(tcp), nonce(), 1),
    assertSafeRejection,
  );
  assert.throws(
    () => peer.inspectRegisteredDarwinUnixPeer(inspector, Object.freeze({})),
    assertSafeRejection,
  );
  assert.throws(
    () => peer.inspectRegisteredDarwinUnixPeer(inspector, Object.freeze({}), 1),
    assertSafeRejection,
  );
});
