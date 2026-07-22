"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const MODULE_PATH = require.resolve("../lib/native-dispatch-contract.js");

function digest(label) {
  return crypto.createHash("sha256").update(`native-dispatch-test:${label}`, "utf8").digest("hex");
}

const commandBytes = Buffer.from([0x11, 0xef, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x15, 0xeb]);

function payload(overrides = {}) {
  return {
    version: 1,
    protocol: "hacker-bob/physical-native-dispatch/v1",
    grant_kind: "bootstrap",
    command_kind: "observe",
    effect_class: "none",
    rf_constraint: "rf_off",
    ticket_id: "native-ticket:bootstrap-1",
    ticket_nonce: Buffer.alloc(24, 7).toString("base64url"),
    ticket_sequence: "1",
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: digest("provider-descriptor"),
    provider_implementation_digest: digest("provider-implementation"),
    semantic_manifest_digest: digest("semantic-manifest"),
    device_identity_digest: digest("device-identity"),
    device_enrollment_digest: digest("device-enrollment"),
    connection_generation: "4",
    execution_principal_id: "principal:active-device-worker",
    worker_process_start_digest: digest("worker-process-start"),
    worker_bundle_digest: digest("worker-bundle"),
    native_loaded_image_identity_digest: digest("native-loaded-image"),
    launcher_ticket_digest: digest("launcher-ticket"),
    launcher_delegation_receipt_digest: digest("launcher-delegation"),
    device_descriptor_inventory_digest: digest("descriptor-inventory"),
    session_nucleus_hash: digest("session-nucleus"),
    node_id: "PH-P7",
    contract_hash: digest("contract"),
    attempt_ref: "attempt:bootstrap-1",
    signed_grant_digest: digest("signed-grant"),
    execution_request_digest: digest("execution-request"),
    authority_resolution_digest: digest("authority-resolution"),
    authority_epoch: "9",
    revocation_generation: "3",
    operation_id: "get_app_version",
    operation_digest: digest("operation"),
    parameter_digest: digest("parameters"),
    requested_effects_digest: digest("effects"),
    required_pre_state_digest: digest("pre-state"),
    authorized_transition_digest: digest("transition"),
    resource_bundle_digest: digest("resource-bundle"),
    allocation_digest: digest("allocation"),
    reservation_receipt_digest: digest("reservation"),
    fencing_token_digest: digest("fence"),
    journal_entry_digest: digest("journal"),
    outbox_entry_digest: digest("outbox"),
    provider_redemption_digest: digest("redemption"),
    safety_contract_digest: digest("safety-contract"),
    safety_custody_receipt_digest: digest("safety-custody"),
    cleanup_precommit_digest: digest("cleanup-precommit"),
    observer_plan_digest: digest("observer-plan"),
    command_sequence: "1",
    command_bytes_digest: crypto.createHash("sha256").update(commandBytes).digest("hex"),
    command_byte_length: commandBytes.length,
    maximum_response_bytes: 4096,
    clock_epoch_digest: digest("clock-epoch"),
    not_before_monotonic_ns: "1000000000",
    deadline_monotonic_ns: "1500000000",
    one_use: true,
    delegated_descriptor_identity_digest: digest("delegated-descriptor-identity"),
    execution_lineage_digest: digest("execution-lineage"),
    vault_reservation_digest: digest("vault-reservation"),
    vault_ingest_capability_digest: digest("vault-ingest-capability"),
    vault_sink_descriptor_identity_digest: digest("vault-sink-descriptor"),
    vault_byte_ceiling: 4096,
    artifact_handle_digest: digest("artifact-handle"),
    ...overrides,
  };
}

function clone(value) {
  return structuredClone(value);
}

function assertRejected(error) {
  assert.equal(error?.code, "physical_native_dispatch_contract_rejected");
  assert.equal(error?.message, "Physical native dispatch contract was rejected");
  return true;
}

test("module import is inert and exposes an explicitly non-authorizing precursor", () => {
  delete require.cache[MODULE_PATH];
  const before = new Set(Object.keys(require.cache));
  const contract = require(MODULE_PATH);
  const loaded = Object.keys(require.cache).filter((entry) => !before.has(entry));
  assert.deepEqual(loaded, [MODULE_PATH]);
  assert.deepEqual(contract.NATIVE_DISPATCH_CONTRACT_ASSURANCE, {
    version: 1,
    protocol: "hacker-bob/physical-native-dispatch/v1",
    canonical_binary_payload: true,
    canonical_signed_binary_envelope: true,
    signature_binds_key_id_and_public_key_digest: true,
    delegated_descriptor_identity_encoding: true,
    response_sink_descriptor_identity_encoding: true,
    raw_command_bytes_embedded_in_ticket: false,
    native_signature_verifier_implemented: false,
    native_monotonic_deadline_recheck_implemented: false,
    launcher_delegated_descriptor_consumption_implemented: false,
    independently_preemptible_effect_boundary_implemented: false,
    hardware_authority_constructible: false,
    production_ready: false,
  });
  assert.equal(typeof contract.open, "undefined");
  assert.equal(typeof contract.dispatch, "undefined");
  assert.equal(typeof contract.loadNative, "undefined");
});

test("fixed TLV encoding is deterministic, canonical, and round trips every binding", () => {
  const {
    decodeNativeDispatchPayload,
    encodeNativeDispatchPayload,
  } = require(MODULE_PATH);
  const expected = payload();
  const first = encodeNativeDispatchPayload(expected);
  const second = encodeNativeDispatchPayload({ ...expected });
  assert.ok(first.equals(second));
  assert.equal(first.subarray(0, 8).toString("ascii"), "HBPHDSP1");
  assert.equal(first.readUInt16BE(8), 1);
  assert.equal(first.readUInt16BE(10), 64);
  assert.deepEqual(decodeNativeDispatchPayload(first), expected);

  for (const mutate of [
    (bytes) => { bytes[0] ^= 1; },
    (bytes) => { bytes.writeUInt16BE(2, 8); },
    (bytes) => { bytes.writeUInt16BE(62, 10); },
    (bytes) => { bytes.writeUInt16BE(2, 12); },
    (bytes) => Buffer.concat([bytes, Buffer.from([0])]),
  ]) {
    let hostile = Buffer.from(first);
    const replacement = mutate(hostile);
    if (replacement) hostile = replacement;
    assert.throws(() => decodeNativeDispatchPayload(hostile), assertRejected);
  }
});

test("Ed25519 ticket verification binds the exact canonical payload and enrolled key", () => {
  const {
    signNativeDispatchTicket,
    verifySignedNativeDispatchTicket,
  } = require(MODULE_PATH);
  const signer = crypto.generateKeyPairSync("ed25519");
  const other = crypto.generateKeyPairSync("ed25519");
  const signed = signNativeDispatchTicket({
    payload: payload(),
    key_id: "native-dispatch-key:issuer-v1",
    private_key: signer.privateKey,
  });
  assert.deepEqual(verifySignedNativeDispatchTicket(signed, signer.publicKey), payload());
  assert.throws(() => verifySignedNativeDispatchTicket(signed, other.publicKey), assertRejected);

  const forgedSignature = clone(signed);
  const forgedEnvelope = Buffer.from(forgedSignature.envelope_b64, "base64url");
  forgedEnvelope[forgedEnvelope.length - 1] ^= 1;
  forgedSignature.envelope_b64 = forgedEnvelope.toString("base64url");
  forgedSignature.envelope_digest = crypto.createHash("sha256")
    .update(forgedEnvelope).digest("hex");
  assert.throws(
    () => verifySignedNativeDispatchTicket(forgedSignature, signer.publicKey),
    assertRejected,
  );

  const fork = clone(signed);
  const forkEnvelope = Buffer.from(fork.envelope_b64, "base64url");
  const decoded = require(MODULE_PATH)._internals.decodeNativeDispatchEnvelopeBytes(forkEnvelope);
  forkEnvelope[decoded.payload_offset + decoded.payload_length - 1] ^= 1;
  fork.envelope_b64 = forkEnvelope.toString("base64url");
  fork.envelope_digest = crypto.createHash("sha256").update(forkEnvelope).digest("hex");
  assert.throws(() => verifySignedNativeDispatchTicket(fork, signer.publicKey), assertRejected);
});

test("the signed binary envelope prevents key-id alias and public-digest rewrites", () => {
  const {
    _internals,
    signNativeDispatchTicket,
    verifySignedNativeDispatchTicket,
  } = require(MODULE_PATH);
  const signer = crypto.generateKeyPairSync("ed25519");
  const signed = signNativeDispatchTicket({
    payload: payload(),
    key_id: "native-dispatch-key:slot-alpha",
    private_key: signer.privateKey,
  });
  assert.deepEqual(
    verifySignedNativeDispatchTicket(
      signed,
      signer.publicKey,
      "native-dispatch-key:slot-alpha",
    ),
    payload(),
  );
  assert.throws(
    () => verifySignedNativeDispatchTicket(
      signed,
      signer.publicKey,
      "native-dispatch-key:slot-bravo",
    ),
    assertRejected,
  );

  const envelope = Buffer.from(signed.envelope_b64, "base64url");
  const decoded = _internals.decodeNativeDispatchEnvelopeBytes(envelope);
  const revoked = Buffer.from(decoded.key_id, "utf8");
  const active = Buffer.from("native-dispatch-key:slot-bravo", "utf8");
  assert.equal(active.length, revoked.length);
  active.copy(envelope, 50);
  const rewritten = {
    ...signed,
    envelope_b64: envelope.toString("base64url"),
    envelope_digest: crypto.createHash("sha256").update(envelope).digest("hex"),
  };
  assert.throws(
    () => verifySignedNativeDispatchTicket(
      rewritten,
      signer.publicKey,
      "native-dispatch-key:slot-bravo",
    ),
    assertRejected,
  );

  const digestRewrite = Buffer.from(signed.envelope_b64, "base64url");
  digestRewrite[18] ^= 1;
  assert.throws(() => verifySignedNativeDispatchTicket({
    ...signed,
    envelope_b64: digestRewrite.toString("base64url"),
    envelope_digest: crypto.createHash("sha256").update(digestRewrite).digest("hex"),
  }, signer.publicKey), assertRejected);
});

test("delegated descriptor identity has one exact cross-language encoding", () => {
  const {
    NATIVE_DELEGATED_DESCRIPTOR_FD,
    NATIVE_DELEGATED_DESCRIPTOR_PURPOSE,
    NATIVE_DELEGATED_DESCRIPTOR_ROLE,
    deriveNativeDelegatedDescriptorIdentityDigest,
    encodeNativeDelegatedDescriptorIdentity,
  } = require(MODULE_PATH);
  const identity = {
    version: 1,
    role: NATIVE_DELEGATED_DESCRIPTOR_ROLE,
    fd_number: NATIVE_DELEGATED_DESCRIPTOR_FD,
    purpose: NATIVE_DELEGATED_DESCRIPTOR_PURPOSE,
    dev: "16777234",
    ino: "9918273",
    rdev: "268435458",
    mode: 0o20600,
    nlink: "1",
    uid: 501,
    gid: 20,
    character_device: true,
    access_mode: 2,
    status_flags: 6,
    fd_flags: 0,
  };
  const first = encodeNativeDelegatedDescriptorIdentity(identity);
  const second = encodeNativeDelegatedDescriptorIdentity({ ...identity });
  assert.ok(first.equals(second));
  assert.equal(first.subarray(0, 8).toString("ascii"), "HBPHDID1");
  assert.equal(first.readUInt16BE(8), 1);
  assert.equal(first.readUInt16BE(10), 15);
  assert.equal(
    deriveNativeDelegatedDescriptorIdentityDigest(identity),
    crypto.createHash("sha256").update(first).digest("hex"),
  );
  for (const hostile of [
    { role: "generic_transport" },
    { fd_number: 9 },
    { purpose: "arbitrary_read_write" },
    { mode: 0o100600 },
    { character_device: false },
    { access_mode: 1, status_flags: 1 },
    { status_flags: 2 },
    { status_flags: 6 | 0x0008 },
    { status_flags: 6 | 0x0040 },
    { fd_flags: 1 },
  ]) {
    assert.throws(
      () => encodeNativeDelegatedDescriptorIdentity({ ...identity, ...hostile }),
      assertRejected,
    );
  }
});

test("pre-reserved response sink identity has one owner-only append descriptor encoding", () => {
  const contract = require(MODULE_PATH);
  const identity = {
    version: 1,
    role: contract.NATIVE_RESPONSE_SINK_DESCRIPTOR_ROLE,
    fd_number: contract.NATIVE_RESPONSE_SINK_DESCRIPTOR_FD,
    purpose: contract.NATIVE_RESPONSE_SINK_DESCRIPTOR_PURPOSE,
    dev: "16777234",
    ino: "9918274",
    rdev: "0",
    mode: 0o100600,
    nlink: "1",
    uid: 501,
    gid: 20,
    regular_file: true,
    access_mode: contract.NATIVE_RESPONSE_SINK_DESCRIPTOR_ACCESS_MODE,
    status_flags: contract.NATIVE_RESPONSE_SINK_DESCRIPTOR_STATUS_FLAGS,
    fd_flags: contract.NATIVE_RESPONSE_SINK_DESCRIPTOR_FD_FLAGS,
    initial_size: "0",
  };
  const encoded = contract.encodeNativeResponseSinkDescriptorIdentity(identity);
  assert.equal(encoded.subarray(0, 8).toString("ascii"), "HBPHDVS1");
  assert.equal(encoded.readUInt16BE(8), 1);
  assert.equal(encoded.readUInt16BE(10), 16);
  assert.equal(
    contract.deriveNativeResponseSinkDescriptorIdentityDigest(identity),
    crypto.createHash("sha256").update(encoded).digest("hex"),
  );
  for (const hostile of [
    { role: "generic_file_sink" },
    { fd_number: 6 },
    { purpose: "arbitrary_file_write" },
    { mode: 0o100644 },
    { mode: 0o20600 },
    { nlink: "2" },
    { regular_file: false },
    { access_mode: 2 },
    { status_flags: 1 },
    { fd_flags: 1 },
    { initial_size: "1" },
  ]) {
    assert.throws(
      () => contract.encodeNativeResponseSinkDescriptorIdentity({ ...identity, ...hostile }),
      assertRejected,
    );
  }
  encoded.fill(0);
});

test("every TLV field is covered by the signature and a field splice cannot survive", () => {
  const {
    _internals,
    signNativeDispatchTicket,
    verifySignedNativeDispatchTicket,
  } = require(MODULE_PATH);
  const signer = crypto.generateKeyPairSync("ed25519");
  const signed = signNativeDispatchTicket({
    payload: payload(),
    key_id: "native-dispatch-key:issuer-v1",
    private_key: signer.privateKey,
  });
  const originalEnvelope = Buffer.from(signed.envelope_b64, "base64url");
  const decoded = _internals.decodeNativeDispatchEnvelopeBytes(originalEnvelope);
  const original = originalEnvelope.subarray(
    decoded.payload_offset,
    decoded.payload_offset + decoded.payload_length,
  );
  let offset = 12;
  for (const [tag] of _internals.FIELD_DEFINITIONS) {
    assert.equal(original.readUInt16BE(offset), tag);
    const length = original.readUInt32BE(offset + 2);
    const hostile = Buffer.from(originalEnvelope);
    hostile[decoded.payload_offset + offset + 6 + Math.max(0, length - 1)] ^= 1;
    const fork = clone(signed);
    fork.envelope_b64 = hostile.toString("base64url");
    fork.envelope_digest = crypto.createHash("sha256").update(hostile).digest("hex");
    assert.throws(() => verifySignedNativeDispatchTicket(fork, signer.publicKey), assertRejected);
    offset += 6 + length;
  }
  assert.equal(offset, original.length);
});

test("closed schemas reject getters, proxies, symbols, unknown fields, and wrong key types", () => {
  const {
    encodeNativeDispatchPayload,
    signNativeDispatchTicket,
  } = require(MODULE_PATH);
  const signer = crypto.generateKeyPairSync("ed25519");
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const withExtra = { ...payload(), raw_device_path: "/dev/cu.usbmodem-secret" };
  assert.throws(() => encodeNativeDispatchPayload(withExtra), assertRejected);
  assert.throws(() => encodeNativeDispatchPayload(new Proxy(payload(), {})), assertRejected);
  const getter = payload();
  Object.defineProperty(getter, "provider_id", { enumerable: true, get() { return "chameleon_ultra"; } });
  assert.throws(() => encodeNativeDispatchPayload(getter), assertRejected);
  const symbol = payload();
  symbol[Symbol("hidden")] = true;
  assert.throws(() => encodeNativeDispatchPayload(symbol), assertRejected);
  assert.throws(() => signNativeDispatchTicket({
    payload: payload(),
    key_id: "native-dispatch-key:issuer-v1",
    private_key: rsa.privateKey,
  }), assertRejected);
  assert.doesNotThrow(() => signNativeDispatchTicket({
    payload: payload(),
    key_id: "native-dispatch-key:issuer-v1",
    private_key: signer.privateKey,
  }));
});

test("captured binary and crypto intrinsics survive hostile prototype substitution", () => {
  const contract = require(MODULE_PATH);
  const signer = crypto.generateKeyPairSync("ed25519");
  const hashPrototype = Object.getPrototypeOf(crypto.createHash("sha256"));
  const publicKeyPrototype = Object.getPrototypeOf(signer.publicKey);
  const expectedPayload = payload();
  const originals = {
    bigIntToString: BigInt.prototype.toString,
    byteLength: Buffer.byteLength,
    copy: Buffer.prototype.copy,
    digest: hashPrototype.digest,
    export: publicKeyPrototype.export,
    update: hashPrototype.update,
  };
  let signed;
  try {
    Buffer.byteLength = () => { throw new Error("mutable Buffer.byteLength reached"); };
    Buffer.prototype.copy = () => { throw new Error("mutable Buffer.copy reached"); };
    BigInt.prototype.toString = () => { throw new Error("mutable BigInt.toString reached"); };
    hashPrototype.update = () => { throw new Error("mutable Hash.update reached"); };
    hashPrototype.digest = () => { throw new Error("mutable Hash.digest reached"); };
    publicKeyPrototype.export = () => { throw new Error("mutable KeyObject.export reached"); };
    signed = contract.signNativeDispatchTicket({
      payload: expectedPayload,
      key_id: "native-dispatch-key:issuer-v1",
      private_key: signer.privateKey,
    });
    assert.deepEqual(
      contract.verifySignedNativeDispatchTicket(
        signed,
        signer.publicKey,
        "native-dispatch-key:issuer-v1",
      ),
      expectedPayload,
    );
  } finally {
    Buffer.byteLength = originals.byteLength;
    Buffer.prototype.copy = originals.copy;
    BigInt.prototype.toString = originals.bigIntToString;
    hashPrototype.update = originals.update;
    hashPrototype.digest = originals.digest;
    publicKeyPrototype.export = originals.export;
  }
  assert.equal(typeof signed.envelope_b64, "string");
});

test("grant-kind, RF, command, clock, and bounded byte invariants fail closed", () => {
  const { encodeNativeDispatchPayload, _internals } = require(MODULE_PATH);
  for (const hostile of [
    { grant_kind: "bootstrap", command_kind: "command" },
    { grant_kind: "bootstrap", effect_class: "target" },
    { grant_kind: "bootstrap", rf_constraint: "bounded" },
    { grant_kind: "cleanup", command_kind: "observe" },
    { deadline_monotonic_ns: "1000000000" },
    { not_before_monotonic_ns: "1500000001" },
    { deadline_monotonic_ns: (1_000_000_000n + _internals.MAX_EFFECT_WINDOW_NS + 1n).toString() },
    { command_byte_length: _internals.MAX_COMMAND_BYTES + 1 },
    { maximum_response_bytes: _internals.MAX_RESPONSE_BYTES + 1 },
    { vault_byte_ceiling: _internals.MAX_RESPONSE_BYTES + 1 },
    { maximum_response_bytes: 4096, vault_byte_ceiling: 4095 },
    { one_use: false },
    { authority_epoch: "0" },
    { ticket_sequence: "01" },
  ]) {
    assert.throws(() => encodeNativeDispatchPayload(payload(hostile)), assertRejected);
  }
});

test("command validation exposes only length/digests and rejects substitution", () => {
  const { assertNativeDispatchCommandBytes } = require(MODULE_PATH);
  assert.deepEqual(assertNativeDispatchCommandBytes(payload(), commandBytes), {
    command_byte_length: commandBytes.length,
    command_bytes_digest: payload().command_bytes_digest,
    maximum_response_bytes: 4096,
  });
  const substituted = Buffer.from(commandBytes);
  substituted[2] ^= 1;
  assert.throws(() => assertNativeDispatchCommandBytes(payload(), substituted), assertRejected);
  assert.throws(
    () => assertNativeDispatchCommandBytes(payload({ command_byte_length: 11 }), commandBytes),
    assertRejected,
  );
});
