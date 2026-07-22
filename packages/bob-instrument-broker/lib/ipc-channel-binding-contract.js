"use strict";

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const SafeError = Error;
const SafeBuffer = Buffer;
const SafeDate = Date;
const bufferAllocUnsafe = Buffer.allocUnsafe;
const bufferFrom = Buffer.from;
const bufferIsBuffer = Buffer.isBuffer;
const bufferCopy = Buffer.prototype.copy;
const bufferToString = Buffer.prototype.toString;
const bufferWriteUInt32BE = Buffer.prototype.writeUInt32BE;
const cryptoCreateHash = crypto.createHash;
const cryptoCreatePublicKey = crypto.createPublicKey;
const cryptoSign = crypto.sign;
const cryptoVerify = crypto.verify;
const dateParse = Date.parse;
const dateToISOString = Date.prototype.toISOString;
const jsonParse = JSON.parse;
const jsonStringify = JSON.stringify;
const numberIsSafeInteger = Number.isSafeInteger;
const numberIsFinite = Number.isFinite;
const numberMaxSafeInteger = Number.MAX_SAFE_INTEGER;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectKeys = Object.keys;
const objectPrototype = Object.prototype;
const objectValues = Object.values;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regExpTest = RegExp.prototype.test;
const stringEndsWith = String.prototype.endsWith;
const stringStartsWith = String.prototype.startsWith;
const utilTypesIsKeyObject = utilTypes.isKeyObject;
const utilTypesIsProxy = utilTypes.isProxy;

const HASH_PROTOTYPE = objectGetPrototypeOf(cryptoCreateHash("sha256"));
const HASH_UPDATE = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "update").value;
const HASH_DIGEST = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "digest").value;
const KEY_OBJECT_TYPE_GETTER = objectGetOwnPropertyDescriptor(
  crypto.KeyObject.prototype,
  "type",
).get;
const ED25519_SPKI_PREFIX_HEX = "302a300506032b6570032100";
const CAPTURE_PUBLIC_KEY = reflectApply(cryptoCreatePublicKey, crypto, [{
  key: reflectApply(bufferFrom, SafeBuffer, [
    `${ED25519_SPKI_PREFIX_HEX}`
      + "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "hex",
  ]),
  format: "der",
  type: "spki",
}]);
const PUBLIC_KEY_EXPORT = objectGetOwnPropertyDescriptor(
  objectGetPrototypeOf(CAPTURE_PUBLIC_KEY),
  "export",
).value;

const IPC_CHANNEL_BINDING_VERSION = 1;
const IPC_CHANNEL_BINDING_PROTOCOL = "instrument_broker_native_channel_binding_v1";
const IPC_CHANNEL_CHALLENGE_DOMAIN =
  "hacker-bob/instrument-broker-ipc-channel-challenge/v1";
const IPC_CHANNEL_PROOF_DOMAIN =
  "hacker-bob/instrument-broker-ipc-channel-proof/v1";
const IPC_CHANNEL_RESPONSE_DOMAIN =
  "hacker-bob/instrument-broker-ipc-channel-response/v1";
const IPC_CHANNEL_CHALLENGE_KEY_USAGE =
  "instrument_broker_ipc_response_signed_channel_challenge";
const IPC_CHANNEL_PROOF_KEY_USAGE =
  "instrument_broker_ipc_request_key_channel_proof";
const IPC_CHANNEL_RESPONSE_KEY_USAGE =
  "instrument_broker_ipc_response_channel_binding";
const IPC_CHANNEL_TEST_ONLY_PROVIDER_ID = "deterministic_mock";
const IPC_CHANNEL_TEST_ONLY_DISPATCH_BOUNDARY_KIND =
  "test_only_deterministic_mock_same_event_loop_cooperative_v1";
const IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SOURCE =
  "test_only_deterministic_mock";
const IPC_CHANNEL_TEST_ONLY_DISPATCH_DEADLINE_ENFORCEMENT =
  "cooperative_timer_and_post_dispatch_fence_only";
const IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS = objectFreeze({
  complete: "complete",
  reject: "reject",
  invalid_error_code: "invalid_error_code",
  unavailable: "unavailable",
  never_settle: "never_settle",
  busy_loop_300ms_then_complete: "busy_loop_300ms_then_complete",
});
const IPC_CHANNEL_SAFE_ERROR_CODES = objectFreeze([
  "dispatch_rejected",
  "dispatch_unavailable",
  "dispatch_timeout",
  "operation_failed",
  "operation_inconclusive",
  "operation_refused",
  "operation_stopped",
]);

const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const CODE_DIRECTORY_CDHASH_PATTERN = /^[a-f0-9]{40}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,128}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;

const AUTHENTICATION_FIELDS = objectFreeze([
  "scheme",
  "key_usage",
  "key_id",
  "public_key_digest",
  "signed_payload_digest",
  "signature",
]);
const CHALLENGE_PAYLOAD_FIELDS = objectFreeze([
  "version",
  "protocol",
  "challenge_nonce",
  "listener_identity_digest",
  "socket_root_identity_digest",
  "socket_identity_digest",
  "connection_generation",
  "acceptor_instance_digest",
  "native_acceptor_implementation_digest",
  "connection_identity_digest",
  "descriptor_registration_nonce",
  "descriptor_registration_token_digest",
  "descriptor_binding_scheme_digest",
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
  "native_loaded_image_identity_digest",
  "server_principal_id",
  "server_bundle_identity_digest",
  "server_launch_attestation_digest",
  "server_process_start_token_digest",
  "expected_request_key_id",
  "expected_request_public_key_digest",
  "ipc_peer_principal_id",
  "execution_principal_id",
  "provider_id",
  "provider_descriptor_digest",
  "provider_implementation_digest",
  "dispatch_boundary_kind",
  "dispatch_fixture_source",
  "dispatch_fixture_script",
  "dispatch_deadline_enforcement",
  "dispatch_separate_identity",
  "dispatch_independently_preemptible",
  "dispatch_worker_trusted_deadline_recheck",
  "dispatch_hardware_authority",
  "dispatch_production_ready",
  "startup_authority_digest",
  "authority_epoch",
  "trusted_monotonic_coordinate",
  "issued_at",
  "expires_at",
  "descriptor_initial_readback_digest",
  "challenge_reservation_receipt_digest",
]);
const PROOF_PAYLOAD_FIELDS = objectFreeze([
  "version",
  "protocol",
  "challenge_digest",
  "signed_request_digest",
  "request_nonce",
  "request_sequence",
  "request_key_id",
  "request_public_key_digest",
  "ipc_peer_principal_id",
  "execution_principal_id",
  "provider_id",
  "provider_descriptor_digest",
  "provider_implementation_digest",
  "client_bundle_identity_digest",
  "client_launch_attestation_digest",
  "proof_nonce",
  "proof_deadline",
]);
const RESPONSE_PAYLOAD_FIELDS = objectFreeze([
  "version",
  "protocol",
  "challenge_digest",
  "proof_digest",
  "request_digest",
  "request_id",
  "request_nonce",
  "request_sequence",
  "server_principal_id",
  "provider_id",
  "provider_descriptor_digest",
  "provider_implementation_digest",
  "dispatch_boundary_kind",
  "dispatch_fixture_source",
  "dispatch_fixture_script",
  "dispatch_deadline_enforcement",
  "dispatch_separate_identity",
  "dispatch_independently_preemptible",
  "dispatch_worker_trusted_deadline_recheck",
  "dispatch_hardware_authority",
  "dispatch_production_ready",
  "status",
  "error_code",
  "operation_result_digest",
  "request_reservation_receipt_digest",
  "proof_reservation_receipt_digest",
  "descriptor_post_reservation_readback_digest",
  "startup_authority_digest",
  "responded_at",
]);

function contractError() {
  const error = new SafeError("IPC channel binding message was rejected");
  objectDefineProperty(error, "code", {
    value: "ipc_channel_binding_message_rejected",
    writable: false,
    enumerable: false,
    configurable: false,
  });
  return error;
}

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || objectIsFrozen(value)) return value;
  const children = objectValues(value);
  for (let index = 0; index < children.length; index += 1) {
    deepFreeze(children[index]);
  }
  return objectFreeze(value);
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

function assertClosedObject(value, fields) {
  if (!isPlainDataObject(value)) throw contractError();
  const keys = objectKeys(value);
  if (keys.length !== fields.length) throw contractError();
  for (let fieldIndex = 0; fieldIndex < fields.length; fieldIndex += 1) {
    let found = false;
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      if (keys[keyIndex] === fields[fieldIndex]) found = true;
    }
    if (!found) throw contractError();
  }
  return value;
}

function assertDigest(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, DIGEST_PATTERN, [value])) throw contractError();
  return value;
}

function assertSelectedCdhash(value, algorithm) {
  if ((algorithm !== 1 && algorithm !== 2 && algorithm !== 3)
      || typeof value !== "string"
      || !reflectApply(regExpTest, CODE_DIRECTORY_CDHASH_PATTERN, [value])) {
    throw contractError();
  }
  return value;
}

function assertToken(value, prefix = null) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, TOKEN_PATTERN, [value])
      || (prefix != null
        && !reflectApply(stringStartsWith, value, [`${prefix}:`]))) throw contractError();
  return value;
}

function assertNonce(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, NONCE_PATTERN, [value])) throw contractError();
  const bytes = reflectApply(bufferFrom, SafeBuffer, [value, "base64url"]);
  if (bytes.length < 16
      || reflectApply(bufferToString, bytes, ["base64url"]) !== value) {
    throw contractError();
  }
  return value;
}

function assertDecimal(value) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, DECIMAL_PATTERN, [value])) throw contractError();
  return value;
}

function assertUint(value, maximum = numberMaxSafeInteger) {
  if (!numberIsSafeInteger(value) || value < 0 || value > maximum) throw contractError();
  return value;
}

function assertSafeErrorCode(value) {
  assertToken(value);
  for (let index = 0; index < IPC_CHANNEL_SAFE_ERROR_CODES.length; index += 1) {
    if (IPC_CHANNEL_SAFE_ERROR_CODES[index] === value) return value;
  }
  throw contractError();
}

function assertTestOnlyDispatchBoundary(input) {
  const fixtureScript = input.dispatch_fixture_script;
  if (input.provider_id !== IPC_CHANNEL_TEST_ONLY_PROVIDER_ID
      || input.dispatch_boundary_kind
        !== IPC_CHANNEL_TEST_ONLY_DISPATCH_BOUNDARY_KIND
      || input.dispatch_fixture_source
        !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SOURCE
      || (fixtureScript !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.complete
        && fixtureScript !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.reject
        && fixtureScript
          !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.invalid_error_code
        && fixtureScript !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.unavailable
        && fixtureScript !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS.never_settle
        && fixtureScript
          !== IPC_CHANNEL_TEST_ONLY_DISPATCH_FIXTURE_SCRIPTS
            .busy_loop_300ms_then_complete)
      || input.dispatch_deadline_enforcement
        !== IPC_CHANNEL_TEST_ONLY_DISPATCH_DEADLINE_ENFORCEMENT
      || input.dispatch_separate_identity !== false
      || input.dispatch_independently_preemptible !== false
      || input.dispatch_worker_trusted_deadline_recheck !== false
      || input.dispatch_hardware_authority !== false
      || input.dispatch_production_ready !== false) {
    throw contractError();
  }
}

function assertTimestamp(value) {
  if (typeof value !== "string") throw contractError();
  const milliseconds = reflectApply(dateParse, SafeDate, [value]);
  const date = new SafeDate(milliseconds);
  if (!numberIsFinite(milliseconds)
      || reflectApply(dateToISOString, date, []) !== value) throw contractError();
  return value;
}

function hashBytes(value) {
  const hash = cryptoCreateHash("sha256");
  reflectApply(HASH_UPDATE, hash, [value]);
  return reflectApply(HASH_DIGEST, hash, ["hex"]);
}

function hashClosed(domain, kind, value) {
  return hashBytes(reflectApply(jsonStringify, JSON, [{ domain, kind, value }]));
}

function assertKey(value, type) {
  if (!utilTypesIsKeyObject(value)
      || reflectApply(KEY_OBJECT_TYPE_GETTER, value, []) !== type) {
    throw contractError();
  }
  return value;
}

function publicKeyDigest(key) {
  if (!utilTypesIsKeyObject(key)) throw contractError();
  const keyType = reflectApply(KEY_OBJECT_TYPE_GETTER, key, []);
  const publicKey = keyType === "private"
    ? reflectApply(cryptoCreatePublicKey, crypto, [key])
    : key;
  assertKey(publicKey, "public");
  const encoded = reflectApply(PUBLIC_KEY_EXPORT, publicKey,
    [{ type: "spki", format: "der" }]);
  if (!bufferIsBuffer(encoded) || encoded.length !== 44
      || reflectApply(bufferToString, encoded, ["hex", 0, 12])
        !== ED25519_SPKI_PREFIX_HEX) {
    throw contractError();
  }
  return hashBytes(encoded);
}

function authenticationBasis(authentication) {
  return deepFreeze({
    scheme: authentication.scheme,
    key_usage: authentication.key_usage,
    key_id: authentication.key_id,
    public_key_digest: authentication.public_key_digest,
    signed_payload_digest: authentication.signed_payload_digest,
  });
}

function normalizeAuthentication(input, keyUsage, payloadDigest) {
  assertClosedObject(input, AUTHENTICATION_FIELDS);
  if (input.scheme !== "ed25519" || input.key_usage !== keyUsage
      || input.signed_payload_digest !== payloadDigest
      || typeof input.signature !== "string"
      || !reflectApply(regExpTest, SIGNATURE_PATTERN, [input.signature])) {
    throw contractError();
  }
  const bytes = reflectApply(bufferFrom, SafeBuffer, [input.signature, "base64url"]);
  if (bytes.length !== 64
      || reflectApply(bufferToString, bytes, ["base64url"]) !== input.signature) {
    throw contractError();
  }
  return deepFreeze({
    scheme: "ed25519",
    key_usage: keyUsage,
    key_id: assertToken(input.key_id, "ipc-key"),
    public_key_digest: assertDigest(input.public_key_digest),
    signed_payload_digest: payloadDigest,
    signature: input.signature,
  });
}

function signEnvelope(domain, kind, keyUsage, payload, signer) {
  assertClosedObject(signer, ["key_id", "public_key_digest", "private_key"]);
  const privateKey = assertKey(signer.private_key, "private");
  const derivedDigest = publicKeyDigest(privateKey);
  if (assertDigest(signer.public_key_digest) !== derivedDigest) throw contractError();
  const payloadDigest = hashClosed(domain, `${kind}_payload`, payload);
  const basis = deepFreeze({
    scheme: "ed25519",
    key_usage: keyUsage,
    key_id: assertToken(signer.key_id, "ipc-key"),
    public_key_digest: derivedDigest,
    signed_payload_digest: payloadDigest,
  });
  const signatureInput = hashClosed(domain, `${kind}_signature`, {
    payload,
    authentication: basis,
  });
  const signature = reflectApply(cryptoSign, crypto, [
    null,
    reflectApply(bufferFrom, SafeBuffer, [signatureInput, "hex"]),
    privateKey,
  ]);
  const authentication = deepFreeze({
    ...basis,
    signature: reflectApply(bufferToString, signature, ["base64url"]),
  });
  return deepFreeze({ payload, authentication });
}

function verifyEnvelope(domain, kind, keyUsage, envelope, publicKey) {
  const key = assertKey(publicKey, "public");
  if (publicKeyDigest(key) !== envelope.authentication.public_key_digest) return false;
  const signatureInput = hashClosed(domain, `${kind}_signature`, {
    payload: envelope.payload,
    authentication: authenticationBasis(envelope.authentication),
  });
  return reflectApply(cryptoVerify, crypto, [
    null,
    reflectApply(bufferFrom, SafeBuffer, [signatureInput, "hex"]),
    key,
    reflectApply(bufferFrom, SafeBuffer,
      [envelope.authentication.signature, "base64url"]),
  ]);
}

function normalizeChallengePayload(input) {
  assertClosedObject(input, CHALLENGE_PAYLOAD_FIELDS);
  const normalized = objectCreate(null);
  for (let index = 0; index < CHALLENGE_PAYLOAD_FIELDS.length; index += 1) {
    const field = CHALLENGE_PAYLOAD_FIELDS[index];
    normalized[field] = input[field];
  }
  if (normalized.version !== IPC_CHANNEL_BINDING_VERSION
      || normalized.protocol !== IPC_CHANNEL_BINDING_PROTOCOL) throw contractError();
  assertNonce(normalized.challenge_nonce);
  assertDecimal(normalized.connection_generation);
  for (let index = 3; index < CHALLENGE_PAYLOAD_FIELDS.length; index += 1) {
    const field = CHALLENGE_PAYLOAD_FIELDS[index];
    if (reflectApply(stringEndsWith, field, ["_digest"])) {
      assertDigest(normalized[field]);
    }
  }
  assertUint(normalized.peer_selected_cdhash_algorithm, 0xffff_ffff);
  assertSelectedCdhash(
    normalized.peer_selected_cdhash,
    normalized.peer_selected_cdhash_algorithm,
  );
  assertNonce(normalized.descriptor_registration_nonce);
  const peerIntegerFields = [
    "peer_euid", "peer_egid", "peer_ruid", "peer_rgid", "peer_pid", "peer_pidversion",
  ];
  for (let index = 0; index < peerIntegerFields.length; index += 1) {
    assertUint(normalized[peerIntegerFields[index]], 0xffff_ffff);
  }
  assertToken(normalized.expected_request_key_id, "ipc-key");
  assertToken(normalized.server_principal_id, "principal");
  assertToken(normalized.ipc_peer_principal_id, "principal");
  assertToken(normalized.execution_principal_id, "principal");
  assertToken(normalized.provider_id);
  assertToken(normalized.dispatch_boundary_kind);
  assertToken(normalized.dispatch_fixture_source);
  assertToken(normalized.dispatch_deadline_enforcement);
  assertTestOnlyDispatchBoundary(normalized);
  assertUint(normalized.authority_epoch);
  assertDecimal(normalized.trusted_monotonic_coordinate);
  assertTimestamp(normalized.issued_at);
  assertTimestamp(normalized.expires_at);
  if (reflectApply(dateParse, SafeDate, [normalized.issued_at])
      >= reflectApply(dateParse, SafeDate, [normalized.expires_at])) {
    throw contractError();
  }
  return deepFreeze(normalized);
}

function normalizeProofPayload(input) {
  assertClosedObject(input, PROOF_PAYLOAD_FIELDS);
  const normalized = objectCreate(null);
  for (let index = 0; index < PROOF_PAYLOAD_FIELDS.length; index += 1) {
    normalized[PROOF_PAYLOAD_FIELDS[index]] = input[PROOF_PAYLOAD_FIELDS[index]];
  }
  if (normalized.version !== IPC_CHANNEL_BINDING_VERSION
      || normalized.protocol !== IPC_CHANNEL_BINDING_PROTOCOL) throw contractError();
  const proofDigestFields = [
    "challenge_digest", "signed_request_digest", "request_public_key_digest",
    "provider_descriptor_digest", "provider_implementation_digest",
    "client_bundle_identity_digest",
    "client_launch_attestation_digest",
  ];
  for (let index = 0; index < proofDigestFields.length; index += 1) {
    assertDigest(normalized[proofDigestFields[index]]);
  }
  assertNonce(normalized.request_nonce);
  assertUint(normalized.request_sequence);
  assertToken(normalized.request_key_id, "ipc-key");
  assertToken(normalized.ipc_peer_principal_id, "principal");
  assertToken(normalized.execution_principal_id, "principal");
  assertToken(normalized.provider_id);
  if (normalized.provider_id !== IPC_CHANNEL_TEST_ONLY_PROVIDER_ID) {
    throw contractError();
  }
  assertNonce(normalized.proof_nonce);
  assertTimestamp(normalized.proof_deadline);
  return deepFreeze(normalized);
}

function normalizeResponsePayload(input) {
  assertClosedObject(input, RESPONSE_PAYLOAD_FIELDS);
  const normalized = objectCreate(null);
  for (let index = 0; index < RESPONSE_PAYLOAD_FIELDS.length; index += 1) {
    normalized[RESPONSE_PAYLOAD_FIELDS[index]] = input[RESPONSE_PAYLOAD_FIELDS[index]];
  }
  if (normalized.version !== IPC_CHANNEL_BINDING_VERSION
      || normalized.protocol !== IPC_CHANNEL_BINDING_PROTOCOL
      || (normalized.status !== "completed" && normalized.status !== "rejected"
        && normalized.status !== "ambiguous")) {
    throw contractError();
  }
  const responseDigestFields = [
    "challenge_digest", "proof_digest", "request_digest", "operation_result_digest",
    "request_reservation_receipt_digest", "proof_reservation_receipt_digest",
    "descriptor_post_reservation_readback_digest",
    "startup_authority_digest", "provider_descriptor_digest",
    "provider_implementation_digest",
  ];
  for (let index = 0; index < responseDigestFields.length; index += 1) {
    assertDigest(normalized[responseDigestFields[index]]);
  }
  assertToken(normalized.request_id, "ipc-request");
  assertNonce(normalized.request_nonce);
  assertUint(normalized.request_sequence);
  assertToken(normalized.server_principal_id, "principal");
  assertToken(normalized.provider_id);
  assertToken(normalized.dispatch_boundary_kind);
  assertToken(normalized.dispatch_fixture_source);
  assertToken(normalized.dispatch_deadline_enforcement);
  assertTestOnlyDispatchBoundary(normalized);
  if (normalized.error_code !== null) assertSafeErrorCode(normalized.error_code);
  if ((normalized.status === "completed" && normalized.error_code !== null)
      || (normalized.status !== "completed" && normalized.error_code === null)) {
    throw contractError();
  }
  assertTimestamp(normalized.responded_at);
  return deepFreeze(normalized);
}

function normalizeSignedEnvelope(input, options) {
  assertClosedObject(input, [
    "version", "kind", "domain", "payload", "authentication", options.digest_field,
  ]);
  if (input.version !== IPC_CHANNEL_BINDING_VERSION
      || input.kind !== options.kind || input.domain !== options.domain) {
    throw contractError();
  }
  const payload = options.normalize_payload(input.payload);
  const payloadDigest = hashClosed(options.domain, `${options.kind}_payload`, payload);
  const authentication = normalizeAuthentication(
    input.authentication,
    options.key_usage,
    payloadDigest,
  );
  const basis = deepFreeze({
    version: IPC_CHANNEL_BINDING_VERSION,
    kind: options.kind,
    domain: options.domain,
    payload,
    authentication,
  });
  const digest = hashClosed(options.domain, `${options.kind}_envelope`, basis);
  if (assertDigest(input[options.digest_field]) !== digest) throw contractError();
  return deepFreeze({ ...basis, [options.digest_field]: digest });
}

const CHALLENGE_OPTIONS = objectFreeze({
  kind: "instrument_channel_challenge",
  domain: IPC_CHANNEL_CHALLENGE_DOMAIN,
  key_usage: IPC_CHANNEL_CHALLENGE_KEY_USAGE,
  digest_field: "challenge_digest",
  normalize_payload: normalizeChallengePayload,
});
const PROOF_OPTIONS = objectFreeze({
  kind: "instrument_channel_proof",
  domain: IPC_CHANNEL_PROOF_DOMAIN,
  key_usage: IPC_CHANNEL_PROOF_KEY_USAGE,
  digest_field: "proof_digest",
  normalize_payload: normalizeProofPayload,
});
const RESPONSE_OPTIONS = objectFreeze({
  kind: "instrument_channel_response",
  domain: IPC_CHANNEL_RESPONSE_DOMAIN,
  key_usage: IPC_CHANNEL_RESPONSE_KEY_USAGE,
  digest_field: "response_digest",
  normalize_payload: normalizeResponsePayload,
});

function signWithOptions(payloadInput, signer, options) {
  const payload = options.normalize_payload(payloadInput);
  const signed = signEnvelope(
    options.domain,
    options.kind,
    options.key_usage,
    payload,
    signer,
  );
  const basis = deepFreeze({
    version: IPC_CHANNEL_BINDING_VERSION,
    kind: options.kind,
    domain: options.domain,
    payload: signed.payload,
    authentication: signed.authentication,
  });
  return normalizeSignedEnvelope({
    ...basis,
    [options.digest_field]: hashClosed(
      options.domain,
      `${options.kind}_envelope`,
      basis,
    ),
  }, options);
}

function signIpcChannelChallenge(payload, signer) {
  return signWithOptions(payload, signer, CHALLENGE_OPTIONS);
}

function normalizeSignedIpcChannelChallenge(input) {
  return normalizeSignedEnvelope(input, CHALLENGE_OPTIONS);
}

function verifyIpcChannelChallenge(input, publicKey) {
  const envelope = normalizeSignedIpcChannelChallenge(input);
  return verifyEnvelope(
    IPC_CHANNEL_CHALLENGE_DOMAIN,
    CHALLENGE_OPTIONS.kind,
    IPC_CHANNEL_CHALLENGE_KEY_USAGE,
    envelope,
    publicKey,
  );
}

function signIpcChannelProof(payload, signer) {
  return signWithOptions(payload, signer, PROOF_OPTIONS);
}

function normalizeSignedIpcChannelProof(input) {
  return normalizeSignedEnvelope(input, PROOF_OPTIONS);
}

function verifyIpcChannelProof(input, publicKey) {
  const envelope = normalizeSignedIpcChannelProof(input);
  return verifyEnvelope(
    IPC_CHANNEL_PROOF_DOMAIN,
    PROOF_OPTIONS.kind,
    IPC_CHANNEL_PROOF_KEY_USAGE,
    envelope,
    publicKey,
  );
}

function signIpcChannelResponse(payload, signer) {
  return signWithOptions(payload, signer, RESPONSE_OPTIONS);
}

function normalizeSignedIpcChannelResponse(input) {
  return normalizeSignedEnvelope(input, RESPONSE_OPTIONS);
}

function verifyIpcChannelResponse(input, publicKey) {
  const envelope = normalizeSignedIpcChannelResponse(input);
  return verifyEnvelope(
    IPC_CHANNEL_RESPONSE_DOMAIN,
    RESPONSE_OPTIONS.kind,
    IPC_CHANNEL_RESPONSE_KEY_USAGE,
    envelope,
    publicKey,
  );
}

function encodeIpcChannelFrame(value) {
  const body = reflectApply(bufferFrom, SafeBuffer,
    [reflectApply(jsonStringify, JSON, [value]), "utf8"]);
  if (body.length < 1 || body.length > 65_536) throw contractError();
  const frame = reflectApply(bufferAllocUnsafe, SafeBuffer, [body.length + 4]);
  reflectApply(bufferWriteUInt32BE, frame, [body.length, 0]);
  reflectApply(bufferCopy, body, [frame, 4]);
  return frame;
}

function decodeIpcChannelBody(body) {
  if (!bufferIsBuffer(body) || utilTypesIsProxy(body)
      || body.length < 1 || body.length > 65_536) throw contractError();
  let value;
  try {
    value = reflectApply(jsonParse, JSON,
      [reflectApply(bufferToString, body, ["utf8"])]);
  } catch {
    throw contractError();
  }
  return value;
}

module.exports = objectFreeze({
  IPC_CHANNEL_BINDING_PROTOCOL,
  IPC_CHANNEL_BINDING_VERSION,
  IPC_CHANNEL_CHALLENGE_DOMAIN,
  IPC_CHANNEL_PROOF_DOMAIN,
  IPC_CHANNEL_RESPONSE_DOMAIN,
  IPC_CHANNEL_SAFE_ERROR_CODES,
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
  _internals: objectFreeze({
    assertClosedObject,
    assertSelectedCdhash,
    assertDigest,
    assertNonce,
    assertSafeErrorCode,
    assertTimestamp,
    assertToken,
    assertUint,
    contractError,
    deepFreeze,
    hashClosed,
  }),
});
