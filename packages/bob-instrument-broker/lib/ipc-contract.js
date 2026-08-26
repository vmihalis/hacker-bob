"use strict";

const crypto = require("node:crypto");

const {
  canonicalJson,
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const IPC_PROTOCOL_VERSION = 1;
const IPC_REQUEST_DOMAIN = "hacker-bob/instrument-broker-ipc-request/v1";
const IPC_RESPONSE_DOMAIN = "hacker-bob/instrument-broker-ipc-response/v1";
const IPC_PEER_CREDENTIAL_EVIDENCE_DOMAIN =
  "hacker-bob/instrument-broker-ipc-peer-credential-evidence/v1";
const IPC_REQUEST_KEY_USAGE = "instrument_broker_ipc_request_signing";
const IPC_RESPONSE_KEY_USAGE = "instrument_broker_ipc_response_signing";
const IPC_PEER_CREDENTIAL_EVIDENCE_KEY_USAGE =
  "instrument_broker_ipc_native_peer_credential_attestation";
const IPC_MAX_FRAME_BYTES = 65_536;
const IPC_MAX_MESSAGES_PER_CONNECTION = 1;
const IPC_MAX_REQUEST_LIFETIME_MS = 30_000;
const IPC_MAX_CLOCK_SKEW_MS = 5_000;
const IPC_MAX_CONNECTION_TIMEOUT_MS = 10_000;
const IPC_MAX_JSON_DEPTH = 16;
const IPC_MAX_JSON_NODES = 2_048;
const IPC_MAX_STRING_BYTES = 16_384;

const REQUEST_PAYLOAD_FIELDS = Object.freeze([
  "version",
  "request_id",
  "ipc_peer_principal_id",
  "execution_principal_id",
  "provider_id",
  "provider_descriptor_digest",
  "operation_id",
  "operation_payload_digest",
  "operation_payload",
  "nonce",
  "sequence",
  "issued_at",
  "deadline",
]);
const PEER_CREDENTIAL_EVIDENCE_PAYLOAD_FIELDS = Object.freeze([
  "version",
  "resolver_id",
  "socket_binding_nonce",
  "credential_source",
  "platform",
  "native_binding_implementation_digest",
  "peer_uid",
  "peer_gid",
  "peer_pid",
  "ipc_peer_principal_id",
  "execution_principal_id",
  "request_key_id",
  "request_public_key_digest",
  "evidence_epoch",
]);
const RESPONSE_PAYLOAD_FIELDS = Object.freeze([
  "version",
  "request_digest",
  "request_id",
  "request_nonce",
  "request_sequence",
  "server_principal_id",
  "status",
  "error_code",
  "operation_result_digest",
  "operation_result",
  "responded_at",
]);
const AUTHENTICATION_FIELDS = Object.freeze([
  "scheme",
  "key_usage",
  "key_id",
  "public_key_digest",
  "signed_payload_digest",
  "signature",
]);
const IPC_RESPONSE_STATUS_VALUES = Object.freeze([
  "completed",
  "rejected",
  "ambiguous",
]);
const IPC_SAFE_ERROR_CODES = Object.freeze([
  "dispatch_rejected",
  "dispatch_unavailable",
  "dispatch_timeout",
  "operation_failed",
  "operation_inconclusive",
  "operation_refused",
  "operation_stopped",
]);

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = Object.keys(value).filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertToken(value, label, prefix = null) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)) {
    throw new Error(`${label} must be a bounded opaque token`);
  }
  if (prefix != null && !value.startsWith(`${prefix}:`)) {
    throw new Error(`${label} must use the ${prefix}: namespace`);
  }
  return value;
}

function assertInteger(value, label, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function assertCanonicalTimestamp(value, label) {
  if (typeof value !== "string") throw new Error(`${label} must be a canonical timestamp`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`${label} must be a canonical ISO-8601 UTC timestamp`);
  }
  return value;
}

function assertNonce(value, label) {
  if (typeof value !== "string" || !NONCE_PATTERN.test(value)) {
    throw new Error(`${label} must be a canonical 128-bit-or-stronger base64url nonce`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < 16 || bytes.toString("base64url") !== value) {
    throw new Error(`${label} must use canonical 128-bit-or-stronger base64url encoding`);
  }
  return value;
}

function assertCanonicalSignature(value, label) {
  if (typeof value !== "string" || !SIGNATURE_PATTERN.test(value)) {
    throw new Error(`${label} must be a canonical Ed25519 base64url signature`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    throw new Error(`${label} must use canonical Ed25519 base64url encoding`);
  }
  return value;
}

function cloneAndValidateOpaqueJson(value, label) {
  let nodes = 0;
  function visit(candidate, depth, path) {
    nodes += 1;
    if (nodes > IPC_MAX_JSON_NODES) throw new Error(`${label} exceeds the JSON node limit`);
    if (depth > IPC_MAX_JSON_DEPTH) throw new Error(`${label} exceeds the JSON depth limit`);
    if (candidate === null || typeof candidate === "boolean") return candidate;
    if (typeof candidate === "number") {
      if (!Number.isFinite(candidate) || Math.abs(candidate) > Number.MAX_SAFE_INTEGER
          || Object.is(candidate, -0)) {
        throw new Error(`${path} must be a finite interoperable JSON number`);
      }
      return candidate;
    }
    if (typeof candidate === "string") {
      if (Buffer.byteLength(candidate, "utf8") > IPC_MAX_STRING_BYTES) {
        throw new Error(`${path} exceeds the string byte limit`);
      }
      return candidate;
    }
    if (Array.isArray(candidate)) {
      if (candidate.length > IPC_MAX_JSON_NODES) throw new Error(`${path} is too large`);
      return candidate.map((entry, index) => visit(entry, depth + 1, `${path}[${index}]`));
    }
    if (!isPlainObject(candidate)) throw new Error(`${path} must contain JSON values only`);
    const keys = Object.keys(candidate);
    if (Object.getOwnPropertySymbols(candidate).length > 0 || keys.length > 256) {
      throw new Error(`${path} has too many or unsupported fields`);
    }
    const result = {};
    for (const key of keys.sort()) {
      if (Buffer.byteLength(key, "utf8") > 256) throw new Error(`${path} has an oversized key`);
      const entry = candidate[key];
      if (entry === undefined || typeof entry === "function" || typeof entry === "symbol"
          || typeof entry === "bigint") {
        throw new Error(`${path}.${key} must be a JSON value`);
      }
      Object.defineProperty(result, key, {
        value: visit(entry, depth + 1, `${path}.${key}`),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return result;
  }
  return deepFreeze(visit(value, 0, label));
}

function assertEd25519Key(key, kind, label) {
  if (!(key instanceof crypto.KeyObject) || key.type !== kind || key.asymmetricKeyType !== "ed25519") {
    throw new Error(`${label} must be an Ed25519 ${kind} KeyObject`);
  }
  return key;
}

function publicKeyDigest(key) {
  const publicKey = key.type === "private" ? crypto.createPublicKey(key) : key;
  assertEd25519Key(publicKey, "public", "public_key");
  return crypto.createHash("sha256").update(
    publicKey.export({ type: "spki", format: "der" }),
  ).digest("hex");
}

function normalizeAuthentication(input, keyUsage, payloadDigest, label) {
  assertClosedObject(input, label, AUTHENTICATION_FIELDS);
  if (input.scheme !== "ed25519") throw new Error(`${label}.scheme must be ed25519`);
  if (input.key_usage !== keyUsage) throw new Error(`${label}.key_usage is not valid for this domain`);
  const normalized = {
    scheme: "ed25519",
    key_usage: keyUsage,
    key_id: assertToken(input.key_id, `${label}.key_id`, "ipc-key"),
    public_key_digest: assertDigest(input.public_key_digest, `${label}.public_key_digest`),
    signed_payload_digest: assertDigest(input.signed_payload_digest, `${label}.signed_payload_digest`),
    signature: assertCanonicalSignature(input.signature, `${label}.signature`),
  };
  if (normalized.signed_payload_digest !== payloadDigest) {
    throw new Error(`${label}.signed_payload_digest does not bind the canonical payload`);
  }
  return deepFreeze(normalized);
}

function normalizeIpcDispatchRequestPayload(input, label = "ipc_request.payload") {
  assertClosedObject(input, label, REQUEST_PAYLOAD_FIELDS);
  if (input.version !== IPC_PROTOCOL_VERSION) throw new Error(`${label}.version must be 1`);
  const operationPayload = cloneAndValidateOpaqueJson(
    input.operation_payload,
    `${label}.operation_payload`,
  );
  const normalized = {
    version: IPC_PROTOCOL_VERSION,
    request_id: assertToken(input.request_id, `${label}.request_id`, "ipc-request"),
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
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    operation_id: assertIdentifier(input.operation_id, `${label}.operation_id`),
    operation_payload_digest: assertDigest(
      input.operation_payload_digest,
      `${label}.operation_payload_digest`,
    ),
    operation_payload: operationPayload,
    nonce: assertNonce(input.nonce, `${label}.nonce`),
    sequence: assertInteger(input.sequence, `${label}.sequence`, 1),
    issued_at: assertCanonicalTimestamp(input.issued_at, `${label}.issued_at`),
    deadline: assertCanonicalTimestamp(input.deadline, `${label}.deadline`),
  };
  if (normalized.operation_payload_digest !== hashCanonicalJson(operationPayload)) {
    throw new Error(`${label}.operation_payload_digest does not bind operation_payload`);
  }
  const lifetime = Date.parse(normalized.deadline) - Date.parse(normalized.issued_at);
  if (lifetime <= 0 || lifetime > IPC_MAX_REQUEST_LIFETIME_MS) {
    throw new Error(`${label} lifetime must be positive and no greater than ${IPC_MAX_REQUEST_LIFETIME_MS}ms`);
  }
  return deepFreeze(normalized);
}

function signatureInputDigest(domain, kind, payload, authenticationBasis) {
  return hashCanonicalJson({
    domain,
    version: IPC_PROTOCOL_VERSION,
    kind,
    payload,
    authentication: authenticationBasis,
  });
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

function normalizeSignedIpcDispatchRequest(input, label = "ipc_request") {
  assertClosedObject(input, label, [
    "version", "kind", "domain", "payload", "authentication", "request_digest",
  ]);
  if (input.version !== IPC_PROTOCOL_VERSION) throw new Error(`${label}.version must be 1`);
  if (input.kind !== "instrument_dispatch_request") {
    throw new Error(`${label}.kind must be instrument_dispatch_request`);
  }
  if (input.domain !== IPC_REQUEST_DOMAIN) throw new Error(`${label}.domain is invalid`);
  const payload = normalizeIpcDispatchRequestPayload(input.payload, `${label}.payload`);
  const payloadDigest = hashCanonicalJson(payload);
  const authentication = normalizeAuthentication(
    input.authentication,
    IPC_REQUEST_KEY_USAGE,
    payloadDigest,
    `${label}.authentication`,
  );
  const envelopeBasis = {
    version: IPC_PROTOCOL_VERSION,
    kind: "instrument_dispatch_request",
    domain: IPC_REQUEST_DOMAIN,
    payload,
    authentication,
  };
  const requestDigest = hashCanonicalJson(envelopeBasis);
  if (assertDigest(input.request_digest, `${label}.request_digest`) !== requestDigest) {
    throw new Error(`${label}.request_digest does not bind the signed request envelope`);
  }
  return deepFreeze({ ...envelopeBasis, request_digest: requestDigest });
}

function signIpcDispatchRequest(payloadInput, signerInput) {
  const payload = normalizeIpcDispatchRequestPayload(payloadInput);
  assertClosedObject(signerInput, "ipc_request_signer", [
    "key_id", "public_key_digest", "private_key",
  ]);
  const privateKey = assertEd25519Key(
    signerInput.private_key,
    "private",
    "ipc_request_signer.private_key",
  );
  const derivedDigest = publicKeyDigest(privateKey);
  if (assertDigest(
    signerInput.public_key_digest,
    "ipc_request_signer.public_key_digest",
  ) !== derivedDigest) {
    throw new Error("ipc_request_signer.public_key_digest does not match private_key");
  }
  const basis = deepFreeze({
    scheme: "ed25519",
    key_usage: IPC_REQUEST_KEY_USAGE,
    key_id: assertToken(signerInput.key_id, "ipc_request_signer.key_id", "ipc-key"),
    public_key_digest: derivedDigest,
    signed_payload_digest: hashCanonicalJson(payload),
  });
  const inputDigest = signatureInputDigest(
    IPC_REQUEST_DOMAIN,
    "instrument_dispatch_request",
    payload,
    basis,
  );
  const authentication = deepFreeze({
    ...basis,
    signature: crypto.sign(null, Buffer.from(inputDigest, "hex"), privateKey).toString("base64url"),
  });
  const envelopeBasis = deepFreeze({
    version: IPC_PROTOCOL_VERSION,
    kind: "instrument_dispatch_request",
    domain: IPC_REQUEST_DOMAIN,
    payload,
    authentication,
  });
  return normalizeSignedIpcDispatchRequest({
    ...envelopeBasis,
    request_digest: hashCanonicalJson(envelopeBasis),
  });
}

function verifyIpcDispatchRequestSignature(requestInput, publicKeyInput) {
  const request = normalizeSignedIpcDispatchRequest(requestInput);
  const publicKey = assertEd25519Key(publicKeyInput, "public", "ipc_request_public_key");
  if (publicKeyDigest(publicKey) !== request.authentication.public_key_digest) return false;
  const inputDigest = signatureInputDigest(
    IPC_REQUEST_DOMAIN,
    request.kind,
    request.payload,
    authenticationBasis(request.authentication),
  );
  return crypto.verify(
    null,
    Buffer.from(inputDigest, "hex"),
    publicKey,
    Buffer.from(request.authentication.signature, "base64url"),
  );
}

function normalizeIpcPeerCredentialEvidencePayload(
  input,
  label = "ipc_peer_credential_evidence.payload",
) {
  assertClosedObject(input, label, PEER_CREDENTIAL_EVIDENCE_PAYLOAD_FIELDS);
  if (input.version !== IPC_PROTOCOL_VERSION) throw new Error(`${label}.version must be 1`);
  if (input.credential_source !== "native_os_socket") {
    throw new Error(`${label}.credential_source must be native_os_socket`);
  }
  return deepFreeze({
    version: IPC_PROTOCOL_VERSION,
    resolver_id: assertIdentifier(input.resolver_id, `${label}.resolver_id`),
    socket_binding_nonce: assertNonce(
      input.socket_binding_nonce,
      `${label}.socket_binding_nonce`,
    ),
    credential_source: "native_os_socket",
    platform: assertIdentifier(input.platform, `${label}.platform`),
    native_binding_implementation_digest: assertDigest(
      input.native_binding_implementation_digest,
      `${label}.native_binding_implementation_digest`,
    ),
    peer_uid: assertInteger(input.peer_uid, `${label}.peer_uid`, 0, 2 ** 32 - 2),
    peer_gid: assertInteger(input.peer_gid, `${label}.peer_gid`, 0, 2 ** 32 - 2),
    peer_pid: assertInteger(input.peer_pid, `${label}.peer_pid`, 1, 2 ** 31 - 1),
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
    request_public_key_digest: assertDigest(
      input.request_public_key_digest,
      `${label}.request_public_key_digest`,
    ),
    evidence_epoch: assertInteger(input.evidence_epoch, `${label}.evidence_epoch`, 1),
  });
}

function normalizeSignedIpcPeerCredentialEvidence(
  input,
  label = "ipc_peer_credential_evidence",
) {
  assertClosedObject(input, label, [
    "version", "kind", "domain", "payload", "authentication", "evidence_digest",
  ]);
  if (input.version !== IPC_PROTOCOL_VERSION) throw new Error(`${label}.version must be 1`);
  if (input.kind !== "native_peer_credential_evidence") {
    throw new Error(`${label}.kind must be native_peer_credential_evidence`);
  }
  if (input.domain !== IPC_PEER_CREDENTIAL_EVIDENCE_DOMAIN) {
    throw new Error(`${label}.domain is invalid`);
  }
  const payload = normalizeIpcPeerCredentialEvidencePayload(input.payload, `${label}.payload`);
  const authentication = normalizeAuthentication(
    input.authentication,
    IPC_PEER_CREDENTIAL_EVIDENCE_KEY_USAGE,
    hashCanonicalJson(payload),
    `${label}.authentication`,
  );
  const envelopeBasis = {
    version: IPC_PROTOCOL_VERSION,
    kind: "native_peer_credential_evidence",
    domain: IPC_PEER_CREDENTIAL_EVIDENCE_DOMAIN,
    payload,
    authentication,
  };
  const evidenceDigest = hashCanonicalJson(envelopeBasis);
  if (assertDigest(input.evidence_digest, `${label}.evidence_digest`) !== evidenceDigest) {
    throw new Error(`${label}.evidence_digest does not bind the signed evidence envelope`);
  }
  return deepFreeze({ ...envelopeBasis, evidence_digest: evidenceDigest });
}

function signIpcPeerCredentialEvidence(payloadInput, signerInput) {
  const payload = normalizeIpcPeerCredentialEvidencePayload(payloadInput);
  assertClosedObject(signerInput, "ipc_peer_credential_evidence_signer", [
    "key_id", "public_key_digest", "private_key",
  ]);
  const privateKey = assertEd25519Key(
    signerInput.private_key,
    "private",
    "ipc_peer_credential_evidence_signer.private_key",
  );
  const derivedDigest = publicKeyDigest(privateKey);
  if (assertDigest(
    signerInput.public_key_digest,
    "ipc_peer_credential_evidence_signer.public_key_digest",
  ) !== derivedDigest) {
    throw new Error("ipc_peer_credential_evidence_signer.public_key_digest does not match private_key");
  }
  const basis = deepFreeze({
    scheme: "ed25519",
    key_usage: IPC_PEER_CREDENTIAL_EVIDENCE_KEY_USAGE,
    key_id: assertToken(
      signerInput.key_id,
      "ipc_peer_credential_evidence_signer.key_id",
      "ipc-key",
    ),
    public_key_digest: derivedDigest,
    signed_payload_digest: hashCanonicalJson(payload),
  });
  const inputDigest = signatureInputDigest(
    IPC_PEER_CREDENTIAL_EVIDENCE_DOMAIN,
    "native_peer_credential_evidence",
    payload,
    basis,
  );
  const authentication = deepFreeze({
    ...basis,
    signature: crypto.sign(null, Buffer.from(inputDigest, "hex"), privateKey).toString("base64url"),
  });
  const envelopeBasis = deepFreeze({
    version: IPC_PROTOCOL_VERSION,
    kind: "native_peer_credential_evidence",
    domain: IPC_PEER_CREDENTIAL_EVIDENCE_DOMAIN,
    payload,
    authentication,
  });
  return normalizeSignedIpcPeerCredentialEvidence({
    ...envelopeBasis,
    evidence_digest: hashCanonicalJson(envelopeBasis),
  });
}

function verifyIpcPeerCredentialEvidenceSignature(evidenceInput, publicKeyInput) {
  const evidence = normalizeSignedIpcPeerCredentialEvidence(evidenceInput);
  const publicKey = assertEd25519Key(
    publicKeyInput,
    "public",
    "ipc_peer_credential_evidence_public_key",
  );
  if (publicKeyDigest(publicKey) !== evidence.authentication.public_key_digest) return false;
  const inputDigest = signatureInputDigest(
    IPC_PEER_CREDENTIAL_EVIDENCE_DOMAIN,
    evidence.kind,
    evidence.payload,
    authenticationBasis(evidence.authentication),
  );
  return crypto.verify(
    null,
    Buffer.from(inputDigest, "hex"),
    publicKey,
    Buffer.from(evidence.authentication.signature, "base64url"),
  );
}

function normalizeIpcDispatchResponsePayload(input, label = "ipc_response.payload") {
  assertClosedObject(input, label, RESPONSE_PAYLOAD_FIELDS);
  if (input.version !== IPC_PROTOCOL_VERSION) throw new Error(`${label}.version must be 1`);
  if (!IPC_RESPONSE_STATUS_VALUES.includes(input.status)) {
    throw new Error(`${label}.status is invalid`);
  }
  const operationResult = input.operation_result == null
    ? null
    : cloneAndValidateOpaqueJson(input.operation_result, `${label}.operation_result`);
  const normalized = {
    version: IPC_PROTOCOL_VERSION,
    request_digest: assertDigest(input.request_digest, `${label}.request_digest`),
    request_id: assertToken(input.request_id, `${label}.request_id`, "ipc-request"),
    request_nonce: assertNonce(input.request_nonce, `${label}.request_nonce`),
    request_sequence: assertInteger(input.request_sequence, `${label}.request_sequence`, 1),
    server_principal_id: assertToken(
      input.server_principal_id,
      `${label}.server_principal_id`,
      "principal",
    ),
    status: input.status,
    error_code: input.error_code,
    operation_result_digest: assertDigest(
      input.operation_result_digest,
      `${label}.operation_result_digest`,
    ),
    operation_result: operationResult,
    responded_at: assertCanonicalTimestamp(input.responded_at, `${label}.responded_at`),
  };
  if (normalized.status === "completed") {
    if (normalized.error_code !== null) throw new Error(`${label}.error_code must be null when completed`);
  } else if (!IPC_SAFE_ERROR_CODES.includes(normalized.error_code)) {
    throw new Error(`${label}.error_code is not a safe IPC error code`);
  }
  if (normalized.operation_result_digest !== hashCanonicalJson(operationResult)) {
    throw new Error(`${label}.operation_result_digest does not bind operation_result`);
  }
  return deepFreeze(normalized);
}

function normalizeSignedIpcDispatchResponse(input, label = "ipc_response") {
  assertClosedObject(input, label, [
    "version", "kind", "domain", "payload", "authentication", "response_digest",
  ]);
  if (input.version !== IPC_PROTOCOL_VERSION) throw new Error(`${label}.version must be 1`);
  if (input.kind !== "instrument_dispatch_response") {
    throw new Error(`${label}.kind must be instrument_dispatch_response`);
  }
  if (input.domain !== IPC_RESPONSE_DOMAIN) throw new Error(`${label}.domain is invalid`);
  const payload = normalizeIpcDispatchResponsePayload(input.payload, `${label}.payload`);
  const authentication = normalizeAuthentication(
    input.authentication,
    IPC_RESPONSE_KEY_USAGE,
    hashCanonicalJson(payload),
    `${label}.authentication`,
  );
  const envelopeBasis = {
    version: IPC_PROTOCOL_VERSION,
    kind: "instrument_dispatch_response",
    domain: IPC_RESPONSE_DOMAIN,
    payload,
    authentication,
  };
  const responseDigest = hashCanonicalJson(envelopeBasis);
  if (assertDigest(input.response_digest, `${label}.response_digest`) !== responseDigest) {
    throw new Error(`${label}.response_digest does not bind the signed response envelope`);
  }
  return deepFreeze({ ...envelopeBasis, response_digest: responseDigest });
}

function signIpcDispatchResponse(payloadInput, signerInput) {
  const payload = normalizeIpcDispatchResponsePayload(payloadInput);
  assertClosedObject(signerInput, "ipc_response_signer", [
    "key_id", "public_key_digest", "private_key",
  ]);
  const privateKey = assertEd25519Key(
    signerInput.private_key,
    "private",
    "ipc_response_signer.private_key",
  );
  const derivedDigest = publicKeyDigest(privateKey);
  if (assertDigest(
    signerInput.public_key_digest,
    "ipc_response_signer.public_key_digest",
  ) !== derivedDigest) {
    throw new Error("ipc_response_signer.public_key_digest does not match private_key");
  }
  const basis = deepFreeze({
    scheme: "ed25519",
    key_usage: IPC_RESPONSE_KEY_USAGE,
    key_id: assertToken(signerInput.key_id, "ipc_response_signer.key_id", "ipc-key"),
    public_key_digest: derivedDigest,
    signed_payload_digest: hashCanonicalJson(payload),
  });
  const inputDigest = signatureInputDigest(
    IPC_RESPONSE_DOMAIN,
    "instrument_dispatch_response",
    payload,
    basis,
  );
  const authentication = deepFreeze({
    ...basis,
    signature: crypto.sign(null, Buffer.from(inputDigest, "hex"), privateKey).toString("base64url"),
  });
  const envelopeBasis = deepFreeze({
    version: IPC_PROTOCOL_VERSION,
    kind: "instrument_dispatch_response",
    domain: IPC_RESPONSE_DOMAIN,
    payload,
    authentication,
  });
  return normalizeSignedIpcDispatchResponse({
    ...envelopeBasis,
    response_digest: hashCanonicalJson(envelopeBasis),
  });
}

function verifyIpcDispatchResponseSignature(responseInput, publicKeyInput) {
  const response = normalizeSignedIpcDispatchResponse(responseInput);
  const publicKey = assertEd25519Key(publicKeyInput, "public", "ipc_response_public_key");
  if (publicKeyDigest(publicKey) !== response.authentication.public_key_digest) return false;
  const inputDigest = signatureInputDigest(
    IPC_RESPONSE_DOMAIN,
    response.kind,
    response.payload,
    authenticationBasis(response.authentication),
  );
  return crypto.verify(
    null,
    Buffer.from(inputDigest, "hex"),
    publicKey,
    Buffer.from(response.authentication.signature, "base64url"),
  );
}

function encodeIpcFrame(envelope) {
  const body = Buffer.from(canonicalJson(envelope), "utf8");
  if (body.length < 1 || body.length > IPC_MAX_FRAME_BYTES) {
    throw new Error("IPC frame exceeds the fixed frame limit");
  }
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(body.length, 0);
  return Buffer.concat([header, body]);
}

function decodeCanonicalIpcFrameBody(bodyInput) {
  if (!Buffer.isBuffer(bodyInput) || bodyInput.length < 1 || bodyInput.length > IPC_MAX_FRAME_BYTES) {
    throw new Error("IPC frame body is outside the fixed frame limit");
  }
  const text = bodyInput.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bodyInput)) throw new Error("IPC frame is not valid UTF-8");
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("IPC frame is not valid JSON");
  }
  if (canonicalJson(parsed) !== text) throw new Error("IPC frame is not canonical JSON");
  return parsed;
}

function projectIpcDispatchRequest(requestInput) {
  const request = normalizeSignedIpcDispatchRequest(requestInput);
  return deepFreeze({
    version: IPC_PROTOCOL_VERSION,
    request_id: request.payload.request_id,
    request_digest: request.request_digest,
    ipc_peer_principal_id: request.payload.ipc_peer_principal_id,
    execution_principal_id: request.payload.execution_principal_id,
    provider_id: request.payload.provider_id,
    provider_descriptor_digest: request.payload.provider_descriptor_digest,
    operation_id: request.payload.operation_id,
    operation_payload_digest: request.payload.operation_payload_digest,
    sequence: request.payload.sequence,
    deadline: request.payload.deadline,
  });
}

function projectIpcDispatchResponse(responseInput) {
  const response = normalizeSignedIpcDispatchResponse(responseInput);
  return deepFreeze({
    version: IPC_PROTOCOL_VERSION,
    response_digest: response.response_digest,
    request_digest: response.payload.request_digest,
    request_id: response.payload.request_id,
    request_sequence: response.payload.request_sequence,
    server_principal_id: response.payload.server_principal_id,
    status: response.payload.status,
    error_code: response.payload.error_code,
    operation_result_digest: response.payload.operation_result_digest,
    responded_at: response.payload.responded_at,
  });
}

module.exports = {
  IPC_MAX_CLOCK_SKEW_MS,
  IPC_MAX_CONNECTION_TIMEOUT_MS,
  IPC_MAX_FRAME_BYTES,
  IPC_MAX_MESSAGES_PER_CONNECTION,
  IPC_MAX_REQUEST_LIFETIME_MS,
  IPC_PROTOCOL_VERSION,
  IPC_PEER_CREDENTIAL_EVIDENCE_DOMAIN,
  IPC_PEER_CREDENTIAL_EVIDENCE_KEY_USAGE,
  IPC_REQUEST_DOMAIN,
  IPC_REQUEST_KEY_USAGE,
  IPC_RESPONSE_DOMAIN,
  IPC_RESPONSE_KEY_USAGE,
  IPC_RESPONSE_STATUS_VALUES,
  IPC_SAFE_ERROR_CODES,
  decodeCanonicalIpcFrameBody,
  encodeIpcFrame,
  normalizeIpcDispatchRequestPayload,
  normalizeIpcDispatchResponsePayload,
  normalizeIpcPeerCredentialEvidencePayload,
  normalizeSignedIpcPeerCredentialEvidence,
  normalizeSignedIpcDispatchRequest,
  normalizeSignedIpcDispatchResponse,
  projectIpcDispatchRequest,
  projectIpcDispatchResponse,
  publicKeyDigest,
  signIpcDispatchRequest,
  signIpcDispatchResponse,
  signIpcPeerCredentialEvidence,
  verifyIpcDispatchRequestSignature,
  verifyIpcDispatchResponseSignature,
  verifyIpcPeerCredentialEvidenceSignature,
  _internals: Object.freeze({
    assertClosedObject,
    assertDigest,
    assertEd25519Key,
    assertIdentifier,
    assertInteger,
    assertToken,
    deepFreeze,
  }),
};
