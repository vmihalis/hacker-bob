"use strict";

// Production-shaped Chameleon availability-evidence resolver.
//
// This module does not enumerate or open hardware and never grants execution
// authority. It verifies independently signed, short-lived availability
// evidence against a separately signed current trust statement, samples Bob's
// restart-durable trusted clock, and claims every accepted evidence identity in
// Bob's signed monotonic owner before returning it to the semantic manifest.
// The current fixed trusted-clock adapter remains non-production until its
// native restart-stable source is installed, so this backend can qualify a
// runtime variant without claiming release or HIL readiness.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const {
  assertPhysicalMonotonicOwnerPort,
  assertProductionPhysicalMonotonicOwnerPort,
  compareAndSetPhysicalMonotonicOwnerState,
  readPhysicalMonotonicOwnerState,
} = require("../../../mcp/domains/physical/physical-monotonic-owner.js");
const {
  assertProductionPhysicalTrustedClockPort,
  assertRestartDurablePhysicalTrustedClockPort,
  assertRestartDurablePhysicalTrustedClockSample,
  sampleRestartDurablePhysicalTrustedClock,
} = require("../../../mcp/domains/physical/physical-trusted-clock-store.js");
const {
  canonicalJson,
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const CREATE_PUBLIC_KEY = crypto.createPublicKey.bind(crypto);
const VERIFY_SIGNATURE = crypto.verify.bind(crypto);
const CREATE_HASH = crypto.createHash.bind(crypto);

const CHAMELEON_AVAILABILITY_BACKEND_VERSION = 2;
const CHAMELEON_AVAILABILITY_BACKEND_MODE =
  "signed_current_evidence_atomic_durable_replay";
const CHAMELEON_AVAILABILITY_OWNER_CONTEXT_DOMAIN =
  "hacker-bob/chameleon-availability-evidence-head/v2";
const CHAMELEON_AVAILABILITY_TRUST_DOMAIN =
  "hacker-bob/chameleon-availability-current-trust/v2";
const CHAMELEON_AVAILABILITY_TRUST_SIGNING_DOMAIN =
  "hacker-bob/chameleon-availability-current-trust-signature/v2";
const CHAMELEON_AVAILABILITY_EVIDENCE_DOMAIN =
  "hacker-bob/chameleon-availability-evidence/v2";
const CHAMELEON_AVAILABILITY_EVIDENCE_SIGNING_DOMAIN =
  "hacker-bob/chameleon-availability-evidence-signature/v2";
const CHAMELEON_AVAILABILITY_EVIDENCE_IDENTITY_DOMAIN =
  "hacker-bob/chameleon-availability-evidence-identity/v2";
const CHAMELEON_AVAILABILITY_REPLAY_CLAIM_DOMAIN =
  "hacker-bob/chameleon-availability-replay-claim/v2";
const CHAMELEON_AVAILABILITY_REPLAY_STATE_DOMAIN =
  "hacker-bob/chameleon-availability-replay-state/v2";

const HASH_RE = /^[a-f0-9]{64}$/u;
const IDENTIFIER_RE = /^[a-z][a-z0-9._-]{0,127}$/u;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const EVIDENCE_REF_RE = /^bob-chameleon-availability:v2:sha256:([a-f0-9]{64})$/u;
const SIGNATURE_RE = /^[A-Za-z0-9_-]{86}$/u;
const MAX_PASSIVE_DEPTH = 32;
const MAX_PASSIVE_NODES = 32_768;
const MAX_ARRAY_LENGTH = 4_096;
const MAX_OBJECT_KEYS = 256;
const MAX_STRING_LENGTH = 16_384;
const MAX_REPLAY_CLAIMS = 4_096;
const MAX_CAS_ATTEMPTS = 4;
const MAX_TRUST_LIFETIME_MS = 24 * 60 * 60 * 1_000;
const MAX_EVIDENCE_LIFETIME_MS = 15 * 60 * 1_000;
const MAX_WALL_MONOTONIC_SKEW_FLOOR_MS = 1_000;

const BACKEND_PORTS = new WeakSet();
const BACKEND_PORT_STATE = new WeakMap();
const BACKEND_PROJECTIONS = new WeakSet();

const REQUEST_FIELDS = Object.freeze([
  "version",
  "provider_id",
  "evidence_ref",
  "target_domain",
  "session_nucleus_hash",
  "semantic_manifest_digest",
  "source_profile_digest",
  "codec_profile_digest",
  "assurance_profile_registry_digest",
  "dependency_proof_registry_digest",
  "inventory_projection_digest",
  "device_identity_digest",
  "custody_id",
  "custody_projection_digest",
  "session_id",
  "authority_id",
  "authority_epoch",
  "revocation_generation",
  "authority_resolution_digest",
]);

const EVIDENCE_PAYLOAD_FIELDS = Object.freeze([
  ...REQUEST_FIELDS,
  "evidence_identity_digest",
  "evidence_owner_principal",
  "evidence_artifact_digest",
  "evidence_trust_epoch",
  "issuer_key_id",
  "issuer_public_key_digest",
  "issuer_revocation_generation",
  "authority_trust_generation",
  "trust_root_epoch",
  "evidence_sequence",
  "nonce",
  "observed_at",
  "expires_at",
  "clock_id",
  "monotonic_epoch_id",
  "observed_monotonic_ms",
  "expires_monotonic_ms",
  "reported_command_ids",
  "assurance_claims",
  "dependency_proofs",
  "variant_qualifications",
]);

function backendError(code, message, cause = null) {
  const error = new Error(`${code}: ${message}`);
  error.code = code;
  if (cause != null) Object.defineProperty(error, "cause", { value: cause });
  return error;
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactRecord(input, label, fields) {
  if (!isPlainObject(input)) {
    throw backendError("chameleon_availability_contract_invalid", `${label} must be an exact plain data object`);
  }
  const keys = Reflect.ownKeys(input);
  const expected = [...fields].sort();
  const actual = [...keys].sort();
  if (keys.some((key) => typeof key !== "string")
      || actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    throw backendError("chameleon_availability_contract_invalid", `${label} fields are not exact`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const output = {};
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw backendError(
        "chameleon_availability_contract_invalid",
        `${label}.${field} must be an enumerable data property`,
      );
    }
    output[field] = descriptor.value;
  }
  return output;
}

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function copyPassiveJson(input, label, depth = 0, budget = { count: 0 }) {
  budget.count += 1;
  if (budget.count > MAX_PASSIVE_NODES || depth > MAX_PASSIVE_DEPTH) {
    throw backendError("chameleon_availability_contract_invalid", `${label} exceeds passive-data limits`);
  }
  if (input === null || typeof input === "boolean") return input;
  if (typeof input === "string") {
    if (input.length > MAX_STRING_LENGTH) {
      throw backendError("chameleon_availability_contract_invalid", `${label} string is too long`);
    }
    return input;
  }
  if (typeof input === "number") {
    if (!Number.isFinite(input) || !Number.isSafeInteger(input)) {
      throw backendError("chameleon_availability_contract_invalid", `${label} must use safe integer JSON numbers`);
    }
    return input;
  }
  if (utilTypes.isProxy(input)) {
    throw backendError("chameleon_availability_contract_invalid", `${label} cannot be a proxy`);
  }
  if (Array.isArray(input)) {
    if (input.length > MAX_ARRAY_LENGTH) {
      throw backendError("chameleon_availability_contract_invalid", `${label} array is too large`);
    }
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const extra = Reflect.ownKeys(descriptors).filter((key) => (
      key !== "length" && (typeof key !== "string" || !/^\d+$/u.test(key))
    ));
    if (extra.length > 0) {
      throw backendError("chameleon_availability_contract_invalid", `${label} array has extra fields`);
    }
    const output = [];
    for (let index = 0; index < input.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || descriptor.enumerable !== true
          || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
        throw backendError("chameleon_availability_contract_invalid", `${label} must be dense data`);
      }
      output.push(copyPassiveJson(descriptor.value, `${label}[${index}]`, depth + 1, budget));
    }
    return output;
  }
  if (!isPlainObject(input)) {
    throw backendError("chameleon_availability_contract_invalid", `${label} must be passive JSON data`);
  }
  const keys = Reflect.ownKeys(input);
  if (keys.length > MAX_OBJECT_KEYS || keys.some((key) => typeof key !== "string")) {
    throw backendError("chameleon_availability_contract_invalid", `${label} object keys are invalid`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const output = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw backendError(
        "chameleon_availability_contract_invalid",
        `${label}.${key} must be an enumerable data property`,
      );
    }
    output[key] = copyPassiveJson(descriptor.value, `${label}.${key}`, depth + 1, budget);
  }
  return output;
}

function digest(value, label) {
  if (typeof value !== "string" || !HASH_RE.test(value)) {
    throw backendError("chameleon_availability_contract_invalid", `${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function identifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_RE.test(value)) {
    throw backendError("chameleon_availability_contract_invalid", `${label} must be a lowercase identifier`);
  }
  return value;
}

function safeDomain(value, label) {
  if (typeof value !== "string" || !DOMAIN_RE.test(value)) {
    throw backendError("chameleon_availability_contract_invalid", `${label} must be a canonical DNS domain`);
  }
  return value;
}

function token(value, label, prefix = null) {
  if (typeof value !== "string" || !TOKEN_RE.test(value)
      || (prefix != null && (!value.startsWith(`${prefix}:`) || value.length === prefix.length + 1))) {
    throw backendError(
      "chameleon_availability_contract_invalid",
      `${label} must be a bounded ${prefix || "opaque"} token`,
    );
  }
  return value;
}

function integer(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw backendError(
      "chameleon_availability_contract_invalid",
      `${label} must be a safe integer greater than or equal to ${minimum}`,
    );
  }
  return value;
}

function boolean(value, label) {
  if (typeof value !== "boolean") {
    throw backendError("chameleon_availability_contract_invalid", `${label} must be a boolean`);
  }
  return value;
}

function timestamp(value, label) {
  if (typeof value !== "string") {
    throw backendError("chameleon_availability_contract_invalid", `${label} must be a canonical timestamp`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw backendError("chameleon_availability_contract_invalid", `${label} must be canonical ISO-8601 UTC`);
  }
  return value;
}

function canonicalSignature(value, label) {
  if (typeof value !== "string" || !SIGNATURE_RE.test(value)) {
    throw backendError("chameleon_availability_signature_invalid", `${label} must be canonical Ed25519 base64url`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    throw backendError("chameleon_availability_signature_invalid", `${label} must be canonical Ed25519 base64url`);
  }
  return value;
}

function importEd25519PublicKey(value, label) {
  if (typeof value !== "string" || value.length < 40 || value.length > 256
      || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw backendError("chameleon_availability_key_invalid", `${label} must be canonical SPKI base64url`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) {
    throw backendError("chameleon_availability_key_invalid", `${label} must be canonical SPKI base64url`);
  }
  let key;
  try {
    key = CREATE_PUBLIC_KEY({ key: bytes, type: "spki", format: "der" });
  } catch (cause) {
    throw backendError("chameleon_availability_key_invalid", `${label} is not a public key`, cause);
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw backendError("chameleon_availability_key_invalid", `${label} must be an Ed25519 public key`);
  }
  return key;
}

function publicKeyDigest(key) {
  return CREATE_HASH("sha256").update(
    key.export({ type: "spki", format: "der" }),
  ).digest("hex");
}

function signingMessage(domain, payloadDigest) {
  return Buffer.from(`${domain}\0${digest(payloadDigest, "signed payload digest")}`, "utf8");
}

function chameleonAvailabilityTrustSigningMessage(payloadDigest) {
  return signingMessage(CHAMELEON_AVAILABILITY_TRUST_SIGNING_DOMAIN, payloadDigest);
}

function chameleonAvailabilityEvidenceSigningMessage(payloadDigest) {
  return signingMessage(CHAMELEON_AVAILABILITY_EVIDENCE_SIGNING_DOMAIN, payloadDigest);
}

function normalizeEvidenceIdentityInput(input, label = "chameleon_availability_evidence_identity") {
  const value = exactRecord(input, label, [
    "version",
    "provider_id",
    "target_domain",
    "session_nucleus_hash",
    "issuer_key_id",
    "issuer_public_key_digest",
    "evidence_sequence",
    "nonce",
  ]);
  if (value.version !== CHAMELEON_AVAILABILITY_BACKEND_VERSION
      || value.provider_id !== "chameleon_ultra") {
    throw backendError("chameleon_availability_contract_invalid", `${label} version or provider drifted`);
  }
  return deepFreeze({
    version: CHAMELEON_AVAILABILITY_BACKEND_VERSION,
    provider_id: "chameleon_ultra",
    target_domain: safeDomain(value.target_domain, `${label}.target_domain`),
    session_nucleus_hash: digest(value.session_nucleus_hash, `${label}.session_nucleus_hash`),
    issuer_key_id: token(value.issuer_key_id, `${label}.issuer_key_id`, "availability-key"),
    issuer_public_key_digest: digest(
      value.issuer_public_key_digest,
      `${label}.issuer_public_key_digest`,
    ),
    evidence_sequence: integer(value.evidence_sequence, `${label}.evidence_sequence`, 1),
    nonce: token(value.nonce, `${label}.nonce`, "availability-nonce"),
  });
}

function chameleonAvailabilityEvidenceIdentityDigest(input) {
  const identity = normalizeEvidenceIdentityInput(input);
  return hashCanonicalJson({
    domain: CHAMELEON_AVAILABILITY_EVIDENCE_IDENTITY_DOMAIN,
    ...identity,
  });
}

function normalizeRequest(input, label = "chameleon_availability_backend_request") {
  const value = exactRecord(input, label, REQUEST_FIELDS);
  if (value.version !== CHAMELEON_AVAILABILITY_BACKEND_VERSION
      || value.provider_id !== "chameleon_ultra") {
    throw backendError("chameleon_availability_contract_invalid", `${label} version or provider drifted`);
  }
  const evidenceRef = token(value.evidence_ref, `${label}.evidence_ref`);
  if (!EVIDENCE_REF_RE.test(evidenceRef)) {
    throw backendError(
      "chameleon_availability_contract_invalid",
      `${label}.evidence_ref must be a v2 Chameleon availability evidence ref`,
    );
  }
  for (const field of [
    "session_nucleus_hash",
    "semantic_manifest_digest",
    "source_profile_digest",
    "codec_profile_digest",
    "assurance_profile_registry_digest",
    "dependency_proof_registry_digest",
    "inventory_projection_digest",
    "device_identity_digest",
    "custody_projection_digest",
    "authority_resolution_digest",
  ]) digest(value[field], `${label}.${field}`);
  token(value.custody_id, `${label}.custody_id`, "custody");
  token(value.session_id, `${label}.session_id`, "session");
  token(value.authority_id, `${label}.authority_id`, "authority");
  integer(value.authority_epoch, `${label}.authority_epoch`, 1);
  integer(value.revocation_generation, `${label}.revocation_generation`, 0);
  safeDomain(value.target_domain, `${label}.target_domain`);
  return deepFreeze(Object.fromEntries(REQUEST_FIELDS.map((field) => [field, value[field]])));
}

function normalizeTrustSigner(input, label) {
  const value = exactRecord(input, label, [
    "key_id",
    "owner_principal",
    "public_key_spki_base64url",
    "public_key_digest",
    "evidence_trust_epoch",
    "revocation_generation",
    "revoked",
    "not_before",
    "expires_at",
  ]);
  const publicKey = importEd25519PublicKey(
    value.public_key_spki_base64url,
    `${label}.public_key_spki_base64url`,
  );
  const keyDigest = publicKeyDigest(publicKey);
  if (digest(value.public_key_digest, `${label}.public_key_digest`) !== keyDigest) {
    throw backendError("chameleon_availability_key_invalid", `${label}.public_key_digest drifted`);
  }
  const notBefore = timestamp(value.not_before, `${label}.not_before`);
  const expiresAt = timestamp(value.expires_at, `${label}.expires_at`);
  const lifetime = Date.parse(expiresAt) - Date.parse(notBefore);
  if (lifetime <= 0 || lifetime > MAX_TRUST_LIFETIME_MS) {
    throw backendError(
      "chameleon_availability_contract_invalid",
      `${label} validity must be positive and no longer than 24 hours`,
    );
  }
  return {
    projection: deepFreeze({
      key_id: token(value.key_id, `${label}.key_id`, "availability-key"),
      owner_principal: token(
        value.owner_principal,
        `${label}.owner_principal`,
        "principal",
      ),
      public_key_spki_base64url: value.public_key_spki_base64url,
      public_key_digest: keyDigest,
      evidence_trust_epoch: integer(
        value.evidence_trust_epoch,
        `${label}.evidence_trust_epoch`,
        1,
      ),
      revocation_generation: integer(
        value.revocation_generation,
        `${label}.revocation_generation`,
        0,
      ),
      revoked: boolean(value.revoked, `${label}.revoked`),
      not_before: notBefore,
      expires_at: expiresAt,
    }),
    publicKey,
  };
}

function assertDefinitelyCurrent(sample, notBefore, expiresAt, label) {
  if (Date.parse(sample.trusted_utc_earliest) < Date.parse(notBefore)) {
    throw backendError("chameleon_availability_not_current", `${label} is not yet definitely current`);
  }
  if (Date.parse(sample.trusted_utc_latest) >= Date.parse(expiresAt)) {
    throw backendError("chameleon_availability_stale", `${label} is stale at trusted-clock uncertainty`);
  }
}

function normalizeSignedTrust(input, portState, sample) {
  const document = exactRecord(input, "signed_chameleon_availability_current_trust", [
    "version",
    "domain",
    "payload",
    "payload_digest",
    "scheme",
    "signature",
    "trust_statement_digest",
  ]);
  if (document.version !== CHAMELEON_AVAILABILITY_BACKEND_VERSION
      || document.domain !== CHAMELEON_AVAILABILITY_TRUST_DOMAIN
      || document.scheme !== "ed25519") {
    throw backendError("chameleon_availability_trust_invalid", "availability trust domain, version, or scheme is invalid");
  }
  const payloadValue = exactRecord(
    document.payload,
    "signed_chameleon_availability_current_trust.payload",
    [
      "version",
      "target_domain",
      "session_nucleus_hash",
      "trust_root_key_id",
      "trust_root_public_key_digest",
      "trust_generation",
      "trust_root_epoch",
      "revocation_generation",
      "not_before",
      "expires_at",
      "evidence_signers",
    ],
  );
  if (payloadValue.version !== CHAMELEON_AVAILABILITY_BACKEND_VERSION
      || payloadValue.target_domain !== portState.targetDomain
      || payloadValue.session_nucleus_hash !== portState.sessionNucleusHash
      || payloadValue.trust_root_key_id !== portState.trustRootKeyId
      || payloadValue.trust_root_public_key_digest !== portState.trustRootPublicKeyDigest) {
    throw backendError("chameleon_availability_trust_invalid", "availability trust root or session binding drifted");
  }
  if (!Array.isArray(payloadValue.evidence_signers)
      || utilTypes.isProxy(payloadValue.evidence_signers)
      || payloadValue.evidence_signers.length < 1
      || payloadValue.evidence_signers.length > 64) {
    throw backendError("chameleon_availability_trust_invalid", "availability trust signer registry is invalid");
  }
  const signers = [];
  const signerKeys = new Map();
  for (let index = 0; index < payloadValue.evidence_signers.length; index += 1) {
    const normalized = normalizeTrustSigner(
      payloadValue.evidence_signers[index],
      `signed_chameleon_availability_current_trust.payload.evidence_signers[${index}]`,
    );
    if (signerKeys.has(normalized.projection.key_id)) {
      throw backendError("chameleon_availability_trust_invalid", "availability trust has duplicate signer key IDs");
    }
    signers.push(normalized.projection);
    signerKeys.set(normalized.projection.key_id, normalized.publicKey);
  }
  const sortedSigners = [...signers].sort((left, right) => left.key_id.localeCompare(right.key_id));
  if (sortedSigners.some((entry, index) => entry.key_id !== signers[index].key_id)) {
    throw backendError("chameleon_availability_trust_invalid", "availability trust signer registry must be sorted");
  }
  const notBefore = timestamp(payloadValue.not_before, "availability trust not_before");
  const expiresAt = timestamp(payloadValue.expires_at, "availability trust expires_at");
  const trustLifetime = Date.parse(expiresAt) - Date.parse(notBefore);
  if (trustLifetime <= 0 || trustLifetime > MAX_TRUST_LIFETIME_MS) {
    throw backendError(
      "chameleon_availability_trust_invalid",
      "availability trust validity must be positive and no longer than 24 hours",
    );
  }
  const payload = deepFreeze({
    version: CHAMELEON_AVAILABILITY_BACKEND_VERSION,
    target_domain: portState.targetDomain,
    session_nucleus_hash: portState.sessionNucleusHash,
    trust_root_key_id: portState.trustRootKeyId,
    trust_root_public_key_digest: portState.trustRootPublicKeyDigest,
    trust_generation: integer(payloadValue.trust_generation, "availability trust generation", 1),
    trust_root_epoch: integer(payloadValue.trust_root_epoch, "availability trust root epoch", 1),
    revocation_generation: integer(
      payloadValue.revocation_generation,
      "availability trust revocation generation",
      0,
    ),
    not_before: notBefore,
    expires_at: expiresAt,
    evidence_signers: sortedSigners,
  });
  const payloadDigest = digest(document.payload_digest, "availability trust payload_digest");
  if (payloadDigest !== hashCanonicalJson(payload)) {
    throw backendError("chameleon_availability_trust_invalid", "availability trust payload digest drifted");
  }
  const signature = canonicalSignature(document.signature, "availability trust signature");
  let verified = false;
  try {
    verified = VERIFY_SIGNATURE(
      null,
      chameleonAvailabilityTrustSigningMessage(payloadDigest),
      portState.trustRootPublicKey,
      Buffer.from(signature, "base64url"),
    );
  } catch {
    verified = false;
  }
  if (!verified) {
    throw backendError("chameleon_availability_trust_invalid", "availability current trust signature is invalid");
  }
  const basis = {
    version: CHAMELEON_AVAILABILITY_BACKEND_VERSION,
    domain: CHAMELEON_AVAILABILITY_TRUST_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  const statementDigest = digest(
    document.trust_statement_digest,
    "availability trust statement digest",
  );
  if (statementDigest !== hashCanonicalJson(basis)) {
    throw backendError("chameleon_availability_trust_invalid", "availability trust statement digest drifted");
  }
  assertDefinitelyCurrent(sample, notBefore, expiresAt, "availability current trust");
  for (const signer of sortedSigners) {
    if (Date.parse(signer.not_before) < Date.parse(notBefore)
        || Date.parse(signer.expires_at) > Date.parse(expiresAt)) {
      throw backendError("chameleon_availability_trust_invalid", "availability signer validity escapes trust window");
    }
  }
  return {
    document: deepFreeze({ ...basis, trust_statement_digest: statementDigest }),
    signerKeys,
  };
}

function normalizeEvidencePayload(input, label = "signed_chameleon_availability_evidence.payload") {
  const value = exactRecord(input, label, EVIDENCE_PAYLOAD_FIELDS);
  const request = normalizeRequest(
    Object.fromEntries(REQUEST_FIELDS.map((field) => [field, value[field]])),
    `${label}.request_binding`,
  );
  const identity = normalizeEvidenceIdentityInput({
    version: value.version,
    provider_id: value.provider_id,
    target_domain: value.target_domain,
    session_nucleus_hash: value.session_nucleus_hash,
    issuer_key_id: value.issuer_key_id,
    issuer_public_key_digest: value.issuer_public_key_digest,
    evidence_sequence: value.evidence_sequence,
    nonce: value.nonce,
  }, `${label}.identity_binding`);
  const identityDigest = chameleonAvailabilityEvidenceIdentityDigest(identity);
  if (digest(value.evidence_identity_digest, `${label}.evidence_identity_digest`)
      !== identityDigest) {
    throw backendError("chameleon_availability_evidence_invalid", `${label}.evidence_identity_digest drifted`);
  }
  const refMatch = EVIDENCE_REF_RE.exec(request.evidence_ref);
  if (!refMatch || refMatch[1] !== identityDigest) {
    throw backendError("chameleon_availability_evidence_invalid", `${label}.evidence_ref does not bind identity`);
  }
  const observedAt = timestamp(value.observed_at, `${label}.observed_at`);
  const expiresAt = timestamp(value.expires_at, `${label}.expires_at`);
  const wallLifetime = Date.parse(expiresAt) - Date.parse(observedAt);
  if (wallLifetime <= 0 || wallLifetime > MAX_EVIDENCE_LIFETIME_MS) {
    throw backendError(
      "chameleon_availability_evidence_invalid",
      `${label} wall-time validity must be positive and no longer than 15 minutes`,
    );
  }
  const observedMonotonicMs = integer(
    value.observed_monotonic_ms,
    `${label}.observed_monotonic_ms`,
    0,
  );
  const expiresMonotonicMs = integer(
    value.expires_monotonic_ms,
    `${label}.expires_monotonic_ms`,
    1,
  );
  const monotonicLifetime = expiresMonotonicMs - observedMonotonicMs;
  if (monotonicLifetime <= 0 || monotonicLifetime > MAX_EVIDENCE_LIFETIME_MS) {
    throw backendError(
      "chameleon_availability_evidence_invalid",
      `${label} monotonic validity must be positive and no longer than 15 minutes`,
    );
  }
  return deepFreeze({
    ...request,
    evidence_identity_digest: identityDigest,
    evidence_owner_principal: token(
      value.evidence_owner_principal,
      `${label}.evidence_owner_principal`,
      "principal",
    ),
    evidence_artifact_digest: digest(
      value.evidence_artifact_digest,
      `${label}.evidence_artifact_digest`,
    ),
    evidence_trust_epoch: integer(
      value.evidence_trust_epoch,
      `${label}.evidence_trust_epoch`,
      1,
    ),
    issuer_key_id: identity.issuer_key_id,
    issuer_public_key_digest: identity.issuer_public_key_digest,
    issuer_revocation_generation: integer(
      value.issuer_revocation_generation,
      `${label}.issuer_revocation_generation`,
      0,
    ),
    authority_trust_generation: integer(
      value.authority_trust_generation,
      `${label}.authority_trust_generation`,
      1,
    ),
    trust_root_epoch: integer(value.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    evidence_sequence: identity.evidence_sequence,
    nonce: identity.nonce,
    observed_at: observedAt,
    expires_at: expiresAt,
    clock_id: token(value.clock_id, `${label}.clock_id`, "physical-clock"),
    monotonic_epoch_id: digest(value.monotonic_epoch_id, `${label}.monotonic_epoch_id`),
    observed_monotonic_ms: observedMonotonicMs,
    expires_monotonic_ms: expiresMonotonicMs,
    reported_command_ids: deepFreeze(copyPassiveJson(
      value.reported_command_ids,
      `${label}.reported_command_ids`,
    )),
    assurance_claims: deepFreeze(copyPassiveJson(
      value.assurance_claims,
      `${label}.assurance_claims`,
    )),
    dependency_proofs: deepFreeze(copyPassiveJson(
      value.dependency_proofs,
      `${label}.dependency_proofs`,
    )),
    variant_qualifications: deepFreeze(copyPassiveJson(
      value.variant_qualifications,
      `${label}.variant_qualifications`,
    )),
  });
}

function normalizeSignedEvidence(input, trust, sample) {
  const document = exactRecord(input, "signed_chameleon_availability_evidence", [
    "version",
    "domain",
    "payload",
    "payload_digest",
    "scheme",
    "signature",
    "signed_evidence_digest",
  ]);
  if (document.version !== CHAMELEON_AVAILABILITY_BACKEND_VERSION
      || document.domain !== CHAMELEON_AVAILABILITY_EVIDENCE_DOMAIN
      || document.scheme !== "ed25519") {
    throw backendError("chameleon_availability_evidence_invalid", "availability evidence domain, version, or scheme is invalid");
  }
  const payload = normalizeEvidencePayload(document.payload);
  const signer = trust.document.payload.evidence_signers.find(
    (entry) => entry.key_id === payload.issuer_key_id,
  );
  if (!signer) {
    throw backendError("chameleon_availability_evidence_untrusted", "availability evidence signer is not enrolled");
  }
  if (signer.revoked) {
    throw backendError("chameleon_availability_evidence_revoked", "availability evidence signer is revoked");
  }
  for (const [actual, expected, field] of [
    [payload.issuer_public_key_digest, signer.public_key_digest, "issuer_public_key_digest"],
    [payload.evidence_owner_principal, signer.owner_principal, "evidence_owner_principal"],
    [payload.evidence_trust_epoch, signer.evidence_trust_epoch, "evidence_trust_epoch"],
    [payload.issuer_revocation_generation, signer.revocation_generation, "issuer_revocation_generation"],
    [payload.authority_trust_generation, trust.document.payload.trust_generation, "authority_trust_generation"],
    [payload.trust_root_epoch, trust.document.payload.trust_root_epoch, "trust_root_epoch"],
  ]) {
    if (actual !== expected) {
      throw backendError("chameleon_availability_evidence_untrusted", `availability evidence ${field} drifted from current trust`);
    }
  }
  if (Date.parse(payload.observed_at) < Date.parse(signer.not_before)
      || Date.parse(payload.expires_at) > Date.parse(signer.expires_at)) {
    throw backendError("chameleon_availability_evidence_untrusted", "availability evidence validity escapes signer enrollment");
  }
  if (payload.clock_id !== sample.clock_id
      || payload.monotonic_epoch_id !== sample.monotonic_epoch_id) {
    throw backendError("chameleon_availability_evidence_untrusted", "availability evidence trusted-clock identity drifted");
  }
  if (payload.observed_monotonic_ms > sample.monotonic_ms) {
    throw backendError("chameleon_availability_not_current", "availability evidence monotonic observation is in the future");
  }
  if (sample.monotonic_ms >= payload.expires_monotonic_ms) {
    throw backendError("chameleon_availability_stale", "availability evidence monotonic validity expired");
  }
  const wallLifetime = Date.parse(payload.expires_at) - Date.parse(payload.observed_at);
  const monotonicLifetime = payload.expires_monotonic_ms - payload.observed_monotonic_ms;
  const skewCeiling = Math.max(
    MAX_WALL_MONOTONIC_SKEW_FLOOR_MS,
    sample.max_uncertainty_ms * 2,
  );
  const observedWallAge = Date.parse(sample.trusted_utc) - Date.parse(payload.observed_at);
  const observedMonotonicAge = sample.monotonic_ms - payload.observed_monotonic_ms;
  if (Math.abs(wallLifetime - monotonicLifetime) > skewCeiling
      || Math.abs(observedWallAge - observedMonotonicAge) > skewCeiling) {
    throw backendError(
      "chameleon_availability_clock_skew",
      "availability wall and monotonic freshness bindings exceed trusted uncertainty",
    );
  }
  assertDefinitelyCurrent(sample, payload.observed_at, payload.expires_at, "availability evidence");
  const payloadDigest = digest(document.payload_digest, "availability evidence payload_digest");
  if (payloadDigest !== hashCanonicalJson(payload)) {
    throw backendError("chameleon_availability_evidence_invalid", "availability evidence payload digest drifted");
  }
  const signature = canonicalSignature(document.signature, "availability evidence signature");
  let verified = false;
  try {
    verified = VERIFY_SIGNATURE(
      null,
      chameleonAvailabilityEvidenceSigningMessage(payloadDigest),
      trust.signerKeys.get(signer.key_id),
      Buffer.from(signature, "base64url"),
    );
  } catch {
    verified = false;
  }
  if (!verified) {
    throw backendError("chameleon_availability_signature_invalid", "availability evidence signature is invalid");
  }
  const basis = {
    version: CHAMELEON_AVAILABILITY_BACKEND_VERSION,
    domain: CHAMELEON_AVAILABILITY_EVIDENCE_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  const signedEvidenceDigest = digest(
    document.signed_evidence_digest,
    "availability signed evidence digest",
  );
  if (signedEvidenceDigest !== hashCanonicalJson(basis)) {
    throw backendError("chameleon_availability_evidence_invalid", "availability signed evidence digest drifted");
  }
  return deepFreeze({ ...basis, signed_evidence_digest: signedEvidenceDigest });
}

function normalizeReplayClaim(input, label) {
  const value = exactRecord(input, label, [
    "evidence_ref",
    "evidence_identity_digest",
    "signed_evidence_digest",
    "request_digest",
    "nonce_digest",
    "issuer_key_id",
    "evidence_trust_epoch",
    "issuer_revocation_generation",
    "evidence_sequence",
    "claim_digest",
  ]);
  const basis = {
    evidence_ref: token(value.evidence_ref, `${label}.evidence_ref`),
    evidence_identity_digest: digest(
      value.evidence_identity_digest,
      `${label}.evidence_identity_digest`,
    ),
    signed_evidence_digest: digest(
      value.signed_evidence_digest,
      `${label}.signed_evidence_digest`,
    ),
    request_digest: digest(value.request_digest, `${label}.request_digest`),
    nonce_digest: digest(value.nonce_digest, `${label}.nonce_digest`),
    issuer_key_id: token(value.issuer_key_id, `${label}.issuer_key_id`, "availability-key"),
    evidence_trust_epoch: integer(
      value.evidence_trust_epoch,
      `${label}.evidence_trust_epoch`,
      1,
    ),
    issuer_revocation_generation: integer(
      value.issuer_revocation_generation,
      `${label}.issuer_revocation_generation`,
      0,
    ),
    evidence_sequence: integer(value.evidence_sequence, `${label}.evidence_sequence`, 1),
  };
  const claimDigest = digest(value.claim_digest, `${label}.claim_digest`);
  if (claimDigest !== hashCanonicalJson({
    domain: CHAMELEON_AVAILABILITY_REPLAY_CLAIM_DOMAIN,
    ...basis,
  })) {
    throw backendError("chameleon_availability_replay_state_invalid", `${label}.claim_digest drifted`);
  }
  return deepFreeze({ ...basis, claim_digest: claimDigest });
}

function normalizeIssuerHighWater(input, label) {
  const value = exactRecord(input, label, [
    "issuer_key_id",
    "evidence_trust_epoch",
    "revocation_generation",
    "evidence_sequence",
  ]);
  return deepFreeze({
    issuer_key_id: token(value.issuer_key_id, `${label}.issuer_key_id`, "availability-key"),
    evidence_trust_epoch: integer(
      value.evidence_trust_epoch,
      `${label}.evidence_trust_epoch`,
      1,
    ),
    revocation_generation: integer(
      value.revocation_generation,
      `${label}.revocation_generation`,
      0,
    ),
    evidence_sequence: integer(value.evidence_sequence, `${label}.evidence_sequence`, 1),
  });
}

function replayStateBasis(state) {
  return {
    version: state.version,
    context_domain: state.context_domain,
    target_domain: state.target_domain,
    session_nucleus_hash: state.session_nucleus_hash,
    store_sequence: state.store_sequence,
    previous_state_digest: state.previous_state_digest,
    clock_id: state.clock_id,
    monotonic_epoch_id: state.monotonic_epoch_id,
    clock_monotonic_ms: state.clock_monotonic_ms,
    clock_trusted_utc: state.clock_trusted_utc,
    clock_durable_observation_sequence: state.clock_durable_observation_sequence,
    trust_generation: state.trust_generation,
    trust_root_epoch: state.trust_root_epoch,
    trust_revocation_generation: state.trust_revocation_generation,
    trust_statement_digest: state.trust_statement_digest,
    issuer_high_waters: state.issuer_high_waters,
    claims: state.claims,
  };
}

function normalizeReplayState(input, portState, label = "chameleon_availability_replay_state") {
  if (input == null) return null;
  const value = exactRecord(input, label, [
    "version",
    "context_domain",
    "target_domain",
    "session_nucleus_hash",
    "store_sequence",
    "previous_state_digest",
    "clock_id",
    "monotonic_epoch_id",
    "clock_monotonic_ms",
    "clock_trusted_utc",
    "clock_durable_observation_sequence",
    "trust_generation",
    "trust_root_epoch",
    "trust_revocation_generation",
    "trust_statement_digest",
    "issuer_high_waters",
    "claims",
    "state_digest",
  ]);
  if (value.version !== CHAMELEON_AVAILABILITY_BACKEND_VERSION
      || value.context_domain !== CHAMELEON_AVAILABILITY_OWNER_CONTEXT_DOMAIN
      || value.target_domain !== portState.targetDomain
      || value.session_nucleus_hash !== portState.sessionNucleusHash) {
    throw backendError("chameleon_availability_replay_state_invalid", `${label} context drifted`);
  }
  if (!Array.isArray(value.issuer_high_waters) || utilTypes.isProxy(value.issuer_high_waters)
      || !Array.isArray(value.claims) || utilTypes.isProxy(value.claims)
      || value.claims.length > MAX_REPLAY_CLAIMS) {
    throw backendError("chameleon_availability_replay_state_invalid", `${label} registries are invalid`);
  }
  const issuerHighWaters = value.issuer_high_waters.map((entry, index) => (
    normalizeIssuerHighWater(entry, `${label}.issuer_high_waters[${index}]`)
  ));
  const claims = value.claims.map((entry, index) => (
    normalizeReplayClaim(entry, `${label}.claims[${index}]`)
  ));
  for (const [rows, key, name] of [
    [issuerHighWaters, (entry) => entry.issuer_key_id, "issuer key"],
    [claims, (entry) => entry.evidence_ref, "evidence ref"],
    [claims, (entry) => entry.nonce_digest, "nonce"],
  ]) {
    if (new Set(rows.map(key)).size !== rows.length) {
      throw backendError("chameleon_availability_replay_state_invalid", `${label} has duplicate ${name}`);
    }
  }
  const normalized = {
    version: CHAMELEON_AVAILABILITY_BACKEND_VERSION,
    context_domain: CHAMELEON_AVAILABILITY_OWNER_CONTEXT_DOMAIN,
    target_domain: portState.targetDomain,
    session_nucleus_hash: portState.sessionNucleusHash,
    store_sequence: integer(value.store_sequence, `${label}.store_sequence`, 1),
    previous_state_digest: digest(value.previous_state_digest, `${label}.previous_state_digest`),
    clock_id: token(value.clock_id, `${label}.clock_id`, "physical-clock"),
    monotonic_epoch_id: digest(value.monotonic_epoch_id, `${label}.monotonic_epoch_id`),
    clock_monotonic_ms: integer(value.clock_monotonic_ms, `${label}.clock_monotonic_ms`, 0),
    clock_trusted_utc: timestamp(value.clock_trusted_utc, `${label}.clock_trusted_utc`),
    clock_durable_observation_sequence: integer(
      value.clock_durable_observation_sequence,
      `${label}.clock_durable_observation_sequence`,
      1,
    ),
    trust_generation: integer(value.trust_generation, `${label}.trust_generation`, 1),
    trust_root_epoch: integer(value.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    trust_revocation_generation: integer(
      value.trust_revocation_generation,
      `${label}.trust_revocation_generation`,
      0,
    ),
    trust_statement_digest: digest(
      value.trust_statement_digest,
      `${label}.trust_statement_digest`,
    ),
    issuer_high_waters: deepFreeze(issuerHighWaters),
    claims: deepFreeze(claims),
  };
  const stateDigest = digest(value.state_digest, `${label}.state_digest`);
  if (stateDigest !== hashCanonicalJson({
    domain: CHAMELEON_AVAILABILITY_REPLAY_STATE_DOMAIN,
    ...replayStateBasis(normalized),
  })) {
    throw backendError("chameleon_availability_replay_state_invalid", `${label}.state_digest drifted`);
  }
  return deepFreeze({ ...normalized, state_digest: stateDigest });
}

function replayClaimFor(request, evidence) {
  const basis = {
    evidence_ref: request.evidence_ref,
    evidence_identity_digest: evidence.payload.evidence_identity_digest,
    signed_evidence_digest: evidence.signed_evidence_digest,
    request_digest: hashCanonicalJson(request),
    nonce_digest: hashCanonicalJson({ nonce: evidence.payload.nonce }),
    issuer_key_id: evidence.payload.issuer_key_id,
    evidence_trust_epoch: evidence.payload.evidence_trust_epoch,
    issuer_revocation_generation: evidence.payload.issuer_revocation_generation,
    evidence_sequence: evidence.payload.evidence_sequence,
  };
  return deepFreeze({
    ...basis,
    claim_digest: hashCanonicalJson({
      domain: CHAMELEON_AVAILABILITY_REPLAY_CLAIM_DOMAIN,
      ...basis,
    }),
  });
}

function assertCurrentHighWaters(previous, trust, sample, claim) {
  if (previous == null) return;
  if (sample.clock_id !== previous.clock_id
      || sample.monotonic_epoch_id !== previous.monotonic_epoch_id) {
    throw backendError("chameleon_availability_clock_rollback", "availability trusted-clock epoch drifted from durable state");
  }
  if (sample.monotonic_ms < previous.clock_monotonic_ms
      || Date.parse(sample.trusted_utc) < Date.parse(previous.clock_trusted_utc)
      || sample.durable_observation_sequence < previous.clock_durable_observation_sequence) {
    throw backendError("chameleon_availability_clock_rollback", "availability trusted clock moved backwards");
  }
  const trustPayload = trust.document.payload;
  if (trustPayload.trust_generation < previous.trust_generation
      || trustPayload.trust_root_epoch < previous.trust_root_epoch
      || trustPayload.revocation_generation < previous.trust_revocation_generation) {
    throw backendError("chameleon_availability_trust_rollback", "availability trust high-water moved backwards");
  }
  if (trustPayload.trust_generation === previous.trust_generation
      && trust.document.trust_statement_digest !== previous.trust_statement_digest) {
    throw backendError("chameleon_availability_trust_fork", "availability trust forked at current generation");
  }
  const priorIssuer = previous.issuer_high_waters.find(
    (entry) => entry.issuer_key_id === claim.issuer_key_id,
  );
  if (priorIssuer != null) {
    const currentSigner = trustPayload.evidence_signers.find(
      (entry) => entry.key_id === claim.issuer_key_id,
    );
    if (currentSigner == null || currentSigner.revoked
        || currentSigner.evidence_trust_epoch < priorIssuer.evidence_trust_epoch
        || currentSigner.revocation_generation < priorIssuer.revocation_generation) {
      throw backendError("chameleon_availability_issuer_rollback", "availability issuer high-water moved backwards");
    }
  }
}

function assertHighWaters(previous, trust, sample, claim) {
  if (previous == null) return;
  assertCurrentHighWaters(previous, trust, sample, claim);
  const priorIssuer = previous.issuer_high_waters.find(
    (entry) => entry.issuer_key_id === claim.issuer_key_id,
  );
  if (priorIssuer != null) {
    if (claim.evidence_sequence <= priorIssuer.evidence_sequence) {
      throw backendError("chameleon_availability_replay", "availability evidence sequence was replayed or moved backwards");
    }
  }
  if (previous.claims.some((entry) => entry.nonce_digest === claim.nonce_digest)) {
    throw backendError("chameleon_availability_replay", "availability evidence nonce was already consumed");
  }
}

function nextReplayState(previous, portState, trust, evidence, sample, claim) {
  if (previous != null && previous.claims.length >= MAX_REPLAY_CLAIMS) {
    throw backendError("chameleon_availability_capacity_exhausted", "availability replay registry is full");
  }
  assertHighWaters(previous, trust, sample, claim);
  const issuerHighWaters = previous == null ? [] : [...previous.issuer_high_waters];
  const priorIndex = issuerHighWaters.findIndex(
    (entry) => entry.issuer_key_id === claim.issuer_key_id,
  );
  const nextIssuer = deepFreeze({
    issuer_key_id: claim.issuer_key_id,
    evidence_trust_epoch: claim.evidence_trust_epoch,
    revocation_generation: claim.issuer_revocation_generation,
    evidence_sequence: claim.evidence_sequence,
  });
  if (priorIndex === -1) issuerHighWaters.push(nextIssuer);
  else issuerHighWaters[priorIndex] = nextIssuer;
  issuerHighWaters.sort((left, right) => left.issuer_key_id.localeCompare(right.issuer_key_id));
  const basis = {
    version: CHAMELEON_AVAILABILITY_BACKEND_VERSION,
    context_domain: CHAMELEON_AVAILABILITY_OWNER_CONTEXT_DOMAIN,
    target_domain: portState.targetDomain,
    session_nucleus_hash: portState.sessionNucleusHash,
    store_sequence: previous == null ? 1 : previous.store_sequence + 1,
    previous_state_digest: previous == null ? "0".repeat(64) : previous.state_digest,
    clock_id: sample.clock_id,
    monotonic_epoch_id: sample.monotonic_epoch_id,
    clock_monotonic_ms: sample.monotonic_ms,
    clock_trusted_utc: sample.trusted_utc,
    clock_durable_observation_sequence: sample.durable_observation_sequence,
    trust_generation: trust.document.payload.trust_generation,
    trust_root_epoch: trust.document.payload.trust_root_epoch,
    trust_revocation_generation: trust.document.payload.revocation_generation,
    trust_statement_digest: trust.document.trust_statement_digest,
    issuer_high_waters: deepFreeze(issuerHighWaters),
    claims: deepFreeze([...(previous?.claims || []), claim]),
  };
  return deepFreeze({
    ...basis,
    state_digest: hashCanonicalJson({
      domain: CHAMELEON_AVAILABILITY_REPLAY_STATE_DOMAIN,
      ...basis,
    }),
  });
}

function refreshedReplayState(previous, portState, trust, sample) {
  const basis = {
    version: CHAMELEON_AVAILABILITY_BACKEND_VERSION,
    context_domain: CHAMELEON_AVAILABILITY_OWNER_CONTEXT_DOMAIN,
    target_domain: portState.targetDomain,
    session_nucleus_hash: portState.sessionNucleusHash,
    store_sequence: previous.store_sequence + 1,
    previous_state_digest: previous.state_digest,
    clock_id: sample.clock_id,
    monotonic_epoch_id: sample.monotonic_epoch_id,
    clock_monotonic_ms: sample.monotonic_ms,
    clock_trusted_utc: sample.trusted_utc,
    clock_durable_observation_sequence: sample.durable_observation_sequence,
    trust_generation: trust.document.payload.trust_generation,
    trust_root_epoch: trust.document.payload.trust_root_epoch,
    trust_revocation_generation: trust.document.payload.revocation_generation,
    trust_statement_digest: trust.document.trust_statement_digest,
    issuer_high_waters: previous.issuer_high_waters,
    claims: previous.claims,
  };
  return deepFreeze({
    ...basis,
    state_digest: hashCanonicalJson({
      domain: CHAMELEON_AVAILABILITY_REPLAY_STATE_DOMAIN,
      ...basis,
    }),
  });
}

function replayReceipt(claim, durable, idempotent) {
  return deepFreeze({
    version: CHAMELEON_AVAILABILITY_BACKEND_VERSION,
    evidence_ref: claim.evidence_ref,
    replay_claim_digest: claim.claim_digest,
    store_sequence: durable.store_sequence,
    durable_state_digest: durable.state_digest,
    idempotent,
    exact_durable_readback: true,
  });
}

function commitReplayClaim(portState, trust, evidence, sample, claim) {
  for (let attempt = 1; attempt <= MAX_CAS_ATTEMPTS; attempt += 1) {
    const raw = readPhysicalMonotonicOwnerState(portState.monotonicOwnerPort);
    const previous = normalizeReplayState(raw, portState);
    const existing = previous?.claims.find((entry) => entry.evidence_ref === claim.evidence_ref);
    assertCurrentHighWaters(previous, trust, sample, claim);
    if (existing != null) {
      if (canonicalJson(existing) !== canonicalJson(claim)) {
        throw backendError("chameleon_availability_replay_conflict", "availability evidence ref conflicts with durable claim");
      }
      if (previous.claims.some((entry) => (
        entry.nonce_digest === claim.nonce_digest && entry.evidence_ref !== claim.evidence_ref
      ))) {
        throw backendError("chameleon_availability_replay", "availability evidence nonce belongs to another durable claim");
      }
      // Persist the newly verified clock/trust high-waters even for an exact
      // idempotent claim. Returning the old head would allow a later resolver
      // to compare against stale trust state after this verification advanced.
      const refreshed = refreshedReplayState(previous, portState, trust, sample);
      let refreshedCommit;
      try {
        refreshedCommit = compareAndSetPhysicalMonotonicOwnerState(
          portState.monotonicOwnerPort,
          raw,
          refreshed,
        );
      } catch (error) {
        const readback = normalizeReplayState(
          readPhysicalMonotonicOwnerState(portState.monotonicOwnerPort),
          portState,
        );
        if (readback != null && canonicalJson(readback) === canonicalJson(refreshed)) {
          return replayReceipt(existing, readback, true);
        }
        throw backendError(
          "chameleon_availability_commit_ambiguous",
          "availability idempotent high-water refresh failed without exact durable readback",
          error,
        );
      }
      if (!refreshedCommit) continue;
      const refreshedReadback = normalizeReplayState(
        readPhysicalMonotonicOwnerState(portState.monotonicOwnerPort),
        portState,
      );
      if (refreshedReadback == null
          || canonicalJson(refreshedReadback) !== canonicalJson(refreshed)) {
        throw backendError(
          "chameleon_availability_commit_ambiguous",
          "availability idempotent high-water refresh lacks exact durable readback",
        );
      }
      return replayReceipt(existing, refreshedReadback, true);
    }
    const next = nextReplayState(previous, portState, trust, evidence, sample, claim);
    let committed;
    try {
      committed = compareAndSetPhysicalMonotonicOwnerState(
        portState.monotonicOwnerPort,
        raw,
        next,
      );
    } catch (error) {
      const readback = normalizeReplayState(
        readPhysicalMonotonicOwnerState(portState.monotonicOwnerPort),
        portState,
      );
      if (readback != null && canonicalJson(readback) === canonicalJson(next)) {
        return replayReceipt(claim, readback, false);
      }
      throw backendError(
        "chameleon_availability_commit_ambiguous",
        "availability replay claim failed without exact durable readback",
        error,
      );
    }
    if (!committed) continue;
    const readback = normalizeReplayState(
      readPhysicalMonotonicOwnerState(portState.monotonicOwnerPort),
      portState,
    );
    if (readback == null || canonicalJson(readback) !== canonicalJson(next)) {
      throw backendError(
        "chameleon_availability_commit_ambiguous",
        "availability replay claim lacks exact durable readback",
      );
    }
    return replayReceipt(claim, readback, false);
  }
  throw backendError("chameleon_availability_commit_contended", "availability replay claim CAS remained contended");
}

function rejectSerialization() {
  throw backendError(
    "chameleon_availability_port_serialization_refused",
    "availability backend ports are process-local private capabilities",
  );
}

function createChameleonAvailabilityEvidenceBackendPort(input = {}) {
  const value = exactRecord(input, "chameleon_availability_evidence_backend_port", [
    "version",
    "port_id",
    "target_domain",
    "session_nucleus_hash",
    "trust_root_key_id",
    "trust_root_public_key_spki_base64url",
    "trusted_clock_port",
    "monotonic_owner_port",
  ]);
  if (value.version !== CHAMELEON_AVAILABILITY_BACKEND_VERSION) {
    throw backendError("chameleon_availability_contract_invalid", "availability backend port version must be 2");
  }
  const targetDomain = safeDomain(value.target_domain, "availability backend target_domain");
  const sessionNucleusHash = digest(
    value.session_nucleus_hash,
    "availability backend session_nucleus_hash",
  );
  const clockPort = assertRestartDurablePhysicalTrustedClockPort(value.trusted_clock_port);
  const ownerPort = assertPhysicalMonotonicOwnerPort(value.monotonic_owner_port);
  if (clockPort.target_domain !== targetDomain
      || clockPort.session_nucleus_hash !== sessionNucleusHash
      || ownerPort.target_domain !== targetDomain
      || ownerPort.session_nucleus_hash !== sessionNucleusHash
      || ownerPort.context_domain !== CHAMELEON_AVAILABILITY_OWNER_CONTEXT_DOMAIN) {
    throw backendError("chameleon_availability_context_drift", "availability clock/owner context does not match backend session");
  }
  const rootKey = importEd25519PublicKey(
    value.trust_root_public_key_spki_base64url,
    "availability backend trust root public key",
  );
  const trustRootPublicKeyDigest = publicKeyDigest(rootKey);
  const readinessBlockers = [];
  // The public constructor can pin a key but cannot prove that Bob's operator
  // enrollment principal selected or still controls that trust root. A future
  // native/Bob-owned enrollment authority must replace this blocker with a
  // privately branded target/session/root-digest projection; caller-selected
  // keys can qualify conformance availability but never production readiness.
  readinessBlockers.push("availability_trust_root_custody_not_bob_enrolled");
  try {
    assertProductionPhysicalTrustedClockPort(clockPort);
  } catch {
    readinessBlockers.push("production_restart_stable_trusted_clock_not_enrolled");
  }
  try {
    assertProductionPhysicalMonotonicOwnerPort(ownerPort);
  } catch {
    readinessBlockers.push("production_isolated_availability_replay_owner_not_enrolled");
  }
  const state = {
    targetDomain,
    sessionNucleusHash,
    trustRootKeyId: token(
      value.trust_root_key_id,
      "availability backend trust_root_key_id",
      "availability-trust-root",
    ),
    trustRootPublicKey: rootKey,
    trustRootPublicKeyDigest,
    trustedClockPort: clockPort,
    monotonicOwnerPort: ownerPort,
    readinessBlockers: deepFreeze(readinessBlockers.sort()),
  };
  let port = Object.create(null);
  Object.defineProperties(port, {
    version: { value: CHAMELEON_AVAILABILITY_BACKEND_VERSION, enumerable: true },
    kind: { value: "chameleon_availability_evidence_backend_port", enumerable: true },
    port_id: {
      value: identifier(value.port_id, "availability backend port_id"),
      enumerable: true,
    },
    target_domain: { value: targetDomain, enumerable: true },
    session_nucleus_hash: { value: sessionNucleusHash, enumerable: true },
    mode: { value: CHAMELEON_AVAILABILITY_BACKEND_MODE, enumerable: true },
    trust_root_key_id: { value: state.trustRootKeyId, enumerable: true },
    trust_root_public_key_digest: { value: trustRootPublicKeyDigest, enumerable: true },
    trusted_clock_port_id: { value: clockPort.port_id, enumerable: true },
    monotonic_owner_slot_digest: { value: ownerPort.slot_digest, enumerable: true },
    independently_signed: { value: true, enumerable: true },
    trust_root_bob_enrolled: { value: false, enumerable: true },
    atomic_durable_replay: { value: true, enumerable: true },
    production_ready: { value: state.readinessBlockers.length === 0, enumerable: true },
    production_blockers: { value: state.readinessBlockers, enumerable: true },
    execution_authority: { value: false, enumerable: true },
    toJSON: { value: rejectSerialization },
  });
  port = Object.freeze(port);
  BACKEND_PORTS.add(port);
  BACKEND_PORT_STATE.set(port, state);
  return port;
}

function assertChameleonAvailabilityEvidenceBackendPort(port) {
  if (!port || utilTypes.isProxy(port) || !Object.isFrozen(port)
      || !BACKEND_PORTS.has(port) || !BACKEND_PORT_STATE.has(port)) {
    throw backendError(
      "chameleon_availability_backend_untrusted",
      "a live privately branded Chameleon availability backend port is required",
    );
  }
  const state = BACKEND_PORT_STATE.get(port);
  assertRestartDurablePhysicalTrustedClockPort(state.trustedClockPort);
  assertPhysicalMonotonicOwnerPort(state.monotonicOwnerPort);
  return port;
}

function resolveChameleonAvailabilityEvidenceBackend(portInput, input) {
  const port = assertChameleonAvailabilityEvidenceBackendPort(portInput);
  const state = BACKEND_PORT_STATE.get(port);
  const value = exactRecord(input, "chameleon_availability_backend_resolution", [
    "version",
    "request",
    "signed_current_trust",
    "signed_evidence",
  ]);
  if (value.version !== CHAMELEON_AVAILABILITY_BACKEND_VERSION) {
    throw backendError("chameleon_availability_contract_invalid", "availability backend resolution version must be 2");
  }
  const request = normalizeRequest(value.request);
  if (request.target_domain !== state.targetDomain
      || request.session_nucleus_hash !== state.sessionNucleusHash) {
    throw backendError("chameleon_availability_context_drift", "availability request does not match backend session");
  }
  // Sampling after document parsing and signature work makes freshness bind to
  // the end of verification, not a stale instant captured before it.
  const firstSample = assertRestartDurablePhysicalTrustedClockSample(
    sampleRestartDurablePhysicalTrustedClock(state.trustedClockPort),
  );
  const preliminaryTrust = normalizeSignedTrust(value.signed_current_trust, state, firstSample);
  const preliminaryEvidence = normalizeSignedEvidence(
    value.signed_evidence,
    preliminaryTrust,
    firstSample,
  );
  const sample = assertRestartDurablePhysicalTrustedClockSample(
    sampleRestartDurablePhysicalTrustedClock(state.trustedClockPort),
  );
  const trust = normalizeSignedTrust(value.signed_current_trust, state, sample);
  const evidence = normalizeSignedEvidence(value.signed_evidence, trust, sample);
  if (evidence.signed_evidence_digest !== preliminaryEvidence.signed_evidence_digest
      || trust.document.trust_statement_digest
        !== preliminaryTrust.document.trust_statement_digest) {
    throw backendError("chameleon_availability_verification_fork", "availability documents changed during verification");
  }
  for (const field of REQUEST_FIELDS) {
    if (evidence.payload[field] !== request[field]) {
      throw backendError(
        "chameleon_availability_binding_drift",
        `availability signed evidence ${field} does not match request`,
      );
    }
  }
  const claim = replayClaimFor(request, evidence);
  const receipt = commitReplayClaim(state, trust, evidence, sample, claim);
  const projection = deepFreeze({
    version: CHAMELEON_AVAILABILITY_BACKEND_VERSION,
    backend_port_id: port.port_id,
    backend_mode: port.mode,
    backend_assurance: port.production_ready
      ? "independently_signed_current_evidence_with_production_clock_and_atomic_owner"
      : "independently_signed_current_evidence_with_restart_durable_conformance_clock",
    ...evidence.payload,
    signed_evidence_digest: evidence.signed_evidence_digest,
    trust_statement_digest: trust.document.trust_statement_digest,
    current_time: sample.trusted_utc,
    current_time_earliest: sample.trusted_utc_earliest,
    current_time_latest: sample.trusted_utc_latest,
    current_monotonic_ms: sample.monotonic_ms,
    trusted_clock_mapping_digest: sample.signed_mapping_digest,
    trusted_clock_durable_state_digest: sample.durable_state_digest,
    replay_receipt: receipt,
    independently_signed: true,
    current_trust_verified: true,
    exact_bindings_verified: true,
    atomic_durable_replay_claimed: true,
    runtime_ready: true,
    production_ready: port.production_ready,
    release_ready: false,
    hil_verified: false,
    execution_authority: false,
    readiness_blockers: deepFreeze([
      ...port.production_blockers,
      "chameleon_real_device_hil_not_verified",
      "physical_capability_pack_dispatch_not_enabled",
    ].sort()),
  });
  BACKEND_PROJECTIONS.add(projection);
  return projection;
}

function assertChameleonAvailabilityEvidenceBackendProjection(input) {
  if (!input || utilTypes.isProxy(input) || !Object.isFrozen(input)
      || !BACKEND_PROJECTIONS.has(input)) {
    throw backendError(
      "chameleon_availability_projection_untrusted",
      "a resolver-issued privately branded Chameleon availability backend projection is required",
    );
  }
  return input;
}

module.exports = Object.freeze({
  CHAMELEON_AVAILABILITY_BACKEND_MODE,
  CHAMELEON_AVAILABILITY_BACKEND_VERSION,
  CHAMELEON_AVAILABILITY_EVIDENCE_DOMAIN,
  CHAMELEON_AVAILABILITY_EVIDENCE_IDENTITY_DOMAIN,
  CHAMELEON_AVAILABILITY_EVIDENCE_SIGNING_DOMAIN,
  CHAMELEON_AVAILABILITY_OWNER_CONTEXT_DOMAIN,
  CHAMELEON_AVAILABILITY_TRUST_DOMAIN,
  CHAMELEON_AVAILABILITY_TRUST_SIGNING_DOMAIN,
  MAX_EVIDENCE_LIFETIME_MS,
  MAX_TRUST_LIFETIME_MS,
  assertChameleonAvailabilityEvidenceBackendPort,
  assertChameleonAvailabilityEvidenceBackendProjection,
  chameleonAvailabilityEvidenceIdentityDigest,
  chameleonAvailabilityEvidenceSigningMessage,
  chameleonAvailabilityTrustSigningMessage,
  createChameleonAvailabilityEvidenceBackendPort,
  resolveChameleonAvailabilityEvidenceBackend,
});
