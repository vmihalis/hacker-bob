"use strict";

// Plane-PH trusted wall-time mapping primitive. A monotonic source is mapped to
// UTC by a short-lived signed authority record and revalidated against live
// trust on every sample. The callbacks belong in the broker/worker trust
// domain; the public port holds no signing key, raw resolver, or mutable clock
// state. This module does not itself provide OS isolation, clock-source
// enrollment, durable rollback state, or integration into existing consumers.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const {
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");

const TRUSTED_CLOCK_VERSION = 1;
const TRUSTED_CLOCK_PORT_MODE = "signed_monotonic_wall_mapping";
const TRUSTED_CLOCK_MAPPING_DOMAIN = "hacker-bob/physical-trusted-clock-mapping/v1";
const TRUSTED_CLOCK_SIGNING_DOMAIN = "hacker-bob/physical-trusted-clock-signature/v1";
const MAX_MAPPING_LIFETIME_MS = 24 * 60 * 60 * 1000;
const MAX_UNCERTAINTY_MS = 60_000;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;

const TRUSTED_CLOCK_PORTS = new WeakSet();
const TRUSTED_CLOCK_PORT_STATE = new WeakMap();
const TRUSTED_CLOCK_SAMPLES = new WeakSet();

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = ownKeys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const field of ownKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
  }
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
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
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)
      || (prefix != null
        && (!value.startsWith(`${prefix}:`) || value.length === prefix.length + 1))) {
    throw new Error(`${label} must be a bounded ${prefix || "opaque"} token`);
  }
  return value;
}

function assertInteger(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string") throw new Error(`${label} must be a canonical timestamp`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`${label} must be a canonical ISO-8601 UTC timestamp`);
  }
  return value;
}

function assertEd25519PublicKey(value, label) {
  if (!(value instanceof crypto.KeyObject) || value.type !== "public"
      || value.asymmetricKeyType !== "ed25519") {
    throw new Error(`${label} must be an Ed25519 public KeyObject`);
  }
  return value;
}

function publicKeyDigest(value) {
  const key = assertEd25519PublicKey(value, "trusted clock public key");
  return crypto.createHash("sha256").update(
    key.export({ type: "spki", format: "der" }),
  ).digest("hex");
}

function physicalClockMappingSigningMessage(payloadDigest) {
  const digest = assertDigest(payloadDigest, "trusted clock payload digest");
  return Buffer.from(`${TRUSTED_CLOCK_SIGNING_DOMAIN}\0${digest}`, "utf8");
}

function normalizeMappingPayload(input, label) {
  assertClosedObject(input, label, [
    "version",
    "clock_id",
    "monotonic_epoch_id",
    "mapping_generation",
    "reference_monotonic_ms",
    "reference_utc",
    "max_uncertainty_ms",
    "not_before",
    "expires_at",
    "trust_root_epoch",
    "authority_epoch",
    "revocation_generation",
    "signer_key_id",
    "signer_public_key_digest",
  ]);
  if (input.version !== TRUSTED_CLOCK_VERSION) throw new Error(`${label}.version must be 1`);
  const referenceUtc = assertTimestamp(input.reference_utc, `${label}.reference_utc`);
  const notBefore = assertTimestamp(input.not_before, `${label}.not_before`);
  const expiresAt = assertTimestamp(input.expires_at, `${label}.expires_at`);
  const lifetime = Date.parse(expiresAt) - Date.parse(notBefore);
  if (lifetime <= 0 || lifetime > MAX_MAPPING_LIFETIME_MS) {
    throw new Error(`${label} validity must be positive and no longer than 24 hours`);
  }
  if (Date.parse(referenceUtc) < Date.parse(notBefore)
      || Date.parse(referenceUtc) >= Date.parse(expiresAt)) {
    throw new Error(`${label}.reference_utc must be inside the mapping validity window`);
  }
  return deepFreeze({
    version: TRUSTED_CLOCK_VERSION,
    clock_id: assertToken(input.clock_id, `${label}.clock_id`, "physical-clock"),
    monotonic_epoch_id: assertDigest(input.monotonic_epoch_id, `${label}.monotonic_epoch_id`),
    mapping_generation: assertInteger(input.mapping_generation, `${label}.mapping_generation`, 1),
    reference_monotonic_ms: assertInteger(
      input.reference_monotonic_ms,
      `${label}.reference_monotonic_ms`,
      0,
    ),
    reference_utc: referenceUtc,
    max_uncertainty_ms: assertInteger(
      input.max_uncertainty_ms,
      `${label}.max_uncertainty_ms`,
      0,
      MAX_UNCERTAINTY_MS,
    ),
    not_before: notBefore,
    expires_at: expiresAt,
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
      0,
    ),
    signer_key_id: assertToken(input.signer_key_id, `${label}.signer_key_id`, "clock-key"),
    signer_public_key_digest: assertDigest(
      input.signer_public_key_digest,
      `${label}.signer_public_key_digest`,
    ),
  });
}

function normalizeSignedPhysicalClockMapping(input, label = "signed_physical_clock_mapping") {
  assertClosedObject(input, label, [
    "version", "domain", "payload", "payload_digest", "scheme", "signature",
    "signed_mapping_digest",
  ]);
  if (input.version !== TRUSTED_CLOCK_VERSION || input.domain !== TRUSTED_CLOCK_MAPPING_DOMAIN
      || input.scheme !== "ed25519") {
    throw new Error(`${label} domain, version, or signature scheme is invalid`);
  }
  const payload = normalizeMappingPayload(input.payload, `${label}.payload`);
  const payloadDigest = assertDigest(input.payload_digest, `${label}.payload_digest`);
  if (payloadDigest !== hashCanonicalJson(payload)) {
    throw new Error(`${label}.payload_digest does not bind the canonical payload`);
  }
  if (typeof input.signature !== "string" || !SIGNATURE_PATTERN.test(input.signature)) {
    throw new Error(`${label}.signature must be canonical Ed25519 base64url`);
  }
  const signature = Buffer.from(input.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== input.signature) {
    throw new Error(`${label}.signature must be canonical Ed25519 base64url`);
  }
  const basis = {
    version: TRUSTED_CLOCK_VERSION,
    domain: TRUSTED_CLOCK_MAPPING_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature: input.signature,
  };
  const signedMappingDigest = assertDigest(
    input.signed_mapping_digest,
    `${label}.signed_mapping_digest`,
  );
  if (signedMappingDigest !== hashCanonicalJson(basis)) {
    throw new Error(`${label}.signed_mapping_digest is invalid`);
  }
  return deepFreeze({ ...basis, signed_mapping_digest: signedMappingDigest });
}

function normalizeCurrentClockTrust(input, label) {
  assertClosedObject(input, label, [
    "version",
    "trusted",
    "revoked",
    "clock_id",
    "monotonic_epoch_id",
    "current_mapping_generation",
    "current_signed_mapping_digest",
    "trust_root_epoch",
    "authority_epoch",
    "revocation_generation",
    "signer_key_id",
    "signer_public_key_digest",
    "public_key",
  ]);
  if (input.version !== TRUSTED_CLOCK_VERSION || typeof input.trusted !== "boolean"
      || typeof input.revoked !== "boolean") {
    throw new Error(`${label} version/trust disposition is invalid`);
  }
  const key = assertEd25519PublicKey(input.public_key, `${label}.public_key`);
  const keyDigest = publicKeyDigest(key);
  if (assertDigest(input.signer_public_key_digest, `${label}.signer_public_key_digest`)
      !== keyDigest) {
    throw new Error(`${label}.signer_public_key_digest does not bind public_key`);
  }
  return Object.freeze({
    version: TRUSTED_CLOCK_VERSION,
    trusted: input.trusted,
    revoked: input.revoked,
    clock_id: assertToken(input.clock_id, `${label}.clock_id`, "physical-clock"),
    monotonic_epoch_id: assertDigest(input.monotonic_epoch_id, `${label}.monotonic_epoch_id`),
    current_mapping_generation: assertInteger(
      input.current_mapping_generation,
      `${label}.current_mapping_generation`,
      1,
    ),
    current_signed_mapping_digest: assertDigest(
      input.current_signed_mapping_digest,
      `${label}.current_signed_mapping_digest`,
    ),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
      0,
    ),
    signer_key_id: assertToken(input.signer_key_id, `${label}.signer_key_id`, "clock-key"),
    signer_public_key_digest: keyDigest,
    public_key: key,
  });
}

function createPhysicalTrustedClockPort(input = {}) {
  assertClosedObject(input, "physical_trusted_clock_port", [
    "port_id",
    "clock_id",
    "monotonic_epoch_id",
    "uncertainty_ceiling_ms",
    "read_monotonic_ms",
    "read_signed_mapping",
    "resolve_current_trust",
  ]);
  for (const field of ["read_monotonic_ms", "read_signed_mapping", "resolve_current_trust"]) {
    if (typeof input[field] !== "function") {
      throw new Error(`physical_trusted_clock_port.${field} must be a synchronous function`);
    }
  }
  const port = deepFreeze({
    version: TRUSTED_CLOCK_VERSION,
    port_id: assertIdentifier(input.port_id, "physical_trusted_clock_port.port_id"),
    clock_id: assertToken(input.clock_id, "physical_trusted_clock_port.clock_id", "physical-clock"),
    monotonic_epoch_id: assertDigest(
      input.monotonic_epoch_id,
      "physical_trusted_clock_port.monotonic_epoch_id",
    ),
    uncertainty_ceiling_ms: assertInteger(
      input.uncertainty_ceiling_ms,
      "physical_trusted_clock_port.uncertainty_ceiling_ms",
      0,
      MAX_UNCERTAINTY_MS,
    ),
    mode: TRUSTED_CLOCK_PORT_MODE,
  });
  TRUSTED_CLOCK_PORTS.add(port);
  TRUSTED_CLOCK_PORT_STATE.set(port, {
    read_monotonic_ms: input.read_monotonic_ms,
    read_signed_mapping: input.read_signed_mapping,
    resolve_current_trust: input.resolve_current_trust,
    last_monotonic_ms: null,
    last_trusted_utc_ms: null,
    last_trusted_utc_earliest_ms: null,
    last_trusted_utc_latest_ms: null,
    last_mapping_generation: null,
    last_mapping_digest: null,
    last_trust_root_epoch: null,
    last_authority_epoch: null,
    last_revocation_generation: null,
    in_flight: false,
  });
  return port;
}

function assertPhysicalTrustedClockPort(port) {
  if (!port || typeof port !== "object" || !Object.isFrozen(port)
      || !TRUSTED_CLOCK_PORTS.has(port) || !TRUSTED_CLOCK_PORT_STATE.has(port)) {
    throw new Error("physical trusted clock must be a privately branded live port");
  }
  return port;
}

function assertPhysicalTrustedClockSample(sample) {
  if (!sample || typeof sample !== "object" || !Object.isFrozen(sample)
      || !TRUSTED_CLOCK_SAMPLES.has(sample)) {
    throw new Error("physical trusted clock sample must come from a privately branded live port");
  }
  return sample;
}

function assertPhysicalTrustedClockValidityWindow(
  sampleInput,
  windowInput,
  label = "trusted_clock_validity_window",
) {
  const sample = assertPhysicalTrustedClockSample(sampleInput);
  assertClosedObject(windowInput, label, ["not_before", "expires_at"]);
  const notBefore = assertTimestamp(windowInput.not_before, `${label}.not_before`);
  const expiresAt = assertTimestamp(windowInput.expires_at, `${label}.expires_at`);
  if (Date.parse(notBefore) >= Date.parse(expiresAt)) {
    throw new Error(`${label} must be a non-empty validity window`);
  }
  if (Date.parse(sample.trusted_utc_earliest) < Date.parse(notBefore)) {
    throw new Error(`${label} is not yet admissible under trusted clock uncertainty`);
  }
  if (Date.parse(sample.trusted_utc_latest) >= Date.parse(expiresAt)) {
    throw new Error(`${label} has expired under trusted clock uncertainty`);
  }
  return sample;
}

function assertPhysicalTrustedClockTimestampNonFuture(
  sampleInput,
  claimedTimestamp,
  label = "trusted_clock_claimed_timestamp",
) {
  const sample = assertPhysicalTrustedClockSample(sampleInput);
  const claimed = assertTimestamp(claimedTimestamp, label);
  if (Date.parse(claimed) > Date.parse(sample.trusted_utc_earliest)) {
    throw new Error(`${label} is in the future under trusted clock uncertainty`);
  }
  return claimed;
}

function callSynchronous(callback, label, argument) {
  let value;
  try {
    value = argument === undefined ? callback() : callback(argument);
  } catch {
    throw new Error(`${label} is unavailable`);
  }
  let then;
  try {
    then = value != null && (typeof value === "object" || typeof value === "function")
      ? value.then
      : undefined;
  } catch {
    throw new Error(`${label} is unavailable`);
  }
  if (typeof then === "function") {
    // A rejected native Promise must not become an unhandled rejection after
    // the synchronous trust boundary has already failed closed. Generic
    // thenables are never invoked.
    if (utilTypes.isPromise(value)) {
      Promise.prototype.then.call(value, undefined, () => {});
    }
    throw new Error(`${label} must be synchronous`);
  }
  return value;
}

function samplePhysicalTrustedClockInternal(port, state) {
  const initialMonotonicMs = assertInteger(
    callSynchronous(state.read_monotonic_ms, "trusted monotonic source"),
    "initial trusted monotonic sample",
    0,
  );
  if (state.last_monotonic_ms != null && initialMonotonicMs < state.last_monotonic_ms) {
    throw new Error("trusted monotonic clock moved backwards");
  }
  const mapping = normalizeSignedPhysicalClockMapping(
    callSynchronous(state.read_signed_mapping, "signed clock mapping source"),
  );
  const payload = mapping.payload;
  if (payload.clock_id !== port.clock_id
      || payload.monotonic_epoch_id !== port.monotonic_epoch_id) {
    throw new Error("signed clock mapping belongs to another clock or monotonic epoch");
  }
  if (payload.max_uncertainty_ms > port.uncertainty_ceiling_ms) {
    throw new Error("signed clock mapping exceeds the enrolled uncertainty ceiling");
  }
  const trustQuery = deepFreeze({
    version: TRUSTED_CLOCK_VERSION,
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    mapping_generation: payload.mapping_generation,
    trust_root_epoch: payload.trust_root_epoch,
    authority_epoch: payload.authority_epoch,
    revocation_generation: payload.revocation_generation,
    signer_key_id: payload.signer_key_id,
    signer_public_key_digest: payload.signer_public_key_digest,
    signed_mapping_digest: mapping.signed_mapping_digest,
  });
  const trust = normalizeCurrentClockTrust(
    callSynchronous(state.resolve_current_trust, "trusted clock authority", trustQuery),
    "current_clock_trust",
  );
  if (!trust.trusted || trust.revoked) {
    throw new Error("signed clock mapping is no longer trusted or current");
  }
  for (const field of [
    "clock_id",
    "monotonic_epoch_id",
    "trust_root_epoch",
    "authority_epoch",
    "revocation_generation",
    "signer_key_id",
    "signer_public_key_digest",
  ]) {
    if (trust[field] !== payload[field]) throw new Error(`signed clock mapping ${field} is stale`);
  }
  if (trust.current_mapping_generation !== payload.mapping_generation
      || trust.current_signed_mapping_digest !== mapping.signed_mapping_digest) {
    throw new Error("signed clock mapping is no longer the authority's exact current mapping");
  }
  let verified = false;
  try {
    verified = crypto.verify(
      null,
      physicalClockMappingSigningMessage(mapping.payload_digest),
      trust.public_key,
      Buffer.from(mapping.signature, "base64url"),
    );
  } catch {
    verified = false;
  }
  if (!verified) throw new Error("signed clock mapping signature is invalid");

  // Mapping/trust sources and signature verification can consume a meaningful
  // part of a short authority window. Re-read the monotonic source after those
  // operations so the returned wall-time interval describes the end of trust
  // verification, rather than a stale instant from before a blocking resolver.
  const monotonicMs = assertInteger(
    callSynchronous(state.read_monotonic_ms, "trusted monotonic source"),
    "final trusted monotonic sample",
    0,
  );
  if (monotonicMs < initialMonotonicMs
      || (state.last_monotonic_ms != null && monotonicMs < state.last_monotonic_ms)) {
    throw new Error("trusted monotonic clock moved backwards");
  }
  if (monotonicMs < payload.reference_monotonic_ms) {
    throw new Error("trusted monotonic sample predates the signed clock mapping reference");
  }

  if (state.last_mapping_generation != null) {
    if (payload.mapping_generation < state.last_mapping_generation) {
      throw new Error("signed clock mapping generation moved backwards");
    }
    if (payload.mapping_generation === state.last_mapping_generation
        && mapping.signed_mapping_digest !== state.last_mapping_digest) {
      throw new Error("signed clock mapping forked at the current generation");
    }
  }
  for (const [field, stateField] of [
    ["trust_root_epoch", "last_trust_root_epoch"],
    ["authority_epoch", "last_authority_epoch"],
    ["revocation_generation", "last_revocation_generation"],
  ]) {
    if (state[stateField] != null && payload[field] < state[stateField]) {
      throw new Error(`signed clock mapping ${field} moved backwards`);
    }
  }
  const trustedUtcMs = Date.parse(payload.reference_utc)
    + (monotonicMs - payload.reference_monotonic_ms);
  const trustedUtcEarliestMs = trustedUtcMs - payload.max_uncertainty_ms;
  const trustedUtcLatestMs = trustedUtcMs + payload.max_uncertainty_ms;
  if (!Number.isSafeInteger(trustedUtcMs)
      || !Number.isSafeInteger(trustedUtcEarliestMs)
      || !Number.isSafeInteger(trustedUtcLatestMs)
      || trustedUtcEarliestMs < Date.parse(payload.not_before)
      || trustedUtcLatestMs >= Date.parse(payload.expires_at)) {
    throw new Error("trusted clock sample is outside the signed mapping validity window");
  }
  if (state.last_trusted_utc_ms != null && trustedUtcMs < state.last_trusted_utc_ms) {
    throw new Error("signed trusted wall clock moved backwards");
  }
  if ((state.last_trusted_utc_earliest_ms != null
        && trustedUtcEarliestMs < state.last_trusted_utc_earliest_ms)
      || (state.last_trusted_utc_latest_ms != null
        && trustedUtcLatestMs < state.last_trusted_utc_latest_ms)) {
    throw new Error("signed trusted wall-clock uncertainty interval moved backwards");
  }

  state.last_monotonic_ms = monotonicMs;
  state.last_trusted_utc_ms = trustedUtcMs;
  state.last_trusted_utc_earliest_ms = trustedUtcEarliestMs;
  state.last_trusted_utc_latest_ms = trustedUtcLatestMs;
  state.last_mapping_generation = payload.mapping_generation;
  state.last_mapping_digest = mapping.signed_mapping_digest;
  state.last_trust_root_epoch = payload.trust_root_epoch;
  state.last_authority_epoch = payload.authority_epoch;
  state.last_revocation_generation = payload.revocation_generation;
  const sample = deepFreeze({
    version: TRUSTED_CLOCK_VERSION,
    clock_id: port.clock_id,
    monotonic_epoch_id: port.monotonic_epoch_id,
    mapping_generation: payload.mapping_generation,
    monotonic_ms: monotonicMs,
    trusted_utc: new Date(trustedUtcMs).toISOString(),
    trusted_utc_earliest: new Date(trustedUtcEarliestMs).toISOString(),
    trusted_utc_latest: new Date(trustedUtcLatestMs).toISOString(),
    max_uncertainty_ms: payload.max_uncertainty_ms,
    signed_mapping_digest: mapping.signed_mapping_digest,
    trust_root_epoch: payload.trust_root_epoch,
    authority_epoch: payload.authority_epoch,
    revocation_generation: payload.revocation_generation,
  });
  TRUSTED_CLOCK_SAMPLES.add(sample);
  return sample;
}

function samplePhysicalTrustedClock(port) {
  assertPhysicalTrustedClockPort(port);
  const state = TRUSTED_CLOCK_PORT_STATE.get(port);
  if (state.in_flight) throw new Error("physical trusted clock sample is already in progress");
  state.in_flight = true;
  try {
    return samplePhysicalTrustedClockInternal(port, state);
  } finally {
    state.in_flight = false;
  }
}

module.exports = {
  MAX_MAPPING_LIFETIME_MS,
  MAX_UNCERTAINTY_MS,
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  TRUSTED_CLOCK_PORT_MODE,
  TRUSTED_CLOCK_SIGNING_DOMAIN,
  TRUSTED_CLOCK_VERSION,
  assertPhysicalTrustedClockSample,
  assertPhysicalTrustedClockPort,
  assertPhysicalTrustedClockTimestampNonFuture,
  assertPhysicalTrustedClockValidityWindow,
  createPhysicalTrustedClockPort,
  normalizeSignedPhysicalClockMapping,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
  samplePhysicalTrustedClock,
};
