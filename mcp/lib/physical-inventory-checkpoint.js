"use strict";

// PH-IP1 provider-neutral inventory checkpoint contract. A checkpoint can be
// captured only through a privately branded, Ed25519-authenticated live source
// and is revalidated against that source plus Bob's signed monotonic wall clock
// before it can be treated as current. This slice is deliberately fixture-level:
// it does not claim hardware-in-loop coverage, durable revocation, OS custody,
// or production source enrollment.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const {
  assertNoPublicByteMaterial,
} = require("./instrument-provider-contract.js");
const {
  normalizeOpaqueRef,
} = require("./physical-quantities.js");
const {
  assertPhysicalTrustedClockPort,
  assertPhysicalTrustedClockTimestampNonFuture,
  assertPhysicalTrustedClockValidityWindow,
  samplePhysicalTrustedClock,
  TRUSTED_CLOCK_PORT_MODE,
} = require("./physical-trusted-clock.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");

const PHYSICAL_INVENTORY_CHECKPOINT_VERSION = 1;
const PHYSICAL_INVENTORY_SOURCE_MODE = "authenticated_fixture_source";
const PHYSICAL_INVENTORY_CAPTURE_DOMAIN = "hacker-bob/physical-inventory-capture/v1";
const PHYSICAL_INVENTORY_SIGNING_DOMAIN = "hacker-bob/physical-inventory-signature/v1";
const MAX_CHECKPOINT_LIFETIME_MS = 24 * 60 * 60 * 1000;

const REQUIRED_OPERATION_IDS = Object.freeze([
  "instrument.capabilities",
  "instrument.health",
  "instrument.inventory",
]);
const SOURCE_DISPOSITIONS = Object.freeze(["current", "revoked", "disconnected"]);
const ASSURANCE_STATUS_VALUES = deepFreeze({
  identity_enrollment: ["unverified", "enrolled", "attested"],
  firmware_provenance: ["unknown", "self_reported", "verified_artifact", "attested_boot"],
  command_surface_conformance: ["unverified", "bootstrap_allowlisted", "conformance_tested"],
  transport_trust: ["untrusted", "local_observed", "authenticated", "attested"],
});
const READINESS_BLOCKERS = Object.freeze([
  "durable_revocation_state_missing",
  "hardware_in_loop_attestation_missing",
  "os_device_custody_integration_missing",
  "production_source_enrollment_missing",
]);

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;

const SOURCE_PORTS = new WeakSet();
const SOURCE_PORT_STATE = new WeakMap();
const CHECKPOINTS = new WeakSet();
const CHECKPOINT_STATE = new WeakMap();

const BINDING_FIELDS = Object.freeze([
  "session_nucleus_hash",
  "physical_scope_axis_digest",
  "instrument_ref",
  "enrollment_candidate_ref",
  "provider_id",
  "provider_descriptor_digest",
  "provider_binary_digest",
  "transport_digest",
  "bootstrap_manifest_digest",
  "connection_generation",
]);

const RECEIPT_FIELDS = Object.freeze([
  "version",
  "operation_id",
  ...BINDING_FIELDS,
  "execution_request_digest",
  "signed_grant_digest",
  "operation_digest",
  "response_digest",
  "receipt_ref",
  "observed_at",
  "receipt_digest",
]);

const INVARIANT_WITNESS_FIELDS = Object.freeze([
  "version",
  ...BINDING_FIELDS,
  "rf_state",
  "rf_off_witness_digest",
  "mode_unchanged",
  "mode_unchanged_witness_digest",
  "workspace_unchanged",
  "workspace_unchanged_witness_digest",
  "witness_authentication_digest",
  "witnessed_at",
  "witness_set_digest",
]);

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = keys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const field of keys) {
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
      || (prefix != null && !value.startsWith(`${prefix}:`))) {
    throw new Error(`${label} must be a bounded ${prefix || "opaque"} token`);
  }
  return value;
}

function assertInteger(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${label} must be a safe integer >= ${minimum}`);
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

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function selectFields(input, fields) {
  return Object.fromEntries(fields.map((field) => [field, input[field]]));
}

function normalizeBindings(input, label = "physical_inventory_bindings") {
  assertNoPublicByteMaterial(input, label);
  assertClosedObject(input, label, BINDING_FIELDS);
  return deepFreeze({
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    physical_scope_axis_digest: assertDigest(
      input.physical_scope_axis_digest,
      `${label}.physical_scope_axis_digest`,
    ),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    enrollment_candidate_ref: normalizeOpaqueRef(
      input.enrollment_candidate_ref,
      `${label}.enrollment_candidate_ref`,
      { prefix: "enrollment-candidate" },
    ),
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    provider_binary_digest: assertDigest(
      input.provider_binary_digest,
      `${label}.provider_binary_digest`,
    ),
    transport_digest: assertDigest(input.transport_digest, `${label}.transport_digest`),
    bootstrap_manifest_digest: assertDigest(
      input.bootstrap_manifest_digest,
      `${label}.bootstrap_manifest_digest`,
    ),
    connection_generation: assertInteger(
      input.connection_generation,
      `${label}.connection_generation`,
      1,
    ),
  });
}

function assertBindingsMatch(actual, expected, label) {
  for (const field of BINDING_FIELDS) {
    if (actual[field] !== expected[field]) {
      throw new Error(`${label}.${field} is detached from the checkpoint bindings`);
    }
  }
}

function normalizeReceipt(input, label) {
  assertClosedObject(input, label, RECEIPT_FIELDS);
  if (input.version !== PHYSICAL_INVENTORY_CHECKPOINT_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_INVENTORY_CHECKPOINT_VERSION}`);
  }
  const operationId = assertEnum(input.operation_id, REQUIRED_OPERATION_IDS, `${label}.operation_id`);
  const bindings = normalizeBindings(selectFields(input, BINDING_FIELDS), `${label}.bindings`);
  const body = {
    version: PHYSICAL_INVENTORY_CHECKPOINT_VERSION,
    operation_id: operationId,
    ...bindings,
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    signed_grant_digest: assertDigest(input.signed_grant_digest, `${label}.signed_grant_digest`),
    operation_digest: assertDigest(input.operation_digest, `${label}.operation_digest`),
    response_digest: assertDigest(input.response_digest, `${label}.response_digest`),
    receipt_ref: normalizeOpaqueRef(input.receipt_ref, `${label}.receipt_ref`, {
      prefix: "bootstrap-receipt",
    }),
    observed_at: assertTimestamp(input.observed_at, `${label}.observed_at`),
  };
  const receiptDigest = assertDigest(input.receipt_digest, `${label}.receipt_digest`);
  if (receiptDigest !== hashCanonicalJson(body)) {
    throw new Error(`${label}.receipt_digest does not bind the canonical receipt`);
  }
  return deepFreeze({ ...body, receipt_digest: receiptDigest });
}

function normalizeInvariantWitness(input, label) {
  assertClosedObject(input, label, INVARIANT_WITNESS_FIELDS);
  if (input.version !== PHYSICAL_INVENTORY_CHECKPOINT_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_INVENTORY_CHECKPOINT_VERSION}`);
  }
  const bindings = normalizeBindings(selectFields(input, BINDING_FIELDS), `${label}.bindings`);
  if (input.rf_state !== "off") throw new Error(`${label}.rf_state must be off`);
  if (input.mode_unchanged !== true) throw new Error(`${label}.mode_unchanged must be true`);
  if (input.workspace_unchanged !== true) {
    throw new Error(`${label}.workspace_unchanged must be true`);
  }
  const body = {
    version: PHYSICAL_INVENTORY_CHECKPOINT_VERSION,
    ...bindings,
    rf_state: "off",
    rf_off_witness_digest: assertDigest(
      input.rf_off_witness_digest,
      `${label}.rf_off_witness_digest`,
    ),
    mode_unchanged: true,
    mode_unchanged_witness_digest: assertDigest(
      input.mode_unchanged_witness_digest,
      `${label}.mode_unchanged_witness_digest`,
    ),
    workspace_unchanged: true,
    workspace_unchanged_witness_digest: assertDigest(
      input.workspace_unchanged_witness_digest,
      `${label}.workspace_unchanged_witness_digest`,
    ),
    witness_authentication_digest: assertDigest(
      input.witness_authentication_digest,
      `${label}.witness_authentication_digest`,
    ),
    witnessed_at: assertTimestamp(input.witnessed_at, `${label}.witnessed_at`),
  };
  const witnessSetDigest = assertDigest(input.witness_set_digest, `${label}.witness_set_digest`);
  if (witnessSetDigest !== hashCanonicalJson(body)) {
    throw new Error(`${label}.witness_set_digest does not bind the invariant witnesses`);
  }
  return deepFreeze({ ...body, witness_set_digest: witnessSetDigest });
}

function normalizeAssuranceClaims(input, label) {
  assertClosedObject(input, label, [
    "identity_enrollment",
    "firmware_provenance",
    "command_surface_conformance",
    "transport_trust",
    "claims_digest",
  ]);
  const body = {};
  for (const axis of [
    "identity_enrollment",
    "firmware_provenance",
    "command_surface_conformance",
    "transport_trust",
  ]) {
    const axisLabel = `${label}.${axis}`;
    assertClosedObject(input[axis], axisLabel, ["status", "evidence_digest"]);
    body[axis] = deepFreeze({
      status: assertEnum(input[axis].status, ASSURANCE_STATUS_VALUES[axis], `${axisLabel}.status`),
      evidence_digest: assertDigest(input[axis].evidence_digest, `${axisLabel}.evidence_digest`),
    });
  }
  const claimsDigest = assertDigest(input.claims_digest, `${label}.claims_digest`);
  if (claimsDigest !== hashCanonicalJson(body)) {
    throw new Error(`${label}.claims_digest does not bind the four assurance axes`);
  }
  return deepFreeze({ ...body, claims_digest: claimsDigest });
}

function normalizeCapturePayload(input, label = "physical_inventory_capture.payload") {
  assertClosedObject(input, label, [
    "version",
    "source_id",
    ...BINDING_FIELDS,
    "assurance_profile_id",
    "assurance_claims",
    "execution_receipts",
    "invariant_witness",
    "captured_at",
    "valid_from",
    "expires_at",
    "attested_at",
    "source_trust_epoch",
    "source_revocation_generation",
  ]);
  if (input.version !== PHYSICAL_INVENTORY_CHECKPOINT_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_INVENTORY_CHECKPOINT_VERSION}`);
  }
  const bindings = normalizeBindings(selectFields(input, BINDING_FIELDS), `${label}.bindings`);
  if (!Array.isArray(input.execution_receipts)
      || input.execution_receipts.length !== REQUIRED_OPERATION_IDS.length) {
    throw new Error(`${label}.execution_receipts must contain the exact three-operation set`);
  }
  for (let index = 0; index < input.execution_receipts.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(input.execution_receipts, index)) {
      throw new Error(`${label}.execution_receipts must be a dense three-operation array`);
    }
  }
  const receipts = input.execution_receipts
    .map((receipt, index) => normalizeReceipt(receipt, `${label}.execution_receipts[${index}]`))
    .sort((left, right) => left.operation_id.localeCompare(right.operation_id));
  if (new Set(receipts.map((receipt) => receipt.operation_id)).size !== REQUIRED_OPERATION_IDS.length
      || receipts.some((receipt, index) => receipt.operation_id !== REQUIRED_OPERATION_IDS[index])) {
    throw new Error(`${label}.execution_receipts must contain inventory, capabilities, and health exactly once`);
  }
  for (const receipt of receipts) {
    assertBindingsMatch(receipt, bindings, `${label}.${receipt.operation_id}`);
  }
  const invariantWitness = normalizeInvariantWitness(
    input.invariant_witness,
    `${label}.invariant_witness`,
  );
  assertBindingsMatch(invariantWitness, bindings, `${label}.invariant_witness`);

  const capturedAt = assertTimestamp(input.captured_at, `${label}.captured_at`);
  const validFrom = assertTimestamp(input.valid_from, `${label}.valid_from`);
  const expiresAt = assertTimestamp(input.expires_at, `${label}.expires_at`);
  const attestedAt = assertTimestamp(input.attested_at, `${label}.attested_at`);
  const validFromMs = Date.parse(validFrom);
  const capturedAtMs = Date.parse(capturedAt);
  const expiresAtMs = Date.parse(expiresAt);
  const attestedAtMs = Date.parse(attestedAt);
  if (validFromMs > capturedAtMs || capturedAtMs > attestedAtMs || attestedAtMs >= expiresAtMs) {
    throw new Error(`${label} timestamps must satisfy valid_from <= captured_at <= attested_at < expires_at`);
  }
  if (expiresAtMs - validFromMs > MAX_CHECKPOINT_LIFETIME_MS) {
    throw new Error(`${label} validity cannot exceed ${MAX_CHECKPOINT_LIFETIME_MS}ms`);
  }
  for (const receipt of receipts) {
    const observedAtMs = Date.parse(receipt.observed_at);
    if (observedAtMs < validFromMs || observedAtMs > capturedAtMs) {
      throw new Error(
        `${label}.${receipt.operation_id}.observed_at must be inside valid_from through captured_at`,
      );
    }
  }
  const witnessedAtMs = Date.parse(invariantWitness.witnessed_at);
  if (witnessedAtMs < validFromMs || witnessedAtMs > capturedAtMs) {
    throw new Error(
      `${label}.invariant_witness.witnessed_at must be inside valid_from through captured_at`,
    );
  }

  return deepFreeze({
    version: PHYSICAL_INVENTORY_CHECKPOINT_VERSION,
    source_id: assertIdentifier(input.source_id, `${label}.source_id`),
    ...bindings,
    assurance_profile_id: assertIdentifier(
      input.assurance_profile_id,
      `${label}.assurance_profile_id`,
    ),
    assurance_claims: normalizeAssuranceClaims(
      input.assurance_claims,
      `${label}.assurance_claims`,
    ),
    execution_receipts: receipts,
    invariant_witness: invariantWitness,
    captured_at: capturedAt,
    valid_from: validFrom,
    expires_at: expiresAt,
    attested_at: attestedAt,
    source_trust_epoch: assertInteger(
      input.source_trust_epoch,
      `${label}.source_trust_epoch`,
      1,
    ),
    source_revocation_generation: assertInteger(
      input.source_revocation_generation,
      `${label}.source_revocation_generation`,
      0,
    ),
  });
}

function assertEd25519PublicKey(value, label) {
  if (!(value instanceof crypto.KeyObject) || value.type !== "public"
      || value.asymmetricKeyType !== "ed25519") {
    throw new Error(`${label} must be an Ed25519 public KeyObject`);
  }
  return value;
}

function publicKeyDigest(publicKey) {
  return crypto.createHash("sha256").update(
    assertEd25519PublicKey(publicKey, "physical inventory source public key")
      .export({ type: "spki", format: "der" }),
  ).digest("hex");
}

function physicalInventoryCaptureSigningMessage(input) {
  assertClosedObject(input, "physical_inventory_capture_signing_basis", [
    "payload_digest",
    "signer_key_id",
    "signer_public_key_digest",
  ]);
  const signingInputDigest = hashCanonicalJson({
    domain: PHYSICAL_INVENTORY_SIGNING_DOMAIN,
    payload_digest: assertDigest(input.payload_digest, "signing_basis.payload_digest"),
    signer_key_id: assertToken(input.signer_key_id, "signing_basis.signer_key_id", "inventory-key"),
    signer_public_key_digest: assertDigest(
      input.signer_public_key_digest,
      "signing_basis.signer_public_key_digest",
    ),
  });
  return Buffer.from(signingInputDigest, "hex");
}

function normalizeAuthenticatedCapture(input, source, state) {
  assertNoPublicByteMaterial(input, "physical_inventory_capture");
  assertClosedObject(input, "physical_inventory_capture", [
    "version",
    "domain",
    "payload",
    "payload_digest",
    "scheme",
    "signer_key_id",
    "signer_public_key_digest",
    "signature",
    "authenticated_capture_digest",
  ]);
  if (input.version !== PHYSICAL_INVENTORY_CHECKPOINT_VERSION
      || input.domain !== PHYSICAL_INVENTORY_CAPTURE_DOMAIN
      || input.scheme !== "ed25519") {
    throw new Error("physical inventory capture domain, version, or signature scheme is invalid");
  }
  const payload = normalizeCapturePayload(input.payload);
  const payloadDigest = assertDigest(input.payload_digest, "physical_inventory_capture.payload_digest");
  if (payloadDigest !== hashCanonicalJson(payload)) {
    throw new Error("physical_inventory_capture.payload_digest does not bind the canonical payload");
  }
  const signerKeyId = assertToken(
    input.signer_key_id,
    "physical_inventory_capture.signer_key_id",
    "inventory-key",
  );
  const signerPublicKeyDigest = assertDigest(
    input.signer_public_key_digest,
    "physical_inventory_capture.signer_public_key_digest",
  );
  if (payload.source_id !== source.source_id
      || signerKeyId !== source.signer_key_id
      || signerPublicKeyDigest !== source.signer_public_key_digest) {
    throw new Error("physical inventory capture is detached from its authenticated source");
  }
  if (typeof input.signature !== "string" || !SIGNATURE_PATTERN.test(input.signature)) {
    throw new Error("physical_inventory_capture.signature must be canonical Ed25519 base64url");
  }
  const signature = Buffer.from(input.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== input.signature) {
    throw new Error("physical_inventory_capture.signature must be canonical Ed25519 base64url");
  }
  let verified = false;
  try {
    verified = crypto.verify(
      null,
      physicalInventoryCaptureSigningMessage({
        payload_digest: payloadDigest,
        signer_key_id: signerKeyId,
        signer_public_key_digest: signerPublicKeyDigest,
      }),
      state.signer_public_key,
      signature,
    );
  } catch {
    verified = false;
  }
  if (!verified) throw new Error("physical inventory capture signature is invalid");

  const basis = {
    version: PHYSICAL_INVENTORY_CHECKPOINT_VERSION,
    domain: PHYSICAL_INVENTORY_CAPTURE_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signer_key_id: signerKeyId,
    signer_public_key_digest: signerPublicKeyDigest,
    signature: input.signature,
  };
  const authenticatedCaptureDigest = assertDigest(
    input.authenticated_capture_digest,
    "physical_inventory_capture.authenticated_capture_digest",
  );
  if (authenticatedCaptureDigest !== hashCanonicalJson(basis)) {
    throw new Error("physical_inventory_capture.authenticated_capture_digest is invalid");
  }
  return deepFreeze({ ...basis, authenticated_capture_digest: authenticatedCaptureDigest });
}

function callSynchronous(callback, label, argument) {
  let value;
  try {
    value = callback(argument);
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
    if (utilTypes.isPromise(value)) Promise.prototype.then.call(value, undefined, () => {});
    throw new Error(`${label} must be synchronous`);
  }
  return value;
}

function normalizeSourceTrust(input, label = "physical_inventory_source_trust") {
  assertNoPublicByteMaterial(input, label);
  assertClosedObject(input, label, [
    "version",
    "source_id",
    "disposition",
    "source_trust_epoch",
    "source_revocation_generation",
    "signer_key_id",
    "signer_public_key_digest",
    "current_connection_generation",
  ]);
  if (input.version !== PHYSICAL_INVENTORY_CHECKPOINT_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_INVENTORY_CHECKPOINT_VERSION}`);
  }
  return deepFreeze({
    version: PHYSICAL_INVENTORY_CHECKPOINT_VERSION,
    source_id: assertIdentifier(input.source_id, `${label}.source_id`),
    disposition: assertEnum(input.disposition, SOURCE_DISPOSITIONS, `${label}.disposition`),
    source_trust_epoch: assertInteger(input.source_trust_epoch, `${label}.source_trust_epoch`, 1),
    source_revocation_generation: assertInteger(
      input.source_revocation_generation,
      `${label}.source_revocation_generation`,
      0,
    ),
    signer_key_id: assertToken(input.signer_key_id, `${label}.signer_key_id`, "inventory-key"),
    signer_public_key_digest: assertDigest(
      input.signer_public_key_digest,
      `${label}.signer_public_key_digest`,
    ),
    current_connection_generation: assertInteger(
      input.current_connection_generation,
      `${label}.current_connection_generation`,
      1,
    ),
  });
}

function sourceTrustQuery(source, capture) {
  const payload = capture.payload;
  return deepFreeze({
    version: PHYSICAL_INVENTORY_CHECKPOINT_VERSION,
    source_id: source.source_id,
    authenticated_capture_digest: capture.authenticated_capture_digest,
    source_trust_epoch: payload.source_trust_epoch,
    source_revocation_generation: payload.source_revocation_generation,
    signer_key_id: capture.signer_key_id,
    signer_public_key_digest: capture.signer_public_key_digest,
    connection_generation: payload.connection_generation,
  });
}

function readSourceDisposition(source, state, capture) {
  let rawTrust;
  try {
    rawTrust = callSynchronous(
      state.resolve_current_trust,
      "physical inventory current trust resolver",
      sourceTrustQuery(source, capture),
    );
  } catch (error) {
    if (/ is unavailable$/.test(error.message)) return "disconnected";
    throw error;
  }
  const trust = normalizeSourceTrust(rawTrust);
  if (trust.source_id !== source.source_id) {
    throw new Error("physical inventory current trust belongs to another source");
  }
  if (trust.disposition !== "current") return trust.disposition;
  if (trust.current_connection_generation !== capture.payload.connection_generation) {
    return "disconnected";
  }
  if (trust.source_trust_epoch !== capture.payload.source_trust_epoch
      || trust.source_revocation_generation !== capture.payload.source_revocation_generation
      || trust.signer_key_id !== capture.signer_key_id
      || trust.signer_public_key_digest !== capture.signer_public_key_digest) {
    return "revoked";
  }
  return "current";
}

function createFixturePhysicalInventoryCheckpointSource(input) {
  assertClosedObject(input, "physical_inventory_checkpoint_source", [
    "source_id",
    "signer_key_id",
    "signer_public_key_digest",
    "signer_public_key",
    "trusted_clock_port",
    "read_authenticated_capture",
    "resolve_current_trust",
  ]);
  const signerPublicKey = assertEd25519PublicKey(
    input.signer_public_key,
    "physical_inventory_checkpoint_source.signer_public_key",
  );
  const signerPublicKeyDigest = assertDigest(
    input.signer_public_key_digest,
    "physical_inventory_checkpoint_source.signer_public_key_digest",
  );
  if (signerPublicKeyDigest !== publicKeyDigest(signerPublicKey)) {
    throw new Error("physical inventory source key digest does not bind signer_public_key");
  }
  if (typeof input.read_authenticated_capture !== "function"
      || typeof input.resolve_current_trust !== "function") {
    throw new Error("physical inventory source callbacks must be functions");
  }
  const trustedClockPort = assertPhysicalTrustedClockPort(input.trusted_clock_port);
  const source = deepFreeze({
    version: PHYSICAL_INVENTORY_CHECKPOINT_VERSION,
    source_id: assertIdentifier(input.source_id, "physical_inventory_checkpoint_source.source_id"),
    mode: PHYSICAL_INVENTORY_SOURCE_MODE,
    signer_key_id: assertToken(
      input.signer_key_id,
      "physical_inventory_checkpoint_source.signer_key_id",
      "inventory-key",
    ),
    signer_public_key_digest: signerPublicKeyDigest,
    trusted_clock_mode: TRUSTED_CLOCK_PORT_MODE,
    production_ready: false,
    hil_attested: false,
    lifecycle_authority: false,
    execution_authority: false,
  });
  SOURCE_PORTS.add(source);
  SOURCE_PORT_STATE.set(source, {
    signer_public_key: signerPublicKey,
    trusted_clock_port: trustedClockPort,
    read_authenticated_capture: input.read_authenticated_capture,
    resolve_current_trust: input.resolve_current_trust,
    in_flight: false,
  });
  return source;
}

function assertFixturePhysicalInventoryCheckpointSource(source) {
  if (!source || typeof source !== "object" || !Object.isFrozen(source)
      || !SOURCE_PORTS.has(source) || !SOURCE_PORT_STATE.has(source)) {
    throw new Error("physical inventory checkpoint source must be a privately branded live source");
  }
  return source;
}

function validateTrustedTime(state, payload) {
  const sample = samplePhysicalTrustedClock(state.trusted_clock_port);
  assertPhysicalTrustedClockValidityWindow(sample, {
    not_before: payload.valid_from,
    expires_at: payload.expires_at,
  }, "physical inventory checkpoint validity");
  assertPhysicalTrustedClockTimestampNonFuture(
    sample,
    payload.captured_at,
    "physical inventory captured_at",
  );
  assertPhysicalTrustedClockTimestampNonFuture(
    sample,
    payload.attested_at,
    "physical inventory attested_at",
  );
  return sample;
}

function buildCheckpoint(capture) {
  const payload = capture.payload;
  const bindings = selectFields(payload, BINDING_FIELDS);
  const executionReceipts = payload.execution_receipts.map((receipt) => deepFreeze({
    operation_id: receipt.operation_id,
    receipt_ref: receipt.receipt_ref,
    receipt_digest: receipt.receipt_digest,
    execution_request_digest: receipt.execution_request_digest,
    signed_grant_digest: receipt.signed_grant_digest,
    operation_digest: receipt.operation_digest,
    response_digest: receipt.response_digest,
    observed_at: receipt.observed_at,
  }));
  const executionReceiptSetDigest = hashCanonicalJson(executionReceipts);
  const invariantWitnessDigests = deepFreeze({
    rf_off: payload.invariant_witness.rf_off_witness_digest,
    mode_unchanged: payload.invariant_witness.mode_unchanged_witness_digest,
    workspace_unchanged: payload.invariant_witness.workspace_unchanged_witness_digest,
    authentication: payload.invariant_witness.witness_authentication_digest,
    witness_set_digest: payload.invariant_witness.witness_set_digest,
  });
  const observationBasis = {
    version: PHYSICAL_INVENTORY_CHECKPOINT_VERSION,
    ...bindings,
    execution_receipt_set_digest: executionReceiptSetDigest,
    invariant_witness_set_digest: payload.invariant_witness.witness_set_digest,
    assurance_profile_id: payload.assurance_profile_id,
    assurance_claims_digest: payload.assurance_claims.claims_digest,
    captured_at: payload.captured_at,
  };
  const inventoryObservationDigest = hashCanonicalJson(observationBasis);
  const inventoryObservationRef = `physical-inventory-observation:${inventoryObservationDigest}`;
  normalizeOpaqueRef(inventoryObservationRef, "derived inventory observation ref", {
    prefix: "physical-inventory-observation",
  });
  const body = {
    version: PHYSICAL_INVENTORY_CHECKPOINT_VERSION,
    source_id: payload.source_id,
    ...bindings,
    required_operation_ids: REQUIRED_OPERATION_IDS,
    execution_receipts: executionReceipts,
    execution_receipt_set_digest: executionReceiptSetDigest,
    authenticated_invariant_witness_digests: invariantWitnessDigests,
    assurance_profile_id: payload.assurance_profile_id,
    assurance_claims: payload.assurance_claims,
    inventory_observation_ref: inventoryObservationRef,
    inventory_observation_digest: inventoryObservationDigest,
    authenticated_capture_digest: capture.authenticated_capture_digest,
    captured_at: payload.captured_at,
    valid_from: payload.valid_from,
    expires_at: payload.expires_at,
    assurance_class: "fixture_contract_only",
    production_ready: false,
    hil_attested: false,
    lifecycle_authority: false,
    execution_authority: false,
    readiness_blockers: READINESS_BLOCKERS,
  };
  const checkpointDigest = hashCanonicalJson(body);
  const checkpointRef = `physical-inventory-checkpoint:${checkpointDigest}`;
  normalizeOpaqueRef(checkpointRef, "derived physical inventory checkpoint ref", {
    prefix: "physical-inventory-checkpoint",
  });
  return deepFreeze({
    ...body,
    checkpoint_ref: checkpointRef,
    checkpoint_digest: checkpointDigest,
  });
}

function captureFixturePhysicalInventoryCheckpoint(sourceInput, expectedBindingsInput) {
  const source = assertFixturePhysicalInventoryCheckpointSource(sourceInput);
  const state = SOURCE_PORT_STATE.get(source);
  const expectedBindings = normalizeBindings(expectedBindingsInput);
  if (state.in_flight) throw new Error("physical inventory checkpoint capture is already in progress");
  state.in_flight = true;
  try {
    const rawCapture = callSynchronous(
      state.read_authenticated_capture,
      "authenticated physical inventory source",
      expectedBindings,
    );
    const capture = normalizeAuthenticatedCapture(rawCapture, source, state);
    assertBindingsMatch(capture.payload, expectedBindings, "physical_inventory_capture.payload");
    const disposition = readSourceDisposition(source, state, capture);
    if (disposition !== "current") {
      throw new Error(`physical inventory source is ${disposition}`);
    }
    validateTrustedTime(state, capture.payload);
    const checkpoint = buildCheckpoint(capture);
    CHECKPOINTS.add(checkpoint);
    CHECKPOINT_STATE.set(checkpoint, { source, capture });
    return checkpoint;
  } finally {
    state.in_flight = false;
  }
}

function assertFixturePhysicalInventoryCheckpoint(checkpoint) {
  if (!checkpoint || typeof checkpoint !== "object" || !Object.isFrozen(checkpoint)
      || !CHECKPOINTS.has(checkpoint) || !CHECKPOINT_STATE.has(checkpoint)) {
    throw new Error("physical inventory checkpoint must be a privately branded authenticated checkpoint");
  }
  return checkpoint;
}

function evaluateCheckpoint(checkpointInput) {
  const checkpoint = assertFixturePhysicalInventoryCheckpoint(checkpointInput);
  const checkpointState = CHECKPOINT_STATE.get(checkpoint);
  const sourceState = SOURCE_PORT_STATE.get(checkpointState.source);
  const disposition = readSourceDisposition(
    checkpointState.source,
    sourceState,
    checkpointState.capture,
  );
  if (disposition === "current") {
    validateTrustedTime(sourceState, checkpointState.capture.payload);
  }
  return { checkpoint, disposition };
}

function projectFixturePhysicalInventoryCheckpoint(checkpointInput) {
  const { checkpoint, disposition } = evaluateCheckpoint(checkpointInput);
  const body = { ...checkpoint, disposition };
  const projection = deepFreeze({ ...body, projection_digest: hashCanonicalJson(body) });
  assertNoPublicByteMaterial(projection, "physical_inventory_checkpoint_projection");
  return projection;
}

function assertCurrentFixturePhysicalInventoryCheckpoint(checkpointInput, expectedBindingsInput) {
  const expectedBindings = normalizeBindings(expectedBindingsInput);
  const { checkpoint, disposition } = evaluateCheckpoint(checkpointInput);
  if (disposition !== "current") {
    throw new Error(`physical inventory checkpoint is ${disposition}`);
  }
  assertBindingsMatch(checkpoint, expectedBindings, "physical_inventory_checkpoint");
  return checkpoint;
}

module.exports = {
  ASSURANCE_STATUS_VALUES,
  MAX_CHECKPOINT_LIFETIME_MS,
  PHYSICAL_INVENTORY_CAPTURE_DOMAIN,
  PHYSICAL_INVENTORY_CHECKPOINT_VERSION,
  PHYSICAL_INVENTORY_SIGNING_DOMAIN,
  PHYSICAL_INVENTORY_SOURCE_MODE,
  READINESS_BLOCKERS,
  REQUIRED_OPERATION_IDS,
  SOURCE_DISPOSITIONS,
  assertCurrentFixturePhysicalInventoryCheckpoint,
  assertFixturePhysicalInventoryCheckpoint,
  assertFixturePhysicalInventoryCheckpointSource,
  captureFixturePhysicalInventoryCheckpoint,
  createFixturePhysicalInventoryCheckpointSource,
  physicalInventoryCaptureSigningMessage,
  projectFixturePhysicalInventoryCheckpoint,
  publicKeyDigest,
};
