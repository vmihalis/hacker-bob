"use strict";

// Plane-PH experiment contracts are deliberately provider-neutral. This module
// owns immutable plan hashing, signed append-only row envelopes, and a derived
// rebuildable join. It does not sign rows, resolve secrets, or adjudicate a
// provider-specific protocol.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const {
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");
const {
  assertDurableReceiptTrustRegistry,
  assertExecutedEvidenceRegistry,
  normalizeExecutedEvidenceRef,
  normalizeAndVerifyDurableEvidenceReceipt,
} = require("../../core/executed-evidence-contract.js");
const {
  EFFECT_ACTIONS,
  EFFECT_CHANNELS,
  EFFECT_PERSISTENCE_VALUES,
  EFFECT_SUBJECT_KINDS,
  assertEffectTemplateRegistry,
  normalizeRequestedEffects,
} = require("../../core/requested-effects.js");
const {
  normalizeOpaqueRef,
} = require("./physical-quantities.js");
const {
  appendMechanismAPhysicalExperimentRow,
  appendProductionPhysicalExperimentRow,
  assertMechanismAPhysicalExperimentDurableHeadPort,
  assertProductionPhysicalExperimentDurableHeadPort,
  ingestMechanismAPhysicalExperimentReceipt,
  ingestProductionPhysicalExperimentReceipt,
  openMechanismAPhysicalExperimentDurableHeadPort,
  openProductionPhysicalExperimentDurableHeadPort,
  readMechanismAPhysicalExperimentHead,
  readMechanismAPhysicalExperimentRows,
  readProductionPhysicalExperimentHead,
  readProductionPhysicalExperimentRows,
  resolveMechanismAPhysicalExperimentCommit,
  resolveMechanismAPhysicalExperimentReceipt,
  resolveProductionPhysicalExperimentCommit,
  resolveProductionPhysicalExperimentReceipt,
} = require("./physical-experiment-store.js");
const {
  assertProductionPhysicalExperimentTrustHeadCurrent,
  assertProductionPhysicalExperimentTrustPort,
  describeProductionPhysicalExperimentTrustPort,
  enrollProductionPhysicalExperimentTrustHead,
} = require("./physical-experiment-trust-store.js");
const {
  assertProductionPhysicalTrustedClockPort,
  assertProductionPhysicalTrustedClockSample,
  assertRestartDurablePhysicalTrustedClockPort,
  assertRestartDurablePhysicalTrustedClockValidityWindow,
  describeProductionPhysicalTrustedClockPort,
  sampleRestartDurablePhysicalTrustedClock,
} = require("./physical-trusted-clock-store.js");

const PHYSICAL_EXPERIMENT_PLAN_VERSION = 1;
const PHYSICAL_EXPERIMENT_ROW_VERSION = 1;
const PHYSICAL_EXPERIMENT_INDEX_VERSION = 1;
const CONSUMPTION_ATTESTATION_VERSION = 1;
const EVIDENCE_VERIFICATION_BINDING_VERSION = 1;
const OPERATOR_ENROLLMENT_REGISTRY_VERSION = 1;
const PHYSICAL_ALLOCATION_RECEIPT_VERSION = 1;
const PHYSICAL_APPEND_RECEIPT_VERSION = 1;
const PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_VERSION = 1;
const PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRY_VERSION = 1;
const VERIFIED_PHYSICAL_CLAIM_PROJECTION_VERSION = 2;

const PHYSICAL_EXPERIMENT_ROW_KINDS = Object.freeze([
  "execution_receipt",
  "observation",
  "claim_verdict",
  "cleanup_verdict",
]);
const COHORT_KINDS = Object.freeze(["positive", "control"]);
const OBSERVATION_SOURCE_KINDS = Object.freeze([
  "instrument",
  "operator",
  "controller",
  "sensor",
]);
const OBSERVATION_START_RULES = Object.freeze([
  "execution_started",
  "execution_ended",
]);
const REPLAY_GUARD_KINDS = Object.freeze([
  "monotonic_sequence",
  "one_time_challenge",
]);
const CONSUMPTION_KINDS = Object.freeze(["grant", "one_time_challenge", "monotonic_sequence"]);
const EXECUTION_STATUSES = Object.freeze(["executed", "failed", "aborted"]);
const CLAIM_DISPOSITIONS = Object.freeze(["verified", "refuted", "inconclusive"]);
const CLEANUP_DISPOSITIONS = Object.freeze(["succeeded", "failed", "inconclusive"]);
const CLAIM_REASON_CODES = Object.freeze([
  "differential_verified",
  "differential_refuted",
  "missing_executed_cohort",
  "missing_planned_observation",
  "independent_observer_missing",
  "executed_evidence_missing",
]);
const VALIDITY_KINDS = Object.freeze(["historical_event", "live_capability"]);
const SIGNATURE_SCHEMES = Object.freeze(["ed25519", "ecdsa-p256-sha256"]);
const RETRY_DISPOSITIONS = Object.freeze([
  "inconclusive",
  "observer_unavailable",
  "transport_failure",
]);

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const MAX_PHYSICAL_EXPERIMENT_EVIDENCE_RECEIPTS = 16_384;
const MAX_EXTERNAL_OBSERVER_INDEPENDENCE_DOMAINS = 256;
const ID_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{16,1024}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;
const ZERO_HASH = "0".repeat(64);
const OPERATOR_ENROLLMENT_REGISTRIES = new WeakSet();
const PHYSICAL_ALLOCATION_TRUST_REGISTRIES = new WeakSet();
const PHYSICAL_ALLOCATION_ISSUERS = new WeakSet();
const PHYSICAL_APPEND_ISSUERS = new WeakSet();
const TEST_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORTS = new WeakSet();
const TEST_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_STATE = new WeakMap();
const MECHANISM_A_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORTS = new WeakSet();
const PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRIES = new WeakSet();
const PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRY_STATE = new WeakMap();
const PRODUCTION_PHYSICAL_EXPERIMENT_LEDGERS = new WeakSet();
const PRODUCTION_PHYSICAL_EXPERIMENT_LEDGER_STATE = new WeakMap();
const MECHANISM_A_PHYSICAL_EXPERIMENT_LEDGERS = new WeakSet();
const MECHANISM_A_PHYSICAL_EXPERIMENT_LEDGER_STATE = new WeakMap();
const NORMALIZED_PLAN_DEPS = new WeakMap();
const PRODUCTION_VERIFIED_PHYSICAL_CLAIM_PROJECTIONS = new WeakSet();
const PRODUCTION_VERIFIED_PHYSICAL_CLAIM_PROJECTION_STATE = new WeakMap();
const TEST_VERIFIED_PHYSICAL_CLAIM_PROJECTIONS = new WeakSet();
const TEST_VERIFIED_PHYSICAL_CLAIM_PROJECTION_STATE = new WeakMap();
const ROW_PREFIX = Object.freeze({
  execution_receipt: "physical-execution-receipt",
  observation: "physical-observation",
  claim_verdict: "physical-claim-verdict",
  cleanup_verdict: "physical-cleanup-verdict",
});
const INTRINSIC_DATE = Date;
const INTRINSIC_DATE_NOW = Date.now.bind(Date);
const INTRINSIC_CREATE_HASH = crypto.createHash.bind(crypto);
const INTRINSIC_CREATE_PUBLIC_KEY = crypto.createPublicKey.bind(crypto);
const INTRINSIC_VERIFY = crypto.verify.bind(crypto);
const LIVE_CAPABILITY_TRUSTED_TIME_BLOCKER =
  "production live physical capability requires restart-durable signed trusted-time validation";

function productionTrustedNow() {
  return new INTRINSIC_DATE(INTRINSIC_DATE_NOW()).toISOString();
}

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

// Production composition inputs cross a trust boundary before the legacy
// contract normalizers run.  Copy only own enumerable data properties so a
// Proxy/getter/thenable cannot execute while authority is being assembled.
function cloneStrictProductionData(value, label, depth = 0) {
  if (depth > 16) throw new Error(`${label} exceeds the maximum nesting depth`);
  if (value == null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`${label} contains a non-finite number`);
    return value;
  }
  if (Array.isArray(value)) {
    if (utilTypes.isProxy(value) || value.length > 4096) {
      throw new Error(`${label} must be a bounded non-proxy array`);
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(value);
    for (const key of keys) {
      if (key === "length") continue;
      if (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key)) {
        throw new Error(`${label} contains a non-index array field`);
      }
      const descriptor = descriptors[key];
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
          || descriptor.enumerable !== true) {
        throw new Error(`${label}[${key}] must be an enumerable data property`);
      }
    }
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor) throw new Error(`${label} cannot be sparse`);
      result.push(cloneStrictProductionData(descriptor.value, `${label}[${index}]`, depth + 1));
    }
    return result;
  }
  if (utilTypes.isProxy(value) || !isPlainObject(value)) {
    throw new Error(`${label} must contain only plain non-proxy data objects`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(value);
  if (keys.length > 512 || keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} has invalid or excessive fields`);
  }
  const result = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error(`${label}.${key} must be an enumerable data property`);
    }
    result[key] = cloneStrictProductionData(descriptor.value, `${label}.${key}`, depth + 1);
  }
  return result;
}

function assertExactProductionObject(value, label, required, optional = []) {
  const copy = cloneStrictProductionData(value, label);
  if (!isPlainObject(copy)) throw new Error(`${label} must be a plain data object`);
  const allowed = new Set([...required, ...optional]);
  const unknown = Object.keys(copy).filter((field) => !allowed.has(field)).sort();
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(copy, field));
  if (unknown.length > 0 || missing.length > 0) {
    throw new Error(
      `${label} fields are not exact (missing: ${missing.join(", ") || "none"}; unknown: ${unknown.join(", ") || "none"})`,
    );
  }
  return copy;
}

function readExactProductionObjectFields(value, label, required, optional = []) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value) || !isPlainObject(value)) {
    throw new Error(`${label} must be a plain non-proxy data object`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = keys.filter((field) => !allowed.has(field)).sort();
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(descriptors, field));
  if (unknown.length > 0 || missing.length > 0) {
    throw new Error(
      `${label} fields are not exact (missing: ${missing.join(", ") || "none"}; unknown: ${unknown.join(", ") || "none"})`,
    );
  }
  const result = {};
  for (const field of keys) {
    const descriptor = descriptors[field];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
    result[field] = descriptor.value;
  }
  return result;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
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

function assertId(value, label) {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertToken(value, label) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)) {
    throw new Error(`${label} must be a bounded opaque token`);
  }
  return value;
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function assertSafeInteger(value, label, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${label} must be a safe integer between ${min} and ${max}`);
  }
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  return value;
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function assertNonce(value, label) {
  if (typeof value !== "string" || !NONCE_PATTERN.test(value)) {
    throw new Error(`${label} must be a 128-bit-or-stronger base64url nonce`);
  }
  return value;
}

function isCurrentTrustValidationMode(mode) {
  return mode === "admission" || mode === "live_revalidation";
}

function receiptTrustValidationMode(mode) {
  return isCurrentTrustValidationMode(mode) ? "admission" : "historical";
}

function normalizeCanonicalJson(value, label, depth = 0) {
  if (depth > 8) throw new Error(`${label} exceeds the maximum nesting depth`);
  if (value == null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`${label} must contain only finite JSON numbers`);
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 64) throw new Error(`${label} arrays may contain at most 64 entries`);
    return Object.freeze(value.map((entry, index) => normalizeCanonicalJson(entry, `${label}[${index}]`, depth + 1)));
  }
  if (!isPlainObject(value)) throw new Error(`${label} must contain only canonical JSON values`);
  const keys = Object.keys(value).sort();
  if (keys.length > 64) throw new Error(`${label} objects may contain at most 64 fields`);
  const result = {};
  for (const key of keys) {
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(key)) throw new Error(`${label} has an invalid key ${key}`);
    result[key] = normalizeCanonicalJson(value[key], `${label}.${key}`, depth + 1);
  }
  return deepFreeze(result);
}

function normalizeUniqueArray(value, label, normalize, { nonempty = false } = {}) {
  if (!Array.isArray(value) || (nonempty && value.length === 0)) {
    throw new Error(`${label} must be ${nonempty ? "a non-empty" : "an"} array`);
  }
  const normalized = value.map((entry, index) => normalize(entry, `${label}[${index}]`));
  const identities = normalized.map((entry) => typeof entry === "string" ? entry : hashCanonicalJson(entry));
  if (new Set(identities).size !== identities.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze(normalized);
}

function normalizeSortedRefs(value, label, prefix = null, { nonempty = false } = {}) {
  const refs = normalizeUniqueArray(
    value,
    label,
    (entry, field) => normalizeOpaqueRef(entry, field, { prefix }),
    { nonempty },
  );
  return Object.freeze([...refs].sort());
}

function normalizePhysicalExperimentSignerDefinition(input, label) {
  const copy = assertExactProductionObject(input, label, [
    "signer_key_id",
    "signer_principal_ref",
    "signature_scheme",
    "public_key_pem",
    "trust_root_epoch",
    "trust_domain_ref",
    "independence_domain_ref",
    "allowed_row_kinds",
    "valid_from",
    "trusted",
    "revoked",
  ], [
    "expires_at",
    "revoked_at",
    "instrument_identity_ref",
    "observer_identity_ref",
  ]);
  if (typeof copy.public_key_pem !== "string" || copy.public_key_pem.length < 1
      || copy.public_key_pem.length > 16_384) {
    throw new Error(`${label}.public_key_pem must be a bounded PEM public key`);
  }
  let publicKey;
  try {
    publicKey = INTRINSIC_CREATE_PUBLIC_KEY(copy.public_key_pem);
  } catch {
    throw new Error(`${label}.public_key_pem is invalid`);
  }
  const signatureScheme = assertEnum(copy.signature_scheme, SIGNATURE_SCHEMES, `${label}.signature_scheme`);
  if (signatureScheme === "ed25519" && publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error(`${label}.public_key_pem must be Ed25519 for signature_scheme ed25519`);
  }
  if (signatureScheme === "ecdsa-p256-sha256"
      && (publicKey.asymmetricKeyType !== "ec"
        || publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1")) {
    throw new Error(`${label}.public_key_pem must be P-256 for signature_scheme ecdsa-p256-sha256`);
  }
  if (typeof copy.trusted !== "boolean" || typeof copy.revoked !== "boolean") {
    throw new Error(`${label} trust flags must be booleans`);
  }
  const allowedRowKinds = normalizeUniqueArray(
    copy.allowed_row_kinds,
    `${label}.allowed_row_kinds`,
    (entry, field) => assertEnum(entry, PHYSICAL_EXPERIMENT_ROW_KINDS, field),
    { nonempty: true },
  );
  const descriptor = {
    signer_key_id: normalizeOpaqueRef(copy.signer_key_id, `${label}.signer_key_id`, { prefix: "signer-key" }),
    signer_principal_ref: normalizeOpaqueRef(
      copy.signer_principal_ref,
      `${label}.signer_principal_ref`,
      { prefix: "principal" },
    ),
    signature_scheme: signatureScheme,
    public_key_spki_sha256: INTRINSIC_CREATE_HASH("sha256").update(
      publicKey.export({ type: "spki", format: "der" }),
    ).digest("hex"),
    trust_root_epoch: assertSafeInteger(copy.trust_root_epoch, `${label}.trust_root_epoch`, { min: 1 }),
    trust_domain_ref: normalizeOpaqueRef(
      copy.trust_domain_ref,
      `${label}.trust_domain_ref`,
      { prefix: "trust-domain" },
    ),
    independence_domain_ref: normalizeOpaqueRef(
      copy.independence_domain_ref,
      `${label}.independence_domain_ref`,
      { prefix: "independence-domain" },
    ),
    allowed_row_kinds: allowedRowKinds,
    valid_from: assertTimestamp(copy.valid_from, `${label}.valid_from`),
    trusted: copy.trusted,
    revoked: copy.revoked,
  };
  if (copy.expires_at != null) {
    descriptor.expires_at = assertTimestamp(copy.expires_at, `${label}.expires_at`);
    if (Date.parse(descriptor.expires_at) <= Date.parse(descriptor.valid_from)) {
      throw new Error(`${label}.expires_at must be after valid_from`);
    }
  }
  if (descriptor.revoked) {
    descriptor.revoked_at = assertTimestamp(copy.revoked_at, `${label}.revoked_at`);
  } else if (copy.revoked_at != null) {
    throw new Error(`${label}.revoked_at requires revoked=true`);
  }
  if (copy.instrument_identity_ref != null) {
    descriptor.instrument_identity_ref = normalizeOpaqueRef(
      copy.instrument_identity_ref,
      `${label}.instrument_identity_ref`,
      { prefix: "instrument-identity" },
    );
  }
  if (copy.observer_identity_ref != null) {
    descriptor.observer_identity_ref = normalizeOpaqueRef(
      copy.observer_identity_ref,
      `${label}.observer_identity_ref`,
      { prefix: "observer" },
    );
  }
  if (allowedRowKinds.includes("execution_receipt") && descriptor.instrument_identity_ref == null) {
    throw new Error(`${label} execution_receipt authority requires instrument_identity_ref`);
  }
  if (allowedRowKinds.includes("observation") && descriptor.observer_identity_ref == null) {
    throw new Error(`${label} observation authority requires observer_identity_ref`);
  }
  if (!allowedRowKinds.includes("execution_receipt") && descriptor.instrument_identity_ref != null) {
    throw new Error(`${label}.instrument_identity_ref requires execution_receipt authority`);
  }
  if (!allowedRowKinds.includes("observation") && descriptor.observer_identity_ref != null) {
    throw new Error(`${label}.observer_identity_ref requires observation authority`);
  }
  const enrollmentDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-experiment-signer-enrollment/v1",
    ...descriptor,
  });
  return {
    descriptor: deepFreeze({ ...descriptor, signer_enrollment_digest: enrollmentDigest }),
    publicKey,
  };
}

function buildPhysicalExperimentSignerTrustRegistry(input) {
  const copy = assertExactProductionObject(input, "physical experiment signer trust registry", [
    "version", "registry_id", "signers",
  ]);
  if (copy.version !== PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRY_VERSION) {
    throw new Error(
      `physical experiment signer trust registry.version must be ${PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRY_VERSION}`,
    );
  }
  const registryId = assertId(copy.registry_id, "physical experiment signer trust registry.registry_id");
  if (!Array.isArray(copy.signers) || copy.signers.length < 1 || copy.signers.length > 256) {
    throw new Error("physical experiment signer trust registry.signers must contain 1..256 entries");
  }
  const entries = new Map();
  const keyMaterial = new Map();
  const normalized = copy.signers.map((entry, index) => normalizePhysicalExperimentSignerDefinition(
    entry,
    `physical experiment signer trust registry.signers[${index}]`,
  ));
  for (const entry of normalized) {
    const key = `${entry.descriptor.signer_key_id}:${entry.descriptor.trust_root_epoch}`;
    if (entries.has(key)) throw new Error(`duplicate physical experiment signer ${key}`);
    const priorKey = keyMaterial.get(entry.descriptor.public_key_spki_sha256);
    if (priorKey != null && priorKey !== key) {
      throw new Error(
        `physical experiment signer public key material is already enrolled as ${priorKey}`,
      );
    }
    keyMaterial.set(entry.descriptor.public_key_spki_sha256, key);
    entries.set(key, entry);
  }
  const descriptors = normalized.map((entry) => entry.descriptor).sort((left, right) => (
    `${left.signer_key_id}:${left.trust_root_epoch}`.localeCompare(
      `${right.signer_key_id}:${right.trust_root_epoch}`,
    )
  ));
  const registryDigest = hashCanonicalJson({
    version: PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRY_VERSION,
    registry_id: registryId,
    signers: descriptors,
  });
  const registry = deepFreeze({
    version: PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRY_VERSION,
    registry_id: registryId,
    registry_digest: registryDigest,
    describe() {
      return Object.freeze([...descriptors]);
    },
  });
  PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRIES.add(registry);
  PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRY_STATE.set(registry, entries);
  return registry;
}

function assertPhysicalExperimentSignerTrustRegistry(registry) {
  if (!registry || !PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRIES.has(registry)
      || !PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRY_STATE.has(registry)
      || !Object.isFrozen(registry)) {
    throw new Error("physical experiment signer trust registry must be a closed Bob registry");
  }
  return registry;
}

function physicalExperimentSignerEntry(registry, signerKeyId, epoch) {
  assertPhysicalExperimentSignerTrustRegistry(registry);
  return PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRY_STATE.get(registry)
    .get(`${signerKeyId}:${epoch}`) || null;
}

function normalizeEnrollmentDefinition(input, label) {
  assertClosedObject(input, label, [
    "observer_enrollment_ref",
    "observer_identity_ref",
    "signer_key_id",
    "source_kind",
    "source_ref",
    "source_assurance_scheme",
    "trust_domain_ref",
    "independence_domain_ref",
    "external_outcome_allowed",
    "valid_from",
    "revoked",
  ], ["expires_at", "revoked_at"]);
  const sourceKind = assertEnum(input.source_kind, OBSERVATION_SOURCE_KINDS, `${label}.source_kind`);
  const externalAllowed = assertBoolean(input.external_outcome_allowed, `${label}.external_outcome_allowed`);
  if (externalAllowed && sourceKind === "instrument") {
    throw new Error(`${label} instrument-origin sources cannot be enrolled as external outcomes`);
  }
  const value = {
    observer_enrollment_ref: normalizeOpaqueRef(
      input.observer_enrollment_ref,
      `${label}.observer_enrollment_ref`,
      { prefix: "observer-enrollment" },
    ),
    observer_identity_ref: normalizeOpaqueRef(
      input.observer_identity_ref,
      `${label}.observer_identity_ref`,
      { prefix: "observer" },
    ),
    signer_key_id: normalizeOpaqueRef(input.signer_key_id, `${label}.signer_key_id`, { prefix: "signer-key" }),
    source_kind: sourceKind,
    source_ref: normalizeOpaqueRef(input.source_ref, `${label}.source_ref`),
    source_assurance_scheme: assertId(input.source_assurance_scheme, `${label}.source_assurance_scheme`),
    trust_domain_ref: normalizeOpaqueRef(
      input.trust_domain_ref,
      `${label}.trust_domain_ref`,
      { prefix: "trust-domain" },
    ),
    independence_domain_ref: normalizeOpaqueRef(
      input.independence_domain_ref,
      `${label}.independence_domain_ref`,
      { prefix: "independence-domain" },
    ),
    external_outcome_allowed: externalAllowed,
    valid_from: assertTimestamp(input.valid_from, `${label}.valid_from`),
    revoked: assertBoolean(input.revoked, `${label}.revoked`),
  };
  if (input.expires_at != null) {
    value.expires_at = assertTimestamp(input.expires_at, `${label}.expires_at`);
    if (Date.parse(value.expires_at) <= Date.parse(value.valid_from)) {
      throw new Error(`${label}.expires_at must be after valid_from`);
    }
  }
  if (value.revoked) value.revoked_at = assertTimestamp(input.revoked_at, `${label}.revoked_at`);
  else if (input.revoked_at != null) throw new Error(`${label}.revoked_at requires revoked=true`);
  const descriptor = deepFreeze(value);
  return deepFreeze({ ...descriptor, enrollment_digest: hashCanonicalJson(descriptor) });
}

function buildPhysicalObserverEnrollmentRegistry(definitions) {
  if (!Array.isArray(definitions) || definitions.length === 0 || definitions.length > 256) {
    throw new Error("physical observer enrollments must be a non-empty array with at most 256 entries");
  }
  const entries = new Map();
  const ordered = definitions.map((entry, index) => (
    normalizeEnrollmentDefinition(entry, `physical_observer_enrollments[${index}]`)
  )).sort((left, right) => left.observer_enrollment_ref.localeCompare(right.observer_enrollment_ref));
  for (const entry of ordered) {
    if (entries.has(entry.observer_enrollment_ref)) {
      throw new Error(`duplicate physical observer enrollment ${entry.observer_enrollment_ref}`);
    }
    entries.set(entry.observer_enrollment_ref, entry);
  }
  const registryDigest = hashCanonicalJson({
    version: OPERATOR_ENROLLMENT_REGISTRY_VERSION,
    enrollments: ordered,
  });
  const registry = Object.freeze({
    version: OPERATOR_ENROLLMENT_REGISTRY_VERSION,
    registry_digest: registryDigest,
    get(enrollmentRef) {
      return entries.get(enrollmentRef) || null;
    },
    describe() {
      return Object.freeze([...ordered]);
    },
  });
  OPERATOR_ENROLLMENT_REGISTRIES.add(registry);
  return registry;
}

function assertPhysicalObserverEnrollmentRegistry(registry) {
  if (!registry || !OPERATOR_ENROLLMENT_REGISTRIES.has(registry)) {
    throw new Error("observer enrollment registry must be a closed Bob registry");
  }
  return registry;
}

const PHYSICAL_RECEIPT_REGISTRY_STATE = new WeakMap();

function normalizePhysicalReceiptIssuer(input, label) {
  assertClosedObject(input, label, [
    "issuer_key_id",
    "issuer_epoch",
    "public_key_pem",
    "valid_from",
    "trusted",
    "revoked",
  ], ["expires_at", "revoked_at"]);
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(input.public_key_pem);
  } catch {
    throw new Error(`${label}.public_key_pem is not a valid public key`);
  }
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error(`${label}.public_key_pem must be Ed25519`);
  const descriptor = {
    issuer_key_id: normalizeOpaqueRef(input.issuer_key_id, `${label}.issuer_key_id`, { prefix: "signer-key" }),
    issuer_epoch: assertSafeInteger(input.issuer_epoch, `${label}.issuer_epoch`, { min: 1 }),
    public_key_spki_sha256: crypto.createHash("sha256").update(
      publicKey.export({ type: "spki", format: "der" }),
    ).digest("hex"),
    valid_from: assertTimestamp(input.valid_from, `${label}.valid_from`),
    trusted: assertBoolean(input.trusted, `${label}.trusted`),
    revoked: assertBoolean(input.revoked, `${label}.revoked`),
  };
  if (input.expires_at != null) descriptor.expires_at = assertTimestamp(input.expires_at, `${label}.expires_at`);
  if (descriptor.expires_at != null && Date.parse(descriptor.expires_at) <= Date.parse(descriptor.valid_from)) {
    throw new Error(`${label}.expires_at must be after valid_from`);
  }
  if (descriptor.revoked) descriptor.revoked_at = assertTimestamp(input.revoked_at, `${label}.revoked_at`);
  else if (input.revoked_at != null) throw new Error(`${label}.revoked_at requires revoked=true`);
  return { descriptor: deepFreeze(descriptor), publicKey };
}

function buildPhysicalReceiptTrustRegistry(input) {
  assertClosedObject(input, "physical_receipt_trust_registry", ["version", "registry_id", "issuers"]);
  if (input.version !== 1) throw new Error("physical_receipt_trust_registry.version must be 1");
  const registryId = assertId(input.registry_id, "physical_receipt_trust_registry.registry_id");
  if (!Array.isArray(input.issuers) || input.issuers.length === 0 || input.issuers.length > 32) {
    throw new Error("physical_receipt_trust_registry.issuers must be a non-empty array with at most 32 entries");
  }
  const issuers = new Map();
  const descriptors = input.issuers.map((entry, index) => {
    const normalized = normalizePhysicalReceiptIssuer(entry, `physical_receipt_trust_registry.issuers[${index}]`);
    const key = `${normalized.descriptor.issuer_key_id}:${normalized.descriptor.issuer_epoch}`;
    if (issuers.has(key)) throw new Error(`duplicate physical receipt issuer ${key}`);
    issuers.set(key, normalized);
    return normalized.descriptor;
  }).sort((left, right) => (
    `${left.issuer_key_id}:${left.issuer_epoch}`.localeCompare(`${right.issuer_key_id}:${right.issuer_epoch}`)
  ));
  const registryDigest = hashCanonicalJson({ version: 1, registry_id: registryId, issuers: descriptors });
  const registry = Object.freeze({ version: 1, registry_id: registryId, registry_digest: registryDigest });
  PHYSICAL_ALLOCATION_TRUST_REGISTRIES.add(registry);
  PHYSICAL_RECEIPT_REGISTRY_STATE.set(registry, issuers);
  return registry;
}

function assertPhysicalReceiptTrustRegistry(registry) {
  if (!registry || !PHYSICAL_ALLOCATION_TRUST_REGISTRIES.has(registry)) {
    throw new Error("physical receipt trust registry must be a closed Bob registry");
  }
  return registry;
}

function physicalReceiptIssuer(registry, keyId, epoch) {
  assertPhysicalReceiptTrustRegistry(registry);
  return PHYSICAL_RECEIPT_REGISTRY_STATE.get(registry).get(`${keyId}:${epoch}`) || null;
}

function assertPhysicalReceiptIssuerUsable(entry, signedAt, { mode = "historical", trustedNow = null } = {}) {
  if (!entry || !entry.descriptor.trusted) throw new Error("physical receipt issuer is not trusted");
  const descriptor = entry.descriptor;
  const signedMs = Date.parse(signedAt);
  if (signedMs < Date.parse(descriptor.valid_from)) throw new Error("physical receipt predates issuer validity");
  if (descriptor.expires_at != null && signedMs > Date.parse(descriptor.expires_at)) {
    throw new Error("physical receipt postdates issuer validity");
  }
  if (descriptor.revoked && signedMs >= Date.parse(descriptor.revoked_at)) {
    throw new Error("physical receipt postdates issuer revocation");
  }
  if (mode === "admission") {
    const nowMs = Date.parse(assertTimestamp(trustedNow, "trusted_now"));
    if (descriptor.revoked && nowMs >= Date.parse(descriptor.revoked_at)) {
      throw new Error("physical receipt issuer is currently revoked");
    }
    if (descriptor.expires_at != null && nowMs > Date.parse(descriptor.expires_at)) {
      throw new Error("physical receipt issuer is currently expired");
    }
  } else if (mode !== "historical") throw new Error("physical receipt verification mode must be historical or admission");
}

function physicalReceiptSignatureInput(kind, body, envelope) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-durable-receipt/v1",
    version: 1,
    kind,
    body,
    registry_digest: envelope.registry_digest,
    issuer_key_id: envelope.issuer_key_id,
    issuer_epoch: envelope.issuer_epoch,
    signed_at: envelope.signed_at,
  });
}

function signPhysicalReceipt(kind, body, context) {
  const signedAt = assertTimestamp(context.now(), `${kind}_issuer.now`);
  const envelope = {
    registry_digest: context.registry.registry_digest,
    issuer_key_id: context.issuer_key_id,
    issuer_epoch: context.issuer_epoch,
    signed_at: signedAt,
  };
  const signatureInput = physicalReceiptSignatureInput(kind, body, envelope);
  const signature = crypto.sign(null, Buffer.from(signatureInput, "hex"), context.private_key).toString("base64url");
  const signedBody = { version: 1, kind, body, ...envelope, signature };
  const receiptDigest = hashCanonicalJson(signedBody);
  return deepFreeze({ ...signedBody, receipt_digest: receiptDigest });
}

function verifyPhysicalReceipt(input, expectedKind, registry, expectedIssuer, {
  mode = "historical",
  trustedNow = null,
  label = "physical_receipt",
} = {}) {
  assertPhysicalReceiptTrustRegistry(registry);
  assertClosedObject(input, label, [
    "version", "kind", "body", "registry_digest", "issuer_key_id", "issuer_epoch",
    "signed_at", "signature", "receipt_digest",
  ]);
  if (input.version !== 1 || input.kind !== expectedKind) throw new Error(`${label} has the wrong kind or version`);
  if (!isPlainObject(input.body)) throw new Error(`${label}.body must be an object`);
  const body = normalizeCanonicalJson(input.body, `${label}.body`);
  const envelope = {
    registry_digest: assertDigest(input.registry_digest, `${label}.registry_digest`),
    issuer_key_id: normalizeOpaqueRef(input.issuer_key_id, `${label}.issuer_key_id`, { prefix: "signer-key" }),
    issuer_epoch: assertSafeInteger(input.issuer_epoch, `${label}.issuer_epoch`, { min: 1 }),
    signed_at: assertTimestamp(input.signed_at, `${label}.signed_at`),
  };
  if (envelope.registry_digest !== registry.registry_digest) throw new Error(`${label} registry digest drift`);
  if (
    envelope.issuer_key_id !== expectedIssuer.issuer_key_id
    || envelope.issuer_epoch !== expectedIssuer.issuer_epoch
  ) throw new Error(`${label} issuer drift`);
  if (typeof input.signature !== "string" || !SIGNATURE_PATTERN.test(input.signature)) {
    throw new Error(`${label}.signature must be base64url`);
  }
  const entry = physicalReceiptIssuer(registry, envelope.issuer_key_id, envelope.issuer_epoch);
  assertPhysicalReceiptIssuerUsable(entry, envelope.signed_at, { mode, trustedNow });
  const signatureInput = physicalReceiptSignatureInput(expectedKind, body, envelope);
  if (!crypto.verify(
    null,
    Buffer.from(signatureInput, "hex"),
    entry.publicKey,
    Buffer.from(input.signature, "base64url"),
  )) throw new Error(`${label} signature verification failed`);
  const signedBody = { version: 1, kind: expectedKind, body, ...envelope, signature: input.signature };
  const receiptDigest = hashCanonicalJson(signedBody);
  if (assertDigest(input.receipt_digest, `${label}.receipt_digest`) !== receiptDigest) {
    throw new Error(`${label}.receipt_digest drift`);
  }
  return deepFreeze({ ...signedBody, receipt_digest: receiptDigest });
}

function createPhysicalIssuerContext(input, label) {
  assertPhysicalReceiptTrustRegistry(input.registry);
  const issuerKeyId = normalizeOpaqueRef(input.issuer_key_id, `${label}.issuer_key_id`, { prefix: "signer-key" });
  const issuerEpoch = assertSafeInteger(input.issuer_epoch, `${label}.issuer_epoch`, { min: 1 });
  const entry = physicalReceiptIssuer(input.registry, issuerKeyId, issuerEpoch);
  if (!entry) throw new Error(`${label} issuer is not registered`);
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(input.private_key_pem);
  } catch {
    throw new Error(`${label}.private_key_pem is invalid`);
  }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error(`${label}.private_key_pem must be Ed25519`);
  const keyProbe = Buffer.from(hashCanonicalJson({
    domain: "hacker-bob/physical-receipt-key-match/v1",
    registry_digest: input.registry.registry_digest,
    issuer_key_id: issuerKeyId,
    issuer_epoch: issuerEpoch,
  }), "hex");
  if (!crypto.verify(null, keyProbe, entry.publicKey, crypto.sign(null, keyProbe, privateKey))) {
    throw new Error(`${label}.private_key_pem does not match the registered public key`);
  }
  if (typeof input.now !== "function") throw new Error(`${label}.now must be a trusted clock function`);
  return {
    registry: input.registry,
    issuer_key_id: issuerKeyId,
    issuer_epoch: issuerEpoch,
    private_key: privateKey,
    now: input.now,
  };
}

function attemptAllocationBindingDigest(input) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-attempt-allocation/v1",
    session_nucleus_hash: input.session_nucleus_hash,
    experiment_id: input.experiment_id,
    task_id: input.task_id,
    attempt_id: input.attempt_id,
    execution_request_digest: input.execution_request_digest,
    cohort_bindings: input.cohort_bindings,
  });
}

function createPhysicalAllocationIssuer(input = {}) {
  const context = createPhysicalIssuerContext(input, "physical_allocation_issuer");
  if (
    typeof input.reserve_unique_batch !== "function"
    || typeof input.consume_unique !== "function"
    || typeof input.resolve_allocation_receipt !== "function"
    || typeof input.resolve_consumption_receipt !== "function"
  ) {
    throw new Error(
      "physical allocation issuer requires durable reserve, consume, and canonical receipt resolution operations",
    );
  }
  if (typeof input.commit_receipt !== "function") {
    throw new Error("physical allocation issuer requires durable commit_receipt");
  }

  function resolveCanonicalReceipt(resolve, request, kind, body, label) {
    const raw = resolve(request);
    if (raw && typeof raw.then === "function") {
      throw new Error(`${label} must synchronously resolve from the strongly consistent durable store`);
    }
    if (raw == null) return null;
    const trustedNow = assertTimestamp(context.now(), `${label}.now`);
    const receipt = verifyPhysicalReceipt(
      raw,
      kind,
      context.registry,
      { issuer_key_id: context.issuer_key_id, issuer_epoch: context.issuer_epoch },
      { mode: "admission", trustedNow, label },
    );
    if (hashCanonicalJson(receipt.body) !== hashCanonicalJson(body)) {
      throw new Error(`${label} conflicts with the requested durable binding`);
    }
    return receipt;
  }

  function commitAndResolve(receipt, resolve, request, kind, body, label) {
    if (input.commit_receipt(receipt) !== true) {
      throw new Error(`${label} was not durably committed`);
    }
    const committed = resolveCanonicalReceipt(resolve, request, kind, body, label);
    if (!committed || committed.receipt_digest !== receipt.receipt_digest) {
      throw new Error(`${label} durable store did not return the committed canonical receipt`);
    }
    return committed;
  }

  const issuer = Object.freeze({
    registry_digest: context.registry.registry_digest,
    issuer_key_id: context.issuer_key_id,
    issuer_epoch: context.issuer_epoch,
    issueAttemptAllocation(allocationInput) {
      const body = normalizeCanonicalJson(allocationInput, "attempt_allocation");
      const bindingDigest = attemptAllocationBindingDigest(body);
      if (body.binding_digest !== bindingDigest) throw new Error("attempt allocation binding digest drift");
      const uniqueKeys = [
        `attempt:${body.session_nucleus_hash}:${body.task_id}:${body.attempt_id}`,
        `request:${body.session_nucleus_hash}:${body.task_id}:${body.execution_request_digest}`,
        ...body.cohort_bindings.flatMap((cohort) => [
          ...cohort.challenge_nonces.map((nonce) => `challenge:${body.session_nucleus_hash}:${nonce}`),
          `grant:${body.session_nucleus_hash}:${cohort.grant_ref}`,
          `execution:${body.session_nucleus_hash}:${cohort.execution_identity}`,
        ]),
      ];
      const resolveRequest = { binding_digest: bindingDigest };
      const existing = resolveCanonicalReceipt(
        input.resolve_allocation_receipt,
        resolveRequest,
        "attempt_allocation",
        body,
        "attempt allocation receipt",
      );
      if (existing) return existing;
      if (input.reserve_unique_batch({ binding_digest: bindingDigest, unique_keys: uniqueKeys, allocation: body }) !== true) {
        const raced = resolveCanonicalReceipt(
          input.resolve_allocation_receipt,
          resolveRequest,
          "attempt_allocation",
          body,
          "attempt allocation receipt",
        );
        if (raced) return raced;
        throw new Error("attempt allocation uniqueness reservation was refused");
      }
      const receipt = signPhysicalReceipt("attempt_allocation", body, context);
      return commitAndResolve(
        receipt,
        input.resolve_allocation_receipt,
        resolveRequest,
        "attempt_allocation",
        body,
        "attempt allocation receipt",
      );
    },
    issueConsumption(consumptionInput) {
      const body = normalizeCanonicalJson(consumptionInput, "physical_consumption");
      const resolveRequest = { subject_ref: body.subject_ref };
      const existing = resolveCanonicalReceipt(
        input.resolve_consumption_receipt,
        resolveRequest,
        "physical_consumption",
        body,
        "physical consumption receipt",
      );
      if (existing) return existing;
      if (input.consume_unique({
        subject_ref: body.subject_ref,
        plan_hash: body.plan_hash,
        attempt_id: body.attempt_id,
        binding_digest: body.binding_digest,
      }) !== true) {
        const raced = resolveCanonicalReceipt(
          input.resolve_consumption_receipt,
          resolveRequest,
          "physical_consumption",
          body,
          "physical consumption receipt",
        );
        if (raced) return raced;
        throw new Error("physical one-use subject was already consumed or not allocated to this attempt");
      }
      const receipt = signPhysicalReceipt("physical_consumption", body, context);
      return commitAndResolve(
        receipt,
        input.resolve_consumption_receipt,
        resolveRequest,
        "physical_consumption",
        body,
        "physical consumption receipt",
      );
    },
  });
  PHYSICAL_ALLOCATION_ISSUERS.add(issuer);
  return issuer;
}

function normalizePhysicalAppendRequest(input, label = "physical_append_request") {
  assertClosedObject(input, label, [
    "version",
    "plan_hash",
    "row_kind",
    "payload_digest",
    "expected_sequence",
    "previous_row_hash",
    "authorization_context_digest",
    "signed_at",
  ]);
  if (input.version !== PHYSICAL_APPEND_RECEIPT_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_APPEND_RECEIPT_VERSION}`);
  }
  return deepFreeze({
    version: PHYSICAL_APPEND_RECEIPT_VERSION,
    plan_hash: assertDigest(input.plan_hash, `${label}.plan_hash`),
    row_kind: assertEnum(input.row_kind, PHYSICAL_EXPERIMENT_ROW_KINDS, `${label}.row_kind`),
    payload_digest: assertDigest(input.payload_digest, `${label}.payload_digest`),
    expected_sequence: assertSafeInteger(
      input.expected_sequence,
      `${label}.expected_sequence`,
      { min: 1, max: 4096 },
    ),
    previous_row_hash: assertDigest(input.previous_row_hash, `${label}.previous_row_hash`),
    authorization_context_digest: assertDigest(
      input.authorization_context_digest,
      `${label}.authorization_context_digest`,
    ),
    signed_at: assertTimestamp(input.signed_at, `${label}.signed_at`),
  });
}

function physicalAppendBindingDigest(request) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-append-reservation/v1",
    ...request,
  });
}

function physicalAppendReservationDigest(input) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-append-reservation-receipt/v1",
    version: input.version,
    append_binding_digest: input.append_binding_digest,
    journal_sequence: input.journal_sequence,
  });
}

function normalizePhysicalAppendReservation(input, appendBindingDigest) {
  assertClosedObject(input, "physical_append_reservation", [
    "version",
    "append_binding_digest",
    "journal_sequence",
    "reservation_digest",
  ]);
  if (input.version !== PHYSICAL_APPEND_RECEIPT_VERSION) {
    throw new Error(`physical_append_reservation.version must be ${PHYSICAL_APPEND_RECEIPT_VERSION}`);
  }
  const basis = {
    version: PHYSICAL_APPEND_RECEIPT_VERSION,
    append_binding_digest: assertDigest(
      input.append_binding_digest,
      "physical_append_reservation.append_binding_digest",
    ),
    journal_sequence: assertSafeInteger(
      input.journal_sequence,
      "physical_append_reservation.journal_sequence",
      { min: 1 },
    ),
  };
  if (basis.append_binding_digest !== appendBindingDigest) {
    throw new Error("physical append reservation returned another append binding");
  }
  const reservationDigest = physicalAppendReservationDigest(basis);
  if (assertDigest(
    input.reservation_digest,
    "physical_append_reservation.reservation_digest",
  ) !== reservationDigest) {
    throw new Error("physical append reservation digest drift");
  }
  return deepFreeze({ ...basis, reservation_digest: reservationDigest });
}

function createPhysicalAppendIssuer(input = {}) {
  const context = createPhysicalIssuerContext(input, "physical_append_issuer");
  if (
    typeof input.reserve_append !== "function"
    || typeof input.commit_receipt !== "function"
    || typeof input.resolve_append_reservation !== "function"
    || typeof input.resolve_append_receipt !== "function"
  ) {
    throw new Error(
      "physical append issuer requires synchronous durable reserve, commit, and canonical reservation/receipt resolution operations",
    );
  }

  function resolveExactAppendReservation(appendBindingDigest) {
    const raw = input.resolve_append_reservation(deepFreeze({
      version: PHYSICAL_APPEND_RECEIPT_VERSION,
      append_binding_digest: appendBindingDigest,
    }));
    if (raw && typeof raw.then === "function") {
      throw new Error(
        "physical append reservation must synchronously resolve from the strongly consistent durable store",
      );
    }
    return raw == null ? null : normalizePhysicalAppendReservation(raw, appendBindingDigest);
  }

  function resolveExactAppendReceipt(request, appendBindingDigest) {
    const raw = input.resolve_append_receipt(deepFreeze({
      version: PHYSICAL_APPEND_RECEIPT_VERSION,
      append_binding_digest: appendBindingDigest,
    }));
    if (raw && typeof raw.then === "function") {
      throw new Error(
        "physical append receipt must synchronously resolve from the strongly consistent durable store",
      );
    }
    if (raw == null) return null;
    const receipt = verifyPhysicalReceipt(
      raw,
      "physical_append",
      context.registry,
      { issuer_key_id: context.issuer_key_id, issuer_epoch: context.issuer_epoch },
      {
        mode: "admission",
        trustedNow: assertTimestamp(context.now(), "physical_append_receipt.now"),
        label: "physical_append_receipt",
      },
    );
    assertClosedObject(receipt.body, "physical_append_receipt.body", [
      "version",
      "plan_hash",
      "row_kind",
      "payload_digest",
      "expected_sequence",
      "previous_row_hash",
      "authorization_context_digest",
      "signed_at",
      "append_binding_digest",
      "append_reservation_digest",
      "journal_sequence",
    ]);
    const bodyRequest = normalizePhysicalAppendRequest(
      {
        version: receipt.body.version,
        plan_hash: receipt.body.plan_hash,
        row_kind: receipt.body.row_kind,
        payload_digest: receipt.body.payload_digest,
        expected_sequence: receipt.body.expected_sequence,
        previous_row_hash: receipt.body.previous_row_hash,
        authorization_context_digest: receipt.body.authorization_context_digest,
        signed_at: receipt.body.signed_at,
      },
      "physical_append_receipt.body",
    );
    if (hashCanonicalJson(bodyRequest) !== hashCanonicalJson(request)
        || assertDigest(
          receipt.body.append_binding_digest,
          "physical_append_receipt.body.append_binding_digest",
        ) !== appendBindingDigest
        || physicalAppendBindingDigest(bodyRequest) !== appendBindingDigest) {
      throw new Error("physical append receipt conflicts with the exact requested append binding");
    }
    assertSafeInteger(
      receipt.body.journal_sequence,
      "physical_append_receipt.body.journal_sequence",
      { min: 1 },
    );
    const expectedReservationDigest = physicalAppendReservationDigest({
      version: PHYSICAL_APPEND_RECEIPT_VERSION,
      append_binding_digest: appendBindingDigest,
      journal_sequence: receipt.body.journal_sequence,
    });
    if (assertDigest(
      receipt.body.append_reservation_digest,
      "physical_append_receipt.body.append_reservation_digest",
    ) !== expectedReservationDigest) {
      throw new Error("physical append receipt reservation digest drift");
    }
    if (receipt.signed_at !== request.signed_at) {
      throw new Error("physical append receipt signing time drift");
    }
    return receipt;
  }

  const issuer = Object.freeze({
    registry_digest: context.registry.registry_digest,
    issuer_key_id: context.issuer_key_id,
    issuer_epoch: context.issuer_epoch,
    issueAppend(appendInput) {
      const request = normalizePhysicalAppendRequest(appendInput);
      const appendBindingDigest = physicalAppendBindingDigest(request);
      const existing = resolveExactAppendReceipt(request, appendBindingDigest);
      if (existing) return existing;

      let reserveResult;
      let reserveFailure = null;
      try {
        reserveResult = input.reserve_append(deepFreeze({
          version: PHYSICAL_APPEND_RECEIPT_VERSION,
          append_binding_digest: appendBindingDigest,
          append_request: request,
        }));
      } catch (cause) {
        reserveFailure = cause;
      }
      if (reserveResult && typeof reserveResult.then === "function") {
        throw new Error("durable append reservation must be synchronous and strongly consistent");
      }
      if (reserveFailure == null && typeof reserveResult !== "boolean") {
        throw new Error("durable append reservation must return a boolean");
      }
      const reservation = resolveExactAppendReservation(appendBindingDigest);
      if (reservation == null) {
        const error = new Error(
          reserveFailure
            ? "durable append reservation acknowledgement was lost without exact readback"
            : "durable append journal did not reserve the exact append binding",
        );
        if (reserveFailure) Object.defineProperty(error, "cause", { value: reserveFailure });
        throw error;
      }
      const journalSequence = reservation.journal_sequence;
      const receipt = signPhysicalReceipt("physical_append", {
        ...request,
        append_binding_digest: appendBindingDigest,
        append_reservation_digest: reservation.reservation_digest,
        journal_sequence: journalSequence,
      }, context);
      if (receipt.signed_at !== request.signed_at) {
        throw new Error("physical append issuer clock does not match the signed row timestamp");
      }
      let commitResult;
      let commitFailure = null;
      try {
        commitResult = input.commit_receipt(receipt, deepFreeze({
          version: PHYSICAL_APPEND_RECEIPT_VERSION,
          append_binding_digest: appendBindingDigest,
        }));
      } catch (cause) {
        commitFailure = cause;
      }
      if (commitResult && typeof commitResult.then === "function") {
        throw new Error("physical append receipt commit must be synchronous and strongly consistent");
      }
      if (commitFailure == null && typeof commitResult !== "boolean") {
        throw new Error("physical append receipt commit must return a boolean");
      }
      const committed = resolveExactAppendReceipt(request, appendBindingDigest);
      if (committed && committed.receipt_digest === receipt.receipt_digest) return committed;
      if (committed) {
        throw new Error("physical append receipt durable readback returned a conflicting receipt");
      }
      const error = new Error(
        commitFailure
          ? "physical append receipt commit acknowledgement was lost without exact durable readback"
          : "physical append receipt was not durably committed and exactly readable",
      );
      if (commitFailure) Object.defineProperty(error, "cause", { value: commitFailure });
      throw error;
    },
  });
  PHYSICAL_APPEND_ISSUERS.add(issuer);
  return issuer;
}

function physicalExperimentRowCommitDigest(input) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-experiment-row-commit/v1",
    version: input.version,
    plan_hash: input.plan_hash,
    expected_sequence: input.expected_sequence,
    previous_row_hash: input.previous_row_hash,
    append_receipt_digest: input.append_receipt_digest,
    row_digest: input.row_digest,
  });
}

function normalizePhysicalExperimentRowCommit(input, label = "physical_experiment_row_commit") {
  assertClosedObject(input, label, [
    "version",
    "plan_hash",
    "expected_sequence",
    "previous_row_hash",
    "append_receipt_digest",
    "row_digest",
    "row_commit_digest",
  ]);
  if (input.version !== PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_VERSION}`);
  }
  const basis = {
    version: PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_VERSION,
    plan_hash: assertDigest(input.plan_hash, `${label}.plan_hash`),
    expected_sequence: assertSafeInteger(
      input.expected_sequence,
      `${label}.expected_sequence`,
      { min: 1, max: 4096 },
    ),
    previous_row_hash: assertDigest(input.previous_row_hash, `${label}.previous_row_hash`),
    append_receipt_digest: assertDigest(
      input.append_receipt_digest,
      `${label}.append_receipt_digest`,
    ),
    row_digest: assertDigest(input.row_digest, `${label}.row_digest`),
  };
  const rowCommitDigest = physicalExperimentRowCommitDigest(basis);
  if (assertDigest(input.row_commit_digest, `${label}.row_commit_digest`) !== rowCommitDigest) {
    throw new Error(`${label}.row_commit_digest does not bind the exact append receipt and row`);
  }
  return deepFreeze({ ...basis, row_commit_digest: rowCommitDigest });
}

function physicalExperimentRowCommit(plan, row) {
  const basis = {
    version: PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_VERSION,
    plan_hash: plan.plan_hash,
    expected_sequence: row.envelope.sequence,
    previous_row_hash: row.envelope.previous_row_hash,
    append_receipt_digest: row.envelope.append_receipt.receipt_digest,
    row_digest: row.row_hash,
  };
  return deepFreeze({
    ...basis,
    row_commit_digest: physicalExperimentRowCommitDigest(basis),
  });
}

// Only a test adapter exists in this module. It brands a closed provider-
// neutral compare-and-append contract and keeps callbacks private, but it does
// not attest that an injected callback backend is actually durable or
// linearizable. Production must supply an independently reviewed backend and
// factory; callers cannot promote this test port by changing a readiness flag.
function createTestPhysicalExperimentDurableHeadPort(input = {}) {
  assertClosedObject(input, "test_physical_experiment_durable_head_port", [
    "version",
    "port_id",
    "test_only",
    "consistency_model",
    "compare_and_append",
    "read_head",
    "resolve_committed_append",
  ]);
  if (input.version !== PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_VERSION) {
    throw new Error(
      `test_physical_experiment_durable_head_port.version must be ${PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_VERSION}`,
    );
  }
  if (input.test_only !== true) {
    throw new Error("physical experiment durable head port factory is test-only");
  }
  if (input.consistency_model !== "linearizable_compare_and_append") {
    throw new Error("physical experiment durable head port rejects weak consistency models");
  }
  for (const name of ["compare_and_append", "read_head", "resolve_committed_append"]) {
    if (typeof input[name] !== "function"
        || input[name].constructor && input[name].constructor.name === "AsyncFunction") {
      throw new Error(`physical experiment durable head port ${name} must be synchronous`);
    }
  }
  const port = deepFreeze({
    version: PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_VERSION,
    port_id: normalizeOpaqueRef(
      input.port_id,
      "test_physical_experiment_durable_head_port.port_id",
      { prefix: "physical-ledger-head-port" },
    ),
    consistency_model: "linearizable_compare_and_append",
    production_ready: false,
    backend_assurance: "test_only_injected_callback_contract_no_production_backend",
  });
  TEST_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORTS.add(port);
  TEST_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_STATE.set(port, {
    compare_and_append: input.compare_and_append,
    read_head: input.read_head,
    resolve_committed_append: input.resolve_committed_append,
  });
  return port;
}

function assertTestPhysicalExperimentDurableHeadPort(port) {
  if (!port || !TEST_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORTS.has(port)
      || !TEST_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_STATE.has(port)
      || !Object.isFrozen(port)) {
    throw new Error(
      "physical experiment ledger requires a branded strongly consistent durable head port",
    );
  }
  return port;
}

function assertSynchronousDurableHeadResult(value, label) {
  if (value && typeof value.then === "function") {
    throw new Error(`${label} must be synchronous; async durable head ports are rejected`);
  }
  return value;
}

function readPhysicalExperimentDurableHead(port, planHash) {
  const raw = port.production_ready === true
    ? readProductionPhysicalExperimentHead(
      assertProductionPhysicalExperimentDurableHeadPort(port),
    )
    : MECHANISM_A_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORTS.has(port)
      ? readMechanismAPhysicalExperimentHead(
        assertMechanismAPhysicalExperimentDurableHeadPort(port),
      )
      : (() => {
      const state = TEST_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_STATE.get(
        assertTestPhysicalExperimentDurableHeadPort(port),
      );
      return assertSynchronousDurableHeadResult(
        state.read_head(deepFreeze({
          version: PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_VERSION,
          plan_hash: planHash,
        })),
        "physical experiment durable head read",
      );
    })();
  if (raw == null) return null;
  const head = normalizePhysicalExperimentRowCommit(raw, "physical_experiment_durable_head");
  if (head.plan_hash !== planHash) {
    throw new Error("physical experiment durable head returned another plan");
  }
  return head;
}

function resolvePhysicalExperimentDurableCommit(port, expected) {
  const request = deepFreeze({
    version: PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_VERSION,
    plan_hash: expected.plan_hash,
    row_commit_digest: expected.row_commit_digest,
  });
  const raw = port.production_ready === true
    ? resolveProductionPhysicalExperimentCommit(
      assertProductionPhysicalExperimentDurableHeadPort(port),
      request,
    )
    : MECHANISM_A_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORTS.has(port)
      ? resolveMechanismAPhysicalExperimentCommit(
        assertMechanismAPhysicalExperimentDurableHeadPort(port),
        request,
      )
      : (() => {
      const state = TEST_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_STATE.get(
        assertTestPhysicalExperimentDurableHeadPort(port),
      );
      return assertSynchronousDurableHeadResult(
        state.resolve_committed_append(request),
        "physical experiment durable append readback",
      );
    })();
  if (raw == null) return null;
  const committed = normalizePhysicalExperimentRowCommit(
    raw,
    "physical_experiment_committed_append",
  );
  if (committed.plan_hash !== expected.plan_hash
      || committed.row_commit_digest !== expected.row_commit_digest) {
    throw new Error("physical experiment durable append readback returned another commit");
  }
  return committed;
}

function exactPhysicalExperimentRowCommit(left, right) {
  return left != null && right != null
    && left.row_commit_digest === right.row_commit_digest
    && hashCanonicalJson(left) === hashCanonicalJson(right);
}

function assertPhysicalExperimentLocalHeadCurrent(port, plan, rows) {
  const durableHead = readPhysicalExperimentDurableHead(port, plan.plan_hash);
  if (rows.length === 0) {
    if (durableHead != null) {
      throw new Error("physical experiment ledger reconstruction is behind the durable head");
    }
    return null;
  }
  const expected = physicalExperimentRowCommit(plan, rows[rows.length - 1]);
  if (!exactPhysicalExperimentRowCommit(durableHead, expected)) {
    throw new Error("physical experiment ledger reconstruction does not match the exact durable head");
  }
  return durableHead;
}

function commitPhysicalExperimentRow(port, expected, row) {
  let compareResult;
  let compareFailure = null;
  try {
    compareResult = port.production_ready === true
      ? appendProductionPhysicalExperimentRow(
        assertProductionPhysicalExperimentDurableHeadPort(port),
        deepFreeze({ commit: expected, row }),
      )
      : MECHANISM_A_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORTS.has(port)
        ? appendMechanismAPhysicalExperimentRow(
          assertMechanismAPhysicalExperimentDurableHeadPort(port),
          deepFreeze({ commit: expected, row }),
        )
      : TEST_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_STATE.get(
        assertTestPhysicalExperimentDurableHeadPort(port),
      ).compare_and_append(expected);
  } catch (cause) {
    compareFailure = cause;
  }
  if (compareResult && typeof compareResult.then === "function") {
    throw new Error(
      "physical experiment durable compare-and-append must be synchronous; async ports are rejected",
    );
  }
  if (compareFailure == null && typeof compareResult !== "boolean") {
    throw new Error("physical experiment durable compare-and-append must return a boolean");
  }
  const committed = resolvePhysicalExperimentDurableCommit(port, expected);
  if (exactPhysicalExperimentRowCommit(committed, expected)) return committed;

  const durableHead = readPhysicalExperimentDurableHead(port, expected.plan_hash);
  const message = compareFailure
    ? "physical experiment durable append acknowledgement was lost without exact readback"
    : compareResult
      ? "physical experiment durable append claimed success without exact readback"
      : durableHead == null
        ? "physical experiment durable append was not committed"
        : "physical experiment durable head compare-and-append conflict";
  const error = new Error(message);
  if (compareFailure) Object.defineProperty(error, "cause", { value: compareFailure });
  throw error;
}

function normalizeObservationWindow(input, label) {
  assertClosedObject(input, label, [
    "start_rule",
    "max_duration_ms",
    "max_clock_offset_abs_ms",
    "max_clock_uncertainty_ms",
  ]);
  return deepFreeze({
    start_rule: assertEnum(input.start_rule, OBSERVATION_START_RULES, `${label}.start_rule`),
    max_duration_ms: assertSafeInteger(input.max_duration_ms, `${label}.max_duration_ms`, { min: 1, max: 86_400_000 }),
    max_clock_offset_abs_ms: assertSafeInteger(
      input.max_clock_offset_abs_ms,
      `${label}.max_clock_offset_abs_ms`,
      { min: 0, max: 86_400_000 },
    ),
    max_clock_uncertainty_ms: assertSafeInteger(
      input.max_clock_uncertainty_ms,
      `${label}.max_clock_uncertainty_ms`,
      { min: 0, max: 86_400_000 },
    ),
  });
}

function normalizeRetryPolicy(input, label) {
  assertClosedObject(input, label, ["fresh_attempt_and_challenge", "max_attempts", "retry_on"]);
  if (input.fresh_attempt_and_challenge !== true) {
    throw new Error(`${label}.fresh_attempt_and_challenge must be true`);
  }
  const retryOn = normalizeUniqueArray(
    input.retry_on,
    `${label}.retry_on`,
    (entry, field) => assertEnum(entry, RETRY_DISPOSITIONS, field),
  );
  return deepFreeze({
    fresh_attempt_and_challenge: true,
    max_attempts: assertSafeInteger(input.max_attempts, `${label}.max_attempts`, { min: 1, max: 1000 }),
    retry_on: Object.freeze([...retryOn].sort()),
  });
}

function normalizeInstrumentAssuranceClaims(input, label) {
  assertClosedObject(input, label, [
    "identity_enrollment",
    "firmware_provenance",
    "command_surface_conformance",
    "transport_trust",
    "claims_digest",
  ]);
  const body = {
    identity_enrollment: assertDigest(input.identity_enrollment, `${label}.identity_enrollment`),
    firmware_provenance: assertDigest(input.firmware_provenance, `${label}.firmware_provenance`),
    command_surface_conformance: assertDigest(
      input.command_surface_conformance,
      `${label}.command_surface_conformance`,
    ),
    transport_trust: assertDigest(input.transport_trust, `${label}.transport_trust`),
  };
  const claimsDigest = hashCanonicalJson(body);
  if (assertDigest(input.claims_digest, `${label}.claims_digest`) !== claimsDigest) {
    throw new Error(`${label}.claims_digest does not match the assurance claims`);
  }
  return deepFreeze({ ...body, claims_digest: claimsDigest });
}

function normalizePlanRequestedEffect(input, label) {
  assertClosedObject(input, label, [
    "version",
    "template_id",
    "template_digest",
    "subject_ref",
    "subject_kind",
    "action",
    "channel",
    "persistence",
    "bounds",
  ]);
  if (input.version !== 1) throw new Error(`${label}.version must be 1`);
  return deepFreeze({
    version: 1,
    template_id: assertId(input.template_id, `${label}.template_id`),
    template_digest: assertDigest(input.template_digest, `${label}.template_digest`),
    subject_ref: normalizeOpaqueRef(input.subject_ref, `${label}.subject_ref`, { prefix: input.subject_kind }),
    subject_kind: assertEnum(input.subject_kind, EFFECT_SUBJECT_KINDS, `${label}.subject_kind`),
    action: assertEnum(input.action, EFFECT_ACTIONS, `${label}.action`),
    channel: assertEnum(input.channel, EFFECT_CHANNELS, `${label}.channel`),
    persistence: assertEnum(input.persistence, EFFECT_PERSISTENCE_VALUES, `${label}.persistence`),
    bounds: normalizeCanonicalJson(input.bounds, `${label}.bounds`),
  });
}

function normalizeControl(input, label) {
  assertClosedObject(input, label, ["kind", "plan_ref", "plan_digest"]);
  return deepFreeze({
    kind: assertId(input.kind, `${label}.kind`),
    plan_ref: normalizeOpaqueRef(input.plan_ref, `${label}.plan_ref`, { prefix: "stimulus-plan" }),
    plan_digest: assertDigest(input.plan_digest, `${label}.plan_digest`),
  });
}

function observerAttemptBindingDigest(input) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-observer-attempt-binding/v1",
    session_nucleus_hash: input.session_nucleus_hash,
    experiment_id: input.experiment_id,
    task_id: input.task_id,
    attempt_id: input.attempt_id,
    cohort_kind: input.cohort_kind,
    execution_request_digest: input.execution_request_digest,
    cohort_execution_request_digest: input.cohort_execution_request_digest,
    stimulus_plan_ref: input.stimulus_plan_ref,
    stimulus_plan_digest: input.stimulus_plan_digest,
    observer_id: input.observer_id,
    observer_identity_ref: input.observer_identity_ref,
    observer_enrollment_ref: input.observer_enrollment_ref,
    observer_enrollment_digest: input.observer_enrollment_digest,
    signer_key_id: input.signer_key_id,
    source_kind: input.source_kind,
    source_ref: input.source_ref,
    required_trust_domain_ref: input.required_trust_domain_ref,
    required_independence_domain_ref: input.required_independence_domain_ref,
    challenge_nonce: input.challenge_nonce,
  });
}

function normalizeObserverPlan(input, context, label, deps) {
  assertClosedObject(input, label, [
    "observer_id",
    "observer_identity_ref",
    "observer_enrollment_ref",
    "source_kind",
    "source_ref",
    "source_assurance_scheme",
    "required_trust_domain_ref",
    "required_independence_domain_ref",
    "challenge_nonce",
    "attempt_binding_digest",
    "external_outcome",
  ]);
  const registry = deps && deps.observerEnrollmentRegistry;
  assertPhysicalObserverEnrollmentRegistry(registry);
  if (registry.registry_digest !== context.observer_enrollment_registry_digest) {
    throw new Error(`${label} observer enrollment registry digest drift`);
  }
  const enrollmentRef = normalizeOpaqueRef(
    input.observer_enrollment_ref,
    `${label}.observer_enrollment_ref`,
    { prefix: "observer-enrollment" },
  );
  const enrollment = registry.get(enrollmentRef);
  if (!enrollment) throw new Error(`${label}.observer_enrollment_ref is not operator-enrolled`);
  const admissionNow = deps.trustedNow == null ? null : assertTimestamp(deps.trustedNow, "trusted_now");
  if (enrollment.revoked) throw new Error(`${label} observer enrollment is revoked`);
  if (admissionNow != null) {
    const nowMs = Date.parse(admissionNow);
    if (nowMs < Date.parse(enrollment.valid_from)) throw new Error(`${label} observer enrollment is not yet valid`);
    if (enrollment.expires_at != null && nowMs > Date.parse(enrollment.expires_at)) {
      throw new Error(`${label} observer enrollment is expired`);
    }
  }
  for (const [field, expected] of [
    ["observer_identity_ref", enrollment.observer_identity_ref],
    ["source_kind", enrollment.source_kind],
    ["source_ref", enrollment.source_ref],
    ["source_assurance_scheme", enrollment.source_assurance_scheme],
    ["required_trust_domain_ref", enrollment.trust_domain_ref],
    ["required_independence_domain_ref", enrollment.independence_domain_ref],
    ["external_outcome", enrollment.external_outcome_allowed],
  ]) {
    if (input[field] !== expected) throw new Error(`${label}.${field} does not match operator enrollment`);
  }
  const normalized = {
    observer_id: assertId(input.observer_id, `${label}.observer_id`),
    observer_identity_ref: normalizeOpaqueRef(
      input.observer_identity_ref,
      `${label}.observer_identity_ref`,
      { prefix: "observer" },
    ),
    observer_enrollment_ref: enrollmentRef,
    observer_enrollment_digest: enrollment.enrollment_digest,
    signer_key_id: enrollment.signer_key_id,
    source_kind: assertEnum(input.source_kind, OBSERVATION_SOURCE_KINDS, `${label}.source_kind`),
    source_ref: normalizeOpaqueRef(input.source_ref, `${label}.source_ref`),
    source_assurance_scheme: assertId(input.source_assurance_scheme, `${label}.source_assurance_scheme`),
    required_trust_domain_ref: normalizeOpaqueRef(
      input.required_trust_domain_ref,
      `${label}.required_trust_domain_ref`,
      { prefix: "trust-domain" },
    ),
    required_independence_domain_ref: normalizeOpaqueRef(
      input.required_independence_domain_ref,
      `${label}.required_independence_domain_ref`,
      { prefix: "independence-domain" },
    ),
    challenge_nonce: assertNonce(input.challenge_nonce, `${label}.challenge_nonce`),
    external_outcome: assertBoolean(input.external_outcome, `${label}.external_outcome`),
  };
  const expectedBinding = observerAttemptBindingDigest({ ...context, ...normalized });
  if (assertDigest(input.attempt_binding_digest, `${label}.attempt_binding_digest`) !== expectedBinding) {
    throw new Error(`${label}.attempt_binding_digest does not match the canonical observer attempt binding`);
  }
  return deepFreeze({ ...normalized, attempt_binding_digest: expectedBinding });
}

function normalizeCohort(input, kind, context, label, deps) {
  assertClosedObject(input, label, [
    "kind",
    "stimulus_plan_ref",
    "stimulus_plan_digest",
    "cohort_execution_request_digest",
    "grant_ref",
    "execution_identity",
    "expected_outcome_digest",
    "observer_plan",
  ]);
  if (input.kind !== kind) throw new Error(`${label}.kind must be ${kind}`);
  const stimulusPlanRef = normalizeOpaqueRef(
    input.stimulus_plan_ref,
    `${label}.stimulus_plan_ref`,
    { prefix: "stimulus-plan" },
  );
  const stimulusPlanDigest = assertDigest(input.stimulus_plan_digest, `${label}.stimulus_plan_digest`);
  const cohortExecutionRequestDigest = assertDigest(
    input.cohort_execution_request_digest,
    `${label}.cohort_execution_request_digest`,
  );
  const grantRef = normalizeOpaqueRef(input.grant_ref, `${label}.grant_ref`, { prefix: "grant" });
  const executionIdentity = normalizeOpaqueRef(
    input.execution_identity,
    `${label}.execution_identity`,
    { prefix: "execution" },
  );
  const observerPlan = normalizeUniqueArray(
    input.observer_plan,
    `${label}.observer_plan`,
    (entry, field) => normalizeObserverPlan(entry, {
      ...context,
      cohort_kind: kind,
      stimulus_plan_ref: stimulusPlanRef,
      stimulus_plan_digest: stimulusPlanDigest,
      cohort_execution_request_digest: cohortExecutionRequestDigest,
    }, field, deps),
    { nonempty: true },
  );
  const observerIds = observerPlan.map((entry) => entry.observer_id);
  if (new Set(observerIds).size !== observerIds.length) {
    throw new Error(`${label}.observer_plan must have unique observer_id values`);
  }
  return deepFreeze({
    kind,
    stimulus_plan_ref: stimulusPlanRef,
    stimulus_plan_digest: stimulusPlanDigest,
    cohort_execution_request_digest: cohortExecutionRequestDigest,
    grant_ref: grantRef,
    execution_identity: executionIdentity,
    expected_outcome_digest: assertDigest(input.expected_outcome_digest, `${label}.expected_outcome_digest`),
    observer_plan: observerPlan,
  });
}

function normalizePhysicalExperimentPlan(input, label = "physical_experiment_plan", deps = {}) {
  if (NORMALIZED_PLAN_DEPS.has(input)) {
    if (deps.observerEnrollmentRegistry != null || deps.planAdmission === true) {
      const registry = assertPhysicalObserverEnrollmentRegistry(deps.observerEnrollmentRegistry);
      if (registry.registry_digest !== input.observer_enrollment_registry_digest) {
        throw new Error(`${label}.observer_enrollment_registry_digest does not match the closed registry`);
      }
    }
    if (deps.physicalReceiptRegistry != null || deps.planAdmission === true) {
      const registry = assertPhysicalReceiptTrustRegistry(deps.physicalReceiptRegistry);
      if (registry.registry_digest !== input.physical_receipt_registry_digest) {
        throw new Error(`${label}.physical_receipt_registry_digest does not match the closed registry`);
      }
    }
    if (deps.evidenceReceiptRegistry != null || deps.planAdmission === true) {
      const registry = assertDurableReceiptTrustRegistry(deps.evidenceReceiptRegistry);
      if (registry.registry_digest !== input.evidence_receipt_registry_digest) {
        throw new Error(`${label}.evidence_receipt_registry_digest does not match the closed registry`);
      }
    }
    if (deps.planAdmission === true) {
      const trustedNow = assertTimestamp(deps.trustedNow, "trusted_now");
      const allocationReceipt = verifyPhysicalReceipt(
        input.attempt_allocation_receipt,
        "attempt_allocation",
        deps.physicalReceiptRegistry,
        { issuer_key_id: input.allocation_issuer_key_id, issuer_epoch: input.allocation_issuer_epoch },
        { mode: "admission", trustedNow, label: `${label}.attempt_allocation_receipt` },
      );
      if (Date.parse(allocationReceipt.signed_at) > Date.parse(trustedNow)) {
        throw new Error(`${label}.attempt_allocation_receipt is signed in the future`);
      }
      for (const cohort of [input.positive_cohort, input.control_cohort]) {
        for (const observer of cohort.observer_plan) {
          const enrollment = deps.observerEnrollmentRegistry.get(observer.observer_enrollment_ref);
          if (!enrollment || enrollment.enrollment_digest !== observer.observer_enrollment_digest) {
            throw new Error(`${label} observer enrollment changed since the plan was normalized`);
          }
          const nowMs = Date.parse(trustedNow);
          if (
            enrollment.revoked
            || nowMs < Date.parse(enrollment.valid_from)
            || (enrollment.expires_at != null && nowMs > Date.parse(enrollment.expires_at))
          ) throw new Error(`${label} observer enrollment is not currently active`);
        }
      }
    }
    return input;
  }
  assertClosedObject(input, label, [
    "version",
    "experiment_id",
    "task_id",
    "attempt_id",
    "session_nucleus_hash",
    "node_id",
    "contract_hash",
    "execution_request_digest",
    "hypothesis_ref",
    "claim_predicate_digest",
    "expected_positive_outcome_digest",
    "expected_control_outcome_digest",
    "verifier_template_id",
    "verifier_template_version",
    "verifier_template_digest",
    "decision_rule_digest",
    "observation_window",
    "retry_policy",
    "trust_registry_digest",
    "executed_evidence_registry_digest",
    "evidence_receipt_registry_digest",
    "evidence_receipt_issuer_key_id",
    "evidence_receipt_issuer_epoch",
    "observer_enrollment_registry_digest",
    "physical_receipt_registry_digest",
    "allocation_issuer_key_id",
    "allocation_issuer_epoch",
    "append_issuer_key_id",
    "append_issuer_epoch",
    "attempt_allocation_receipt",
    "ingestion_policy",
    "consumption_registry_digest",
    "consumption_issuer_key_id",
    "consumption_issuer_epoch",
    "instrument_ref",
    "instrument_identity_ref",
    "instrument_inventory_ref",
    "assurance_profile_id",
    "instrument_assurance_claims",
    "provider_manifest_digest",
    "source_asset_ref",
    "target_asset_ref",
    "operation_id",
    "parameter_digest",
    "requested_effects_registry_digest",
    "requested_effects",
    "requested_effects_digest",
    "positive_cohort",
    "control_cohort",
    "controls",
    "cleanup_plan_digest",
  ], ["plan_hash"]);
  if (input.version !== PHYSICAL_EXPERIMENT_PLAN_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_EXPERIMENT_PLAN_VERSION}`);
  }
  const experimentId = assertId(input.experiment_id, `${label}.experiment_id`);
  const taskId = assertToken(input.task_id, `${label}.task_id`);
  const attemptId = assertToken(input.attempt_id, `${label}.attempt_id`);
  const sessionNucleusHash = assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`);
  const observerEnrollmentRegistry = assertPhysicalObserverEnrollmentRegistry(deps.observerEnrollmentRegistry);
  const observerEnrollmentRegistryDigest = assertDigest(
    input.observer_enrollment_registry_digest,
    `${label}.observer_enrollment_registry_digest`,
  );
  if (observerEnrollmentRegistry.registry_digest !== observerEnrollmentRegistryDigest) {
    throw new Error(`${label}.observer_enrollment_registry_digest does not match the closed registry`);
  }
  const physicalReceiptRegistry = assertPhysicalReceiptTrustRegistry(deps.physicalReceiptRegistry);
  const physicalReceiptRegistryDigest = assertDigest(
    input.physical_receipt_registry_digest,
    `${label}.physical_receipt_registry_digest`,
  );
  if (physicalReceiptRegistry.registry_digest !== physicalReceiptRegistryDigest) {
    throw new Error(`${label}.physical_receipt_registry_digest does not match the closed registry`);
  }
  const evidenceReceiptRegistry = assertDurableReceiptTrustRegistry(deps.evidenceReceiptRegistry);
  const evidenceReceiptRegistryDigest = assertDigest(
    input.evidence_receipt_registry_digest,
    `${label}.evidence_receipt_registry_digest`,
  );
  if (evidenceReceiptRegistry.registry_digest !== evidenceReceiptRegistryDigest) {
    throw new Error(`${label}.evidence_receipt_registry_digest does not match the closed registry`);
  }
  const trustedNow = assertTimestamp(deps.trustedNow, "trusted_now");
  const executionRequestDigest = assertDigest(
    input.execution_request_digest,
    `${label}.execution_request_digest`,
  );
  const cohortContext = {
    session_nucleus_hash: sessionNucleusHash,
    experiment_id: experimentId,
    task_id: taskId,
    attempt_id: attemptId,
    execution_request_digest: executionRequestDigest,
    observer_enrollment_registry_digest: observerEnrollmentRegistryDigest,
  };
  const positiveCohort = normalizeCohort(
    input.positive_cohort,
    "positive",
    cohortContext,
    `${label}.positive_cohort`,
    { ...deps, trustedNow },
  );
  const controlCohort = normalizeCohort(
    input.control_cohort,
    "control",
    cohortContext,
    `${label}.control_cohort`,
    { ...deps, trustedNow },
  );
  const expectedPositive = assertDigest(
    input.expected_positive_outcome_digest,
    `${label}.expected_positive_outcome_digest`,
  );
  const expectedControl = assertDigest(
    input.expected_control_outcome_digest,
    `${label}.expected_control_outcome_digest`,
  );
  if (positiveCohort.expected_outcome_digest !== expectedPositive) {
    throw new Error(`${label}.positive_cohort expected outcome does not match the plan`);
  }
  if (controlCohort.expected_outcome_digest !== expectedControl) {
    throw new Error(`${label}.control_cohort expected outcome does not match the plan`);
  }
  if (expectedPositive === expectedControl) {
    throw new Error(`${label} requires a discriminating control outcome`);
  }
  if (positiveCohort.stimulus_plan_ref === controlCohort.stimulus_plan_ref) {
    throw new Error(`${label} positive and control cohorts require distinct stimulus plans`);
  }
  if (positiveCohort.stimulus_plan_digest === controlCohort.stimulus_plan_digest) {
    throw new Error(`${label} positive and control cohorts require distinct stimulus-plan digests`);
  }
  if (positiveCohort.cohort_execution_request_digest === controlCohort.cohort_execution_request_digest) {
    throw new Error(`${label} positive and control cohorts require distinct execution requests`);
  }
  for (const field of ["grant_ref", "execution_identity"]) {
    if (positiveCohort[field] === controlCohort[field]) {
      throw new Error(`${label} positive and control cohorts require distinct ${field} values`);
    }
  }
  const observerIds = [
    ...positiveCohort.observer_plan.map((entry) => entry.observer_id),
    ...controlCohort.observer_plan.map((entry) => entry.observer_id),
  ];
  if (new Set(observerIds).size !== observerIds.length) {
    throw new Error(`${label} observer IDs must be unique across cohorts`);
  }
  const challenges = [
    ...positiveCohort.observer_plan.map((entry) => entry.challenge_nonce),
    ...controlCohort.observer_plan.map((entry) => entry.challenge_nonce),
  ];
  if (new Set(challenges).size !== challenges.length) {
    throw new Error(`${label} challenge nonces must be unique across cohorts`);
  }
  const requestedEffects = normalizeUniqueArray(
    input.requested_effects,
    `${label}.requested_effects`,
    normalizePlanRequestedEffect,
    { nonempty: true },
  );
  const requestedEffectsDigest = hashCanonicalJson(requestedEffects);
  if (assertDigest(input.requested_effects_digest, `${label}.requested_effects_digest`) !== requestedEffectsDigest) {
    throw new Error(`${label}.requested_effects_digest does not match requested_effects`);
  }
  const controls = normalizeUniqueArray(input.controls, `${label}.controls`, normalizeControl, { nonempty: true });
  if (!controls.some((control) => (
    control.plan_ref === controlCohort.stimulus_plan_ref
    && control.plan_digest === controlCohort.stimulus_plan_digest
  ))) {
    throw new Error(`${label}.controls must bind the control cohort stimulus plan and digest`);
  }
  const instrumentRef = normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, { prefix: "instrument" });
  const sourceAssetRef = normalizeOpaqueRef(input.source_asset_ref, `${label}.source_asset_ref`, { prefix: "source" });
  const targetAssetRef = normalizeOpaqueRef(input.target_asset_ref, `${label}.target_asset_ref`, { prefix: "target" });
  if (sourceAssetRef === targetAssetRef) throw new Error(`${label} source and target assets must be distinct`);
  for (let index = 0; index < requestedEffects.length; index += 1) {
    const effect = requestedEffects[index];
    if (effect.subject_kind === "instrument" && effect.subject_ref !== instrumentRef) {
      throw new Error(`${label}.requested_effects[${index}] does not bind the planned instrument`);
    }
    if (effect.subject_kind === "target" && effect.subject_ref !== targetAssetRef) {
      throw new Error(`${label}.requested_effects[${index}] does not bind the planned target asset`);
    }
  }
  const body = {
    version: PHYSICAL_EXPERIMENT_PLAN_VERSION,
    experiment_id: experimentId,
    task_id: taskId,
    attempt_id: attemptId,
    session_nucleus_hash: sessionNucleusHash,
    node_id: assertToken(input.node_id, `${label}.node_id`),
    contract_hash: assertDigest(input.contract_hash, `${label}.contract_hash`),
    execution_request_digest: executionRequestDigest,
    hypothesis_ref: normalizeOpaqueRef(input.hypothesis_ref, `${label}.hypothesis_ref`, { prefix: "hypothesis" }),
    claim_predicate_digest: assertDigest(input.claim_predicate_digest, `${label}.claim_predicate_digest`),
    expected_positive_outcome_digest: expectedPositive,
    expected_control_outcome_digest: expectedControl,
    verifier_template_id: assertId(input.verifier_template_id, `${label}.verifier_template_id`),
    verifier_template_version: assertSafeInteger(
      input.verifier_template_version,
      `${label}.verifier_template_version`,
      { min: 1 },
    ),
    verifier_template_digest: assertDigest(input.verifier_template_digest, `${label}.verifier_template_digest`),
    decision_rule_digest: assertDigest(input.decision_rule_digest, `${label}.decision_rule_digest`),
    observation_window: normalizeObservationWindow(input.observation_window, `${label}.observation_window`),
    retry_policy: normalizeRetryPolicy(input.retry_policy, `${label}.retry_policy`),
    trust_registry_digest: assertDigest(input.trust_registry_digest, `${label}.trust_registry_digest`),
    executed_evidence_registry_digest: assertDigest(
      input.executed_evidence_registry_digest,
      `${label}.executed_evidence_registry_digest`,
    ),
    evidence_receipt_registry_digest: evidenceReceiptRegistryDigest,
    evidence_receipt_issuer_key_id: normalizeOpaqueRef(
      input.evidence_receipt_issuer_key_id,
      `${label}.evidence_receipt_issuer_key_id`,
      { prefix: "signer-key" },
    ),
    evidence_receipt_issuer_epoch: assertSafeInteger(
      input.evidence_receipt_issuer_epoch,
      `${label}.evidence_receipt_issuer_epoch`,
      { min: 1 },
    ),
    observer_enrollment_registry_digest: observerEnrollmentRegistryDigest,
    physical_receipt_registry_digest: physicalReceiptRegistryDigest,
    allocation_issuer_key_id: normalizeOpaqueRef(
      input.allocation_issuer_key_id,
      `${label}.allocation_issuer_key_id`,
      { prefix: "signer-key" },
    ),
    allocation_issuer_epoch: assertSafeInteger(
      input.allocation_issuer_epoch,
      `${label}.allocation_issuer_epoch`,
      { min: 1 },
    ),
    append_issuer_key_id: normalizeOpaqueRef(
      input.append_issuer_key_id,
      `${label}.append_issuer_key_id`,
      { prefix: "signer-key" },
    ),
    append_issuer_epoch: assertSafeInteger(
      input.append_issuer_epoch,
      `${label}.append_issuer_epoch`,
      { min: 1 },
    ),
    ingestion_policy: (() => {
      assertClosedObject(input.ingestion_policy, `${label}.ingestion_policy`, [
        "max_future_skew_ms", "max_ingestion_delay_ms",
      ]);
      return deepFreeze({
        max_future_skew_ms: assertSafeInteger(
          input.ingestion_policy.max_future_skew_ms,
          `${label}.ingestion_policy.max_future_skew_ms`,
          { min: 0, max: 300_000 },
        ),
        max_ingestion_delay_ms: assertSafeInteger(
          input.ingestion_policy.max_ingestion_delay_ms,
          `${label}.ingestion_policy.max_ingestion_delay_ms`,
          { min: 0, max: 86_400_000 },
        ),
      });
    })(),
    consumption_registry_digest: assertDigest(
      input.consumption_registry_digest,
      `${label}.consumption_registry_digest`,
    ),
    consumption_issuer_key_id: normalizeOpaqueRef(
      input.consumption_issuer_key_id,
      `${label}.consumption_issuer_key_id`,
      { prefix: "signer-key" },
    ),
    consumption_issuer_epoch: assertSafeInteger(
      input.consumption_issuer_epoch,
      `${label}.consumption_issuer_epoch`,
      { min: 1 },
    ),
    instrument_ref: instrumentRef,
    instrument_identity_ref: normalizeOpaqueRef(
      input.instrument_identity_ref,
      `${label}.instrument_identity_ref`,
      { prefix: "instrument-identity" },
    ),
    instrument_inventory_ref: normalizeOpaqueRef(
      input.instrument_inventory_ref,
      `${label}.instrument_inventory_ref`,
      { prefix: "inventory" },
    ),
    assurance_profile_id: assertToken(input.assurance_profile_id, `${label}.assurance_profile_id`),
    instrument_assurance_claims: normalizeInstrumentAssuranceClaims(
      input.instrument_assurance_claims,
      `${label}.instrument_assurance_claims`,
    ),
    provider_manifest_digest: assertDigest(input.provider_manifest_digest, `${label}.provider_manifest_digest`),
    source_asset_ref: sourceAssetRef,
    target_asset_ref: targetAssetRef,
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    parameter_digest: assertDigest(input.parameter_digest, `${label}.parameter_digest`),
    requested_effects_registry_digest: assertDigest(
      input.requested_effects_registry_digest,
      `${label}.requested_effects_registry_digest`,
    ),
    requested_effects: requestedEffects,
    requested_effects_digest: requestedEffectsDigest,
    positive_cohort: positiveCohort,
    control_cohort: controlCohort,
    controls,
    cleanup_plan_digest: assertDigest(input.cleanup_plan_digest, `${label}.cleanup_plan_digest`),
  };
  const allocationBody = {
    version: PHYSICAL_ALLOCATION_RECEIPT_VERSION,
    session_nucleus_hash: sessionNucleusHash,
    experiment_id: experimentId,
    task_id: taskId,
    attempt_id: attemptId,
    execution_request_digest: executionRequestDigest,
    cohort_bindings: [positiveCohort, controlCohort].map((cohort) => deepFreeze({
      cohort_kind: cohort.kind,
      cohort_execution_request_digest: cohort.cohort_execution_request_digest,
      grant_ref: cohort.grant_ref,
      execution_identity: cohort.execution_identity,
      challenge_nonces: Object.freeze(cohort.observer_plan.map((observer) => observer.challenge_nonce).sort()),
    })),
  };
  if (
    body.consumption_registry_digest !== body.physical_receipt_registry_digest
    || body.consumption_issuer_key_id !== body.allocation_issuer_key_id
    || body.consumption_issuer_epoch !== body.allocation_issuer_epoch
  ) {
    throw new Error(`${label} consumption issuer must be the plan-bound durable allocation issuer`);
  }
  allocationBody.binding_digest = attemptAllocationBindingDigest(allocationBody);
  const allocationReceipt = verifyPhysicalReceipt(
    input.attempt_allocation_receipt,
    "attempt_allocation",
    physicalReceiptRegistry,
    { issuer_key_id: body.allocation_issuer_key_id, issuer_epoch: body.allocation_issuer_epoch },
    { mode: "admission", trustedNow, label: `${label}.attempt_allocation_receipt` },
  );
  if (hashCanonicalJson(allocationReceipt.body) !== hashCanonicalJson(allocationBody)) {
    throw new Error(`${label}.attempt_allocation_receipt does not bind this attempt, challenges, grants, and executions`);
  }
  if (Date.parse(allocationReceipt.signed_at) > Date.parse(trustedNow)) {
    throw new Error(`${label}.attempt_allocation_receipt is signed in the future`);
  }
  body.attempt_allocation_receipt = allocationReceipt;
  const planHash = hashCanonicalJson(body);
  if (input.plan_hash != null && assertDigest(input.plan_hash, `${label}.plan_hash`) !== planHash) {
    throw new Error(`${label}.plan_hash does not match the immutable plan`);
  }
  const plan = deepFreeze({ ...body, plan_hash: planHash });
  NORMALIZED_PLAN_DEPS.set(plan, {
    observerEnrollmentRegistry,
    physicalReceiptRegistry,
    evidenceReceiptRegistry,
  });
  return plan;
}

function commonPayload(input, plan, label) {
  const common = {
    version: PHYSICAL_EXPERIMENT_ROW_VERSION,
    plan_hash: assertDigest(input.plan_hash, `${label}.plan_hash`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    task_id: assertToken(input.task_id, `${label}.task_id`),
    attempt_id: assertToken(input.attempt_id, `${label}.attempt_id`),
  };
  for (const [field, expected] of [
    ["plan_hash", plan.plan_hash],
    ["session_nucleus_hash", plan.session_nucleus_hash],
    ["task_id", plan.task_id],
    ["attempt_id", plan.attempt_id],
  ]) {
    if (common[field] !== expected) throw new Error(`${label}.${field} does not match the immutable plan`);
  }
  return common;
}

function consumptionAttestationInputDigest(attestation) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-one-use-consumption/v2",
    receipt_digest: attestation.receipt_digest || attestation.attestation_digest,
  });
}

function normalizeConsumptionAttestation(
  input,
  expectedKind,
  expectedBindingDigest,
  expectedSubjectRef,
  plan,
  label,
  { mode = "historical", trustedNow = null } = {},
) {
  const planDeps = NORMALIZED_PLAN_DEPS.get(plan);
  if (!planDeps) throw new Error(`${label} requires a normalized plan with closed receipt registries`);
  let durableReceipt = input;
  let providedProjection = null;
  if (isPlainObject(input) && Object.hasOwn(input, "durable_receipt")) {
    assertClosedObject(input, label, [
      "version",
      "kind",
      "binding_digest",
      "subject_ref",
      "consumption_ref",
      "plan_hash",
      "attempt_id",
      "sequence",
      "consumed_at",
      "registry_digest",
      "issuer_key_id",
      "issuer_epoch",
      "receipt_signed_at",
      "durable_receipt",
      "attestation_digest",
    ]);
    providedProjection = input;
    durableReceipt = input.durable_receipt;
  }
  const receipt = verifyPhysicalReceipt(
    durableReceipt,
    "physical_consumption",
    planDeps.physicalReceiptRegistry,
    { issuer_key_id: plan.consumption_issuer_key_id, issuer_epoch: plan.consumption_issuer_epoch },
    { mode: receiptTrustValidationMode(mode), trustedNow, label },
  );
  assertClosedObject(receipt.body, `${label}.body`, [
    "version",
    "kind",
    "binding_digest",
    "subject_ref",
    "consumption_ref",
    "plan_hash",
    "attempt_id",
    "sequence",
    "consumed_at",
  ]);
  const kind = assertEnum(receipt.body.kind, CONSUMPTION_KINDS, `${label}.body.kind`);
  if (kind !== expectedKind) throw new Error(`${label}.body.kind must be ${expectedKind}`);
  if (receipt.body.version !== CONSUMPTION_ATTESTATION_VERSION) {
    throw new Error(`${label}.body.version must be ${CONSUMPTION_ATTESTATION_VERSION}`);
  }
  const body = {
    version: CONSUMPTION_ATTESTATION_VERSION,
    kind,
    binding_digest: assertDigest(receipt.body.binding_digest, `${label}.body.binding_digest`),
    subject_ref: normalizeOpaqueRef(receipt.body.subject_ref, `${label}.body.subject_ref`),
    consumption_ref: normalizeOpaqueRef(
      receipt.body.consumption_ref,
      `${label}.body.consumption_ref`,
      { prefix: "consumption" },
    ),
    plan_hash: assertDigest(receipt.body.plan_hash, `${label}.body.plan_hash`),
    attempt_id: assertToken(receipt.body.attempt_id, `${label}.body.attempt_id`),
    sequence: assertSafeInteger(receipt.body.sequence, `${label}.body.sequence`, { min: 1 }),
    consumed_at: assertTimestamp(receipt.body.consumed_at, `${label}.body.consumed_at`),
  };
  if (body.binding_digest !== expectedBindingDigest) {
    throw new Error(`${label}.body.binding_digest does not match the one-use subject`);
  }
  if (body.subject_ref !== expectedSubjectRef) throw new Error(`${label}.body.subject_ref drift`);
  if (body.plan_hash !== plan.plan_hash || body.attempt_id !== plan.attempt_id) {
    throw new Error(`${label} crosses an immutable plan or attempt boundary`);
  }
  if (Date.parse(receipt.signed_at) < Date.parse(body.consumed_at)) {
    throw new Error(`${label} durable receipt cannot predate the asserted consumption`);
  }
  const normalized = {
    ...body,
    registry_digest: receipt.registry_digest,
    issuer_key_id: receipt.issuer_key_id,
    issuer_epoch: receipt.issuer_epoch,
    receipt_signed_at: receipt.signed_at,
    durable_receipt: receipt,
    attestation_digest: receipt.receipt_digest,
  };
  if (providedProjection) {
    for (const field of [
      "version",
      "kind",
      "binding_digest",
      "subject_ref",
      "consumption_ref",
      "plan_hash",
      "attempt_id",
      "sequence",
      "consumed_at",
      "registry_digest",
      "issuer_key_id",
      "issuer_epoch",
      "receipt_signed_at",
      "attestation_digest",
    ]) {
      if (providedProjection[field] !== normalized[field]) {
        throw new Error(`${label}.${field} drifts from the durable receipt`);
      }
    }
  }
  return deepFreeze(normalized);
}

function executionConsumptionBindingDigest(plan, cohort, grantRef, executionIdentity) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-grant-consumption/v1",
    plan_hash: plan.plan_hash,
    session_nucleus_hash: plan.session_nucleus_hash,
    attempt_id: plan.attempt_id,
    cohort_kind: cohort.kind,
    stimulus_plan_ref: cohort.stimulus_plan_ref,
    stimulus_plan_digest: cohort.stimulus_plan_digest,
    cohort_execution_request_digest: cohort.cohort_execution_request_digest,
    grant_ref: grantRef,
    execution_identity: executionIdentity,
  });
}

function observationConsumptionBindingDigest(plan, observer, input, replayGuard) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-observation-consumption/v1",
    plan_hash: plan.plan_hash,
    session_nucleus_hash: plan.session_nucleus_hash,
    attempt_id: plan.attempt_id,
    cohort_kind: input.cohort_kind,
    execution_receipt_ref: input.execution_receipt_ref,
    grant_ref: input.grant_ref,
    execution_identity: input.execution_identity,
    observer_id: observer.observer_id,
    observer_identity_ref: observer.observer_identity_ref,
    source_ref: observer.source_ref,
    challenge_nonce: observer.challenge_nonce,
    attempt_binding_digest: observer.attempt_binding_digest,
    replay_guard: replayGuard,
  });
}

function normalizeExecutionReceiptPayload(input, plan, label, validation = {}) {
  assertClosedObject(input, label, [
    "version",
    "plan_hash",
    "session_nucleus_hash",
    "task_id",
    "attempt_id",
    "cohort_kind",
    "stimulus_plan_ref",
    "stimulus_plan_digest",
    "cohort_execution_request_digest",
    "grant_ref",
    "execution_identity",
    "execution_request_digest",
    "instrument_ref",
    "instrument_identity_ref",
    "instrument_inventory_ref",
    "provider_manifest_digest",
    "instrument_trust_domain_ref",
    "status",
    "started_at",
    "ended_at",
    "consumption_attestation",
  ], ["state_epoch_before", "state_epoch_after", "stimulus_artifact_ref"]);
  const common = commonPayload(input, plan, label);
  const startedAt = assertTimestamp(input.started_at, `${label}.started_at`);
  const endedAt = assertTimestamp(input.ended_at, `${label}.ended_at`);
  if (Date.parse(endedAt) < Date.parse(startedAt)) throw new Error(`${label}.ended_at must not precede started_at`);
  if (input.execution_request_digest !== plan.execution_request_digest) {
    throw new Error(`${label}.execution_request_digest does not match the immutable plan`);
  }
  if (input.instrument_ref !== plan.instrument_ref) {
    throw new Error(`${label}.instrument_ref does not match the immutable plan`);
  }
  const cohortKind = assertEnum(input.cohort_kind, COHORT_KINDS, `${label}.cohort_kind`);
  const cohort = cohortKind === "positive" ? plan.positive_cohort : plan.control_cohort;
  for (const [field, expected] of [
    ["stimulus_plan_ref", cohort.stimulus_plan_ref],
    ["stimulus_plan_digest", cohort.stimulus_plan_digest],
    ["cohort_execution_request_digest", cohort.cohort_execution_request_digest],
    ["instrument_identity_ref", plan.instrument_identity_ref],
    ["instrument_inventory_ref", plan.instrument_inventory_ref],
    ["provider_manifest_digest", plan.provider_manifest_digest],
    ["grant_ref", cohort.grant_ref],
    ["execution_identity", cohort.execution_identity],
  ]) {
    if (input[field] !== expected) throw new Error(`${label}.${field} does not match the immutable plan`);
  }
  const grantRef = normalizeOpaqueRef(input.grant_ref, `${label}.grant_ref`, { prefix: "grant" });
  const executionIdentity = normalizeOpaqueRef(
    input.execution_identity,
    `${label}.execution_identity`,
    { prefix: "execution" },
  );
  const consumptionBinding = executionConsumptionBindingDigest(plan, cohort, grantRef, executionIdentity);
  const consumptionAttestation = normalizeConsumptionAttestation(
    input.consumption_attestation,
    "grant",
    consumptionBinding,
    grantRef,
    plan,
    `${label}.consumption_attestation`,
    validation,
  );
  if (Date.parse(consumptionAttestation.consumed_at) > Date.parse(startedAt)) {
    throw new Error(`${label}.consumption_attestation must precede execution start`);
  }
  const payload = {
    ...common,
    cohort_kind: cohortKind,
    stimulus_plan_ref: cohort.stimulus_plan_ref,
    stimulus_plan_digest: cohort.stimulus_plan_digest,
    cohort_execution_request_digest: cohort.cohort_execution_request_digest,
    grant_ref: grantRef,
    execution_identity: executionIdentity,
    execution_request_digest: plan.execution_request_digest,
    instrument_ref: plan.instrument_ref,
    instrument_identity_ref: plan.instrument_identity_ref,
    instrument_inventory_ref: plan.instrument_inventory_ref,
    provider_manifest_digest: plan.provider_manifest_digest,
    instrument_trust_domain_ref: normalizeOpaqueRef(
      input.instrument_trust_domain_ref,
      `${label}.instrument_trust_domain_ref`,
      { prefix: "trust-domain" },
    ),
    status: assertEnum(input.status, EXECUTION_STATUSES, `${label}.status`),
    started_at: startedAt,
    ended_at: endedAt,
    consumption_attestation: consumptionAttestation,
  };
  for (const field of ["state_epoch_before", "state_epoch_after"]) {
    if (input[field] != null) payload[field] = assertSafeInteger(input[field], `${label}.${field}`, { min: 0 });
  }
  if (
    payload.state_epoch_before != null
    && payload.state_epoch_after != null
    && payload.state_epoch_after < payload.state_epoch_before
  ) {
    throw new Error(`${label}.state_epoch_after must not precede state_epoch_before`);
  }
  if (input.stimulus_artifact_ref != null) {
    payload.stimulus_artifact_ref = normalizeOpaqueRef(
      input.stimulus_artifact_ref,
      `${label}.stimulus_artifact_ref`,
      { prefix: "artifact" },
    );
  }
  return deepFreeze(payload);
}

function normalizeReplayGuard(input, challengeNonce, label) {
  assertClosedObject(input, label, ["kind", "value"]);
  const kind = assertEnum(input.kind, REPLAY_GUARD_KINDS, `${label}.kind`);
  if (kind === "monotonic_sequence") {
    return deepFreeze({ kind, value: assertSafeInteger(input.value, `${label}.value`, { min: 1 }) });
  }
  const value = assertNonce(input.value, `${label}.value`);
  if (value !== challengeNonce) throw new Error(`${label}.value must match the plan-bound one-time challenge`);
  return deepFreeze({ kind, value });
}

function planObserver(plan, cohortKind, observerId) {
  const cohort = cohortKind === "positive" ? plan.positive_cohort : plan.control_cohort;
  return cohort.observer_plan.find((entry) => entry.observer_id === observerId) || null;
}

function normalizeObservationPayload(input, plan, label, validation = {}) {
  assertClosedObject(input, label, [
    "version",
    "plan_hash",
    "session_nucleus_hash",
    "task_id",
    "attempt_id",
    "cohort_kind",
    "execution_receipt_ref",
    "grant_ref",
    "execution_identity",
    "observer_id",
    "observer_enrollment_ref",
    "source_kind",
    "source_ref",
    "trust_domain_ref",
    "independence_domain_ref",
    "observer_identity_ref",
    "source_assurance_scheme",
    "challenge_nonce",
    "attempt_binding_digest",
    "replay_guard",
    "consumption_attestation",
    "observed_outcome_digest",
    "observed_state_digest",
    "captured_at",
    "received_at",
    "clock_offset_ms",
    "clock_uncertainty_ms",
  ], ["observed_state_epoch", "artifact_ref"]);
  const common = commonPayload(input, plan, label);
  const cohortKind = assertEnum(input.cohort_kind, COHORT_KINDS, `${label}.cohort_kind`);
  const observerId = assertId(input.observer_id, `${label}.observer_id`);
  const observer = planObserver(plan, cohortKind, observerId);
  if (!observer) throw new Error(`${label}.observer_id is not planned for the ${cohortKind} cohort`);
  const capturedAt = assertTimestamp(input.captured_at, `${label}.captured_at`);
  const receivedAt = assertTimestamp(input.received_at, `${label}.received_at`);
  const clockOffset = assertSafeInteger(
    input.clock_offset_ms,
    `${label}.clock_offset_ms`,
    {
      min: -plan.observation_window.max_clock_offset_abs_ms,
      max: plan.observation_window.max_clock_offset_abs_ms,
    },
  );
  const clockUncertainty = assertSafeInteger(
    input.clock_uncertainty_ms,
    `${label}.clock_uncertainty_ms`,
    { min: 0, max: plan.observation_window.max_clock_uncertainty_ms },
  );
  const correctedCapturedAtMs = Date.parse(capturedAt) + clockOffset;
  if (correctedCapturedAtMs - clockUncertainty > Date.parse(receivedAt)) {
    throw new Error(`${label}.received_at precedes the corrected capture interval`);
  }
  for (const [field, expected] of [
    ["source_kind", observer.source_kind],
    ["source_ref", observer.source_ref],
    ["trust_domain_ref", observer.required_trust_domain_ref],
    ["independence_domain_ref", observer.required_independence_domain_ref],
    ["observer_identity_ref", observer.observer_identity_ref],
    ["observer_enrollment_ref", observer.observer_enrollment_ref],
    ["source_assurance_scheme", observer.source_assurance_scheme],
    ["challenge_nonce", observer.challenge_nonce],
    ["attempt_binding_digest", observer.attempt_binding_digest],
  ]) {
    if (input[field] !== expected) throw new Error(`${label}.${field} does not match the immutable observer plan`);
  }
  const executionReceiptRef = normalizeOpaqueRef(
    input.execution_receipt_ref,
    `${label}.execution_receipt_ref`,
    { prefix: ROW_PREFIX.execution_receipt },
  );
  const grantRef = normalizeOpaqueRef(input.grant_ref, `${label}.grant_ref`, { prefix: "grant" });
  const executionIdentity = normalizeOpaqueRef(
    input.execution_identity,
    `${label}.execution_identity`,
    { prefix: "execution" },
  );
  const replayGuard = normalizeReplayGuard(input.replay_guard, observer.challenge_nonce, `${label}.replay_guard`);
  const consumptionBinding = observationConsumptionBindingDigest(plan, observer, {
    cohort_kind: cohortKind,
    execution_receipt_ref: executionReceiptRef,
    grant_ref: grantRef,
    execution_identity: executionIdentity,
  }, replayGuard);
  const consumptionAttestation = normalizeConsumptionAttestation(
    input.consumption_attestation,
    replayGuard.kind,
    consumptionBinding,
    replayGuard.kind === "one_time_challenge"
      ? `challenge:${observer.challenge_nonce}`
      : `monotonic:${observer.observer_enrollment_ref}`,
    plan,
    `${label}.consumption_attestation`,
    validation,
  );
  if (replayGuard.kind === "monotonic_sequence" && consumptionAttestation.sequence !== replayGuard.value) {
    throw new Error(`${label}.consumption_attestation sequence does not match the monotonic replay guard`);
  }
  if (Date.parse(consumptionAttestation.consumed_at) > Date.parse(receivedAt)) {
    throw new Error(`${label}.consumption_attestation cannot postdate observation receipt`);
  }
  const payload = {
    ...common,
    cohort_kind: cohortKind,
    execution_receipt_ref: executionReceiptRef,
    grant_ref: grantRef,
    execution_identity: executionIdentity,
    observer_id: observerId,
    observer_enrollment_ref: observer.observer_enrollment_ref,
    source_kind: observer.source_kind,
    source_ref: observer.source_ref,
    trust_domain_ref: observer.required_trust_domain_ref,
    independence_domain_ref: observer.required_independence_domain_ref,
    observer_identity_ref: observer.observer_identity_ref,
    source_assurance_scheme: observer.source_assurance_scheme,
    challenge_nonce: observer.challenge_nonce,
    attempt_binding_digest: observer.attempt_binding_digest,
    replay_guard: replayGuard,
    consumption_attestation: consumptionAttestation,
    observed_outcome_digest: assertDigest(input.observed_outcome_digest, `${label}.observed_outcome_digest`),
    observed_state_digest: assertDigest(input.observed_state_digest, `${label}.observed_state_digest`),
    captured_at: capturedAt,
    received_at: receivedAt,
    clock_offset_ms: clockOffset,
    clock_uncertainty_ms: clockUncertainty,
  };
  if (input.observed_state_epoch != null) {
    payload.observed_state_epoch = assertSafeInteger(
      input.observed_state_epoch,
      `${label}.observed_state_epoch`,
      { min: 0 },
    );
  }
  if (input.artifact_ref != null) {
    payload.artifact_ref = normalizeOpaqueRef(input.artifact_ref, `${label}.artifact_ref`, { prefix: "artifact" });
  }
  return deepFreeze(payload);
}

function normalizeEvidenceVerificationBinding(input, label) {
  assertClosedObject(input, label, [
    "version",
    "executed_evidence_ref",
    "verification_receipt_ref",
    "verification_receipt_digest",
  ]);
  if (input.version !== EVIDENCE_VERIFICATION_BINDING_VERSION) {
    throw new Error(`${label}.version must be ${EVIDENCE_VERIFICATION_BINDING_VERSION}`);
  }
  return deepFreeze({
    version: EVIDENCE_VERIFICATION_BINDING_VERSION,
    executed_evidence_ref: normalizeExecutedEvidenceRef(
      input.executed_evidence_ref,
      `${label}.executed_evidence_ref`,
    ),
    verification_receipt_ref: normalizeOpaqueRef(
      input.verification_receipt_ref,
      `${label}.verification_receipt_ref`,
      { prefix: "evidence-verification" },
    ),
    verification_receipt_digest: assertDigest(
      input.verification_receipt_digest,
      `${label}.verification_receipt_digest`,
    ),
  });
}

function normalizeExecutedEvidenceRefs(value, label) {
  const refs = normalizeUniqueArray(value, label, normalizeEvidenceVerificationBinding);
  return Object.freeze([...refs].sort((left, right) => (
    left.executed_evidence_ref.evidence_ref.localeCompare(right.executed_evidence_ref.evidence_ref)
  )));
}

function normalizeClaimVerdictPayload(input, plan, label) {
  assertClosedObject(input, label, [
    "version",
    "plan_hash",
    "session_nucleus_hash",
    "task_id",
    "attempt_id",
    "execution_receipt_refs",
    "observation_refs",
    "positive_executed_evidence_refs",
    "control_executed_evidence_refs",
    "executed_evidence_registry_digest",
    "verifier_template_id",
    "verifier_template_version",
    "verifier_template_digest",
    "decision_rule_digest",
    "verifier_execution_receipt_ref",
    "verifier_execution_receipt_digest",
    "outcome",
    "reason_code",
    "validity_kind",
    "valid_from",
    "decided_at",
  ], ["state_epoch", "expires_at", "capability_instance_ref", "custody_state_digest"]);
  const common = commonPayload(input, plan, label);
  for (const [field, expected] of [
    ["verifier_template_id", plan.verifier_template_id],
    ["verifier_template_version", plan.verifier_template_version],
    ["verifier_template_digest", plan.verifier_template_digest],
    ["decision_rule_digest", plan.decision_rule_digest],
  ]) {
    if (input[field] !== expected) throw new Error(`${label}.${field} does not match the immutable plan`);
  }
  const validityKind = assertEnum(input.validity_kind, VALIDITY_KINDS, `${label}.validity_kind`);
  const validFrom = assertTimestamp(input.valid_from, `${label}.valid_from`);
  const decidedAt = assertTimestamp(input.decided_at, `${label}.decided_at`);
  if (Date.parse(validFrom) < Date.parse(decidedAt)) {
    throw new Error(`${label}.valid_from must not precede decided_at`);
  }
  const payload = {
    ...common,
    execution_receipt_refs: normalizeSortedRefs(
      input.execution_receipt_refs,
      `${label}.execution_receipt_refs`,
      ROW_PREFIX.execution_receipt,
    ),
    observation_refs: normalizeSortedRefs(input.observation_refs, `${label}.observation_refs`, ROW_PREFIX.observation),
    positive_executed_evidence_refs: normalizeExecutedEvidenceRefs(
      input.positive_executed_evidence_refs,
      `${label}.positive_executed_evidence_refs`,
    ),
    control_executed_evidence_refs: normalizeExecutedEvidenceRefs(
      input.control_executed_evidence_refs,
      `${label}.control_executed_evidence_refs`,
    ),
    executed_evidence_registry_digest: assertDigest(
      input.executed_evidence_registry_digest,
      `${label}.executed_evidence_registry_digest`,
    ),
    verifier_template_id: plan.verifier_template_id,
    verifier_template_version: plan.verifier_template_version,
    verifier_template_digest: plan.verifier_template_digest,
    decision_rule_digest: plan.decision_rule_digest,
    verifier_execution_receipt_ref: normalizeOpaqueRef(
      input.verifier_execution_receipt_ref,
      `${label}.verifier_execution_receipt_ref`,
      { prefix: "verifier-execution" },
    ),
    verifier_execution_receipt_digest: assertDigest(
      input.verifier_execution_receipt_digest,
      `${label}.verifier_execution_receipt_digest`,
    ),
    outcome: assertEnum(input.outcome, CLAIM_DISPOSITIONS, `${label}.outcome`),
    reason_code: assertEnum(input.reason_code, CLAIM_REASON_CODES, `${label}.reason_code`),
    validity_kind: validityKind,
    valid_from: validFrom,
    decided_at: decidedAt,
  };
  if (payload.executed_evidence_registry_digest !== plan.executed_evidence_registry_digest) {
    throw new Error(`${label}.executed_evidence_registry_digest does not match the immutable plan`);
  }
  const liveFields = ["state_epoch", "expires_at", "capability_instance_ref", "custody_state_digest"];
  if (validityKind === "live_capability") {
    const missing = liveFields.filter((field) => input[field] == null);
    if (missing.length > 0) throw new Error(`${label} live capability is missing fields: ${missing.join(", ")}`);
    payload.state_epoch = assertSafeInteger(input.state_epoch, `${label}.state_epoch`, { min: 0 });
    payload.expires_at = assertTimestamp(input.expires_at, `${label}.expires_at`);
    if (Date.parse(payload.expires_at) <= Date.parse(payload.valid_from)) {
      throw new Error(`${label}.expires_at must be after valid_from`);
    }
    payload.capability_instance_ref = normalizeOpaqueRef(
      input.capability_instance_ref,
      `${label}.capability_instance_ref`,
      { prefix: "capability-instance" },
    );
    payload.custody_state_digest = assertDigest(input.custody_state_digest, `${label}.custody_state_digest`);
  } else if (liveFields.some((field) => input[field] != null)) {
    throw new Error(`${label} historical event cannot carry live-capability fields`);
  }
  return deepFreeze(payload);
}

function normalizeCleanupVerdictPayload(input, plan, label) {
  assertClosedObject(input, label, [
    "version",
    "plan_hash",
    "session_nucleus_hash",
    "task_id",
    "attempt_id",
    "execution_receipt_refs",
    "cleanup_plan_digest",
    "outcome",
    "cleanup_state_digest",
    "decided_at",
  ], ["restoration_receipt_ref", "residual_state_artifact_ref"]);
  const common = commonPayload(input, plan, label);
  if (input.cleanup_plan_digest !== plan.cleanup_plan_digest) {
    throw new Error(`${label}.cleanup_plan_digest does not match the immutable plan`);
  }
  const outcome = assertEnum(input.outcome, CLEANUP_DISPOSITIONS, `${label}.outcome`);
  const payload = {
    ...common,
    execution_receipt_refs: normalizeSortedRefs(
      input.execution_receipt_refs,
      `${label}.execution_receipt_refs`,
      ROW_PREFIX.execution_receipt,
    ),
    cleanup_plan_digest: plan.cleanup_plan_digest,
    outcome,
    cleanup_state_digest: assertDigest(input.cleanup_state_digest, `${label}.cleanup_state_digest`),
    decided_at: assertTimestamp(input.decided_at, `${label}.decided_at`),
  };
  if (input.restoration_receipt_ref != null) {
    payload.restoration_receipt_ref = normalizeOpaqueRef(
      input.restoration_receipt_ref,
      `${label}.restoration_receipt_ref`,
      { prefix: "restoration-receipt" },
    );
  }
  if (input.residual_state_artifact_ref != null) {
    payload.residual_state_artifact_ref = normalizeOpaqueRef(
      input.residual_state_artifact_ref,
      `${label}.residual_state_artifact_ref`,
      { prefix: "artifact" },
    );
  }
  if (outcome === "succeeded" && payload.restoration_receipt_ref == null) {
    throw new Error(`${label} succeeded cleanup requires restoration_receipt_ref`);
  }
  if (outcome === "failed" && payload.residual_state_artifact_ref == null) {
    throw new Error(`${label} failed cleanup requires residual_state_artifact_ref`);
  }
  return deepFreeze(payload);
}

function normalizePhysicalExperimentRowPayload(
  rowKind,
  input,
  planInput,
  label = "physical_experiment_row.payload",
  deps = {},
) {
  const plan = normalizePhysicalExperimentPlan(planInput, "physical_experiment_plan", deps);
  assertEnum(rowKind, PHYSICAL_EXPERIMENT_ROW_KINDS, "physical_experiment_row.row_kind");
  if (input.version !== PHYSICAL_EXPERIMENT_ROW_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_EXPERIMENT_ROW_VERSION}`);
  }
  const validation = { mode: deps.validationMode || "historical", trustedNow: deps.trustedNow || null };
  if (rowKind === "execution_receipt") return normalizeExecutionReceiptPayload(input, plan, label, validation);
  if (rowKind === "observation") return normalizeObservationPayload(input, plan, label, validation);
  if (rowKind === "claim_verdict") return normalizeClaimVerdictPayload(input, plan, label);
  return normalizeCleanupVerdictPayload(input, plan, label);
}

function normalizeSignerResolution(input, label) {
  assertClosedObject(input, label, [
    "signer_principal_ref",
    "trust_domain_ref",
    "independence_domain_ref",
    "trust_root_epoch",
    "trust_registry_digest",
    "signer_enrollment_digest",
    "authorization_context_digest",
    "allowed_row_kinds",
    "trusted",
    "revoked",
  ]);
  if (typeof input.trusted !== "boolean" || typeof input.revoked !== "boolean") {
    throw new Error(`${label} trust flags must be booleans`);
  }
  return deepFreeze({
    signer_principal_ref: normalizeOpaqueRef(
      input.signer_principal_ref,
      `${label}.signer_principal_ref`,
      { prefix: "principal" },
    ),
    trust_domain_ref: normalizeOpaqueRef(
      input.trust_domain_ref,
      `${label}.trust_domain_ref`,
      { prefix: "trust-domain" },
    ),
    independence_domain_ref: normalizeOpaqueRef(
      input.independence_domain_ref,
      `${label}.independence_domain_ref`,
      { prefix: "independence-domain" },
    ),
    trust_root_epoch: assertSafeInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, { min: 1 }),
    trust_registry_digest: assertDigest(input.trust_registry_digest, `${label}.trust_registry_digest`),
    signer_enrollment_digest: assertDigest(input.signer_enrollment_digest, `${label}.signer_enrollment_digest`),
    authorization_context_digest: assertDigest(
      input.authorization_context_digest,
      `${label}.authorization_context_digest`,
    ),
    allowed_row_kinds: normalizeUniqueArray(
      input.allowed_row_kinds,
      `${label}.allowed_row_kinds`,
      (entry, field) => assertEnum(entry, PHYSICAL_EXPERIMENT_ROW_KINDS, field),
      { nonempty: true },
    ),
    trusted: input.trusted,
    revoked: input.revoked,
  });
}

function rowAuthorizationContext(rowKind, payload, plan) {
  let binding;
  if (rowKind === "execution_receipt") {
    binding = {
      instrument_ref: payload.instrument_ref,
      instrument_identity_ref: payload.instrument_identity_ref,
      instrument_inventory_ref: payload.instrument_inventory_ref,
      provider_manifest_digest: payload.provider_manifest_digest,
      operation_id: plan.operation_id,
      parameter_digest: plan.parameter_digest,
      requested_effects_digest: plan.requested_effects_digest,
      cohort_kind: payload.cohort_kind,
      stimulus_plan_ref: payload.stimulus_plan_ref,
      stimulus_plan_digest: payload.stimulus_plan_digest,
      cohort_execution_request_digest: payload.cohort_execution_request_digest,
    };
  } else if (rowKind === "observation") {
    const observer = planObserver(plan, payload.cohort_kind, payload.observer_id);
    binding = {
      observer_id: payload.observer_id,
      observer_identity_ref: payload.observer_identity_ref,
      observer_enrollment_ref: payload.observer_enrollment_ref,
      source_kind: payload.source_kind,
      source_ref: payload.source_ref,
      source_assurance_scheme: payload.source_assurance_scheme,
      trust_domain_ref: payload.trust_domain_ref,
      independence_domain_ref: payload.independence_domain_ref,
      external_outcome: observer.external_outcome,
      attempt_binding_digest: payload.attempt_binding_digest,
    };
  } else if (rowKind === "claim_verdict") {
    binding = {
      executed_evidence_registry_digest: payload.executed_evidence_registry_digest,
      verifier_template_id: payload.verifier_template_id,
      verifier_template_version: payload.verifier_template_version,
      verifier_template_digest: payload.verifier_template_digest,
      decision_rule_digest: payload.decision_rule_digest,
    };
  } else {
    binding = { cleanup_plan_digest: payload.cleanup_plan_digest };
  }
  return deepFreeze({
    domain: "hacker-bob/physical-row-authorization-context/v1",
    row_kind: rowKind,
    plan_hash: plan.plan_hash,
    session_nucleus_hash: plan.session_nucleus_hash,
    task_id: plan.task_id,
    attempt_id: plan.attempt_id,
    binding,
  });
}

function rowAuthorizationContextDigest(rowKind, payload, plan) {
  return hashCanonicalJson(rowAuthorizationContext(rowKind, payload, plan));
}

function signatureInputDigest(rowKind, payloadDigest, envelope) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-experiment-row/v1",
    row_kind: rowKind,
    signer_key_id: envelope.signer_key_id,
    signer_principal_ref: envelope.signer_principal_ref,
    signature_scheme: envelope.signature_scheme,
    trust_root_epoch: envelope.trust_root_epoch,
    trust_domain_ref: envelope.trust_domain_ref,
    independence_domain_ref: envelope.independence_domain_ref,
    trust_registry_digest: envelope.trust_registry_digest,
    signer_enrollment_digest: envelope.signer_enrollment_digest,
    authorization_context_digest: envelope.authorization_context_digest,
    sequence: envelope.sequence,
    previous_row_hash: envelope.previous_row_hash,
    payload_digest: payloadDigest,
    signed_at: envelope.signed_at,
    append_receipt_digest: envelope.append_receipt.receipt_digest,
  });
}

function normalizeEnvelope(input, rowKind, payload, plan, deps, label) {
  assertClosedObject(input, label, [
    "version",
    "signer_key_id",
    "signer_principal_ref",
    "signature_scheme",
    "trust_root_epoch",
    "trust_domain_ref",
    "independence_domain_ref",
    "trust_registry_digest",
    "signer_enrollment_digest",
    "authorization_context_digest",
    "sequence",
    "previous_row_hash",
    "payload_digest",
    "signed_at",
    "append_receipt",
    "signature",
  ]);
  if (input.version !== PHYSICAL_EXPERIMENT_ROW_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_EXPERIMENT_ROW_VERSION}`);
  }
  const payloadDigest = hashCanonicalJson(payload);
  if (assertDigest(input.payload_digest, `${label}.payload_digest`) !== payloadDigest) {
    throw new Error(`${label}.payload_digest does not match the canonical payload`);
  }
  const envelope = {
    version: PHYSICAL_EXPERIMENT_ROW_VERSION,
    signer_key_id: normalizeOpaqueRef(input.signer_key_id, `${label}.signer_key_id`, { prefix: "signer-key" }),
    signer_principal_ref: normalizeOpaqueRef(
      input.signer_principal_ref,
      `${label}.signer_principal_ref`,
      { prefix: "principal" },
    ),
    signature_scheme: assertEnum(input.signature_scheme, SIGNATURE_SCHEMES, `${label}.signature_scheme`),
    trust_root_epoch: assertSafeInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, { min: 1 }),
    trust_domain_ref: normalizeOpaqueRef(
      input.trust_domain_ref,
      `${label}.trust_domain_ref`,
      { prefix: "trust-domain" },
    ),
    independence_domain_ref: normalizeOpaqueRef(
      input.independence_domain_ref,
      `${label}.independence_domain_ref`,
      { prefix: "independence-domain" },
    ),
    trust_registry_digest: assertDigest(input.trust_registry_digest, `${label}.trust_registry_digest`),
    signer_enrollment_digest: assertDigest(input.signer_enrollment_digest, `${label}.signer_enrollment_digest`),
    authorization_context_digest: assertDigest(
      input.authorization_context_digest,
      `${label}.authorization_context_digest`,
    ),
    sequence: assertSafeInteger(input.sequence, `${label}.sequence`, { min: 1 }),
    previous_row_hash: assertDigest(input.previous_row_hash, `${label}.previous_row_hash`),
    payload_digest: payloadDigest,
    signed_at: assertTimestamp(input.signed_at, `${label}.signed_at`),
    append_receipt: input.append_receipt,
    signature: typeof input.signature === "string" && SIGNATURE_PATTERN.test(input.signature)
      ? input.signature
      : (() => { throw new Error(`${label}.signature must be a base64url signature`); })(),
  };
  if (!deps || typeof deps.resolveSigner !== "function" || typeof deps.verifySignature !== "function") {
    throw new Error("physical experiment rows require resolveSigner and verifySignature trust dependencies");
  }
  if (envelope.trust_registry_digest !== plan.trust_registry_digest) {
    throw new Error(`${label}.trust_registry_digest does not match the immutable plan`);
  }
  const authorizationContext = rowAuthorizationContext(rowKind, payload, plan);
  const expectedAuthorizationContextDigest = hashCanonicalJson(authorizationContext);
  if (envelope.authorization_context_digest !== expectedAuthorizationContextDigest) {
    throw new Error(`${label}.authorization_context_digest does not match the row authorization context`);
  }
  const planDeps = NORMALIZED_PLAN_DEPS.get(plan);
  if (!planDeps) throw new Error(`${label} requires a normalized plan with closed receipt registries`);
  const validationMode = deps.validationMode || "historical";
  const currentTrustValidation = isCurrentTrustValidationMode(validationMode);
  const trustedNow = currentTrustValidation
    ? assertTimestamp(deps.trustedNow, "trusted_now")
    : null;
  const appendReceipt = verifyPhysicalReceipt(
    envelope.append_receipt,
    "physical_append",
    planDeps.physicalReceiptRegistry,
    { issuer_key_id: plan.append_issuer_key_id, issuer_epoch: plan.append_issuer_epoch },
    {
      mode: receiptTrustValidationMode(validationMode),
      trustedNow,
      label: `${label}.append_receipt`,
    },
  );
  assertClosedObject(appendReceipt.body, `${label}.append_receipt.body`, [
    "version", "plan_hash", "row_kind", "payload_digest", "expected_sequence",
    "previous_row_hash", "authorization_context_digest", "signed_at",
    "append_binding_digest", "append_reservation_digest", "journal_sequence",
  ]);
  const appendBody = appendReceipt.body;
  for (const [actual, expected, field] of [
    [appendBody.version, PHYSICAL_APPEND_RECEIPT_VERSION, "version"],
    [appendBody.plan_hash, plan.plan_hash, "plan_hash"],
    [appendBody.row_kind, rowKind, "row_kind"],
    [appendBody.payload_digest, payloadDigest, "payload_digest"],
    [appendBody.expected_sequence, envelope.sequence, "expected_sequence"],
    [appendBody.previous_row_hash, envelope.previous_row_hash, "previous_row_hash"],
    [appendBody.authorization_context_digest, envelope.authorization_context_digest, "authorization_context_digest"],
    [appendBody.signed_at, envelope.signed_at, "signed_at"],
  ]) {
    if (actual !== expected) throw new Error(`${label}.append_receipt ${field} drift`);
  }
  if (appendReceipt.signed_at !== envelope.signed_at) {
    throw new Error(`${label}.append_receipt signing time drift`);
  }
  const appendRequest = normalizePhysicalAppendRequest({
    version: appendBody.version,
    plan_hash: appendBody.plan_hash,
    row_kind: appendBody.row_kind,
    payload_digest: appendBody.payload_digest,
    expected_sequence: appendBody.expected_sequence,
    previous_row_hash: appendBody.previous_row_hash,
    authorization_context_digest: appendBody.authorization_context_digest,
    signed_at: appendBody.signed_at,
  }, `${label}.append_receipt.body`);
  if (assertDigest(
    appendBody.append_binding_digest,
    `${label}.append_receipt.body.append_binding_digest`,
  ) !== physicalAppendBindingDigest(appendRequest)) {
    throw new Error(`${label}.append_receipt append_binding_digest drift`);
  }
  assertSafeInteger(appendBody.journal_sequence, `${label}.append_receipt.body.journal_sequence`, { min: 1 });
  const appendReservationDigest = physicalAppendReservationDigest({
    version: PHYSICAL_APPEND_RECEIPT_VERSION,
    append_binding_digest: appendBody.append_binding_digest,
    journal_sequence: appendBody.journal_sequence,
  });
  if (assertDigest(
    appendBody.append_reservation_digest,
    `${label}.append_receipt.body.append_reservation_digest`,
  ) !== appendReservationDigest) {
    throw new Error(`${label}.append_receipt append_reservation_digest drift`);
  }
  envelope.append_receipt = appendReceipt;
  if (validationMode === "admission") {
    const nowMs = Date.parse(trustedNow);
    const signedMs = Date.parse(envelope.signed_at);
    const terminalTimestamp = rowKind === "execution_receipt"
      ? payload.ended_at
      : rowKind === "observation"
        ? payload.received_at
        : payload.decided_at;
    const terminalMs = Date.parse(terminalTimestamp);
    if (signedMs > nowMs + plan.ingestion_policy.max_future_skew_ms) {
      throw new Error(`${label}.signed_at exceeds trusted clock skew`);
    }
    if (signedMs < nowMs - plan.ingestion_policy.max_future_skew_ms) {
      throw new Error(`${label}.signed_at is backdated beyond trusted clock skew`);
    }
    if (terminalMs > nowMs + plan.ingestion_policy.max_future_skew_ms) {
      throw new Error(`${label} payload terminal timestamp is in the future`);
    }
    if (signedMs - terminalMs > plan.ingestion_policy.max_ingestion_delay_ms) {
      throw new Error(`${label} exceeded the plan-bound ingestion delay`);
    }
  }
  const resolution = normalizeSignerResolution(
    deps.resolveSigner({
      signer_key_id: envelope.signer_key_id,
      trust_root_epoch: envelope.trust_root_epoch,
      signed_at: envelope.signed_at,
      row_kind: rowKind,
      plan_hash: plan.plan_hash,
      consumption_registry_digest: plan.consumption_registry_digest,
      trust_registry_digest: envelope.trust_registry_digest,
      signer_enrollment_digest: envelope.signer_enrollment_digest,
      authorization_context_digest: envelope.authorization_context_digest,
      authorization_context: authorizationContext,
      validation_mode: validationMode,
      trusted_now: trustedNow,
    }),
    `${label}.signer_resolution`,
  );
  if (!resolution.trusted || resolution.revoked) throw new Error(`${label} signer is not trusted and active`);
  if (currentTrustValidation) {
    if (typeof deps.isSignerCurrentlyRevoked !== "function") {
      throw new Error("physical row admission requires isSignerCurrentlyRevoked");
    }
    if (deps.isSignerCurrentlyRevoked({
      signer_key_id: envelope.signer_key_id,
      signer_enrollment_digest: envelope.signer_enrollment_digest,
      trust_registry_digest: envelope.trust_registry_digest,
      trusted_now: trustedNow,
    }) !== false) throw new Error(`${label} signer is currently revoked or revocation state is unavailable`);
  }
  if (!resolution.allowed_row_kinds.includes(rowKind)) {
    throw new Error(`${label} signer is not authorized for ${rowKind} rows`);
  }
  for (const field of [
    "signer_principal_ref",
    "trust_domain_ref",
    "independence_domain_ref",
    "trust_root_epoch",
    "trust_registry_digest",
    "signer_enrollment_digest",
    "authorization_context_digest",
  ]) {
    if (envelope[field] !== resolution[field]) throw new Error(`${label}.${field} does not match the trusted signer registry`);
  }
  const signatureInput = signatureInputDigest(rowKind, payloadDigest, envelope);
  if (deps.verifySignature({
    signature_input_digest: signatureInput,
    row_kind: rowKind,
    payload,
    envelope: deepFreeze({ ...envelope }),
  }) !== true) {
    throw new Error(`${label}.signature verification failed`);
  }
  return deepFreeze(envelope);
}

function normalizePhysicalExperimentRow(input, planInput, deps, label = "physical_experiment_row") {
  assertClosedObject(input, label, ["version", "row_kind", "payload", "envelope"], ["row_hash", "row_ref"]);
  if (input.version !== PHYSICAL_EXPERIMENT_ROW_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_EXPERIMENT_ROW_VERSION}`);
  }
  const rowKind = assertEnum(input.row_kind, PHYSICAL_EXPERIMENT_ROW_KINDS, `${label}.row_kind`);
  const payload = normalizePhysicalExperimentRowPayload(rowKind, input.payload, planInput, `${label}.payload`, deps);
  const plan = normalizePhysicalExperimentPlan(planInput, "physical_experiment_plan", deps);
  const envelope = normalizeEnvelope(input.envelope, rowKind, payload, plan, deps, `${label}.envelope`);
  if (rowKind === "execution_receipt" && payload.instrument_trust_domain_ref !== envelope.trust_domain_ref) {
    throw new Error(`${label} execution signer and instrument must resolve to the same trust domain`);
  }
  if (rowKind === "observation" && payload.trust_domain_ref !== envelope.trust_domain_ref) {
    throw new Error(`${label} observation signer and source must resolve to the same trust domain`);
  }
  if (rowKind === "observation" && payload.independence_domain_ref !== envelope.independence_domain_ref) {
    throw new Error(`${label} observation signer and source must resolve to the same independence domain`);
  }
  if (rowKind === "observation") {
    const observer = planObserver(plan, payload.cohort_kind, payload.observer_id);
    if (envelope.signer_key_id !== observer.signer_key_id) {
      throw new Error(`${label} observation signer is not assigned by the operator enrollment`);
    }
    if (isCurrentTrustValidationMode(deps.validationMode)) {
      if (typeof deps.isObserverEnrollmentCurrentlyRevoked !== "function") {
        throw new Error("physical observation admission requires isObserverEnrollmentCurrentlyRevoked");
      }
      if (deps.isObserverEnrollmentCurrentlyRevoked({
        observer_enrollment_ref: observer.observer_enrollment_ref,
        observer_enrollment_digest: observer.observer_enrollment_digest,
        trusted_now: deps.trustedNow,
      }) !== false) throw new Error(`${label} observer enrollment is currently revoked or unavailable`);
    }
  }
  const terminalTimestamp = rowKind === "execution_receipt"
    ? payload.ended_at
    : rowKind === "observation"
      ? payload.received_at
      : payload.decided_at;
  if (Date.parse(envelope.signed_at) < Date.parse(terminalTimestamp)) {
    throw new Error(`${label}.envelope.signed_at must not precede the payload terminal timestamp`);
  }
  if (["execution_receipt", "observation"].includes(rowKind)) {
    const attestation = payload.consumption_attestation;
    if (Date.parse(attestation.consumed_at) > Date.parse(envelope.signed_at)) {
      throw new Error(`${label} consumption cannot postdate the row signature`);
    }
    if (Date.parse(attestation.receipt_signed_at) > Date.parse(envelope.signed_at)) {
      throw new Error(`${label} durable consumption receipt cannot postdate the row signature`);
    }
  }
  const signedBody = { version: PHYSICAL_EXPERIMENT_ROW_VERSION, row_kind: rowKind, payload, envelope };
  const rowHash = hashCanonicalJson(signedBody);
  const rowRef = `${ROW_PREFIX[rowKind]}:v1:${rowHash}`;
  if (input.row_hash != null && assertDigest(input.row_hash, `${label}.row_hash`) !== rowHash) {
    throw new Error(`${label}.row_hash does not match the signed row`);
  }
  if (input.row_ref != null && normalizeOpaqueRef(input.row_ref, `${label}.row_ref`, { prefix: ROW_PREFIX[rowKind] }) !== rowRef) {
    throw new Error(`${label}.row_ref does not match the signed row`);
  }
  return deepFreeze({ ...signedBody, row_hash: rowHash, row_ref: rowRef });
}

function assertExactRefSet(actual, expected, label) {
  const left = [...actual].sort();
  const right = [...expected].sort();
  if (left.length !== right.length || left.some((entry, index) => entry !== right[index])) {
    throw new Error(`${label} must bind the exact preceding row set`);
  }
}

function assertObservationWindow(observation, receipt, plan, label) {
  const anchor = plan.observation_window.start_rule === "execution_started"
    ? Date.parse(receipt.payload.started_at)
    : Date.parse(receipt.payload.ended_at);
  const captured = Date.parse(observation.payload.captured_at) + observation.payload.clock_offset_ms;
  const uncertainty = observation.payload.clock_uncertainty_ms;
  if (captured + uncertainty < anchor) throw new Error(`${label} precedes its plan-bound observation window`);
  if (captured - uncertainty > anchor + plan.observation_window.max_duration_ms) {
    throw new Error(`${label} exceeds its plan-bound observation window`);
  }
}

function evidenceRefsForObservation(claim, observationRef) {
  return [
    ...claim.payload.positive_executed_evidence_refs,
    ...claim.payload.control_executed_evidence_refs,
  ].filter((entry) => entry.executed_evidence_ref.evidence_ref === observationRef);
}

function normalizeEvidenceVerificationReceipt(input, plan, deps, label) {
  const planDeps = NORMALIZED_PLAN_DEPS.get(plan);
  const mode = deps.validationMode || "historical";
  const receipt = normalizeAndVerifyDurableEvidenceReceipt(input, planDeps.evidenceReceiptRegistry, {
    expected_kind: "executed_evidence_verification",
    mode: receiptTrustValidationMode(mode),
    trusted_now: isCurrentTrustValidationMode(mode) ? deps.trustedNow : null,
    label,
  });
  if (
    receipt.issuer_key_id !== plan.evidence_receipt_issuer_key_id
    || receipt.issuer_epoch !== plan.evidence_receipt_issuer_epoch
  ) throw new Error(`${label} issuer does not match the immutable plan`);
  assertClosedObject(receipt.payload, `${label}.payload`, [
    "version",
    "evidence_registry_digest",
    "plan_hash",
    "source_id",
    "source_adapter_digest",
    "evidence_ref",
    "payload_digest",
    "verdict_hash",
    "execution_identity",
    "node_contract_digest",
    "context_digest",
    "verified_outcome_digest",
    "disposition",
    "decided_at",
  ]);
  const payload = {
    version: EVIDENCE_VERIFICATION_BINDING_VERSION,
    registry_digest: assertDigest(receipt.payload.evidence_registry_digest, `${label}.payload.evidence_registry_digest`),
    plan_hash: assertDigest(receipt.payload.plan_hash, `${label}.payload.plan_hash`),
    source_id: assertId(receipt.payload.source_id, `${label}.payload.source_id`),
    source_adapter_digest: assertDigest(receipt.payload.source_adapter_digest, `${label}.payload.source_adapter_digest`),
    evidence_ref: normalizeOpaqueRef(receipt.payload.evidence_ref, `${label}.payload.evidence_ref`),
    payload_digest: assertDigest(receipt.payload.payload_digest, `${label}.payload.payload_digest`),
    verdict_hash: assertDigest(receipt.payload.verdict_hash, `${label}.payload.verdict_hash`),
    execution_identity: normalizeOpaqueRef(
      receipt.payload.execution_identity,
      `${label}.payload.execution_identity`,
      { prefix: "execution" },
    ),
    node_contract_digest: assertDigest(receipt.payload.node_contract_digest, `${label}.payload.node_contract_digest`),
    context_digest: assertDigest(receipt.payload.context_digest, `${label}.payload.context_digest`),
    verified_outcome_digest: assertDigest(
      receipt.payload.verified_outcome_digest,
      `${label}.payload.verified_outcome_digest`,
    ),
    disposition: assertEnum(
      receipt.payload.disposition,
      ["verified", "refuted", "inconclusive"],
      `${label}.payload.disposition`,
    ),
    decided_at: assertTimestamp(receipt.payload.decided_at, `${label}.payload.decided_at`),
    verification_receipt_ref: receipt.receipt_ref,
    verification_receipt_digest: receipt.receipt_digest,
    receipt_signed_at: receipt.signed_at,
  };
  if (payload.plan_hash !== plan.plan_hash) throw new Error(`${label} plan hash drift`);
  if (payload.disposition !== "verified") throw new Error(`${label} did not produce a verified PH-S10 outcome`);
  if (Date.parse(payload.receipt_signed_at) < Date.parse(payload.decided_at)) {
    throw new Error(`${label} durable receipt predates the PH-S10 decision`);
  }
  return deepFreeze(payload);
}

function normalizeVerifierExecutionReceipt(input, plan, deps, label) {
  const planDeps = NORMALIZED_PLAN_DEPS.get(plan);
  const mode = deps.validationMode || "historical";
  const receipt = normalizeAndVerifyDurableEvidenceReceipt(input, planDeps.evidenceReceiptRegistry, {
    expected_kind: "physical_verifier_execution",
    mode: receiptTrustValidationMode(mode),
    trusted_now: isCurrentTrustValidationMode(mode) ? deps.trustedNow : null,
    label,
  });
  if (
    receipt.issuer_key_id !== plan.evidence_receipt_issuer_key_id
    || receipt.issuer_epoch !== plan.evidence_receipt_issuer_epoch
  ) throw new Error(`${label} issuer does not match the immutable plan`);
  assertClosedObject(receipt.payload, `${label}.payload`, [
    "version", "registry_digest", "plan_hash", "verifier_template_id", "verifier_template_version",
    "verifier_template_digest", "decision_rule_digest", "evidence_verification_receipt_digests",
    "outcome", "reason_code", "decided_at",
  ]);
  const body = {
    version: 1,
    registry_digest: assertDigest(receipt.payload.registry_digest, `${label}.payload.registry_digest`),
    receipt_ref: receipt.receipt_ref,
    plan_hash: assertDigest(receipt.payload.plan_hash, `${label}.payload.plan_hash`),
    verifier_template_id: assertId(receipt.payload.verifier_template_id, `${label}.payload.verifier_template_id`),
    verifier_template_version: assertSafeInteger(
      receipt.payload.verifier_template_version,
      `${label}.payload.verifier_template_version`,
      { min: 1 },
    ),
    verifier_template_digest: assertDigest(
      receipt.payload.verifier_template_digest,
      `${label}.payload.verifier_template_digest`,
    ),
    decision_rule_digest: assertDigest(receipt.payload.decision_rule_digest, `${label}.payload.decision_rule_digest`),
    evidence_verification_receipt_digests: Object.freeze(normalizeUniqueArray(
      receipt.payload.evidence_verification_receipt_digests,
      `${label}.payload.evidence_verification_receipt_digests`,
      assertDigest,
    ).slice().sort()),
    outcome: assertEnum(receipt.payload.outcome, CLAIM_DISPOSITIONS, `${label}.payload.outcome`),
    reason_code: assertEnum(receipt.payload.reason_code, CLAIM_REASON_CODES, `${label}.payload.reason_code`),
    decided_at: assertTimestamp(receipt.payload.decided_at, `${label}.payload.decided_at`),
    receipt_digest: receipt.receipt_digest,
    receipt_signed_at: receipt.signed_at,
  };
  if (Date.parse(body.receipt_signed_at) < Date.parse(body.decided_at)) {
    throw new Error(`${label} durable receipt predates the verifier decision`);
  }
  return deepFreeze(body);
}

function assertRegistryComponentUsableAt(component, at, label) {
  if (component.trust_state !== "trusted" || component.revoked === true) {
    throw new Error(`${label} is not trusted and active`);
  }
  const atMs = Date.parse(at);
  const attestedMs = Date.parse(component.attested_at);
  if (!Number.isFinite(attestedMs) || attestedMs > atMs) throw new Error(`${label} attestation is not yet valid`);
  if (!Number.isSafeInteger(component.freshness_window_ms) || atMs - attestedMs > component.freshness_window_ms) {
    throw new Error(`${label} attestation is stale`);
  }
  if (component.expires_at != null && atMs > Date.parse(component.expires_at)) {
    throw new Error(`${label} is expired`);
  }
}

function assertImmutableRegistry(plan, deps, at = null) {
  const registry = deps && deps.evidenceRegistry;
  assertExecutedEvidenceRegistry(registry);
  if (registry.registry_digest !== plan.executed_evidence_registry_digest) {
    throw new Error("executed-evidence registry digest does not match the immutable plan");
  }
  const template = registry.get("verifier_templates", plan.verifier_template_id);
  if (!template) throw new Error(`plan-bound verifier template is unregistered: ${plan.verifier_template_id}`);
  for (const [field, expected] of [
    ["template_version", plan.verifier_template_version],
    ["template_digest", plan.verifier_template_digest],
    ["decision_rule_digest", plan.decision_rule_digest],
  ]) {
    if (template[field] !== expected) throw new Error(`plan-bound verifier template ${field} drift`);
  }
  if (template.trust_state !== "trusted" || template.revoked === true) {
    throw new Error("plan-bound verifier template is not trusted and active");
  }
  return registry;
}

function assertPlanEffectRegistry(plan, deps) {
  const registry = deps && deps.effectRegistry;
  if (!registry || registry.registry_digest !== plan.requested_effects_registry_digest) {
    throw new Error("requested-effect registry does not match the immutable experiment plan");
  }
  const normalized = normalizeRequestedEffects(plan.requested_effects, registry, "physical_experiment_plan.requested_effects");
  if (hashCanonicalJson(normalized) !== plan.requested_effects_digest) {
    throw new Error("requested effects do not resolve under the immutable effect-template registry");
  }
  return registry;
}

function resolveEvidenceVerification(binding, plan, claim, deps) {
  const registry = assertImmutableRegistry(plan, deps, claim.payload.decided_at);
  const ref = binding.executed_evidence_ref;
  const source = registry.get("source_adapters", ref.source_id);
  if (!source || source.adapter_digest !== ref.source_adapter_digest) {
    throw new Error(`executed-evidence source adapter drift for ${ref.source_id}`);
  }
  const template = registry.get("verifier_templates", plan.verifier_template_id);
  if (!template.source_ids.includes(ref.source_id)) {
    throw new Error(`plan-bound verifier template does not admit source ${ref.source_id}`);
  }
  if (isCurrentTrustValidationMode(deps.validationMode)) {
    if (typeof deps.isEvidenceComponentCurrentlyRevoked !== "function") {
      throw new Error("physical claim admission requires isEvidenceComponentCurrentlyRevoked");
    }
    const componentBindings = [
      ["source_adapter", ref.source_id],
      ["verifier_template", plan.verifier_template_id],
      ["context_resolver", template.context_resolver_id],
      ["replay_executor", template.replay_executor_id],
      ...template.dependency_provider_ids.map((providerId) => ["dependency_proof_provider", providerId]),
    ];
    for (const [componentKind, componentId] of componentBindings) {
      if (deps.isEvidenceComponentCurrentlyRevoked({
        component_kind: componentKind,
        component_id: componentId,
        registry_digest: plan.executed_evidence_registry_digest,
        trusted_now: deps.trustedNow,
      }) !== false) throw new Error(`executed-evidence ${componentKind} ${componentId} is currently revoked or unavailable`);
    }
  }
  if (typeof deps.resolveExecutedEvidenceVerification !== "function") {
    throw new Error("physical claim verification requires resolveExecutedEvidenceVerification");
  }
  const raw = deps.resolveExecutedEvidenceVerification({
    verification_receipt_ref: binding.verification_receipt_ref,
    verification_receipt_digest: binding.verification_receipt_digest,
    executed_evidence_ref: ref,
    registry_digest: plan.executed_evidence_registry_digest,
  });
  if (raw && typeof raw.then === "function") {
    throw new Error("resolveExecutedEvidenceVerification must synchronously resolve a durable receipt");
  }
  const receipt = normalizeEvidenceVerificationReceipt(
    raw,
    plan,
    deps,
    "executed_evidence_verification_receipt",
  );
  for (const [actual, expected, field] of [
    [receipt.registry_digest, plan.executed_evidence_registry_digest, "registry_digest"],
    [receipt.verification_receipt_ref, binding.verification_receipt_ref, "verification_receipt_ref"],
    [receipt.verification_receipt_digest, binding.verification_receipt_digest, "verification_receipt_digest"],
    [receipt.source_id, ref.source_id, "source_id"],
    [receipt.source_adapter_digest, ref.source_adapter_digest, "source_adapter_digest"],
    [receipt.evidence_ref, ref.evidence_ref, "evidence_ref"],
    [receipt.payload_digest, ref.expected_payload_digest, "payload_digest"],
    [receipt.verdict_hash, ref.expected_verdict_hash, "verdict_hash"],
    [receipt.execution_identity, ref.execution_identity, "execution_identity"],
    [receipt.node_contract_digest, ref.node_contract_digest, "node_contract_digest"],
    [receipt.context_digest, ref.context_digest, "context_digest"],
  ]) {
    if (actual !== expected) throw new Error(`executed-evidence verification ${field} drift`);
  }
  if (Date.parse(receipt.decided_at) > Date.parse(claim.payload.decided_at)) {
    throw new Error("executed-evidence verification receipt postdates the claim decision");
  }
  if (Date.parse(receipt.receipt_signed_at) > Date.parse(claim.payload.decided_at)) {
    throw new Error("executed-evidence durable receipt postdates the claim decision");
  }
  return receipt;
}

function resolveVerifierExecutionReceipt(claim, plan, evidenceReceipts, deps) {
  assertImmutableRegistry(plan, deps, claim.payload.decided_at);
  if (typeof deps.resolveVerifierExecutionReceipt !== "function") {
    throw new Error("physical claim verification requires resolveVerifierExecutionReceipt");
  }
  const raw = deps.resolveVerifierExecutionReceipt({
    receipt_ref: claim.payload.verifier_execution_receipt_ref,
    receipt_digest: claim.payload.verifier_execution_receipt_digest,
    plan_hash: plan.plan_hash,
    registry_digest: plan.executed_evidence_registry_digest,
  });
  if (raw && typeof raw.then === "function") {
    throw new Error("resolveVerifierExecutionReceipt must synchronously resolve a durable receipt");
  }
  const receipt = normalizeVerifierExecutionReceipt(raw, plan, deps, "verifier_execution_receipt");
  const expectedEvidenceDigests = evidenceReceipts.map((entry) => entry.verification_receipt_digest).sort();
  for (const [actual, expected, field] of [
    [receipt.registry_digest, plan.executed_evidence_registry_digest, "registry_digest"],
    [receipt.receipt_ref, claim.payload.verifier_execution_receipt_ref, "receipt_ref"],
    [receipt.receipt_digest, claim.payload.verifier_execution_receipt_digest, "receipt_digest"],
    [receipt.plan_hash, plan.plan_hash, "plan_hash"],
    [receipt.verifier_template_id, plan.verifier_template_id, "verifier_template_id"],
    [receipt.verifier_template_version, plan.verifier_template_version, "verifier_template_version"],
    [receipt.verifier_template_digest, plan.verifier_template_digest, "verifier_template_digest"],
    [receipt.decision_rule_digest, plan.decision_rule_digest, "decision_rule_digest"],
    [JSON.stringify(receipt.evidence_verification_receipt_digests), JSON.stringify(expectedEvidenceDigests), "evidence receipts"],
    [receipt.outcome, claim.payload.outcome, "outcome"],
    [receipt.reason_code, claim.payload.reason_code, "reason_code"],
    [receipt.decided_at, claim.payload.decided_at, "decided_at"],
  ]) {
    if (actual !== expected) throw new Error(`verifier execution receipt ${field} drift`);
  }
  if (Date.parse(receipt.receipt_signed_at) > Date.parse(claim.payload.decided_at)) {
    throw new Error("verifier execution durable receipt postdates the claim decision");
  }
  return receipt;
}

function deriveClaimProjection(plan, receipts, observations, claim = null) {
  const receiptByCohort = new Map(receipts.map((row) => [row.payload.cohort_kind, row]));
  for (const cohortKind of COHORT_KINDS) {
    const receipt = receiptByCohort.get(cohortKind);
    if (!receipt || receipt.payload.status !== "executed") {
      return deepFreeze({ outcome: "inconclusive", reason_code: "missing_executed_cohort" });
    }
  }

  for (const cohortKind of COHORT_KINDS) {
    const cohort = cohortKind === "positive" ? plan.positive_cohort : plan.control_cohort;
    const cohortObservations = observations.filter((row) => row.payload.cohort_kind === cohortKind);
    for (const observer of cohort.observer_plan) {
      if (!cohortObservations.some((row) => row.payload.observer_id === observer.observer_id)) {
        return deepFreeze({ outcome: "inconclusive", reason_code: "missing_planned_observation" });
      }
    }
    const instrumentIndependenceDomain = receiptByCohort.get(cohortKind).envelope.independence_domain_ref;
    const independent = cohortObservations.some((row) => {
      const observer = planObserver(plan, cohortKind, row.payload.observer_id);
      const instrumentTrustDomain = receiptByCohort.get(cohortKind).payload.instrument_trust_domain_ref;
      return observer.external_outcome
        && observer.source_kind !== "instrument"
        && row.payload.trust_domain_ref !== instrumentTrustDomain
        && row.payload.independence_domain_ref !== instrumentIndependenceDomain;
    });
    if (!independent) {
      return deepFreeze({ outcome: "inconclusive", reason_code: "independent_observer_missing" });
    }
  }

  if (claim) {
    for (const observation of observations) {
      const matching = evidenceRefsForObservation(claim, observation.row_ref);
      if (matching.length !== 1) {
        return deepFreeze({ outcome: "inconclusive", reason_code: "executed_evidence_missing" });
      }
      const evidence = matching[0].executed_evidence_ref;
      const receipt = receiptByCohort.get(observation.payload.cohort_kind);
      if (
        evidence.execution_identity !== receipt.payload.execution_identity
        || evidence.node_contract_digest !== plan.contract_hash
        || evidence.context_digest !== plan.plan_hash
        || evidence.expected_payload_digest !== observation.envelope.payload_digest
        || evidence.expected_verdict_hash !== observation.row_hash
      ) {
        return deepFreeze({ outcome: "inconclusive", reason_code: "executed_evidence_missing" });
      }
    }
  } else {
    return deepFreeze({ outcome: "inconclusive", reason_code: "executed_evidence_missing" });
  }

  const allMatch = COHORT_KINDS.every((cohortKind) => {
    const expected = cohortKind === "positive"
      ? plan.expected_positive_outcome_digest
      : plan.expected_control_outcome_digest;
    return observations
      .filter((row) => row.payload.cohort_kind === cohortKind)
      .every((row) => row.payload.observed_outcome_digest === expected);
  });
  return allMatch
    ? deepFreeze({ outcome: "verified", reason_code: "differential_verified" })
    : deepFreeze({ outcome: "refuted", reason_code: "differential_refuted" });
}

function normalizeLedger(
  planInput,
  rowInputs,
  deps,
  { admissionSequence = null, liveRevalidation = false } = {},
) {
  const plan = normalizePhysicalExperimentPlan(planInput, "physical_experiment_plan", deps);
  assertPlanEffectRegistry(plan, deps);
  if (!Array.isArray(rowInputs) || rowInputs.length > 4096) {
    throw new Error("physical experiment rows must be an array with at most 4096 entries");
  }
  const rows = rowInputs.map((row, index) => {
    const validationMode = liveRevalidation
      ? "live_revalidation"
      : admissionSequence != null && index + 1 === admissionSequence
        ? "admission"
        : "historical";
    return normalizePhysicalExperimentRow(
      row,
      plan,
      { ...deps, validationMode },
      `physical_experiment_rows[${index}]`,
    );
  }).sort((left, right) => left.envelope.sequence - right.envelope.sequence);
  if (new Set(rows.map((row) => row.row_hash)).size !== rows.length) {
    throw new Error("physical experiment ledger contains duplicate rows");
  }
  let previousHash = ZERO_HASH;
  let previousJournalSequence = 0;
  rows.forEach((row, index) => {
    const expectedSequence = index + 1;
    if (row.envelope.sequence !== expectedSequence) {
      throw new Error(`physical experiment ledger sequence must be contiguous at ${expectedSequence}`);
    }
    if (row.envelope.previous_row_hash !== previousHash) {
      throw new Error(`physical experiment ledger hash chain is broken at sequence ${expectedSequence}`);
    }
    const journalSequence = row.envelope.append_receipt.body.journal_sequence;
    if (journalSequence <= previousJournalSequence) {
      throw new Error(`physical experiment append journal is not monotonic at sequence ${expectedSequence}`);
    }
    previousJournalSequence = journalSequence;
    previousHash = row.row_hash;
  });

  const receipts = rows.filter((row) => row.row_kind === "execution_receipt");
  const observations = rows.filter((row) => row.row_kind === "observation");
  const claims = rows.filter((row) => row.row_kind === "claim_verdict");
  const cleanupVerdicts = rows.filter((row) => row.row_kind === "cleanup_verdict");
  if (claims.length > 1) throw new Error("physical experiment ledger may contain only one claim verdict");
  if (cleanupVerdicts.length > 1) throw new Error("physical experiment ledger may contain only one cleanup verdict");
  const terminalClaim = claims[0] || null;
  if (terminalClaim && rows.some((row) => ["execution_receipt", "observation"].includes(row.row_kind)
    && row.envelope.sequence > terminalClaim.envelope.sequence)) {
    throw new Error("claim evidence cannot be appended after the claim verdict");
  }
  const terminalCleanup = cleanupVerdicts[0] || null;
  if (terminalCleanup && rows.some((row) => ["execution_receipt", "observation"].includes(row.row_kind)
    && row.envelope.sequence > terminalCleanup.envelope.sequence)) {
    throw new Error("attempt evidence cannot be appended after the cleanup verdict");
  }
  for (const cohortKind of COHORT_KINDS) {
    if (receipts.filter((row) => row.payload.cohort_kind === cohortKind).length > 1) {
      throw new Error(`physical experiment ledger may contain only one ${cohortKind} execution receipt`);
    }
  }
  for (const field of ["grant_ref", "execution_identity"]) {
    if (new Set(receipts.map((row) => row.payload[field])).size !== receipts.length) {
      throw new Error(`positive/control execution receipts must use distinct ${field} values`);
    }
  }

  const consumedRows = rows.filter((row) => ["execution_receipt", "observation"].includes(row.row_kind));
  for (const field of ["consumption_ref", "binding_digest"]) {
    const values = consumedRows.map((row) => row.payload.consumption_attestation[field]);
    if (new Set(values).size !== values.length) {
      throw new Error(`physical experiment one-use attestations must have unique ${field} values`);
    }
  }
  const lastConsumptionSequence = new Map();
  for (const row of consumedRows) {
    const attestation = row.payload.consumption_attestation;
    const key = `${attestation.issuer_key_id}:${attestation.issuer_epoch}:${attestation.kind}`;
    const prior = lastConsumptionSequence.get(key) || 0;
    if (attestation.sequence <= prior) {
      throw new Error(`one-use attestation sequence is not monotonic for ${key}`);
    }
    lastConsumptionSequence.set(key, attestation.sequence);
  }

  const receiptByRef = new Map(receipts.map((row) => [row.row_ref, row]));
  const observationKeys = new Set();
  for (const observation of observations) {
    const receipt = receiptByRef.get(observation.payload.execution_receipt_ref);
    if (!receipt) throw new Error(`observation ${observation.row_ref} references an unknown execution receipt`);
    if (receipt.payload.cohort_kind !== observation.payload.cohort_kind) {
      throw new Error(`observation ${observation.row_ref} crosses positive/control cohorts`);
    }
    if (
      receipt.payload.grant_ref !== observation.payload.grant_ref
      || receipt.payload.execution_identity !== observation.payload.execution_identity
    ) {
      throw new Error(`observation ${observation.row_ref} grant/execution binding drift`);
    }
    const observerKey = `${observation.payload.cohort_kind}:${observation.payload.observer_id}`;
    if (observationKeys.has(observerKey)) {
      throw new Error(`physical experiment may contain only one observation for ${observerKey}`);
    }
    observationKeys.add(observerKey);
    const consumptionTime = Date.parse(observation.payload.consumption_attestation.consumed_at);
    const observationAnchor = plan.observation_window.start_rule === "execution_started"
      ? Date.parse(receipt.payload.started_at)
      : Date.parse(receipt.payload.ended_at);
    if (consumptionTime < observationAnchor - observation.payload.clock_uncertainty_ms) {
      throw new Error(`observation ${observation.row_ref} consumed its challenge before the observation window`);
    }
    assertObservationWindow(observation, receipt, plan, `observation ${observation.row_ref}`);
  }

  const claim = claims[0] || null;
  let verifiedEvidenceReceipts = [];
  if (claim) {
    const claimDeps = {
      ...deps,
      validationMode: liveRevalidation
        ? "live_revalidation"
        : admissionSequence === claim.envelope.sequence
          ? "admission"
          : "historical",
    };
    assertExactRefSet(
      claim.payload.execution_receipt_refs,
      receipts.map((row) => row.row_ref),
      "claim_verdict.execution_receipt_refs",
    );
    assertExactRefSet(
      claim.payload.observation_refs,
      observations.map((row) => row.row_ref),
      "claim_verdict.observation_refs",
    );
    const allEvidenceRefs = [
      ...claim.payload.positive_executed_evidence_refs,
      ...claim.payload.control_executed_evidence_refs,
    ];
    if (new Set(allEvidenceRefs.map((entry) => entry.executed_evidence_ref.evidence_ref)).size !== allEvidenceRefs.length) {
      throw new Error("claim verdict executed-evidence references must be unique across cohorts");
    }
    for (const entry of claim.payload.positive_executed_evidence_refs) {
      const observation = observations.find((row) => row.row_ref === entry.executed_evidence_ref.evidence_ref);
      if (!observation || observation.payload.cohort_kind !== "positive") {
        throw new Error("positive executed evidence must resolve to a positive observation row");
      }
    }
    for (const entry of claim.payload.control_executed_evidence_refs) {
      const observation = observations.find((row) => row.row_ref === entry.executed_evidence_ref.evidence_ref);
      if (!observation || observation.payload.cohort_kind !== "control") {
        throw new Error("control executed evidence must resolve to a control observation row");
      }
    }
    const latestEvidenceTime = Math.max(
      0,
      ...receipts.map((row) => Date.parse(row.payload.ended_at)),
      ...observations.map((row) => Date.parse(row.payload.received_at)),
    );
    if (Date.parse(claim.payload.decided_at) < latestEvidenceTime) {
      throw new Error("claim verdict decided_at precedes its signed evidence");
    }
    verifiedEvidenceReceipts = allEvidenceRefs.map((entry) => (
      resolveEvidenceVerification(entry, plan, claim, claimDeps)
    ));
  }

  const cleanup = cleanupVerdicts[0] || null;
  if (cleanup) {
    assertExactRefSet(
      cleanup.payload.execution_receipt_refs,
      receipts.map((row) => row.row_ref),
      "cleanup_verdict.execution_receipt_refs",
    );
    const latestExecutionTime = Math.max(0, ...receipts.map((row) => Date.parse(row.payload.ended_at)));
    if (Date.parse(cleanup.payload.decided_at) < latestExecutionTime) {
      throw new Error("cleanup verdict decided_at precedes execution completion");
    }
  }

  const claimProjection = deriveClaimProjection(plan, receipts, observations, claim);
  if (claim && (
    claim.payload.outcome !== claimProjection.outcome
    || claim.payload.reason_code !== claimProjection.reason_code
  )) {
    throw new Error(
      `claim verdict must be ${claimProjection.outcome}/${claimProjection.reason_code} for the signed differential evidence`,
    );
  }
  const verifiedVerifierReceipt = claim
    ? resolveVerifierExecutionReceipt(
      claim,
      plan,
      verifiedEvidenceReceipts,
      {
        ...deps,
        validationMode: liveRevalidation
          ? "live_revalidation"
          : admissionSequence === claim.envelope.sequence
            ? "admission"
            : "historical",
      },
    )
    : null;
  const cleanupProjection = cleanup
    ? deepFreeze({ outcome: cleanup.payload.outcome, cleanup_state_digest: cleanup.payload.cleanup_state_digest })
    : null;
  const projectedClaim = claim ? deepFreeze({
    ...claimProjection,
    validity_kind: claim.payload.validity_kind,
    valid_from: claim.payload.valid_from,
    decided_at: claim.payload.decided_at,
    prerequisite_eligibility: claim.payload.validity_kind === "live_capability"
      ? "requires_live_revalidation"
      : "historical_event_only",
    ...(claim.payload.validity_kind === "live_capability" ? {
      state_epoch: claim.payload.state_epoch,
      expires_at: claim.payload.expires_at,
      capability_instance_ref: claim.payload.capability_instance_ref,
      custody_state_digest: claim.payload.custody_state_digest,
    } : {}),
  }) : claimProjection;
  const indexBody = {
    version: PHYSICAL_EXPERIMENT_INDEX_VERSION,
    plan_hash: plan.plan_hash,
    row_count: rows.length,
    row_chain_head: rows.length > 0 ? rows[rows.length - 1].row_hash : ZERO_HASH,
    execution_receipt_refs: Object.freeze(receipts.map((row) => row.row_ref).sort()),
    observation_refs: Object.freeze(observations.map((row) => row.row_ref).sort()),
    control_plan_refs: Object.freeze(plan.controls.map((entry) => entry.plan_ref).sort()),
    claim_verdict_ref: claim ? claim.row_ref : null,
    cleanup_verdict_ref: cleanup ? cleanup.row_ref : null,
    claim_projection: projectedClaim,
    cleanup_projection: cleanupProjection,
  };
  const index = deepFreeze({ ...indexBody, index_digest: hashCanonicalJson(indexBody) });
  return {
    plan,
    rows: Object.freeze(rows),
    index,
    verified_claim_state: claim ? Object.freeze({
      claim,
      execution_receipts: Object.freeze(receipts),
      observations: Object.freeze(observations),
      evidence_receipts: Object.freeze(verifiedEvidenceReceipts),
      verifier_receipt: verifiedVerifierReceipt,
    }) : null,
  };
}

function rebuildPhysicalExperimentIndex(planInput, rowInputs, deps) {
  return normalizeLedger(planInput, rowInputs, deps).index;
}

function assertEvidenceRegistryCurrentlyUsable(plan, deps, evidenceReceipts, trustedNow) {
  const registry = assertImmutableRegistry(plan, deps);
  const template = registry.get("verifier_templates", plan.verifier_template_id);
  const components = [
    ["verifier template", template],
    ["context resolver", registry.get("context_resolvers", template.context_resolver_id)],
    ["replay executor", registry.get("replay_executors", template.replay_executor_id)],
    ...template.dependency_provider_ids.map((providerId) => [
      `dependency proof provider ${providerId}`,
      registry.get("dependency_proof_providers", providerId),
    ]),
    ...evidenceReceipts.map((receipt) => [
      `source adapter ${receipt.source_id}`,
      registry.get("source_adapters", receipt.source_id),
    ]),
  ];
  const seen = new Set();
  for (const [label, component] of components) {
    if (!component) throw new Error(`verified physical claim ${label} is unregistered`);
    const identity = `${label}:${component.owner_principal}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    assertRegistryComponentUsableAt(component, trustedNow, `verified physical claim ${label}`);
  }
}

function deriveExternalObserverAssurance(normalized, deps) {
  const { plan, verified_claim_state: claimState } = normalized;
  if (!claimState) {
    throw new Error("external observer assurance requires a verified claim state");
  }
  const observerRegistry = assertPhysicalObserverEnrollmentRegistry(
    deps.observerEnrollmentRegistry,
  );
  const independenceDomains = new Set();
  for (const observation of claimState.observations) {
    const planned = planObserver(
      plan,
      observation.payload.cohort_kind,
      observation.payload.observer_id,
    );
    if (!planned) {
      throw new Error("external observer assurance encountered an unplanned observation");
    }
    const enrollment = observerRegistry.get(planned.observer_enrollment_ref);
    if (!enrollment
        || enrollment.enrollment_digest !== planned.observer_enrollment_digest
        || enrollment.independence_domain_ref !== planned.required_independence_domain_ref) {
      throw new Error("external observer assurance enrollment binding drift");
    }
    if (planned.external_outcome === true && enrollment.external_outcome_allowed === true) {
      independenceDomains.add(enrollment.independence_domain_ref);
    }
  }
  const sortedDomains = [...independenceDomains].sort();
  if (sortedDomains.length > MAX_EXTERNAL_OBSERVER_INDEPENDENCE_DOMAINS) {
    throw new Error("external observer assurance exceeds the bounded independence-domain count");
  }
  return deepFreeze({
    external_observer_independence_domain_count: sortedDomains.length,
    external_observer_independence_domain_digest: hashCanonicalJson({
      domain: "hacker-bob/verified-physical-claim-external-observer-independence-domains/v1",
      independence_domain_refs: sortedDomains,
    }),
    high_impact_corroboration_satisfied: sortedDomains.length >= 2,
  });
}

function buildVerifiedPhysicalClaimProjection(normalized, deps, trustedNow, {
  productionPort = null,
  productionTrustPort = null,
  productionTrustedClockPort = null,
  productionTrustedClockSample = null,
} = {}) {
  const { plan, index, verified_claim_state: claimState } = normalized;
  if (!claimState) throw new Error("verified physical claim projection requires an appended claim verdict");
  if (
    index.claim_projection.outcome !== "verified"
    || index.claim_projection.reason_code !== "differential_verified"
  ) {
    throw new Error(
      "verified physical claim projection requires a verified/differential_verified derived outcome",
    );
  }
  const { claim, execution_receipts: executionReceipts, evidence_receipts: evidenceReceipts } = claimState;
  if (!claimState.verifier_receipt) {
    throw new Error("verified physical claim projection requires a verified durable verifier receipt");
  }
  const trustedNowMs = Date.parse(trustedNow);
  if (trustedNowMs < Date.parse(claim.payload.valid_from)) {
    throw new Error("verified physical claim is not yet valid at the trusted time");
  }
  if (
    claim.payload.validity_kind === "live_capability"
    && trustedNowMs >= Date.parse(claim.payload.expires_at)
  ) throw new Error("verified physical live claim is stale at the trusted time");

  assertEvidenceRegistryCurrentlyUsable(plan, deps, evidenceReceipts, trustedNow);

  const upstreamEvidenceReceipts = evidenceReceipts.map((receipt) => deepFreeze({
    evidence_ref: receipt.evidence_ref,
    source_id: receipt.source_id,
    source_adapter_digest: receipt.source_adapter_digest,
    payload_digest: receipt.payload_digest,
    verdict_hash: receipt.verdict_hash,
    execution_identity: receipt.execution_identity,
    node_contract_digest: receipt.node_contract_digest,
    context_digest: receipt.context_digest,
    verification_receipt_ref: receipt.verification_receipt_ref,
    verification_receipt_digest: receipt.verification_receipt_digest,
  })).sort((left, right) => left.evidence_ref.localeCompare(right.evidence_ref));
  const upstreamExecutionIdentities = Object.freeze([
    ...new Set(upstreamEvidenceReceipts.map((receipt) => receipt.execution_identity)),
  ].sort());
  const executionIdentities = Object.freeze([
    ...new Set(executionReceipts.map((receipt) => receipt.payload.execution_identity)),
  ].sort());
  if (
    upstreamExecutionIdentities.length !== executionIdentities.length
    || upstreamExecutionIdentities.some((identity, index_) => identity !== executionIdentities[index_])
  ) throw new Error("verified physical claim upstream execution identity set drift");

  const upstreamContextDigest = hashCanonicalJson({
    domain: "hacker-bob/verified-physical-claim-upstream-context/v1",
    session_nucleus_hash: plan.session_nucleus_hash,
    experiment_id: plan.experiment_id,
    task_id: plan.task_id,
    attempt_id: plan.attempt_id,
    plan_hash: plan.plan_hash,
    contract_hash: plan.contract_hash,
    execution_request_digest: plan.execution_request_digest,
    claim_predicate_digest: plan.claim_predicate_digest,
    claim_verdict_ref: claim.row_ref,
    claim_verdict_hash: claim.row_hash,
    upstream_evidence_receipts: upstreamEvidenceReceipts,
    verifier_execution_receipt_ref: claim.payload.verifier_execution_receipt_ref,
    verifier_execution_receipt_digest: claim.payload.verifier_execution_receipt_digest,
  });
  const transitionStateDigest = hashCanonicalJson({
    domain: "hacker-bob/verified-physical-claim-transition-state/v1",
    validity_kind: claim.payload.validity_kind,
    valid_from: claim.payload.valid_from,
    decided_at: claim.payload.decided_at,
    claim_verdict_hash: claim.row_hash,
    upstream_context_digest: upstreamContextDigest,
    ...(claim.payload.validity_kind === "live_capability" ? {
      state_epoch: claim.payload.state_epoch,
      expires_at: claim.payload.expires_at,
      capability_instance_ref: claim.payload.capability_instance_ref,
      custody_state_digest: claim.payload.custody_state_digest,
    } : {
      historical_event_sequence: claim.envelope.sequence,
    }),
  });
  const transitionStateEpoch = claim.payload.validity_kind === "live_capability"
    ? claim.payload.state_epoch
    : `historical-event:${claim.envelope.sequence}:${transitionStateDigest.slice(0, 16)}`;
  if ((productionPort == null) !== (productionTrustPort == null)) {
    throw new Error("production verified physical claim requires both durable and signed trust ports");
  }
  const production = productionPort != null;
  const productionTargetDomain = production ? productionPort.target_domain : null;
  const liveCapability = claim.payload.validity_kind === "live_capability";
  if ((productionTrustedClockPort == null) !== (productionTrustedClockSample == null)) {
    throw new Error("production verified physical claim trusted-clock port/sample binding is incomplete");
  }
  if (production && liveCapability) {
    if (productionTrustedClockPort == null) {
      throw new Error(LIVE_CAPABILITY_TRUSTED_TIME_BLOCKER);
    }
    const trustedClockPort = assertProductionPhysicalTrustedClockPort(
      productionTrustedClockPort,
    );
    const trustedClockSample = assertProductionPhysicalTrustedClockSample(
      productionTrustedClockSample,
    );
    if (trustedClockPort.target_domain !== productionTargetDomain
        || trustedClockPort.session_nucleus_hash !== plan.session_nucleus_hash
        || trustedClockSample.target_domain !== productionTargetDomain
        || trustedClockSample.session_nucleus_hash !== plan.session_nucleus_hash
        || trustedClockSample.port_id !== trustedClockPort.port_id
        || trustedClockSample.clock_id !== trustedClockPort.clock_id
        || trustedClockSample.trust_root_public_key_digest
          !== trustedClockPort.trust_root_public_key_digest
        || trustedClockSample.monotonic_owner_slot_digest
          !== trustedClockPort.monotonic_owner_slot_digest
        || trustedClockSample.trusted_utc !== trustedNow) {
      throw new Error("production verified physical live claim trusted-clock binding drifted");
    }
    assertRestartDurablePhysicalTrustedClockValidityWindow(trustedClockSample, {
      not_before: claim.payload.valid_from,
      expires_at: claim.payload.expires_at,
    }, "production verified physical live claim validity");
  }
  const productionTrustHead = production
    ? describeProductionPhysicalExperimentTrustPort(
      assertProductionPhysicalExperimentTrustPort(productionTrustPort),
    )
    : null;
  if (production && productionTrustHead.session_nucleus_hash !== plan.session_nucleus_hash) {
    throw new Error("production verified physical claim trust head belongs to another session nucleus");
  }
  const durableHead = production
    ? readPhysicalExperimentDurableHead(
      assertProductionPhysicalExperimentDurableHeadPort(productionPort),
      plan.plan_hash,
    )
    : null;
  if (production && (durableHead == null || durableHead.row_digest !== index.row_chain_head)) {
    throw new Error("production verified physical claim does not match the exact durable journal head");
  }
  const externalObserverAssurance = deriveExternalObserverAssurance(normalized, deps);
  const body = {
    version: VERIFIED_PHYSICAL_CLAIM_PROJECTION_VERSION,
    projection_trust_class: production
      ? "production_bob_durable_experiment_projection"
      : "test_only_conformance_projection",
    production_ready: production,
    projection_assurance: production
      ? liveCapability
        ? "isolated_signed_trust_head_disjoint_root_monotonic_row_journal_and_restart_durable_exact_signed_time"
        : "isolated_signed_trust_head_and_disjoint_root_monotonic_two_phase_row_journal"
      : "test_only_injected_durable_head_non_authorizing",
    session_nucleus_hash: plan.session_nucleus_hash,
    experiment_id: plan.experiment_id,
    task_id: plan.task_id,
    attempt_id: plan.attempt_id,
    node_id: plan.node_id,
    contract_hash: plan.contract_hash,
    plan_hash: plan.plan_hash,
    execution_request_digest: plan.execution_request_digest,
    claim_predicate_digest: plan.claim_predicate_digest,
    claim_verdict_ref: claim.row_ref,
    claim_verdict_hash: claim.row_hash,
    claim_verdict_signer_key_id: claim.envelope.signer_key_id,
    claim_verdict_signer_principal_ref: claim.envelope.signer_principal_ref,
    claim_verdict_trust_root_epoch: claim.envelope.trust_root_epoch,
    claim_verdict_trust_domain_ref: claim.envelope.trust_domain_ref,
    claim_verdict_independence_domain_ref: claim.envelope.independence_domain_ref,
    claim_verdict_trust_registry_digest: claim.envelope.trust_registry_digest,
    claim_verdict_signer_enrollment_digest: claim.envelope.signer_enrollment_digest,
    claim_verdict_authorization_context_digest: claim.envelope.authorization_context_digest,
    executed_evidence_registry_digest: plan.executed_evidence_registry_digest,
    upstream_evidence_receipts: Object.freeze(upstreamEvidenceReceipts),
    upstream_execution_identities: upstreamExecutionIdentities,
    upstream_context_digest: upstreamContextDigest,
    verifier_template_id: plan.verifier_template_id,
    verifier_template_version: plan.verifier_template_version,
    verifier_template_digest: plan.verifier_template_digest,
    decision_rule_digest: plan.decision_rule_digest,
    verifier_execution_receipt_ref: claim.payload.verifier_execution_receipt_ref,
    verifier_execution_receipt_digest: claim.payload.verifier_execution_receipt_digest,
    outcome: "verified",
    reason_code: "differential_verified",
    validity_kind: claim.payload.validity_kind,
    valid_from: claim.payload.valid_from,
    decided_at: claim.payload.decided_at,
    transition_state_epoch: transitionStateEpoch,
    transition_state_digest: transitionStateDigest,
    source_asset_ref: plan.source_asset_ref,
    target_asset_ref: plan.target_asset_ref,
    instrument_ref: plan.instrument_ref,
    instrument_identity_ref: plan.instrument_identity_ref,
    instrument_inventory_ref: plan.instrument_inventory_ref,
    ...externalObserverAssurance,
    ...(production ? {
      durable_head_port_id: productionPort.port_id,
      durable_store_binding_digest: productionPort.store_binding_digest,
      durable_head_commit_digest: durableHead.row_commit_digest,
      external_monotonic_owner_digest: productionPort.external_monotonic_owner_digest,
      durable_row_count: index.row_count,
      durable_row_chain_head: index.row_chain_head,
      production_trust_binding_digest: productionTrustHead.trust_binding_digest,
      production_trust_head_sequence: productionTrustHead.trust_head_sequence,
      production_trust_head_digest: productionTrustHead.trust_head_digest,
    } : {}),
    ...(claim.payload.validity_kind === "live_capability" ? {
      expires_at: claim.payload.expires_at,
      capability_instance_ref: claim.payload.capability_instance_ref,
      custody_state_digest: claim.payload.custody_state_digest,
      ...(production ? {
        trusted_clock_port_id: productionTrustedClockSample.port_id,
        trusted_clock_id: productionTrustedClockSample.clock_id,
        trusted_clock_monotonic_epoch_id: productionTrustedClockSample.monotonic_epoch_id,
        trusted_clock_mapping_generation: productionTrustedClockSample.mapping_generation,
        trusted_clock_mapping_digest: productionTrustedClockSample.signed_mapping_digest,
        trusted_clock_trust_statement_digest:
          productionTrustedClockSample.trust_statement_digest,
        trusted_clock_trust_root_public_key_digest:
          productionTrustedClockSample.trust_root_public_key_digest,
        trusted_clock_monotonic_owner_slot_digest:
          productionTrustedClockSample.monotonic_owner_slot_digest,
        trusted_clock_durable_observation_sequence:
          productionTrustedClockSample.durable_observation_sequence,
        trusted_clock_durable_state_digest: productionTrustedClockSample.durable_state_digest,
        trusted_clock_utc_earliest: productionTrustedClockSample.trusted_utc_earliest,
        trusted_clock_utc_latest: productionTrustedClockSample.trusted_utc_latest,
        trusted_clock_max_uncertainty_ms: productionTrustedClockSample.max_uncertainty_ms,
      } : {}),
    } : {}),
  };
  const projection = deepFreeze({ ...body, projection_digest: hashCanonicalJson(body) });
  if (production) {
    const capturedHeadDigest = hashCanonicalJson(durableHead);
    const capturedRows = normalized.rows;
    const revalidate = () => {
      const currentTrustHead = describeProductionPhysicalExperimentTrustPort(
        assertProductionPhysicalExperimentTrustPort(productionTrustPort),
      );
      if (currentTrustHead.trust_head_digest !== body.production_trust_head_digest
          || currentTrustHead.trust_head_sequence !== body.production_trust_head_sequence
          || currentTrustHead.trust_binding_digest !== body.production_trust_binding_digest
          || currentTrustHead.session_nucleus_hash !== body.session_nucleus_hash) {
        throw new Error("production verified physical claim projection signed trust head changed");
      }
      const currentHead = readPhysicalExperimentDurableHead(
        assertProductionPhysicalExperimentDurableHeadPort(productionPort),
        plan.plan_hash,
      );
      if (currentHead == null || hashCanonicalJson(currentHead) !== capturedHeadDigest) {
        throw new Error("production verified physical claim projection is no longer at the exact durable head");
      }
      let currentTrustedNow;
      if (body.validity_kind === "live_capability") {
        const currentClockPort = assertProductionPhysicalTrustedClockPort(
          productionTrustedClockPort,
        );
        const currentClockSample = assertProductionPhysicalTrustedClockSample(
          sampleRestartDurablePhysicalTrustedClock(currentClockPort),
        );
        if (currentClockSample.target_domain !== productionTargetDomain
            || currentClockSample.session_nucleus_hash !== body.session_nucleus_hash
            || currentClockSample.port_id !== body.trusted_clock_port_id
            || currentClockSample.clock_id !== body.trusted_clock_id
            || currentClockSample.monotonic_epoch_id
              !== body.trusted_clock_monotonic_epoch_id
            || currentClockSample.trust_root_public_key_digest
              !== body.trusted_clock_trust_root_public_key_digest
            || currentClockSample.monotonic_owner_slot_digest
              !== body.trusted_clock_monotonic_owner_slot_digest
            || currentClockSample.mapping_generation < body.trusted_clock_mapping_generation
            || currentClockSample.durable_observation_sequence
              <= body.trusted_clock_durable_observation_sequence) {
          throw new Error("production verified physical live claim trusted-clock state drifted");
        }
        assertRestartDurablePhysicalTrustedClockValidityWindow(currentClockSample, {
          not_before: body.valid_from,
          expires_at: body.expires_at,
        }, "production verified physical live claim current validity");
        currentTrustedNow = currentClockSample.trusted_utc;
      } else {
        currentTrustedNow = productionTrustedNow();
      }
      const current = normalizeLedger(
        plan,
        capturedRows,
        { ...deps, trustedNow: currentTrustedNow, planAdmission: true },
        { liveRevalidation: true },
      );
      const currentExternalObserverAssurance = deriveExternalObserverAssurance(current, deps);
      if (current.index.row_count !== body.durable_row_count
          || current.index.row_chain_head !== body.durable_row_chain_head
          || current.index.claim_projection?.outcome !== "verified"
          || current.index.claim_projection?.reason_code !== "differential_verified"
          || currentExternalObserverAssurance.external_observer_independence_domain_count
            !== body.external_observer_independence_domain_count
          || currentExternalObserverAssurance.external_observer_independence_domain_digest
            !== body.external_observer_independence_domain_digest
          || currentExternalObserverAssurance.high_impact_corroboration_satisfied
            !== body.high_impact_corroboration_satisfied) {
        throw new Error("production verified physical claim projection failed live ledger revalidation");
      }
      return true;
    };
    PRODUCTION_VERIFIED_PHYSICAL_CLAIM_PROJECTIONS.add(projection);
    PRODUCTION_VERIFIED_PHYSICAL_CLAIM_PROJECTION_STATE.set(projection, Object.freeze({
      projection,
      revalidate,
    }));
  } else {
    TEST_VERIFIED_PHYSICAL_CLAIM_PROJECTIONS.add(projection);
    TEST_VERIFIED_PHYSICAL_CLAIM_PROJECTION_STATE.set(projection, projection);
  }
  return projection;
}

function assertVerifiedPhysicalClaimProjection(value) {
  const issuance = value && PRODUCTION_VERIFIED_PHYSICAL_CLAIM_PROJECTION_STATE.get(value);
  if (
    !value
    || !PRODUCTION_VERIFIED_PHYSICAL_CLAIM_PROJECTIONS.has(value)
    || !issuance
    || issuance.projection !== value
    || value.production_ready !== true
  ) {
    throw new Error(
      "verified physical claim projection must be production-qualified by a live Bob experiment ledger",
    );
  }
  issuance.revalidate();
  return value;
}

function assertTestVerifiedPhysicalClaimProjection(value) {
  if (
    !value
    || !TEST_VERIFIED_PHYSICAL_CLAIM_PROJECTIONS.has(value)
    || TEST_VERIFIED_PHYSICAL_CLAIM_PROJECTION_STATE.get(value) !== value
    || value.production_ready !== false
    || value.projection_trust_class !== "test_only_conformance_projection"
  ) throw new Error("test physical claim projection must be issued by a live test Bob ledger");
  return value;
}

function createPhysicalExperimentLedgerInternal({
  plan: planInput,
  initialRows = [],
  durableHeadPort,
  resolveSigner,
  verifySignature,
  observerEnrollmentRegistry,
  physicalReceiptRegistry,
  evidenceReceiptRegistry,
  trustedNow,
  isSignerCurrentlyRevoked,
  isObserverEnrollmentCurrentlyRevoked,
  isEvidenceComponentCurrentlyRevoked,
  effectRegistry,
  evidenceRegistry,
  resolveExecutedEvidenceVerification,
  resolveVerifierExecutionReceipt: resolveVerifierReceipt,
} = {}, {
  production = false,
  durabilityTrustClass = "test_only_injected_callback",
  targetDomain = null,
  trustEnrollment = null,
  ingestEvidenceReceiptFn = null,
  trustedClockPort = null,
} = {}) {
  const mechanismA = durabilityTrustClass
    === "mechanism_a_local_signer_custodied_rollback_detection";
  const trustBound = production || mechanismA;
  const productionTrustPort = trustBound
    ? assertProductionPhysicalExperimentTrustPort(trustEnrollment)
    : null;
  const restartDurableTrustedClockPort = trustedClockPort == null
    ? null
    : assertRestartDurablePhysicalTrustedClockPort(trustedClockPort);
  if (restartDurableTrustedClockPort != null && !production) {
    throw new Error("restart-durable production trusted time is accepted only by production ledgers");
  }
  const trustedClockDescription = restartDurableTrustedClockPort == null
    ? null
    : describeProductionPhysicalTrustedClockPort(restartDurableTrustedClockPort);
  const productionTrustedClockPort = trustedClockDescription?.production_ready === true
    ? assertProductionPhysicalTrustedClockPort(restartDurableTrustedClockPort)
    : null;
  if (trustBound) assertProductionPhysicalExperimentTrustHeadCurrent(productionTrustPort);
  if (typeof trustedNow !== "function") throw new Error("physical experiment ledger requires trustedNow");
  const initialNow = assertTimestamp(trustedNow(), "trusted_now");
  const plan = normalizePhysicalExperimentPlan(planInput, "physical_experiment_plan", {
    observerEnrollmentRegistry,
    physicalReceiptRegistry,
    evidenceReceiptRegistry,
    trustedNow: initialNow,
    planAdmission: true,
  });
  const deps = {
    resolveSigner,
    verifySignature,
    observerEnrollmentRegistry,
    physicalReceiptRegistry,
    evidenceReceiptRegistry,
    trustedNow: initialNow,
    isSignerCurrentlyRevoked,
    isObserverEnrollmentCurrentlyRevoked,
    isEvidenceComponentCurrentlyRevoked,
    effectRegistry,
    evidenceRegistry,
    resolveExecutedEvidenceVerification,
    resolveVerifierExecutionReceipt: resolveVerifierReceipt,
  };
  // Validate dependencies before any row is accepted, while keeping key custody
  // outside this closure.
  if (
    typeof resolveSigner !== "function"
    || typeof verifySignature !== "function"
    || typeof isSignerCurrentlyRevoked !== "function"
    || typeof isObserverEnrollmentCurrentlyRevoked !== "function"
    || typeof isEvidenceComponentCurrentlyRevoked !== "function"
    || !effectRegistry
  ) {
    throw new Error(
      "physical experiment ledger requires signer, closed receipt registries, trusted time, and effect-registry dependencies",
    );
  }
  assertImmutableRegistry(plan, deps);
  const headPort = production
    ? assertProductionPhysicalExperimentDurableHeadPort(durableHeadPort)
    : mechanismA
      ? assertMechanismAPhysicalExperimentDurableHeadPort(durableHeadPort)
      : assertTestPhysicalExperimentDurableHeadPort(durableHeadPort);
  // Durable row bytes are owned by the caller's append journal, while the
  // injected strongly-consistent port owns the one canonical committed head.
  // Supplying a recovered chain replays every signature, append receipt,
  // sequence, hash, cohort, evidence, and verifier binding, then requires its
  // last row to match that durable head before a live ledger brand is issued.
  // This is reconstruction, not trust in a serialized WeakSet brand.
  let state = normalizeLedger(plan, initialRows, deps);
  assertPhysicalExperimentLocalHeadCurrent(headPort, plan, state.rows);
  if (trustBound) assertProductionPhysicalExperimentTrustHeadCurrent(productionTrustPort);
  const assertProductionTrustCurrent = () => {
    if (!trustBound) return null;
    return assertProductionPhysicalExperimentTrustHeadCurrent(productionTrustPort);
  };
  const ledger = Object.freeze({
    plan,
    ingestEvidenceReceipt(receipt) {
      if (!trustBound || typeof ingestEvidenceReceiptFn !== "function") {
        throw new Error("durable evidence receipt ingestion requires a trust-bound experiment ledger");
      }
      const admittedReceipt = cloneStrictProductionData(
        receipt,
        "production physical experiment evidence receipt",
      );
      assertProductionTrustCurrent();
      const ingested = ingestEvidenceReceiptFn(admittedReceipt);
      assertProductionTrustCurrent();
      return ingested;
    },
    append(rowInput) {
      const admittedRowInput = trustBound
        ? cloneStrictProductionData(rowInput, "production physical experiment append row")
        : rowInput;
      assertProductionTrustCurrent();
      assertPhysicalExperimentLocalHeadCurrent(headPort, plan, state.rows);
      const expectedSequence = state.rows.length + 1;
      const next = normalizeLedger(
        plan,
        [...state.rows, admittedRowInput],
        { ...deps, trustedNow: assertTimestamp(trustedNow(), "trusted_now") },
        { admissionSequence: expectedSequence },
      );
      const appended = next.rows.find((row) => row.envelope.sequence === next.rows.length);
      const committed = commitPhysicalExperimentRow(
        headPort,
        physicalExperimentRowCommit(plan, appended),
        appended,
      );
      if (committed.expected_sequence !== expectedSequence
          || committed.previous_row_hash !== appended.envelope.previous_row_hash
          || committed.append_receipt_digest !== appended.envelope.append_receipt.receipt_digest
          || committed.row_digest !== appended.row_hash) {
        throw new Error("physical experiment durable append exact binding drift");
      }
      assertProductionTrustCurrent();
      state = next;
      return deepFreeze({ row: appended, index: next.index });
    },
    rows() {
      assertProductionTrustCurrent();
      return state.rows;
    },
    rebuildIndex() {
      assertProductionTrustCurrent();
      assertPhysicalExperimentLocalHeadCurrent(headPort, plan, state.rows);
      const rebuilt = normalizeLedger(plan, state.rows, deps).index;
      assertProductionTrustCurrent();
      return rebuilt;
    },
    readiness() {
      const currentTrustHead = assertProductionTrustCurrent();
      const currentTrustedClock = restartDurableTrustedClockPort == null
        ? null
        : describeProductionPhysicalTrustedClockPort(restartDurableTrustedClockPort);
      const liveCapabilityReady = production && currentTrustedClock?.production_ready === true;
      return deepFreeze({
        version: PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_VERSION,
        production_ready: production,
        durable_head_consistency: headPort.consistency_model,
        durable_head_port_id: headPort.port_id,
        durable_head_backend_assurance: headPort.backend_assurance,
        durability_trust_class: mechanismA
          ? "mechanism_a_local_signer_custodied_rollback_detection"
          : production
            ? "independently_retained_monotonic_owner"
            : "test_only_injected_callback",
        external_monotonic_owner_bound: production,
        external_monotonic_owner_digest: production
          ? headPort.external_monotonic_owner_digest
          : null,
        historical_event_ready: production,
        live_capability_ready: liveCapabilityReady,
        live_capability_reason: liveCapabilityReady
          ? null
          : currentTrustedClock?.production_blocker || (production || mechanismA
            ? "restart_durable_signed_trusted_time_not_installed"
            : "production_durable_head_not_installed"),
        ...(restartDurableTrustedClockPort == null ? {} : {
          restart_durable_trusted_clock_bound: true,
          trusted_clock_port_id: restartDurableTrustedClockPort.port_id,
          trusted_clock_source_assurance: currentTrustedClock.source_assurance,
          trusted_clock_exact_signed_time_ready:
            currentTrustedClock.exact_signed_time_ready === true,
          trusted_clock_production_ready: currentTrustedClock.production_ready === true,
        }),
        ...(trustBound ? {
          production_trust_assurance: productionTrustPort.trust_assurance,
          production_trust_head_sequence: currentTrustHead.sequence,
          production_trust_head_digest: currentTrustHead.head_digest,
        } : {}),
        reason: production
          ? null
          : mechanismA
            ? "independently_retained_monotonic_row_head_owner_unavailable"
            : "production_strongly_consistent_durable_head_backend_not_implemented",
      });
    },
    projectVerifiedClaim() {
      if (!production) {
        throw new Error(
          "production verified physical claim projection is unavailable without a production durable head",
        );
      }
      assertProductionTrustCurrent();
      assertPhysicalExperimentLocalHeadCurrent(headPort, plan, state.rows);
      const liveCapability = state.index.claim_projection?.validity_kind === "live_capability";
      if (liveCapability && productionTrustedClockPort == null) {
        throw new Error(LIVE_CAPABILITY_TRUSTED_TIME_BLOCKER);
      }
      const trustedClockSample = liveCapability
        ? assertProductionPhysicalTrustedClockSample(
          sampleRestartDurablePhysicalTrustedClock(productionTrustedClockPort),
        )
        : null;
      const currentTrustedNow = trustedClockSample == null
        ? assertTimestamp(trustedNow(), "trusted_now")
        : trustedClockSample.trusted_utc;
      const revalidated = normalizeLedger(
        plan,
        state.rows,
        { ...deps, trustedNow: currentTrustedNow, planAdmission: true },
        { liveRevalidation: true },
      );
      return buildVerifiedPhysicalClaimProjection(revalidated, deps, currentTrustedNow, {
        productionPort: headPort,
        productionTrustPort,
        productionTrustedClockPort: trustedClockSample == null
          ? null
          : productionTrustedClockPort,
        productionTrustedClockSample: trustedClockSample,
      });
    },
    projectTestVerifiedClaim() {
      if (production) {
        throw new Error("production physical experiment ledgers do not issue test claim projections");
      }
      if (mechanismA) {
        throw new Error(
          "Mechanism-A local durability cannot issue a verified projection without an independently retained monotonic owner",
        );
      }
      assertPhysicalExperimentLocalHeadCurrent(headPort, plan, state.rows);
      const currentTrustedNow = assertTimestamp(trustedNow(), "trusted_now");
      const revalidated = normalizeLedger(
        plan,
        state.rows,
        { ...deps, trustedNow: currentTrustedNow, planAdmission: true },
        { liveRevalidation: true },
      );
      return buildVerifiedPhysicalClaimProjection(revalidated, deps, currentTrustedNow);
    },
  });
  if (production) {
    PRODUCTION_PHYSICAL_EXPERIMENT_LEDGERS.add(ledger);
    PRODUCTION_PHYSICAL_EXPERIMENT_LEDGER_STATE.set(ledger, deepFreeze({
      target_domain: targetDomain,
      session_nucleus_hash: plan.session_nucleus_hash,
      plan_hash: plan.plan_hash,
      durable_head_port_id: headPort.port_id,
      production_trust_binding_digest: productionTrustPort.trust_binding_digest,
      production_trust_head_sequence: productionTrustPort.trust_head_sequence,
      production_trust_head_digest: productionTrustPort.trust_head_digest,
      external_monotonic_owner_digest: headPort.external_monotonic_owner_digest,
      production_ready: true,
      restart_durable_trusted_clock_bound: restartDurableTrustedClockPort != null,
      trusted_clock_port_id: restartDurableTrustedClockPort?.port_id || null,
      trusted_clock_source_assurance: trustedClockDescription?.source_assurance || null,
      live_capability_ready: productionTrustedClockPort != null,
      live_capability_reason: productionTrustedClockPort == null
        ? trustedClockDescription?.production_blocker
          || "restart_durable_signed_trusted_time_not_installed"
        : null,
    }));
  } else if (mechanismA) {
    MECHANISM_A_PHYSICAL_EXPERIMENT_LEDGERS.add(ledger);
    MECHANISM_A_PHYSICAL_EXPERIMENT_LEDGER_STATE.set(ledger, deepFreeze({
      target_domain: targetDomain,
      session_nucleus_hash: plan.session_nucleus_hash,
      plan_hash: plan.plan_hash,
      durable_head_port_id: headPort.port_id,
      production_trust_binding_digest: productionTrustPort.trust_binding_digest,
      production_trust_head_sequence: productionTrustPort.trust_head_sequence,
      production_trust_head_digest: productionTrustPort.trust_head_digest,
      production_ready: false,
      blocker: "independently_retained_monotonic_row_head_owner_unavailable",
    }));
  }
  return ledger;
}

function createPhysicalExperimentLedger(input = {}) {
  return createPhysicalExperimentLedgerInternal(input);
}

function physicalExperimentProductionTrustBinding({
  signerTrustRegistry,
  observerEnrollmentRegistry,
  physicalReceiptRegistry,
  evidenceReceiptRegistry,
  effectRegistry,
  evidenceRegistry,
}) {
  const signer = assertPhysicalExperimentSignerTrustRegistry(signerTrustRegistry);
  const observer = assertPhysicalObserverEnrollmentRegistry(observerEnrollmentRegistry);
  const physicalReceipt = assertPhysicalReceiptTrustRegistry(physicalReceiptRegistry);
  const evidenceReceipt = assertDurableReceiptTrustRegistry(evidenceReceiptRegistry);
  const effects = assertEffectTemplateRegistry(effectRegistry);
  const evidence = assertExecutedEvidenceRegistry(evidenceRegistry);
  return deepFreeze({
    signer_trust_registry_digest: signer.registry_digest,
    observer_enrollment_registry_digest: observer.registry_digest,
    physical_receipt_registry_digest: physicalReceipt.registry_digest,
    evidence_receipt_registry_digest: evidenceReceipt.registry_digest,
    requested_effects_registry_digest: effects.registry_digest,
    executed_evidence_registry_digest: evidence.registry_digest,
  });
}

function enrollProductionPhysicalExperimentTrust(input) {
  const fields = readExactProductionObjectFields(
    input,
    "production physical experiment trust enrollment",
    [
      "version",
      "target_domain",
      "session_nucleus_hash",
      "signerTrustRegistry",
      "observerEnrollmentRegistry",
      "physicalReceiptRegistry",
      "evidenceReceiptRegistry",
      "effectRegistry",
      "evidenceRegistry",
    ],
  );
  if (fields.version !== 1) throw new Error("production physical experiment trust enrollment.version must be 1");
  return enrollProductionPhysicalExperimentTrustHead({
    version: 1,
    target_domain: fields.target_domain,
    session_nucleus_hash: assertDigest(
      fields.session_nucleus_hash,
      "production physical experiment trust enrollment.session_nucleus_hash",
    ),
    trust_binding: physicalExperimentProductionTrustBinding(fields),
  });
}

function assertCurrentProductionPhysicalExperimentTrust(trustEnrollment) {
  return describeProductionPhysicalExperimentTrustPort(
    assertProductionPhysicalExperimentTrustPort(trustEnrollment),
  );
}

function productionSignerTrustDependencies(registry) {
  const signerRegistry = assertPhysicalExperimentSignerTrustRegistry(registry);

  function signerAt(request) {
    const entry = physicalExperimentSignerEntry(
      signerRegistry,
      request.signer_key_id,
      request.trust_root_epoch,
    );
    if (!entry) throw new Error("physical experiment signer is not enrolled in the production trust registry");
    return entry;
  }

  return Object.freeze({
    resolveSigner(request) {
      const entry = signerAt(request);
      const descriptor = entry.descriptor;
      if (request.trust_registry_digest !== signerRegistry.registry_digest
          || request.signer_enrollment_digest !== descriptor.signer_enrollment_digest) {
        throw new Error("physical experiment signer trust binding drift");
      }
      if (request.row_kind === "execution_receipt"
          && request.authorization_context?.binding?.instrument_identity_ref
            !== descriptor.instrument_identity_ref) {
        throw new Error("physical experiment execution signer is not assigned to the instrument identity");
      }
      if (request.row_kind === "observation"
          && request.authorization_context?.binding?.observer_identity_ref
            !== descriptor.observer_identity_ref) {
        throw new Error("physical experiment observation signer is not assigned to the observer identity");
      }
      if (hashCanonicalJson(request.authorization_context) !== request.authorization_context_digest) {
        throw new Error("physical experiment signer authorization context digest drift");
      }
      const signedAtMs = Date.parse(assertTimestamp(request.signed_at, "physical experiment signer signed_at"));
      const validAtSignature = descriptor.trusted === true
        && signedAtMs >= Date.parse(descriptor.valid_from)
        && (descriptor.expires_at == null || signedAtMs <= Date.parse(descriptor.expires_at))
        && (!descriptor.revoked || signedAtMs < Date.parse(descriptor.revoked_at));
      let activeNow = true;
      if (isCurrentTrustValidationMode(request.validation_mode)) {
        const nowMs = Date.parse(assertTimestamp(request.trusted_now, "physical experiment signer trusted_now"));
        activeNow = descriptor.trusted === true
          && nowMs >= Date.parse(descriptor.valid_from)
          && (descriptor.expires_at == null || nowMs <= Date.parse(descriptor.expires_at))
          && (!descriptor.revoked || nowMs < Date.parse(descriptor.revoked_at));
      }
      return {
        signer_principal_ref: descriptor.signer_principal_ref,
        trust_domain_ref: descriptor.trust_domain_ref,
        independence_domain_ref: descriptor.independence_domain_ref,
        trust_root_epoch: descriptor.trust_root_epoch,
        trust_registry_digest: signerRegistry.registry_digest,
        signer_enrollment_digest: descriptor.signer_enrollment_digest,
        authorization_context_digest: request.authorization_context_digest,
        allowed_row_kinds: descriptor.allowed_row_kinds,
        trusted: validAtSignature && activeNow,
        revoked: !validAtSignature || !activeNow,
      };
    },
    verifySignature({ signature_input_digest: signatureInputDigest, envelope }) {
      const entry = physicalExperimentSignerEntry(
        signerRegistry,
        envelope.signer_key_id,
        envelope.trust_root_epoch,
      );
      if (!entry || envelope.signature_scheme !== entry.descriptor.signature_scheme
          || typeof envelope.signature !== "string") return false;
      let signature;
      try {
        signature = Buffer.from(envelope.signature, "base64url");
      } catch {
        return false;
      }
      if (signature.length < 1 || signature.toString("base64url") !== envelope.signature) return false;
      if (entry.descriptor.signature_scheme === "ed25519" && signature.length !== 64) return false;
      try {
        return INTRINSIC_VERIFY(
          entry.descriptor.signature_scheme === "ed25519" ? null : "sha256",
          Buffer.from(assertDigest(signatureInputDigest, "physical experiment signature input"), "hex"),
          entry.publicKey,
          signature,
        );
      } catch {
        return false;
      }
    },
    isSignerCurrentlyRevoked(request) {
      if (request.trust_registry_digest !== signerRegistry.registry_digest) return true;
      const entries = PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRY_STATE.get(signerRegistry);
      const matches = [...entries.values()].filter((entry) => (
        entry.descriptor.signer_key_id === request.signer_key_id
        && entry.descriptor.signer_enrollment_digest === request.signer_enrollment_digest
      ));
      if (matches.length !== 1) return true;
      const descriptor = matches[0].descriptor;
      const nowMs = Date.parse(request.trusted_now);
      return !Number.isFinite(nowMs)
        || descriptor.trusted !== true
        || nowMs < Date.parse(descriptor.valid_from)
        || (descriptor.expires_at != null && nowMs > Date.parse(descriptor.expires_at))
        || (descriptor.revoked && nowMs >= Date.parse(descriptor.revoked_at));
    },
  });
}

function productionEvidenceComponentCurrentlyRevoked(evidenceRegistry, request) {
  if (!evidenceRegistry || request.registry_digest !== evidenceRegistry.registry_digest) return true;
  const kindMap = Object.freeze({
    source_adapter: "source_adapters",
    verifier_template: "verifier_templates",
    context_resolver: "context_resolvers",
    replay_executor: "replay_executors",
    dependency_proof_provider: "dependency_proof_providers",
  });
  const kind = kindMap[request.component_kind];
  if (!kind) return true;
  const component = evidenceRegistry.get(kind, request.component_id);
  if (!component || component.trust_state !== "trusted" || component.revoked === true) return true;
  const nowMs = Date.parse(request.trusted_now);
  if (!Number.isFinite(nowMs) || nowMs < Date.parse(component.attested_at)
      || nowMs - Date.parse(component.attested_at) > component.freshness_window_ms
      || (component.expires_at != null && nowMs > Date.parse(component.expires_at))) return true;
  return false;
}

function productionObserverEnrollmentCurrentlyRevoked(observerRegistry, request) {
  const enrollment = observerRegistry.get(request.observer_enrollment_ref);
  if (!enrollment || enrollment.enrollment_digest !== request.observer_enrollment_digest) return true;
  const nowMs = Date.parse(request.trusted_now);
  return !Number.isFinite(nowMs)
    || enrollment.revoked === true
    || nowMs < Date.parse(enrollment.valid_from)
    || (enrollment.expires_at != null && nowMs > Date.parse(enrollment.expires_at));
}

function createTrustedPhysicalExperimentLedger(input, { production }) {
  const fields = readExactProductionObjectFields(
    input,
    "production physical experiment ledger",
    [
      "version",
      "target_domain",
      "plan",
      "trustEnrollment",
      "signerTrustRegistry",
      "observerEnrollmentRegistry",
      "physicalReceiptRegistry",
      "evidenceReceiptRegistry",
      "effectRegistry",
      "evidenceRegistry",
    ],
    ["evidenceReceipts", "monotonicHeadOwner", "trustedClock"],
  );
  if (fields.version !== 1) throw new Error("production physical experiment ledger.version must be 1");
  const targetDomain = typeof fields.target_domain === "string" ? fields.target_domain : "";
  if (targetDomain.length < 1 || targetDomain !== targetDomain.trim()) {
    throw new Error("production physical experiment ledger.target_domain is invalid");
  }
  const signerTrustRegistry = assertPhysicalExperimentSignerTrustRegistry(fields.signerTrustRegistry);
  const observerEnrollmentRegistry = assertPhysicalObserverEnrollmentRegistry(fields.observerEnrollmentRegistry);
  const physicalReceiptRegistry = assertPhysicalReceiptTrustRegistry(fields.physicalReceiptRegistry);
  const evidenceReceiptRegistry = assertDurableReceiptTrustRegistry(fields.evidenceReceiptRegistry);
  const effectRegistry = assertEffectTemplateRegistry(fields.effectRegistry);
  const evidenceRegistry = assertExecutedEvidenceRegistry(fields.evidenceRegistry);
  const trustEnrollment = assertProductionPhysicalExperimentTrustPort(fields.trustEnrollment);
  const trustHead = describeProductionPhysicalExperimentTrustPort(trustEnrollment);
  if (!production && fields.trustedClock != null) {
    throw new Error("Mechanism-A local experiment ledgers cannot accept a production trusted clock");
  }
  const restartDurableTrustedClock = fields.trustedClock == null
    ? null
    : assertRestartDurablePhysicalTrustedClockPort(fields.trustedClock);
  const trustedClockDescription = restartDurableTrustedClock == null
    ? null
    : describeProductionPhysicalTrustedClockPort(restartDurableTrustedClock);
  if (trustedClockDescription != null
      && (trustedClockDescription.target_domain !== targetDomain
        || trustedClockDescription.session_nucleus_hash !== trustHead.session_nucleus_hash)) {
    throw new Error("production physical experiment trusted clock belongs to another target or session nucleus");
  }
  const productionTrustedClock = trustedClockDescription?.production_ready === true
    ? assertProductionPhysicalTrustedClockPort(restartDurableTrustedClock)
    : null;
  const ledgerTrustedNow = productionTrustedClock == null
    ? productionTrustedNow
    : () => assertProductionPhysicalTrustedClockSample(
      sampleRestartDurablePhysicalTrustedClock(productionTrustedClock),
    ).trusted_utc;
  const currentTrustedNow = ledgerTrustedNow();
  const planInput = cloneStrictProductionData(fields.plan, "production physical experiment ledger.plan");
  const plan = normalizePhysicalExperimentPlan(planInput, "physical_experiment_plan", {
    observerEnrollmentRegistry,
    physicalReceiptRegistry,
    evidenceReceiptRegistry,
    trustedNow: currentTrustedNow,
    planAdmission: true,
  });
  if (plan.trust_registry_digest !== signerTrustRegistry.registry_digest) {
    throw new Error("production physical experiment plan does not bind the signer trust registry");
  }
  // normalizeRequestedEffects performs the registry's private WeakSet check
  // before any registry property or method is read.  Keep that check ahead of
  // registry_digest so a Proxy/accessor lookalike cannot execute at the
  // production composition boundary.
  normalizeRequestedEffects(
    plan.requested_effects,
    effectRegistry,
    "production physical experiment plan.requested_effects",
  );
  if (effectRegistry.registry_digest !== plan.requested_effects_registry_digest) {
    throw new Error("production physical experiment plan does not bind the requested-effect registry");
  }
  if (evidenceRegistry.registry_digest !== plan.executed_evidence_registry_digest) {
    throw new Error("production physical experiment plan does not bind the executed-evidence registry");
  }
  const productionTrustBinding = physicalExperimentProductionTrustBinding({
    signerTrustRegistry,
    observerEnrollmentRegistry,
    physicalReceiptRegistry,
    evidenceReceiptRegistry,
    effectRegistry,
    evidenceRegistry,
  });
  if (trustHead.target_domain !== targetDomain
      || trustHead.session_nucleus_hash !== plan.session_nucleus_hash
      || hashCanonicalJson(trustHead.trust_binding) !== hashCanonicalJson(productionTrustBinding)) {
    throw new Error("production physical experiment trust enrollment does not bind this exact session and registry set");
  }
  const evidenceReceiptInput = fields.evidenceReceipts == null ? [] : fields.evidenceReceipts;
  if (!Array.isArray(evidenceReceiptInput) || utilTypes.isProxy(evidenceReceiptInput)
      || evidenceReceiptInput.length > MAX_PHYSICAL_EXPERIMENT_EVIDENCE_RECEIPTS) {
    throw new Error("production physical experiment ledger.evidenceReceipts must be a bounded array");
  }
  const evidenceReceipts = cloneStrictProductionData(
    evidenceReceiptInput,
    "production physical experiment ledger.evidenceReceipts",
  );
  if (production && fields.monotonicHeadOwner == null) {
    throw new Error(
      "production physical experiment durability requires a genuine independently retained monotonic row-head owner",
    );
  }
  if (!production && fields.monotonicHeadOwner != null) {
    throw new Error("Mechanism-A local experiment ledgers cannot accept a production monotonic owner");
  }
  const trustBindingDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-experiment-production-trust-binding/v1",
    target_domain: targetDomain,
    session_nucleus_hash: plan.session_nucleus_hash,
    plan_hash: plan.plan_hash,
    signer_trust_registry_digest: signerTrustRegistry.registry_digest,
    observer_enrollment_registry_digest: observerEnrollmentRegistry.registry_digest,
    physical_receipt_registry_digest: physicalReceiptRegistry.registry_digest,
    evidence_receipt_registry_digest: evidenceReceiptRegistry.registry_digest,
    requested_effects_registry_digest: effectRegistry.registry_digest,
    executed_evidence_registry_digest: evidenceRegistry.registry_digest,
    production_trust_head_digest: trustHead.trust_head_digest,
  });
  const durableHeadInput = {
    version: 1,
    target_domain: targetDomain,
    session_nucleus_hash: plan.session_nucleus_hash,
    plan_hash: plan.plan_hash,
    trust_binding_digest: trustBindingDigest,
    trust_head_digest: trustHead.trust_head_digest,
    signer_owner_custody_digest: trustHead.signer_owner_custody_digest,
  };
  const durableHeadPort = production
    ? openProductionPhysicalExperimentDurableHeadPort(
      durableHeadInput,
      trustEnrollment,
      fields.monotonicHeadOwner,
    )
    : openMechanismAPhysicalExperimentDurableHeadPort(durableHeadInput, trustEnrollment);
  if (!production) {
    assertMechanismAPhysicalExperimentDurableHeadPort(durableHeadPort);
    MECHANISM_A_PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORTS.add(durableHeadPort);
  }

  function normalizeAndIngestEvidenceReceipt(receiptInput) {
    const admittedReceipt = cloneStrictProductionData(
      receiptInput,
      "production physical experiment evidence receipt",
    );
    assertProductionPhysicalExperimentTrustHeadCurrent(trustEnrollment);
    const receipt = normalizeAndVerifyDurableEvidenceReceipt(
      admittedReceipt,
      evidenceReceiptRegistry,
      {
        mode: "admission",
        trusted_now: ledgerTrustedNow(),
        label: "production physical experiment evidence receipt",
      },
    );
    if (!["executed_evidence_verification", "physical_verifier_execution"].includes(receipt.receipt_kind)) {
      throw new Error("production physical experiment ledger accepts only experiment evidence receipts");
    }
    const ingested = production
      ? ingestProductionPhysicalExperimentReceipt(durableHeadPort, receipt)
      : ingestMechanismAPhysicalExperimentReceipt(durableHeadPort, receipt);
    assertProductionPhysicalExperimentTrustHeadCurrent(trustEnrollment);
    return ingested;
  }

  for (const receipt of evidenceReceipts) normalizeAndIngestEvidenceReceipt(receipt);

  const signerDeps = productionSignerTrustDependencies(signerTrustRegistry);
  const initialRows = production
    ? readProductionPhysicalExperimentRows(durableHeadPort)
    : readMechanismAPhysicalExperimentRows(durableHeadPort);
  return createPhysicalExperimentLedgerInternal({
    plan,
    initialRows,
    durableHeadPort,
    resolveSigner: signerDeps.resolveSigner,
    verifySignature: signerDeps.verifySignature,
    observerEnrollmentRegistry,
    physicalReceiptRegistry,
    evidenceReceiptRegistry,
    trustedNow: ledgerTrustedNow,
    isSignerCurrentlyRevoked: signerDeps.isSignerCurrentlyRevoked,
    isObserverEnrollmentCurrentlyRevoked: (request) => (
      productionObserverEnrollmentCurrentlyRevoked(observerEnrollmentRegistry, request)
    ),
    isEvidenceComponentCurrentlyRevoked: (request) => (
      productionEvidenceComponentCurrentlyRevoked(evidenceRegistry, request)
    ),
    effectRegistry,
    evidenceRegistry,
    resolveExecutedEvidenceVerification(request) {
      const lookup = {
        receipt_ref: request.verification_receipt_ref,
        receipt_digest: request.verification_receipt_digest,
      };
      return production
        ? resolveProductionPhysicalExperimentReceipt(durableHeadPort, lookup)
        : resolveMechanismAPhysicalExperimentReceipt(durableHeadPort, lookup);
    },
    resolveVerifierExecutionReceipt(request) {
      const lookup = {
        receipt_ref: request.receipt_ref,
        receipt_digest: request.receipt_digest,
      };
      return production
        ? resolveProductionPhysicalExperimentReceipt(durableHeadPort, lookup)
        : resolveMechanismAPhysicalExperimentReceipt(durableHeadPort, lookup);
    },
  }, {
    production,
    durabilityTrustClass: production
      ? "independently_retained_monotonic_owner"
      : "mechanism_a_local_signer_custodied_rollback_detection",
    targetDomain,
    trustEnrollment,
    ingestEvidenceReceiptFn: normalizeAndIngestEvidenceReceipt,
    trustedClockPort: restartDurableTrustedClock,
  });
}

function createMechanismAPhysicalExperimentLedger(input) {
  return createTrustedPhysicalExperimentLedger(input, { production: false });
}

function createProductionPhysicalExperimentLedger(input) {
  return createTrustedPhysicalExperimentLedger(input, { production: true });
}

function assertMechanismAPhysicalExperimentLedger(ledger) {
  if (!ledger || !MECHANISM_A_PHYSICAL_EXPERIMENT_LEDGERS.has(ledger)
      || !MECHANISM_A_PHYSICAL_EXPERIMENT_LEDGER_STATE.has(ledger)
      || !Object.isFrozen(ledger)
      || ledger.readiness().production_ready !== false
      || ledger.readiness().durability_trust_class
        !== "mechanism_a_local_signer_custodied_rollback_detection") {
    throw new Error("physical experiment ledger must be a live Mechanism-A local composition");
  }
  return ledger;
}

function describeMechanismAPhysicalExperimentLedger(ledger) {
  assertMechanismAPhysicalExperimentLedger(ledger);
  return MECHANISM_A_PHYSICAL_EXPERIMENT_LEDGER_STATE.get(ledger);
}

function assertProductionPhysicalExperimentLedger(ledger) {
  if (!ledger || !PRODUCTION_PHYSICAL_EXPERIMENT_LEDGERS.has(ledger)
      || !PRODUCTION_PHYSICAL_EXPERIMENT_LEDGER_STATE.has(ledger)
      || !Object.isFrozen(ledger)
      || ledger.readiness().production_ready !== true) {
    throw new Error("physical experiment ledger must be a live Bob-owned production composition");
  }
  return ledger;
}

function describeProductionPhysicalExperimentLedger(ledger) {
  assertProductionPhysicalExperimentLedger(ledger);
  return PRODUCTION_PHYSICAL_EXPERIMENT_LEDGER_STATE.get(ledger);
}

require("../../core/physical-domain-runtime-ports.js")
  .configurePhysicalDomainRuntimePorts({ assertVerifiedPhysicalClaimProjection });

module.exports = {
  CLAIM_DISPOSITIONS,
  CLAIM_REASON_CODES,
  CLEANUP_DISPOSITIONS,
  COHORT_KINDS,
  OBSERVATION_SOURCE_KINDS,
  PHYSICAL_EXPERIMENT_INDEX_VERSION,
  PHYSICAL_EXPERIMENT_DURABLE_HEAD_PORT_VERSION,
  PHYSICAL_EXPERIMENT_SIGNER_TRUST_REGISTRY_VERSION,
  PHYSICAL_EXPERIMENT_PLAN_VERSION,
  PHYSICAL_EXPERIMENT_ROW_KINDS,
  PHYSICAL_EXPERIMENT_ROW_VERSION,
  SIGNATURE_SCHEMES,
  VALIDITY_KINDS,
  VERIFIED_PHYSICAL_CLAIM_PROJECTION_VERSION,
  ZERO_HASH,
  assertPhysicalObserverEnrollmentRegistry,
  assertPhysicalReceiptTrustRegistry,
  assertPhysicalExperimentSignerTrustRegistry,
  assertCurrentProductionPhysicalExperimentTrust,
  assertMechanismAPhysicalExperimentLedger,
  assertProductionPhysicalExperimentLedger,
  assertTestVerifiedPhysicalClaimProjection,
  assertVerifiedPhysicalClaimProjection,
  attemptAllocationBindingDigest,
  buildPhysicalObserverEnrollmentRegistry,
  buildPhysicalExperimentSignerTrustRegistry,
  buildPhysicalReceiptTrustRegistry,
  consumptionAttestationInputDigest,
  createPhysicalAllocationIssuer,
  createPhysicalAppendIssuer,
  createPhysicalExperimentLedger,
  createMechanismAPhysicalExperimentLedger,
  enrollProductionPhysicalExperimentTrust,
  createProductionPhysicalExperimentLedger,
  createTestPhysicalExperimentDurableHeadPort,
  executionConsumptionBindingDigest,
  describeMechanismAPhysicalExperimentLedger,
  describeProductionPhysicalExperimentLedger,
  normalizePhysicalExperimentPlan,
  normalizePhysicalExperimentRow,
  normalizePhysicalExperimentRowPayload,
  observerAttemptBindingDigest,
  observationConsumptionBindingDigest,
  rowAuthorizationContextDigest,
  rebuildPhysicalExperimentIndex,
  signatureInputDigest,
};
