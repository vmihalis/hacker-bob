"use strict";

// Signed trust envelopes for Plane-PH resource reservations. These primitives
// are deliberately callback-backed integration contracts: they authenticate
// exact inventory/checkpoint documents and current signer epochs, but do not
// claim that a JavaScript callback is an external HSM, monotonic store, or
// process-isolated trust service.

const crypto = require("node:crypto");

const {
  normalizePhysicalResourceInventory,
} = require("../../../mcp/domains/physical/physical-resource-scheduler.js");
const {
  assertPhysicalTrustedClockSample,
} = require("../../../mcp/domains/physical/physical-trusted-clock.js");
const {
  normalizeOpaqueRef,
} = require("../../../mcp/domains/physical/physical-quantities.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const RESOURCE_RESERVATION_ATTESTATION_VERSION = 1;
const RESOURCE_INVENTORY_ATTESTATION_DOMAIN =
  "hacker-bob/physical-resource-inventory-attestation/v1";
const RESOURCE_INVENTORY_ATTESTATION_SIGNING_DOMAIN =
  "hacker-bob/physical-resource-inventory-attestation-signature/v1";
const RESOURCE_RESERVATION_CHECKPOINT_DOMAIN =
  "hacker-bob/physical-resource-reservation-checkpoint/v1";
const RESOURCE_RESERVATION_CHECKPOINT_SIGNING_DOMAIN =
  "hacker-bob/physical-resource-reservation-checkpoint-signature/v1";
const RESOURCE_RESERVATION_COMPACTION_DOMAIN =
  "hacker-bob/physical-resource-reservation-history-compaction/v1";
const RESOURCE_INVENTORY_TRUST_PORT_CONTRACT =
  "external-current-physical-resource-inventory-signer-trust-v1";
const RESOURCE_CHECKPOINT_TRUST_PORT_CONTRACT =
  "external-monotonic-physical-resource-reservation-checkpoint-anchor-v1";
const RESOURCE_CHECKPOINT_CLOCK_TRANSITION_CONTRACT =
  "external-trusted-monotonic-clock-epoch-transition-v1";
const MAX_CHECKPOINT_CHAIN_LENGTH = 4_096;
const MAX_COMPACTION_BATCH_RECORD_DIGESTS = 4_096;
const MAX_RESERVATION_CHECKPOINT_HISTORY_DIGESTS = 4_096 + 16_384;
const MAX_RESERVATION_CHECKPOINT_TOMBSTONE_DIGESTS = 16_384;
const MAX_ATTESTATION_VALIDITY_MS = 24 * 60 * 60 * 1_000;
const MAX_CANONICAL_TREE_NODES = 250_000;
const MAX_CANONICAL_TREE_KEYS = 250_000;

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;

const INVENTORY_TRUST_PORTS = new WeakSet();
const INVENTORY_TRUST_PRIVATE = new WeakMap();
const CHECKPOINT_TRUST_PORTS = new WeakSet();
const CHECKPOINT_TRUST_PRIVATE = new WeakMap();
const ACTIVE_TRUST_CALLBACKS = new WeakSet();

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = keys.filter((key) => !allowed.has(key)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}.${key} must be an enumerable data field`);
    }
  }
  return value;
}

function assertCanonicalDataTree(value, label, traversal = null, depth = 0) {
  const state = traversal || { seen: new WeakSet(), nodes: 0, keys: 0 };
  if (depth > 64) throw new Error(`${label} exceeds the canonical nesting limit`);
  state.nodes += 1;
  if (state.nodes > MAX_CANONICAL_TREE_NODES) {
    throw new Error(`${label} exceeds the canonical node budget`);
  }
  if (value === null || ["string", "boolean"].includes(typeof value)) return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new Error(`${label} must contain canonical safe integers`);
    }
    return value;
  }
  if (typeof value !== "object") throw new Error(`${label} must contain JSON data only`);
  if (state.seen.has(value)) throw new Error(`${label} cannot contain aliased or cyclic objects`);
  state.seen.add(value);
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      throw new Error(`${label} must use the intrinsic Array prototype`);
    }
    const allowed = new Set(["length", ...Array.from({ length: value.length }, (_, index) => String(index))]);
    const keys = Reflect.ownKeys(value);
    state.keys += keys.length;
    if (state.keys > MAX_CANONICAL_TREE_KEYS) {
      throw new Error(`${label} exceeds the canonical key budget`);
    }
    if (keys.some((key) => typeof key !== "string") || keys.some((key) => !allowed.has(key))) {
      throw new Error(`${label} cannot contain adorned or symbol array fields`);
    }
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new Error(`${label}[${index}] must be a dense enumerable data field`);
      }
      assertCanonicalDataTree(descriptor.value, `${label}[${index}]`, state, depth + 1);
    }
    return value;
  }
  if (!isPlainObject(value)) throw new Error(`${label} must use a plain object prototype`);
  const keys = Reflect.ownKeys(value);
  state.keys += keys.length;
  if (state.keys > MAX_CANONICAL_TREE_KEYS) {
    throw new Error(`${label} exceeds the canonical key budget`);
  }
  for (const key of keys) {
    if (typeof key !== "string") throw new Error(`${label} cannot contain symbol fields`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}.${key} must be an enumerable data field`);
    }
    assertCanonicalDataTree(descriptor.value, `${label}.${key}`, state, depth + 1);
  }
  return value;
}

function assertDataArray(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  assertCanonicalDataTree(value, label);
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw new Error(`${label} must contain ${minimum}-${maximum} entries`);
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

function assertNullableDigest(value, label) {
  return value === null ? null : assertDigest(value, label);
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
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

function assertInteger(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string") throw new Error(`${label} must be a canonical UTC timestamp`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC timestamp`);
  }
  return value;
}

function assertNullableRevision(value, label) {
  return value === null ? null : assertInteger(value, label, 0);
}

function normalizeSortedDigestArray(
  value,
  label,
  maximum = MAX_COMPACTION_BATCH_RECORD_DIGESTS,
) {
  assertDataArray(value, label, 0, maximum);
  const normalized = value.map((entry, index) => assertDigest(entry, `${label}[${index}]`));
  if (new Set(normalized).size !== normalized.length
      || normalized.some((entry, index) => index > 0 && entry <= normalized[index - 1])) {
    throw new Error(`${label} must be unique and strictly sorted`);
  }
  return Object.freeze(normalized);
}

function assertEd25519PublicKey(value, label) {
  if (!(value instanceof crypto.KeyObject) || value.type !== "public"
      || value.asymmetricKeyType !== "ed25519") {
    throw new Error(`${label} must be an Ed25519 public KeyObject`);
  }
  return value;
}

function physicalResourceAttestationPublicKeyDigest(value) {
  const key = assertEd25519PublicKey(value, "physical resource attestation public key");
  return crypto.createHash("sha256").update(
    key.export({ type: "spki", format: "der" }),
  ).digest("hex");
}

function assertSignature(value, label) {
  if (typeof value !== "string" || !SIGNATURE_PATTERN.test(value)) {
    throw new Error(`${label} must be canonical Ed25519 base64url`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    throw new Error(`${label} must be canonical Ed25519 base64url`);
  }
  return value;
}

function signingMessage(domain, payloadDigest) {
  return Buffer.from(`${domain}\0${assertDigest(payloadDigest, "signed payload digest")}`, "utf8");
}

function physicalResourceInventoryAttestationSigningMessage(payloadDigest) {
  return signingMessage(RESOURCE_INVENTORY_ATTESTATION_SIGNING_DOMAIN, payloadDigest);
}

function physicalResourceReservationCheckpointSigningMessage(payloadDigest) {
  return signingMessage(RESOURCE_RESERVATION_CHECKPOINT_SIGNING_DOMAIN, payloadDigest);
}

function physicalResourceWorkspaceStateDigest(inventoryInput) {
  const inventory = normalizePhysicalResourceInventory(inventoryInput);
  return hashCanonicalJson(inventory.resources.map((resource) => ({
    resource_ref: resource.resource_ref,
    state_epoch_digest: resource.state_epoch_digest,
    current_mode_ref: resource.current_mode_ref || null,
    current_workspace_ref: resource.current_workspace_ref || null,
  })));
}

function physicalResourceSessionBindingDigest(input = {}) {
  assertClosedObject(input, "physical_resource_session_binding", [
    "broker_ref",
    "broker_epoch",
    "session_nucleus_hash",
    "source_graph_hash",
  ]);
  return hashCanonicalJson({
    broker_ref: normalizeOpaqueRef(input.broker_ref, "physical_resource_session_binding.broker_ref", { prefix: "broker" }),
    broker_epoch: assertInteger(input.broker_epoch, "physical_resource_session_binding.broker_epoch", 1),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, "physical_resource_session_binding.session_nucleus_hash"),
    source_graph_hash: assertDigest(input.source_graph_hash, "physical_resource_session_binding.source_graph_hash"),
  });
}

function physicalResourceReservationAuthorityDigest(input = {}) {
  assertClosedObject(input, "physical_resource_reservation_authority_binding", [
    "state_domain_digest",
    "broker_ref",
    "broker_epoch",
    "session_nucleus_hash",
    "source_graph_hash",
    "state_port_id",
    "trusted_clock_port_id",
    "bundle_resolver_port_id",
    "inventory_trust_port_id",
    "checkpoint_trust_port_id",
  ]);
  return hashCanonicalJson({
    state_domain_digest: assertDigest(input.state_domain_digest, "physical_resource_reservation_authority_binding.state_domain_digest"),
    broker_ref: normalizeOpaqueRef(input.broker_ref, "physical_resource_reservation_authority_binding.broker_ref", { prefix: "broker" }),
    broker_epoch: assertInteger(input.broker_epoch, "physical_resource_reservation_authority_binding.broker_epoch", 1),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, "physical_resource_reservation_authority_binding.session_nucleus_hash"),
    source_graph_hash: assertDigest(input.source_graph_hash, "physical_resource_reservation_authority_binding.source_graph_hash"),
    state_port_id: assertIdentifier(input.state_port_id, "physical_resource_reservation_authority_binding.state_port_id"),
    trusted_clock_port_id: assertIdentifier(input.trusted_clock_port_id, "physical_resource_reservation_authority_binding.trusted_clock_port_id"),
    bundle_resolver_port_id: assertIdentifier(input.bundle_resolver_port_id, "physical_resource_reservation_authority_binding.bundle_resolver_port_id"),
    inventory_trust_port_id: assertIdentifier(input.inventory_trust_port_id, "physical_resource_reservation_authority_binding.inventory_trust_port_id"),
    checkpoint_trust_port_id: assertIdentifier(input.checkpoint_trust_port_id, "physical_resource_reservation_authority_binding.checkpoint_trust_port_id"),
  });
}

function physicalResourceReservationCompactionAccumulatorDigest(input = {}) {
  assertClosedObject(input, "physical_resource_reservation_compaction_accumulator", [
    "compaction_generation",
    "prior_accumulator",
    "compacted_record_digests",
    "source_checkpoint_generation",
    "source_checkpoint_digest",
    "source_state_revision",
    "source_state_digest",
    "tombstone_set_digest",
    "tombstone_count",
    "compacted_record_count",
  ]);
  return hashCanonicalJson({
    domain: RESOURCE_RESERVATION_COMPACTION_DOMAIN,
    version: RESOURCE_RESERVATION_ATTESTATION_VERSION,
    compaction_generation: assertInteger(
      input.compaction_generation,
      "physical_resource_reservation_compaction_accumulator.compaction_generation",
      1,
    ),
    prior_accumulator: assertNullableDigest(
      input.prior_accumulator,
      "physical_resource_reservation_compaction_accumulator.prior_accumulator",
    ),
    compacted_record_digests: normalizeSortedDigestArray(
      input.compacted_record_digests,
      "physical_resource_reservation_compaction_accumulator.compacted_record_digests",
    ),
    source_checkpoint_generation: assertInteger(
      input.source_checkpoint_generation,
      "physical_resource_reservation_compaction_accumulator.source_checkpoint_generation",
      1,
    ),
    source_checkpoint_digest: assertDigest(
      input.source_checkpoint_digest,
      "physical_resource_reservation_compaction_accumulator.source_checkpoint_digest",
    ),
    source_state_revision: assertInteger(
      input.source_state_revision,
      "physical_resource_reservation_compaction_accumulator.source_state_revision",
      0,
    ),
    source_state_digest: assertDigest(
      input.source_state_digest,
      "physical_resource_reservation_compaction_accumulator.source_state_digest",
    ),
    tombstone_set_digest: assertDigest(
      input.tombstone_set_digest,
      "physical_resource_reservation_compaction_accumulator.tombstone_set_digest",
    ),
    tombstone_count: assertInteger(
      input.tombstone_count,
      "physical_resource_reservation_compaction_accumulator.tombstone_count",
      1,
    ),
    compacted_record_count: assertInteger(
      input.compacted_record_count,
      "physical_resource_reservation_compaction_accumulator.compacted_record_count",
      1,
    ),
  });
}

function physicalResourceClockBindingDigest(input) {
  return hashCanonicalJson({
    clock_id: assertToken(input.clock_id, "physical_resource_clock_binding.clock_id"),
    monotonic_epoch_id: assertDigest(input.monotonic_epoch_id, "physical_resource_clock_binding.monotonic_epoch_id"),
    clock_mapping_generation: assertInteger(input.clock_mapping_generation, "physical_resource_clock_binding.clock_mapping_generation", 1),
    signed_clock_mapping_digest: assertDigest(input.signed_clock_mapping_digest, "physical_resource_clock_binding.signed_clock_mapping_digest"),
    clock_trust_root_epoch: assertInteger(input.clock_trust_root_epoch, "physical_resource_clock_binding.clock_trust_root_epoch", 1),
    clock_authority_epoch: assertInteger(input.clock_authority_epoch, "physical_resource_clock_binding.clock_authority_epoch", 1),
    clock_revocation_generation: assertInteger(input.clock_revocation_generation, "physical_resource_clock_binding.clock_revocation_generation", 0),
  });
}

function physicalResourceClockEpochTransitionDigest(input = {}) {
  assertClosedObject(input, "physical_resource_clock_epoch_transition", [
    "anchored_clock_binding_digest",
    "current_clock_binding_digest",
    "clock_epoch_transition_generation",
  ]);
  return hashCanonicalJson({
    contract: RESOURCE_CHECKPOINT_CLOCK_TRANSITION_CONTRACT,
    anchored_clock_binding_digest: assertDigest(
      input.anchored_clock_binding_digest,
      "physical_resource_clock_epoch_transition.anchored_clock_binding_digest",
    ),
    current_clock_binding_digest: assertDigest(
      input.current_clock_binding_digest,
      "physical_resource_clock_epoch_transition.current_clock_binding_digest",
    ),
    clock_epoch_transition_generation: assertInteger(
      input.clock_epoch_transition_generation,
      "physical_resource_clock_epoch_transition.clock_epoch_transition_generation",
      0,
    ),
  });
}

function normalizeClockBinding(input, label) {
  const value = {
    clock_id: assertToken(input.clock_id, `${label}.clock_id`),
    monotonic_epoch_id: assertDigest(input.monotonic_epoch_id, `${label}.monotonic_epoch_id`),
    clock_mapping_generation: assertInteger(input.clock_mapping_generation, `${label}.clock_mapping_generation`, 1),
    signed_clock_mapping_digest: assertDigest(input.signed_clock_mapping_digest, `${label}.signed_clock_mapping_digest`),
    clock_trust_root_epoch: assertInteger(input.clock_trust_root_epoch, `${label}.clock_trust_root_epoch`, 1),
    clock_authority_epoch: assertInteger(input.clock_authority_epoch, `${label}.clock_authority_epoch`, 1),
    clock_revocation_generation: assertInteger(input.clock_revocation_generation, `${label}.clock_revocation_generation`, 0),
  };
  return value;
}

function normalizeSignerBinding(input, label, authorityField) {
  return {
    [authorityField]: assertToken(input[authorityField], `${label}.${authorityField}`),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: assertInteger(input.revocation_generation, `${label}.revocation_generation`, 0),
    signer_key_id: assertToken(input.signer_key_id, `${label}.signer_key_id`),
    signer_public_key_digest: assertDigest(input.signer_public_key_digest, `${label}.signer_public_key_digest`),
  };
}

const CLOCK_FIELDS = [
  "clock_id",
  "monotonic_epoch_id",
  "clock_mapping_generation",
  "signed_clock_mapping_digest",
  "clock_trust_root_epoch",
  "clock_authority_epoch",
  "clock_revocation_generation",
];
const SIGNER_FIELDS = [
  "trust_root_epoch",
  "authority_epoch",
  "revocation_generation",
  "signer_key_id",
  "signer_public_key_digest",
];

function normalizeInventoryPayload(input, label) {
  assertClosedObject(input, label, [
    "version",
    "inventory_authority_id",
    "attestation_generation",
    "prior_attestation_digest",
    "reservation_authority_digest",
    "state_domain_digest",
    "broker_ref",
    "broker_epoch",
    "workspace_state_digest",
    "session_binding_digest",
    "session_nucleus_hash",
    "source_graph_hash",
    "expected_state_revision",
    "expected_state_digest",
    "prior_inventory_digest",
    "inventory_digest",
    "inventory",
    "issued_at",
    "not_before",
    "expires_at",
    ...CLOCK_FIELDS,
    ...SIGNER_FIELDS,
  ]);
  if (input.version !== RESOURCE_RESERVATION_ATTESTATION_VERSION) {
    throw new Error(`${label}.version must be ${RESOURCE_RESERVATION_ATTESTATION_VERSION}`);
  }
  const inventory = normalizePhysicalResourceInventory(input.inventory, `${label}.inventory`);
  const inventoryDigest = assertDigest(input.inventory_digest, `${label}.inventory_digest`);
  if (inventoryDigest !== inventory.inventory_digest) {
    throw new Error(`${label}.inventory_digest does not bind inventory`);
  }
  const issuedAt = assertTimestamp(input.issued_at, `${label}.issued_at`);
  const notBefore = assertTimestamp(input.not_before, `${label}.not_before`);
  const expiresAt = assertTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(notBefore) > Date.parse(issuedAt)
      || Date.parse(expiresAt) <= Date.parse(issuedAt)
      || Date.parse(expiresAt) - Date.parse(notBefore) > MAX_ATTESTATION_VALIDITY_MS) {
    throw new Error(`${label} has an invalid validity window`);
  }
  if (issuedAt !== inventory.captured_at || notBefore !== inventory.valid_from
      || expiresAt !== inventory.expires_at) {
    throw new Error(`${label} validity does not exactly bind the inventory observation`);
  }
  const value = {
    version: RESOURCE_RESERVATION_ATTESTATION_VERSION,
    inventory_authority_id: assertToken(input.inventory_authority_id, `${label}.inventory_authority_id`),
    attestation_generation: assertInteger(input.attestation_generation, `${label}.attestation_generation`, 1),
    prior_attestation_digest: assertNullableDigest(input.prior_attestation_digest, `${label}.prior_attestation_digest`),
    reservation_authority_digest: assertDigest(input.reservation_authority_digest, `${label}.reservation_authority_digest`),
    state_domain_digest: assertDigest(input.state_domain_digest, `${label}.state_domain_digest`),
    broker_ref: normalizeOpaqueRef(input.broker_ref, `${label}.broker_ref`, { prefix: "broker" }),
    broker_epoch: assertInteger(input.broker_epoch, `${label}.broker_epoch`, 1),
    workspace_state_digest: assertDigest(input.workspace_state_digest, `${label}.workspace_state_digest`),
    session_binding_digest: assertDigest(input.session_binding_digest, `${label}.session_binding_digest`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    source_graph_hash: assertDigest(input.source_graph_hash, `${label}.source_graph_hash`),
    expected_state_revision: assertInteger(input.expected_state_revision, `${label}.expected_state_revision`, 0),
    expected_state_digest: assertDigest(input.expected_state_digest, `${label}.expected_state_digest`),
    prior_inventory_digest: assertDigest(input.prior_inventory_digest, `${label}.prior_inventory_digest`),
    inventory_digest: inventoryDigest,
    inventory,
    issued_at: issuedAt,
    not_before: notBefore,
    expires_at: expiresAt,
    ...normalizeClockBinding(input, label),
    ...normalizeSignerBinding(input, label, "inventory_authority_id"),
  };
  if (value.workspace_state_digest !== physicalResourceWorkspaceStateDigest(inventory)) {
    throw new Error(`${label}.workspace_state_digest does not bind inventory workspace state`);
  }
  return deepFreeze(value);
}

function normalizeCheckpointPayload(input, label) {
  assertClosedObject(input, label, [
    "version",
    "checkpoint_authority_id",
    "checkpoint_generation",
    "prior_checkpoint_digest",
    "reservation_authority_digest",
    "state_domain_digest",
    "broker_ref",
    "broker_epoch",
    "workspace_state_digest",
    "session_binding_digest",
    "session_nucleus_hash",
    "source_graph_hash",
    "state_revision",
    "state_digest",
    "prior_state_revision",
    "prior_state_digest",
    "inventory_generation",
    "inventory_digest",
    "inventory_attestation_generation",
    "inventory_attestation_digest",
    "inventory_attestation_prior_digest",
    "inventory_attestation_state_revision",
    "inventory_attestation_state_digest",
    "inventory_attestation_prior_inventory_digest",
    "attested_inventory_digest",
    "compaction_generation",
    "compaction_history_accumulator",
    "compaction_prior_accumulator",
    "compaction_source_checkpoint_generation",
    "compaction_source_checkpoint_digest",
    "compaction_source_state_revision",
    "compaction_source_state_digest",
    "compaction_batch_record_digests",
    "compaction_tombstone_set_digest",
    "compacted_record_count",
    "reservation_tombstone_count",
    "reservation_tombstone_digests",
    "compacted_source_record_digests",
    "reservation_history_digest",
    "terminal_history_digest",
    "reservation_request_digests",
    "terminal_receipt_digests",
    "terminal_record_digests",
    "issued_at",
    "not_before",
    "expires_at",
    ...CLOCK_FIELDS,
    ...SIGNER_FIELDS,
  ]);
  if (input.version !== RESOURCE_RESERVATION_ATTESTATION_VERSION) {
    throw new Error(`${label}.version must be ${RESOURCE_RESERVATION_ATTESTATION_VERSION}`);
  }
  const stateRevision = assertInteger(input.state_revision, `${label}.state_revision`, 0);
  const priorStateRevision = assertNullableRevision(input.prior_state_revision, `${label}.prior_state_revision`);
  const priorStateDigest = assertNullableDigest(input.prior_state_digest, `${label}.prior_state_digest`);
  if (stateRevision === 0) {
    if (priorStateRevision !== null || priorStateDigest !== null) {
      throw new Error(`${label} genesis cannot claim prior state ancestry`);
    }
  } else if (priorStateRevision !== stateRevision - 1 || priorStateDigest === null) {
    throw new Error(`${label} must bind the immediate prior state revision and digest`);
  }
  const checkpointGeneration = assertInteger(input.checkpoint_generation, `${label}.checkpoint_generation`, 1);
  const priorCheckpointDigest = assertNullableDigest(input.prior_checkpoint_digest, `${label}.prior_checkpoint_digest`);
  if ((checkpointGeneration === 1) !== (priorCheckpointDigest === null)) {
    throw new Error(`${label} prior checkpoint digest does not match checkpoint generation`);
  }
  if (checkpointGeneration !== stateRevision + 1) {
    throw new Error(`${label} checkpoint generation must exactly track durable state revision`);
  }
  const inventoryAttestationGeneration = assertInteger(
    input.inventory_attestation_generation,
    `${label}.inventory_attestation_generation`,
    0,
  );
  const inventoryAttestationDigest = assertNullableDigest(
    input.inventory_attestation_digest,
    `${label}.inventory_attestation_digest`,
  );
  const inventoryAttestationPriorDigest = assertNullableDigest(
    input.inventory_attestation_prior_digest,
    `${label}.inventory_attestation_prior_digest`,
  );
  const inventoryAttestationStateRevision = assertNullableRevision(
    input.inventory_attestation_state_revision,
    `${label}.inventory_attestation_state_revision`,
  );
  const inventoryAttestationStateDigest = assertNullableDigest(
    input.inventory_attestation_state_digest,
    `${label}.inventory_attestation_state_digest`,
  );
  const inventoryAttestationPriorInventoryDigest = assertNullableDigest(
    input.inventory_attestation_prior_inventory_digest,
    `${label}.inventory_attestation_prior_inventory_digest`,
  );
  const attestedInventoryDigest = assertNullableDigest(
    input.attested_inventory_digest,
    `${label}.attested_inventory_digest`,
  );
  const hasNoInventoryAttestation = inventoryAttestationGeneration === 0;
  if (hasNoInventoryAttestation !== (inventoryAttestationDigest === null)
      || hasNoInventoryAttestation !== (inventoryAttestationStateRevision === null)
      || hasNoInventoryAttestation !== (inventoryAttestationStateDigest === null)
      || hasNoInventoryAttestation !== (inventoryAttestationPriorInventoryDigest === null)
      || hasNoInventoryAttestation !== (attestedInventoryDigest === null)
      || ((inventoryAttestationGeneration <= 1)
        !== (inventoryAttestationPriorDigest === null))) {
    throw new Error(`${label} inventory attestation lineage is incomplete`);
  }
  const compactionGeneration = assertInteger(
    input.compaction_generation,
    `${label}.compaction_generation`,
    0,
  );
  const compactionHistoryAccumulator = assertNullableDigest(
    input.compaction_history_accumulator,
    `${label}.compaction_history_accumulator`,
  );
  const compactionPriorAccumulator = assertNullableDigest(
    input.compaction_prior_accumulator,
    `${label}.compaction_prior_accumulator`,
  );
  const compactionSourceCheckpointGeneration = assertNullableRevision(
    input.compaction_source_checkpoint_generation,
    `${label}.compaction_source_checkpoint_generation`,
  );
  const compactionSourceCheckpointDigest = assertNullableDigest(
    input.compaction_source_checkpoint_digest,
    `${label}.compaction_source_checkpoint_digest`,
  );
  const compactionSourceStateRevision = assertNullableRevision(
    input.compaction_source_state_revision,
    `${label}.compaction_source_state_revision`,
  );
  const compactionSourceStateDigest = assertNullableDigest(
    input.compaction_source_state_digest,
    `${label}.compaction_source_state_digest`,
  );
  const compactionBatchRecordDigests = normalizeSortedDigestArray(
    input.compaction_batch_record_digests,
    `${label}.compaction_batch_record_digests`,
  );
  const compactionTombstoneSetDigest = assertNullableDigest(
    input.compaction_tombstone_set_digest,
    `${label}.compaction_tombstone_set_digest`,
  );
  const compactedRecordCount = assertInteger(
    input.compacted_record_count,
    `${label}.compacted_record_count`,
    0,
  );
  const reservationTombstoneCount = assertInteger(
    input.reservation_tombstone_count,
    `${label}.reservation_tombstone_count`,
    0,
    MAX_RESERVATION_CHECKPOINT_TOMBSTONE_DIGESTS,
  );
  const reservationTombstoneDigests = normalizeSortedDigestArray(
    input.reservation_tombstone_digests,
    `${label}.reservation_tombstone_digests`,
    MAX_RESERVATION_CHECKPOINT_TOMBSTONE_DIGESTS,
  );
  const compactedSourceRecordDigests = normalizeSortedDigestArray(
    input.compacted_source_record_digests,
    `${label}.compacted_source_record_digests`,
    MAX_RESERVATION_CHECKPOINT_TOMBSTONE_DIGESTS,
  );
  if (reservationTombstoneDigests.length !== reservationTombstoneCount
      || compactedSourceRecordDigests.length !== compactedRecordCount) {
    throw new Error(`${label} compacted member digests do not match tombstone counts`);
  }
  const hasNoCompaction = compactionGeneration === 0;
  if (hasNoCompaction) {
    if (compactionHistoryAccumulator !== null
        || compactionPriorAccumulator !== null
        || compactionSourceCheckpointGeneration !== null
        || compactionSourceCheckpointDigest !== null
        || compactionSourceStateRevision !== null
        || compactionSourceStateDigest !== null
        || compactionBatchRecordDigests.length !== 0
        || compactionTombstoneSetDigest !== null
        || compactedRecordCount !== 0
        || reservationTombstoneCount !== 0) {
      throw new Error(`${label} compaction genesis is inconsistent`);
    }
  } else if (compactionHistoryAccumulator === null
      || (compactionGeneration === 1) !== (compactionPriorAccumulator === null)
      || compactionSourceCheckpointGeneration === null
      || compactionSourceCheckpointGeneration < 1
      || compactionSourceCheckpointDigest === null
      || compactionSourceStateRevision === null
      || compactionSourceStateDigest === null
      || compactionBatchRecordDigests.length === 0
      || compactionTombstoneSetDigest === null
      || compactedRecordCount !== reservationTombstoneCount
      || compactionSourceCheckpointGeneration !== compactionSourceStateRevision + 1
      || compactionSourceStateRevision >= stateRevision) {
    throw new Error(`${label} compaction lineage is incomplete`);
  } else if (compactionHistoryAccumulator
      !== physicalResourceReservationCompactionAccumulatorDigest({
        compaction_generation: compactionGeneration,
        prior_accumulator: compactionPriorAccumulator,
        compacted_record_digests: compactionBatchRecordDigests,
        source_checkpoint_generation: compactionSourceCheckpointGeneration,
        source_checkpoint_digest: compactionSourceCheckpointDigest,
        source_state_revision: compactionSourceStateRevision,
        source_state_digest: compactionSourceStateDigest,
        tombstone_set_digest: compactionTombstoneSetDigest,
        tombstone_count: reservationTombstoneCount,
        compacted_record_count: compactedRecordCount,
      })) {
    throw new Error(`${label} compaction accumulator is invalid`);
  }
  const issuedAt = assertTimestamp(input.issued_at, `${label}.issued_at`);
  const notBefore = assertTimestamp(input.not_before, `${label}.not_before`);
  const expiresAt = assertTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(notBefore) > Date.parse(issuedAt)
      || Date.parse(expiresAt) <= Date.parse(issuedAt)
      || Date.parse(expiresAt) - Date.parse(notBefore) > MAX_ATTESTATION_VALIDITY_MS) {
    throw new Error(`${label} has an invalid validity window`);
  }
  return deepFreeze({
    version: RESOURCE_RESERVATION_ATTESTATION_VERSION,
    checkpoint_authority_id: assertToken(input.checkpoint_authority_id, `${label}.checkpoint_authority_id`),
    checkpoint_generation: checkpointGeneration,
    prior_checkpoint_digest: priorCheckpointDigest,
    reservation_authority_digest: assertDigest(input.reservation_authority_digest, `${label}.reservation_authority_digest`),
    state_domain_digest: assertDigest(input.state_domain_digest, `${label}.state_domain_digest`),
    broker_ref: normalizeOpaqueRef(input.broker_ref, `${label}.broker_ref`, { prefix: "broker" }),
    broker_epoch: assertInteger(input.broker_epoch, `${label}.broker_epoch`, 1),
    workspace_state_digest: assertDigest(input.workspace_state_digest, `${label}.workspace_state_digest`),
    session_binding_digest: assertDigest(input.session_binding_digest, `${label}.session_binding_digest`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    source_graph_hash: assertDigest(input.source_graph_hash, `${label}.source_graph_hash`),
    state_revision: stateRevision,
    state_digest: assertDigest(input.state_digest, `${label}.state_digest`),
    prior_state_revision: priorStateRevision,
    prior_state_digest: priorStateDigest,
    inventory_generation: assertInteger(input.inventory_generation, `${label}.inventory_generation`, 1),
    inventory_digest: assertDigest(input.inventory_digest, `${label}.inventory_digest`),
    inventory_attestation_generation: inventoryAttestationGeneration,
    inventory_attestation_digest: inventoryAttestationDigest,
    inventory_attestation_prior_digest: inventoryAttestationPriorDigest,
    inventory_attestation_state_revision: inventoryAttestationStateRevision,
    inventory_attestation_state_digest: inventoryAttestationStateDigest,
    inventory_attestation_prior_inventory_digest: inventoryAttestationPriorInventoryDigest,
    attested_inventory_digest: attestedInventoryDigest,
    compaction_generation: compactionGeneration,
    compaction_history_accumulator: compactionHistoryAccumulator,
    compaction_prior_accumulator: compactionPriorAccumulator,
    compaction_source_checkpoint_generation: compactionSourceCheckpointGeneration,
    compaction_source_checkpoint_digest: compactionSourceCheckpointDigest,
    compaction_source_state_revision: compactionSourceStateRevision,
    compaction_source_state_digest: compactionSourceStateDigest,
    compaction_batch_record_digests: compactionBatchRecordDigests,
    compaction_tombstone_set_digest: compactionTombstoneSetDigest,
    compacted_record_count: compactedRecordCount,
    reservation_tombstone_count: reservationTombstoneCount,
    reservation_tombstone_digests: reservationTombstoneDigests,
    compacted_source_record_digests: compactedSourceRecordDigests,
    reservation_history_digest: assertDigest(input.reservation_history_digest, `${label}.reservation_history_digest`),
    terminal_history_digest: assertDigest(input.terminal_history_digest, `${label}.terminal_history_digest`),
    reservation_request_digests: normalizeSortedDigestArray(
      input.reservation_request_digests,
      `${label}.reservation_request_digests`,
      MAX_RESERVATION_CHECKPOINT_HISTORY_DIGESTS,
    ),
    terminal_receipt_digests: normalizeSortedDigestArray(
      input.terminal_receipt_digests,
      `${label}.terminal_receipt_digests`,
      MAX_RESERVATION_CHECKPOINT_HISTORY_DIGESTS,
    ),
    terminal_record_digests: normalizeSortedDigestArray(
      input.terminal_record_digests,
      `${label}.terminal_record_digests`,
      MAX_RESERVATION_CHECKPOINT_HISTORY_DIGESTS,
    ),
    issued_at: issuedAt,
    not_before: notBefore,
    expires_at: expiresAt,
    ...normalizeClockBinding(input, label),
    ...normalizeSignerBinding(input, label, "checkpoint_authority_id"),
  });
}

function normalizeSignedEnvelope(input, label, domain, normalizePayload) {
  assertCanonicalDataTree(input, label);
  assertClosedObject(input, label, [
    "version",
    "domain",
    "payload",
    "payload_digest",
    "scheme",
    "signature",
    "signed_document_digest",
  ]);
  if (input.version !== RESOURCE_RESERVATION_ATTESTATION_VERSION
      || input.domain !== domain || input.scheme !== "ed25519") {
    throw new Error(`${label} domain, version, or signature scheme is invalid`);
  }
  const payload = normalizePayload(input.payload, `${label}.payload`);
  const payloadDigest = assertDigest(input.payload_digest, `${label}.payload_digest`);
  if (payloadDigest !== hashCanonicalJson(payload)) {
    throw new Error(`${label}.payload_digest does not bind canonical payload`);
  }
  const basis = {
    version: RESOURCE_RESERVATION_ATTESTATION_VERSION,
    domain,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature: assertSignature(input.signature, `${label}.signature`),
  };
  const signedDocumentDigest = assertDigest(input.signed_document_digest, `${label}.signed_document_digest`);
  if (signedDocumentDigest !== hashCanonicalJson(basis)) {
    throw new Error(`${label}.signed_document_digest is invalid`);
  }
  return deepFreeze({ ...basis, signed_document_digest: signedDocumentDigest });
}

function normalizeSignedPhysicalResourceInventoryAttestation(
  input,
  label = "signed_physical_resource_inventory_attestation",
) {
  return normalizeSignedEnvelope(
    input,
    label,
    RESOURCE_INVENTORY_ATTESTATION_DOMAIN,
    normalizeInventoryPayload,
  );
}

function normalizeSignedPhysicalResourceReservationCheckpoint(
  input,
  label = "signed_physical_resource_reservation_checkpoint",
) {
  return normalizeSignedEnvelope(
    input,
    label,
    RESOURCE_RESERVATION_CHECKPOINT_DOMAIN,
    normalizeCheckpointPayload,
  );
}

function assertSynchronousResult(value, label) {
  let then;
  try {
    then = value != null && (typeof value === "object" || typeof value === "function")
      ? value.then
      : undefined;
  } catch (cause) {
    throw new Error(`${label} returned a hostile thenable`, { cause });
  }
  if (typeof then === "function") throw new Error(`${label} must be synchronous`);
  return value;
}

function createTrustPort(input, label, contract, authorityField, ports, privatePorts) {
  assertClosedObject(input, label, ["port_id", authorityField, "resolve_current_trust"]);
  if (typeof input.resolve_current_trust !== "function") {
    throw new Error(`${label}.resolve_current_trust must be synchronous`);
  }
  const port = deepFreeze({
    version: RESOURCE_RESERVATION_ATTESTATION_VERSION,
    port_id: assertIdentifier(input.port_id, `${label}.port_id`),
    [authorityField]: assertToken(input[authorityField], `${label}.${authorityField}`),
    contract,
    trust_assurance: "caller_asserted_callback_unattested",
  });
  ports.add(port);
  privatePorts.set(port, Object.freeze({ resolve_current_trust: input.resolve_current_trust }));
  return port;
}

function createPhysicalResourceInventoryTrustPort(input = {}) {
  return createTrustPort(
    input,
    "physical_resource_inventory_trust_port",
    RESOURCE_INVENTORY_TRUST_PORT_CONTRACT,
    "inventory_authority_id",
    INVENTORY_TRUST_PORTS,
    INVENTORY_TRUST_PRIVATE,
  );
}

function createPhysicalResourceReservationCheckpointTrustPort(input = {}) {
  return createTrustPort(
    input,
    "physical_resource_reservation_checkpoint_trust_port",
    RESOURCE_CHECKPOINT_TRUST_PORT_CONTRACT,
    "checkpoint_authority_id",
    CHECKPOINT_TRUST_PORTS,
    CHECKPOINT_TRUST_PRIVATE,
  );
}

function assertPhysicalResourceInventoryTrustPort(port) {
  if (!port || !Object.isFrozen(port) || !INVENTORY_TRUST_PORTS.has(port)
      || !INVENTORY_TRUST_PRIVATE.has(port)) {
    throw new Error("physical resource inventory trust port must be created by Bob's private factory");
  }
  return port;
}

function assertPhysicalResourceReservationCheckpointTrustPort(port) {
  if (!port || !Object.isFrozen(port) || !CHECKPOINT_TRUST_PORTS.has(port)
      || !CHECKPOINT_TRUST_PRIVATE.has(port)) {
    throw new Error("physical resource reservation checkpoint trust port must be created by Bob's private factory");
  }
  return port;
}

function callTrust(port, privatePorts, query, label) {
  if (ACTIVE_TRUST_CALLBACKS.has(port)) throw new Error(`${label} cannot re-enter its trust port`);
  ACTIVE_TRUST_CALLBACKS.add(port);
  try {
    return assertSynchronousResult(
      privatePorts.get(port).resolve_current_trust(deepFreeze(query)),
      `${label}.resolve_current_trust`,
    );
  } finally {
    ACTIVE_TRUST_CALLBACKS.delete(port);
  }
}

function normalizeSignerTrust(input, label, authorityField, extraFields = []) {
  assertClosedObject(input, label, [
    "version",
    "trusted",
    "revoked",
    authorityField,
    "trust_root_epoch",
    "authority_epoch",
    "revocation_generation",
    "signer_key_id",
    "signer_public_key_digest",
    "public_key",
    ...extraFields,
  ]);
  if (input.version !== RESOURCE_RESERVATION_ATTESTATION_VERSION
      || typeof input.trusted !== "boolean" || typeof input.revoked !== "boolean") {
    throw new Error(`${label} version/trust disposition is invalid`);
  }
  const publicKey = assertEd25519PublicKey(input.public_key, `${label}.public_key`);
  const keyDigest = physicalResourceAttestationPublicKeyDigest(publicKey);
  if (assertDigest(input.signer_public_key_digest, `${label}.signer_public_key_digest`) !== keyDigest) {
    throw new Error(`${label}.signer_public_key_digest does not bind public_key`);
  }
  return {
    version: RESOURCE_RESERVATION_ATTESTATION_VERSION,
    trusted: input.trusted,
    revoked: input.revoked,
    [authorityField]: assertToken(input[authorityField], `${label}.${authorityField}`),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: assertInteger(input.revocation_generation, `${label}.revocation_generation`, 0),
    signer_key_id: assertToken(input.signer_key_id, `${label}.signer_key_id`),
    signer_public_key_digest: keyDigest,
    public_key: publicKey,
  };
}

function assertLiveClockBinding(payload, sample, label) {
  assertPhysicalTrustedClockSample(sample);
  const exact = {
    clock_id: sample.clock_id,
    monotonic_epoch_id: sample.monotonic_epoch_id,
    clock_mapping_generation: sample.mapping_generation,
    signed_clock_mapping_digest: sample.signed_mapping_digest,
    clock_trust_root_epoch: sample.trust_root_epoch,
    clock_authority_epoch: sample.authority_epoch,
    clock_revocation_generation: sample.revocation_generation,
  };
  for (const [field, value] of Object.entries(exact)) {
    if (payload[field] !== value) throw new Error(`${label}.${field} is not current`);
  }
  if (Date.parse(payload.issued_at) > Date.parse(sample.trusted_utc_earliest)) {
    throw new Error(`${label}.issued_at is in the future under trusted clock uncertainty`);
  }
  if (Date.parse(sample.trusted_utc_earliest) < Date.parse(payload.not_before)
      || Date.parse(sample.trusted_utc_latest) >= Date.parse(payload.expires_at)) {
    throw new Error(`${label} is stale, not yet valid, or expired under trusted clock uncertainty`);
  }
}

function assertHistoricalClockBinding(payload, sample, label) {
  assertPhysicalTrustedClockSample(sample);
  if (Date.parse(payload.issued_at) > Date.parse(sample.trusted_utc_earliest)) {
    throw new Error(`${label}.issued_at is in the future under trusted clock uncertainty`);
  }
  for (const [payloadField, sampleField] of [
    ["clock_trust_root_epoch", "trust_root_epoch"],
    ["clock_authority_epoch", "authority_epoch"],
    ["clock_revocation_generation", "revocation_generation"],
  ]) {
    if (payload[payloadField] > sample[sampleField]) {
      throw new Error(`${label}.${payloadField} is ahead of current trusted clock state`);
    }
  }
  if (payload.clock_id === sample.clock_id
      && payload.monotonic_epoch_id === sample.monotonic_epoch_id) {
    if (payload.clock_mapping_generation > sample.mapping_generation) {
      throw new Error(`${label}.clock_mapping_generation is ahead of current trusted clock state`);
    }
    if (payload.clock_mapping_generation === sample.mapping_generation
        && payload.signed_clock_mapping_digest !== sample.signed_mapping_digest) {
      throw new Error(`${label} clock mapping forked at the current generation`);
    }
  }
}

function isSubset(prior, next) {
  const nextSet = new Set(next);
  return prior.every((value) => nextSet.has(value));
}

function assertCheckpointLinkMonotonic(priorDocument, nextDocument) {
  const prior = priorDocument.payload;
  const next = nextDocument.payload;
  if (next.checkpoint_generation !== prior.checkpoint_generation + 1
      || next.prior_checkpoint_digest !== priorDocument.signed_document_digest
      || next.state_revision !== prior.state_revision + 1
      || next.prior_state_revision !== prior.state_revision
      || next.prior_state_digest !== prior.state_digest) {
    throw new Error("signed physical resource checkpoint chain has non-contiguous ancestry");
  }
  for (const field of ["issued_at", "not_before", "expires_at"]) {
    if (Date.parse(next[field]) < Date.parse(prior[field])) {
      throw new Error(`signed physical resource checkpoint ${field} moved backwards`);
    }
  }
  for (const field of [
    "clock_trust_root_epoch",
    "clock_authority_epoch",
    "clock_revocation_generation",
    "trust_root_epoch",
    "authority_epoch",
    "revocation_generation",
  ]) {
    if (next[field] < prior[field]) {
      throw new Error(`signed physical resource checkpoint ${field} moved backwards`);
    }
  }
  const sameMonotonicEpoch = next.clock_id === prior.clock_id
    && next.monotonic_epoch_id === prior.monotonic_epoch_id;
  if (sameMonotonicEpoch) {
    if (next.clock_mapping_generation < prior.clock_mapping_generation) {
      throw new Error("signed physical resource checkpoint clock mapping generation moved backwards");
    }
    if (next.clock_mapping_generation === prior.clock_mapping_generation
        && next.signed_clock_mapping_digest !== prior.signed_clock_mapping_digest) {
      throw new Error("signed physical resource checkpoint clock mapping forked at one generation");
    }
  } else if (next.clock_trust_root_epoch === prior.clock_trust_root_epoch
      && next.clock_authority_epoch === prior.clock_authority_epoch
      && next.clock_revocation_generation === prior.clock_revocation_generation) {
    throw new Error("signed physical resource checkpoint clock epoch changed without a trust epoch advance");
  }
  const signerChanged = next.signer_key_id !== prior.signer_key_id
    || next.signer_public_key_digest !== prior.signer_public_key_digest;
  if (signerChanged
      && next.trust_root_epoch === prior.trust_root_epoch
      && next.authority_epoch === prior.authority_epoch
      && next.revocation_generation === prior.revocation_generation) {
    throw new Error("signed physical resource checkpoint signer changed without an epoch advance");
  }
  if (next.inventory_generation < prior.inventory_generation
      || next.inventory_generation > prior.inventory_generation + 1) {
    throw new Error("signed physical resource checkpoint inventory generation is not monotonic");
  }
  if (next.inventory_generation === prior.inventory_generation
      && (next.inventory_digest !== prior.inventory_digest
        || next.workspace_state_digest !== prior.workspace_state_digest)) {
    throw new Error("signed physical resource checkpoint inventory forked at one generation");
  }
  if (next.inventory_attestation_generation < prior.inventory_attestation_generation
      || next.inventory_attestation_generation > prior.inventory_attestation_generation + 1) {
    throw new Error("signed physical resource checkpoint inventory attestation generation is not monotonic");
  }
  if (next.inventory_attestation_generation === prior.inventory_attestation_generation) {
    if ([
      "inventory_attestation_digest",
      "inventory_attestation_prior_digest",
      "inventory_attestation_state_revision",
      "inventory_attestation_state_digest",
      "inventory_attestation_prior_inventory_digest",
      "attested_inventory_digest",
    ].some((field) => next[field] !== prior[field])) {
      throw new Error("signed physical resource checkpoint inventory attestation forked at one generation");
    }
  } else if (next.inventory_attestation_digest === null
      || next.inventory_attestation_digest === prior.inventory_attestation_digest
      || next.inventory_attestation_prior_digest !== prior.inventory_attestation_digest
      || next.inventory_attestation_state_revision !== prior.state_revision
      || next.inventory_attestation_state_digest !== prior.state_digest
      || next.inventory_attestation_prior_inventory_digest !== prior.inventory_digest
      || next.attested_inventory_digest === null) {
    throw new Error("signed physical resource checkpoint inventory attestation advance is invalid");
  }
  const compactionStableFields = [
    "compaction_history_accumulator",
    "compaction_prior_accumulator",
    "compaction_source_checkpoint_generation",
    "compaction_source_checkpoint_digest",
    "compaction_source_state_revision",
    "compaction_source_state_digest",
    "compaction_batch_record_digests",
    "compaction_tombstone_set_digest",
    "compacted_record_count",
    "reservation_tombstone_count",
    "reservation_tombstone_digests",
    "compacted_source_record_digests",
  ];
  if (next.compaction_generation === prior.compaction_generation) {
    if (compactionStableFields.some((field) => {
      const left = prior[field];
      const right = next[field];
      return left != null && typeof left === "object"
        ? hashCanonicalJson(left) !== hashCanonicalJson(right)
        : left !== right;
    })) {
      throw new Error("signed physical resource checkpoint compaction history forked without an advance");
    }
  } else {
    const priorTombstoneDigests = new Set(prior.reservation_tombstone_digests);
    const priorSourceRecordDigests = new Set(prior.compacted_source_record_digests);
    const newTombstoneDigests = next.reservation_tombstone_digests.filter(
      (digest) => !priorTombstoneDigests.has(digest),
    );
    const newSourceRecordDigests = next.compacted_source_record_digests.filter(
      (digest) => !priorSourceRecordDigests.has(digest),
    );
    const priorTerminalRecordDigests = new Set(prior.terminal_record_digests);
    if (next.compaction_generation !== prior.compaction_generation + 1
        || next.compaction_prior_accumulator !== prior.compaction_history_accumulator
        || next.compaction_source_checkpoint_generation !== prior.checkpoint_generation
        || next.compaction_source_checkpoint_digest !== priorDocument.signed_document_digest
        || next.compaction_source_state_revision !== prior.state_revision
        || next.compaction_source_state_digest !== prior.state_digest
        || next.compacted_record_count - prior.compacted_record_count
          !== next.compaction_batch_record_digests.length
        || next.reservation_tombstone_count - prior.reservation_tombstone_count
          !== next.compaction_batch_record_digests.length
        || newTombstoneDigests.length !== next.compaction_batch_record_digests.length
        || hashCanonicalJson(newSourceRecordDigests)
          !== hashCanonicalJson(next.compaction_batch_record_digests)
        || newSourceRecordDigests.some((digest) => !priorTerminalRecordDigests.has(digest))
        || next.compaction_history_accumulator
          !== physicalResourceReservationCompactionAccumulatorDigest({
            compaction_generation: next.compaction_generation,
            prior_accumulator: next.compaction_prior_accumulator,
            compacted_record_digests: next.compaction_batch_record_digests,
            source_checkpoint_generation: next.compaction_source_checkpoint_generation,
            source_checkpoint_digest: next.compaction_source_checkpoint_digest,
            source_state_revision: next.compaction_source_state_revision,
            source_state_digest: next.compaction_source_state_digest,
            tombstone_set_digest: next.compaction_tombstone_set_digest,
            tombstone_count: next.reservation_tombstone_count,
            compacted_record_count: next.compacted_record_count,
          })) {
      throw new Error("signed physical resource checkpoint compaction advance is invalid");
    }
  }
  if (!isSubset(prior.reservation_tombstone_digests, next.reservation_tombstone_digests)
      || !isSubset(
        prior.compacted_source_record_digests,
        next.compacted_source_record_digests,
      )) {
    throw new Error("signed physical resource checkpoint deleted or rewrote compacted tombstone proof history");
  }
  if (!isSubset(prior.reservation_request_digests, next.reservation_request_digests)
      || !isSubset(prior.terminal_receipt_digests, next.terminal_receipt_digests)
      || !isSubset(prior.terminal_record_digests, next.terminal_record_digests)) {
    throw new Error("signed physical resource checkpoint deleted reservation or terminal proof history");
  }
}

function assertSignerMatchesPayload(payload, trust, authorityField, label) {
  if (!trust.trusted || trust.revoked) throw new Error(`${label} signer is not currently trusted`);
  for (const field of [authorityField, ...SIGNER_FIELDS]) {
    if (payload[field] !== trust[field]) throw new Error(`${label}.${field} is stale or belongs to another signer`);
  }
}

function verifySignature(document, trust, signingMessageFactory, label) {
  let valid = false;
  try {
    valid = crypto.verify(
      null,
      signingMessageFactory(document.payload_digest),
      trust.public_key,
      Buffer.from(document.signature, "base64url"),
    );
  } catch {
    valid = false;
  }
  if (!valid) throw new Error(`${label} signature is invalid`);
}

function assertExternalClockTransition(payload, sample, trust, label) {
  const anchoredClockBindingDigest = physicalResourceClockBindingDigest(payload);
  const currentClockBindingDigest = physicalResourceClockBindingDigest({
    clock_id: sample.clock_id,
    monotonic_epoch_id: sample.monotonic_epoch_id,
    clock_mapping_generation: sample.mapping_generation,
    signed_clock_mapping_digest: sample.signed_mapping_digest,
    clock_trust_root_epoch: sample.trust_root_epoch,
    clock_authority_epoch: sample.authority_epoch,
    clock_revocation_generation: sample.revocation_generation,
  });
  const clockEpochChanged = payload.clock_id !== sample.clock_id
    || payload.monotonic_epoch_id !== sample.monotonic_epoch_id;
  if ((clockEpochChanged && trust.clock_epoch_transition_generation < 1)
      || (!clockEpochChanged && trust.clock_epoch_transition_generation !== 0)
      || trust.anchored_clock_binding_digest !== anchoredClockBindingDigest
      || trust.current_clock_binding_digest !== currentClockBindingDigest
      || trust.clock_epoch_transition_digest !== physicalResourceClockEpochTransitionDigest({
        anchored_clock_binding_digest: anchoredClockBindingDigest,
        current_clock_binding_digest: currentClockBindingDigest,
        clock_epoch_transition_generation: trust.clock_epoch_transition_generation,
      })) {
    throw new Error(`${label} clock epoch transition is not externally anchored`);
  }
}

function verifySignedPhysicalResourceInventoryAttestation(input, options = {}) {
  assertClosedObject(options, "physical_resource_inventory_verification", [
    "trust_port",
    "trusted_clock_sample",
    "expected",
  ], ["historical"]);
  const port = assertPhysicalResourceInventoryTrustPort(options.trust_port);
  const document = normalizeSignedPhysicalResourceInventoryAttestation(input);
  const payload = document.payload;
  if (payload.inventory_authority_id !== port.inventory_authority_id) {
    throw new Error("signed physical resource inventory belongs to another inventory authority");
  }
  if (options.historical === true) {
    assertHistoricalClockBinding(
      payload,
      options.trusted_clock_sample,
      "signed physical resource inventory",
    );
  } else {
    assertLiveClockBinding(payload, options.trusted_clock_sample, "signed physical resource inventory");
  }
  assertClosedObject(options.expected, "physical_resource_inventory_expected_binding", [
    "reservation_authority_digest",
    "state_domain_digest",
    "broker_ref",
    "broker_epoch",
    "session_binding_digest",
    "session_nucleus_hash",
    "source_graph_hash",
    "expected_state_revision",
    "expected_state_digest",
    "prior_inventory_digest",
    "expected_inventory_generation",
    "expected_attestation_generation",
    "prior_attestation_digest",
  ]);
  const expected = {
    reservation_authority_digest: assertDigest(options.expected.reservation_authority_digest, "physical_resource_inventory_expected_binding.reservation_authority_digest"),
    state_domain_digest: assertDigest(options.expected.state_domain_digest, "physical_resource_inventory_expected_binding.state_domain_digest"),
    broker_ref: normalizeOpaqueRef(options.expected.broker_ref, "physical_resource_inventory_expected_binding.broker_ref", { prefix: "broker" }),
    broker_epoch: assertInteger(options.expected.broker_epoch, "physical_resource_inventory_expected_binding.broker_epoch", 1),
    session_binding_digest: assertDigest(options.expected.session_binding_digest, "physical_resource_inventory_expected_binding.session_binding_digest"),
    session_nucleus_hash: assertDigest(options.expected.session_nucleus_hash, "physical_resource_inventory_expected_binding.session_nucleus_hash"),
    source_graph_hash: assertDigest(options.expected.source_graph_hash, "physical_resource_inventory_expected_binding.source_graph_hash"),
    expected_state_revision: assertInteger(options.expected.expected_state_revision, "physical_resource_inventory_expected_binding.expected_state_revision", 0),
    expected_state_digest: assertDigest(options.expected.expected_state_digest, "physical_resource_inventory_expected_binding.expected_state_digest"),
    prior_inventory_digest: assertDigest(options.expected.prior_inventory_digest, "physical_resource_inventory_expected_binding.prior_inventory_digest"),
    inventory_generation: assertInteger(options.expected.expected_inventory_generation, "physical_resource_inventory_expected_binding.expected_inventory_generation", 1),
    attestation_generation: assertInteger(options.expected.expected_attestation_generation, "physical_resource_inventory_expected_binding.expected_attestation_generation", 1),
    prior_attestation_digest: assertNullableDigest(options.expected.prior_attestation_digest, "physical_resource_inventory_expected_binding.prior_attestation_digest"),
  };
  for (const [field, value] of Object.entries(expected)) {
    if (field === "inventory_generation") {
      if (payload.inventory.inventory_generation !== value) throw new Error("signed physical resource inventory generation is not the exact successor");
    } else if (payload[field] !== value) {
      throw new Error(`signed physical resource inventory ${field} binding drift`);
    }
  }
  const trustQuery = {
    version: RESOURCE_RESERVATION_ATTESTATION_VERSION,
    inventory_authority_id: payload.inventory_authority_id,
    attestation_generation: payload.attestation_generation,
    signed_attestation_digest: document.signed_document_digest,
    reservation_authority_digest: payload.reservation_authority_digest,
    state_domain_digest: payload.state_domain_digest,
    inventory_digest: payload.inventory_digest,
  };
  const rawTrust = callTrust(
    port,
    INVENTORY_TRUST_PRIVATE,
    trustQuery,
    "physical resource inventory trust",
  );
  assertClosedObject(rawTrust, "current_physical_resource_inventory_trust", [
    "version", "trusted", "revoked", "inventory_authority_id",
    "current_attestation_generation", "current_signed_attestation_digest",
    "anchored_clock_binding_digest", "current_clock_binding_digest",
    "clock_epoch_transition_generation", "clock_epoch_transition_digest",
    ...SIGNER_FIELDS, "public_key",
  ]);
  const trust = normalizeSignerTrust(
    rawTrust,
    "current_physical_resource_inventory_trust",
    "inventory_authority_id",
    [
      "current_attestation_generation",
      "current_signed_attestation_digest",
      "anchored_clock_binding_digest",
      "current_clock_binding_digest",
      "clock_epoch_transition_generation",
      "clock_epoch_transition_digest",
    ],
  );
  trust.current_attestation_generation = assertInteger(
    rawTrust.current_attestation_generation,
    "current_physical_resource_inventory_trust.current_attestation_generation",
    1,
  );
  trust.current_signed_attestation_digest = assertDigest(
    rawTrust.current_signed_attestation_digest,
    "current_physical_resource_inventory_trust.current_signed_attestation_digest",
  );
  for (const field of [
    "anchored_clock_binding_digest",
    "current_clock_binding_digest",
    "clock_epoch_transition_digest",
  ]) {
    trust[field] = assertDigest(rawTrust[field], `current_physical_resource_inventory_trust.${field}`);
  }
  trust.clock_epoch_transition_generation = assertInteger(
    rawTrust.clock_epoch_transition_generation,
    "current_physical_resource_inventory_trust.clock_epoch_transition_generation",
    0,
  );
  assertSignerMatchesPayload(payload, trust, "inventory_authority_id", "signed physical resource inventory");
  if (trust.current_attestation_generation !== payload.attestation_generation
      || trust.current_signed_attestation_digest !== document.signed_document_digest) {
    throw new Error("signed physical resource inventory is not the authority's exact current attestation");
  }
  verifySignature(document, trust, physicalResourceInventoryAttestationSigningMessage, "signed physical resource inventory");
  assertExternalClockTransition(
    payload,
    options.trusted_clock_sample,
    trust,
    "signed physical resource inventory",
  );
  return document;
}

function checkpointStateBindings(state) {
  const terminal = state.reservations.filter((record) => !["held", "cleanup_pending"].includes(record.receipt.state));
  const tombstones = state.reservation_tombstones;
  return deepFreeze({
    state_revision: state.revision,
    state_digest: state.state_digest,
    prior_state_revision: state.revision === 0 ? null : state.revision - 1,
    prior_state_digest: state.prior_state_digest,
    inventory_generation: state.inventory.inventory_generation,
    inventory_digest: state.inventory.inventory_digest,
    inventory_attestation_generation: state.inventory_attestation_generation,
    inventory_attestation_digest: state.inventory_attestation_digest,
    inventory_attestation_prior_digest: state.inventory_attestation_prior_digest,
    inventory_attestation_state_revision: state.inventory_attestation_state_revision,
    inventory_attestation_state_digest: state.inventory_attestation_state_digest,
    inventory_attestation_prior_inventory_digest:
      state.inventory_attestation_prior_inventory_digest,
    attested_inventory_digest: state.attested_inventory == null
      ? null
      : state.attested_inventory.inventory_digest,
    compaction_generation: state.compaction_generation,
    compaction_history_accumulator: state.compaction_history_accumulator,
    compaction_prior_accumulator: state.compaction_prior_accumulator,
    compaction_source_checkpoint_generation: state.compaction_source_checkpoint_generation,
    compaction_source_checkpoint_digest: state.compaction_source_checkpoint_digest,
    compaction_source_state_revision: state.compaction_source_state_revision,
    compaction_source_state_digest: state.compaction_source_state_digest,
    compaction_batch_record_digests: state.compaction_batch_record_digests,
    compaction_tombstone_set_digest: state.compaction_tombstone_set_digest,
    compacted_record_count: state.compacted_record_count,
    reservation_tombstone_count: tombstones.length,
    reservation_tombstone_digests: Object.freeze(tombstones
      .map((record) => record.tombstone_digest)
      .sort()),
    compacted_source_record_digests: Object.freeze(tombstones
      .map((record) => record.source_record_digest)
      .sort()),
    reservation_history_digest: hashCanonicalJson({
      full_records: state.reservations,
      tombstones,
    }),
    terminal_history_digest: hashCanonicalJson({
      full_records: terminal,
      tombstones,
    }),
    reservation_request_digests: Object.freeze([
      ...state.reservations.map((record) => record.request.reservation_request_digest),
      ...tombstones.map((record) => record.reservation_request_digest),
    ]
      .sort()),
    terminal_receipt_digests: Object.freeze([
      ...terminal.map((record) => record.receipt.receipt_digest),
      ...tombstones.map((record) => record.receipt.receipt_digest),
    ]
      .sort()),
    terminal_record_digests: Object.freeze([
      ...terminal.map((record) => hashCanonicalJson(record)),
      ...tombstones.map((record) => record.source_record_digest),
    ]
      .sort()),
    workspace_state_digest: physicalResourceWorkspaceStateDigest(state.inventory),
  });
}

function verifySignedPhysicalResourceReservationCheckpointChain(input, options = {}) {
  assertClosedObject(options, "physical_resource_reservation_checkpoint_verification", [
    "trust_port",
    "trusted_clock_sample",
    "expected",
  ]);
  const port = assertPhysicalResourceReservationCheckpointTrustPort(options.trust_port);
  assertDataArray(input, "signed_physical_resource_reservation_checkpoint_chain", 1, MAX_CHECKPOINT_CHAIN_LENGTH);
  const chain = input.map((entry, index) => normalizeSignedPhysicalResourceReservationCheckpoint(
    entry,
    `signed_physical_resource_reservation_checkpoint_chain[${index}]`,
  ));
  assertClosedObject(options.expected, "physical_resource_reservation_checkpoint_expected_binding", [
    "reservation_authority_digest",
    "state_domain_digest",
    "broker_ref",
    "broker_epoch",
    "session_binding_digest",
    "session_nucleus_hash",
    "source_graph_hash",
    "state",
  ]);
  const stateBindings = checkpointStateBindings(options.expected.state);
  const exact = {
    reservation_authority_digest: assertDigest(options.expected.reservation_authority_digest, "physical_resource_reservation_checkpoint_expected_binding.reservation_authority_digest"),
    state_domain_digest: assertDigest(options.expected.state_domain_digest, "physical_resource_reservation_checkpoint_expected_binding.state_domain_digest"),
    broker_ref: normalizeOpaqueRef(options.expected.broker_ref, "physical_resource_reservation_checkpoint_expected_binding.broker_ref", { prefix: "broker" }),
    broker_epoch: assertInteger(options.expected.broker_epoch, "physical_resource_reservation_checkpoint_expected_binding.broker_epoch", 1),
    session_binding_digest: assertDigest(options.expected.session_binding_digest, "physical_resource_reservation_checkpoint_expected_binding.session_binding_digest"),
    session_nucleus_hash: assertDigest(options.expected.session_nucleus_hash, "physical_resource_reservation_checkpoint_expected_binding.session_nucleus_hash"),
    source_graph_hash: assertDigest(options.expected.source_graph_hash, "physical_resource_reservation_checkpoint_expected_binding.source_graph_hash"),
  };
  for (let index = 0; index < chain.length; index += 1) {
    const document = chain[index];
    const payload = document.payload;
    if (payload.checkpoint_authority_id !== port.checkpoint_authority_id) {
      throw new Error("signed physical resource checkpoint belongs to another checkpoint authority");
    }
    for (const [field, value] of Object.entries(exact)) {
      if (payload[field] !== value) throw new Error(`signed physical resource checkpoint ${field} binding drift`);
    }
    assertHistoricalClockBinding(
      payload,
      options.trusted_clock_sample,
      "signed physical resource checkpoint",
    );
    if (index > 0) {
      const prior = chain[index - 1];
      assertCheckpointLinkMonotonic(prior, document);
    }
  }
  const first = chain[0];
  const last = chain[chain.length - 1];
  for (const [field, value] of Object.entries(stateBindings)) {
    const matches = value != null && typeof value === "object"
      ? hashCanonicalJson(last.payload[field]) === hashCanonicalJson(value)
      : last.payload[field] === value;
    if (!matches) {
      throw new Error(`signed physical resource checkpoint ${field} does not bind the durable state head`);
    }
  }
  const trustQuery = {
    version: RESOURCE_RESERVATION_ATTESTATION_VERSION,
    checkpoint_authority_id: last.payload.checkpoint_authority_id,
    reservation_authority_digest: exact.reservation_authority_digest,
    state_domain_digest: exact.state_domain_digest,
  };
  const rawTrust = callTrust(
    port,
    CHECKPOINT_TRUST_PRIVATE,
    trustQuery,
    "physical resource reservation checkpoint trust",
  );
  assertClosedObject(rawTrust, "current_physical_resource_checkpoint_trust", [
    "version", "trusted", "revoked", "checkpoint_authority_id",
    "anchor_checkpoint_generation", "anchor_signed_checkpoint_digest",
    "current_checkpoint_generation", "current_signed_checkpoint_digest",
    "anchored_clock_binding_digest", "current_clock_binding_digest",
    "clock_epoch_transition_generation", "clock_epoch_transition_digest",
    ...SIGNER_FIELDS, "public_key",
  ]);
  const trust = normalizeSignerTrust(
    rawTrust,
    "current_physical_resource_checkpoint_trust",
    "checkpoint_authority_id",
    [
      "anchor_checkpoint_generation",
      "anchor_signed_checkpoint_digest",
      "current_checkpoint_generation",
      "current_signed_checkpoint_digest",
      "anchored_clock_binding_digest",
      "current_clock_binding_digest",
      "clock_epoch_transition_generation",
      "clock_epoch_transition_digest",
    ],
  );
  for (const field of ["anchor_checkpoint_generation", "current_checkpoint_generation"]) {
    trust[field] = assertInteger(rawTrust[field], `current_physical_resource_checkpoint_trust.${field}`, 1);
  }
  for (const field of ["anchor_signed_checkpoint_digest", "current_signed_checkpoint_digest"]) {
    trust[field] = assertDigest(rawTrust[field], `current_physical_resource_checkpoint_trust.${field}`);
  }
  for (const field of [
    "anchored_clock_binding_digest",
    "current_clock_binding_digest",
    "clock_epoch_transition_digest",
  ]) {
    trust[field] = assertDigest(rawTrust[field], `current_physical_resource_checkpoint_trust.${field}`);
  }
  trust.clock_epoch_transition_generation = assertInteger(
    rawTrust.clock_epoch_transition_generation,
    "current_physical_resource_checkpoint_trust.clock_epoch_transition_generation",
    0,
  );
  assertSignerMatchesPayload(last.payload, trust, "checkpoint_authority_id", "signed physical resource checkpoint");
  if (trust.anchor_checkpoint_generation !== first.payload.checkpoint_generation
      || trust.anchor_signed_checkpoint_digest !== first.signed_document_digest
      || trust.current_checkpoint_generation !== last.payload.checkpoint_generation
      || trust.current_signed_checkpoint_digest !== last.signed_document_digest) {
    throw new Error("signed physical resource checkpoint chain does not match external monotonic anchors");
  }
  const anchoredClockBindingDigest = physicalResourceClockBindingDigest(last.payload);
  const sample = options.trusted_clock_sample;
  const currentClockBindingDigest = physicalResourceClockBindingDigest({
    clock_id: sample.clock_id,
    monotonic_epoch_id: sample.monotonic_epoch_id,
    clock_mapping_generation: sample.mapping_generation,
    signed_clock_mapping_digest: sample.signed_mapping_digest,
    clock_trust_root_epoch: sample.trust_root_epoch,
    clock_authority_epoch: sample.authority_epoch,
    clock_revocation_generation: sample.revocation_generation,
  });
  const clockEpochChanged = last.payload.clock_id !== sample.clock_id
    || last.payload.monotonic_epoch_id !== sample.monotonic_epoch_id;
  if ((clockEpochChanged && trust.clock_epoch_transition_generation < 1)
      || (!clockEpochChanged && trust.clock_epoch_transition_generation !== 0)
      || trust.anchored_clock_binding_digest !== anchoredClockBindingDigest
      || trust.current_clock_binding_digest !== currentClockBindingDigest
      || trust.clock_epoch_transition_digest !== physicalResourceClockEpochTransitionDigest({
        anchored_clock_binding_digest: anchoredClockBindingDigest,
        current_clock_binding_digest: currentClockBindingDigest,
        clock_epoch_transition_generation: trust.clock_epoch_transition_generation,
      })) {
    throw new Error("signed physical resource checkpoint clock epoch transition is not externally anchored");
  }
  // The external first anchor and the current head signature transitively bind
  // the normalized historical documents through prior_checkpoint_digest. Old
  // signatures may use rotated keys and old clock mappings; their trust is not
  // reconstructed from the one current trust response.
  verifySignature(last, trust, physicalResourceReservationCheckpointSigningMessage, "signed physical resource checkpoint");
  return deepFreeze({
    chain: Object.freeze(chain),
    anchor_checkpoint_generation: first.payload.checkpoint_generation,
    anchor_signed_checkpoint_digest: first.signed_document_digest,
    current_checkpoint_generation: last.payload.checkpoint_generation,
    current_signed_checkpoint_digest: last.signed_document_digest,
  });
}

module.exports = {
  MAX_ATTESTATION_VALIDITY_MS,
  MAX_CANONICAL_TREE_KEYS,
  MAX_CANONICAL_TREE_NODES,
  MAX_CHECKPOINT_CHAIN_LENGTH,
  MAX_COMPACTION_BATCH_RECORD_DIGESTS,
  MAX_RESERVATION_CHECKPOINT_HISTORY_DIGESTS,
  MAX_RESERVATION_CHECKPOINT_TOMBSTONE_DIGESTS,
  RESOURCE_CHECKPOINT_TRUST_PORT_CONTRACT,
  RESOURCE_CHECKPOINT_CLOCK_TRANSITION_CONTRACT,
  RESOURCE_INVENTORY_ATTESTATION_DOMAIN,
  RESOURCE_INVENTORY_ATTESTATION_SIGNING_DOMAIN,
  RESOURCE_INVENTORY_TRUST_PORT_CONTRACT,
  RESOURCE_RESERVATION_ATTESTATION_VERSION,
  RESOURCE_RESERVATION_CHECKPOINT_DOMAIN,
  RESOURCE_RESERVATION_CHECKPOINT_SIGNING_DOMAIN,
  RESOURCE_RESERVATION_COMPACTION_DOMAIN,
  assertPhysicalResourceInventoryTrustPort,
  assertPhysicalResourceReservationCheckpointTrustPort,
  checkpointStateBindings,
  createPhysicalResourceInventoryTrustPort,
  createPhysicalResourceReservationCheckpointTrustPort,
  normalizeSignedPhysicalResourceInventoryAttestation,
  normalizeSignedPhysicalResourceReservationCheckpoint,
  physicalResourceAttestationPublicKeyDigest,
  physicalResourceClockBindingDigest,
  physicalResourceClockEpochTransitionDigest,
  physicalResourceInventoryAttestationSigningMessage,
  physicalResourceReservationAuthorityDigest,
  physicalResourceReservationCompactionAccumulatorDigest,
  physicalResourceReservationCheckpointSigningMessage,
  physicalResourceSessionBindingDigest,
  physicalResourceWorkspaceStateDigest,
  verifySignedPhysicalResourceInventoryAttestation,
  verifySignedPhysicalResourceReservationCheckpointChain,
};
