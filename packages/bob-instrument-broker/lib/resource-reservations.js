"use strict";

// Plane-PH PH-S11 broker-private atomic resource reservations.
//
// This module deliberately is not an MCP tool. Public callers can present a
// resource-bound reservation request and receive a normalized receipt, but the
// inventory, allocation plan, CAS state, and raw resource fences stay behind
// privately branded broker ports. The callback-backed CAS port is an
// integration contract, not proof of process/host durability; readiness says
// that explicitly and never calls a caller callback to manufacture assurance.
// A live authority is also the sole accepted writer: only the exact successor
// it proposed to CAS may advance its revision floor. Restart recovery requires
// an exact externally anchored checkpoint plus the independently signed current
// external inventory observation. A checkpoint is an admission anchor, not a
// promise that later live mutations were already published outside this process.

const crypto = require("node:crypto");

const {
  PHYSICAL_RESERVATION_RECEIPT_VERSION,
  assertReservationBindings,
  normalizePhysicalReservationReceipt,
  normalizePhysicalReservationRequest,
  normalizePhysicalResourceBundle,
  projectPhysicalReservationState,
} = require("../../../mcp/lib/physical-resource-contract.js");
const {
  normalizePhysicalResourceInventory,
  planPhysicalResourceBundle,
} = require("../../../mcp/lib/physical-resource-scheduler.js");
const {
  assertPhysicalTrustedClockPort,
  samplePhysicalTrustedClock,
} = require("../../../mcp/lib/physical-trusted-clock.js");
const {
  normalizeOpaqueRef,
} = require("../../../mcp/lib/physical-quantities.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/lib/verification-contracts.js");
const {
  RESOURCE_CHECKPOINT_TRUST_PORT_CONTRACT,
  RESOURCE_INVENTORY_TRUST_PORT_CONTRACT,
  RESOURCE_RESERVATION_COMPACTION_DOMAIN,
  assertPhysicalResourceInventoryTrustPort,
  assertPhysicalResourceReservationCheckpointTrustPort,
  physicalResourceReservationAuthorityDigest,
  physicalResourceReservationCompactionAccumulatorDigest,
  physicalResourceSessionBindingDigest,
  normalizeSignedPhysicalResourceInventoryAttestation,
  verifySignedPhysicalResourceInventoryAttestation,
  verifySignedPhysicalResourceReservationCheckpointChain,
} = require("./resource-reservation-attestations.js");

const RESOURCE_RESERVATION_AUTHORITY_VERSION = 1;
const RESOURCE_RESERVATION_STATE_VERSION = 1;
const RESOURCE_RESERVATION_RECORD_VERSION = 1;
const RESOURCE_RESERVATION_TOMBSTONE_VERSION = 1;
const RESOURCE_RESERVATION_CREDENTIAL_VERSION = 1;
const RESOURCE_RESERVATION_ELIGIBILITY_VERSION = 1;
const RESOURCE_RESERVATION_STATE_PORT_CONTRACT =
  "external-linearizable-physical-resource-reservation-cas-v1";
const RESOURCE_BUNDLE_RESOLVER_CONTRACT = "exact-physical-resource-bundle-digest-resolver-v1";
// Shared reservations deliberately do not use classic "largest generation is
// the only valid token" semantics: a later compatible join would invalidate
// an older live holder. Generations remain strictly monotonic audit/fence
// epochs, while validity is the exact set of active durable record+token
// bindings. Provider seams must validate the branded credential against that
// set immediately before effect; they must not implement max-generation-only
// acceptance for shared resources.
const RESOURCE_FENCING_SEMANTICS = "broker-active-token-set-monotonic-generation-v1";
const RESOURCE_RESERVATION_COMPACTION_CONTRACT =
  "external-exact-checkpoint-proof-preserving-terminal-tombstones-v1";
const MAX_CAS_CONFLICT_RETRIES = 8;
const MAX_RESERVATIONS = 4_096;
const MAX_RESERVATION_TOMBSTONES = 16_384;
const RESERVATION_TOMBSTONE_SAFETY_RESERVE = 256;
const MAX_GENERAL_RESERVATION_TOMBSTONES =
  MAX_RESERVATION_TOMBSTONES - RESERVATION_TOMBSTONE_SAFETY_RESERVE;
const RAW_FENCE_BYTES = 32;

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;
const RAW_FENCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const EFFECT_STATE_VALUES = Object.freeze(["not_started", "started", "cleanup"]);
const ACTIVE_RECEIPT_STATES = new Set(["held", "cleanup_pending"]);

const STATE_PORTS = new WeakSet();
const STATE_PORT_PRIVATE = new WeakMap();
const BUNDLE_RESOLVER_PORTS = new WeakSet();
const BUNDLE_RESOLVER_PRIVATE = new WeakMap();
const AUTHORITIES = new WeakSet();
const AUTHORITY_PRIVATE = new WeakMap();
const CREDENTIALS = new WeakSet();
const CREDENTIAL_PRIVATE = new WeakMap();
const ELIGIBILITY_PORTS = new WeakSet();
const ELIGIBILITY_PRIVATE = new WeakMap();
const ACTIVE_STATE_PORT_CALLBACKS = new WeakSet();
const ACTIVE_BUNDLE_RESOLVERS = new WeakSet();

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

function assertDenseDataArray(value, label, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw new Error(`${label} must be an array with ${minimum}-${maximum} entries`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set(["length", ...Array.from({ length: value.length }, (_, index) => String(index))]);
  const unknown = keys.filter((key) => !allowed.has(key)).sort();
  if (unknown.length > 0) throw new Error(`${label} has adorned fields: ${unknown.join(", ")}`);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}[${index}] must be an enumerable data field (sparse/accessor arrays are forbidden)`);
    }
  }
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function compareCodeUnits(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
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

function reservationError(code, message, cause = null) {
  const error = new Error(message, cause == null ? undefined : { cause });
  Object.defineProperty(error, "code", { value: code, enumerable: true });
  return error;
}

function assertSyncResult(result, label) {
  if (result && (typeof result === "object" || typeof result === "function")) {
    let then;
    try {
      then = result.then;
    } catch (cause) {
      throw reservationError(
        "reservation_callback_contract_violation",
        `${label} returned a hostile thenable`,
        cause,
      );
    }
    if (typeof then === "function") {
      throw reservationError(
        "reservation_callback_contract_violation",
        `${label} must be synchronous`,
      );
    }
  }
  return result;
}

function createPhysicalResourceReservationStatePort(input = {}) {
  assertClosedObject(input, "physical_resource_reservation_state_port", [
    "port_id",
    "state_domain_digest",
    "read_state",
    "compare_and_set",
  ]);
  if (typeof input.read_state !== "function" || typeof input.compare_and_set !== "function") {
    throw new Error("physical resource reservation state port requires synchronous read_state and compare_and_set functions");
  }
  const port = deepFreeze({
    version: RESOURCE_RESERVATION_STATE_VERSION,
    port_id: assertIdentifier(input.port_id, "physical_resource_reservation_state_port.port_id"),
    state_domain_digest: assertDigest(
      input.state_domain_digest,
      "physical_resource_reservation_state_port.state_domain_digest",
    ),
    contract: RESOURCE_RESERVATION_STATE_PORT_CONTRACT,
    durability_assurance: "caller_asserted_callback_unattested",
  });
  STATE_PORTS.add(port);
  STATE_PORT_PRIVATE.set(port, Object.freeze({
    read_state: input.read_state,
    compare_and_set: input.compare_and_set,
  }));
  return port;
}

function assertPhysicalResourceReservationStatePort(port) {
  if (!port || !Object.isFrozen(port) || !STATE_PORTS.has(port) || !STATE_PORT_PRIVATE.has(port)) {
    throw new Error("physical resource reservation state port must be created by Bob's private factory");
  }
  return port;
}

function createPhysicalResourceBundleResolverPort(input = {}) {
  assertClosedObject(input, "physical_resource_bundle_resolver_port", ["port_id", "resolve_bundle"]);
  if (typeof input.resolve_bundle !== "function") {
    throw new Error("physical resource bundle resolver requires a synchronous resolve_bundle function");
  }
  const port = deepFreeze({
    version: RESOURCE_RESERVATION_AUTHORITY_VERSION,
    port_id: assertIdentifier(input.port_id, "physical_resource_bundle_resolver_port.port_id"),
    contract: RESOURCE_BUNDLE_RESOLVER_CONTRACT,
    resolver_assurance: "caller_asserted_callback_unattested",
  });
  BUNDLE_RESOLVER_PORTS.add(port);
  BUNDLE_RESOLVER_PRIVATE.set(port, Object.freeze({ resolve_bundle: input.resolve_bundle }));
  return port;
}

function assertPhysicalResourceBundleResolverPort(port) {
  if (!port || !Object.isFrozen(port) || !BUNDLE_RESOLVER_PORTS.has(port)
      || !BUNDLE_RESOLVER_PRIVATE.has(port)) {
    throw new Error("physical resource bundle resolver port must be created by Bob's private factory");
  }
  return port;
}

function normalizeRawFence(input, label) {
  assertClosedObject(input, label, [
    "resource_ref",
    "fencing_generation",
    "raw_fence",
    "fencing_token_hash",
  ]);
  const rawFence = input.raw_fence;
  if (typeof rawFence !== "string" || !RAW_FENCE_PATTERN.test(rawFence)) {
    throw new Error(`${label}.raw_fence must be a 32-byte base64url secret`);
  }
  const bytes = Buffer.from(rawFence, "base64url");
  if (bytes.length !== RAW_FENCE_BYTES) throw new Error(`${label}.raw_fence has invalid length`);
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  bytes.fill(0);
  if (digest !== assertDigest(input.fencing_token_hash, `${label}.fencing_token_hash`)) {
    throw new Error(`${label}.raw_fence does not match fencing_token_hash`);
  }
  return deepFreeze({
    resource_ref: assertToken(input.resource_ref, `${label}.resource_ref`),
    fencing_generation: assertInteger(
      input.fencing_generation,
      `${label}.fencing_generation`,
      1,
    ),
    raw_fence: rawFence,
    fencing_token_hash: digest,
  });
}

function normalizeReservationRecord(input, label = "physical_resource_reservation_record") {
  assertClosedObject(input, label, [
    "version",
    "request",
    "bundle",
    "allocation_plan_digest",
    "lock_order",
    "receipt",
    "effect_state",
    "resource_fences",
  ], ["effect_started_at", "effect_ended_at", "cooldown_until"]);
  if (input.version !== RESOURCE_RESERVATION_RECORD_VERSION) {
    throw new Error(`${label}.version must be ${RESOURCE_RESERVATION_RECORD_VERSION}`);
  }
  const request = normalizePhysicalReservationRequest(input.request, `${label}.request`);
  const bundle = normalizePhysicalResourceBundle(input.bundle, `${label}.bundle`);
  const receipt = assertReservationBindings(input.receipt, request, bundle);
  const lockOrder = assertDenseDataArray(input.lock_order, `${label}.lock_order`, {
    minimum: 1,
    maximum: 64,
  });
  const normalizedLockOrder = lockOrder.map((value, index) => assertToken(value, `${label}.lock_order[${index}]`));
  if (new Set(normalizedLockOrder).size !== normalizedLockOrder.length
      || normalizedLockOrder.some((value, index) => index > 0 && value <= normalizedLockOrder[index - 1])) {
    throw new Error(`${label}.lock_order must be unique and strictly sorted`);
  }
  const expectedLockOrder = [...new Set(receipt.allocations.map((entry) => entry.resource_ref))].sort();
  if (hashCanonicalJson(normalizedLockOrder) !== hashCanonicalJson(expectedLockOrder)) {
    throw new Error(`${label}.lock_order is detached from receipt allocations`);
  }
  const receiptIsActive = ACTIVE_RECEIPT_STATES.has(receipt.state);
  assertDenseDataArray(input.resource_fences, `${label}.resource_fences`, { maximum: 64 });
  if ((receiptIsActive && input.resource_fences.length !== expectedLockOrder.length)
      || (!receiptIsActive && input.resource_fences.length !== 0)) {
    throw new Error(
      receiptIsActive
        ? `${label}.resource_fences must contain one fence per resource`
        : `${label}.terminal receipt cannot retain raw resource fences`,
    );
  }
  const resourceFences = input.resource_fences.map((entry, index) => (
    normalizeRawFence(entry, `${label}.resource_fences[${index}]`)
  )).sort((left, right) => compareCodeUnits(left.resource_ref, right.resource_ref));
  if (new Set(resourceFences.map((entry) => entry.resource_ref)).size !== resourceFences.length
      || (receiptIsActive
        && hashCanonicalJson(resourceFences.map((entry) => entry.resource_ref))
          !== hashCanonicalJson(expectedLockOrder))) {
    throw new Error(`${label}.resource_fences do not cover the exact lock order`);
  }
  const allocationByResource = new Map();
  for (const allocation of receipt.allocations) {
    const prior = allocationByResource.get(allocation.resource_ref);
    if (prior && (prior.fencing_generation !== allocation.fencing_generation
        || prior.fencing_token_hash !== allocation.fencing_token_hash)) {
      throw new Error(`${label}.receipt has inconsistent per-resource fence bindings`);
    }
    allocationByResource.set(allocation.resource_ref, allocation);
  }
  for (const fence of resourceFences) {
    const allocation = allocationByResource.get(fence.resource_ref);
    if (fence.fencing_generation !== allocation.fencing_generation
        || fence.fencing_token_hash !== allocation.fencing_token_hash) {
      throw new Error(`${label}.resource fence is detached from receipt allocation`);
    }
  }
  const effectState = input.effect_state;
  if (!EFFECT_STATE_VALUES.includes(effectState)) {
    throw new Error(`${label}.effect_state must be one of ${EFFECT_STATE_VALUES.join(", ")}`);
  }
  const normalized = {
    version: RESOURCE_RESERVATION_RECORD_VERSION,
    request,
    bundle,
    allocation_plan_digest: assertDigest(
      input.allocation_plan_digest,
      `${label}.allocation_plan_digest`,
    ),
    lock_order: Object.freeze(normalizedLockOrder),
    receipt,
    effect_state: effectState,
    resource_fences: Object.freeze(resourceFences),
  };
  if (effectState === "not_started") {
    if (input.effect_started_at != null || input.effect_ended_at != null || input.cooldown_until != null) {
      throw new Error(`${label}.not_started cannot carry effect timestamps`);
    }
  } else {
    normalized.effect_started_at = assertTimestamp(input.effect_started_at, `${label}.effect_started_at`);
    if (effectState === "started") {
      if (input.effect_ended_at != null || input.cooldown_until != null) {
        throw new Error(`${label}.started cannot carry effect completion timestamps`);
      }
    } else {
      normalized.effect_ended_at = assertTimestamp(input.effect_ended_at, `${label}.effect_ended_at`);
      normalized.cooldown_until = assertTimestamp(input.cooldown_until, `${label}.cooldown_until`);
      if (Date.parse(normalized.effect_ended_at) < Date.parse(normalized.effect_started_at)
          || Date.parse(normalized.cooldown_until) < Date.parse(normalized.effect_ended_at)) {
        throw new Error(`${label} has invalid effect/cooldown timestamp order`);
      }
    }
  }
  if (receipt.state === "held" && effectState === "cleanup") {
    throw new Error(`${label}.held receipt cannot be in cleanup effect state`);
  }
  if (receipt.state === "cleanup_pending" && effectState !== "cleanup") {
    throw new Error(`${label}.cleanup_pending receipt requires cleanup effect state`);
  }
  if (receipt.state === "released") {
    const beforeEffect = new Set([
      "cancelled_before_effect",
      "expired_before_effect",
      "preempted_before_effect",
    ]);
    if ((beforeEffect.has(receipt.terminal_disposition) && effectState !== "not_started")
        || (receipt.terminal_disposition === "cleanup_confirmed" && effectState !== "cleanup")
        || (!beforeEffect.has(receipt.terminal_disposition)
          && receipt.terminal_disposition !== "cleanup_confirmed")) {
      throw new Error(`${label}.released receipt has an impossible terminal/effect disposition`);
    }
  }
  if (receipt.state === "fenced" && receipt.terminal_disposition !== "unknown_effect") {
    throw new Error(`${label}.fenced receipt requires unknown_effect disposition`);
  }
  if (receipt.state === "quarantined" && receipt.terminal_disposition !== "quarantined") {
    throw new Error(`${label}.quarantined receipt requires quarantined disposition`);
  }
  return deepFreeze(normalized);
}

function terminalAttemptConsumesBudget(receipt, effectState) {
  return effectState !== "not_started"
    || ["unknown_effect", "quarantined"].includes(receipt.terminal_disposition);
}

function assertTerminalEffectDisposition(receipt, effectState, label) {
  if (ACTIVE_RECEIPT_STATES.has(receipt.state)) {
    throw new Error(`${label} must retain terminal receipt state only`);
  }
  if (!EFFECT_STATE_VALUES.includes(effectState)) {
    throw new Error(`${label}.effect_state must be one of ${EFFECT_STATE_VALUES.join(", ")}`);
  }
  if (receipt.state === "released") {
    const beforeEffect = new Set([
      "cancelled_before_effect",
      "expired_before_effect",
      "preempted_before_effect",
    ]);
    if ((beforeEffect.has(receipt.terminal_disposition) && effectState !== "not_started")
        || (receipt.terminal_disposition === "cleanup_confirmed" && effectState !== "cleanup")
        || (!beforeEffect.has(receipt.terminal_disposition)
          && receipt.terminal_disposition !== "cleanup_confirmed")) {
      throw new Error(`${label} has an impossible terminal/effect disposition`);
    }
  }
  if (receipt.state === "fenced" && receipt.terminal_disposition !== "unknown_effect") {
    throw new Error(`${label}.fenced receipt requires unknown_effect disposition`);
  }
  if (receipt.state === "quarantined" && receipt.terminal_disposition !== "quarantined") {
    throw new Error(`${label}.quarantined receipt requires quarantined disposition`);
  }
}

function normalizeReservationTombstone(
  input,
  label = "physical_resource_reservation_tombstone",
) {
  assertClosedObject(input, label, [
    "version",
    "source_record_digest",
    "reservation_request_id",
    "reservation_request_digest",
    "attempt_ref",
    "node_id",
    "contract_hash",
    "source_graph_hash",
    "session_nucleus_hash",
    "resource_bundle_digest",
    "receipt",
    "allocation_plan_digest",
    "lock_order_digest",
    "effect_state",
    "attempt_budget_consumed",
  ], ["tombstone_digest"]);
  if (input.version !== RESOURCE_RESERVATION_TOMBSTONE_VERSION) {
    throw new Error(`${label}.version must be ${RESOURCE_RESERVATION_TOMBSTONE_VERSION}`);
  }
  const receipt = normalizePhysicalReservationReceipt(input.receipt, `${label}.receipt`);
  const effectState = input.effect_state;
  assertTerminalEffectDisposition(receipt, effectState, label);
  const exact = {
    reservation_request_digest: assertDigest(
      input.reservation_request_digest,
      `${label}.reservation_request_digest`,
    ),
    attempt_ref: assertToken(input.attempt_ref, `${label}.attempt_ref`),
    node_id: assertToken(input.node_id, `${label}.node_id`),
    contract_hash: assertDigest(input.contract_hash, `${label}.contract_hash`),
    source_graph_hash: assertDigest(input.source_graph_hash, `${label}.source_graph_hash`),
    session_nucleus_hash: assertDigest(
      input.session_nucleus_hash,
      `${label}.session_nucleus_hash`,
    ),
    resource_bundle_digest: assertDigest(
      input.resource_bundle_digest,
      `${label}.resource_bundle_digest`,
    ),
  };
  for (const [field, value] of Object.entries(exact)) {
    if (receipt[field] !== value) {
      throw new Error(`${label}.${field} is detached from terminal receipt`);
    }
  }
  const attemptBudgetConsumed = terminalAttemptConsumesBudget(receipt, effectState);
  if (input.attempt_budget_consumed !== attemptBudgetConsumed) {
    throw new Error(`${label}.attempt_budget_consumed is inconsistent with terminal effect state`);
  }
  const normalized = {
    version: RESOURCE_RESERVATION_TOMBSTONE_VERSION,
    source_record_digest: assertDigest(input.source_record_digest, `${label}.source_record_digest`),
    reservation_request_id: assertToken(
      input.reservation_request_id,
      `${label}.reservation_request_id`,
    ),
    ...exact,
    receipt,
    allocation_plan_digest: assertDigest(
      input.allocation_plan_digest,
      `${label}.allocation_plan_digest`,
    ),
    lock_order_digest: assertDigest(input.lock_order_digest, `${label}.lock_order_digest`),
    effect_state: effectState,
    attempt_budget_consumed: attemptBudgetConsumed,
  };
  const tombstoneDigest = hashCanonicalJson(normalized);
  if (input.tombstone_digest != null
      && assertDigest(input.tombstone_digest, `${label}.tombstone_digest`) !== tombstoneDigest) {
    throw new Error(`${label}.tombstone_digest does not bind normalized content`);
  }
  return deepFreeze({ ...normalized, tombstone_digest: tombstoneDigest });
}

function makeReservationTombstone(recordInput) {
  const record = normalizeReservationRecord(recordInput);
  assertTerminalEffectDisposition(record.receipt, record.effect_state, "reservation compaction record");
  return normalizeReservationTombstone({
    version: RESOURCE_RESERVATION_TOMBSTONE_VERSION,
    source_record_digest: hashCanonicalJson(record),
    reservation_request_id: record.request.reservation_request_id,
    reservation_request_digest: record.request.reservation_request_digest,
    attempt_ref: record.request.attempt_ref,
    node_id: record.request.node_id,
    contract_hash: record.request.contract_hash,
    source_graph_hash: record.request.source_graph_hash,
    session_nucleus_hash: record.request.session_nucleus_hash,
    resource_bundle_digest: record.request.resource_bundle_digest,
    receipt: record.receipt,
    allocation_plan_digest: record.allocation_plan_digest,
    lock_order_digest: hashCanonicalJson(record.lock_order),
    effect_state: record.effect_state,
    attempt_budget_consumed: terminalAttemptConsumesBudget(record.receipt, record.effect_state),
  });
}

function reservationTombstoneSetDigest(tombstones) {
  return hashCanonicalJson(tombstones);
}

function normalizePhysicalResourceReservationState(input, expected = null) {
  assertClosedObject(input, "physical_resource_reservation_state", [
    "version",
    "state_domain_digest",
    "broker_ref",
    "broker_epoch",
    "revision",
    "prior_state_digest",
    "inventory_attestation_generation",
    "inventory_attestation_digest",
    "inventory_attestation_prior_digest",
    "inventory_attestation_state_revision",
    "inventory_attestation_state_digest",
    "inventory_attestation_prior_inventory_digest",
    "attested_inventory",
    "inventory",
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
    "reservation_tombstones",
    "reservations",
  ], ["state_digest"]);
  if (input.version !== RESOURCE_RESERVATION_STATE_VERSION) {
    throw new Error(`physical_resource_reservation_state.version must be ${RESOURCE_RESERVATION_STATE_VERSION}`);
  }
  const inventory = normalizePhysicalResourceInventory(input.inventory);
  const attestedInventory = input.attested_inventory === null
    ? null
    : normalizePhysicalResourceInventory(
      input.attested_inventory,
      "physical_resource_reservation_state.attested_inventory",
    );
  const reservations = assertDenseDataArray(
    input.reservations,
    "physical_resource_reservation_state.reservations",
    { maximum: MAX_RESERVATIONS },
  );
  const normalizedReservations = reservations.map((entry, index) => (
    normalizeReservationRecord(entry, `physical_resource_reservation_state.reservations[${index}]`)
  )).sort((left, right) => compareCodeUnits(
    left.receipt.reservation_ref,
    right.receipt.reservation_ref,
  ));
  const tombstones = assertDenseDataArray(
    input.reservation_tombstones,
    "physical_resource_reservation_state.reservation_tombstones",
    { maximum: MAX_RESERVATION_TOMBSTONES },
  );
  const normalizedTombstones = tombstones.map((entry, index) => (
    normalizeReservationTombstone(
      entry,
      `physical_resource_reservation_state.reservation_tombstones[${index}]`,
    )
  )).sort((left, right) => compareCodeUnits(
    left.receipt.reservation_ref,
    right.receipt.reservation_ref,
  ));
  const generalTombstoneCount = normalizedTombstones.filter((entry) => (
    !["fenced", "quarantined"].includes(entry.receipt.state)
  )).length;
  if (generalTombstoneCount > MAX_GENERAL_RESERVATION_TOMBSTONES) {
    throw new Error("physical resource reservation general tombstone capacity is exhausted");
  }
  const reservationRefs = [
    ...normalizedReservations.map((entry) => entry.receipt.reservation_ref),
    ...normalizedTombstones.map((entry) => entry.receipt.reservation_ref),
  ];
  const requestIds = [
    ...normalizedReservations.map((entry) => entry.request.reservation_request_id),
    ...normalizedTombstones.map((entry) => entry.reservation_request_id),
  ];
  if (new Set(reservationRefs).size !== reservationRefs.length
      || new Set(requestIds).size !== requestIds.length) {
    throw new Error("physical resource reservation state has duplicate reservation or request identities");
  }
  const revision = assertInteger(input.revision, "physical_resource_reservation_state.revision", 0);
  const priorStateDigest = input.prior_state_digest === null
    ? null
    : assertDigest(input.prior_state_digest, "physical_resource_reservation_state.prior_state_digest");
  if ((revision === 0) !== (priorStateDigest === null)) {
    throw new Error("physical resource reservation state prior_state_digest does not match revision ancestry");
  }
  const inventoryAttestationGeneration = assertInteger(
    input.inventory_attestation_generation,
    "physical_resource_reservation_state.inventory_attestation_generation",
    0,
  );
  const inventoryAttestationDigest = input.inventory_attestation_digest === null
    ? null
    : assertDigest(
      input.inventory_attestation_digest,
      "physical_resource_reservation_state.inventory_attestation_digest",
    );
  const inventoryAttestationPriorDigest = input.inventory_attestation_prior_digest === null
    ? null
    : assertDigest(
      input.inventory_attestation_prior_digest,
      "physical_resource_reservation_state.inventory_attestation_prior_digest",
    );
  const inventoryAttestationStateRevision = input.inventory_attestation_state_revision === null
    ? null
    : assertInteger(
      input.inventory_attestation_state_revision,
      "physical_resource_reservation_state.inventory_attestation_state_revision",
      0,
    );
  const inventoryAttestationStateDigest = input.inventory_attestation_state_digest === null
    ? null
    : assertDigest(
      input.inventory_attestation_state_digest,
      "physical_resource_reservation_state.inventory_attestation_state_digest",
    );
  const inventoryAttestationPriorInventoryDigest =
    input.inventory_attestation_prior_inventory_digest === null
      ? null
      : assertDigest(
        input.inventory_attestation_prior_inventory_digest,
        "physical_resource_reservation_state.inventory_attestation_prior_inventory_digest",
      );
  const hasNoInventoryAttestation = inventoryAttestationGeneration === 0;
  if (hasNoInventoryAttestation !== (inventoryAttestationDigest === null)
      || hasNoInventoryAttestation !== (inventoryAttestationStateRevision === null)
      || hasNoInventoryAttestation !== (inventoryAttestationStateDigest === null)
      || hasNoInventoryAttestation !== (inventoryAttestationPriorInventoryDigest === null)
      || hasNoInventoryAttestation !== (attestedInventory === null)
      || ((inventoryAttestationGeneration <= 1)
        !== (inventoryAttestationPriorDigest === null))) {
    throw new Error("physical resource reservation state inventory attestation lineage is incomplete");
  }
  if (!hasNoInventoryAttestation && inventoryAttestationStateRevision >= revision) {
    throw new Error("physical resource reservation inventory attestation must bind a prior durable state");
  }
  const compactionGeneration = assertInteger(
    input.compaction_generation,
    "physical_resource_reservation_state.compaction_generation",
    0,
  );
  const compactionHistoryAccumulator = input.compaction_history_accumulator === null
    ? null
    : assertDigest(
      input.compaction_history_accumulator,
      "physical_resource_reservation_state.compaction_history_accumulator",
    );
  const compactionPriorAccumulator = input.compaction_prior_accumulator === null
    ? null
    : assertDigest(
      input.compaction_prior_accumulator,
      "physical_resource_reservation_state.compaction_prior_accumulator",
    );
  const compactionSourceCheckpointGeneration =
    input.compaction_source_checkpoint_generation === null
      ? null
      : assertInteger(
        input.compaction_source_checkpoint_generation,
        "physical_resource_reservation_state.compaction_source_checkpoint_generation",
        1,
      );
  const compactionSourceCheckpointDigest = input.compaction_source_checkpoint_digest === null
    ? null
    : assertDigest(
      input.compaction_source_checkpoint_digest,
      "physical_resource_reservation_state.compaction_source_checkpoint_digest",
    );
  const compactionSourceStateRevision = input.compaction_source_state_revision === null
    ? null
    : assertInteger(
      input.compaction_source_state_revision,
      "physical_resource_reservation_state.compaction_source_state_revision",
      0,
    );
  const compactionSourceStateDigest = input.compaction_source_state_digest === null
    ? null
    : assertDigest(
      input.compaction_source_state_digest,
      "physical_resource_reservation_state.compaction_source_state_digest",
    );
  const batchRecordDigestsInput = assertDenseDataArray(
    input.compaction_batch_record_digests,
    "physical_resource_reservation_state.compaction_batch_record_digests",
    { maximum: MAX_RESERVATIONS },
  );
  const compactionBatchRecordDigests = batchRecordDigestsInput.map((entry, index) => (
    assertDigest(
      entry,
      `physical_resource_reservation_state.compaction_batch_record_digests[${index}]`,
    )
  ));
  if (new Set(compactionBatchRecordDigests).size !== compactionBatchRecordDigests.length
      || compactionBatchRecordDigests.some((entry, index) => (
        index > 0 && entry <= compactionBatchRecordDigests[index - 1]
      ))) {
    throw new Error("physical resource reservation compaction batch digests must be unique and sorted");
  }
  const compactionTombstoneSetDigest = input.compaction_tombstone_set_digest === null
    ? null
    : assertDigest(
      input.compaction_tombstone_set_digest,
      "physical_resource_reservation_state.compaction_tombstone_set_digest",
    );
  const compactedRecordCount = assertInteger(
    input.compacted_record_count,
    "physical_resource_reservation_state.compacted_record_count",
    0,
    MAX_RESERVATION_TOMBSTONES,
  );
  const hasNoCompaction = compactionGeneration === 0;
  const computedTombstoneSetDigest = reservationTombstoneSetDigest(normalizedTombstones);
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
        || normalizedTombstones.length !== 0) {
      throw new Error("physical resource reservation compaction genesis is inconsistent");
    }
  } else {
    if (compactionHistoryAccumulator === null
        || (compactionGeneration === 1) !== (compactionPriorAccumulator === null)
        || compactionSourceCheckpointGeneration === null
        || compactionSourceCheckpointDigest === null
        || compactionSourceStateRevision === null
        || compactionSourceStateDigest === null
        || compactionBatchRecordDigests.length === 0
        || compactionTombstoneSetDigest !== computedTombstoneSetDigest
        || compactedRecordCount !== normalizedTombstones.length
        || compactionSourceCheckpointGeneration !== compactionSourceStateRevision + 1
        || compactionSourceStateRevision >= revision) {
      throw new Error("physical resource reservation compaction lineage is incomplete");
    }
    const tombstoneRecordDigests = new Set(normalizedTombstones.map((entry) => (
      entry.source_record_digest
    )));
    if (compactionBatchRecordDigests.some((entry) => !tombstoneRecordDigests.has(entry))) {
      throw new Error("physical resource reservation compaction batch is detached from tombstones");
    }
    const computedAccumulator = physicalResourceReservationCompactionAccumulatorDigest({
      compaction_generation: compactionGeneration,
      prior_accumulator: compactionPriorAccumulator,
      compacted_record_digests: compactionBatchRecordDigests,
      source_checkpoint_generation: compactionSourceCheckpointGeneration,
      source_checkpoint_digest: compactionSourceCheckpointDigest,
      source_state_revision: compactionSourceStateRevision,
      source_state_digest: compactionSourceStateDigest,
      tombstone_set_digest: compactionTombstoneSetDigest,
      tombstone_count: normalizedTombstones.length,
      compacted_record_count: compactedRecordCount,
    });
    if (compactionHistoryAccumulator !== computedAccumulator) {
      throw new Error("physical resource reservation compaction accumulator is invalid");
    }
  }
  const normalized = {
    version: RESOURCE_RESERVATION_STATE_VERSION,
    state_domain_digest: assertDigest(input.state_domain_digest, "physical_resource_reservation_state.state_domain_digest"),
    broker_ref: normalizeOpaqueRef(input.broker_ref, "physical_resource_reservation_state.broker_ref", { prefix: "broker" }),
    broker_epoch: assertInteger(input.broker_epoch, "physical_resource_reservation_state.broker_epoch", 1),
    revision,
    prior_state_digest: priorStateDigest,
    inventory_attestation_generation: inventoryAttestationGeneration,
    inventory_attestation_digest: inventoryAttestationDigest,
    inventory_attestation_prior_digest: inventoryAttestationPriorDigest,
    inventory_attestation_state_revision: inventoryAttestationStateRevision,
    inventory_attestation_state_digest: inventoryAttestationStateDigest,
    inventory_attestation_prior_inventory_digest: inventoryAttestationPriorInventoryDigest,
    attested_inventory: attestedInventory,
    inventory,
    compaction_generation: compactionGeneration,
    compaction_history_accumulator: compactionHistoryAccumulator,
    compaction_prior_accumulator: compactionPriorAccumulator,
    compaction_source_checkpoint_generation: compactionSourceCheckpointGeneration,
    compaction_source_checkpoint_digest: compactionSourceCheckpointDigest,
    compaction_source_state_revision: compactionSourceStateRevision,
    compaction_source_state_digest: compactionSourceStateDigest,
    compaction_batch_record_digests: Object.freeze(compactionBatchRecordDigests),
    compaction_tombstone_set_digest: compactionTombstoneSetDigest,
    compacted_record_count: compactedRecordCount,
    reservation_tombstones: Object.freeze(normalizedTombstones),
    reservations: Object.freeze(normalizedReservations),
  };
  if (inventory.broker_ref !== normalized.broker_ref || inventory.broker_epoch !== normalized.broker_epoch) {
    throw new Error("physical resource reservation state inventory broker binding drift");
  }
  if (attestedInventory != null) {
    for (const field of [
      "broker_ref",
      "broker_epoch",
      "session_nucleus_hash",
      "source_graph_hash",
      "captured_at",
      "valid_from",
      "expires_at",
    ]) {
      if (inventory[field] !== attestedInventory[field]) {
        throw new Error(`physical resource reservation logical inventory ${field} drifted from its attested observation`);
      }
    }
    if (inventory.inventory_generation < attestedInventory.inventory_generation) {
      throw new Error("physical resource reservation logical inventory generation predates its attested observation");
    }
    const attestedByRef = new Map(attestedInventory.resources.map((resource) => [
      resource.resource_ref,
      resource,
    ]));
    if (attestedByRef.size !== inventory.resources.length
        || inventory.resources.some((resource) => !attestedByRef.has(resource.resource_ref))) {
      throw new Error("physical resource reservation logical inventory resource identities drifted from attestation");
    }
    for (const resource of inventory.resources) {
      const attested = attestedByRef.get(resource.resource_ref);
      for (const field of [
        "resource_kind",
        "state_epoch_digest",
        "total_capacity_units",
        "setup_cost_units",
        "eligible_requirement_digests",
        "switchable_mode_refs",
        "switchable_workspace_refs",
        "current_mode_ref",
        "current_workspace_ref",
      ]) {
        if (hashCanonicalJson(resource[field] == null ? null : resource[field])
            !== hashCanonicalJson(attested[field] == null ? null : attested[field])) {
          throw new Error(`physical resource reservation logical inventory ${field} drifted from attestation`);
        }
      }
      const availabilityCanDescend = attested.availability === "available"
        || (attested.availability === "degraded" && resource.availability !== "available")
        || (attested.availability === "unavailable"
          && ["unavailable", "quarantined"].includes(resource.availability))
        || (attested.availability === "quarantined" && resource.availability === "quarantined");
      if (!availabilityCanDescend
          || resource.available_capacity_units > attested.available_capacity_units
          || (resource.exclusive_available && !attested.exclusive_available)
          || resource.fencing_generation < attested.fencing_generation) {
        throw new Error("physical resource reservation logical inventory widened beyond its attested observation");
      }
    }
  }
  if (expected != null) {
    for (const field of ["state_domain_digest", "broker_ref", "broker_epoch"] ) {
      if (normalized[field] !== expected[field]) {
        throw new Error(`physical resource reservation state ${field} binding drift`);
      }
    }
    if (inventory.source_graph_hash !== expected.source_graph_hash
        || inventory.session_nucleus_hash !== expected.session_nucleus_hash) {
      throw new Error("physical resource reservation state graph/nucleus binding drift");
    }
  }
  // A durable callback cannot smuggle a public-looking inventory that ignores
  // reservations already held in the same atomic state. External holders may
  // consume additional capacity, so this is a ceiling rather than an equality.
  const resourcesByRef = new Map(inventory.resources.map((resource) => [resource.resource_ref, resource]));
  const activeByResource = new Map();
  for (const record of normalizedReservations) {
    if (!ACTIVE_RECEIPT_STATES.has(record.receipt.state)) continue;
    for (const allocation of record.receipt.allocations) {
      const resource = resourcesByRef.get(allocation.resource_ref);
      if (!resource || resource.resource_kind !== allocation.resource_kind) {
        throw new Error("physical resource reservation state has an active allocation absent from inventory");
      }
      const requirement = record.bundle.requirements.find((entry) => entry.alias === allocation.alias);
      const active = activeByResource.get(allocation.resource_ref) || {
        capacity_units: 0,
        ownerships: new Set(),
        compatibility_refs: new Set(),
        mode_refs: new Set(),
        workspace_refs: new Set(),
        max_fencing_generation: 0,
      };
      active.capacity_units += allocation.capacity_units;
      active.ownerships.add(allocation.ownership);
      if (requirement.compatibility_ref) active.compatibility_refs.add(requirement.compatibility_ref);
      if (requirement.mode_ref) active.mode_refs.add(requirement.mode_ref);
      if (requirement.workspace_ref) active.workspace_refs.add(requirement.workspace_ref);
      active.max_fencing_generation = Math.max(active.max_fencing_generation, allocation.fencing_generation);
      activeByResource.set(allocation.resource_ref, active);
    }
  }
  for (const [resourceRef, active] of activeByResource) {
    const resource = resourcesByRef.get(resourceRef);
    const consumedCapacity = resource.total_capacity_units - resource.available_capacity_units;
    if (active.capacity_units > consumedCapacity
        || active.ownerships.size !== 1
        || resource.exclusive_available
        || resource.fencing_generation < active.max_fencing_generation) {
      throw new Error("physical resource reservation state inventory does not reflect held capacity/fencing");
    }
    if (active.ownerships.has("exclusive") && resource.available_capacity_units !== 0) {
      throw new Error("physical resource reservation state exclusive hold still exposes capacity");
    }
    if (active.ownerships.has("shared")
        && (active.compatibility_refs.size !== 1
          || resource.active_shared_compatibility_ref !== [...active.compatibility_refs][0])) {
      throw new Error("physical resource reservation state shared compatibility drift");
    }
  }
  if (attestedInventory != null) {
    // A locally fenced/quarantined terminal allocation remains a durable safety
    // floor until a later signed observation crosses that allocation's fence
    // generation. This prevents a restart checkpoint from laundering a direct
    // state edit that silently resurrects a resource without inventory trust.
    const safetyFloorByResource = new Map();
    for (const record of [...normalizedReservations, ...normalizedTombstones]) {
      if (!["fenced", "quarantined"].includes(record.receipt.state)) continue;
      for (const allocation of record.receipt.allocations) {
        safetyFloorByResource.set(
          allocation.resource_ref,
          Math.max(
            safetyFloorByResource.get(allocation.resource_ref) || 0,
            allocation.fencing_generation,
          ),
        );
      }
    }
    const attestedByRef = new Map(attestedInventory.resources.map((resource) => [
      resource.resource_ref,
      resource,
    ]));
    for (const [resourceRef, safetyFloor] of safetyFloorByResource) {
      const observed = attestedByRef.get(resourceRef);
      const logical = resourcesByRef.get(resourceRef);
      if (observed.fencing_generation <= safetyFloor
          && logical.availability === "available") {
        throw new Error(
          "physical resource reservation state resurrected a safety-fenced resource without a newer signed observation",
        );
      }
    }
  }
  const digest = hashCanonicalJson(normalized);
  if (input.state_digest != null
      && assertDigest(input.state_digest, "physical_resource_reservation_state.state_digest") !== digest) {
    throw new Error("physical_resource_reservation_state.state_digest does not match normalized content");
  }
  return deepFreeze({ ...normalized, state_digest: digest });
}

function createInitialPhysicalResourceReservationState(input = {}) {
  assertClosedObject(input, "initial_physical_resource_reservation_state", [
    "state_domain_digest",
    "inventory",
  ]);
  const inventory = normalizePhysicalResourceInventory(input.inventory);
  return normalizePhysicalResourceReservationState({
    version: RESOURCE_RESERVATION_STATE_VERSION,
    state_domain_digest: input.state_domain_digest,
    broker_ref: inventory.broker_ref,
    broker_epoch: inventory.broker_epoch,
    revision: 0,
    prior_state_digest: null,
    inventory_attestation_generation: 0,
    inventory_attestation_digest: null,
    inventory_attestation_prior_digest: null,
    inventory_attestation_state_revision: null,
    inventory_attestation_state_digest: null,
    inventory_attestation_prior_inventory_digest: null,
    attested_inventory: null,
    inventory,
    compaction_generation: 0,
    compaction_history_accumulator: null,
    compaction_prior_accumulator: null,
    compaction_source_checkpoint_generation: null,
    compaction_source_checkpoint_digest: null,
    compaction_source_state_revision: null,
    compaction_source_state_digest: null,
    compaction_batch_record_digests: [],
    compaction_tombstone_set_digest: null,
    compacted_record_count: 0,
    reservation_tombstones: [],
    reservations: [],
  });
}

function resolveBundle(port, digest, request) {
  assertPhysicalResourceBundleResolverPort(port);
  if (ACTIVE_BUNDLE_RESOLVERS.has(port)) {
    throw reservationError(
      "resource_bundle_resolver_reentrant",
      "physical resource bundle resolver cannot re-enter its authority surface",
    );
  }
  let result;
  ACTIVE_BUNDLE_RESOLVERS.add(port);
  try {
    result = assertSyncResult(
      BUNDLE_RESOLVER_PRIVATE.get(port).resolve_bundle(deepFreeze({
        version: RESOURCE_RESERVATION_AUTHORITY_VERSION,
        resource_bundle_digest: digest,
        reservation_request_digest: request.reservation_request_digest,
      })),
      "physical resource bundle resolver",
    );
  } finally {
    ACTIVE_BUNDLE_RESOLVERS.delete(port);
  }
  const bundle = normalizePhysicalResourceBundle(result);
  if (bundle.resource_bundle_digest !== digest) {
    throw reservationError("resource_bundle_binding_drift", "resolved physical resource bundle digest drift");
  }
  return bundle;
}

// Broker-private consumers such as the resource arbiter admission seam may
// resolve only the exact bundle named by a fully normalized reservation
// request. The branded resolver callback and its reentrancy guard remain
// private to this module; exporting this attenuated operation does not expose
// the callback or permit a caller to substitute scheduling metadata.
function resolvePhysicalResourceBundleForAdmission(port, input = {}) {
  assertClosedObject(input, "physical_resource_bundle_admission_resolution", [
    "reservation_request",
  ]);
  const request = normalizePhysicalReservationRequest(
    input.reservation_request,
    "physical_resource_bundle_admission_resolution.reservation_request",
  );
  return resolveBundle(port, request.resource_bundle_digest, request);
}

function makeStateContext(authorityState) {
  return deepFreeze({
    version: RESOURCE_RESERVATION_STATE_VERSION,
    state_domain_digest: authorityState.state_domain_digest,
    broker_ref: authorityState.broker_ref,
    broker_epoch: authorityState.broker_epoch,
    source_graph_hash: authorityState.source_graph_hash,
    session_nucleus_hash: authorityState.session_nucleus_hash,
  });
}

function readAuthorityState(authorityState) {
  if (authorityState.ambiguous) {
    throw reservationError(
      "reservation_state_ambiguous",
      "physical resource reservation authority is fail-closed pending external reconciliation and restart",
    );
  }
  const callbacks = STATE_PORT_PRIVATE.get(authorityState.state_port);
  let result;
  if (ACTIVE_STATE_PORT_CALLBACKS.has(authorityState.state_port)) {
    throw reservationError(
      "reservation_state_reentrant_callback",
      "physical resource reservation state callbacks cannot re-enter the authority surface",
    );
  }
  ACTIVE_STATE_PORT_CALLBACKS.add(authorityState.state_port);
  try {
    result = assertSyncResult(callbacks.read_state(makeStateContext(authorityState)), "physical resource reservation read_state");
  } catch (cause) {
    throw reservationError("reservation_state_unavailable", "physical resource reservation state is unavailable", cause);
  } finally {
    ACTIVE_STATE_PORT_CALLBACKS.delete(authorityState.state_port);
  }
  if (result == null) {
    throw reservationError("reservation_state_uninitialized", "physical resource reservation state is not initialized");
  }
  const normalized = normalizePhysicalResourceReservationState(result, authorityState);
  if (authorityState.last_revision != null) {
    if (normalized.revision < authorityState.last_revision
        || normalized.inventory.inventory_generation < authorityState.last_inventory_generation) {
      authorityState.ambiguous = true;
      throw reservationError(
        "reservation_state_rollback",
        "physical resource reservation state rolled back below the live authority floor",
      );
    }
    if (normalized.revision === authorityState.last_revision
        && normalized.state_digest !== authorityState.last_state_digest) {
      authorityState.ambiguous = true;
      throw reservationError(
        "reservation_state_fork",
        "physical resource reservation state forked at an observed revision",
      );
    }
    if (normalized.revision > authorityState.last_revision) {
      const pending = authorityState.pending_successor;
      if (!pending
          || normalized.revision !== pending.revision
          || normalized.state_digest !== pending.state_digest) {
        authorityState.ambiguous = true;
        throw reservationError(
          "reservation_state_history_unverified",
          "physical resource reservation state advanced outside the live authority's exact CAS successor",
        );
      }
    }
  }
  if (authorityState.last_revision == null || normalized.revision > authorityState.last_revision) {
    authorityState.last_revision = normalized.revision;
    authorityState.last_state_digest = normalized.state_digest;
    authorityState.last_inventory_generation = normalized.inventory.inventory_generation;
  }
  authorityState.live_observed_revision = normalized.revision;
  authorityState.live_observed_state_digest = normalized.state_digest;
  authorityState.live_full_record_count = normalized.reservations.length;
  authorityState.live_tombstone_count = normalized.reservation_tombstones.length;
  authorityState.live_compaction_generation = normalized.compaction_generation;
  return normalized;
}

function assertAuthorityMutationReady(authorityState) {
  if (authorityState.compaction_in_flight) {
    throw reservationError(
      "reservation_history_compaction_reentrant_mutation",
      "physical resource reservation mutations cannot re-enter checkpoint-bound history compaction",
    );
  }
  if (!authorityState.mutations_enabled) {
    throw reservationError(
      "reservation_checkpoint_refresh_required",
      "signed inventory provisioning changed the durable head; an exact external checkpoint must anchor that successor before authority can be used",
    );
  }
}

function callCas(authorityState, expected, next) {
  if (authorityState.ambiguous) {
    throw reservationError(
      "reservation_state_ambiguous",
      "physical resource reservation mutations are fail-closed after an ambiguous CAS outcome",
    );
  }
  if (authorityState.cas_in_flight) {
    throw reservationError(
      "reservation_state_reentrant_mutation",
      "physical resource reservation CAS callbacks cannot re-enter mutation authority",
    );
  }
  if (authorityState.inventory_refresh_in_flight
      && !authorityState.inventory_refresh_committing) {
    throw reservationError(
      "resource_inventory_refresh_reentrant_mutation",
      "physical resource reservation mutations cannot re-enter inventory trust resolution",
    );
  }
  if (!authorityState.mutations_enabled && !authorityState.bootstrap_inventory_provisioning) {
    assertAuthorityMutationReady(authorityState);
  }
  const callbacks = STATE_PORT_PRIVATE.get(authorityState.state_port);
  let result;
  let casError = null;
  let observed = null;
  let readError = null;
  authorityState.cas_in_flight = true;
  authorityState.pending_successor = Object.freeze({
    revision: next.revision,
    state_digest: next.state_digest,
  });
  try {
    try {
      if (ACTIVE_STATE_PORT_CALLBACKS.has(authorityState.state_port)) {
        throw reservationError(
          "reservation_state_reentrant_callback",
          "physical resource reservation state callbacks cannot re-enter the authority surface",
        );
      }
      ACTIVE_STATE_PORT_CALLBACKS.add(authorityState.state_port);
      result = assertSyncResult(callbacks.compare_and_set(deepFreeze({
        ...makeStateContext(authorityState),
        expected_revision: expected.revision,
        expected_state_digest: expected.state_digest,
        next_state: next,
      })), "physical resource reservation compare_and_set");
      if (result !== true && result !== false) {
        throw new Error("physical resource reservation compare_and_set must return a boolean");
      }
    } catch (cause) {
      casError = cause;
    } finally {
      ACTIVE_STATE_PORT_CALLBACKS.delete(authorityState.state_port);
    }
    try { observed = readAuthorityState(authorityState); } catch (cause) { readError = cause; }
  } finally {
    authorityState.pending_successor = null;
    authorityState.cas_in_flight = false;
  }
  if (observed && observed.state_digest === next.state_digest) {
    authorityState.checkpoint_head_state = authorityState.bootstrap_inventory_provisioning
      ? "inventory_successor_unanchored"
      : "stale_after_live_mutation";
    return Object.freeze({ committed: true, state: observed });
  }
  if (casError == null && result === false && observed != null) {
    return Object.freeze({ committed: false, state: observed });
  }
  authorityState.ambiguous = true;
  throw reservationError(
    "reservation_state_ambiguous",
    "physical resource reservation CAS outcome is ambiguous and mutations are fail-closed",
    casError || readError,
  );
}

function findRequestRecord(state, request) {
  return state.reservations.find((record) => (
    record.request.reservation_request_id === request.reservation_request_id
  )) || state.reservation_tombstones.find((tombstone) => (
    tombstone.reservation_request_id === request.reservation_request_id
  )) || null;
}

function assertExactDuplicate(record, request) {
  const requestDigest = record.request == null
    ? record.reservation_request_digest
    : record.request.reservation_request_digest;
  if (requestDigest !== request.reservation_request_digest) {
    throw reservationError(
      "reservation_request_identity_conflict",
      "physical reservation request ID is already bound to different content",
    );
  }
  return record;
}

function makeCredential(authorityState, record) {
  if (!ACTIVE_RECEIPT_STATES.has(record.receipt.state) || record.resource_fences.length === 0) return null;
  const publicValue = deepFreeze({
    version: RESOURCE_RESERVATION_CREDENTIAL_VERSION,
    reservation_ref: record.receipt.reservation_ref,
    broker_ref: record.receipt.broker_ref,
    broker_epoch: record.receipt.broker_epoch,
    reservation_request_digest: record.request.reservation_request_digest,
    receipt_digest: record.receipt.receipt_digest,
    resource_fence_count: record.resource_fences.length,
    fencing_semantics: RESOURCE_FENCING_SEMANTICS,
    credential_binding_digest: hashCanonicalJson({
      reservation_ref: record.receipt.reservation_ref,
      reservation_request_digest: record.request.reservation_request_digest,
      receipt_digest: record.receipt.receipt_digest,
      resource_fence_hashes: record.resource_fences.map((entry) => entry.fencing_token_hash),
    }),
  });
  CREDENTIALS.add(publicValue);
  CREDENTIAL_PRIVATE.set(publicValue, Object.freeze({
    authority_state: authorityState,
    resource_fences: record.resource_fences,
  }));
  return publicValue;
}

function publicReservationResult(authorityState, record, idempotent = false) {
  if (record.request == null) {
    return deepFreeze({
      receipt: record.receipt,
      credential: null,
      allocation_plan_digest: record.allocation_plan_digest,
      reservation_projection: projectBrokerPhysicalResourceReservationTombstone(record),
      idempotent,
    });
  }
  return deepFreeze({
    receipt: record.receipt,
    credential: makeCredential(authorityState, record),
    allocation_plan_digest: record.allocation_plan_digest,
    reservation_projection: projectBrokerPhysicalResourceReservation(record),
    idempotent,
  });
}

function projectBrokerPhysicalResourceReservation(recordInput) {
  const record = normalizeReservationRecord(recordInput);
  const core = projectPhysicalReservationState(record.receipt);
  const value = {
    version: RESOURCE_RESERVATION_RECORD_VERSION,
    ...core,
    allocation_plan_digest: record.allocation_plan_digest,
    lock_order_digest: hashCanonicalJson(record.lock_order),
    effect_state: record.effect_state,
    fencing_semantics: RESOURCE_FENCING_SEMANTICS,
  };
  return deepFreeze({ ...value, broker_reservation_digest: hashCanonicalJson(value) });
}

function projectBrokerPhysicalResourceReservationTombstone(tombstoneInput) {
  const tombstone = normalizeReservationTombstone(tombstoneInput);
  const core = projectPhysicalReservationState(tombstone.receipt);
  const value = {
    version: RESOURCE_RESERVATION_RECORD_VERSION,
    ...core,
    allocation_plan_digest: tombstone.allocation_plan_digest,
    lock_order_digest: tombstone.lock_order_digest,
    effect_state: tombstone.effect_state,
    fencing_semantics: RESOURCE_FENCING_SEMANTICS,
  };
  return deepFreeze({ ...value, broker_reservation_digest: hashCanonicalJson(value) });
}

function assertCredentialBrand(credential, authorityState = null) {
  if (!credential || !Object.isFrozen(credential) || !CREDENTIALS.has(credential)
      || !CREDENTIAL_PRIVATE.has(credential)) {
    throw reservationError(
      "resource_reservation_credential_untrusted",
      "physical resource reservation credential must be a privately branded broker credential",
    );
  }
  const privateState = CREDENTIAL_PRIVATE.get(credential);
  if (authorityState != null && privateState.authority_state !== authorityState) {
    throw reservationError("resource_reservation_credential_wrong_authority", "reservation credential belongs to another authority");
  }
  return privateState;
}

function inventoryIsCurrent(inventory, sample) {
  const earliest = Date.parse(sample.trusted_utc_earliest);
  const latest = Date.parse(sample.trusted_utc_latest);
  return Date.parse(inventory.captured_at) <= earliest
    && Date.parse(inventory.valid_from) <= earliest
    && latest < Date.parse(inventory.expires_at);
}

function recordHasLiveInventory(record, inventory) {
  const resources = new Map(inventory.resources.map((resource) => [resource.resource_ref, resource]));
  const requirements = new Map(record.bundle.requirements.map((requirement) => [requirement.alias, requirement]));
  for (const allocation of record.receipt.allocations) {
    const resource = resources.get(allocation.resource_ref);
    const requirement = requirements.get(allocation.alias);
    if (!resource || !requirement
        || resource.availability !== "available"
        || resource.resource_kind !== allocation.resource_kind
        || resource.state_epoch_digest !== allocation.state_epoch_digest
        || resource.fencing_generation < allocation.fencing_generation
        || (requirement.mode_ref != null && resource.current_mode_ref !== requirement.mode_ref)
        || (requirement.workspace_ref != null
          && resource.current_workspace_ref !== requirement.workspace_ref)
        || (allocation.ownership === "shared"
          && resource.active_shared_compatibility_ref !== requirement.compatibility_ref)) return false;
  }
  return true;
}

function findCurrentCredentialRecord(authorityState, credential, { allowExpired = false } = {}) {
  assertCredentialBrand(credential, authorityState);
  const state = readAuthorityState(authorityState);
  const record = state.reservations.find((entry) => entry.receipt.reservation_ref === credential.reservation_ref);
  if (!record || !ACTIVE_RECEIPT_STATES.has(record.receipt.state)
      || record.receipt.receipt_digest !== credential.receipt_digest
      || record.request.reservation_request_digest !== credential.reservation_request_digest) {
    throw reservationError("resource_reservation_credential_stale", "physical resource reservation credential is stale");
  }
  const privateFences = CREDENTIAL_PRIVATE.get(credential).resource_fences;
  if (hashCanonicalJson(privateFences) !== hashCanonicalJson(record.resource_fences)) {
    throw reservationError("resource_reservation_credential_stale", "physical resource reservation fence authority is stale");
  }
  const clock = samplePhysicalTrustedClock(authorityState.trusted_clock_port);
  if (!allowExpired && Date.parse(clock.trusted_utc_latest) >= Date.parse(record.receipt.expires_at)) {
    throw reservationError("resource_reservation_expired", "physical resource reservation has expired");
  }
  return { state, record, clock };
}

function assertCurrentPhysicalResourceReservationCredential(authority, credential, options = {}) {
  assertPhysicalResourceReservationAuthority(authority);
  assertClosedObject(options, "physical_resource_reservation_credential_options", [], ["allow_expired"]);
  const authorityState = AUTHORITY_PRIVATE.get(authority);
  assertAuthorityMutationReady(authorityState);
  const current = findCurrentCredentialRecord(authorityState, credential, {
    allowExpired: options.allow_expired === true,
  });
  if (!inventoryIsCurrent(current.state.inventory, current.clock)) {
    throw reservationError(
      "resource_inventory_expired",
      "physical resource inventory is no longer current for credential use",
    );
  }
  if (!recordHasLiveInventory(current.record, current.state.inventory)) {
    throw reservationError(
      "resource_inventory_binding_drift",
      "physical resource inventory no longer satisfies the credential allocation",
    );
  }
  return deepFreeze({
    version: RESOURCE_RESERVATION_CREDENTIAL_VERSION,
    reservation_ref: current.record.receipt.reservation_ref,
    receipt_digest: current.record.receipt.receipt_digest,
    state: current.record.receipt.state,
    effect_state: current.record.effect_state,
    allocation_plan_digest: current.record.allocation_plan_digest,
    fencing_semantics: RESOURCE_FENCING_SEMANTICS,
  });
}

function assertPhysicalResourceEffectAuthorizedNow(authority, credential) {
  assertPhysicalResourceReservationAuthority(authority);
  const authorityState = AUTHORITY_PRIVATE.get(authority);
  assertAuthorityMutationReady(authorityState);
  const current = findCurrentCredentialRecord(authorityState, credential, { allowExpired: false });
  if (current.record.receipt.state !== "held" || current.record.effect_state !== "started") {
    throw reservationError(
      "reservation_effect_not_started",
      "physical resource effect authority requires an exact started reservation",
    );
  }
  if (Date.parse(current.clock.trusted_utc_earliest)
        < Date.parse(current.record.request.effect_not_before)
      || Date.parse(current.clock.trusted_utc_latest)
        >= Date.parse(current.record.request.effect_deadline)) {
    throw reservationError(
      "reservation_effect_window_expired",
      "physical resource effect authority is outside the exact request window",
    );
  }
  if (!inventoryIsCurrent(current.state.inventory, current.clock)) {
    throw reservationError(
      "resource_inventory_expired",
      "physical resource effect authority requires current external inventory",
    );
  }
  if (!recordHasLiveInventory(current.record, current.state.inventory)) {
    throw reservationError(
      "resource_inventory_binding_drift",
      "physical resource effect authority no longer has its exact live allocation",
    );
  }
  const value = {
    version: RESOURCE_RESERVATION_CREDENTIAL_VERSION,
    reservation_ref: current.record.receipt.reservation_ref,
    receipt_digest: current.record.receipt.receipt_digest,
    reservation_request_digest: current.record.request.reservation_request_digest,
    node_id: current.record.request.node_id,
    contract_hash: current.record.request.contract_hash,
    source_graph_hash: current.record.request.source_graph_hash,
    session_nucleus_hash: current.record.request.session_nucleus_hash,
    experiment_ref: current.record.request.experiment_ref,
    attempt_ref: current.record.request.attempt_ref,
    execution_principal_ref: current.record.request.execution_principal_ref,
    resource_bundle_digest: current.record.request.resource_bundle_digest,
    allocation_plan_digest: current.record.allocation_plan_digest,
    allocation_digest: hashCanonicalJson(current.record.receipt.allocations),
    credential_binding_digest: credential.credential_binding_digest,
    fencing_semantics: RESOURCE_FENCING_SEMANTICS,
    effect_deadline: current.record.request.effect_deadline,
    reservation_expires_at: current.record.receipt.expires_at,
  };
  return deepFreeze({ ...value, effect_authorization_digest: hashCanonicalJson(value) });
}

function rebuildInventory(input, resources, generation, sample) {
  // Capacity/fence generations are broker-owned mutation state, but physical
  // health/mode/workspace freshness remains that of the exact external
  // inventory observation. Never manufacture a newer capture timestamp here.
  return normalizePhysicalResourceInventory({
    version: input.version,
    broker_ref: input.broker_ref,
    broker_epoch: input.broker_epoch,
    inventory_generation: generation,
    captured_at: input.captured_at,
    valid_from: input.valid_from,
    expires_at: input.expires_at,
    session_nucleus_hash: input.session_nucleus_hash,
    source_graph_hash: input.source_graph_hash,
    resources,
  });
}

function applyHoldToInventory(inventory, plan, sample) {
  const allocationsByResource = new Map();
  for (const allocation of plan.allocations) {
    if (!allocationsByResource.has(allocation.resource_ref)) allocationsByResource.set(allocation.resource_ref, []);
    allocationsByResource.get(allocation.resource_ref).push(allocation);
  }
  const resources = inventory.resources.map((resource) => {
    const allocations = allocationsByResource.get(resource.resource_ref);
    if (!allocations) return { ...resource };
    const used = allocations.reduce((sum, entry) => sum + entry.capacity_units, 0);
    const ownerships = new Set(allocations.map((entry) => entry.ownership));
    if (used > resource.available_capacity_units || ownerships.size !== 1) {
      throw reservationError("allocation_plan_capacity_drift", "allocation plan capacity drift under reservation mutation");
    }
    const ownership = allocations[0].ownership;
    if (ownership === "exclusive" && (allocations.length !== 1 || !resource.exclusive_available)) {
      throw reservationError("allocation_plan_exclusive_drift", "exclusive allocation drift under reservation mutation");
    }
    const compatibility = ownership === "shared" ? allocations[0].compatibility_ref : null;
    if (ownership === "shared" && allocations.some((entry) => entry.compatibility_ref !== compatibility)) {
      throw reservationError("allocation_plan_compatibility_drift", "shared allocation compatibility drift");
    }
    const next = {
      ...resource,
      available_capacity_units: resource.available_capacity_units - used,
      exclusive_available: false,
      fencing_generation: resource.fencing_generation + 1,
    };
    if (ownership === "shared") next.active_shared_compatibility_ref = compatibility;
    else delete next.active_shared_compatibility_ref;
    return next;
  });
  return rebuildInventory(inventory, resources, inventory.inventory_generation + 1, sample);
}

function activeCapacityByResource(records, excludedReservationRef = null) {
  const active = new Map();
  for (const record of records) {
    if (record.receipt.reservation_ref === excludedReservationRef
        || !ACTIVE_RECEIPT_STATES.has(record.receipt.state)) continue;
    for (const allocation of record.receipt.allocations) {
      const item = active.get(allocation.resource_ref) || { count: 0, compatibility_refs: new Set() };
      item.count += allocation.capacity_units;
      const requirement = record.bundle.requirements.find((entry) => entry.alias === allocation.alias);
      if (requirement && requirement.compatibility_ref) item.compatibility_refs.add(requirement.compatibility_ref);
      active.set(allocation.resource_ref, item);
    }
  }
  return active;
}

function releaseInventory(inventory, records, record, terminalState, sample) {
  const releasedByResource = new Map();
  for (const allocation of record.receipt.allocations) {
    releasedByResource.set(
      allocation.resource_ref,
      (releasedByResource.get(allocation.resource_ref) || 0) + allocation.capacity_units,
    );
  }
  const otherActive = activeCapacityByResource(records, record.receipt.reservation_ref);
  const resources = inventory.resources.map((resource) => {
    const released = releasedByResource.get(resource.resource_ref);
    if (!released) return { ...resource };
    const nextGeneration = resource.fencing_generation + 1;
    if (terminalState === "fenced" || terminalState === "quarantined") {
      const next = {
        ...resource,
        availability: terminalState === "quarantined" ? "quarantined" : "unavailable",
        available_capacity_units: 0,
        exclusive_available: false,
        fencing_generation: nextGeneration,
      };
      delete next.active_shared_compatibility_ref;
      return next;
    }
    // Releasing Bob's logical hold cannot convert an externally observed
    // unavailable/quarantined resource back into an available one. Preserve
    // the physical health observation and require an explicit fresh inventory
    // protocol to recover capacity.
    if (resource.availability !== "available") {
      const next = {
        ...resource,
        available_capacity_units: 0,
        exclusive_available: false,
        fencing_generation: nextGeneration,
      };
      delete next.active_shared_compatibility_ref;
      return next;
    }
    const available = resource.available_capacity_units + released;
    if (available > resource.total_capacity_units) {
      throw reservationError("resource_capacity_corrupt", "resource release would exceed total capacity");
    }
    const active = otherActive.get(resource.resource_ref);
    const next = {
      ...resource,
      availability: "available",
      available_capacity_units: available,
      exclusive_available: active == null && available === resource.total_capacity_units,
      fencing_generation: nextGeneration,
    };
    if (active == null) delete next.active_shared_compatibility_ref;
    else if (active.compatibility_refs.size === 1) {
      [next.active_shared_compatibility_ref] = active.compatibility_refs;
    } else {
      throw reservationError("resource_compatibility_corrupt", "active shared resource compatibility state is corrupt");
    }
    return next;
  });
  return rebuildInventory(inventory, resources, inventory.inventory_generation + 1, sample);
}

function mintResourceFences(plan) {
  const allocationsByResource = new Map();
  for (const allocation of plan.allocations) {
    if (!allocationsByResource.has(allocation.resource_ref)) allocationsByResource.set(allocation.resource_ref, []);
    allocationsByResource.get(allocation.resource_ref).push(allocation);
  }
  const fences = [];
  for (const resourceRef of plan.lock_order) {
    const bytes = crypto.randomBytes(RAW_FENCE_BYTES);
    const raw = bytes.toString("base64url");
    const digest = crypto.createHash("sha256").update(bytes).digest("hex");
    bytes.fill(0);
    const allocations = allocationsByResource.get(resourceRef);
    const generations = new Set(allocations.map((entry) => entry.expected_fencing_generation));
    if (generations.size !== 1) throw reservationError("allocation_plan_fencing_drift", "allocation plan fencing generation drift");
    fences.push(deepFreeze({
      resource_ref: resourceRef,
      fencing_generation: allocations[0].expected_fencing_generation,
      raw_fence: raw,
      fencing_token_hash: digest,
    }));
  }
  return Object.freeze(fences);
}

function makeReceipt(authorityState, request, bundle, inventory, plan, fences, sample) {
  const fenceByResource = new Map(fences.map((entry) => [entry.resource_ref, entry]));
  const requirements = new Map(bundle.requirements.map((entry) => [entry.alias, entry]));
  const issuedAtMs = Date.parse(sample.trusted_utc_earliest);
  const expiresAtMs = issuedAtMs + bundle.reservation_ttl_ms;
  const requiredThroughMs = Date.parse(request.effect_deadline) + bundle.cooldown_ms;
  if (expiresAtMs < requiredThroughMs) {
    throw reservationError(
      "reservation_ttl_insufficient",
      "resource bundle TTL cannot cover this request effect window and cooldown from trusted issuance",
    );
  }
  const allocations = plan.allocations.map((allocation) => {
    const requirement = requirements.get(allocation.alias);
    const fence = fenceByResource.get(allocation.resource_ref);
    if (!requirement || !fence
        || allocation.requirement_digest !== hashCanonicalJson(requirement)
        || allocation.expected_state_epoch_digest == null) {
      throw reservationError("allocation_plan_binding_drift", "allocation plan requirement binding drift");
    }
    return {
      alias: allocation.alias,
      resource_kind: allocation.resource_kind,
      resource_ref: allocation.resource_ref,
      ownership: allocation.ownership,
      capacity_units: allocation.capacity_units,
      state_epoch_digest: allocation.expected_state_epoch_digest,
      fencing_generation: fence.fencing_generation,
      fencing_token_hash: fence.fencing_token_hash,
    };
  });
  const receipt = normalizePhysicalReservationReceipt({
    version: PHYSICAL_RESERVATION_RECEIPT_VERSION,
    reservation_ref: `reservation:v1:${request.reservation_request_digest.slice(0, 32)}`,
    broker_ref: authorityState.broker_ref,
    broker_epoch: authorityState.broker_epoch,
    reservation_request_digest: request.reservation_request_digest,
    node_id: request.node_id,
    contract_hash: request.contract_hash,
    source_graph_hash: request.source_graph_hash,
    session_nucleus_hash: request.session_nucleus_hash,
    experiment_ref: request.experiment_ref,
    attempt_ref: request.attempt_ref,
    owner_principal_ref: request.owner_principal_ref,
    execution_principal_ref: request.execution_principal_ref,
    resource_bundle_digest: request.resource_bundle_digest,
    inventory_digest: inventory.inventory_digest,
    state: "held",
    sequence: 0,
    issued_at: new Date(issuedAtMs).toISOString(),
    updated_at: new Date(issuedAtMs).toISOString(),
    expires_at: new Date(expiresAtMs).toISOString(),
    allocations,
  });
  return assertReservationBindings(receipt, request, bundle);
}

function assertPlanBindings(plan, request, bundle, inventory) {
  if (!plan || plan.disposition !== "planned") {
    throw reservationError("resources_unschedulable", `physical resources are unschedulable: ${plan && plan.reason || "unknown"}`);
  }
  const exact = {
    reservation_request_digest: request.reservation_request_digest,
    node_id: request.node_id,
    contract_hash: request.contract_hash,
    source_graph_hash: request.source_graph_hash,
    session_nucleus_hash: request.session_nucleus_hash,
    resource_bundle_digest: bundle.resource_bundle_digest,
    inventory_digest: inventory.inventory_digest,
    broker_ref: inventory.broker_ref,
    broker_epoch: inventory.broker_epoch,
    inventory_generation: inventory.inventory_generation,
  };
  for (const [field, value] of Object.entries(exact)) {
    if (plan[field] !== value) throw reservationError("allocation_plan_binding_drift", `allocation plan ${field} binding drift`);
  }
  const expectedLockOrder = [...new Set(plan.allocations.map((entry) => entry.resource_ref))].sort();
  if (hashCanonicalJson(plan.lock_order) !== hashCanonicalJson(expectedLockOrder)) {
    throw reservationError("allocation_plan_lock_order_drift", "allocation plan total lock order drift");
  }
  if (plan.allocations.some((allocation) => allocation.mode_change || allocation.workspace_change)) {
    throw reservationError(
      "resource_setup_transition_required",
      "reservation cannot manufacture a planned mode/workspace transition without an externally observed setup protocol",
    );
  }
  if (plan.allocation_plan_digest !== hashCanonicalJson(Object.fromEntries(
    Object.entries(plan).filter(([field]) => field !== "allocation_plan_digest"),
  ))) {
    throw reservationError("allocation_plan_digest_drift", "allocation plan digest drift");
  }
  return plan;
}

function nextState(
  authorityState,
  state,
  inventory,
  records,
  inventoryAttestation = null,
  compactionUpdate = null,
) {
  const attestationGeneration = inventoryAttestation == null
    ? state.inventory_attestation_generation
    : inventoryAttestation.generation;
  const attestationDigest = inventoryAttestation == null
    ? state.inventory_attestation_digest
    : inventoryAttestation.digest;
  const attestationPriorDigest = inventoryAttestation == null
    ? state.inventory_attestation_prior_digest
    : inventoryAttestation.prior_digest;
  const attestationStateRevision = inventoryAttestation == null
    ? state.inventory_attestation_state_revision
    : inventoryAttestation.state_revision;
  const attestationStateDigest = inventoryAttestation == null
    ? state.inventory_attestation_state_digest
    : inventoryAttestation.state_digest;
  const attestationPriorInventoryDigest = inventoryAttestation == null
    ? state.inventory_attestation_prior_inventory_digest
    : inventoryAttestation.prior_inventory_digest;
  const attestedInventory = inventoryAttestation == null
    ? state.attested_inventory
    : inventoryAttestation.inventory;
  return normalizePhysicalResourceReservationState({
    version: RESOURCE_RESERVATION_STATE_VERSION,
    state_domain_digest: authorityState.state_domain_digest,
    broker_ref: authorityState.broker_ref,
    broker_epoch: authorityState.broker_epoch,
    revision: state.revision + 1,
    prior_state_digest: state.state_digest,
    inventory_attestation_generation: attestationGeneration,
    inventory_attestation_digest: attestationDigest,
    inventory_attestation_prior_digest: attestationPriorDigest,
    inventory_attestation_state_revision: attestationStateRevision,
    inventory_attestation_state_digest: attestationStateDigest,
    inventory_attestation_prior_inventory_digest: attestationPriorInventoryDigest,
    attested_inventory: attestedInventory,
    inventory,
    compaction_generation: compactionUpdate == null
      ? state.compaction_generation
      : compactionUpdate.generation,
    compaction_history_accumulator: compactionUpdate == null
      ? state.compaction_history_accumulator
      : compactionUpdate.accumulator,
    compaction_prior_accumulator: compactionUpdate == null
      ? state.compaction_prior_accumulator
      : compactionUpdate.prior_accumulator,
    compaction_source_checkpoint_generation: compactionUpdate == null
      ? state.compaction_source_checkpoint_generation
      : compactionUpdate.source_checkpoint_generation,
    compaction_source_checkpoint_digest: compactionUpdate == null
      ? state.compaction_source_checkpoint_digest
      : compactionUpdate.source_checkpoint_digest,
    compaction_source_state_revision: compactionUpdate == null
      ? state.compaction_source_state_revision
      : compactionUpdate.source_state_revision,
    compaction_source_state_digest: compactionUpdate == null
      ? state.compaction_source_state_digest
      : compactionUpdate.source_state_digest,
    compaction_batch_record_digests: compactionUpdate == null
      ? state.compaction_batch_record_digests
      : compactionUpdate.batch_record_digests,
    compaction_tombstone_set_digest: compactionUpdate == null
      ? state.compaction_tombstone_set_digest
      : compactionUpdate.tombstone_set_digest,
    compacted_record_count: compactionUpdate == null
      ? state.compacted_record_count
      : compactionUpdate.compacted_record_count,
    reservation_tombstones: compactionUpdate == null
      ? state.reservation_tombstones
      : compactionUpdate.tombstones,
    reservations: records,
  }, authorityState);
}

function assertInventoryRefreshSuccessor(prior, next) {
  if (next.inventory_generation !== prior.inventory_generation + 1) {
    throw reservationError(
      "resource_inventory_generation_non_successor",
      "signed physical resource inventory must be the exact generation successor",
    );
  }
  if (Date.parse(next.captured_at) < Date.parse(prior.captured_at)) {
    throw reservationError(
      "resource_inventory_time_rollback",
      "signed physical resource inventory capture time moved backwards",
    );
  }
  const priorByRef = new Map(prior.resources.map((resource) => [resource.resource_ref, resource]));
  const nextByRef = new Map(next.resources.map((resource) => [resource.resource_ref, resource]));
  if (priorByRef.size !== nextByRef.size
      || [...priorByRef.keys()].some((resourceRef) => !nextByRef.has(resourceRef))) {
    throw reservationError(
      "resource_inventory_identity_set_drift",
      "signed physical resource inventory cannot add or delete enrolled resource identities",
    );
  }
  for (const [resourceRef, priorResource] of priorByRef) {
    const nextResource = nextByRef.get(resourceRef);
    if (nextResource.resource_kind !== priorResource.resource_kind
        || nextResource.total_capacity_units !== priorResource.total_capacity_units) {
      throw reservationError(
        "resource_inventory_identity_binding_drift",
        "signed physical resource inventory changed immutable resource kind or capacity",
      );
    }
    if (nextResource.fencing_generation < priorResource.fencing_generation) {
      throw reservationError(
        "resource_inventory_fencing_rollback",
        "signed physical resource inventory fencing generation moved backwards",
      );
    }
  }
  return next;
}

function reconcileAttestedInventoryWithReservations(observedInventory, records) {
  const activeByResource = new Map();
  for (const record of records) {
    if (!ACTIVE_RECEIPT_STATES.has(record.receipt.state)) continue;
    for (const allocation of record.receipt.allocations) {
      const requirement = record.bundle.requirements.find((entry) => entry.alias === allocation.alias);
      const active = activeByResource.get(allocation.resource_ref) || {
        capacity_units: 0,
        ownerships: new Set(),
        compatibility_refs: new Set(),
        max_fencing_generation: 0,
      };
      active.capacity_units += allocation.capacity_units;
      active.ownerships.add(allocation.ownership);
      if (requirement && requirement.compatibility_ref) {
        active.compatibility_refs.add(requirement.compatibility_ref);
      }
      active.max_fencing_generation = Math.max(
        active.max_fencing_generation,
        allocation.fencing_generation,
      );
      activeByResource.set(allocation.resource_ref, active);
    }
  }
  const resources = observedInventory.resources.map((resource) => {
    const active = activeByResource.get(resource.resource_ref);
    if (active == null) return { ...resource };
    if (active.capacity_units > resource.total_capacity_units
        || active.ownerships.size !== 1) {
      throw reservationError(
        "resource_inventory_active_hold_conflict",
        "signed physical resource observation cannot represent the durable active holds",
      );
    }
    const next = {
      ...resource,
      available_capacity_units: Math.max(
        0,
        resource.available_capacity_units - active.capacity_units,
      ),
      exclusive_available: false,
      fencing_generation: Math.max(
        resource.fencing_generation,
        active.max_fencing_generation,
      ),
    };
    if (active.ownerships.has("shared")) {
      if (active.compatibility_refs.size !== 1) {
        throw reservationError(
          "resource_inventory_active_hold_conflict",
          "signed physical resource observation conflicts with shared hold compatibility",
        );
      }
      const [compatibilityRef] = active.compatibility_refs;
      if (resource.active_shared_compatibility_ref != null
          && resource.active_shared_compatibility_ref !== compatibilityRef) {
        throw reservationError(
          "resource_inventory_active_hold_conflict",
          "signed physical resource observation reports incompatible shared occupancy",
        );
      }
      next.active_shared_compatibility_ref = compatibilityRef;
    } else {
      delete next.active_shared_compatibility_ref;
    }
    return next;
  });
  return rebuildInventory(
    observedInventory,
    resources,
    observedInventory.inventory_generation,
    null,
  );
}

function refreshPhysicalResourceInventory(authority, signedAttestationInput) {
  assertPhysicalResourceReservationAuthority(authority);
  const authorityState = AUTHORITY_PRIVATE.get(authority);
  assertAuthorityMutationReady(authorityState);
  if (authorityState.inventory_refresh_in_flight) {
    throw reservationError(
      "resource_inventory_refresh_reentrant",
      "physical resource inventory refresh is already in progress",
    );
  }
  authorityState.inventory_refresh_in_flight = true;
  try {
    const state = readAuthorityState(authorityState);
    const sample = samplePhysicalTrustedClock(authorityState.trusted_clock_port);
    const expected = {
      reservation_authority_digest: authorityState.reservation_authority_digest,
      state_domain_digest: authorityState.state_domain_digest,
      broker_ref: authorityState.broker_ref,
      broker_epoch: authorityState.broker_epoch,
      session_binding_digest: authorityState.session_binding_digest,
      session_nucleus_hash: authorityState.session_nucleus_hash,
      source_graph_hash: authorityState.source_graph_hash,
      expected_state_revision: state.revision,
      expected_state_digest: state.state_digest,
      prior_inventory_digest: state.inventory.inventory_digest,
      expected_inventory_generation: state.inventory.inventory_generation + 1,
      expected_attestation_generation: state.inventory_attestation_generation + 1,
      prior_attestation_digest: state.inventory_attestation_digest,
    };
    let document;
    try {
      document = verifySignedPhysicalResourceInventoryAttestation(signedAttestationInput, {
        trust_port: authorityState.inventory_trust_port,
        trusted_clock_sample: sample,
        expected,
      });
      document = verifySignedPhysicalResourceInventoryAttestation(document, {
        trust_port: authorityState.inventory_trust_port,
        trusted_clock_sample: samplePhysicalTrustedClock(authorityState.trusted_clock_port),
        expected,
      });
    } catch (cause) {
      throw reservationError(
        "resource_inventory_attestation_invalid",
        "signed physical resource inventory attestation is invalid or stale",
        cause,
      );
    }
    const observedInventory = assertInventoryRefreshSuccessor(
      state.inventory,
      document.payload.inventory,
    );
    const inventory = reconcileAttestedInventoryWithReservations(
      observedInventory,
      state.reservations,
    );
    const candidate = nextState(
      authorityState,
      state,
      inventory,
      state.reservations,
      {
        generation: document.payload.attestation_generation,
        digest: document.signed_document_digest,
        prior_digest: document.payload.prior_attestation_digest,
        state_revision: document.payload.expected_state_revision,
        state_digest: document.payload.expected_state_digest,
        prior_inventory_digest: document.payload.prior_inventory_digest,
        inventory: document.payload.inventory,
      },
    );
    authorityState.inventory_refresh_committing = true;
    let committed;
    try {
      committed = callCas(authorityState, state, candidate);
    } finally {
      authorityState.inventory_refresh_committing = false;
    }
    if (!committed.committed) {
      throw reservationError(
        "resource_inventory_refresh_conflict",
        "signed physical resource inventory lost its exact CAS state binding",
      );
    }
    return deepFreeze({
      version: RESOURCE_RESERVATION_AUTHORITY_VERSION,
      state_revision: committed.state.revision,
      state_digest: committed.state.state_digest,
      inventory_generation: committed.state.inventory.inventory_generation,
      inventory_digest: committed.state.inventory.inventory_digest,
      inventory_attestation_generation: committed.state.inventory_attestation_generation,
      inventory_attestation_digest: committed.state.inventory_attestation_digest,
    });
  } finally {
    authorityState.inventory_refresh_committing = false;
    authorityState.inventory_refresh_in_flight = false;
  }
}

function reservationSafetyStateResolved(record, state) {
  if (!["fenced", "quarantined"].includes(record.receipt.state)) return true;
  if (state.attested_inventory == null) return false;
  const observedByRef = new Map(state.attested_inventory.resources.map((resource) => [
    resource.resource_ref,
    resource,
  ]));
  return record.receipt.allocations.every((allocation) => {
    const observed = observedByRef.get(allocation.resource_ref);
    return observed != null
      && observed.availability === "available"
      && observed.fencing_generation > allocation.fencing_generation;
  });
}

function compactionCheckpointExpected(authorityState, state) {
  return {
    reservation_authority_digest: authorityState.reservation_authority_digest,
    state_domain_digest: authorityState.state_domain_digest,
    broker_ref: authorityState.broker_ref,
    broker_epoch: authorityState.broker_epoch,
    session_binding_digest: authorityState.session_binding_digest,
    session_nucleus_hash: authorityState.session_nucleus_hash,
    source_graph_hash: authorityState.source_graph_hash,
    state,
  };
}

function recordVerifiedCompactionCheckpoint(authorityState, state, checkpoint) {
  authorityState.restart_checkpoint_generation = checkpoint.current_checkpoint_generation;
  authorityState.restart_checkpoint_digest = checkpoint.current_signed_checkpoint_digest;
  authorityState.checkpoint_verified_revision = state.revision;
  authorityState.checkpoint_verified_state_digest = state.state_digest;
  authorityState.checkpoint_head_state = "verified_exact_head_at_authority_operation";
}

function compactPhysicalResourceReservationHistory(authority, input = {}) {
  assertPhysicalResourceReservationAuthority(authority);
  assertClosedObject(input, "physical_resource_reservation_history_compaction", [
    "checkpoint_chain",
  ]);
  const authorityState = AUTHORITY_PRIVATE.get(authority);
  if (authorityState.compaction_in_flight) {
    throw reservationError(
      "reservation_history_compaction_reentrant",
      "physical resource reservation history compaction cannot re-enter itself",
    );
  }
  assertAuthorityMutationReady(authorityState);
  authorityState.compaction_in_flight = true;
  try {
    const state = readAuthorityState(authorityState);
    const expected = compactionCheckpointExpected(authorityState, state);
    let checkpoint;
    try {
      checkpoint = verifySignedPhysicalResourceReservationCheckpointChain(
        input.checkpoint_chain,
        {
          trust_port: authorityState.checkpoint_trust_port,
          trusted_clock_sample: samplePhysicalTrustedClock(authorityState.trusted_clock_port),
          expected,
        },
      );
    } catch (cause) {
      throw reservationError(
        "reservation_history_compaction_checkpoint_invalid",
        "reservation history compaction requires an exact externally anchored current checkpoint",
        cause,
      );
    }
    const middleState = readAuthorityState(authorityState);
    if (middleState.state_digest !== state.state_digest) {
      throw reservationError(
        "reservation_history_compaction_checkpoint_race",
        "reservation state changed during the first compaction checkpoint verification",
      );
    }
    try {
      checkpoint = verifySignedPhysicalResourceReservationCheckpointChain(
        checkpoint.chain,
        {
          trust_port: authorityState.checkpoint_trust_port,
          trusted_clock_sample: samplePhysicalTrustedClock(authorityState.trusted_clock_port),
          expected,
        },
      );
    } catch (cause) {
      throw reservationError(
        "reservation_history_compaction_checkpoint_invalid",
        "reservation history compaction checkpoint lost current external trust",
        cause,
      );
    }
    const exactState = readAuthorityState(authorityState);
    if (exactState.state_digest !== state.state_digest) {
      throw reservationError(
        "reservation_history_compaction_checkpoint_race",
        "reservation state changed during the second compaction checkpoint verification",
      );
    }
    recordVerifiedCompactionCheckpoint(authorityState, state, checkpoint);

    const eligible = [];
    let retainedActiveCount = 0;
    let retainedSafetyCount = 0;
    for (const record of state.reservations) {
      if (ACTIVE_RECEIPT_STATES.has(record.receipt.state)) {
        retainedActiveCount += 1;
      } else if (!reservationSafetyStateResolved(record, state)) {
        retainedSafetyCount += 1;
      } else {
        eligible.push(record);
      }
    }
    if (eligible.length === 0) {
      return deepFreeze({
        version: RESOURCE_RESERVATION_AUTHORITY_VERSION,
        idempotent: true,
        compacted_record_count: 0,
        retained_active_record_count: retainedActiveCount,
        retained_unresolved_safety_record_count: retainedSafetyCount,
        state_revision: state.revision,
        state_digest: state.state_digest,
        compaction_generation: state.compaction_generation,
        compaction_history_accumulator: state.compaction_history_accumulator,
        reservation_tombstone_count: state.reservation_tombstones.length,
      });
    }

    const newTombstones = eligible.map((record) => makeReservationTombstone(record));
    const generalNewCount = newTombstones.filter((entry) => (
      !["fenced", "quarantined"].includes(entry.receipt.state)
    )).length;
    const existingGeneralCount = state.reservation_tombstones.filter((entry) => (
      !["fenced", "quarantined"].includes(entry.receipt.state)
    )).length;
    if (state.reservation_tombstones.length + newTombstones.length
          > MAX_RESERVATION_TOMBSTONES
        || existingGeneralCount + generalNewCount > MAX_GENERAL_RESERVATION_TOMBSTONES) {
      throw reservationError(
        "reservation_history_tombstone_capacity_exhausted",
        "bounded reservation tombstone capacity is exhausted; no history was compacted",
      );
    }
    const tombstones = [...state.reservation_tombstones, ...newTombstones]
      .sort((left, right) => compareCodeUnits(
        left.receipt.reservation_ref,
        right.receipt.reservation_ref,
      ));
    const batchRecordDigests = newTombstones
      .map((entry) => entry.source_record_digest)
      .sort(compareCodeUnits);
    const tombstoneSetDigest = reservationTombstoneSetDigest(tombstones);
    const compactionGeneration = state.compaction_generation + 1;
    const compactedRecordCount = state.compacted_record_count + newTombstones.length;
    const sourceCheckpointGeneration = checkpoint.current_checkpoint_generation;
    const sourceCheckpointDigest = checkpoint.current_signed_checkpoint_digest;
    const accumulator = physicalResourceReservationCompactionAccumulatorDigest({
      compaction_generation: compactionGeneration,
      prior_accumulator: state.compaction_history_accumulator,
      compacted_record_digests: batchRecordDigests,
      source_checkpoint_generation: sourceCheckpointGeneration,
      source_checkpoint_digest: sourceCheckpointDigest,
      source_state_revision: state.revision,
      source_state_digest: state.state_digest,
      tombstone_set_digest: tombstoneSetDigest,
      tombstone_count: tombstones.length,
      compacted_record_count: compactedRecordCount,
    });
    const eligibleRefs = new Set(eligible.map((record) => record.receipt.reservation_ref));
    const retainedRecords = state.reservations.filter((record) => (
      !eligibleRefs.has(record.receipt.reservation_ref)
    ));
    const candidate = nextState(
      authorityState,
      state,
      state.inventory,
      retainedRecords,
      null,
      {
        generation: compactionGeneration,
        accumulator,
        prior_accumulator: state.compaction_history_accumulator,
        source_checkpoint_generation: sourceCheckpointGeneration,
        source_checkpoint_digest: sourceCheckpointDigest,
        source_state_revision: state.revision,
        source_state_digest: state.state_digest,
        batch_record_digests: batchRecordDigests,
        tombstone_set_digest: tombstoneSetDigest,
        compacted_record_count: compactedRecordCount,
        tombstones,
      },
    );
    authorityState.compaction_committing = true;
    let committed;
    try {
      committed = callCas(authorityState, state, candidate);
    } finally {
      authorityState.compaction_committing = false;
    }
    if (!committed.committed) {
      throw reservationError(
        "reservation_history_compaction_conflict",
        "reservation history compaction lost its exact checkpoint-bound CAS",
      );
    }
    return deepFreeze({
      version: RESOURCE_RESERVATION_AUTHORITY_VERSION,
      idempotent: false,
      compacted_record_count: newTombstones.length,
      retained_active_record_count: retainedActiveCount,
      retained_unresolved_safety_record_count: retainedSafetyCount,
      state_revision: committed.state.revision,
      state_digest: committed.state.state_digest,
      compaction_generation: committed.state.compaction_generation,
      compaction_history_accumulator: committed.state.compaction_history_accumulator,
      reservation_tombstone_count: committed.state.reservation_tombstones.length,
      source_checkpoint_generation: sourceCheckpointGeneration,
      source_checkpoint_digest: sourceCheckpointDigest,
    });
  } finally {
    authorityState.compaction_committing = false;
    authorityState.compaction_in_flight = false;
  }
}

function sameAttemptBudgetDomain(record, request) {
  const prior = record.request || record;
  return prior.node_id === request.node_id
    && prior.contract_hash === request.contract_hash
    && prior.source_graph_hash === request.source_graph_hash
    && prior.session_nucleus_hash === request.session_nucleus_hash
    && prior.resource_bundle_digest === request.resource_bundle_digest;
}

function assertAttemptBudgetAvailable(state, request, bundle) {
  const domainRecords = [...state.reservations, ...state.reservation_tombstones]
    .filter((record) => sameAttemptBudgetDomain(record, request));
  if (domainRecords.some((record) => (
    (record.request == null ? record.attempt_ref : record.request.attempt_ref) === request.attempt_ref
  ))) {
    throw reservationError(
      "reservation_attempt_identity_conflict",
      "physical attempt_ref is already bound within this resource budget domain",
    );
  }
  const consumed = domainRecords.filter((record) => (
    record.request == null
      ? record.attempt_budget_consumed
      : (record.effect_state !== "not_started"
        || (ACTIVE_RECEIPT_STATES.has(record.receipt.state) && record.effect_state === "not_started")
        || ["unknown_effect", "quarantined"].includes(record.receipt.terminal_disposition))
  )).length;
  if (consumed >= bundle.attempt_budget) {
    throw reservationError(
      "resource_attempt_budget_exhausted",
      "physical resource bundle attempt budget is exhausted for this exact node/contract/bundle domain",
    );
  }
}

function reservePhysicalResources(authority, requestInput) {
  assertPhysicalResourceReservationAuthority(authority);
  const authorityState = AUTHORITY_PRIVATE.get(authority);
  assertAuthorityMutationReady(authorityState);
  const request = normalizePhysicalReservationRequest(requestInput);
  if (request.source_graph_hash !== authorityState.source_graph_hash
      || request.session_nucleus_hash !== authorityState.session_nucleus_hash) {
    throw reservationError("reservation_authority_binding_drift", "reservation request graph/nucleus binding drift");
  }
  const bundle = resolveBundle(authorityState.bundle_resolver_port, request.resource_bundle_digest, request);
  for (let attempt = 0; attempt < MAX_CAS_CONFLICT_RETRIES; attempt += 1) {
    const state = readAuthorityState(authorityState);
    const duplicate = findRequestRecord(state, request);
    if (duplicate) return publicReservationResult(authorityState, assertExactDuplicate(duplicate, request), true);
    assertAttemptBudgetAvailable(state, request, bundle);
    if (state.reservations.length >= MAX_RESERVATIONS) {
      throw reservationError("reservation_capacity_exhausted", "physical reservation state capacity is exhausted");
    }
    const plan = assertPlanBindings(
      planPhysicalResourceBundle(bundle, request, state.inventory, {
        trusted_clock_port: authorityState.trusted_clock_port,
      }),
      request,
      bundle,
      state.inventory,
    );
    // The planner sampled a private clock, but reservation issuance and CAS
    // get a fresh post-plan sample so time spent planning cannot cross a
    // deadline unnoticed.
    const sample = samplePhysicalTrustedClock(authorityState.trusted_clock_port);
    if (Date.parse(sample.trusted_utc_latest) >= Date.parse(request.effect_deadline)) {
      throw reservationError("reservation_effect_window_expired", "reservation effect deadline elapsed during planning");
    }
    const fences = mintResourceFences(plan);
    const receipt = makeReceipt(authorityState, request, bundle, state.inventory, plan, fences, sample);
    const heldInventory = applyHoldToInventory(state.inventory, plan, sample);
    const record = normalizeReservationRecord({
      version: RESOURCE_RESERVATION_RECORD_VERSION,
      request,
      bundle,
      allocation_plan_digest: plan.allocation_plan_digest,
      lock_order: plan.lock_order,
      receipt,
      effect_state: "not_started",
      resource_fences: fences,
    });
    const candidate = nextState(authorityState, state, heldInventory, [...state.reservations, record]);
    const committed = callCas(authorityState, state, candidate);
    if (committed.committed) return publicReservationResult(authorityState, record, false);
    const winner = findRequestRecord(committed.state, request);
    if (winner) return publicReservationResult(authorityState, assertExactDuplicate(winner, request), true);
    // A definitive false CAS means another complete transaction won. Re-read,
    // replan, and mint fresh fences; no partial allocation can have escaped.
  }
  throw reservationError("reservation_cas_contention", "physical reservation CAS contention exceeded retry budget");
}

function transitionReceipt(record, state, disposition, sample, cleanupHandoffRef = null) {
  const base = {
    ...record.receipt,
    state,
    sequence: record.receipt.sequence + 1,
    updated_at: sample.trusted_utc_earliest,
  };
  delete base.receipt_digest;
  delete base.closed_at;
  delete base.terminal_disposition;
  delete base.cleanup_handoff_ref;
  if (state === "cleanup_pending") base.cleanup_handoff_ref = cleanupHandoffRef;
  if (!["held", "cleanup_pending"].includes(state)) {
    base.closed_at = base.updated_at;
    base.terminal_disposition = disposition;
  }
  return normalizePhysicalReservationReceipt(base);
}

function mutateCredentialRecord(authority, credential, mutation, { allowExpired = true } = {}) {
  assertPhysicalResourceReservationAuthority(authority);
  const authorityState = AUTHORITY_PRIVATE.get(authority);
  assertAuthorityMutationReady(authorityState);
  for (let attempt = 0; attempt < MAX_CAS_CONFLICT_RETRIES; attempt += 1) {
    const current = findCurrentCredentialRecord(authorityState, credential, { allowExpired });
    const outcome = mutation(current.record, current.clock, current.state);
    const records = outcome.records || current.state.reservations.map((entry) => (
      entry.receipt.reservation_ref === current.record.receipt.reservation_ref ? outcome.record : entry
    ));
    const candidate = nextState(authorityState, current.state, outcome.inventory, records);
    const committed = callCas(authorityState, current.state, candidate);
    if (committed.committed) return publicReservationResult(authorityState, outcome.record, false);
    const observed = committed.state.reservations.find((entry) => (
      entry.receipt.reservation_ref === credential.reservation_ref
    ));
    if (!observed || observed.receipt.receipt_digest !== credential.receipt_digest) {
      throw reservationError("resource_reservation_credential_stale", "reservation changed during atomic transition");
    }
  }
  throw reservationError("reservation_cas_contention", "physical reservation transition contention exceeded retry budget");
}

function inventoryWithoutResourceChange(inventory, sample) {
  return inventory;
}

function markPhysicalResourceEffectStarted(authority, credential) {
  return mutateCredentialRecord(authority, credential, (record, sample, state) => {
    if (record.receipt.state !== "held" || record.effect_state !== "not_started") {
      throw reservationError("reservation_effect_already_started", "physical reservation effect is not startable");
    }
    if (Date.parse(sample.trusted_utc_earliest) < Date.parse(record.request.effect_not_before)) {
      throw reservationError("reservation_effect_not_yet_valid", "physical reservation effect window has not opened");
    }
    if (Date.parse(sample.trusted_utc_latest) >= Date.parse(record.request.effect_deadline)
        || Date.parse(sample.trusted_utc_latest) >= Date.parse(record.receipt.expires_at)) {
      throw reservationError("reservation_effect_window_expired", "physical reservation effect window has expired");
    }
    if (!inventoryIsCurrent(state.inventory, sample)) {
      throw reservationError("resource_inventory_expired", "physical resource inventory is no longer current");
    }
    if (!recordHasLiveInventory(record, state.inventory)) {
      throw reservationError("resource_inventory_binding_drift", "physical resource inventory no longer satisfies the held allocation");
    }
    return {
      record: normalizeReservationRecord({
        ...record,
        receipt: transitionReceipt(record, "held", null, sample),
        effect_state: "started",
        effect_started_at: sample.trusted_utc_earliest,
      }),
      inventory: inventoryWithoutResourceChange(state.inventory, sample),
    };
  }, { allowExpired: false });
}

function beginPhysicalResourceCleanup(authority, credential, cleanupHandoffRefInput) {
  const cleanupHandoffRef = normalizeOpaqueRef(
    cleanupHandoffRefInput,
    "physical_resource_cleanup.cleanup_handoff_ref",
    { prefix: "cleanup-handoff" },
  );
  return mutateCredentialRecord(authority, credential, (record, sample, state) => {
    if (record.receipt.state !== "held" || record.effect_state !== "started") {
      throw reservationError("reservation_cleanup_invalid_state", "physical reservation is not ready for cleanup");
    }
    const effectEndedAt = sample.trusted_utc_latest;
    const cooldownUntilMs = Date.parse(effectEndedAt) + record.bundle.cooldown_ms;
    if (cooldownUntilMs > Date.parse(record.receipt.expires_at)) {
      throw reservationError("reservation_cleanup_ttl_exceeded", "cleanup cooldown exceeds reservation TTL");
    }
    return {
      record: normalizeReservationRecord({
        ...record,
        receipt: transitionReceipt(record, "cleanup_pending", null, sample, cleanupHandoffRef),
        effect_state: "cleanup",
        effect_ended_at: effectEndedAt,
        cooldown_until: new Date(cooldownUntilMs).toISOString(),
      }),
      inventory: inventoryWithoutResourceChange(state.inventory, sample),
    };
  });
}

function completePhysicalResourceCleanup(authority, credential) {
  return mutateCredentialRecord(authority, credential, (record, sample, state) => {
    if (record.receipt.state !== "cleanup_pending" || record.effect_state !== "cleanup") {
      throw reservationError("reservation_cleanup_invalid_state", "physical reservation cleanup is not pending");
    }
    if (Date.parse(sample.trusted_utc_earliest) < Date.parse(record.cooldown_until)) {
      throw reservationError("reservation_cooldown_pending", "physical resource cooldown has not elapsed");
    }
    const terminalReceipt = transitionReceipt(record, "released", "cleanup_confirmed", sample);
    const terminalRecord = normalizeReservationRecord({
      ...record,
      receipt: terminalReceipt,
      resource_fences: [],
    });
    return {
      record: terminalRecord,
      inventory: releaseInventory(state.inventory, state.reservations, record, "released", sample),
    };
  });
}

function closeBeforeEffect(authority, credential, kind) {
  const details = {
    cancel: ["released", "cancelled_before_effect"],
    preempt: ["released", "preempted_before_effect"],
    expire: ["released", "expired_before_effect"],
  }[kind];
  return mutateCredentialRecord(authority, credential, (record, sample, state) => {
    if (record.receipt.state !== "held" || record.effect_state !== "not_started") {
      throw reservationError("reservation_effect_already_started", `${kind} is forbidden after physical effect start`);
    }
    if (kind !== "expire"
        && (Date.parse(sample.trusted_utc_latest) >= Date.parse(record.request.effect_deadline)
          || Date.parse(sample.trusted_utc_latest) >= Date.parse(record.receipt.expires_at))) {
      throw reservationError("resource_reservation_expired", "expired reservation requires the explicit expiry transition");
    }
    if (kind === "preempt" && record.bundle.preemption_policy !== "before_effect_only") {
      throw reservationError("reservation_preemption_forbidden", "resource bundle forbids preemption");
    }
    if (kind === "expire" && Date.parse(sample.trusted_utc_latest) < Date.parse(record.request.effect_deadline)
        && Date.parse(sample.trusted_utc_latest) < Date.parse(record.receipt.expires_at)) {
      throw reservationError("reservation_not_expired", "physical reservation has not expired");
    }
    const terminalReceipt = transitionReceipt(record, details[0], details[1], sample);
    const terminalRecord = normalizeReservationRecord({
      ...record,
      receipt: terminalReceipt,
      resource_fences: [],
    });
    return {
      record: terminalRecord,
      inventory: releaseInventory(state.inventory, state.reservations, record, details[0], sample),
    };
  });
}

function cancelPhysicalResourceReservation(authority, credential) {
  return closeBeforeEffect(authority, credential, "cancel");
}

function preemptPhysicalResourceReservation(authority, credential) {
  return closeBeforeEffect(authority, credential, "preempt");
}

function expirePhysicalResourceReservation(authority, credential) {
  return closeBeforeEffect(authority, credential, "expire");
}

function terminalSafetyTransition(authority, credential, stateName) {
  return mutateCredentialRecord(authority, credential, (record, sample, state) => {
    const disposition = stateName === "quarantined" ? "quarantined" : "unknown_effect";
    // A fence/quarantine is a resource-level safety action. Close the entire
    // connected component of active reservations so a compatible shared
    // holder cannot retain authority over a now-unavailable resource.
    const affectedResources = new Set(record.receipt.allocations.map((entry) => entry.resource_ref));
    const affectedReservations = new Set([record.receipt.reservation_ref]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const candidate of state.reservations) {
        if (!ACTIVE_RECEIPT_STATES.has(candidate.receipt.state)
            || affectedReservations.has(candidate.receipt.reservation_ref)
            || !candidate.receipt.allocations.some((entry) => affectedResources.has(entry.resource_ref))) continue;
        affectedReservations.add(candidate.receipt.reservation_ref);
        for (const allocation of candidate.receipt.allocations) {
          if (!affectedResources.has(allocation.resource_ref)) {
            affectedResources.add(allocation.resource_ref);
            changed = true;
          }
        }
        changed = true;
      }
    }
    let terminalRecord = null;
    const records = state.reservations.map((candidate) => {
      if (!affectedReservations.has(candidate.receipt.reservation_ref)) return candidate;
      const closed = normalizeReservationRecord({
        ...candidate,
        receipt: transitionReceipt(candidate, stateName, disposition, sample),
        resource_fences: [],
      });
      if (candidate.receipt.reservation_ref === record.receipt.reservation_ref) terminalRecord = closed;
      return closed;
    });
    const resources = state.inventory.resources.map((resource) => {
      if (!affectedResources.has(resource.resource_ref)) return { ...resource };
      const next = {
        ...resource,
        availability: stateName === "quarantined" ? "quarantined" : "unavailable",
        available_capacity_units: 0,
        exclusive_available: false,
        fencing_generation: resource.fencing_generation + 1,
      };
      delete next.active_shared_compatibility_ref;
      return next;
    });
    return {
      record: terminalRecord,
      records,
      inventory: rebuildInventory(
        state.inventory,
        resources,
        state.inventory.inventory_generation + 1,
        sample,
      ),
    };
  });
}

function fencePhysicalResourceReservation(authority, credential) {
  return terminalSafetyTransition(authority, credential, "fenced");
}

function quarantinePhysicalResourceReservation(authority, credential) {
  return terminalSafetyTransition(authority, credential, "quarantined");
}

function rehydratePhysicalResourceReservationCredential(authority, input = {}) {
  assertPhysicalResourceReservationAuthority(authority);
  assertClosedObject(input, "physical_resource_reservation_rehydrate", [
    "reservation_ref",
    "receipt_digest",
  ]);
  const authorityState = AUTHORITY_PRIVATE.get(authority);
  assertAuthorityMutationReady(authorityState);
  const state = readAuthorityState(authorityState);
  const reservationRef = normalizeOpaqueRef(input.reservation_ref, "physical_resource_reservation_rehydrate.reservation_ref", { prefix: "reservation" });
  const receiptDigest = assertDigest(input.receipt_digest, "physical_resource_reservation_rehydrate.receipt_digest");
  const record = state.reservations.find((entry) => entry.receipt.reservation_ref === reservationRef);
  if (!record || !ACTIVE_RECEIPT_STATES.has(record.receipt.state)
      || record.receipt.receipt_digest !== receiptDigest) {
    throw reservationError("resource_reservation_credential_stale", "cannot rehydrate a stale or terminal reservation credential");
  }
  return makeCredential(authorityState, record);
}

function projectPhysicalResourceReservationInventory(authority) {
  assertPhysicalResourceReservationAuthority(authority);
  const state = readAuthorityState(AUTHORITY_PRIVATE.get(authority));
  return state.inventory;
}

function readPhysicalResourceReservationProjection(authority, reservationRefInput) {
  assertPhysicalResourceReservationAuthority(authority);
  const reservationRef = normalizeOpaqueRef(
    reservationRefInput,
    "physical_resource_reservation_projection.reservation_ref",
    { prefix: "reservation" },
  );
  const state = readAuthorityState(AUTHORITY_PRIVATE.get(authority));
  const record = state.reservations.find((entry) => entry.receipt.reservation_ref === reservationRef);
  if (record != null) return projectBrokerPhysicalResourceReservation(record);
  const tombstone = state.reservation_tombstones.find((entry) => (
    entry.receipt.reservation_ref === reservationRef
  ));
  return tombstone == null
    ? null
    : projectBrokerPhysicalResourceReservationTombstone(tombstone);
}

function physicalResourceReservationReadiness(authority) {
  assertPhysicalResourceReservationAuthority(authority);
  const state = AUTHORITY_PRIVATE.get(authority);
  // Do not call read_state, compare_and_set, the bundle resolver, or the clock.
  // A JavaScript callback brand cannot prove external crash durability.
  return deepFreeze({
    version: RESOURCE_RESERVATION_AUTHORITY_VERSION,
    production_ready: false,
    broker_ref: state.broker_ref,
    broker_epoch: state.broker_epoch,
    state_port_contract: RESOURCE_RESERVATION_STATE_PORT_CONTRACT,
    inventory_trust_port_contract: RESOURCE_INVENTORY_TRUST_PORT_CONTRACT,
    checkpoint_trust_port_contract: RESOURCE_CHECKPOINT_TRUST_PORT_CONTRACT,
    durability_assurance: "caller_asserted_callback_unattested",
    live_writer_contract: "single-live-authority-exact-cas-successor-v1",
    history_compaction_contract: RESOURCE_RESERVATION_COMPACTION_CONTRACT,
    history_compaction_domain: RESOURCE_RESERVATION_COMPACTION_DOMAIN,
    restart_checkpoint_state: state.checkpoint_head_state,
    restart_checkpoint_generation: state.restart_checkpoint_generation,
    restart_checkpoint_digest: state.restart_checkpoint_digest,
    checkpoint_verified_revision: state.checkpoint_verified_revision,
    checkpoint_verified_state_digest: state.checkpoint_verified_state_digest,
    live_observed_revision: state.live_observed_revision,
    live_observed_state_digest: state.live_observed_state_digest,
    checkpoint_matches_live_head: state.checkpoint_verified_revision === state.live_observed_revision
      && state.checkpoint_verified_state_digest === state.live_observed_state_digest,
    reservation_history_capacity: {
      full_record_limit: MAX_RESERVATIONS,
      observed_full_record_count: state.live_full_record_count,
      tombstone_limit: MAX_RESERVATION_TOMBSTONES,
      observed_tombstone_count: state.live_tombstone_count,
      general_tombstone_limit: MAX_GENERAL_RESERVATION_TOMBSTONES,
      safety_tombstone_reserve: RESERVATION_TOMBSTONE_SAFETY_RESERVE,
      observed_compaction_generation: state.live_compaction_generation,
      overflow_disposition: "fail_closed_without_history_deletion_or_budget_reset",
    },
    trusted_clock_mode: state.trusted_clock_port.mode,
    fencing_semantics: RESOURCE_FENCING_SEMANTICS,
    mutation_state: state.ambiguous
      ? "ambiguous_fail_closed"
      : (state.mutations_enabled ? "available" : "checkpoint_refresh_required"),
    reason: state.ambiguous
      ? "external_cas_reconciliation_and_authority_restart_required"
      : (state.mutations_enabled
        ? (state.checkpoint_head_state === "stale_after_live_mutation"
          ? "live_exact_cas_successors_require_external_checkpoint_before_crash_restart"
          : "external_archival_os_isolation_linearizable_cas_and_monotonic_trust_services_unattested")
        : "signed_inventory_successor_requires_external_checkpoint_before_use"),
  });
}

function createPhysicalResourceReservationAuthority(input = {}) {
  assertClosedObject(input, "physical_resource_reservation_authority", [
    "state_port",
    "trusted_clock_port",
    "bundle_resolver_port",
    "inventory_trust_port",
    "checkpoint_trust_port",
    "restart_checkpoint_chain",
    "restart_inventory_attestation",
    "broker_ref",
    "broker_epoch",
    "source_graph_hash",
    "session_nucleus_hash",
  ]);
  const statePort = assertPhysicalResourceReservationStatePort(input.state_port);
  const trustedClockPort = assertPhysicalTrustedClockPort(input.trusted_clock_port);
  const bundleResolverPort = assertPhysicalResourceBundleResolverPort(input.bundle_resolver_port);
  const inventoryTrustPort = assertPhysicalResourceInventoryTrustPort(input.inventory_trust_port);
  const checkpointTrustPort = assertPhysicalResourceReservationCheckpointTrustPort(
    input.checkpoint_trust_port,
  );
  const authorityBinding = {
    state_domain_digest: statePort.state_domain_digest,
    broker_ref: input.broker_ref,
    broker_epoch: input.broker_epoch,
    session_nucleus_hash: input.session_nucleus_hash,
    source_graph_hash: input.source_graph_hash,
    state_port_id: statePort.port_id,
    trusted_clock_port_id: trustedClockPort.port_id,
    bundle_resolver_port_id: bundleResolverPort.port_id,
    inventory_trust_port_id: inventoryTrustPort.port_id,
    checkpoint_trust_port_id: checkpointTrustPort.port_id,
  };
  const reservationAuthorityDigest = physicalResourceReservationAuthorityDigest(authorityBinding);
  const authority = deepFreeze({
    version: RESOURCE_RESERVATION_AUTHORITY_VERSION,
    broker_ref: normalizeOpaqueRef(input.broker_ref, "physical_resource_reservation_authority.broker_ref", { prefix: "broker" }),
    broker_epoch: assertInteger(input.broker_epoch, "physical_resource_reservation_authority.broker_epoch", 1),
    source_graph_hash: assertDigest(input.source_graph_hash, "physical_resource_reservation_authority.source_graph_hash"),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, "physical_resource_reservation_authority.session_nucleus_hash"),
    state_port_id: statePort.port_id,
    trusted_clock_port_id: trustedClockPort.port_id,
    bundle_resolver_port_id: bundleResolverPort.port_id,
    inventory_trust_port_id: inventoryTrustPort.port_id,
    checkpoint_trust_port_id: checkpointTrustPort.port_id,
    reservation_authority_digest: reservationAuthorityDigest,
  });
  const privateState = {
    state_port: statePort,
    state_domain_digest: statePort.state_domain_digest,
    trusted_clock_port: trustedClockPort,
    bundle_resolver_port: bundleResolverPort,
    inventory_trust_port: inventoryTrustPort,
    checkpoint_trust_port: checkpointTrustPort,
    broker_ref: authority.broker_ref,
    broker_epoch: authority.broker_epoch,
    source_graph_hash: authority.source_graph_hash,
    session_nucleus_hash: authority.session_nucleus_hash,
    reservation_authority_digest: reservationAuthorityDigest,
    session_binding_digest: physicalResourceSessionBindingDigest({
      broker_ref: authority.broker_ref,
      broker_epoch: authority.broker_epoch,
      session_nucleus_hash: authority.session_nucleus_hash,
      source_graph_hash: authority.source_graph_hash,
    }),
    ambiguous: false,
    cas_in_flight: false,
    inventory_refresh_in_flight: false,
    inventory_refresh_committing: false,
    compaction_in_flight: false,
    compaction_committing: false,
    bootstrap_inventory_provisioning: false,
    mutations_enabled: false,
    last_revision: null,
    last_state_digest: null,
    last_inventory_generation: null,
    live_observed_revision: null,
    live_observed_state_digest: null,
    live_full_record_count: null,
    live_tombstone_count: null,
    live_compaction_generation: null,
    pending_successor: null,
    restart_checkpoint_generation: null,
    restart_checkpoint_digest: null,
    checkpoint_verified_revision: null,
    checkpoint_verified_state_digest: null,
    checkpoint_head_state: null,
  };
  // Restart admission is fail-closed: a live authority is not branded until an
  // externally anchored signed checkpoint chain binds the exact durable state
  // head and its terminal/replay/inventory lineage under the live clock.
  const initialState = readAuthorityState(privateState);
  const checkpointExpected = {
    reservation_authority_digest: reservationAuthorityDigest,
    state_domain_digest: statePort.state_domain_digest,
    broker_ref: authority.broker_ref,
    broker_epoch: authority.broker_epoch,
    session_binding_digest: privateState.session_binding_digest,
    session_nucleus_hash: authority.session_nucleus_hash,
    source_graph_hash: authority.source_graph_hash,
    state: initialState,
  };
  const sample = samplePhysicalTrustedClock(trustedClockPort);
  let checkpoint = verifySignedPhysicalResourceReservationCheckpointChain(
    input.restart_checkpoint_chain,
    {
      trust_port: checkpointTrustPort,
      trusted_clock_sample: sample,
      expected: checkpointExpected,
    },
  );
  checkpoint = verifySignedPhysicalResourceReservationCheckpointChain(
    checkpoint.chain,
    {
      trust_port: checkpointTrustPort,
      trusted_clock_sample: samplePhysicalTrustedClock(trustedClockPort),
      expected: checkpointExpected,
    },
  );
  const postCheckpointState = readAuthorityState(privateState);
  if (postCheckpointState.state_digest !== initialState.state_digest) {
    throw reservationError(
      "reservation_restart_checkpoint_race",
      "physical resource reservation state changed during restart checkpoint verification",
    );
  }
  privateState.restart_checkpoint_generation = checkpoint.current_checkpoint_generation;
  privateState.restart_checkpoint_digest = checkpoint.current_signed_checkpoint_digest;
  privateState.checkpoint_verified_revision = initialState.revision;
  privateState.checkpoint_verified_state_digest = initialState.state_digest;
  privateState.checkpoint_head_state = "verified_exact_head_at_authority_start";
  let normalizedRestartInventory;
  try {
    normalizedRestartInventory = normalizeSignedPhysicalResourceInventoryAttestation(
      input.restart_inventory_attestation,
    );
  } catch (cause) {
    throw reservationError(
      "reservation_restart_inventory_attestation_invalid",
      "physical resource reservation restart inventory is unattested, stale, or invalid",
      cause,
    );
  }
  const presentedInventoryGeneration =
    normalizedRestartInventory.payload.attestation_generation;
  const isUnattestedGenesis = initialState.inventory_attestation_generation === 0;
  const isExactCurrentAttestation = !isUnattestedGenesis
    && presentedInventoryGeneration === initialState.inventory_attestation_generation
    && normalizedRestartInventory.signed_document_digest
      === initialState.inventory_attestation_digest;
  const isSuccessorAttestation = !isUnattestedGenesis
    && presentedInventoryGeneration === initialState.inventory_attestation_generation + 1;
  if (!isUnattestedGenesis && !isExactCurrentAttestation && !isSuccessorAttestation) {
    throw reservationError(
      "reservation_restart_inventory_lineage_drift",
      "signed restart inventory is neither the durable current attestation nor its exact successor",
    );
  }
  const inventoryExpected = {
    reservation_authority_digest: reservationAuthorityDigest,
    state_domain_digest: statePort.state_domain_digest,
    broker_ref: authority.broker_ref,
    broker_epoch: authority.broker_epoch,
    session_binding_digest: privateState.session_binding_digest,
    session_nucleus_hash: authority.session_nucleus_hash,
    source_graph_hash: authority.source_graph_hash,
    expected_state_revision: isExactCurrentAttestation
      ? initialState.inventory_attestation_state_revision
      : initialState.revision,
    expected_state_digest: isExactCurrentAttestation
      ? initialState.inventory_attestation_state_digest
      : initialState.state_digest,
    prior_inventory_digest: isExactCurrentAttestation
      ? initialState.inventory_attestation_prior_inventory_digest
      : initialState.inventory.inventory_digest,
    expected_inventory_generation: isSuccessorAttestation
      ? initialState.inventory.inventory_generation + 1
      : (isExactCurrentAttestation
        ? initialState.attested_inventory.inventory_generation
        : initialState.inventory.inventory_generation),
    expected_attestation_generation: isExactCurrentAttestation
      ? initialState.inventory_attestation_generation
      : initialState.inventory_attestation_generation + 1,
    prior_attestation_digest: isExactCurrentAttestation
      ? initialState.inventory_attestation_prior_digest
      : initialState.inventory_attestation_digest,
  };
  let inventoryDocument;
  try {
    inventoryDocument = verifySignedPhysicalResourceInventoryAttestation(
      normalizedRestartInventory,
      {
        trust_port: inventoryTrustPort,
        trusted_clock_sample: samplePhysicalTrustedClock(trustedClockPort),
        expected: inventoryExpected,
        historical: true,
      },
    );
    inventoryDocument = verifySignedPhysicalResourceInventoryAttestation(
      inventoryDocument,
      {
        trust_port: inventoryTrustPort,
        trusted_clock_sample: samplePhysicalTrustedClock(trustedClockPort),
        expected: inventoryExpected,
        historical: true,
      },
    );
  } catch (cause) {
    throw reservationError(
      "reservation_restart_inventory_attestation_invalid",
      "physical resource reservation restart inventory is unattested, stale, or invalid",
      cause,
    );
  }
  const expectedAttestedInventoryDigest = isUnattestedGenesis
    ? initialState.inventory.inventory_digest
    : initialState.attested_inventory.inventory_digest;
  if (!isSuccessorAttestation
      && inventoryDocument.payload.inventory_digest !== expectedAttestedInventoryDigest) {
    throw reservationError(
      "reservation_restart_inventory_binding_drift",
      "signed restart inventory does not bind the exact durable inventory",
    );
  }
  let admittedState = readAuthorityState(privateState);
  if (admittedState.state_digest !== initialState.state_digest) {
    throw reservationError(
      "reservation_restart_inventory_race",
      "physical resource reservation state changed during inventory trust verification",
    );
  }
  if (isUnattestedGenesis || isSuccessorAttestation) {
    const nextInventory = isSuccessorAttestation
      ? reconcileAttestedInventoryWithReservations(
        assertInventoryRefreshSuccessor(
          initialState.inventory,
          inventoryDocument.payload.inventory,
        ),
        initialState.reservations,
      )
      : initialState.inventory;
    const provisioned = nextState(
      privateState,
      initialState,
      nextInventory,
      initialState.reservations,
      {
        generation: inventoryDocument.payload.attestation_generation,
        digest: inventoryDocument.signed_document_digest,
        prior_digest: inventoryDocument.payload.prior_attestation_digest,
        state_revision: inventoryDocument.payload.expected_state_revision,
        state_digest: inventoryDocument.payload.expected_state_digest,
        prior_inventory_digest: inventoryDocument.payload.prior_inventory_digest,
        inventory: inventoryDocument.payload.inventory,
      },
    );
    privateState.bootstrap_inventory_provisioning = true;
    let committed;
    try {
      committed = callCas(privateState, initialState, provisioned);
    } finally {
      privateState.bootstrap_inventory_provisioning = false;
    }
    if (!committed.committed) {
      throw reservationError(
        "reservation_restart_inventory_provisioning_conflict",
        "initial signed physical resource inventory lost its exact CAS binding",
      );
    }
    admittedState = committed.state;
  }
  if (admittedState.inventory_attestation_digest !== inventoryDocument.signed_document_digest) {
    throw reservationError(
      "reservation_restart_inventory_lineage_drift",
      "durable inventory attestation lineage does not match the current signed document",
    );
  }
  privateState.mutations_enabled = isExactCurrentAttestation;
  AUTHORITIES.add(authority);
  AUTHORITY_PRIVATE.set(authority, privateState);
  return authority;
}

function assertPhysicalResourceReservationAuthority(authority) {
  if (!authority || !Object.isFrozen(authority) || !AUTHORITIES.has(authority)
      || !AUTHORITY_PRIVATE.has(authority)) {
    throw new Error("physical resource reservation authority must be created by Bob's private factory");
  }
  return authority;
}

function createPhysicalResourceReservationEligibilityPort(authority) {
  assertPhysicalResourceReservationAuthority(authority);
  const authorityState = AUTHORITY_PRIVATE.get(authority);
  assertAuthorityMutationReady(authorityState);
  const port = deepFreeze({
    version: RESOURCE_RESERVATION_ELIGIBILITY_VERSION,
    broker_ref: authority.broker_ref,
    broker_epoch: authority.broker_epoch,
    source_graph_hash: authority.source_graph_hash,
    session_nucleus_hash: authority.session_nucleus_hash,
    contract: "broker-private-held-physical-resource-eligibility-v1",
  });
  ELIGIBILITY_PORTS.add(port);
  ELIGIBILITY_PRIVATE.set(port, authorityState);
  return port;
}

function assertPhysicalResourceReservationEligibilityPort(port) {
  if (!port || !Object.isFrozen(port) || !ELIGIBILITY_PORTS.has(port)
      || !ELIGIBILITY_PRIVATE.has(port)) {
    throw new Error("physical resource reservation eligibility port must be created by Bob's private factory");
  }
  return port;
}

function resolveHeldPhysicalResourceForNode(port, input = {}) {
  assertPhysicalResourceReservationEligibilityPort(port);
  assertClosedObject(input, "held_physical_resource_node_binding", [
    "node_id",
    "contract_hash",
    "source_graph_hash",
    "session_nucleus_hash",
    "resource_bundle_digest",
  ]);
  const authorityState = ELIGIBILITY_PRIVATE.get(port);
  assertAuthorityMutationReady(authorityState);
  const binding = {
    node_id: assertToken(input.node_id, "held_physical_resource_node_binding.node_id"),
    contract_hash: assertDigest(input.contract_hash, "held_physical_resource_node_binding.contract_hash"),
    source_graph_hash: assertDigest(input.source_graph_hash, "held_physical_resource_node_binding.source_graph_hash"),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, "held_physical_resource_node_binding.session_nucleus_hash"),
    resource_bundle_digest: assertDigest(input.resource_bundle_digest, "held_physical_resource_node_binding.resource_bundle_digest"),
  };
  if (binding.source_graph_hash !== authorityState.source_graph_hash
      || binding.session_nucleus_hash !== authorityState.session_nucleus_hash) return null;
  const state = readAuthorityState(authorityState);
  const matches = state.reservations.filter((record) => (
    record.receipt.state === "held"
    && record.effect_state === "not_started"
    && record.request.node_id === binding.node_id
    && record.request.contract_hash === binding.contract_hash
    && record.request.source_graph_hash === binding.source_graph_hash
    && record.request.session_nucleus_hash === binding.session_nucleus_hash
    && record.request.resource_bundle_digest === binding.resource_bundle_digest
  ));
  if (matches.length === 0) return null;
  if (matches.length !== 1) {
    throw reservationError("held_resource_binding_ambiguous", "multiple held reservations match the exact node binding");
  }
  const record = matches[0];
  const sample = samplePhysicalTrustedClock(authorityState.trusted_clock_port);
  if (!inventoryIsCurrent(state.inventory, sample)
      || !recordHasLiveInventory(record, state.inventory)
      || Date.parse(sample.trusted_utc_earliest) < Date.parse(record.request.effect_not_before)
      || Date.parse(sample.trusted_utc_latest) >= Date.parse(record.request.effect_deadline)
      || Date.parse(sample.trusted_utc_latest) >= Date.parse(record.receipt.expires_at)) return null;
  const value = {
    version: RESOURCE_RESERVATION_ELIGIBILITY_VERSION,
    held: true,
    reservation_ref: record.receipt.reservation_ref,
    broker_ref: record.receipt.broker_ref,
    broker_epoch: record.receipt.broker_epoch,
    reservation_request_digest: record.request.reservation_request_digest,
    node_id: record.request.node_id,
    contract_hash: record.request.contract_hash,
    source_graph_hash: record.request.source_graph_hash,
    session_nucleus_hash: record.request.session_nucleus_hash,
    resource_bundle_digest: record.request.resource_bundle_digest,
    receipt_digest: record.receipt.receipt_digest,
    allocation_digest: hashCanonicalJson(record.receipt.allocations),
    allocation_plan_digest: record.allocation_plan_digest,
    fencing_semantics: RESOURCE_FENCING_SEMANTICS,
    expires_at: record.receipt.expires_at,
  };
  return deepFreeze({ ...value, eligibility_digest: hashCanonicalJson(value) });
}

module.exports = {
  MAX_CAS_CONFLICT_RETRIES,
  MAX_GENERAL_RESERVATION_TOMBSTONES,
  MAX_RESERVATIONS,
  MAX_RESERVATION_TOMBSTONES,
  RAW_FENCE_BYTES,
  RESERVATION_TOMBSTONE_SAFETY_RESERVE,
  RESOURCE_BUNDLE_RESOLVER_CONTRACT,
  RESOURCE_FENCING_SEMANTICS,
  RESOURCE_RESERVATION_AUTHORITY_VERSION,
  RESOURCE_RESERVATION_COMPACTION_CONTRACT,
  RESOURCE_RESERVATION_CREDENTIAL_VERSION,
  RESOURCE_RESERVATION_ELIGIBILITY_VERSION,
  RESOURCE_RESERVATION_STATE_PORT_CONTRACT,
  RESOURCE_RESERVATION_STATE_VERSION,
  RESOURCE_RESERVATION_TOMBSTONE_VERSION,
  assertCurrentPhysicalResourceReservationCredential,
  assertPhysicalResourceEffectAuthorizedNow,
  assertPhysicalResourceBundleResolverPort,
  assertPhysicalResourceReservationAuthority,
  assertPhysicalResourceReservationEligibilityPort,
  assertPhysicalResourceReservationStatePort,
  beginPhysicalResourceCleanup,
  cancelPhysicalResourceReservation,
  completePhysicalResourceCleanup,
  compactPhysicalResourceReservationHistory,
  createInitialPhysicalResourceReservationState,
  createPhysicalResourceBundleResolverPort,
  createPhysicalResourceReservationAuthority,
  createPhysicalResourceReservationEligibilityPort,
  createPhysicalResourceReservationStatePort,
  expirePhysicalResourceReservation,
  fencePhysicalResourceReservation,
  markPhysicalResourceEffectStarted,
  normalizePhysicalResourceReservationState,
  physicalResourceReservationReadiness,
  preemptPhysicalResourceReservation,
  projectPhysicalResourceReservationInventory,
  quarantinePhysicalResourceReservation,
  refreshPhysicalResourceInventory,
  rehydratePhysicalResourceReservationCredential,
  readPhysicalResourceReservationProjection,
  reservePhysicalResources,
  resolveHeldPhysicalResourceForNode,
  resolvePhysicalResourceBundleForAdmission,
};
