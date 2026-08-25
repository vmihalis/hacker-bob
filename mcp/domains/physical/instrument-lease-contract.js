"use strict";

// Plane-PH PH-S7 contract nucleus. This module is intentionally pure: it
// describes the records a broker, worker, and safety supervisor must durably
// persist, but it never opens an instrument, writes a journal, signs a record,
// starts a worker, or performs cleanup itself.

const { types: utilTypes } = require("node:util");

const arrayIsArray = Array.isArray;
const arrayPrototypeEvery = Array.prototype.every;
const arrayPrototypeFilter = Array.prototype.filter;
const arrayPrototypeFind = Array.prototype.find;
const arrayPrototypeIncludes = Array.prototype.includes;
const arrayPrototypeJoin = Array.prototype.join;
const arrayPrototypeMap = Array.prototype.map;
const arrayPrototypePush = Array.prototype.push;
const arrayPrototypeReduce = Array.prototype.reduce;
const arrayPrototypeSome = Array.prototype.some;
const arrayPrototypeSort = Array.prototype.sort;
const dateConstructor = Date;
const dateParse = Date.parse;
const datePrototypeToISOString = Date.prototype.toISOString;
const mathFloor = Math.floor;
const mathMax = Math.max;
const numberIsNaN = Number.isNaN;
const numberIsSafeInteger = Number.isSafeInteger;
const objectFreeze = Object.freeze;
const objectFromEntries = Object.fromEntries;
const objectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwnProperty = Object.prototype.hasOwnProperty;
const objectIsFrozen = Object.isFrozen;
const objectPrototype = Object.prototype;
const objectValues = Object.values;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regexpPrototypeExec = RegExp.prototype.exec;
const SetConstructor = Set;
const setPrototypeAdd = Set.prototype.add;
const setPrototypeHas = Set.prototype.has;
const utilIsProxy = utilTypes.isProxy;
const weakSetPrototypeAdd = WeakSet.prototype.add;
const weakSetPrototypeHas = WeakSet.prototype.has;

function apply(function_, receiver, arguments_) {
  return reflectApply(function_, receiver, arguments_);
}

function hasOwn(value, field) {
  return apply(objectHasOwnProperty, value, [field]);
}

function arrayEvery(value, callback) {
  return apply(arrayPrototypeEvery, value, [callback]);
}

function arrayFilter(value, callback) {
  return apply(arrayPrototypeFilter, value, [callback]);
}

function arrayFind(value, callback) {
  return apply(arrayPrototypeFind, value, [callback]);
}

function arrayIncludes(value, candidate) {
  return apply(arrayPrototypeIncludes, value, [candidate]);
}

function arrayJoin(value, separator) {
  return apply(arrayPrototypeJoin, value, [separator]);
}

function arrayMap(value, callback) {
  return apply(arrayPrototypeMap, value, [callback]);
}

function arrayPush(value, candidate) {
  return apply(arrayPrototypePush, value, [candidate]);
}

function arrayReduce(value, callback, initial) {
  return apply(arrayPrototypeReduce, value, [callback, initial]);
}

function arraySome(value, callback) {
  return apply(arrayPrototypeSome, value, [callback]);
}

function arraySort(value, compare) {
  apply(arrayPrototypeSort, value, compare == null ? [] : [compare]);
  return value;
}

function patternMatches(pattern, value) {
  return apply(regexpPrototypeExec, pattern, [value]) !== null;
}

function parseTimestamp(value) {
  return apply(dateParse, dateConstructor, [value]);
}

function setAdd(set, value) {
  apply(setPrototypeAdd, set, [value]);
}

function setHas(set, value) {
  return apply(setPrototypeHas, set, [value]);
}

function hasDuplicateArrayValues(values) {
  const seen = new SetConstructor();
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (setHas(seen, value)) return true;
    setAdd(seen, value);
  }
  return false;
}

function uniqueSortedArray(values) {
  const seen = new SetConstructor();
  const unique = [];
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (setHas(seen, value)) continue;
    setAdd(seen, value);
    arrayPush(unique, value);
  }
  return arraySort(unique);
}

const {
  ATTEMPT_STATE_VALUES,
  ATTEMPT_TRANSITIONS,
  EFFECT_DISPOSITION_VALUES,
  normalizeAttemptReport,
} = require("./instrument-provider-contract.js");
const {
  normalizeCleanupCapability,
} = require("./physical-authority.js");
const {
  normalizeOpaqueRef,
} = require("./physical-quantities.js");
const {
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");

const INSTRUMENT_LEASE_VERSION = 1;
const ATTEMPT_JOURNAL_VERSION = 1;
const EFFECT_DISPATCH_VERSION = 1;
const PROVIDER_DISPATCH_CREDENTIAL_VERSION = 1;
const PROVIDER_DISPATCH_REDEMPTION_VERSION = 1;
const PROVIDER_DISPATCH_CREDENTIAL_DOMAIN = "hacker-bob/provider-dispatch-credential/v1";
const PROVIDER_DISPATCH_FENCE_DOMAIN = "hacker-bob/provider-dispatch-fence/v1";
const DURABLE_OUTBOX_VERSION = 1;
const STOP_PROTOCOL_VERSION = 1;
const SAFETY_SUPERVISOR_VERSION = 1;
const RECOVERY_BOOTSTRAP_VERSION = 1;
const RESTORATION_RECEIPT_VERSION = 1;
const STARTUP_RECONCILIATION_VERSION = 1;
const SIGNED_ENVELOPE_VERSION = 1;
// A hardware worker must lose executable authority promptly when its
// supervisor loses liveness. Longer operations renew the durable lease; they
// do not weaken deadman detection by stretching one heartbeat window.
const MAX_SUPERVISOR_DEADMAN_WINDOW_MS = 60_000;

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;

const LEASE_STATE_VALUES = Object.freeze([
  "held",
  "stop_requested",
  "fenced",
  "restoring",
  "released",
  "quarantined",
]);
const LEASE_BLOCKING_STATES = Object.freeze([
  "held",
  "stop_requested",
  "fenced",
  "restoring",
  "quarantined",
]);
const LEASE_TERMINAL_DISPOSITIONS = Object.freeze([
  "confirmed_no_effect",
  "restored",
  "quarantined",
  "irreversible_authorized",
  "unknown_effect",
]);
const LEASE_FENCE_REASONS = Object.freeze([
  "deadman_missed",
  "lease_expired",
  "operator_stop",
  "provider_unreachable",
  "revocation",
  "startup_reconciliation",
  "stop_unacknowledged",
  "worker_exit",
]);

const JOURNAL_STATE_VALUES = Object.freeze([
  "precommitted",
  "admitted",
  "effect_starting",
  "running",
  "effect_recorded",
  "stop_requested",
  "stop_acked",
  "stop_forced",
  "ambiguous_effect",
  "restoring",
  "reconciled_no_effect",
  "restored",
  "quarantined",
  "irreversible_authorized",
  "unknown_effect",
]);
const JOURNAL_TERMINAL_STATES = Object.freeze([
  "restored",
  "reconciled_no_effect",
  "quarantined",
  "irreversible_authorized",
  "unknown_effect",
]);
const JOURNAL_TRANSITIONS = Object.freeze({
  precommitted: Object.freeze(["admitted", "reconciled_no_effect"]),
  admitted: Object.freeze(["effect_starting", "stop_requested", "reconciled_no_effect"]),
  effect_starting: Object.freeze([
    "running",
    "stop_requested",
    "ambiguous_effect",
    "reconciled_no_effect",
    "quarantined",
    "unknown_effect",
  ]),
  running: Object.freeze([
    "effect_recorded",
    "stop_requested",
    "ambiguous_effect",
    "quarantined",
    "unknown_effect",
  ]),
  effect_recorded: Object.freeze(["restoring", "quarantined", "irreversible_authorized"]),
  stop_requested: Object.freeze([
    "stop_acked",
    "stop_forced",
    "ambiguous_effect",
    "quarantined",
    "unknown_effect",
  ]),
  stop_acked: Object.freeze(["restoring", "quarantined"]),
  stop_forced: Object.freeze(["restoring", "quarantined", "unknown_effect"]),
  ambiguous_effect: Object.freeze([
    "restoring",
    "reconciled_no_effect",
    "quarantined",
    "unknown_effect",
  ]),
  restoring: Object.freeze(["restored", "quarantined", "unknown_effect"]),
  reconciled_no_effect: Object.freeze([]),
  restored: Object.freeze([]),
  quarantined: Object.freeze([]),
  irreversible_authorized: Object.freeze([]),
  unknown_effect: Object.freeze([]),
});

const JOURNAL_PROVIDER_STATES = Object.freeze({
  precommitted: Object.freeze(["created"]),
  admitted: Object.freeze(["prepared"]),
  effect_starting: Object.freeze(["prepared"]),
  running: Object.freeze(["dispatched", "stop_requested"]),
  effect_recorded: Object.freeze(["acknowledged"]),
  stop_requested: Object.freeze(["dispatched", "stop_requested"]),
  stop_acked: Object.freeze(["stopped"]),
  stop_forced: Object.freeze(["stop_requested", "stopped", "ambiguous_effect", "unknown_effect"]),
  ambiguous_effect: Object.freeze(["ambiguous_effect"]),
  restoring: Object.freeze(["acknowledged", "stopped"]),
  reconciled_no_effect: Object.freeze(["prepared", "refused", "reconciled_no_effect"]),
  restored: Object.freeze(["restored"]),
  quarantined: Object.freeze(["quarantined"]),
  irreversible_authorized: Object.freeze(["irreversible_authorized"]),
  unknown_effect: Object.freeze(["unknown_effect"]),
});

const JOURNAL_EFFECT_DISPOSITIONS = Object.freeze({
  precommitted: Object.freeze(["not_dispatched"]),
  admitted: Object.freeze(["not_dispatched"]),
  effect_starting: Object.freeze(["not_dispatched"]),
  running: Object.freeze(["ambiguous"]),
  effect_recorded: Object.freeze(["confirmed_effect"]),
  stop_requested: Object.freeze(["ambiguous"]),
  stop_acked: Object.freeze(["confirmed_no_effect", "confirmed_effect"]),
  stop_forced: Object.freeze(["ambiguous", "confirmed_no_effect", "confirmed_effect", "unknown"]),
  ambiguous_effect: Object.freeze(["ambiguous"]),
  restoring: Object.freeze(["confirmed_no_effect", "confirmed_effect"]),
  reconciled_no_effect: Object.freeze(["confirmed_no_effect"]),
  restored: Object.freeze(["confirmed_effect"]),
  quarantined: Object.freeze(["ambiguous", "confirmed_effect", "unknown"]),
  irreversible_authorized: Object.freeze(["confirmed_effect"]),
  unknown_effect: Object.freeze(["unknown"]),
});

const OUTBOX_PAYLOAD_KINDS = Object.freeze([
  "cleanup_receipt",
  "provider_report",
  "restoration_receipt",
  "stop_acknowledgement",
  "worker_receipt",
]);
const STOP_REASONS = Object.freeze([
  "authority_epoch_advanced",
  "deadman_missed",
  "lease_expired",
  "operator_requested",
  "provider_unreachable",
  "revocation_generation_advanced",
  "scope_invalidated",
  "startup_reconciliation",
  "worker_exit",
]);
const STOP_ACK_OUTCOMES = Object.freeze(["stopped", "forced", "cannot_confirm"]);
const STOP_ACKNOWLEDGER_KINDS = Object.freeze(["active_worker", "safety_supervisor"]);
const EMISSION_STATE_VALUES = Object.freeze(["inhibited", "unknown"]);
const SIGNATURE_METHODS = Object.freeze(["ed25519"]);
const VERIFIED_RECOVERY_BOOTSTRAP_PROJECTIONS = new WeakSet();
const CONTAINMENT_MODES = Object.freeze(["electronic", "operator_containment"]);
const CONTAINMENT_ACTIONS = Object.freeze([
  "device_reset",
  "power_isolation",
  "rf_interlock",
  "transport_close",
  "worker_kill",
]);
const SUPERVISOR_DECISIONS = Object.freeze([
  "continue",
  "inactive",
  "stop_fence_cleanup",
]);
const SAFETY_ROOT_STATUS_VALUES = Object.freeze(["trusted", "compromised", "unavailable"]);
const RECONCILIATION_ACTIONS = Object.freeze([
  "close_confirmed_no_effect",
  "finalize_irreversible_authorized",
  "finalize_quarantined",
  "finalize_restored",
  "quarantine",
  "record_irreversible_terminal",
  "record_quarantine_terminal",
  "record_restoration_receipt",
  "resume_restore",
  "stop_reconcile_restore",
]);

function deepFreeze(value) {
  if (!value || typeof value !== "object" || objectIsFrozen(value)) return value;
  for (const child of objectValues(value)) deepFreeze(child);
  return objectFreeze(value);
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || arrayIsArray(value)
      || utilIsProxy(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  return prototype === objectPrototype || prototype === null;
}

function assertClosedObject(value, label, requiredFields, optionalFields = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const descriptors = objectGetOwnPropertyDescriptors(value);
  const keys = reflectOwnKeys(descriptors);
  if (arraySome(keys, (field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = arrayMap(requiredFields, (field) => field);
  for (const field of optionalFields) arrayPush(allowed, field);
  const unknown = arraySort(arrayFilter(keys, (field) => !arrayIncludes(allowed, field)));
  if (unknown.length > 0) {
    throw new Error(`${label} has unknown fields: ${arrayJoin(unknown, ", ")}`);
  }
  const missing = arrayFilter(requiredFields, (field) => !hasOwn(descriptors, field));
  if (missing.length > 0) {
    throw new Error(`${label} is missing fields: ${arrayJoin(missing, ", ")}`);
  }
  if (objectGetPrototypeOf(value) === objectPrototype) {
    const prototypeDescriptors = objectGetOwnPropertyDescriptors(objectPrototype);
    const inheritedOptional = arrayFilter(optionalFields, (field) => (
      !hasOwn(descriptors, field) && hasOwn(prototypeDescriptors, field)
    ));
    if (inheritedOptional.length > 0) {
      throw new Error(
        `${label} cannot inherit optional fields: ${arrayJoin(inheritedOptional, ", ")}`,
      );
    }
  }
  for (const field of keys) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true || !hasOwn(descriptor, "value")) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
  }
  return value;
}

function assertEnum(value, values, label) {
  if (!arrayIncludes(values, value)) {
    throw new Error(`${label} must be one of ${arrayJoin(values, ", ")}`);
  }
  return value;
}

function assertToken(value, label) {
  if (typeof value !== "string" || !patternMatches(TOKEN_PATTERN, value)) {
    throw new Error(`${label} must be a bounded opaque token`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !patternMatches(IDENTIFIER_PATTERN, value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !patternMatches(HASH_PATTERN, value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertInteger(value, label, min = 0) {
  if (!numberIsSafeInteger(value) || value < min) {
    throw new Error(`${label} must be a safe integer >= ${min}`);
  }
  return value;
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function assertCanonicalTimestamp(value, label) {
  if (typeof value !== "string" || numberIsNaN(parseTimestamp(value))) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  if (apply(datePrototypeToISOString, new dateConstructor(value), []) !== value) {
    throw new Error(`${label} must use canonical UTC ISO-8601 form`);
  }
  return value;
}

function assertTimeOrder(earlier, later, label, { allowEqual = true } = {}) {
  const left = parseTimestamp(earlier);
  const right = parseTimestamp(later);
  if (allowEqual ? right < left : right <= left) {
    throw new Error(`${label} is not in required chronological order`);
  }
}

function assertDerivedDigest(input, field, expected, label) {
  if (!hasOwn(input, field)) return;
  if (assertDigest(input[field], `${label}.${field}`) !== expected) {
    throw new Error(`${label}.${field} does not match normalized content`);
  }
}

function assertExactBindings(actual, expected, fields, label) {
  for (const field of fields) {
    if (actual[field] !== expected[field]) throw new Error(`${label}.${field} binding drift`);
  }
}

function normalizeUniqueSorted(values, label, normalize, { min = 0, max = 64 } = {}) {
  if (!arrayIsArray(values) || values.length < min || values.length > max) {
    throw new Error(`${label} must be an array with ${min}-${max} entries`);
  }
  const normalized = arrayMap(values, (value, index) => normalize(value, `${label}[${index}]`));
  if (hasDuplicateArrayValues(normalized)) throw new Error(`${label} must not contain duplicates`);
  return objectFreeze(arraySort([...normalized]));
}

const LEASE_COMMON_FIELDS = Object.freeze([
  "version",
  "lease_id",
  "instrument_ref",
  "owner_principal_id",
  "execution_principal_id",
  "terminal_receipt_recipient_principal_id",
  "terminal_receipt_idempotency_domain_digest",
  "attempt_ref",
  "operation_id",
  "execution_request_digest",
  "resource_bundle_digest",
  "fencing_token",
  "fencing_generation",
  "state",
  "sequence",
  "acquired_at",
  "updated_at",
  "effect_not_before",
  "effect_deadline",
  "heartbeat_deadline",
  "expires_at",
]);
const LEASE_TERMINAL_FIELDS = Object.freeze([
  "closed_at",
  "terminal_disposition",
  "terminal_receipt_ref",
  "terminal_receipt_digest",
]);

function normalizeInstrumentLease(input, label = "instrument_lease") {
  assertClosedObject(input, label, LEASE_COMMON_FIELDS, [...LEASE_TERMINAL_FIELDS, "lease_digest"]);
  if (input.version !== INSTRUMENT_LEASE_VERSION) {
    throw new Error(`${label}.version must be ${INSTRUMENT_LEASE_VERSION}`);
  }
  const state = assertEnum(input.state, LEASE_STATE_VALUES, `${label}.state`);
  const acquiredAt = assertCanonicalTimestamp(input.acquired_at, `${label}.acquired_at`);
  const updatedAt = assertCanonicalTimestamp(input.updated_at, `${label}.updated_at`);
  const effectNotBefore = assertCanonicalTimestamp(
    input.effect_not_before,
    `${label}.effect_not_before`,
  );
  const effectDeadline = assertCanonicalTimestamp(input.effect_deadline, `${label}.effect_deadline`);
  const heartbeatDeadline = assertCanonicalTimestamp(
    input.heartbeat_deadline,
    `${label}.heartbeat_deadline`,
  );
  const expiresAt = assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`);
  assertTimeOrder(acquiredAt, heartbeatDeadline, `${label} acquired_at -> heartbeat_deadline`, {
    allowEqual: false,
  });
  assertTimeOrder(acquiredAt, updatedAt, `${label} acquired_at -> updated_at`);
  assertTimeOrder(acquiredAt, effectDeadline, `${label} acquired_at -> effect_deadline`, {
    allowEqual: false,
  });
  assertTimeOrder(effectNotBefore, effectDeadline, `${label} effect window`, {
    allowEqual: false,
  });
  assertTimeOrder(effectDeadline, expiresAt, `${label} effect_deadline -> expires_at`);
  assertTimeOrder(heartbeatDeadline, expiresAt, `${label} heartbeat_deadline -> expires_at`);

  const normalized = {
    version: INSTRUMENT_LEASE_VERSION,
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    owner_principal_id: normalizeOpaqueRef(input.owner_principal_id, `${label}.owner_principal_id`, {
      prefix: "principal",
    }),
    execution_principal_id: normalizeOpaqueRef(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      { prefix: "principal" },
    ),
    terminal_receipt_recipient_principal_id: normalizeOpaqueRef(
      input.terminal_receipt_recipient_principal_id,
      `${label}.terminal_receipt_recipient_principal_id`,
      { prefix: "principal" },
    ),
    terminal_receipt_idempotency_domain_digest: assertDigest(
      input.terminal_receipt_idempotency_domain_digest,
      `${label}.terminal_receipt_idempotency_domain_digest`,
    ),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    resource_bundle_digest: assertDigest(input.resource_bundle_digest, `${label}.resource_bundle_digest`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    state,
    sequence: assertInteger(input.sequence, `${label}.sequence`),
    acquired_at: acquiredAt,
    updated_at: updatedAt,
    effect_not_before: effectNotBefore,
    effect_deadline: effectDeadline,
    heartbeat_deadline: heartbeatDeadline,
    expires_at: expiresAt,
  };

  const terminal = state === "released" || state === "quarantined";
  const presentTerminalFields = arrayFilter(LEASE_TERMINAL_FIELDS, (field) => (
    hasOwn(input, field)
  ));
  if (terminal && presentTerminalFields.length !== LEASE_TERMINAL_FIELDS.length) {
    throw new Error(`${label}.${state} requires all terminal closure fields`);
  }
  if (!terminal && presentTerminalFields.length > 0) {
    throw new Error(`${label}.${state} cannot carry terminal closure fields`);
  }
  if (terminal) {
    const disposition = assertEnum(
      input.terminal_disposition,
      LEASE_TERMINAL_DISPOSITIONS,
      `${label}.terminal_disposition`,
    );
    if (state === "released"
        && arrayIncludes(["quarantined", "unknown_effect"], disposition)) {
      throw new Error(`${label}.released cannot conceal ${disposition}`);
    }
    if (state === "quarantined"
        && !arrayIncludes(["quarantined", "unknown_effect"], disposition)) {
      throw new Error(`${label}.quarantined requires quarantined or unknown_effect disposition`);
    }
    const closedAt = assertCanonicalTimestamp(input.closed_at, `${label}.closed_at`);
    if (closedAt !== updatedAt) throw new Error(`${label}.closed_at must equal terminal updated_at`);
    normalized.closed_at = closedAt;
    normalized.terminal_disposition = disposition;
    normalized.terminal_receipt_ref = normalizeOpaqueRef(
      input.terminal_receipt_ref,
      `${label}.terminal_receipt_ref`,
      { prefix: "receipt" },
    );
    normalized.terminal_receipt_digest = assertDigest(
      input.terminal_receipt_digest,
      `${label}.terminal_receipt_digest`,
    );
  }
  const leaseDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "lease_digest", leaseDigest, label);
  return deepFreeze({ ...normalized, lease_digest: leaseDigest });
}

function isLeaseBlocking(input) {
  return arrayIncludes(LEASE_BLOCKING_STATES, normalizeInstrumentLease(input).state);
}

function acquireInstrumentLease(input, history = [], label = "instrument_lease_acquire") {
  const candidate = normalizeInstrumentLease(input, `${label}.candidate`);
  if (candidate.state !== "held" || candidate.sequence !== 0) {
    throw new Error(`${label}.candidate must begin held at sequence 0`);
  }
  if (candidate.updated_at !== candidate.acquired_at) {
    throw new Error(`${label}.candidate.updated_at must equal acquired_at`);
  }
  if (!arrayIsArray(history) || history.length > 100000) {
    throw new Error(`${label}.history must be an array with at most 100000 leases`);
  }
  const leases = arrayMap(
    history,
    (lease, index) => normalizeInstrumentLease(lease, `${label}.history[${index}]`),
  );
  const ids = arrayMap(leases, (lease) => lease.lease_id);
  if (hasDuplicateArrayValues(ids)) throw new Error(`${label}.history contains duplicate lease IDs`);
  if (arrayIncludes(ids, candidate.lease_id)) {
    throw new Error(`${label}.candidate.lease_id has already been used`);
  }
  const instrumentHistory = arrayFilter(
    leases,
    (lease) => lease.instrument_ref === candidate.instrument_ref,
  );
  const conflict = arrayFind(
    instrumentHistory,
    (lease) => arrayIncludes(LEASE_BLOCKING_STATES, lease.state),
  );
  if (conflict) throw new Error(`${label} refused: instrument already bound by lease ${conflict.lease_id}`);
  const priorGeneration = arrayReduce(
    instrumentHistory,
    (maximum, lease) => mathMax(maximum, lease.fencing_generation),
    0,
  );
  if (candidate.fencing_generation !== priorGeneration + 1) {
    throw new Error(`${label}.candidate.fencing_generation must advance exactly once`);
  }
  for (const prior of instrumentHistory) {
    const priorBoundary = prior.closed_at || prior.expires_at;
    if (parseTimestamp(candidate.acquired_at) < parseTimestamp(priorBoundary)) {
      throw new Error(`${label}.candidate.acquired_at overlaps prior lease ${prior.lease_id}`);
    }
  }
  return candidate;
}

const LEASE_MUTATION_BINDINGS = Object.freeze([
  "lease_id",
  "instrument_ref",
  "owner_principal_id",
  "execution_principal_id",
  "fencing_token",
  "fencing_generation",
]);

function normalizeLeaseMutationBase(input, lease, label, extraFields) {
  assertClosedObject(
    input,
    label,
    ["version", ...LEASE_MUTATION_BINDINGS, "expected_sequence", ...extraFields],
  );
  if (input.version !== INSTRUMENT_LEASE_VERSION) {
    throw new Error(`${label}.version must be ${INSTRUMENT_LEASE_VERSION}`);
  }
  const normalized = {
    version: INSTRUMENT_LEASE_VERSION,
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    owner_principal_id: normalizeOpaqueRef(input.owner_principal_id, `${label}.owner_principal_id`, {
      prefix: "principal",
    }),
    execution_principal_id: normalizeOpaqueRef(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      { prefix: "principal" },
    ),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    expected_sequence: assertInteger(input.expected_sequence, `${label}.expected_sequence`),
  };
  assertExactBindings(normalized, lease, LEASE_MUTATION_BINDINGS, label);
  if (normalized.expected_sequence !== lease.sequence) {
    throw new Error(`${label}.expected_sequence is stale`);
  }
  return normalized;
}

function renewInstrumentLease(priorInput, input, label = "instrument_lease_renewal") {
  const prior = normalizeInstrumentLease(priorInput, `${label}.prior`);
  if (prior.state !== "held") throw new Error(`${label} requires a held lease`);
  const request = normalizeLeaseMutationBase(
    input,
    prior,
    label,
    ["renewed_at", "heartbeat_deadline", "expires_at"],
  );
  const renewedAt = assertCanonicalTimestamp(input.renewed_at, `${label}.renewed_at`);
  const heartbeatDeadline = assertCanonicalTimestamp(
    input.heartbeat_deadline,
    `${label}.heartbeat_deadline`,
  );
  const expiresAt = assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`);
  assertTimeOrder(prior.updated_at, renewedAt, `${label} prior update -> renewed_at`);
  assertTimeOrder(renewedAt, prior.expires_at, `${label} renewed_at before prior expiry`, {
    allowEqual: false,
  });
  assertTimeOrder(
    prior.heartbeat_deadline,
    heartbeatDeadline,
    `${label} heartbeat deadline extension`,
    { allowEqual: false },
  );
  assertTimeOrder(renewedAt, heartbeatDeadline, `${label} renewed_at -> heartbeat_deadline`, {
    allowEqual: false,
  });
  assertTimeOrder(heartbeatDeadline, expiresAt, `${label} heartbeat_deadline -> expires_at`);
  assertTimeOrder(prior.expires_at, expiresAt, `${label} expiry extension`, { allowEqual: false });
  const result = {
    ...prior,
    sequence: prior.sequence + 1,
    updated_at: renewedAt,
    heartbeat_deadline: heartbeatDeadline,
    expires_at: expiresAt,
  };
  delete result.lease_digest;
  return normalizeInstrumentLease(result, `${label}.result`);
}

function fenceInstrumentLease(priorInput, input, label = "instrument_lease_fence") {
  const prior = normalizeInstrumentLease(priorInput, `${label}.prior`);
  if (!arrayIncludes(["held", "stop_requested"], prior.state)) {
    throw new Error(`${label} requires a held or stop_requested lease`);
  }
  normalizeLeaseMutationBase(input, prior, label, ["fenced_at", "reason"]);
  const fencedAt = assertCanonicalTimestamp(input.fenced_at, `${label}.fenced_at`);
  assertTimeOrder(prior.updated_at, fencedAt, `${label} prior update -> fenced_at`);
  assertEnum(input.reason, LEASE_FENCE_REASONS, `${label}.reason`);
  const result = {
    ...prior,
    state: "fenced",
    sequence: prior.sequence + 1,
    updated_at: fencedAt,
  };
  delete result.lease_digest;
  return normalizeInstrumentLease(result, `${label}.result`);
}

function beginInstrumentRestoration(priorInput, input, label = "instrument_lease_restoration") {
  const prior = normalizeInstrumentLease(priorInput, `${label}.prior`);
  if (!arrayIncludes(["held", "stop_requested", "fenced"], prior.state)) {
    throw new Error(`${label} requires a live or fenced lease`);
  }
  normalizeLeaseMutationBase(input, prior, label, ["started_at", "cleanup_capability_digest"]);
  const startedAt = assertCanonicalTimestamp(input.started_at, `${label}.started_at`);
  assertTimeOrder(prior.updated_at, startedAt, `${label} prior update -> started_at`);
  assertDigest(input.cleanup_capability_digest, `${label}.cleanup_capability_digest`);
  const result = {
    ...prior,
    state: "restoring",
    sequence: prior.sequence + 1,
    updated_at: startedAt,
  };
  delete result.lease_digest;
  return normalizeInstrumentLease(result, `${label}.result`);
}

function releaseInstrumentLease(priorInput, input, label = "instrument_lease_release") {
  const prior = normalizeInstrumentLease(priorInput, `${label}.prior`);
  if (!arrayIncludes(["held", "stop_requested", "fenced", "restoring"], prior.state)) {
    throw new Error(`${label} requires a nonterminal lease`);
  }
  normalizeLeaseMutationBase(
    input,
    prior,
    label,
    ["closed_at", "terminal_disposition", "terminal_receipt_ref", "terminal_receipt_digest"],
  );
  const disposition = assertEnum(
    input.terminal_disposition,
    LEASE_TERMINAL_DISPOSITIONS,
    `${label}.terminal_disposition`,
  );
  const closedAt = assertCanonicalTimestamp(input.closed_at, `${label}.closed_at`);
  assertTimeOrder(prior.updated_at, closedAt, `${label} prior update -> closed_at`);
  if (prior.state === "restoring" && disposition === "confirmed_no_effect") {
    throw new Error(`${label} cannot erase a started restoration as confirmed_no_effect`);
  }
  if (disposition === "restored" && prior.state !== "restoring") {
    throw new Error(`${label}.restored requires a prior restoring lease state`);
  }
  const result = {
    ...prior,
    state: arrayIncludes(["quarantined", "unknown_effect"], disposition)
      ? "quarantined"
      : "released",
    sequence: prior.sequence + 1,
    updated_at: closedAt,
    closed_at: closedAt,
    terminal_disposition: disposition,
    terminal_receipt_ref: normalizeOpaqueRef(
      input.terminal_receipt_ref,
      `${label}.terminal_receipt_ref`,
      { prefix: "receipt" },
    ),
    terminal_receipt_digest: assertDigest(
      input.terminal_receipt_digest,
      `${label}.terminal_receipt_digest`,
    ),
  };
  delete result.lease_digest;
  return normalizeInstrumentLease(result, `${label}.result`);
}

const JOURNAL_LEGACY_BINDING_FIELDS = Object.freeze([
  "attempt_ref",
  "instrument_ref",
  "lease_id",
  "fencing_token",
  "fencing_generation",
  "operation_id",
  "execution_request_digest",
  "authority_resolution_digest",
  "signed_grant_digest",
  "replay_claim_digest",
  "replay_reservation_receipt_digest",
  "provider_id",
  "provider_descriptor_digest",
  "provider_request_digest",
  "cleanup_capability_digest",
  "cleanup_plan_digest",
  "workspace_snapshot_ref",
  "workspace_snapshot_digest",
  "stop_contract_digest",
]);
const JOURNAL_EXECUTION_LINEAGE_FIELDS = Object.freeze([
  "experiment_plan_hash",
  "execution_lineage_digest",
]);
const JOURNAL_BINDING_FIELDS = Object.freeze([
  ...JOURNAL_LEGACY_BINDING_FIELDS,
  ...JOURNAL_EXECUTION_LINEAGE_FIELDS,
]);

function normalizeAttemptJournalEntry(input, label = "attempt_journal_entry") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "journal_entry_ref",
      ...JOURNAL_LEGACY_BINDING_FIELDS,
      "state",
      "provider_state",
      "provider_sequence",
      "effect_disposition",
      "sequence",
      "previous_entry_digest",
      "recorded_at",
      "fsynced_at",
    ],
    ["journal_entry_digest", ...JOURNAL_EXECUTION_LINEAGE_FIELDS],
  );
  if (input.version !== ATTEMPT_JOURNAL_VERSION) {
    throw new Error(`${label}.version must be ${ATTEMPT_JOURNAL_VERSION}`);
  }
  const state = assertEnum(input.state, JOURNAL_STATE_VALUES, `${label}.state`);
  const providerState = assertEnum(input.provider_state, ATTEMPT_STATE_VALUES, `${label}.provider_state`);
  const effectDisposition = assertEnum(
    input.effect_disposition,
    EFFECT_DISPOSITION_VALUES,
    `${label}.effect_disposition`,
  );
  if (!arrayIncludes(JOURNAL_PROVIDER_STATES[state], providerState)) {
    throw new Error(`${label}.provider_state is inconsistent with journal state ${state}`);
  }
  if (!arrayIncludes(JOURNAL_EFFECT_DISPOSITIONS[state], effectDisposition)) {
    throw new Error(`${label}.effect_disposition is inconsistent with journal state ${state}`);
  }
  const providerSequence = assertInteger(
    input.provider_sequence,
    `${label}.provider_sequence`,
  );
  if (!providerStateReachableAtDistance("created", providerState, providerSequence)) {
    throw new Error(
      `${label}.provider_state ${providerState} is inconsistent with provider_sequence ${providerSequence}`,
    );
  }
  const sequence = assertInteger(input.sequence, `${label}.sequence`);
  const previousEntryDigest = input.previous_entry_digest == null
    ? null
    : assertDigest(input.previous_entry_digest, `${label}.previous_entry_digest`);
  if (sequence === 0 && (state !== "precommitted" || previousEntryDigest !== null)) {
    throw new Error(`${label} sequence 0 must be an unlinked precommitted entry`);
  }
  if (sequence > 0 && previousEntryDigest === null) {
    throw new Error(`${label} sequence ${sequence} requires previous_entry_digest`);
  }
  const recordedAt = assertCanonicalTimestamp(input.recorded_at, `${label}.recorded_at`);
  const fsyncedAt = assertCanonicalTimestamp(input.fsynced_at, `${label}.fsynced_at`);
  assertTimeOrder(recordedAt, fsyncedAt, `${label} recorded_at -> fsynced_at`);

  const normalized = {
    version: ATTEMPT_JOURNAL_VERSION,
    journal_entry_ref: normalizeOpaqueRef(
      input.journal_entry_ref,
      `${label}.journal_entry_ref`,
      { prefix: "journal-entry" },
    ),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    authority_resolution_digest: assertDigest(
      input.authority_resolution_digest,
      `${label}.authority_resolution_digest`,
    ),
    signed_grant_digest: assertDigest(
      input.signed_grant_digest,
      `${label}.signed_grant_digest`,
    ),
    replay_claim_digest: assertDigest(
      input.replay_claim_digest,
      `${label}.replay_claim_digest`,
    ),
    replay_reservation_receipt_digest: assertDigest(
      input.replay_reservation_receipt_digest,
      `${label}.replay_reservation_receipt_digest`,
    ),
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    provider_request_digest: assertDigest(
      input.provider_request_digest,
      `${label}.provider_request_digest`,
    ),
    cleanup_capability_digest: assertDigest(
      input.cleanup_capability_digest,
      `${label}.cleanup_capability_digest`,
    ),
    cleanup_plan_digest: assertDigest(
      input.cleanup_plan_digest,
      `${label}.cleanup_plan_digest`,
    ),
    workspace_snapshot_ref: normalizeOpaqueRef(
      input.workspace_snapshot_ref,
      `${label}.workspace_snapshot_ref`,
      { prefix: "workspace-snapshot" },
    ),
    workspace_snapshot_digest: assertDigest(
      input.workspace_snapshot_digest,
      `${label}.workspace_snapshot_digest`,
    ),
    stop_contract_digest: assertDigest(input.stop_contract_digest, `${label}.stop_contract_digest`),
    state,
    provider_state: providerState,
    provider_sequence: providerSequence,
    effect_disposition: effectDisposition,
    sequence,
    previous_entry_digest: previousEntryDigest,
    recorded_at: recordedAt,
    fsynced_at: fsyncedAt,
  };
  for (const field of JOURNAL_EXECUTION_LINEAGE_FIELDS) {
    if (hasOwn(input, field)) {
      normalized[field] = assertDigest(input[field], `${label}.${field}`);
    }
  }
  const journalEntryDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "journal_entry_digest", journalEntryDigest, label);
  return deepFreeze({ ...normalized, journal_entry_digest: journalEntryDigest });
}

function assertAttemptJournalAppend(previousInput, nextInput) {
  const previous = normalizeAttemptJournalEntry(previousInput, "previous_attempt_journal_entry");
  const next = normalizeAttemptJournalEntry(nextInput, "next_attempt_journal_entry");
  assertExactBindings(next, previous, JOURNAL_BINDING_FIELDS, "attempt_journal_append");
  if (next.sequence !== previous.sequence + 1) {
    throw new Error("attempt_journal_append sequence must increment by exactly one");
  }
  if (next.previous_entry_digest !== previous.journal_entry_digest) {
    throw new Error("attempt_journal_append previous_entry_digest does not bind the prior row");
  }
  if (!arrayIncludes(JOURNAL_TRANSITIONS[previous.state], next.state)) {
    throw new Error(`attempt_journal_append ${previous.state} -> ${next.state} is not allowed`);
  }
  const providerSequenceDelta = next.provider_sequence - previous.provider_sequence;
  if (providerSequenceDelta < 0
      || !providerStateReachableAtDistance(
        previous.provider_state,
        next.provider_state,
        providerSequenceDelta,
      )) {
    throw new Error(
      "attempt_journal_append provider state/sequence transition "
      + `${previous.provider_state}@${previous.provider_sequence} -> `
      + `${next.provider_state}@${next.provider_sequence} is not allowed`,
    );
  }
  assertTimeOrder(previous.fsynced_at, next.recorded_at, "attempt_journal_append durable ordering");
  return next;
}

function normalizeEffectDispatchRecord(input, journalInput, label = "effect_dispatch_record") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "dispatch_event_ref",
      "journal_entry_ref",
      "journal_entry_digest",
      "attempt_ref",
      "instrument_ref",
      "lease_id",
      "fencing_token",
      "fencing_generation",
      "operation_id",
      "execution_request_digest",
      "provider_id",
      "provider_descriptor_digest",
      "provider_request_digest",
      "provider_sequence",
      "dispatched_at",
    ],
    ["dispatch_record_digest"],
  );
  if (input.version !== EFFECT_DISPATCH_VERSION) {
    throw new Error(`${label}.version must be ${EFFECT_DISPATCH_VERSION}`);
  }
  const journal = normalizeAttemptJournalEntry(journalInput, `${label}.journal_entry`);
  if (journal.state !== "effect_starting" || journal.provider_state !== "prepared") {
    throw new Error(`${label} requires an fsynced effect_starting/prepared journal entry`);
  }
  const normalized = {
    version: EFFECT_DISPATCH_VERSION,
    dispatch_event_ref: normalizeOpaqueRef(
      input.dispatch_event_ref,
      `${label}.dispatch_event_ref`,
      { prefix: "dispatch-event" },
    ),
    journal_entry_ref: normalizeOpaqueRef(
      input.journal_entry_ref,
      `${label}.journal_entry_ref`,
      { prefix: "journal-entry" },
    ),
    journal_entry_digest: assertDigest(input.journal_entry_digest, `${label}.journal_entry_digest`),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    provider_request_digest: assertDigest(input.provider_request_digest, `${label}.provider_request_digest`),
    provider_sequence: assertInteger(input.provider_sequence, `${label}.provider_sequence`),
    dispatched_at: assertCanonicalTimestamp(input.dispatched_at, `${label}.dispatched_at`),
  };
  assertExactBindings(
    normalized,
    journal,
    [
      "journal_entry_ref",
      "journal_entry_digest",
      "attempt_ref",
      "instrument_ref",
      "lease_id",
      "fencing_token",
      "fencing_generation",
      "operation_id",
      "execution_request_digest",
      "provider_id",
      "provider_descriptor_digest",
      "provider_request_digest",
      "provider_sequence",
    ],
    label,
  );
  assertTimeOrder(journal.fsynced_at, normalized.dispatched_at, `${label} fsync-before-effect`);
  const dispatchRecordDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "dispatch_record_digest", dispatchRecordDigest, label);
  return deepFreeze({ ...normalized, dispatch_record_digest: dispatchRecordDigest });
}

function providerDispatchFenceBindingDigest(input, label = "provider_dispatch_fence_binding") {
  assertClosedObject(input, label, [
    "runtime_id",
    "session_nucleus_hash",
    "attempt_ref",
    "instrument_ref",
    "execution_principal_id",
    "lease_id",
    "fencing_token",
    "fencing_generation",
    "execution_request_digest",
    "provider_id",
    "provider_descriptor_digest",
  ]);
  return hashCanonicalJson(deepFreeze({
    domain: PROVIDER_DISPATCH_FENCE_DOMAIN,
    runtime_id: assertToken(input.runtime_id, `${label}.runtime_id`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    instrument_ref: normalizeOpaqueRef(
      input.instrument_ref,
      `${label}.instrument_ref`,
      { prefix: "instrument" },
    ),
    execution_principal_id: normalizeOpaqueRef(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      { prefix: "principal" },
    ),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(
      input.fencing_generation,
      `${label}.fencing_generation`,
      1,
    ),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
  }));
}

const PROVIDER_DISPATCH_CREDENTIAL_LEGACY_FIELDS = Object.freeze([
  "version",
  "domain",
  "credential_ref",
  "runtime_id",
  "session_nucleus_hash",
  "dispatch_record_digest",
  "journal_entry_ref",
  "journal_entry_digest",
  "attempt_ref",
  "instrument_ref",
  "execution_principal_id",
  "lease_id",
  "fencing_generation",
  "fence_binding_digest",
  "effect_not_before",
  "effect_deadline",
  "operation_id",
  "execution_request_digest",
  "provider_id",
  "provider_descriptor_digest",
  "provider_request_digest",
  "provider_state",
  "provider_sequence",
  "store_generation",
  "store_head_event_digest",
]);
const PROVIDER_DISPATCH_CREDENTIAL_LINEAGE_FIELDS = Object.freeze([
  "experiment_plan_hash",
  "execution_lineage_digest",
]);
const PROVIDER_DISPATCH_CREDENTIAL_FIELDS = Object.freeze([
  ...PROVIDER_DISPATCH_CREDENTIAL_LEGACY_FIELDS,
  ...PROVIDER_DISPATCH_CREDENTIAL_LINEAGE_FIELDS,
]);

function normalizeProviderDispatchCredential(input, label = "provider_dispatch_credential") {
  assertClosedObject(
    input,
    label,
    PROVIDER_DISPATCH_CREDENTIAL_LEGACY_FIELDS,
    ["credential_digest", ...PROVIDER_DISPATCH_CREDENTIAL_LINEAGE_FIELDS],
  );
  if (input.version !== PROVIDER_DISPATCH_CREDENTIAL_VERSION) {
    throw new Error(`${label}.version must be ${PROVIDER_DISPATCH_CREDENTIAL_VERSION}`);
  }
  if (input.domain !== PROVIDER_DISPATCH_CREDENTIAL_DOMAIN) {
    throw new Error(`${label}.domain must be ${PROVIDER_DISPATCH_CREDENTIAL_DOMAIN}`);
  }
  if (input.provider_state !== "prepared") {
    throw new Error(`${label}.provider_state must be prepared`);
  }
  const normalized = {
    version: PROVIDER_DISPATCH_CREDENTIAL_VERSION,
    domain: PROVIDER_DISPATCH_CREDENTIAL_DOMAIN,
    credential_ref: normalizeOpaqueRef(
      input.credential_ref,
      `${label}.credential_ref`,
      { prefix: "provider-dispatch-credential" },
    ),
    runtime_id: assertToken(input.runtime_id, `${label}.runtime_id`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    dispatch_record_digest: assertDigest(
      input.dispatch_record_digest,
      `${label}.dispatch_record_digest`,
    ),
    journal_entry_ref: normalizeOpaqueRef(
      input.journal_entry_ref,
      `${label}.journal_entry_ref`,
      { prefix: "journal-entry" },
    ),
    journal_entry_digest: assertDigest(input.journal_entry_digest, `${label}.journal_entry_digest`),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    instrument_ref: normalizeOpaqueRef(
      input.instrument_ref,
      `${label}.instrument_ref`,
      { prefix: "instrument" },
    ),
    execution_principal_id: normalizeOpaqueRef(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      { prefix: "principal" },
    ),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    fence_binding_digest: assertDigest(input.fence_binding_digest, `${label}.fence_binding_digest`),
    effect_not_before: assertCanonicalTimestamp(
      input.effect_not_before,
      `${label}.effect_not_before`,
    ),
    effect_deadline: assertCanonicalTimestamp(input.effect_deadline, `${label}.effect_deadline`),
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    provider_request_digest: assertDigest(
      input.provider_request_digest,
      `${label}.provider_request_digest`,
    ),
    provider_state: "prepared",
    provider_sequence: assertInteger(input.provider_sequence, `${label}.provider_sequence`),
    store_generation: assertInteger(input.store_generation, `${label}.store_generation`, 1),
    store_head_event_digest: assertDigest(
      input.store_head_event_digest,
      `${label}.store_head_event_digest`,
    ),
  };
  for (const field of PROVIDER_DISPATCH_CREDENTIAL_LINEAGE_FIELDS) {
    if (hasOwn(input, field)) {
      normalized[field] = assertDigest(input[field], `${label}.${field}`);
    }
  }
  assertTimeOrder(
    normalized.effect_not_before,
    normalized.effect_deadline,
    `${label} effect window`,
    { allowEqual: false },
  );
  const credentialDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "credential_digest", credentialDigest, label);
  return deepFreeze({ ...normalized, credential_digest: credentialDigest });
}

function normalizeProviderDispatchRedemption(
  input,
  credentialInput = null,
  label = "provider_dispatch_redemption",
) {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "redemption_ref",
      ...arrayFilter(
        PROVIDER_DISPATCH_CREDENTIAL_LEGACY_FIELDS,
        (field) => !arrayIncludes(["version", "domain"], field),
      ),
      "credential_digest",
      "redeemed_at",
    ],
    ["redemption_digest", ...PROVIDER_DISPATCH_CREDENTIAL_LINEAGE_FIELDS],
  );
  if (input.version !== PROVIDER_DISPATCH_REDEMPTION_VERSION) {
    throw new Error(`${label}.version must be ${PROVIDER_DISPATCH_REDEMPTION_VERSION}`);
  }
  const credential = normalizeProviderDispatchCredential({
    version: PROVIDER_DISPATCH_CREDENTIAL_VERSION,
    domain: PROVIDER_DISPATCH_CREDENTIAL_DOMAIN,
    ...objectFromEntries(
      arrayMap(
        arrayFilter(
          arrayFilter(
            PROVIDER_DISPATCH_CREDENTIAL_FIELDS,
            (field) => !arrayIncludes(["version", "domain"], field),
          ),
          (field) => hasOwn(input, field),
        ),
        (field) => [field, input[field]],
      ),
    ),
    credential_digest: input.credential_digest,
  }, `${label}.credential`);
  if (credentialInput != null) {
    const expected = normalizeProviderDispatchCredential(credentialInput, `${label}.expected_credential`);
    if (credential.credential_digest !== expected.credential_digest) {
      throw new Error(`${label}.credential_digest binding drift`);
    }
  }
  const normalized = {
    version: PROVIDER_DISPATCH_REDEMPTION_VERSION,
    redemption_ref: normalizeOpaqueRef(
      input.redemption_ref,
      `${label}.redemption_ref`,
      { prefix: "provider-dispatch-redemption" },
    ),
    ...objectFromEntries(
      arrayMap(
        arrayFilter(
          arrayFilter(
            PROVIDER_DISPATCH_CREDENTIAL_FIELDS,
            (field) => !arrayIncludes(["version", "domain"], field),
          ),
          (field) => hasOwn(credential, field),
        ),
        (field) => [field, credential[field]],
      ),
    ),
    credential_digest: credential.credential_digest,
    redeemed_at: assertCanonicalTimestamp(input.redeemed_at, `${label}.redeemed_at`),
  };
  const redemptionDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "redemption_digest", redemptionDigest, label);
  return deepFreeze({ ...normalized, redemption_digest: redemptionDigest });
}

function normalizeDurableOutboxEntry(input, label = "durable_outbox_entry") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "outbox_entry_ref",
      "attempt_ref",
      "instrument_ref",
      "lease_id",
      "fencing_token",
      "fencing_generation",
      "operation_id",
      "execution_request_digest",
      "source_journal_entry_digest",
      "payload_kind",
      "payload_ref",
      "payload_digest",
      "sequence",
      "previous_entry_digest",
      "recorded_at",
      "fsynced_at",
    ],
    ["outbox_entry_digest"],
  );
  if (input.version !== DURABLE_OUTBOX_VERSION) {
    throw new Error(`${label}.version must be ${DURABLE_OUTBOX_VERSION}`);
  }
  const sequence = assertInteger(input.sequence, `${label}.sequence`);
  const previousEntryDigest = input.previous_entry_digest == null
    ? null
    : assertDigest(input.previous_entry_digest, `${label}.previous_entry_digest`);
  if ((sequence === 0) !== (previousEntryDigest === null)) {
    throw new Error(`${label}.previous_entry_digest must be null exactly at sequence 0`);
  }
  const recordedAt = assertCanonicalTimestamp(input.recorded_at, `${label}.recorded_at`);
  const fsyncedAt = assertCanonicalTimestamp(input.fsynced_at, `${label}.fsynced_at`);
  assertTimeOrder(recordedAt, fsyncedAt, `${label} recorded_at -> fsynced_at`);
  const normalized = {
    version: DURABLE_OUTBOX_VERSION,
    outbox_entry_ref: normalizeOpaqueRef(
      input.outbox_entry_ref,
      `${label}.outbox_entry_ref`,
      { prefix: "outbox-entry" },
    ),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    source_journal_entry_digest: assertDigest(
      input.source_journal_entry_digest,
      `${label}.source_journal_entry_digest`,
    ),
    payload_kind: assertEnum(input.payload_kind, OUTBOX_PAYLOAD_KINDS, `${label}.payload_kind`),
    payload_ref: normalizeOpaqueRef(input.payload_ref, `${label}.payload_ref`),
    payload_digest: assertDigest(input.payload_digest, `${label}.payload_digest`),
    sequence,
    previous_entry_digest: previousEntryDigest,
    recorded_at: recordedAt,
    fsynced_at: fsyncedAt,
  };
  const outboxEntryDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "outbox_entry_digest", outboxEntryDigest, label);
  return deepFreeze({ ...normalized, outbox_entry_digest: outboxEntryDigest });
}

const OUTBOX_BINDING_FIELDS = Object.freeze([
  "attempt_ref",
  "instrument_ref",
  "lease_id",
  "fencing_token",
  "fencing_generation",
  "operation_id",
  "execution_request_digest",
]);

function assertDurableOutboxAppend(previousInput, nextInput) {
  const previous = normalizeDurableOutboxEntry(previousInput, "previous_durable_outbox_entry");
  const next = normalizeDurableOutboxEntry(nextInput, "next_durable_outbox_entry");
  assertExactBindings(next, previous, OUTBOX_BINDING_FIELDS, "durable_outbox_append");
  if (next.sequence !== previous.sequence + 1) {
    throw new Error("durable_outbox_append sequence must increment by exactly one");
  }
  if (next.previous_entry_digest !== previous.outbox_entry_digest) {
    throw new Error("durable_outbox_append previous_entry_digest does not bind the prior row");
  }
  assertTimeOrder(previous.fsynced_at, next.recorded_at, "durable_outbox_append ordering");
  return next;
}

function assertOutboxJournalBinding(outboxInput, journalInput) {
  const outbox = normalizeDurableOutboxEntry(outboxInput, "outbox_journal_binding.outbox_entry");
  const journal = normalizeAttemptJournalEntry(journalInput, "outbox_journal_binding.journal_entry");
  assertExactBindings(outbox, journal, OUTBOX_BINDING_FIELDS, "outbox_journal_binding");
  if (outbox.source_journal_entry_digest !== journal.journal_entry_digest) {
    throw new Error("outbox_journal_binding.source_journal_entry_digest does not bind the journal row");
  }
  assertTimeOrder(journal.fsynced_at, outbox.recorded_at, "outbox_journal_binding journal-before-outbox");
  return outbox;
}

function normalizeOutboxAcknowledgement(input, outboxInput, label = "outbox_acknowledgement") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "acknowledgement_ref",
      "outbox_entry_ref",
      "outbox_entry_digest",
      "recipient_principal_id",
      "acknowledged_at",
    ],
    ["acknowledgement_digest"],
  );
  if (input.version !== DURABLE_OUTBOX_VERSION) {
    throw new Error(`${label}.version must be ${DURABLE_OUTBOX_VERSION}`);
  }
  const outbox = normalizeDurableOutboxEntry(outboxInput, `${label}.outbox_entry`);
  const normalized = {
    version: DURABLE_OUTBOX_VERSION,
    acknowledgement_ref: normalizeOpaqueRef(
      input.acknowledgement_ref,
      `${label}.acknowledgement_ref`,
      { prefix: "outbox-ack" },
    ),
    outbox_entry_ref: normalizeOpaqueRef(
      input.outbox_entry_ref,
      `${label}.outbox_entry_ref`,
      { prefix: "outbox-entry" },
    ),
    outbox_entry_digest: assertDigest(input.outbox_entry_digest, `${label}.outbox_entry_digest`),
    recipient_principal_id: normalizeOpaqueRef(
      input.recipient_principal_id,
      `${label}.recipient_principal_id`,
      { prefix: "principal" },
    ),
    acknowledged_at: assertCanonicalTimestamp(input.acknowledged_at, `${label}.acknowledged_at`),
  };
  assertExactBindings(normalized, outbox, ["outbox_entry_ref", "outbox_entry_digest"], label);
  assertTimeOrder(outbox.fsynced_at, normalized.acknowledged_at, `${label} fsync-before-ack`);
  const acknowledgementDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "acknowledgement_digest", acknowledgementDigest, label);
  return deepFreeze({ ...normalized, acknowledgement_digest: acknowledgementDigest });
}

function providerStateReachableAtDistance(from, to, distance) {
  if (!numberIsSafeInteger(distance) || distance < 0 || distance >= ATTEMPT_STATE_VALUES.length) {
    return false;
  }
  let frontier = [from];
  for (let step = 0; step < distance; step += 1) {
    const seen = new SetConstructor();
    const nextFrontier = [];
    for (let stateIndex = 0; stateIndex < frontier.length; stateIndex += 1) {
      const transitions = ATTEMPT_TRANSITIONS[frontier[stateIndex]];
      for (let nextIndex = 0; nextIndex < transitions.length; nextIndex += 1) {
        const next = transitions[nextIndex];
        if (setHas(seen, next)) continue;
        setAdd(seen, next);
        arrayPush(nextFrontier, next);
      }
    }
    frontier = nextFrontier;
    if (frontier.length === 0) return false;
  }
  return arrayIncludes(frontier, to);
}

function assertProviderAlignedJournalState(journalInput, reportInput, operationRegistry) {
  const journal = normalizeAttemptJournalEntry(journalInput, "provider_alignment.journal_entry");
  const report = normalizeAttemptReport(reportInput, operationRegistry, "provider_alignment.provider_report");
  assertExactBindings(
    report,
    {
      attempt_ref: journal.attempt_ref,
      operation_id: journal.operation_id,
      request_digest: journal.provider_request_digest,
    },
    ["attempt_ref", "operation_id", "request_digest"],
    "provider_alignment",
  );
  const providerSequenceDelta = report.sequence - journal.provider_sequence;
  if (providerSequenceDelta < 0
      || !providerStateReachableAtDistance(
        journal.provider_state,
        report.state,
        providerSequenceDelta,
      )) {
    throw new Error(
      "provider_alignment report state/sequence "
      + `${report.state}@${report.sequence} is unreachable from journal state/sequence `
      + `${journal.provider_state}@${journal.provider_sequence}`,
    );
  }
  return report;
}

function normalizeSignatureEnvelope(input, payloadDigest, label) {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "method",
      "signer_key_id",
      "trust_root_epoch",
      "signed_payload_digest",
      "proof_ref",
      "proof_digest",
    ],
  );
  if (input.version !== SIGNED_ENVELOPE_VERSION) {
    throw new Error(`${label}.version must be ${SIGNED_ENVELOPE_VERSION}`);
  }
  const normalized = {
    version: SIGNED_ENVELOPE_VERSION,
    method: assertEnum(input.method, SIGNATURE_METHODS, `${label}.method`),
    signer_key_id: assertToken(input.signer_key_id, `${label}.signer_key_id`),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    signed_payload_digest: assertDigest(input.signed_payload_digest, `${label}.signed_payload_digest`),
    proof_ref: normalizeOpaqueRef(input.proof_ref, `${label}.proof_ref`, { prefix: "auth-proof" }),
    proof_digest: assertDigest(input.proof_digest, `${label}.proof_digest`),
  };
  if (normalized.signed_payload_digest !== payloadDigest) {
    throw new Error(`${label}.signed_payload_digest does not bind the normalized payload`);
  }
  return deepFreeze(normalized);
}

function normalizeTrustedSignatureVerification(input, label = "trusted_signature_verification") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "verified",
      "method",
      "signer_key_id",
      "trust_root_epoch",
      "verified_payload_digest",
      "verified_proof_digest",
      "signature_verifier_id",
      "signature_verdict_digest",
    ],
  );
  if (input.version !== SIGNED_ENVELOPE_VERSION) {
    throw new Error(`${label}.version must be ${SIGNED_ENVELOPE_VERSION}`);
  }
  if (input.verified !== true) throw new Error(`${label}.verified must be true`);
  return deepFreeze({
    version: SIGNED_ENVELOPE_VERSION,
    verified: true,
    method: assertEnum(input.method, SIGNATURE_METHODS, `${label}.method`),
    signer_key_id: assertToken(input.signer_key_id, `${label}.signer_key_id`),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    verified_payload_digest: assertDigest(
      input.verified_payload_digest,
      `${label}.verified_payload_digest`,
    ),
    verified_proof_digest: assertDigest(input.verified_proof_digest, `${label}.verified_proof_digest`),
    signature_verifier_id: assertToken(input.signature_verifier_id, `${label}.signature_verifier_id`),
    signature_verdict_digest: assertDigest(
      input.signature_verdict_digest,
      `${label}.signature_verdict_digest`,
    ),
  });
}

function assertSignatureVerification(envelope, trustedInput, label) {
  const trusted = normalizeTrustedSignatureVerification(trustedInput, label);
  const pairs = [
    [trusted.method, envelope.method, "method"],
    [trusted.signer_key_id, envelope.signer_key_id, "signer_key_id"],
    [trusted.trust_root_epoch, envelope.trust_root_epoch, "trust_root_epoch"],
    [trusted.verified_payload_digest, envelope.signed_payload_digest, "verified_payload_digest"],
    [trusted.verified_proof_digest, envelope.proof_digest, "verified_proof_digest"],
  ];
  for (const [actual, expected, field] of pairs) {
    if (actual !== expected) throw new Error(`${label}.${field} does not match the signed envelope`);
  }
  return trusted;
}

const STOP_OPERATION_BINDINGS = Object.freeze([
  "attempt_ref",
  "instrument_ref",
  "lease_id",
  "fencing_token",
  "fencing_generation",
  "operation_id",
  "execution_request_digest",
]);

function normalizeSignedStopRequest(input, label = "signed_stop_request") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "stop_request_ref",
      ...STOP_OPERATION_BINDINGS,
      "authority_epoch",
      "revocation_generation",
      "issuer_principal_id",
      "reason",
      "sequence",
      "nonce",
      "requested_at",
      "ack_deadline",
      "authentication",
    ],
    ["stop_request_digest"],
  );
  if (input.version !== STOP_PROTOCOL_VERSION) {
    throw new Error(`${label}.version must be ${STOP_PROTOCOL_VERSION}`);
  }
  const requestedAt = assertCanonicalTimestamp(input.requested_at, `${label}.requested_at`);
  const ackDeadline = assertCanonicalTimestamp(input.ack_deadline, `${label}.ack_deadline`);
  assertTimeOrder(requestedAt, ackDeadline, `${label} requested_at -> ack_deadline`, {
    allowEqual: false,
  });
  const payload = {
    version: STOP_PROTOCOL_VERSION,
    stop_request_ref: normalizeOpaqueRef(
      input.stop_request_ref,
      `${label}.stop_request_ref`,
      { prefix: "stop-request" },
    ),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
    ),
    issuer_principal_id: normalizeOpaqueRef(
      input.issuer_principal_id,
      `${label}.issuer_principal_id`,
      { prefix: "principal" },
    ),
    reason: assertEnum(input.reason, STOP_REASONS, `${label}.reason`),
    sequence: assertInteger(input.sequence, `${label}.sequence`, 1),
    nonce: assertToken(input.nonce, `${label}.nonce`),
    requested_at: requestedAt,
    ack_deadline: ackDeadline,
  };
  const stopRequestDigest = hashCanonicalJson(payload);
  assertDerivedDigest(input, "stop_request_digest", stopRequestDigest, label);
  const authentication = normalizeSignatureEnvelope(
    input.authentication,
    stopRequestDigest,
    `${label}.authentication`,
  );
  return deepFreeze({ ...payload, stop_request_digest: stopRequestDigest, authentication });
}

function projectVerifiedStopRequest(input, trustedInput) {
  const request = normalizeSignedStopRequest(input);
  const trusted = assertSignatureVerification(
    request.authentication,
    trustedInput,
    "trusted_stop_request_verification",
  );
  const projection = {
    version: STOP_PROTOCOL_VERSION,
    stop_request_digest: request.stop_request_digest,
    ...objectFromEntries(arrayMap(STOP_OPERATION_BINDINGS, (field) => [field, request[field]])),
    reason: request.reason,
    sequence: request.sequence,
    requested_at: request.requested_at,
    ack_deadline: request.ack_deadline,
    verified_signer_key_id: trusted.signer_key_id,
    verified_trust_root_epoch: trusted.trust_root_epoch,
    signature_verifier_id: trusted.signature_verifier_id,
    signature_verdict_digest: trusted.signature_verdict_digest,
  };
  return deepFreeze({ ...projection, verified_stop_request_digest: hashCanonicalJson(projection) });
}

function assertStopRequestLeaseBinding(requestInput, leaseInput) {
  const request = normalizeSignedStopRequest(requestInput);
  const lease = normalizeInstrumentLease(leaseInput);
  assertExactBindings(request, lease, STOP_OPERATION_BINDINGS, "signed_stop_request");
  if (!arrayIncludes(["held", "stop_requested", "fenced"], lease.state)) {
    throw new Error("signed_stop_request cannot target a terminal or restoring lease");
  }
  return request;
}

function requestInstrumentLeaseStop(
  priorInput,
  stopRequestInput,
  trustedInput,
  label = "instrument_lease_stop",
) {
  const prior = normalizeInstrumentLease(priorInput, `${label}.prior`);
  if (prior.state !== "held") throw new Error(`${label} requires a held lease`);
  const request = assertStopRequestLeaseBinding(stopRequestInput, prior);
  projectVerifiedStopRequest(request, trustedInput);
  if (parseTimestamp(request.requested_at) < parseTimestamp(prior.updated_at)) {
    throw new Error(`${label}.requested_at predates the current lease state`);
  }
  const result = {
    ...prior,
    state: "stop_requested",
    sequence: prior.sequence + 1,
    updated_at: request.requested_at,
  };
  delete result.lease_digest;
  return normalizeInstrumentLease(result, `${label}.result`);
}

function normalizeSignedStopAcknowledgement(
  input,
  stopRequestInput,
  leaseInput,
  label = "signed_stop_acknowledgement",
) {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "stop_ack_ref",
      "stop_request_digest",
      ...STOP_OPERATION_BINDINGS,
      "acknowledger_kind",
      "acknowledger_principal_id",
      "observed_stop_sequence",
      "outcome",
      "emission_state",
      "provider_receipt_ref",
      "provider_receipt_digest",
      "acknowledged_at",
      "authentication",
    ],
    ["stop_ack_digest", "deadline_met"],
  );
  if (input.version !== STOP_PROTOCOL_VERSION) {
    throw new Error(`${label}.version must be ${STOP_PROTOCOL_VERSION}`);
  }
  const request = assertStopRequestLeaseBinding(stopRequestInput, leaseInput);
  const outcome = assertEnum(input.outcome, STOP_ACK_OUTCOMES, `${label}.outcome`);
  const acknowledgerKind = assertEnum(
    input.acknowledger_kind,
    STOP_ACKNOWLEDGER_KINDS,
    `${label}.acknowledger_kind`,
  );
  const emissionState = assertEnum(input.emission_state, EMISSION_STATE_VALUES, `${label}.emission_state`);
  if (outcome === "stopped" && emissionState !== "inhibited") {
    throw new Error(`${label}.stopped requires independently reportable inhibited emission state`);
  }
  if (outcome === "stopped" && acknowledgerKind !== "active_worker") {
    throw new Error(`${label}.stopped must be acknowledged by the active worker`);
  }
  if (outcome === "forced" && (acknowledgerKind !== "safety_supervisor" || emissionState !== "inhibited")) {
    throw new Error(`${label}.forced requires a safety-supervisor acknowledgement of inhibited emission`);
  }
  if (outcome === "cannot_confirm" && emissionState !== "unknown") {
    throw new Error(`${label}.cannot_confirm must preserve unknown emission state`);
  }
  const acknowledgedAt = assertCanonicalTimestamp(input.acknowledged_at, `${label}.acknowledged_at`);
  assertTimeOrder(request.requested_at, acknowledgedAt, `${label} requested_at -> acknowledged_at`);
  const payload = {
    version: STOP_PROTOCOL_VERSION,
    stop_ack_ref: normalizeOpaqueRef(input.stop_ack_ref, `${label}.stop_ack_ref`, {
      prefix: "stop-ack",
    }),
    stop_request_digest: assertDigest(input.stop_request_digest, `${label}.stop_request_digest`),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    acknowledger_kind: acknowledgerKind,
    acknowledger_principal_id: normalizeOpaqueRef(
      input.acknowledger_principal_id,
      `${label}.acknowledger_principal_id`,
      { prefix: "principal" },
    ),
    observed_stop_sequence: assertInteger(
      input.observed_stop_sequence,
      `${label}.observed_stop_sequence`,
      1,
    ),
    outcome,
    emission_state: emissionState,
    provider_receipt_ref: normalizeOpaqueRef(
      input.provider_receipt_ref,
      `${label}.provider_receipt_ref`,
      { prefix: "receipt" },
    ),
    provider_receipt_digest: assertDigest(
      input.provider_receipt_digest,
      `${label}.provider_receipt_digest`,
    ),
    acknowledged_at: acknowledgedAt,
  };
  if (payload.stop_request_digest !== request.stop_request_digest) {
    throw new Error(`${label}.stop_request_digest does not bind the request`);
  }
  assertExactBindings(payload, request, STOP_OPERATION_BINDINGS, label);
  if (payload.observed_stop_sequence !== request.sequence) {
    throw new Error(`${label}.observed_stop_sequence does not bind the request sequence`);
  }
  if (payload.acknowledger_kind === "active_worker"
      && payload.acknowledger_principal_id !== normalizeInstrumentLease(leaseInput).execution_principal_id) {
    throw new Error(`${label}.acknowledger_principal_id is not the leased active worker`);
  }
  const stopAckDigest = hashCanonicalJson(payload);
  assertDerivedDigest(input, "stop_ack_digest", stopAckDigest, label);
  const deadlineMet = parseTimestamp(acknowledgedAt) <= parseTimestamp(request.ack_deadline);
  if (hasOwn(input, "deadline_met")
      && input.deadline_met !== deadlineMet) {
    throw new Error(`${label}.deadline_met does not match the bound timestamps`);
  }
  const authentication = normalizeSignatureEnvelope(
    input.authentication,
    stopAckDigest,
    `${label}.authentication`,
  );
  return deepFreeze({
    ...payload,
    stop_ack_digest: stopAckDigest,
    deadline_met: deadlineMet,
    authentication,
  });
}

function projectVerifiedStopAcknowledgement(
  input,
  stopRequest,
  lease,
  trustedAckInput,
  trustedRequestInput,
) {
  const verifiedRequest = projectVerifiedStopRequest(stopRequest, trustedRequestInput);
  const acknowledgement = normalizeSignedStopAcknowledgement(input, stopRequest, lease);
  const trusted = assertSignatureVerification(
    acknowledgement.authentication,
    trustedAckInput,
    "trusted_stop_ack_verification",
  );
  const projection = {
    version: STOP_PROTOCOL_VERSION,
    stop_ack_digest: acknowledgement.stop_ack_digest,
    stop_request_digest: acknowledgement.stop_request_digest,
    verified_stop_request_digest: verifiedRequest.verified_stop_request_digest,
    ...objectFromEntries(
      arrayMap(STOP_OPERATION_BINDINGS, (field) => [field, acknowledgement[field]]),
    ),
    outcome: acknowledgement.outcome,
    acknowledger_kind: acknowledgement.acknowledger_kind,
    acknowledger_principal_id: acknowledgement.acknowledger_principal_id,
    emission_state: acknowledgement.emission_state,
    acknowledged_at: acknowledgement.acknowledged_at,
    deadline_met: acknowledgement.deadline_met,
    verified_signer_key_id: trusted.signer_key_id,
    verified_trust_root_epoch: trusted.trust_root_epoch,
    signature_verifier_id: trusted.signature_verifier_id,
    signature_verdict_digest: trusted.signature_verdict_digest,
  };
  return deepFreeze({ ...projection, verified_stop_ack_digest: hashCanonicalJson(projection) });
}

function normalizeSafetySupervisorContract(input, label = "safety_supervisor_contract") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "supervisor_ref",
      "supervisor_principal_id",
      "supervisor_signer_key_id",
      "trust_root_epoch",
      "safety_root_ref",
      ...STOP_OPERATION_BINDINGS,
      "worker_principal_id",
      "worker_heartbeat_signer_key_id",
      "cleanup_capability_digest",
      "authority_epoch",
      "revocation_generation",
      "heartbeat_interval_ms",
      "miss_tolerance",
      "stop_ack_deadline_ms",
      "containment_mode",
      "containment_actions",
      "operator_containment_plan_digest",
    ],
    ["supervisor_contract_digest"],
  );
  if (input.version !== SAFETY_SUPERVISOR_VERSION) {
    throw new Error(`${label}.version must be ${SAFETY_SUPERVISOR_VERSION}`);
  }
  const containmentMode = assertEnum(
    input.containment_mode,
    CONTAINMENT_MODES,
    `${label}.containment_mode`,
  );
  const containmentActions = normalizeUniqueSorted(
    input.containment_actions,
    `${label}.containment_actions`,
    (value, itemLabel) => assertEnum(value, CONTAINMENT_ACTIONS, itemLabel),
    { min: 1, max: CONTAINMENT_ACTIONS.length },
  );
  const operatorPlan = input.operator_containment_plan_digest == null
    ? null
    : assertDigest(
      input.operator_containment_plan_digest,
      `${label}.operator_containment_plan_digest`,
    );
  if (containmentMode === "operator_containment" && operatorPlan == null) {
    throw new Error(`${label}.operator_containment requires a precommitted containment plan`);
  }
  if (containmentMode === "electronic" && operatorPlan != null) {
    throw new Error(`${label}.electronic mode cannot imply an operator-only fallback`);
  }
  if (containmentMode === "electronic"
      && !arraySome(containmentActions, (action) => arrayIncludes([
        "device_reset",
        "power_isolation",
        "rf_interlock",
      ], action))) {
    throw new Error(`${label}.electronic mode requires an independent device/RF/power action`);
  }
  const heartbeatIntervalMs = assertInteger(
    input.heartbeat_interval_ms,
    `${label}.heartbeat_interval_ms`,
    1,
  );
  const missTolerance = assertInteger(input.miss_tolerance, `${label}.miss_tolerance`, 1);
  // Divide before multiplying so even two individually safe integers cannot
  // overflow or round into an effectively unbounded liveness policy.
  if (heartbeatIntervalMs > mathFloor(MAX_SUPERVISOR_DEADMAN_WINDOW_MS / missTolerance)) {
    throw new Error(
      `${label} deadman window must not exceed ${MAX_SUPERVISOR_DEADMAN_WINDOW_MS} milliseconds`,
    );
  }
  const normalized = {
    version: SAFETY_SUPERVISOR_VERSION,
    supervisor_ref: normalizeOpaqueRef(input.supervisor_ref, `${label}.supervisor_ref`, {
      prefix: "safety-supervisor",
    }),
    supervisor_principal_id: normalizeOpaqueRef(
      input.supervisor_principal_id,
      `${label}.supervisor_principal_id`,
      { prefix: "principal" },
    ),
    supervisor_signer_key_id: assertToken(
      input.supervisor_signer_key_id,
      `${label}.supervisor_signer_key_id`,
    ),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    safety_root_ref: normalizeOpaqueRef(input.safety_root_ref, `${label}.safety_root_ref`, {
      prefix: "safety-root",
    }),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    worker_principal_id: normalizeOpaqueRef(
      input.worker_principal_id,
      `${label}.worker_principal_id`,
      { prefix: "principal" },
    ),
    worker_heartbeat_signer_key_id: assertToken(
      input.worker_heartbeat_signer_key_id,
      `${label}.worker_heartbeat_signer_key_id`,
    ),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    cleanup_capability_digest: assertDigest(
      input.cleanup_capability_digest,
      `${label}.cleanup_capability_digest`,
    ),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
    ),
    heartbeat_interval_ms: heartbeatIntervalMs,
    miss_tolerance: missTolerance,
    stop_ack_deadline_ms: assertInteger(
      input.stop_ack_deadline_ms,
      `${label}.stop_ack_deadline_ms`,
      1,
    ),
    containment_mode: containmentMode,
    containment_actions: containmentActions,
    operator_containment_plan_digest: operatorPlan,
  };
  const supervisorContractDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "supervisor_contract_digest", supervisorContractDigest, label);
  return deepFreeze({ ...normalized, supervisor_contract_digest: supervisorContractDigest });
}

function assertSupervisorLeaseBinding(supervisorInput, leaseInput) {
  const supervisor = normalizeSafetySupervisorContract(supervisorInput);
  const lease = normalizeInstrumentLease(leaseInput);
  assertExactBindings(supervisor, lease, STOP_OPERATION_BINDINGS, "safety_supervisor_contract");
  return { supervisor, lease };
}

function normalizeSignedDeadmanHeartbeat(input, supervisorInput, label = "signed_deadman_heartbeat") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "heartbeat_ref",
      "supervisor_contract_digest",
      ...STOP_OPERATION_BINDINGS,
      "worker_principal_id",
      "heartbeat_sequence",
      "authority_epoch",
      "revocation_generation",
      "emitted_at",
      "valid_until",
      "authentication",
    ],
    ["heartbeat_digest"],
  );
  if (input.version !== SAFETY_SUPERVISOR_VERSION) {
    throw new Error(`${label}.version must be ${SAFETY_SUPERVISOR_VERSION}`);
  }
  const supervisor = normalizeSafetySupervisorContract(supervisorInput, `${label}.supervisor_contract`);
  const emittedAt = assertCanonicalTimestamp(input.emitted_at, `${label}.emitted_at`);
  const validUntil = assertCanonicalTimestamp(input.valid_until, `${label}.valid_until`);
  assertTimeOrder(emittedAt, validUntil, `${label} emitted_at -> valid_until`, { allowEqual: false });
  const maximumValidity = supervisor.heartbeat_interval_ms * supervisor.miss_tolerance;
  if (parseTimestamp(validUntil) - parseTimestamp(emittedAt) > maximumValidity) {
    throw new Error(`${label}.valid_until exceeds the supervisor deadman window`);
  }
  const payload = {
    version: SAFETY_SUPERVISOR_VERSION,
    heartbeat_ref: normalizeOpaqueRef(input.heartbeat_ref, `${label}.heartbeat_ref`, {
      prefix: "heartbeat",
    }),
    supervisor_contract_digest: assertDigest(
      input.supervisor_contract_digest,
      `${label}.supervisor_contract_digest`,
    ),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    worker_principal_id: normalizeOpaqueRef(
      input.worker_principal_id,
      `${label}.worker_principal_id`,
      { prefix: "principal" },
    ),
    heartbeat_sequence: assertInteger(input.heartbeat_sequence, `${label}.heartbeat_sequence`, 1),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
    ),
    emitted_at: emittedAt,
    valid_until: validUntil,
  };
  if (payload.supervisor_contract_digest !== supervisor.supervisor_contract_digest) {
    throw new Error(`${label}.supervisor_contract_digest binding drift`);
  }
  assertExactBindings(payload, supervisor, STOP_OPERATION_BINDINGS, label);
  for (const field of ["worker_principal_id", "authority_epoch", "revocation_generation"]) {
    if (payload[field] !== supervisor[field]) throw new Error(`${label}.${field} binding drift`);
  }
  const heartbeatDigest = hashCanonicalJson(payload);
  assertDerivedDigest(input, "heartbeat_digest", heartbeatDigest, label);
  const authentication = normalizeSignatureEnvelope(
    input.authentication,
    heartbeatDigest,
    `${label}.authentication`,
  );
  if (authentication.signer_key_id !== supervisor.worker_heartbeat_signer_key_id
      || authentication.trust_root_epoch !== supervisor.trust_root_epoch) {
    throw new Error(`${label}.authentication is not bound to the enrolled worker heartbeat key`);
  }
  return deepFreeze({ ...payload, heartbeat_digest: heartbeatDigest, authentication });
}

function assertDeadmanHeartbeatTransition(
  previousInput,
  nextInput,
  supervisorInput,
  label = "deadman_heartbeat_transition",
) {
  const supervisor = normalizeSafetySupervisorContract(
    supervisorInput,
    `${label}.supervisor_contract`,
  );
  const previous = normalizeSignedDeadmanHeartbeat(previousInput, supervisor, `${label}.previous`);
  const next = normalizeSignedDeadmanHeartbeat(nextInput, supervisor, `${label}.next`);
  if (next.heartbeat_sequence !== previous.heartbeat_sequence + 1) {
    throw new Error(`${label}.heartbeat_sequence must increment by exactly one`);
  }
  if (next.heartbeat_ref === previous.heartbeat_ref) {
    throw new Error(`${label}.heartbeat_ref must be unique`);
  }
  assertTimeOrder(previous.emitted_at, next.emitted_at, `${label} emitted_at ordering`, {
    allowEqual: false,
  });
  assertTimeOrder(previous.valid_until, next.valid_until, `${label} valid_until ordering`, {
    allowEqual: false,
  });
  return next;
}

function evaluateSafetySupervisor(input, label = "safety_supervisor_evaluation") {
  assertClosedObject(
    input,
    label,
    [
      "supervisor_contract",
      "lease",
      "heartbeat",
      "heartbeat_verification",
      "observed_at",
      "authority_epoch",
      "revocation_generation",
      "provider_reachable",
      "worker_alive",
    ],
  );
  const { supervisor, lease } = assertSupervisorLeaseBinding(
    input.supervisor_contract,
    input.lease,
  );
  const observedAt = assertCanonicalTimestamp(input.observed_at, `${label}.observed_at`);
  const authorityEpoch = assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1);
  const revocationGeneration = assertInteger(
    input.revocation_generation,
    `${label}.revocation_generation`,
  );
  const providerReachable = assertBoolean(input.provider_reachable, `${label}.provider_reachable`);
  const workerAlive = assertBoolean(input.worker_alive, `${label}.worker_alive`);
  const heartbeat = input.heartbeat == null
    ? null
    : normalizeSignedDeadmanHeartbeat(input.heartbeat, supervisor, `${label}.heartbeat`);
  if ((heartbeat == null) !== (input.heartbeat_verification == null)) {
    throw new Error(`${label}.heartbeat and heartbeat_verification must appear together`);
  }
  if (heartbeat != null) {
    assertSignatureVerification(
      heartbeat.authentication,
      input.heartbeat_verification,
      `${label}.heartbeat_verification`,
    );
    assertTimeOrder(lease.acquired_at, heartbeat.emitted_at, `${label} lease -> heartbeat`);
    assertTimeOrder(heartbeat.emitted_at, observedAt, `${label} heartbeat -> observation`);
    if (parseTimestamp(heartbeat.valid_until) > parseTimestamp(lease.heartbeat_deadline)) {
      throw new Error(`${label}.heartbeat cannot extend beyond the durable lease heartbeat deadline`);
    }
  }

  const reasons = [];
  let decision = "continue";
  if (arrayIncludes(["released", "quarantined"], lease.state)) {
    decision = "inactive";
    arrayPush(reasons, `lease_${lease.state}`);
  } else if (lease.state !== "held") {
    decision = "stop_fence_cleanup";
    arrayPush(reasons, `lease_${lease.state}`);
  } else {
    if (authorityEpoch !== supervisor.authority_epoch) {
      arrayPush(reasons, "authority_epoch_drift");
    }
    if (revocationGeneration !== supervisor.revocation_generation) {
      arrayPush(reasons, "revocation_generation_drift");
    }
    if (!providerReachable) arrayPush(reasons, "provider_unreachable");
    if (!workerAlive) arrayPush(reasons, "worker_exit");
    if (parseTimestamp(observedAt) > parseTimestamp(lease.expires_at)) {
      arrayPush(reasons, "lease_expired");
    }
    if (heartbeat == null
        || parseTimestamp(observedAt) > parseTimestamp(heartbeat.valid_until)
        || parseTimestamp(observedAt) > parseTimestamp(lease.heartbeat_deadline)) {
      arrayPush(reasons, "deadman_missed");
    }
    if (reasons.length > 0) decision = "stop_fence_cleanup";
  }
  assertEnum(decision, SUPERVISOR_DECISIONS, `${label}.decision`);
  const normalized = {
    version: SAFETY_SUPERVISOR_VERSION,
    supervisor_contract_digest: supervisor.supervisor_contract_digest,
    lease_digest: lease.lease_digest,
    heartbeat_digest: heartbeat == null ? null : heartbeat.heartbeat_digest,
    observed_at: observedAt,
    decision,
    reasons: objectFreeze(uniqueSortedArray(reasons)),
    containment_mode: supervisor.containment_mode,
    containment_actions: supervisor.containment_actions,
    automatic_retry_allowed: false,
  };
  return deepFreeze({ ...normalized, evaluation_digest: hashCanonicalJson(normalized) });
}

function normalizeRecoveryWorkerBootstrap(
  input,
  cleanupCapabilityInput,
  effectRegistry,
  label = "recovery_worker_bootstrap",
) {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "bootstrap_ref",
      "bootstrap_source",
      "supervisor_principal_id",
      "supervisor_signer_key_id",
      "trust_root_epoch",
      "recovery_principal_id",
      "recovery_receipt_signer_key_id",
      "safety_root_ref",
      "safety_root_status",
      "cleanup_capability_digest",
      "source_execution_request_digest",
      "attempt_ref",
      "instrument_ref",
      "enrolled_device_identity_digest",
      "provider_manifest_digest",
      "recovery_worker_binary_digest",
      "lease_id",
      "fencing_token",
      "fencing_generation",
      "workspace_snapshot_ref",
      "workspace_snapshot_digest",
      "restore_operation_id",
      "restore_operation_digest",
      "cleanup_plan_digest",
      "expected_terminal_state_digest",
      "snapshot_materialization_capability_ref",
      "snapshot_materialization_capability_digest",
      "allowed_operation_ids",
      "allowed_materialization_refs",
      "agent_channel_enabled",
      "administration_enabled",
      "destruction_enabled",
      "one_time",
      "nonce",
      "not_before",
      "expires_at",
      "authentication",
    ],
    ["recovery_bootstrap_digest"],
  );
  if (input.version !== RECOVERY_BOOTSTRAP_VERSION) {
    throw new Error(`${label}.version must be ${RECOVERY_BOOTSTRAP_VERSION}`);
  }
  if (input.bootstrap_source !== "safety_supervisor") {
    throw new Error(`${label}.bootstrap_source must be safety_supervisor`);
  }
  if (input.safety_root_status !== "trusted") {
    throw new Error(`${label}.safety_root_status must be trusted; compromise requires quarantine`);
  }
  if (input.agent_channel_enabled !== false
      || input.administration_enabled !== false
      || input.destruction_enabled !== false
      || input.one_time !== true) {
    throw new Error(`${label} must be one-time, agent-isolated, restore-only authority`);
  }
  const capability = normalizeCleanupCapability(
    cleanupCapabilityInput,
    effectRegistry,
    `${label}.cleanup_capability`,
  );
  const notBefore = assertCanonicalTimestamp(input.not_before, `${label}.not_before`);
  const expiresAt = assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`);
  assertTimeOrder(notBefore, expiresAt, `${label} not_before -> expires_at`, { allowEqual: false });
  const allowedOperationIds = normalizeUniqueSorted(
    input.allowed_operation_ids,
    `${label}.allowed_operation_ids`,
    assertToken,
    { min: 1, max: 1 },
  );
  const allowedMaterializationRefs = normalizeUniqueSorted(
    input.allowed_materialization_refs,
    `${label}.allowed_materialization_refs`,
    (value, itemLabel) => normalizeOpaqueRef(value, itemLabel, { prefix: "workspace-snapshot" }),
    { min: 1, max: 1 },
  );
  if (allowedOperationIds[0] !== capability.restore_operation_id) {
    throw new Error(`${label}.allowed_operation_ids must contain only the precommitted restore operation`);
  }
  if (allowedMaterializationRefs[0] !== capability.workspace_snapshot_ref) {
    throw new Error(`${label}.allowed_materialization_refs must contain only the precommitted snapshot`);
  }
  const normalized = {
    version: RECOVERY_BOOTSTRAP_VERSION,
    bootstrap_ref: normalizeOpaqueRef(input.bootstrap_ref, `${label}.bootstrap_ref`, {
      prefix: "recovery-bootstrap",
    }),
    bootstrap_source: "safety_supervisor",
    supervisor_principal_id: normalizeOpaqueRef(
      input.supervisor_principal_id,
      `${label}.supervisor_principal_id`,
      { prefix: "principal" },
    ),
    supervisor_signer_key_id: assertToken(
      input.supervisor_signer_key_id,
      `${label}.supervisor_signer_key_id`,
    ),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    recovery_principal_id: normalizeOpaqueRef(
      input.recovery_principal_id,
      `${label}.recovery_principal_id`,
      { prefix: "principal" },
    ),
    recovery_receipt_signer_key_id: assertToken(
      input.recovery_receipt_signer_key_id,
      `${label}.recovery_receipt_signer_key_id`,
    ),
    safety_root_ref: normalizeOpaqueRef(input.safety_root_ref, `${label}.safety_root_ref`, {
      prefix: "safety-root",
    }),
    safety_root_status: "trusted",
    cleanup_capability_digest: assertDigest(
      input.cleanup_capability_digest,
      `${label}.cleanup_capability_digest`,
    ),
    source_execution_request_digest: assertDigest(
      input.source_execution_request_digest,
      `${label}.source_execution_request_digest`,
    ),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    enrolled_device_identity_digest: assertDigest(
      input.enrolled_device_identity_digest,
      `${label}.enrolled_device_identity_digest`,
    ),
    provider_manifest_digest: assertDigest(
      input.provider_manifest_digest,
      `${label}.provider_manifest_digest`,
    ),
    recovery_worker_binary_digest: assertDigest(
      input.recovery_worker_binary_digest,
      `${label}.recovery_worker_binary_digest`,
    ),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    workspace_snapshot_ref: normalizeOpaqueRef(
      input.workspace_snapshot_ref,
      `${label}.workspace_snapshot_ref`,
      { prefix: "workspace-snapshot" },
    ),
    workspace_snapshot_digest: assertDigest(
      input.workspace_snapshot_digest,
      `${label}.workspace_snapshot_digest`,
    ),
    restore_operation_id: assertToken(input.restore_operation_id, `${label}.restore_operation_id`),
    restore_operation_digest: assertDigest(
      input.restore_operation_digest,
      `${label}.restore_operation_digest`,
    ),
    cleanup_plan_digest: assertDigest(input.cleanup_plan_digest, `${label}.cleanup_plan_digest`),
    expected_terminal_state_digest: assertDigest(
      input.expected_terminal_state_digest,
      `${label}.expected_terminal_state_digest`,
    ),
    snapshot_materialization_capability_ref: normalizeOpaqueRef(
      input.snapshot_materialization_capability_ref,
      `${label}.snapshot_materialization_capability_ref`,
      { prefix: "vault-capability" },
    ),
    snapshot_materialization_capability_digest: assertDigest(
      input.snapshot_materialization_capability_digest,
      `${label}.snapshot_materialization_capability_digest`,
    ),
    allowed_operation_ids: allowedOperationIds,
    allowed_materialization_refs: allowedMaterializationRefs,
    agent_channel_enabled: false,
    administration_enabled: false,
    destruction_enabled: false,
    one_time: true,
    nonce: assertToken(input.nonce, `${label}.nonce`),
    not_before: notBefore,
    expires_at: expiresAt,
  };
  const capabilityBindings = [
    "recovery_principal_id",
    "safety_root_ref",
    "cleanup_capability_digest",
    "source_execution_request_digest",
    "instrument_ref",
    "lease_id",
    "fencing_token",
    "workspace_snapshot_ref",
    "workspace_snapshot_digest",
    "restore_operation_id",
    "restore_operation_digest",
    "cleanup_plan_digest",
  ];
  for (const field of capabilityBindings) {
    const expected = field === "cleanup_capability_digest" ? capability.capability_digest : capability[field];
    if (normalized[field] !== expected) throw new Error(`${label}.${field} redirects cleanup authority`);
  }
  const recoveryBootstrapDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "recovery_bootstrap_digest", recoveryBootstrapDigest, label);
  const authentication = normalizeSignatureEnvelope(
    input.authentication,
    recoveryBootstrapDigest,
    `${label}.authentication`,
  );
  if (authentication.signer_key_id !== normalized.supervisor_signer_key_id
      || authentication.trust_root_epoch !== normalized.trust_root_epoch) {
    throw new Error(`${label}.authentication is not bound to the enrolled safety-supervisor key`);
  }
  return deepFreeze({
    ...normalized,
    recovery_bootstrap_digest: recoveryBootstrapDigest,
    authentication,
  });
}

function projectVerifiedRecoveryWorkerBootstrap(
  input,
  cleanupCapability,
  effectRegistry,
  supervisorInput,
  trustedInput,
) {
  const bootstrap = normalizeRecoveryWorkerBootstrap(input, cleanupCapability, effectRegistry);
  const supervisor = normalizeSafetySupervisorContract(
    supervisorInput,
    "recovery_bootstrap_supervisor_contract",
  );
  const supervisorBindings = [
    [bootstrap.supervisor_principal_id, supervisor.supervisor_principal_id, "supervisor_principal_id"],
    [bootstrap.supervisor_signer_key_id, supervisor.supervisor_signer_key_id, "supervisor_signer_key_id"],
    [bootstrap.trust_root_epoch, supervisor.trust_root_epoch, "trust_root_epoch"],
    [bootstrap.safety_root_ref, supervisor.safety_root_ref, "safety_root_ref"],
    [bootstrap.cleanup_capability_digest, supervisor.cleanup_capability_digest, "cleanup_capability_digest"],
    [bootstrap.source_execution_request_digest, supervisor.execution_request_digest,
      "source_execution_request_digest"],
    [bootstrap.attempt_ref, supervisor.attempt_ref, "attempt_ref"],
    [bootstrap.instrument_ref, supervisor.instrument_ref, "instrument_ref"],
    [bootstrap.lease_id, supervisor.lease_id, "lease_id"],
    [bootstrap.fencing_token, supervisor.fencing_token, "fencing_token"],
    [bootstrap.fencing_generation, supervisor.fencing_generation, "fencing_generation"],
  ];
  for (const [actual, expected, field] of supervisorBindings) {
    if (actual !== expected) throw new Error(`recovery_worker_bootstrap.${field} is detached from the supervisor`);
  }
  const trusted = assertSignatureVerification(
    bootstrap.authentication,
    trustedInput,
    "trusted_recovery_bootstrap_verification",
  );
  const projection = {
    version: RECOVERY_BOOTSTRAP_VERSION,
    supervisor_contract_digest: supervisor.supervisor_contract_digest,
    recovery_bootstrap_digest: bootstrap.recovery_bootstrap_digest,
    cleanup_capability_digest: bootstrap.cleanup_capability_digest,
    source_execution_request_digest: bootstrap.source_execution_request_digest,
    attempt_ref: bootstrap.attempt_ref,
    instrument_ref: bootstrap.instrument_ref,
    lease_id: bootstrap.lease_id,
    fencing_token: bootstrap.fencing_token,
    fencing_generation: bootstrap.fencing_generation,
    recovery_principal_id: bootstrap.recovery_principal_id,
    recovery_receipt_signer_key_id: bootstrap.recovery_receipt_signer_key_id,
    supervisor_signer_key_id: bootstrap.supervisor_signer_key_id,
    trust_root_epoch: bootstrap.trust_root_epoch,
    workspace_snapshot_ref: bootstrap.workspace_snapshot_ref,
    workspace_snapshot_digest: bootstrap.workspace_snapshot_digest,
    restore_operation_id: bootstrap.restore_operation_id,
    restore_operation_digest: bootstrap.restore_operation_digest,
    cleanup_plan_digest: bootstrap.cleanup_plan_digest,
    expected_terminal_state_digest: bootstrap.expected_terminal_state_digest,
    not_before: bootstrap.not_before,
    expires_at: bootstrap.expires_at,
    verified_signer_key_id: trusted.signer_key_id,
    verified_trust_root_epoch: trusted.trust_root_epoch,
    signature_verifier_id: trusted.signature_verifier_id,
    signature_verdict_digest: trusted.signature_verdict_digest,
  };
  const verifiedProjection = deepFreeze({
    ...projection,
    verified_bootstrap_digest: hashCanonicalJson(projection),
  });
  apply(weakSetPrototypeAdd, VERIFIED_RECOVERY_BOOTSTRAP_PROJECTIONS, [verifiedProjection]);
  return verifiedProjection;
}

function normalizeVerifiedRecoveryBootstrapProjection(
  input,
  label = "verified_recovery_bootstrap",
) {
  const fields = [
    "version",
    "supervisor_contract_digest",
    "recovery_bootstrap_digest",
    "cleanup_capability_digest",
    "source_execution_request_digest",
    "attempt_ref",
    "instrument_ref",
    "lease_id",
    "fencing_token",
    "fencing_generation",
    "recovery_principal_id",
    "recovery_receipt_signer_key_id",
    "supervisor_signer_key_id",
    "trust_root_epoch",
    "workspace_snapshot_ref",
    "workspace_snapshot_digest",
    "restore_operation_id",
    "restore_operation_digest",
    "cleanup_plan_digest",
    "expected_terminal_state_digest",
    "not_before",
    "expires_at",
    "verified_signer_key_id",
    "verified_trust_root_epoch",
    "signature_verifier_id",
    "signature_verdict_digest",
  ];
  assertClosedObject(input, label, fields, ["verified_bootstrap_digest"]);
  if (input.version !== RECOVERY_BOOTSTRAP_VERSION) {
    throw new Error(`${label}.version must be ${RECOVERY_BOOTSTRAP_VERSION}`);
  }
  const normalized = {
    version: RECOVERY_BOOTSTRAP_VERSION,
    supervisor_contract_digest: assertDigest(
      input.supervisor_contract_digest,
      `${label}.supervisor_contract_digest`,
    ),
    recovery_bootstrap_digest: assertDigest(
      input.recovery_bootstrap_digest,
      `${label}.recovery_bootstrap_digest`,
    ),
    cleanup_capability_digest: assertDigest(
      input.cleanup_capability_digest,
      `${label}.cleanup_capability_digest`,
    ),
    source_execution_request_digest: assertDigest(
      input.source_execution_request_digest,
      `${label}.source_execution_request_digest`,
    ),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    recovery_principal_id: normalizeOpaqueRef(
      input.recovery_principal_id,
      `${label}.recovery_principal_id`,
      { prefix: "principal" },
    ),
    recovery_receipt_signer_key_id: assertToken(
      input.recovery_receipt_signer_key_id,
      `${label}.recovery_receipt_signer_key_id`,
    ),
    supervisor_signer_key_id: assertToken(
      input.supervisor_signer_key_id,
      `${label}.supervisor_signer_key_id`,
    ),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    workspace_snapshot_ref: normalizeOpaqueRef(
      input.workspace_snapshot_ref,
      `${label}.workspace_snapshot_ref`,
      { prefix: "workspace-snapshot" },
    ),
    workspace_snapshot_digest: assertDigest(
      input.workspace_snapshot_digest,
      `${label}.workspace_snapshot_digest`,
    ),
    restore_operation_id: assertToken(input.restore_operation_id, `${label}.restore_operation_id`),
    restore_operation_digest: assertDigest(
      input.restore_operation_digest,
      `${label}.restore_operation_digest`,
    ),
    cleanup_plan_digest: assertDigest(input.cleanup_plan_digest, `${label}.cleanup_plan_digest`),
    expected_terminal_state_digest: assertDigest(
      input.expected_terminal_state_digest,
      `${label}.expected_terminal_state_digest`,
    ),
    not_before: assertCanonicalTimestamp(input.not_before, `${label}.not_before`),
    expires_at: assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`),
    verified_signer_key_id: assertToken(
      input.verified_signer_key_id,
      `${label}.verified_signer_key_id`,
    ),
    verified_trust_root_epoch: assertInteger(
      input.verified_trust_root_epoch,
      `${label}.verified_trust_root_epoch`,
      1,
    ),
    signature_verifier_id: assertToken(input.signature_verifier_id, `${label}.signature_verifier_id`),
    signature_verdict_digest: assertDigest(
      input.signature_verdict_digest,
      `${label}.signature_verdict_digest`,
    ),
  };
  if (normalized.verified_signer_key_id !== normalized.supervisor_signer_key_id
      || normalized.verified_trust_root_epoch !== normalized.trust_root_epoch) {
    throw new Error(`${label} signer projection drift`);
  }
  assertTimeOrder(
    normalized.not_before,
    normalized.expires_at,
    `${label} not_before -> expires_at`,
    { allowEqual: false },
  );
  const verifiedBootstrapDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "verified_bootstrap_digest", verifiedBootstrapDigest, label);
  return deepFreeze({ ...normalized, verified_bootstrap_digest: verifiedBootstrapDigest });
}

function assertVerifiedRecoveryBootstrapProjection(
  input,
  label = "verified_recovery_bootstrap",
) {
  if (!apply(weakSetPrototypeHas, VERIFIED_RECOVERY_BOOTSTRAP_PROJECTIONS, [input])) {
    throw new Error(`${label} was not issued by the recovery-bootstrap verifier`);
  }
  return normalizeVerifiedRecoveryBootstrapProjection(input, label);
}

function normalizeSignedRestorationReceipt(
  input,
  recoveryBootstrapInput,
  cleanupCapabilityInput,
  effectRegistry,
  label = "signed_restoration_receipt",
) {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "restoration_receipt_ref",
      "recovery_bootstrap_digest",
      "cleanup_capability_digest",
      "source_execution_request_digest",
      "instrument_ref",
      "lease_id",
      "fencing_token",
      "workspace_snapshot_ref",
      "workspace_snapshot_digest",
      "restore_operation_id",
      "restore_operation_digest",
      "pre_restore_state_digest",
      "expected_terminal_state_digest",
      "observed_terminal_state_digest",
      "terminal_state",
      "provider_receipt_ref",
      "provider_receipt_digest",
      "residual_state_ref",
      "residual_state_digest",
      "completed_at",
      "authentication",
    ],
    ["restoration_receipt_digest"],
  );
  if (input.version !== RESTORATION_RECEIPT_VERSION) {
    throw new Error(`${label}.version must be ${RESTORATION_RECEIPT_VERSION}`);
  }
  const capability = normalizeCleanupCapability(
    cleanupCapabilityInput,
    effectRegistry,
    `${label}.cleanup_capability`,
  );
  const bootstrap = normalizeRecoveryWorkerBootstrap(
    recoveryBootstrapInput,
    capability,
    effectRegistry,
    `${label}.recovery_bootstrap`,
  );
  const terminalState = assertEnum(
    input.terminal_state,
    ["restored", "quarantined", "unknown_effect"],
    `${label}.terminal_state`,
  );
  if (!arrayIncludes(capability.allowed_terminal_states, terminalState)) {
    throw new Error(`${label}.terminal_state was not authorized by the cleanup capability`);
  }
  const expectedTerminalStateDigest = assertDigest(
    input.expected_terminal_state_digest,
    `${label}.expected_terminal_state_digest`,
  );
  if (expectedTerminalStateDigest !== bootstrap.expected_terminal_state_digest) {
    throw new Error(`${label}.expected_terminal_state_digest was not precommitted by the bootstrap`);
  }
  const observedTerminalStateDigest = assertDigest(
    input.observed_terminal_state_digest,
    `${label}.observed_terminal_state_digest`,
  );
  if (terminalState === "restored" && observedTerminalStateDigest !== expectedTerminalStateDigest) {
    throw new Error(`${label}.restored requires exact expected terminal state`);
  }
  const residualStateRef = input.residual_state_ref == null
    ? null
    : normalizeOpaqueRef(input.residual_state_ref, `${label}.residual_state_ref`, {
      prefix: "residual-state",
    });
  const residualStateDigest = input.residual_state_digest == null
    ? null
    : assertDigest(input.residual_state_digest, `${label}.residual_state_digest`);
  if ((residualStateRef == null) !== (residualStateDigest == null)) {
    throw new Error(`${label}.residual_state_ref and residual_state_digest must appear together`);
  }
  if (terminalState === "restored" && residualStateRef != null) {
    throw new Error(`${label}.restored cannot conceal residual state`);
  }
  if (terminalState !== "restored" && residualStateRef == null) {
    throw new Error(`${label}.${terminalState} requires an explicit residual-state record`);
  }
  const payload = {
    version: RESTORATION_RECEIPT_VERSION,
    restoration_receipt_ref: normalizeOpaqueRef(
      input.restoration_receipt_ref,
      `${label}.restoration_receipt_ref`,
      { prefix: "receipt" },
    ),
    recovery_bootstrap_digest: assertDigest(
      input.recovery_bootstrap_digest,
      `${label}.recovery_bootstrap_digest`,
    ),
    cleanup_capability_digest: assertDigest(
      input.cleanup_capability_digest,
      `${label}.cleanup_capability_digest`,
    ),
    source_execution_request_digest: assertDigest(
      input.source_execution_request_digest,
      `${label}.source_execution_request_digest`,
    ),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    workspace_snapshot_ref: normalizeOpaqueRef(
      input.workspace_snapshot_ref,
      `${label}.workspace_snapshot_ref`,
      { prefix: "workspace-snapshot" },
    ),
    workspace_snapshot_digest: assertDigest(
      input.workspace_snapshot_digest,
      `${label}.workspace_snapshot_digest`,
    ),
    restore_operation_id: assertToken(input.restore_operation_id, `${label}.restore_operation_id`),
    restore_operation_digest: assertDigest(
      input.restore_operation_digest,
      `${label}.restore_operation_digest`,
    ),
    pre_restore_state_digest: assertDigest(
      input.pre_restore_state_digest,
      `${label}.pre_restore_state_digest`,
    ),
    expected_terminal_state_digest: expectedTerminalStateDigest,
    observed_terminal_state_digest: observedTerminalStateDigest,
    terminal_state: terminalState,
    provider_receipt_ref: normalizeOpaqueRef(
      input.provider_receipt_ref,
      `${label}.provider_receipt_ref`,
      { prefix: "receipt" },
    ),
    provider_receipt_digest: assertDigest(
      input.provider_receipt_digest,
      `${label}.provider_receipt_digest`,
    ),
    residual_state_ref: residualStateRef,
    residual_state_digest: residualStateDigest,
    completed_at: assertCanonicalTimestamp(input.completed_at, `${label}.completed_at`),
  };
  const exactBindings = [
    "recovery_bootstrap_digest",
    "cleanup_capability_digest",
    "source_execution_request_digest",
    "instrument_ref",
    "lease_id",
    "fencing_token",
    "workspace_snapshot_ref",
    "workspace_snapshot_digest",
    "restore_operation_id",
    "restore_operation_digest",
  ];
  const expected = { ...bootstrap, cleanup_capability_digest: capability.capability_digest };
  assertExactBindings(payload, expected, exactBindings, label);
  assertTimeOrder(bootstrap.not_before, payload.completed_at, `${label} bootstrap -> completion`);
  if (parseTimestamp(payload.completed_at) > parseTimestamp(bootstrap.expires_at)) {
    throw new Error(`${label}.completed_at exceeds recovery bootstrap expiry`);
  }
  const restorationReceiptDigest = hashCanonicalJson(payload);
  assertDerivedDigest(input, "restoration_receipt_digest", restorationReceiptDigest, label);
  const authentication = normalizeSignatureEnvelope(
    input.authentication,
    restorationReceiptDigest,
    `${label}.authentication`,
  );
  if (authentication.signer_key_id !== bootstrap.recovery_receipt_signer_key_id
      || authentication.trust_root_epoch !== bootstrap.trust_root_epoch) {
    throw new Error(`${label}.authentication is not bound to the cleanup worker receipt key`);
  }
  return deepFreeze({
    ...payload,
    restoration_receipt_digest: restorationReceiptDigest,
    authentication,
  });
}

function projectVerifiedRestorationReceipt(
  input,
  recoveryBootstrap,
  cleanupCapability,
  effectRegistry,
  supervisor,
  trustedReceiptInput,
  trustedBootstrapInput,
) {
  const verifiedBootstrap = projectVerifiedRecoveryWorkerBootstrap(
    recoveryBootstrap,
    cleanupCapability,
    effectRegistry,
    supervisor,
    trustedBootstrapInput,
  );
  const receipt = normalizeSignedRestorationReceipt(
    input,
    recoveryBootstrap,
    cleanupCapability,
    effectRegistry,
  );
  const trusted = assertSignatureVerification(
    receipt.authentication,
    trustedReceiptInput,
    "trusted_restoration_receipt_verification",
  );
  const projection = {
    version: RESTORATION_RECEIPT_VERSION,
    restoration_receipt_digest: receipt.restoration_receipt_digest,
    recovery_bootstrap_digest: receipt.recovery_bootstrap_digest,
    verified_bootstrap_digest: verifiedBootstrap.verified_bootstrap_digest,
    cleanup_capability_digest: receipt.cleanup_capability_digest,
    instrument_ref: receipt.instrument_ref,
    lease_id: receipt.lease_id,
    fencing_token: receipt.fencing_token,
    terminal_state: receipt.terminal_state,
    expected_terminal_state_digest: receipt.expected_terminal_state_digest,
    observed_terminal_state_digest: receipt.observed_terminal_state_digest,
    residual_state_digest: receipt.residual_state_digest,
    completed_at: receipt.completed_at,
    verified_signer_key_id: trusted.signer_key_id,
    verified_trust_root_epoch: trusted.trust_root_epoch,
    signature_verifier_id: trusted.signature_verifier_id,
    signature_verdict_digest: trusted.signature_verdict_digest,
  };
  return deepFreeze({ ...projection, verified_restoration_digest: hashCanonicalJson(projection) });
}

function reconcileStartupAttempt(input, operationRegistry, label = "startup_reconciliation") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "reconciliation_ref",
      "observed_at",
      "journal_head",
      "lease",
      "provider_report",
      "outbox_head",
      "safety_root_status",
      "verified_recovery_bootstrap",
    ],
  );
  if (input.version !== STARTUP_RECONCILIATION_VERSION) {
    throw new Error(`${label}.version must be ${STARTUP_RECONCILIATION_VERSION}`);
  }
  const observedAt = assertCanonicalTimestamp(input.observed_at, `${label}.observed_at`);
  const journal = normalizeAttemptJournalEntry(input.journal_head, `${label}.journal_head`);
  const lease = normalizeInstrumentLease(input.lease, `${label}.lease`);
  assertExactBindings(
    journal,
    lease,
    [
      "attempt_ref",
      "instrument_ref",
      "lease_id",
      "fencing_token",
      "fencing_generation",
      "operation_id",
      "execution_request_digest",
    ],
    label,
  );
  const providerReport = input.provider_report == null
    ? null
    : assertProviderAlignedJournalState(journal, input.provider_report, operationRegistry);
  const outbox = input.outbox_head == null
    ? null
    : assertOutboxJournalBinding(input.outbox_head, journal);
  const safetyRootStatus = assertEnum(
    input.safety_root_status,
    SAFETY_ROOT_STATUS_VALUES,
    `${label}.safety_root_status`,
  );
  const recoveryBootstrap = input.verified_recovery_bootstrap == null
    ? null
    : normalizeVerifiedRecoveryBootstrapProjection(
      input.verified_recovery_bootstrap,
      `${label}.verified_recovery_bootstrap`,
    );
  const recoveryBootstrapDigest = recoveryBootstrap == null
    ? null
    : recoveryBootstrap.recovery_bootstrap_digest;
  const recoveryBootstrapBindings = recoveryBootstrap == null ? [] : [
    [recoveryBootstrap.cleanup_capability_digest, journal.cleanup_capability_digest],
    [recoveryBootstrap.source_execution_request_digest, journal.execution_request_digest],
    [recoveryBootstrap.attempt_ref, journal.attempt_ref],
    [recoveryBootstrap.instrument_ref, journal.instrument_ref],
    [recoveryBootstrap.lease_id, journal.lease_id],
    [recoveryBootstrap.fencing_token, journal.fencing_token],
    [recoveryBootstrap.fencing_generation, journal.fencing_generation],
  ];
  const recoveryBootstrapUsable = recoveryBootstrap != null
    && arrayEvery(recoveryBootstrapBindings, ([actual, expected]) => actual === expected)
    && parseTimestamp(observedAt) <= parseTimestamp(recoveryBootstrap.expires_at);
  const staleLease = parseTimestamp(observedAt) > parseTimestamp(lease.expires_at);
  const effectMayHaveOccurred = !arrayIncludes(["precommitted", "admitted"], journal.state);
  const providerState = providerReport == null ? null : providerReport.state;

  let action;
  let terminalState = null;
  let requiresFence = staleLease;
  let requiresCleanup = false;
  const reasons = [];

  const journalTerminal = arrayIncludes(JOURNAL_TERMINAL_STATES, journal.state);
  const terminalLeaseMismatch = lease.state === "released"
    ? !(
      (journal.state === "restored" && lease.terminal_disposition === "restored")
      || (journal.state === "reconciled_no_effect"
        && lease.terminal_disposition === "confirmed_no_effect")
      || (journal.state === "irreversible_authorized"
        && lease.terminal_disposition === "irreversible_authorized")
    )
    : lease.state === "quarantined"
      ? !(
        (journal.state === "quarantined" && lease.terminal_disposition === "quarantined")
        || (journal.state === "unknown_effect" && lease.terminal_disposition === "unknown_effect")
      )
      : false;

  if (terminalLeaseMismatch) {
    action = "quarantine";
    terminalState = "quarantined";
    requiresFence = true;
    arrayPush(reasons, "lease_journal_terminal_mismatch");
  } else if (journalTerminal) {
    if (journal.state === "restored") {
      action = "finalize_restored";
      terminalState = "restored";
    } else if (journal.state === "irreversible_authorized") {
      action = "finalize_irreversible_authorized";
      terminalState = "irreversible_authorized";
    } else if (journal.state === "reconciled_no_effect") {
      action = "close_confirmed_no_effect";
      terminalState = "reconciled_no_effect";
    } else {
      action = journal.state === "quarantined" ? "finalize_quarantined" : "quarantine";
      terminalState = journal.state;
    }
    arrayPush(reasons, "journal_terminal");
  } else if (lease.state === "released" || lease.state === "quarantined") {
    action = "quarantine";
    terminalState = "quarantined";
    requiresFence = true;
    arrayPush(reasons, "lease_journal_terminal_mismatch");
  } else if (!effectMayHaveOccurred
      && (providerState == null || arrayIncludes(
        ["created", "prepared", "refused", "reconciled_no_effect"],
        providerState,
      ))) {
    action = "close_confirmed_no_effect";
    terminalState = "reconciled_no_effect";
    arrayPush(reasons, "durably_pre_effect");
  } else if (providerState === "restored") {
    action = "record_restoration_receipt";
    requiresFence = true;
    arrayPush(reasons,
      outbox != null && outbox.payload_kind === "restoration_receipt"
        ? "durable_restoration_receipt_pending_journal"
        : "provider_restored_receipt_not_durable",
    );
  } else if (providerState === "irreversible_authorized") {
    action = "record_irreversible_terminal";
    requiresFence = true;
    arrayPush(reasons, "provider_irreversible_terminal_pending_journal");
  } else if (providerState === "quarantined") {
    action = "record_quarantine_terminal";
    requiresFence = true;
    arrayPush(reasons, "provider_quarantine_pending_journal");
  } else if (providerState === "unknown_effect") {
    action = "quarantine";
    terminalState = "unknown_effect";
    requiresFence = true;
    arrayPush(reasons, "provider_unknown_effect");
  } else if (providerState === "reconciled_no_effect" || providerState === "refused") {
    action = "close_confirmed_no_effect";
    terminalState = "reconciled_no_effect";
    requiresFence = true;
    arrayPush(reasons, "provider_confirmed_no_effect");
  } else if (arrayIncludes(["acknowledged", "stopped"], providerState)
      || arrayIncludes(["effect_recorded", "stop_acked", "restoring"], journal.state)) {
    action = "resume_restore";
    requiresFence = true;
    requiresCleanup = true;
    arrayPush(reasons, "effect_confirmed_cleanup_incomplete");
  } else {
    action = "stop_reconcile_restore";
    requiresFence = true;
    requiresCleanup = true;
    arrayPush(
      reasons,
      providerState == null ? "provider_status_missing" : `provider_${providerState}`,
    );
  }

  if (requiresCleanup && (safetyRootStatus !== "trusted" || !recoveryBootstrapUsable)) {
    action = "quarantine";
    terminalState = "quarantined";
    requiresFence = true;
    requiresCleanup = false;
    arrayPush(reasons,
      safetyRootStatus !== "trusted"
        ? `safety_root_${safetyRootStatus}`
        : recoveryBootstrap == null
          ? "recovery_bootstrap_missing"
          : parseTimestamp(observedAt) > parseTimestamp(recoveryBootstrap.expires_at)
            ? "recovery_bootstrap_expired"
            : "recovery_bootstrap_binding_drift",
    );
  }
  if (staleLease) arrayPush(reasons, "lease_expired");

  assertEnum(action, RECONCILIATION_ACTIONS, `${label}.action`);
  const normalized = {
    version: STARTUP_RECONCILIATION_VERSION,
    reconciliation_ref: normalizeOpaqueRef(
      input.reconciliation_ref,
      `${label}.reconciliation_ref`,
      { prefix: "startup-reconciliation" },
    ),
    observed_at: observedAt,
    journal_entry_digest: journal.journal_entry_digest,
    lease_digest: lease.lease_digest,
    provider_report_digest: providerReport == null ? null : hashCanonicalJson(providerReport),
    outbox_entry_digest: outbox == null ? null : outbox.outbox_entry_digest,
    recovery_bootstrap_digest: recoveryBootstrapDigest,
    verified_bootstrap_digest: recoveryBootstrap == null
      ? null
      : recoveryBootstrap.verified_bootstrap_digest,
    safety_root_status: safetyRootStatus,
    action,
    terminal_state: terminalState,
    requires_fence: requiresFence,
    requires_cleanup: requiresCleanup,
    requires_lease_closure: !arrayIncludes(["released", "quarantined"], lease.state),
    automatic_retry_allowed: false,
    reasons: objectFreeze(uniqueSortedArray(reasons)),
  };
  return deepFreeze({ ...normalized, reconciliation_digest: hashCanonicalJson(normalized) });
}

module.exports = {
  ATTEMPT_JOURNAL_VERSION,
  CONTAINMENT_ACTIONS,
  CONTAINMENT_MODES,
  DURABLE_OUTBOX_VERSION,
  EFFECT_DISPATCH_VERSION,
  PROVIDER_DISPATCH_CREDENTIAL_DOMAIN,
  PROVIDER_DISPATCH_CREDENTIAL_VERSION,
  PROVIDER_DISPATCH_FENCE_DOMAIN,
  PROVIDER_DISPATCH_REDEMPTION_VERSION,
  EMISSION_STATE_VALUES,
  INSTRUMENT_LEASE_VERSION,
  JOURNAL_STATE_VALUES,
  JOURNAL_TERMINAL_STATES,
  JOURNAL_TRANSITIONS,
  LEASE_BLOCKING_STATES,
  LEASE_FENCE_REASONS,
  LEASE_STATE_VALUES,
  LEASE_TERMINAL_DISPOSITIONS,
  MAX_SUPERVISOR_DEADMAN_WINDOW_MS,
  OUTBOX_PAYLOAD_KINDS,
  RECONCILIATION_ACTIONS,
  RECOVERY_BOOTSTRAP_VERSION,
  RESTORATION_RECEIPT_VERSION,
  SAFETY_ROOT_STATUS_VALUES,
  SAFETY_SUPERVISOR_VERSION,
  SIGNATURE_METHODS,
  SIGNED_ENVELOPE_VERSION,
  STARTUP_RECONCILIATION_VERSION,
  STOP_ACK_OUTCOMES,
  STOP_ACKNOWLEDGER_KINDS,
  STOP_PROTOCOL_VERSION,
  STOP_REASONS,
  SUPERVISOR_DECISIONS,
  acquireInstrumentLease,
  assertAttemptJournalAppend,
  assertDeadmanHeartbeatTransition,
  assertDurableOutboxAppend,
  assertOutboxJournalBinding,
  assertProviderAlignedJournalState,
  assertStopRequestLeaseBinding,
  assertVerifiedRecoveryBootstrapProjection,
  beginInstrumentRestoration,
  evaluateSafetySupervisor,
  fenceInstrumentLease,
  isLeaseBlocking,
  normalizeAttemptJournalEntry,
  normalizeDurableOutboxEntry,
  normalizeEffectDispatchRecord,
  normalizeProviderDispatchCredential,
  normalizeProviderDispatchRedemption,
  normalizeInstrumentLease,
  normalizeOutboxAcknowledgement,
  normalizeRecoveryWorkerBootstrap,
  normalizeSafetySupervisorContract,
  normalizeSignedDeadmanHeartbeat,
  normalizeSignedRestorationReceipt,
  normalizeSignedStopAcknowledgement,
  normalizeSignedStopRequest,
  normalizeTrustedSignatureVerification,
  normalizeVerifiedRecoveryBootstrapProjection,
  projectVerifiedStopAcknowledgement,
  projectVerifiedRecoveryWorkerBootstrap,
  projectVerifiedRestorationReceipt,
  projectVerifiedStopRequest,
  providerDispatchFenceBindingDigest,
  reconcileStartupAttempt,
  releaseInstrumentLease,
  requestInstrumentLeaseStop,
  renewInstrumentLease,
};
