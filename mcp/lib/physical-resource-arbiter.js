"use strict";

// Plane-PH PH-S11 provider-neutral fairness arbiter. This module orders
// hash-bound reservation requests; it deliberately has no inventory, lock,
// fence, lease, device, or effect surface. The broker coordinator must commit
// each returned state + queue pair atomically in a durable CAS journal before
// acting on a selection.

const {
  hashCanonicalJson,
} = require("./verification-contracts.js");

const PHYSICAL_RESOURCE_QUEUE_TICKET_VERSION = 1;
const PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION = 1;
const PHYSICAL_RESOURCE_ARBITER_CONFIG_VERSION = 1;
const PHYSICAL_RESOURCE_ARBITER_STATE_VERSION = 1;
const PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION = 1;
const PHYSICAL_RESOURCE_ARBITER_DECISION_VERSION = 1;
const PHYSICAL_RESOURCE_ARBITER_TRANSITION_VERSION = 1;
const PHYSICAL_RESOURCE_ARBITER_INITIALIZATION_VERSION = 1;

const ACTIVE_TICKET_STATE_VALUES = Object.freeze([
  "blocked",
  "ready",
]);
const TERMINAL_TICKET_STATE_VALUES = Object.freeze([
  "cancelled",
  "selected",
  "unschedulable",
]);
const TICKET_STATE_VALUES = Object.freeze([
  ...ACTIVE_TICKET_STATE_VALUES,
  ...TERMINAL_TICKET_STATE_VALUES,
]);
const ARBITER_COMMAND_KIND_VALUES = Object.freeze([
  "cancel",
  "enqueue",
  "mark_blocked",
  "mark_ready",
  "mark_unschedulable",
]);
const ARBITER_DECISION_DISPOSITION_VALUES = Object.freeze([
  "idle",
  "selected",
]);

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const MAX_FAIRNESS_CLASSES = 64;
const MAX_QUEUE_TICKETS = 65_536;
const MAX_COMMANDS_PER_TRANSITION = 4_096;
const MAX_BATCH_SIZE = 256;
const MAX_BATCH_BURST = 4_096;
const MAX_SETUP_COST_UNITS = 1_000_000;
const MAX_DEFERRAL_COUNT = 1_000_000_000;
const MAX_ARBITER_GENERATION = Number.MAX_SAFE_INTEGER - 1;

// Protocol ordering must not depend on the host locale or ICU version. All
// strings admitted by this module are restricted ASCII, so ECMAScript's
// code-unit relational ordering is a stable byte-for-byte canonical order.
function comparePhysicalResourceArbiterProtocolStrings(left, right) {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

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
  const unknown = keys
    .filter((key) => !allowed.has(key))
    .sort(comparePhysicalResourceArbiterProtocolStrings);
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

function readEnumerableDataField(value, key, label) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
    throw new Error(`${label}.${key} must be an enumerable data field`);
  }
  return descriptor.value;
}

function assertDataArray(value, label, minimum, maximum) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw new Error(`${label} must contain ${minimum}-${maximum} entries`);
  }
  const allowedKeys = new Set(["length"]);
  for (let index = 0; index < value.length; index += 1) allowedKeys.add(String(index));
  const unknown = Reflect.ownKeys(value).filter((key) => !allowedKeys.has(key));
  if (unknown.length > 0) throw new Error(`${label} cannot contain extra or symbol fields`);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}[${index}] must be an enumerable data field`);
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

function assertInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function assertNullableDigest(value, label) {
  if (value === null) return null;
  return assertDigest(value, label);
}

function assertNullableIdentifier(value, label) {
  if (value === null) return null;
  return assertIdentifier(value, label);
}

function finalizeDigest(value, suppliedDigest, digestField, label) {
  const digest = hashCanonicalJson(value);
  if (suppliedDigest != null) {
    assertDigest(suppliedDigest, `${label}.${digestField}`);
    if (suppliedDigest !== digest) throw new Error(`${label}.${digestField} does not match canonical content`);
  }
  return deepFreeze({
    ...value,
    [digestField]: digest,
  });
}

function normalizeFairnessClasses(value, label) {
  assertDataArray(value, label, 1, MAX_FAIRNESS_CLASSES);
  const classes = value.map((entry, index) => assertIdentifier(entry, `${label}[${index}]`));
  if (new Set(classes).size !== classes.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze(classes.slice().sort(comparePhysicalResourceArbiterProtocolStrings));
}

function normalizePhysicalResourceArbiterConfig(input, label = "physical_resource_arbiter_config") {
  assertClosedObject(input, label, [
    "version",
    "fairness_classes",
    "aging_threshold",
    "max_batch_size",
    "max_batch_burst",
    "max_queue_tickets",
  ], ["config_digest"]);
  if (input.version !== PHYSICAL_RESOURCE_ARBITER_CONFIG_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_RESOURCE_ARBITER_CONFIG_VERSION}`);
  }
  const maxBatchSize = assertInteger(
    input.max_batch_size,
    `${label}.max_batch_size`,
    1,
    MAX_BATCH_SIZE,
  );
  const maxBatchBurst = assertInteger(
    input.max_batch_burst,
    `${label}.max_batch_burst`,
    1,
    MAX_BATCH_BURST,
  );
  if (maxBatchSize > maxBatchBurst) {
    throw new Error(`${label}.max_batch_size cannot exceed max_batch_burst`);
  }
  const value = {
    version: PHYSICAL_RESOURCE_ARBITER_CONFIG_VERSION,
    fairness_classes: normalizeFairnessClasses(input.fairness_classes, `${label}.fairness_classes`),
    aging_threshold: assertInteger(
      input.aging_threshold,
      `${label}.aging_threshold`,
      1,
      MAX_DEFERRAL_COUNT,
    ),
    max_batch_size: maxBatchSize,
    max_batch_burst: maxBatchBurst,
    max_queue_tickets: assertInteger(
      input.max_queue_tickets,
      `${label}.max_queue_tickets`,
      1,
      MAX_QUEUE_TICKETS,
    ),
  };
  return finalizeDigest(value, input.config_digest, "config_digest", label);
}

function normalizePhysicalResourceQueueTicket(input, label = "physical_resource_queue_ticket") {
  const ticketState = assertEnum(
    readEnumerableDataField(input, "ticket_state", label),
    TICKET_STATE_VALUES,
    `${label}.ticket_state`,
  );
  const terminal = TERMINAL_TICKET_STATE_VALUES.includes(ticketState);
  const required = [
    "version",
    "reservation_request_digest",
    "resource_bundle_digest",
    "fairness_class",
    "batch_key",
    "setup_cost_units",
    "enqueue_generation",
    "deferral_count",
    "ticket_state",
  ];
  if (terminal) required.push("terminal_generation");
  assertClosedObject(input, label, required, ["ticket_digest"]);
  if (input.version !== PHYSICAL_RESOURCE_QUEUE_TICKET_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_RESOURCE_QUEUE_TICKET_VERSION}`);
  }
  const enqueueGeneration = assertInteger(
    input.enqueue_generation,
    `${label}.enqueue_generation`,
    0,
    MAX_ARBITER_GENERATION,
  );
  const value = {
    version: PHYSICAL_RESOURCE_QUEUE_TICKET_VERSION,
    reservation_request_digest: assertDigest(
      input.reservation_request_digest,
      `${label}.reservation_request_digest`,
    ),
    resource_bundle_digest: assertDigest(input.resource_bundle_digest, `${label}.resource_bundle_digest`),
    fairness_class: assertIdentifier(input.fairness_class, `${label}.fairness_class`),
    // A batch key is an opaque digest, not a provider name, resource identity,
    // priority string, or authority-bearing setup instruction.
    batch_key: assertDigest(input.batch_key, `${label}.batch_key`),
    setup_cost_units: assertInteger(
      input.setup_cost_units,
      `${label}.setup_cost_units`,
      0,
      MAX_SETUP_COST_UNITS,
    ),
    enqueue_generation: enqueueGeneration,
    deferral_count: assertInteger(
      input.deferral_count,
      `${label}.deferral_count`,
      0,
      MAX_DEFERRAL_COUNT,
    ),
    ticket_state: ticketState,
  };
  if (terminal) {
    value.terminal_generation = assertInteger(
      input.terminal_generation,
      `${label}.terminal_generation`,
      enqueueGeneration,
      MAX_ARBITER_GENERATION,
    );
  }
  return finalizeDigest(value, input.ticket_digest, "ticket_digest", label);
}

function normalizePhysicalResourceArbiterQueue(input, label = "physical_resource_arbiter_queue") {
  assertClosedObject(input, label, ["version", "tickets"], ["queue_digest"]);
  if (input.version !== PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION}`);
  }
  assertDataArray(input.tickets, `${label}.tickets`, 0, MAX_QUEUE_TICKETS);
  const tickets = input.tickets.map((ticket, index) => (
    normalizePhysicalResourceQueueTicket(ticket, `${label}.tickets[${index}]`)
  ));
  const requestDigests = tickets.map((ticket) => ticket.reservation_request_digest);
  if (new Set(requestDigests).size !== requestDigests.length) {
    throw new Error(`${label}.tickets must not contain duplicate reservation requests`);
  }
  const ticketDigests = tickets.map((ticket) => ticket.ticket_digest);
  if (new Set(ticketDigests).size !== ticketDigests.length) {
    throw new Error(`${label}.tickets must not contain duplicate tickets`);
  }
  const value = {
    version: PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION,
    tickets: Object.freeze(tickets.slice().sort((left, right) => (
      comparePhysicalResourceArbiterProtocolStrings(
        left.reservation_request_digest,
        right.reservation_request_digest,
      )
    ))),
  };
  return finalizeDigest(value, input.queue_digest, "queue_digest", label);
}

function normalizeActiveBatch(input, label) {
  if (input === null) return null;
  assertClosedObject(input, label, [
    "fairness_class",
    "batch_key",
    "selected_count",
  ]);
  return deepFreeze({
    fairness_class: assertIdentifier(input.fairness_class, `${label}.fairness_class`),
    batch_key: assertDigest(input.batch_key, `${label}.batch_key`),
    selected_count: assertInteger(input.selected_count, `${label}.selected_count`, 1, MAX_BATCH_BURST),
  });
}

function normalizeClassBatchCursors(input, label) {
  assertDataArray(input, label, 0, MAX_FAIRNESS_CLASSES);
  const cursors = input.map((entry, index) => {
    const field = `${label}[${index}]`;
    assertClosedObject(entry, field, ["fairness_class", "last_batch_key"]);
    return deepFreeze({
      fairness_class: assertIdentifier(entry.fairness_class, `${field}.fairness_class`),
      last_batch_key: assertNullableDigest(entry.last_batch_key, `${field}.last_batch_key`),
    });
  });
  const classes = cursors.map((cursor) => cursor.fairness_class);
  if (new Set(classes).size !== classes.length) throw new Error(`${label} has duplicate fairness classes`);
  return Object.freeze(cursors.slice().sort((left, right) => (
    comparePhysicalResourceArbiterProtocolStrings(left.fairness_class, right.fairness_class)
  )));
}

function normalizePhysicalResourceArbiterState(input, label = "physical_resource_arbiter_state") {
  assertClosedObject(input, label, [
    "version",
    "generation",
    "config_digest",
    "queue_digest",
    "last_served_fairness_class",
    "class_batch_cursors",
    "active_batch",
    "previous_state_digest",
    "applied_input_digest",
  ], ["state_digest"]);
  if (input.version !== PHYSICAL_RESOURCE_ARBITER_STATE_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_RESOURCE_ARBITER_STATE_VERSION}`);
  }
  const generation = assertInteger(
    input.generation,
    `${label}.generation`,
    0,
    MAX_ARBITER_GENERATION,
  );
  const lastServed = assertNullableIdentifier(
    input.last_served_fairness_class,
    `${label}.last_served_fairness_class`,
  );
  const activeBatch = normalizeActiveBatch(input.active_batch, `${label}.active_batch`);
  if (activeBatch != null && activeBatch.fairness_class !== lastServed) {
    throw new Error(`${label}.active_batch fairness class must equal last_served_fairness_class`);
  }
  const previousStateDigest = assertNullableDigest(
    input.previous_state_digest,
    `${label}.previous_state_digest`,
  );
  const appliedInputDigest = assertNullableDigest(
    input.applied_input_digest,
    `${label}.applied_input_digest`,
  );
  if (generation === 0 && (previousStateDigest !== null || appliedInputDigest !== null)) {
    throw new Error(`${label} generation zero cannot claim a prior state or applied input`);
  }
  if (generation > 0 && (previousStateDigest === null || appliedInputDigest === null)) {
    throw new Error(`${label} nonzero generation must bind its prior state and applied input`);
  }
  const value = {
    version: PHYSICAL_RESOURCE_ARBITER_STATE_VERSION,
    generation,
    config_digest: assertDigest(input.config_digest, `${label}.config_digest`),
    queue_digest: assertDigest(input.queue_digest, `${label}.queue_digest`),
    last_served_fairness_class: lastServed,
    class_batch_cursors: normalizeClassBatchCursors(
      input.class_batch_cursors,
      `${label}.class_batch_cursors`,
    ),
    active_batch: activeBatch,
    previous_state_digest: previousStateDigest,
    applied_input_digest: appliedInputDigest,
  };
  return finalizeDigest(value, input.state_digest, "state_digest", label);
}

function normalizePhysicalResourceArbiterCommand(input, label = "physical_resource_arbiter_command") {
  const kind = assertEnum(
    readEnumerableDataField(input, "command_kind", label),
    ARBITER_COMMAND_KIND_VALUES,
    `${label}.command_kind`,
  );
  if (kind === "enqueue") {
    assertClosedObject(input, label, ["version", "command_kind", "ticket"], ["command_digest"]);
  } else {
    assertClosedObject(input, label, [
      "version",
      "command_kind",
      "reservation_request_digest",
    ], ["command_digest"]);
  }
  if (input.version !== PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION}`);
  }
  const value = kind === "enqueue"
    ? {
      version: PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
      command_kind: kind,
      ticket: normalizePhysicalResourceQueueTicket(input.ticket, `${label}.ticket`),
    }
    : {
      version: PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
      command_kind: kind,
      reservation_request_digest: assertDigest(
        input.reservation_request_digest,
        `${label}.reservation_request_digest`,
      ),
    };
  return finalizeDigest(value, input.command_digest, "command_digest", label);
}

function commandRequestDigest(command) {
  return command.command_kind === "enqueue"
    ? command.ticket.reservation_request_digest
    : command.reservation_request_digest;
}

function normalizeCommands(input, label = "physical_resource_arbiter_commands") {
  assertDataArray(input, label, 0, MAX_COMMANDS_PER_TRANSITION);
  const commands = input.map((command, index) => (
    normalizePhysicalResourceArbiterCommand(command, `${label}[${index}]`)
  ));
  const requestDigests = commands.map(commandRequestDigest);
  if (new Set(requestDigests).size !== requestDigests.length) {
    throw new Error(`${label} must not mutate one reservation request more than once`);
  }
  return Object.freeze(commands.slice().sort((left, right) => (
    comparePhysicalResourceArbiterProtocolStrings(
      commandRequestDigest(left),
      commandRequestDigest(right),
    )
  )));
}

function ticketContent(ticket) {
  const value = { ...ticket };
  delete value.ticket_digest;
  return value;
}

function replaceTicket(ticket, changes) {
  const value = {
    ...ticketContent(ticket),
    ...changes,
  };
  if (!TERMINAL_TICKET_STATE_VALUES.includes(value.ticket_state)) delete value.terminal_generation;
  return normalizePhysicalResourceQueueTicket(value);
}

function validateBoundState(config, state, queue, label) {
  if (state.config_digest !== config.config_digest) {
    throw new Error(`${label}.state does not bind the exact arbiter config`);
  }
  if (state.queue_digest !== queue.queue_digest) {
    throw new Error(`${label}.state does not bind the exact input queue`);
  }
  const fairnessClasses = new Set(config.fairness_classes);
  if (state.last_served_fairness_class != null
      && !fairnessClasses.has(state.last_served_fairness_class)) {
    throw new Error(`${label}.state last-served fairness class is not registered by config`);
  }
  if (state.active_batch != null) {
    if (!fairnessClasses.has(state.active_batch.fairness_class)) {
      throw new Error(`${label}.state active fairness class is not registered by config`);
    }
    if (state.active_batch.selected_count >= config.max_batch_burst) {
      throw new Error(`${label}.state active batch must remain below config max_batch_burst`);
    }
  }
  const cursorClasses = state.class_batch_cursors.map((cursor) => cursor.fairness_class);
  if (cursorClasses.length !== config.fairness_classes.length
      || cursorClasses.some((fairnessClass, index) => fairnessClass !== config.fairness_classes[index])) {
    throw new Error(`${label}.state class batch cursors must exactly cover configured fairness classes`);
  }
  if (state.last_served_fairness_class == null
      && state.class_batch_cursors.some((cursor) => cursor.last_batch_key != null)) {
    throw new Error(`${label}.state cannot have batch progress before serving a fairness class`);
  }
  if (state.active_batch != null) {
    const activeCursor = state.class_batch_cursors.find((cursor) => (
      cursor.fairness_class === state.active_batch.fairness_class
    ));
    if (activeCursor.last_batch_key !== state.active_batch.batch_key) {
      throw new Error(`${label}.state active batch must match its durable class batch cursor`);
    }
    const hasReadyContinuation = queue.tickets.some((ticket) => (
      ticket.ticket_state === "ready"
      && ticket.fairness_class === state.active_batch.fairness_class
      && ticket.batch_key === state.active_batch.batch_key
    ));
    if (!hasReadyContinuation) {
      throw new Error(`${label}.state active batch must have a compatible ready continuation`);
    }
  }
  if (queue.tickets.length > config.max_queue_tickets) {
    throw new Error(`${label}.queue exceeds config max_queue_tickets`);
  }
  for (const ticket of queue.tickets) {
    if (!fairnessClasses.has(ticket.fairness_class)) {
      throw new Error(`${label}.queue ticket fairness class is not registered by config`);
    }
    if (ticket.enqueue_generation > state.generation) {
      throw new Error(`${label}.queue ticket enqueue generation is ahead of state`);
    }
    // Genesis tickets exist before generation one. Later arrivals enter at the
    // start of their enqueue generation and can therefore be deferred once in
    // that same transition.
    const ageGeneration = ticket.terminal_generation == null
      ? state.generation
      : ticket.terminal_generation;
    const maximumReachableDeferrals = ageGeneration - ticket.enqueue_generation
      + (ticket.enqueue_generation === 0 ? 0 : 1);
    if (ticket.deferral_count > maximumReachableDeferrals) {
      throw new Error(`${label}.queue ticket deferral count is not reachable from the state generation`);
    }
    if (ticket.terminal_generation != null && ticket.terminal_generation > state.generation) {
      throw new Error(`${label}.queue terminal generation is ahead of state`);
    }
  }
}

function initializePhysicalResourceArbiter(input, label = "physical_resource_arbiter_initialization") {
  assertClosedObject(input, label, ["config", "queue"]);
  const config = normalizePhysicalResourceArbiterConfig(input.config, `${label}.config`);
  const queue = normalizePhysicalResourceArbiterQueue(input.queue, `${label}.queue`);
  if (queue.tickets.length > config.max_queue_tickets) {
    throw new Error(`${label}.queue exceeds config max_queue_tickets`);
  }
  const fairnessClasses = new Set(config.fairness_classes);
  for (const ticket of queue.tickets) {
    if (!fairnessClasses.has(ticket.fairness_class)) {
      throw new Error(`${label}.queue ticket fairness class is not registered by config`);
    }
    if (!ACTIVE_TICKET_STATE_VALUES.includes(ticket.ticket_state)) {
      throw new Error(`${label}.queue can only initialize active tickets`);
    }
    if (ticket.enqueue_generation !== 0 || ticket.deferral_count !== 0) {
      throw new Error(`${label}.queue initial tickets must start at generation and deferral zero`);
    }
  }
  const state = normalizePhysicalResourceArbiterState({
    version: PHYSICAL_RESOURCE_ARBITER_STATE_VERSION,
    generation: 0,
    config_digest: config.config_digest,
    queue_digest: queue.queue_digest,
    last_served_fairness_class: null,
    class_batch_cursors: config.fairness_classes.map((fairnessClass) => ({
      fairness_class: fairnessClass,
      last_batch_key: null,
    })),
    active_batch: null,
    previous_state_digest: null,
    applied_input_digest: null,
  }, `${label}.state`);
  const value = {
    version: PHYSICAL_RESOURCE_ARBITER_INITIALIZATION_VERSION,
    config,
    queue,
    state,
  };
  return deepFreeze({
    ...value,
    initialization_digest: hashCanonicalJson(value),
  });
}

function rankReadyTickets(left, right) {
  return (
    right.deferral_count - left.deferral_count
    || left.enqueue_generation - right.enqueue_generation
    // Setup cost is only a tie-breaker after broker-owned age coordinates.
    || left.setup_cost_units - right.setup_cost_units
    || comparePhysicalResourceArbiterProtocolStrings(
      left.reservation_request_digest,
      right.reservation_request_digest,
    )
  );
}

function nextRoundRobinClass(config, readyTickets, lastServed) {
  const readyClasses = new Set(readyTickets.map((ticket) => ticket.fairness_class));
  if (readyClasses.size === 0) return null;
  const startIndex = lastServed == null ? -1 : config.fairness_classes.indexOf(lastServed);
  for (let offset = 1; offset <= config.fairness_classes.length; offset += 1) {
    const index = (startIndex + offset) % config.fairness_classes.length;
    const candidate = config.fairness_classes[index];
    if (readyClasses.has(candidate)) return candidate;
  }
  throw new Error("physical resource arbiter could not resolve a registered ready fairness class");
}

function nextKeyAfterCursor(keys, cursor) {
  if (keys.length === 0) return null;
  if (cursor == null) return keys[0];
  const next = keys.find((key) => (
    comparePhysicalResourceArbiterProtocolStrings(key, cursor) > 0
  ));
  return next == null ? keys[0] : next;
}

function chooseBatchKeyForClass(config, state, fairnessClass, classTickets) {
  const byBatch = new Map();
  for (const ticket of classTickets) {
    if (!byBatch.has(ticket.batch_key)) byBatch.set(ticket.batch_key, []);
    byBatch.get(ticket.batch_key).push(ticket);
  }
  const cursor = state.class_batch_cursors.find((entry) => (
    entry.fairness_class === fairnessClass
  )).last_batch_key;
  const aged = classTickets.filter((ticket) => ticket.deferral_count >= config.aging_threshold);
  if (aged.length > 0) {
    const maximumDeferral = Math.max(...aged.map((ticket) => ticket.deferral_count));
    const maximallyDeferred = aged.filter((ticket) => ticket.deferral_count === maximumDeferral);
    const oldestGeneration = Math.min(...maximallyDeferred.map((ticket) => ticket.enqueue_generation));
    const oldestKeys = [...new Set(maximallyDeferred
      .filter((ticket) => ticket.enqueue_generation === oldestGeneration)
      .map((ticket) => ticket.batch_key))]
      .sort(comparePhysicalResourceArbiterProtocolStrings);
    return nextKeyAfterCursor(oldestKeys, cursor);
  }
  const keys = [...byBatch.keys()].sort(comparePhysicalResourceArbiterProtocolStrings);
  if (cursor != null) return nextKeyAfterCursor(keys, cursor);
  // Setup cost may choose the first compatible batch only before this class has
  // a durable batch cursor. It can never outrank broker-owned age coordinates.
  return keys.slice().sort((left, right) => {
    const leftCost = Math.min(...byBatch.get(left).map((ticket) => ticket.setup_cost_units));
    const rightCost = Math.min(...byBatch.get(right).map((ticket) => ticket.setup_cost_units));
    return leftCost - rightCost
      || comparePhysicalResourceArbiterProtocolStrings(left, right);
  })[0];
}

function terminalStateForCommand(kind) {
  if (kind === "cancel") return "cancelled";
  if (kind === "mark_unschedulable") return "unschedulable";
  return null;
}

function applyCommands(ticketMap, commands, config, nextGeneration, label) {
  const fairnessClasses = new Set(config.fairness_classes);
  for (const command of commands) {
    const requestDigest = commandRequestDigest(command);
    const current = ticketMap.get(requestDigest);
    if (command.command_kind === "enqueue") {
      if (current != null) {
        throw new Error(`${label} cannot enqueue a duplicate or terminal reservation request`);
      }
      const ticket = command.ticket;
      if (!fairnessClasses.has(ticket.fairness_class)) {
        throw new Error(`${label} enqueue fairness class is not registered by config`);
      }
      if (!ACTIVE_TICKET_STATE_VALUES.includes(ticket.ticket_state)) {
        throw new Error(`${label} enqueue ticket must be ready or blocked`);
      }
      if (ticket.enqueue_generation !== nextGeneration || ticket.deferral_count !== 0) {
        throw new Error(`${label} enqueue ticket must use the next generation and zero deferrals`);
      }
      ticketMap.set(requestDigest, ticket);
      continue;
    }
    if (current == null) throw new Error(`${label} command references an unknown reservation request`);
    if (!ACTIVE_TICKET_STATE_VALUES.includes(current.ticket_state)) {
      throw new Error(`${label} cannot mutate a terminal reservation request`);
    }
    if (command.command_kind === "mark_ready") {
      if (current.ticket_state !== "blocked") {
        throw new Error(`${label} mark_ready requires a blocked ticket`);
      }
      ticketMap.set(requestDigest, replaceTicket(current, { ticket_state: "ready" }));
      continue;
    }
    if (command.command_kind === "mark_blocked") {
      if (current.ticket_state !== "ready") {
        throw new Error(`${label} mark_blocked requires a ready ticket`);
      }
      ticketMap.set(requestDigest, replaceTicket(current, { ticket_state: "blocked" }));
      continue;
    }
    const terminalState = terminalStateForCommand(command.command_kind);
    ticketMap.set(requestDigest, replaceTicket(current, {
      ticket_state: terminalState,
      terminal_generation: nextGeneration,
    }));
  }
  if (ticketMap.size > config.max_queue_tickets) {
    throw new Error(`${label} commands exceed config max_queue_tickets`);
  }
}

function selectReadyBatch(config, state, readyTickets) {
  if (readyTickets.length === 0) {
    return {
      fairness_class: null,
      batch_key: null,
      continued_batch: false,
      selected: [],
    };
  }
  const active = state.active_batch;
  let continuedBatch = false;
  let fairnessClass = null;
  let batchKey = null;
  let priorBurstCount = 0;
  if (active != null && active.selected_count < config.max_batch_burst) {
    const matching = readyTickets.filter((ticket) => (
      ticket.fairness_class === active.fairness_class
      && ticket.batch_key === active.batch_key
    ));
    const agedDifferentBatch = readyTickets.some((ticket) => (
      ticket.fairness_class === active.fairness_class
      && ticket.batch_key !== active.batch_key
      && ticket.deferral_count >= config.aging_threshold
    ));
    if (matching.length > 0 && !agedDifferentBatch) {
      continuedBatch = true;
      fairnessClass = active.fairness_class;
      batchKey = active.batch_key;
      priorBurstCount = active.selected_count;
    }
  }
  if (!continuedBatch) {
    fairnessClass = nextRoundRobinClass(
      config,
      readyTickets,
      state.last_served_fairness_class,
    );
    batchKey = chooseBatchKeyForClass(
      config,
      state,
      fairnessClass,
      readyTickets.filter((ticket) => ticket.fairness_class === fairnessClass),
    );
  }
  const capacity = Math.min(
    config.max_batch_size,
    config.max_batch_burst - priorBurstCount,
  );
  const selected = readyTickets
    .filter((ticket) => (
      ticket.fairness_class === fairnessClass
      && ticket.batch_key === batchKey
    ))
    .sort(rankReadyTickets)
    .slice(0, capacity);
  if (selected.length === 0) {
    throw new Error("physical resource arbiter selected an empty ready batch");
  }
  return {
    fairness_class: fairnessClass,
    batch_key: batchKey,
    continued_batch: continuedBatch,
    selected,
  };
}

function transitionPhysicalResourceArbiter(input, label = "physical_resource_arbiter_transition_input") {
  assertClosedObject(input, label, ["config", "state", "queue", "commands"]);
  const config = normalizePhysicalResourceArbiterConfig(input.config, `${label}.config`);
  const state = normalizePhysicalResourceArbiterState(input.state, `${label}.state`);
  const queue = normalizePhysicalResourceArbiterQueue(input.queue, `${label}.queue`);
  const commands = normalizeCommands(input.commands, `${label}.commands`);
  validateBoundState(config, state, queue, label);
  if (state.generation >= MAX_ARBITER_GENERATION) {
    throw new Error(`${label}.state generation is exhausted`);
  }
  const commandsDigest = hashCanonicalJson(commands);
  const inputValue = {
    version: PHYSICAL_RESOURCE_ARBITER_TRANSITION_VERSION,
    config,
    state,
    queue,
    commands,
  };
  const inputDigest = hashCanonicalJson(inputValue);
  const nextGeneration = state.generation + 1;
  const ticketMap = new Map(queue.tickets.map((ticket) => [
    ticket.reservation_request_digest,
    ticket,
  ]));
  applyCommands(ticketMap, commands, config, nextGeneration, `${label}.commands`);

  const readyTickets = [...ticketMap.values()].filter((ticket) => ticket.ticket_state === "ready");
  const selection = selectReadyBatch(config, state, readyTickets);
  const selectedRequestDigests = new Set(
    selection.selected.map((ticket) => ticket.reservation_request_digest),
  );
  const selectedTicketDigests = selection.selected.map((ticket) => ticket.ticket_digest);
  const deferrals = [];
  for (const ticket of readyTickets) {
    const requestDigest = ticket.reservation_request_digest;
    if (selectedRequestDigests.has(requestDigest)) {
      ticketMap.set(requestDigest, replaceTicket(ticket, {
        ticket_state: "selected",
        terminal_generation: nextGeneration,
      }));
      continue;
    }
    const nextDeferralCount = Math.min(MAX_DEFERRAL_COUNT, ticket.deferral_count + 1);
    const nextTicket = replaceTicket(ticket, { deferral_count: nextDeferralCount });
    ticketMap.set(requestDigest, nextTicket);
    deferrals.push(deepFreeze({
      reservation_request_digest: requestDigest,
      prior_deferral_count: ticket.deferral_count,
      next_deferral_count: nextDeferralCount,
      prior_ticket_digest: ticket.ticket_digest,
      next_ticket_digest: nextTicket.ticket_digest,
    }));
  }

  const nextQueue = normalizePhysicalResourceArbiterQueue({
    version: PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION,
    tickets: [...ticketMap.values()],
  }, "physical_resource_arbiter_transition.next_queue");
  let nextActiveBatch = null;
  if (selection.selected.length > 0) {
    const priorCount = selection.continued_batch ? state.active_batch.selected_count : 0;
    const selectedCount = priorCount + selection.selected.length;
    const hasRemainingCompatible = nextQueue.tickets.some((ticket) => (
      ticket.ticket_state === "ready"
      && ticket.fairness_class === selection.fairness_class
      && ticket.batch_key === selection.batch_key
    ));
    if (hasRemainingCompatible && selectedCount < config.max_batch_burst) {
      nextActiveBatch = {
        fairness_class: selection.fairness_class,
        batch_key: selection.batch_key,
        selected_count: selectedCount,
      };
    }
  }

  const terminalizedTickets = nextQueue.tickets
    .filter((ticket) => ticket.terminal_generation === nextGeneration)
    .map((ticket) => deepFreeze({
      reservation_request_digest: ticket.reservation_request_digest,
      terminal_state: ticket.ticket_state,
      terminal_generation: ticket.terminal_generation,
      ticket_digest: ticket.ticket_digest,
    }));
  const decisionValue = {
    version: PHYSICAL_RESOURCE_ARBITER_DECISION_VERSION,
    generation: nextGeneration,
    disposition: selection.selected.length > 0 ? "selected" : "idle",
    fairness_class: selection.fairness_class,
    batch_key: selection.batch_key,
    continued_batch: selection.continued_batch,
    selected_reservation_request_digests: Object.freeze(
      selection.selected.map((ticket) => ticket.reservation_request_digest),
    ),
    selected_ticket_digests: Object.freeze(selectedTicketDigests),
    deferrals: Object.freeze(deferrals.sort((left, right) => (
      comparePhysicalResourceArbiterProtocolStrings(
        left.reservation_request_digest,
        right.reservation_request_digest,
      )
    ))),
    blocked_without_credit_ticket_digests: Object.freeze(nextQueue.tickets
      .filter((ticket) => ticket.ticket_state === "blocked")
      .map((ticket) => ticket.ticket_digest)
      .sort(comparePhysicalResourceArbiterProtocolStrings)),
    unschedulable_without_credit_ticket_digests: Object.freeze(nextQueue.tickets
      .filter((ticket) => ticket.ticket_state === "unschedulable")
      .map((ticket) => ticket.ticket_digest)
      .sort(comparePhysicalResourceArbiterProtocolStrings)),
    terminalized_tickets: Object.freeze(terminalizedTickets),
    active_batch_after: nextActiveBatch == null ? null : deepFreeze(nextActiveBatch),
  };
  const decision = deepFreeze({
    ...decisionValue,
    decision_digest: hashCanonicalJson(decisionValue),
  });
  const nextState = normalizePhysicalResourceArbiterState({
    version: PHYSICAL_RESOURCE_ARBITER_STATE_VERSION,
    generation: nextGeneration,
    config_digest: config.config_digest,
    queue_digest: nextQueue.queue_digest,
    last_served_fairness_class: selection.fairness_class == null
      ? state.last_served_fairness_class
      : selection.fairness_class,
    class_batch_cursors: state.class_batch_cursors.map((cursor) => ({
      fairness_class: cursor.fairness_class,
      last_batch_key: selection.fairness_class === cursor.fairness_class
        ? selection.batch_key
        : cursor.last_batch_key,
    })),
    active_batch: nextActiveBatch,
    previous_state_digest: state.state_digest,
    applied_input_digest: inputDigest,
  }, "physical_resource_arbiter_transition.next_state");
  const transitionValue = {
    version: PHYSICAL_RESOURCE_ARBITER_TRANSITION_VERSION,
    input_digest: inputDigest,
    input_state_digest: state.state_digest,
    input_queue_digest: queue.queue_digest,
    config_digest: config.config_digest,
    commands_digest: commandsDigest,
    decision,
    next_queue: nextQueue,
    next_state: nextState,
  };
  return deepFreeze({
    ...transitionValue,
    transition_digest: hashCanonicalJson(transitionValue),
  });
}

module.exports = {
  ACTIVE_TICKET_STATE_VALUES,
  ARBITER_COMMAND_KIND_VALUES,
  ARBITER_DECISION_DISPOSITION_VALUES,
  MAX_ARBITER_GENERATION,
  MAX_BATCH_BURST,
  MAX_BATCH_SIZE,
  MAX_COMMANDS_PER_TRANSITION,
  MAX_DEFERRAL_COUNT,
  MAX_FAIRNESS_CLASSES,
  MAX_QUEUE_TICKETS,
  MAX_SETUP_COST_UNITS,
  PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
  PHYSICAL_RESOURCE_ARBITER_CONFIG_VERSION,
  PHYSICAL_RESOURCE_ARBITER_DECISION_VERSION,
  PHYSICAL_RESOURCE_ARBITER_INITIALIZATION_VERSION,
  PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION,
  PHYSICAL_RESOURCE_ARBITER_STATE_VERSION,
  PHYSICAL_RESOURCE_ARBITER_TRANSITION_VERSION,
  PHYSICAL_RESOURCE_QUEUE_TICKET_VERSION,
  TERMINAL_TICKET_STATE_VALUES,
  TICKET_STATE_VALUES,
  assertPhysicalResourceArbiterBoundState: validateBoundState,
  comparePhysicalResourceArbiterProtocolStrings,
  initializePhysicalResourceArbiter,
  normalizePhysicalResourceArbiterCommand,
  normalizePhysicalResourceArbiterCommands: normalizeCommands,
  normalizePhysicalResourceArbiterConfig,
  normalizePhysicalResourceArbiterQueue,
  normalizePhysicalResourceArbiterState,
  normalizePhysicalResourceQueueTicket,
  transitionPhysicalResourceArbiter,
};
