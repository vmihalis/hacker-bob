"use strict";

// Plane-PH PH-S11 broker-private durable arbiter journal. This module commits
// the pure arbiter's complete next queue, state, and decision as one external
// linearizable CAS value before it returns a selection. It does not reserve a
// resource, inspect inventory, mint a fence/lease, open a device, or perform IO
// itself. Callback ports are integration seams and are never production proof.

const {
  ACTIVE_TICKET_STATE_VALUES,
  ARBITER_DECISION_DISPOSITION_VALUES,
  MAX_BATCH_BURST,
  MAX_DEFERRAL_COUNT,
  PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
  PHYSICAL_RESOURCE_ARBITER_DECISION_VERSION,
  PHYSICAL_RESOURCE_ARBITER_TRANSITION_VERSION,
  TERMINAL_TICKET_STATE_VALUES,
  assertPhysicalResourceArbiterBoundState,
  comparePhysicalResourceArbiterProtocolStrings,
  initializePhysicalResourceArbiter,
  normalizePhysicalResourceArbiterCommands,
  normalizePhysicalResourceArbiterConfig,
  normalizePhysicalResourceArbiterQueue,
  normalizePhysicalResourceArbiterState,
  normalizePhysicalResourceQueueTicket,
  transitionPhysicalResourceArbiter,
} = require("../../../mcp/domains/physical/physical-resource-arbiter.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const RESOURCE_ARBITER_STATE_PORT_VERSION = 1;
const RESOURCE_ARBITER_STORE_VERSION = 1;
const RESOURCE_ARBITER_JOURNAL_HEAD_VERSION = 1;
const RESOURCE_ARBITER_CAS_EXPECTATION_VERSION = 1;
const RESOURCE_ARBITER_COMMIT_RECEIPT_VERSION = 1;
const RESOURCE_ARBITER_SAFE_PROJECTION_VERSION = 1;
const RESOURCE_ARBITER_READINESS_VERSION = 1;
const RESOURCE_ARBITER_STATE_PORT_CONTRACT =
  "external-linearizable-physical-resource-arbiter-cas-v1";
const RESOURCE_ARBITER_DURABILITY_ASSURANCE = "caller_asserted_callback_unattested";
const RESOURCE_ARBITER_COMPACTION_CONTRACT =
  "proof-preserving-terminal-tombstone-checkpoint-required-v1";
const RESOURCE_ARBITER_COMPACTION_STATE = "not_implemented_refuse_deletion";
const MAX_SAFE_ARRAY_ENTRIES = 65_536;

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const TERMINAL_STATE_SET = new Set(TERMINAL_TICKET_STATE_VALUES);
const STATE_PORTS = new WeakSet();
const STATE_PORT_PRIVATE = new WeakMap();
const STORES = new WeakSet();
const STORE_PRIVATE = new WeakMap();

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

function assertDataArray(value, label, minimum = 0, maximum = MAX_SAFE_ARRAY_ENTRIES) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw new Error(`${label} must contain ${minimum}-${maximum} entries`);
  }
  const allowed = new Set(["length"]);
  for (let index = 0; index < value.length; index += 1) allowed.add(String(index));
  if (Reflect.ownKeys(value).some((key) => !allowed.has(key))) {
    throw new Error(`${label} cannot contain extra or symbol fields`);
  }
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

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertNullableDigest(value, label) {
  if (value === null) return null;
  return assertDigest(value, label);
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertNullableIdentifier(value, label) {
  if (value === null) return null;
  return assertIdentifier(value, label);
}

function assertInteger(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function finalizeDigest(value, supplied, field, label) {
  const digest = hashCanonicalJson(value);
  if (supplied != null) {
    assertDigest(supplied, `${label}.${field}`);
    if (supplied !== digest) throw new Error(`${label}.${field} does not match canonical content`);
  }
  return deepFreeze({ ...value, [field]: digest });
}

function storeError(code, message, cause = null) {
  const error = new Error(message, cause == null ? undefined : { cause });
  Object.defineProperty(error, "code", { value: code, enumerable: true });
  return error;
}

function assertSynchronousResult(value, label) {
  if (value && (typeof value === "object" || typeof value === "function")) {
    let then;
    try {
      then = value.then;
    } catch (cause) {
      throw storeError("arbiter_port_contract_violation", `${label} returned a hostile thenable`, cause);
    }
    if (typeof then === "function") {
      throw storeError("arbiter_port_contract_violation", `${label} must be synchronous`);
    }
  }
  return value;
}

function normalizeDigestArray(input, label, { minimum = 0, unique = true } = {}) {
  assertDataArray(input, label, minimum);
  const values = input.map((entry, index) => assertDigest(entry, `${label}[${index}]`));
  if (unique && new Set(values).size !== values.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze(values);
}

function normalizeDeferral(input, label) {
  assertClosedObject(input, label, [
    "reservation_request_digest",
    "prior_deferral_count",
    "next_deferral_count",
    "prior_ticket_digest",
    "next_ticket_digest",
  ]);
  const prior = assertInteger(input.prior_deferral_count, `${label}.prior_deferral_count`, 0, MAX_DEFERRAL_COUNT);
  const next = assertInteger(input.next_deferral_count, `${label}.next_deferral_count`, 0, MAX_DEFERRAL_COUNT);
  if (next !== Math.min(MAX_DEFERRAL_COUNT, prior + 1)) {
    throw new Error(`${label}.next_deferral_count must be the saturated successor`);
  }
  return deepFreeze({
    reservation_request_digest: assertDigest(
      input.reservation_request_digest,
      `${label}.reservation_request_digest`,
    ),
    prior_deferral_count: prior,
    next_deferral_count: next,
    prior_ticket_digest: assertDigest(input.prior_ticket_digest, `${label}.prior_ticket_digest`),
    next_ticket_digest: assertDigest(input.next_ticket_digest, `${label}.next_ticket_digest`),
  });
}

function normalizeTerminalizedTicket(input, label) {
  assertClosedObject(input, label, [
    "reservation_request_digest",
    "terminal_state",
    "terminal_generation",
    "ticket_digest",
  ]);
  return deepFreeze({
    reservation_request_digest: assertDigest(
      input.reservation_request_digest,
      `${label}.reservation_request_digest`,
    ),
    terminal_state: assertEnum(
      input.terminal_state,
      TERMINAL_TICKET_STATE_VALUES,
      `${label}.terminal_state`,
    ),
    terminal_generation: assertInteger(input.terminal_generation, `${label}.terminal_generation`, 1),
    ticket_digest: assertDigest(input.ticket_digest, `${label}.ticket_digest`),
  });
}

function normalizeActiveBatch(input, label) {
  if (input === null) return null;
  assertClosedObject(input, label, ["fairness_class", "batch_key", "selected_count"]);
  return deepFreeze({
    fairness_class: assertIdentifier(input.fairness_class, `${label}.fairness_class`),
    batch_key: assertDigest(input.batch_key, `${label}.batch_key`),
    selected_count: assertInteger(input.selected_count, `${label}.selected_count`, 1, MAX_BATCH_BURST),
  });
}

function normalizePhysicalResourceArbiterDecision(input, label = "physical_resource_arbiter_decision") {
  assertClosedObject(input, label, [
    "version",
    "generation",
    "disposition",
    "fairness_class",
    "batch_key",
    "continued_batch",
    "selected_reservation_request_digests",
    "selected_ticket_digests",
    "deferrals",
    "blocked_without_credit_ticket_digests",
    "unschedulable_without_credit_ticket_digests",
    "terminalized_tickets",
    "active_batch_after",
  ], ["decision_digest"]);
  if (input.version !== PHYSICAL_RESOURCE_ARBITER_DECISION_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_RESOURCE_ARBITER_DECISION_VERSION}`);
  }
  const disposition = assertEnum(
    input.disposition,
    ARBITER_DECISION_DISPOSITION_VALUES,
    `${label}.disposition`,
  );
  const selectedRequests = normalizeDigestArray(
    input.selected_reservation_request_digests,
    `${label}.selected_reservation_request_digests`,
  );
  const selectedTickets = normalizeDigestArray(
    input.selected_ticket_digests,
    `${label}.selected_ticket_digests`,
  );
  if (selectedRequests.length !== selectedTickets.length) {
    throw new Error(`${label} selected request and ticket counts must match`);
  }
  assertDataArray(input.deferrals, `${label}.deferrals`);
  const deferrals = input.deferrals.map((entry, index) => normalizeDeferral(entry, `${label}.deferrals[${index}]`));
  if (new Set(deferrals.map((entry) => entry.reservation_request_digest)).size !== deferrals.length) {
    throw new Error(`${label}.deferrals must not repeat reservation requests`);
  }
  assertDataArray(input.terminalized_tickets, `${label}.terminalized_tickets`);
  const terminalized = input.terminalized_tickets.map((entry, index) => (
    normalizeTerminalizedTicket(entry, `${label}.terminalized_tickets[${index}]`)
  ));
  if (new Set(terminalized.map((entry) => entry.reservation_request_digest)).size !== terminalized.length) {
    throw new Error(`${label}.terminalized_tickets must not repeat reservation requests`);
  }
  const value = {
    version: PHYSICAL_RESOURCE_ARBITER_DECISION_VERSION,
    generation: assertInteger(input.generation, `${label}.generation`, 1),
    disposition,
    fairness_class: assertNullableIdentifier(input.fairness_class, `${label}.fairness_class`),
    batch_key: assertNullableDigest(input.batch_key, `${label}.batch_key`),
    continued_batch: assertBoolean(input.continued_batch, `${label}.continued_batch`),
    selected_reservation_request_digests: selectedRequests,
    selected_ticket_digests: selectedTickets,
    deferrals: Object.freeze(deferrals),
    blocked_without_credit_ticket_digests: normalizeDigestArray(
      input.blocked_without_credit_ticket_digests,
      `${label}.blocked_without_credit_ticket_digests`,
    ),
    unschedulable_without_credit_ticket_digests: normalizeDigestArray(
      input.unschedulable_without_credit_ticket_digests,
      `${label}.unschedulable_without_credit_ticket_digests`,
    ),
    terminalized_tickets: Object.freeze(terminalized),
    active_batch_after: normalizeActiveBatch(input.active_batch_after, `${label}.active_batch_after`),
  };
  if (disposition === "idle") {
    if (value.fairness_class !== null || value.batch_key !== null || value.continued_batch
        || selectedRequests.length !== 0 || value.active_batch_after !== null) {
      throw new Error(`${label} idle disposition cannot claim selection or batch progress`);
    }
  } else if (value.fairness_class === null || value.batch_key === null || selectedRequests.length < 1) {
    throw new Error(`${label} selected disposition requires a class, batch, and selected ticket`);
  }
  return finalizeDigest(value, input.decision_digest, "decision_digest", label);
}

function sameCanonical(left, right) {
  return hashCanonicalJson(left) === hashCanonicalJson(right);
}

function rewriteQueueTicket(ticket, changes, label) {
  const value = {
    ...ticket,
    ...changes,
  };
  delete value.ticket_digest;
  if (!TERMINAL_STATE_SET.has(value.ticket_state)) delete value.terminal_generation;
  return normalizePhysicalResourceQueueTicket(value, label);
}

function assertDecisionMatchesQueueState(decision, queue, state, label) {
  if (decision.generation !== state.generation) throw new Error(`${label} generation does not match state`);
  if (!sameCanonical(decision.active_batch_after, state.active_batch)) {
    throw new Error(`${label}.active_batch_after does not match state`);
  }
  if (decision.fairness_class != null && state.last_served_fairness_class !== decision.fairness_class) {
    throw new Error(`${label}.fairness_class does not match state cursor`);
  }
  const ticketByRequest = new Map(queue.tickets.map((ticket) => [
    ticket.reservation_request_digest,
    ticket,
  ]));
  const terminalizedByRequest = new Map(decision.terminalized_tickets.map((entry) => [
    entry.reservation_request_digest,
    entry,
  ]));
  const currentSelectedTickets = queue.tickets.filter((ticket) => (
    ticket.ticket_state === "selected"
    && ticket.terminal_generation === state.generation
  ));
  const selectedRequestSet = new Set(decision.selected_reservation_request_digests);
  if (currentSelectedTickets.length !== selectedRequestSet.size
      || currentSelectedTickets.some((ticket) => (
        !selectedRequestSet.has(ticket.reservation_request_digest)
      ))) {
    throw new Error(`${label} selected request set does not exactly match the committed selection`);
  }
  for (let index = 0; index < decision.selected_reservation_request_digests.length; index += 1) {
    const requestDigest = decision.selected_reservation_request_digests[index];
    const ticket = ticketByRequest.get(requestDigest);
    const terminalized = terminalizedByRequest.get(requestDigest);
    if (!ticket || ticket.ticket_state !== "selected" || ticket.terminal_generation !== state.generation
        || !terminalized || terminalized.terminal_state !== "selected"
        || terminalized.ticket_digest !== ticket.ticket_digest) {
      throw new Error(`${label} selected request is not the exact committed terminal ticket`);
    }
    if (ticket.fairness_class !== decision.fairness_class
        || ticket.batch_key !== decision.batch_key) {
      throw new Error(`${label} selected ticket does not match the decision class and batch`);
    }
    const preTerminalTicket = rewriteQueueTicket(ticket, {
      ticket_state: "ready",
    }, `${label}.selected_pre_terminal_ticket`);
    if (preTerminalTicket.ticket_digest !== decision.selected_ticket_digests[index]) {
      throw new Error(`${label} selected ticket digest does not bind its exact pre-terminal ticket`);
    }
  }
  const deferredRequests = new Set();
  for (const deferral of decision.deferrals) {
    const ticket = ticketByRequest.get(deferral.reservation_request_digest);
    if (!ticket || ticket.ticket_state !== "ready"
        || ticket.deferral_count !== deferral.next_deferral_count
        || ticket.ticket_digest !== deferral.next_ticket_digest) {
      throw new Error(`${label} deferral does not match the committed ready ticket`);
    }
    const priorTicket = rewriteQueueTicket(ticket, {
      deferral_count: deferral.prior_deferral_count,
    }, `${label}.deferral_prior_ticket`);
    if (priorTicket.ticket_digest !== deferral.prior_ticket_digest) {
      throw new Error(`${label} deferral does not bind its exact predecessor ticket`);
    }
    deferredRequests.add(deferral.reservation_request_digest);
  }
  const readyRequests = queue.tickets
    .filter((ticket) => ticket.ticket_state === "ready")
    .map((ticket) => ticket.reservation_request_digest);
  if (readyRequests.length !== deferredRequests.size
      || readyRequests.some((requestDigest) => !deferredRequests.has(requestDigest))) {
    throw new Error(`${label} must bind every committed ready ticket as a deferral`);
  }
  const blockedDigests = queue.tickets
    .filter((ticket) => ticket.ticket_state === "blocked")
    .map((ticket) => ticket.ticket_digest)
    .sort(comparePhysicalResourceArbiterProtocolStrings);
  if (!sameCanonical(
    blockedDigests,
    [...decision.blocked_without_credit_ticket_digests]
      .sort(comparePhysicalResourceArbiterProtocolStrings),
  )) {
    throw new Error(`${label} blocked no-credit set does not match queue`);
  }
  const unschedulableDigests = queue.tickets
    .filter((ticket) => ticket.ticket_state === "unschedulable")
    .map((ticket) => ticket.ticket_digest)
    .sort(comparePhysicalResourceArbiterProtocolStrings);
  if (!sameCanonical(
    unschedulableDigests,
    [...decision.unschedulable_without_credit_ticket_digests]
      .sort(comparePhysicalResourceArbiterProtocolStrings),
  )) {
    throw new Error(`${label} unschedulable no-credit set does not match queue`);
  }
  const currentTerminalized = queue.tickets
    .filter((ticket) => ticket.terminal_generation === state.generation)
    .map((ticket) => ({
      reservation_request_digest: ticket.reservation_request_digest,
      terminal_state: ticket.ticket_state,
      terminal_generation: ticket.terminal_generation,
      ticket_digest: ticket.ticket_digest,
    }));
  if (!sameCanonical(currentTerminalized, decision.terminalized_tickets)) {
    throw new Error(`${label} terminalized set does not match queue`);
  }
}

function normalizePhysicalResourceArbiterJournalHead(
  input,
  label = "physical_resource_arbiter_journal_head",
) {
  assertClosedObject(input, label, [
    "version",
    "journal_domain_digest",
    "initialization_digest",
    "config_digest",
    "generation",
    "prior_head_digest",
    "input_digest",
    "input_state_digest",
    "input_queue_digest",
    "commands_digest",
    "transition_digest",
    "decision",
    "state",
    "queue",
  ], ["head_digest"]);
  if (input.version !== RESOURCE_ARBITER_JOURNAL_HEAD_VERSION) {
    throw new Error(`${label}.version must be ${RESOURCE_ARBITER_JOURNAL_HEAD_VERSION}`);
  }
  const state = normalizePhysicalResourceArbiterState(input.state, `${label}.state`);
  const queue = normalizePhysicalResourceArbiterQueue(input.queue, `${label}.queue`);
  const generation = assertInteger(input.generation, `${label}.generation`);
  if (state.generation !== generation || state.queue_digest !== queue.queue_digest) {
    throw new Error(`${label} generation or queue binding does not match state`);
  }
  const value = {
    version: RESOURCE_ARBITER_JOURNAL_HEAD_VERSION,
    journal_domain_digest: assertDigest(input.journal_domain_digest, `${label}.journal_domain_digest`),
    initialization_digest: assertDigest(input.initialization_digest, `${label}.initialization_digest`),
    config_digest: assertDigest(input.config_digest, `${label}.config_digest`),
    generation,
    prior_head_digest: assertNullableDigest(input.prior_head_digest, `${label}.prior_head_digest`),
    input_digest: assertNullableDigest(input.input_digest, `${label}.input_digest`),
    input_state_digest: assertNullableDigest(input.input_state_digest, `${label}.input_state_digest`),
    input_queue_digest: assertNullableDigest(input.input_queue_digest, `${label}.input_queue_digest`),
    commands_digest: assertNullableDigest(input.commands_digest, `${label}.commands_digest`),
    transition_digest: assertNullableDigest(input.transition_digest, `${label}.transition_digest`),
    decision: input.decision === null
      ? null
      : normalizePhysicalResourceArbiterDecision(input.decision, `${label}.decision`),
    state,
    queue,
  };
  if (value.config_digest !== state.config_digest) throw new Error(`${label} config digest does not match state`);
  const transitionFields = [
    value.prior_head_digest,
    value.input_digest,
    value.input_state_digest,
    value.input_queue_digest,
    value.commands_digest,
    value.transition_digest,
    value.decision,
  ];
  if (generation === 0) {
    if (transitionFields.some((entry) => entry !== null)) {
      throw new Error(`${label} genesis cannot claim a transition`);
    }
  } else {
    if (transitionFields.some((entry) => entry === null)) {
      throw new Error(`${label} non-genesis must bind its complete transition`);
    }
    if (state.previous_state_digest !== value.input_state_digest
        || state.applied_input_digest !== value.input_digest) {
      throw new Error(`${label} transition input does not match state chain`);
    }
    assertDecisionMatchesQueueState(value.decision, queue, state, `${label}.decision`);
    const transitionValue = {
      version: PHYSICAL_RESOURCE_ARBITER_TRANSITION_VERSION,
      input_digest: value.input_digest,
      input_state_digest: value.input_state_digest,
      input_queue_digest: value.input_queue_digest,
      config_digest: value.config_digest,
      commands_digest: value.commands_digest,
      decision: value.decision,
      next_queue: queue,
      next_state: state,
    };
    if (hashCanonicalJson(transitionValue) !== value.transition_digest) {
      throw new Error(`${label}.transition_digest does not match committed transition`);
    }
  }
  return finalizeDigest(value, input.head_digest, "head_digest", label);
}

function createPhysicalResourceArbiterStatePort(input = {}) {
  assertClosedObject(input, "physical_resource_arbiter_state_port", [
    "port_id",
    "journal_domain_digest",
    "read_head",
    "compare_and_set",
  ]);
  if (typeof input.read_head !== "function" || typeof input.compare_and_set !== "function") {
    throw new Error("physical resource arbiter state port requires synchronous read_head and compare_and_set functions");
  }
  const port = deepFreeze({
    version: RESOURCE_ARBITER_STATE_PORT_VERSION,
    port_id: assertIdentifier(input.port_id, "physical_resource_arbiter_state_port.port_id"),
    journal_domain_digest: assertDigest(
      input.journal_domain_digest,
      "physical_resource_arbiter_state_port.journal_domain_digest",
    ),
    contract: RESOURCE_ARBITER_STATE_PORT_CONTRACT,
    durability_assurance: RESOURCE_ARBITER_DURABILITY_ASSURANCE,
    production_attested: false,
  });
  STATE_PORTS.add(port);
  STATE_PORT_PRIVATE.set(port, Object.freeze({
    read_head: input.read_head,
    compare_and_set: input.compare_and_set,
  }));
  return port;
}

function assertPhysicalResourceArbiterStatePort(port) {
  if (!port || !Object.isFrozen(port) || !STATE_PORTS.has(port) || !STATE_PORT_PRIVATE.has(port)) {
    throw new Error("physical resource arbiter state port must be created by Bob's private factory");
  }
  return port;
}

function readExternalHead(port) {
  assertPhysicalResourceArbiterStatePort(port);
  const callback = STATE_PORT_PRIVATE.get(port).read_head;
  let raw;
  try {
    raw = assertSynchronousResult(callback(), "physical resource arbiter read_head");
  } catch (cause) {
    if (cause && cause.code === "arbiter_port_contract_violation") throw cause;
    throw storeError("arbiter_state_unavailable", "physical resource arbiter head read failed", cause);
  }
  if (raw === null) return null;
  try {
    return normalizePhysicalResourceArbiterJournalHead(raw);
  } catch (cause) {
    throw storeError("arbiter_head_invalid", "physical resource arbiter external head is invalid", cause);
  }
}

function headExpectation(head) {
  return deepFreeze({
    version: RESOURCE_ARBITER_CAS_EXPECTATION_VERSION,
    journal_domain_digest: head.journal_domain_digest,
    config_digest: head.config_digest,
    generation: head.generation,
    head_digest: head.head_digest,
    state_digest: head.state.state_digest,
    queue_digest: head.queue.queue_digest,
  });
}

function compareAndSetExternalHead(port, expectedHead, nextHead) {
  assertPhysicalResourceArbiterStatePort(port);
  const callback = STATE_PORT_PRIVATE.get(port).compare_and_set;
  const expected = expectedHead == null ? null : headExpectation(expectedHead);
  let result;
  try {
    result = assertSynchronousResult(
      callback(expected == null ? null : cloneJson(expected), cloneJson(nextHead)),
      "physical resource arbiter compare_and_set",
    );
  } catch (cause) {
    if (cause && cause.code === "arbiter_port_contract_violation") throw cause;
    throw storeError("arbiter_cas_response_unknown", "physical resource arbiter CAS response was not observed", cause);
  }
  if (typeof result !== "boolean") {
    throw storeError("arbiter_port_contract_violation", "physical resource arbiter compare_and_set must return a boolean");
  }
  return result;
}

function createGenesisHead(initialization, journalDomainDigest) {
  return normalizePhysicalResourceArbiterJournalHead({
    version: RESOURCE_ARBITER_JOURNAL_HEAD_VERSION,
    journal_domain_digest: journalDomainDigest,
    initialization_digest: initialization.initialization_digest,
    config_digest: initialization.config.config_digest,
    generation: 0,
    prior_head_digest: null,
    input_digest: null,
    input_state_digest: null,
    input_queue_digest: null,
    commands_digest: null,
    transition_digest: null,
    decision: null,
    state: initialization.state,
    queue: initialization.queue,
  });
}

function createTransitionHead(priorHead, transition) {
  return normalizePhysicalResourceArbiterJournalHead({
    version: RESOURCE_ARBITER_JOURNAL_HEAD_VERSION,
    journal_domain_digest: priorHead.journal_domain_digest,
    initialization_digest: priorHead.initialization_digest,
    config_digest: transition.config_digest,
    generation: transition.next_state.generation,
    prior_head_digest: priorHead.head_digest,
    input_digest: transition.input_digest,
    input_state_digest: transition.input_state_digest,
    input_queue_digest: transition.input_queue_digest,
    commands_digest: transition.commands_digest,
    transition_digest: transition.transition_digest,
    decision: transition.decision,
    state: transition.next_state,
    queue: transition.next_queue,
  });
}

function reconstructPostCommandQueue(successor, label) {
  const selectedIndexByRequest = new Map(
    successor.decision.selected_reservation_request_digests.map((requestDigest, index) => [
      requestDigest,
      index,
    ]),
  );
  const deferralByRequest = new Map(successor.decision.deferrals.map((deferral) => [
    deferral.reservation_request_digest,
    deferral,
  ]));
  const tickets = successor.queue.tickets.map((ticket, index) => {
    const requestDigest = ticket.reservation_request_digest;
    if (selectedIndexByRequest.has(requestDigest)) {
      const selectedIndex = selectedIndexByRequest.get(requestDigest);
      const preTerminal = rewriteQueueTicket(ticket, {
        ticket_state: "ready",
      }, `${label}.selected_pre_terminal_tickets[${selectedIndex}]`);
      if (preTerminal.ticket_digest !== successor.decision.selected_ticket_digests[selectedIndex]) {
        throw new Error(`${label} selected ticket predecessor digest drift`);
      }
      return preTerminal;
    }
    if (deferralByRequest.has(requestDigest)) {
      const deferral = deferralByRequest.get(requestDigest);
      const predecessor = rewriteQueueTicket(ticket, {
        deferral_count: deferral.prior_deferral_count,
      }, `${label}.deferral_predecessor_tickets[${index}]`);
      if (predecessor.ticket_digest !== deferral.prior_ticket_digest) {
        throw new Error(`${label} deferral predecessor digest drift`);
      }
      return predecessor;
    }
    return ticket;
  });
  return normalizePhysicalResourceArbiterQueue({
    version: successor.queue.version,
    tickets,
  }, `${label}.post_command_queue`);
}

function arbiterCommand(commandKind, requestDigest) {
  return {
    version: PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
    command_kind: commandKind,
    reservation_request_digest: requestDigest,
  };
}

function inferSuccessorCommands(predecessor, successor, postCommandQueue, label) {
  const predecessorByRequest = new Map(predecessor.queue.tickets.map((ticket) => [
    ticket.reservation_request_digest,
    ticket,
  ]));
  const postCommandByRequest = new Map(postCommandQueue.tickets.map((ticket) => [
    ticket.reservation_request_digest,
    ticket,
  ]));
  const commands = [];
  for (const predecessorTicket of predecessor.queue.tickets) {
    const requestDigest = predecessorTicket.reservation_request_digest;
    const nextTicket = postCommandByRequest.get(requestDigest);
    if (!nextTicket) throw new Error(`${label} successor deleted a durable queue ticket`);
    if (sameCanonical(predecessorTicket, nextTicket)) continue;
    if (!ACTIVE_TICKET_STATE_VALUES.includes(predecessorTicket.ticket_state)) {
      throw new Error(`${label} successor mutated a terminal queue ticket`);
    }
    const candidates = [];
    if (predecessorTicket.ticket_state === "blocked") {
      candidates.push({
        command: arbiterCommand("mark_ready", requestDigest),
        ticket: rewriteQueueTicket(predecessorTicket, {
          ticket_state: "ready",
        }, `${label}.mark_ready_candidate`),
      });
    }
    if (predecessorTicket.ticket_state === "ready") {
      candidates.push({
        command: arbiterCommand("mark_blocked", requestDigest),
        ticket: rewriteQueueTicket(predecessorTicket, {
          ticket_state: "blocked",
        }, `${label}.mark_blocked_candidate`),
      });
    }
    for (const [commandKind, terminalState] of [
      ["cancel", "cancelled"],
      ["mark_unschedulable", "unschedulable"],
    ]) {
      candidates.push({
        command: arbiterCommand(commandKind, requestDigest),
        ticket: rewriteQueueTicket(predecessorTicket, {
          ticket_state: terminalState,
          terminal_generation: successor.generation,
        }, `${label}.${commandKind}_candidate`),
      });
    }
    const matched = candidates.filter((candidate) => sameCanonical(candidate.ticket, nextTicket));
    if (matched.length !== 1) {
      throw new Error(`${label} successor ticket mutation is not one exact arbiter command`);
    }
    commands.push(matched[0].command);
  }
  for (const nextTicket of postCommandQueue.tickets) {
    if (predecessorByRequest.has(nextTicket.reservation_request_digest)) continue;
    if (!ACTIVE_TICKET_STATE_VALUES.includes(nextTicket.ticket_state)
        || nextTicket.enqueue_generation !== successor.generation
        || nextTicket.deferral_count !== 0) {
      throw new Error(`${label} successor added a ticket that is not an exact enqueue`);
    }
    commands.push({
      version: PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
      command_kind: "enqueue",
      ticket: nextTicket,
    });
  }
  return normalizePhysicalResourceArbiterCommands(commands, `${label}.inferred_commands`);
}

function assertExactPhysicalResourceArbiterSuccessor(
  predecessor,
  successor,
  config,
  label = "physical resource arbiter successor",
) {
  const metadataMatches = successor.generation === predecessor.generation + 1
    && successor.prior_head_digest === predecessor.head_digest
    && successor.journal_domain_digest === predecessor.journal_domain_digest
    && successor.initialization_digest === predecessor.initialization_digest
    && successor.config_digest === predecessor.config_digest
    && successor.input_state_digest === predecessor.state.state_digest
    && successor.input_queue_digest === predecessor.queue.queue_digest;
  if (!metadataMatches) {
    throw storeError(
      "arbiter_head_successor_invalid",
      `${label} does not bind every exact predecessor coordinate`,
    );
  }
  try {
    assertPhysicalResourceArbiterBoundState(config, predecessor.state, predecessor.queue, `${label}.predecessor`);
    assertPhysicalResourceArbiterBoundState(config, successor.state, successor.queue, `${label}.successor`);
    const postCommandQueue = reconstructPostCommandQueue(successor, label);
    const commands = inferSuccessorCommands(predecessor, successor, postCommandQueue, label);
    if (hashCanonicalJson(commands) !== successor.commands_digest) {
      throw new Error(`${label} inferred command digest does not match the committed command digest`);
    }
    const transition = transitionPhysicalResourceArbiter({
      config,
      state: predecessor.state,
      queue: predecessor.queue,
      commands,
    }, `${label}.replayed_transition`);
    const expectedHead = createTransitionHead(predecessor, transition);
    if (!sameCanonical(expectedHead, successor)) {
      throw new Error(`${label} is not the exact deterministic arbiter successor`);
    }
  } catch (cause) {
    if (cause && cause.code === "arbiter_head_successor_invalid") throw cause;
    throw storeError(
      "arbiter_head_successor_invalid",
      `${label} failed exact predecessor-bound transition replay`,
      cause,
    );
  }
  return successor;
}

function assertHeadBinding(head, privateState, label = "physical resource arbiter head") {
  if (head.journal_domain_digest !== privateState.port.journal_domain_digest) {
    markAmbiguous(privateState);
    throw storeError("arbiter_domain_drift", `${label} journal domain drift`);
  }
  if (head.initialization_digest !== privateState.initialization.initialization_digest) {
    markAmbiguous(privateState);
    throw storeError("arbiter_initialization_drift", `${label} initialization drift`);
  }
  if (head.config_digest !== privateState.config.config_digest
      || head.state.config_digest !== privateState.config.config_digest) {
    markAmbiguous(privateState);
    throw storeError("arbiter_config_drift", `${label} config drift`);
  }
  if (head.queue.tickets.length > privateState.config.max_queue_tickets) {
    markAmbiguous(privateState);
    throw storeError("arbiter_queue_capacity_invalid", `${label} exceeds bound queue capacity`);
  }
  try {
    assertPhysicalResourceArbiterBoundState(
      privateState.config,
      head.state,
      head.queue,
      label,
    );
  } catch (cause) {
    markAmbiguous(privateState);
    throw storeError(
      "arbiter_head_binding_invalid",
      `${label} violates the config-bound state and queue invariant`,
      cause,
    );
  }
  return head;
}

function reconcileGenesis(port, genesis, config, casResult, casError) {
  let observed;
  try {
    observed = readExternalHead(port);
  } catch (readError) {
    if (casResult === true || casError != null) {
      throw storeError(
        "arbiter_state_ambiguous",
        "physical resource arbiter genesis outcome cannot be reconciled",
        readError,
      );
    }
    throw readError;
  }
  if (observed && observed.head_digest === genesis.head_digest) return observed;
  if (observed
      && observed.generation === 1
      && observed.prior_head_digest === genesis.head_digest) {
    try {
      return assertExactPhysicalResourceArbiterSuccessor(
        genesis,
        observed,
        config,
        "concurrent arbiter genesis successor",
      );
    } catch (cause) {
      throw storeError(
        "arbiter_genesis_conflict",
        "concurrent arbiter genesis successor is not predecessor-bound",
        cause,
      );
    }
  }
  if (observed === null) {
    if (casError && casError.code === "arbiter_port_contract_violation") throw casError;
    if (casError != null) throw storeError("arbiter_state_unavailable", "arbiter genesis was not committed", casError);
    if (casResult === false) throw storeError("arbiter_genesis_conflict", "arbiter genesis CAS reported conflict without a winner");
    throw storeError("arbiter_state_ambiguous", "arbiter genesis CAS success was not externally visible");
  }
  throw storeError("arbiter_genesis_conflict", "a different arbiter journal already occupies this domain");
}

function createPhysicalResourceArbiterStore(input = {}) {
  assertClosedObject(input, "physical_resource_arbiter_store", ["state_port", "config", "queue"]);
  const port = assertPhysicalResourceArbiterStatePort(input.state_port);
  const config = normalizePhysicalResourceArbiterConfig(input.config, "physical_resource_arbiter_store.config");
  const queue = normalizePhysicalResourceArbiterQueue(input.queue, "physical_resource_arbiter_store.queue");
  const initialization = initializePhysicalResourceArbiter({ config, queue });
  const privateState = {
    port,
    config: initialization.config,
    initialization,
    cached_head: null,
    mutation_state: "ready",
    active_operation: null,
  };
  let head = readExternalHead(port);
  if (head === null) {
    const genesis = createGenesisHead(initialization, port.journal_domain_digest);
    let casResult = null;
    let casError = null;
    try {
      casResult = compareAndSetExternalHead(port, null, genesis);
    } catch (error) {
      casError = error;
    }
    head = reconcileGenesis(port, genesis, initialization.config, casResult, casError);
  }
  assertHeadBinding(head, privateState);
  privateState.cached_head = head;
  const store = deepFreeze({
    version: RESOURCE_ARBITER_STORE_VERSION,
    port_id: port.port_id,
    journal_domain_digest: port.journal_domain_digest,
    initialization_digest: initialization.initialization_digest,
    config_digest: initialization.config.config_digest,
    state_port_contract: RESOURCE_ARBITER_STATE_PORT_CONTRACT,
    durability_assurance: RESOURCE_ARBITER_DURABILITY_ASSURANCE,
    production_attested: false,
  });
  STORES.add(store);
  STORE_PRIVATE.set(store, privateState);
  return store;
}

function assertPhysicalResourceArbiterStore(store) {
  if (!store || !Object.isFrozen(store) || !STORES.has(store) || !STORE_PRIVATE.has(store)) {
    throw new Error("physical resource arbiter store must be created by Bob's private factory");
  }
  return store;
}

function markAmbiguous(privateState) {
  privateState.mutation_state = "ambiguous_fail_closed";
}

function assertStoreMutable(privateState) {
  if (privateState.mutation_state !== "ready") {
    throw storeError("arbiter_state_ambiguous", "physical resource arbiter store is ambiguous and fail closed");
  }
}

function withPhysicalResourceArbiterStoreOperation(privateState, operation, callback) {
  if (privateState.active_operation !== null) {
    throw storeError(
      "arbiter_state_reentrant_mutation",
      `physical resource arbiter ${operation} cannot re-enter active ${privateState.active_operation}`,
    );
  }
  privateState.active_operation = operation;
  try {
    return callback();
  } finally {
    privateState.active_operation = null;
  }
}

function normalizeCommitInput(input, label = "physical_resource_arbiter_commit") {
  assertClosedObject(input, label, [
    "expected_generation",
    "expected_head_digest",
    "expected_state_digest",
    "expected_queue_digest",
    "commands",
  ]);
  const commands = normalizePhysicalResourceArbiterCommands(input.commands, `${label}.commands`);
  return deepFreeze({
    expected_generation: assertInteger(input.expected_generation, `${label}.expected_generation`),
    expected_head_digest: assertDigest(input.expected_head_digest, `${label}.expected_head_digest`),
    expected_state_digest: assertDigest(input.expected_state_digest, `${label}.expected_state_digest`),
    expected_queue_digest: assertDigest(input.expected_queue_digest, `${label}.expected_queue_digest`),
    commands,
    commands_digest: hashCanonicalJson(commands),
  });
}

function expectationMatchesHead(commit, head) {
  return commit.expected_generation === head.generation
    && commit.expected_head_digest === head.head_digest
    && commit.expected_state_digest === head.state.state_digest
    && commit.expected_queue_digest === head.queue.queue_digest;
}

function isExactCommittedReplay(head, commit) {
  return head.generation === commit.expected_generation + 1
    && head.prior_head_digest === commit.expected_head_digest
    && head.input_state_digest === commit.expected_state_digest
    && head.input_queue_digest === commit.expected_queue_digest
    && head.commands_digest === commit.commands_digest;
}

function relationError(reference, observed, config, context) {
  if (observed === null || observed.generation < reference.generation) {
    return storeError("arbiter_head_rollback", `${context} observed an arbiter head rollback`);
  }
  if (observed.generation === reference.generation) {
    return storeError("arbiter_head_fork", `${context} observed a same-generation arbiter fork`);
  }
  if (observed.generation === reference.generation + 1
      && observed.prior_head_digest === reference.head_digest) {
    try {
      assertExactPhysicalResourceArbiterSuccessor(
        reference,
        observed,
        config,
        `${context} direct successor`,
      );
    } catch (cause) {
      return storeError(
        "arbiter_head_fork",
        `${context} observed a direct successor with invalid predecessor bindings`,
        cause,
      );
    }
    return storeError("arbiter_cas_conflict", `${context} lost to a concurrent committed transition`);
  }
  if (observed.generation > reference.generation + 1) {
    return storeError("arbiter_head_gap", `${context} observed an unverified arbiter generation gap`);
  }
  return storeError("arbiter_head_fork", `${context} observed a broken arbiter ancestry link`);
}

function safeTicketProjection(ticket) {
  const value = {
    reservation_request_digest: ticket.reservation_request_digest,
    resource_bundle_digest: ticket.resource_bundle_digest,
    fairness_class: ticket.fairness_class,
    batch_key: ticket.batch_key,
    enqueue_generation: ticket.enqueue_generation,
    deferral_count: ticket.deferral_count,
    ticket_state: ticket.ticket_state,
    ticket_digest: ticket.ticket_digest,
  };
  if (ticket.terminal_generation != null) value.terminal_generation = ticket.terminal_generation;
  return deepFreeze(value);
}

function capacityProjection(config, head) {
  const ticketStateCounts = Object.fromEntries(
    [...ACTIVE_TICKET_STATE_VALUES, ...TERMINAL_TICKET_STATE_VALUES]
      .map((state) => [state, head.queue.tickets.filter((ticket) => ticket.ticket_state === state).length]),
  );
  const used = head.queue.tickets.length;
  const remaining = config.max_queue_tickets - used;
  const terminalTombstones = head.queue.tickets.filter((ticket) => TERMINAL_STATE_SET.has(ticket.ticket_state)).length;
  let capacityState = "ready";
  if (remaining === 0) capacityState = "exhausted";
  else if (used * 10 >= config.max_queue_tickets * 9) capacityState = "near_capacity";
  return deepFreeze({
    max_queue_tickets: config.max_queue_tickets,
    queue_ticket_count: used,
    remaining_ticket_capacity: remaining,
    terminal_tombstone_count: terminalTombstones,
    ticket_state_counts: deepFreeze(ticketStateCounts),
    capacity_state: capacityState,
    request_digest_reuse_allowed: false,
    compaction_contract: RESOURCE_ARBITER_COMPACTION_CONTRACT,
    compaction_state: RESOURCE_ARBITER_COMPACTION_STATE,
  });
}

function safeHeadProjection(privateState, head) {
  const capacity = capacityProjection(privateState.config, head);
  const value = {
    version: RESOURCE_ARBITER_SAFE_PROJECTION_VERSION,
    journal_domain_digest: head.journal_domain_digest,
    initialization_digest: head.initialization_digest,
    config_digest: head.config_digest,
    generation: head.generation,
    head_digest: head.head_digest,
    prior_head_digest: head.prior_head_digest,
    state_digest: head.state.state_digest,
    queue_digest: head.queue.queue_digest,
    transition_digest: head.transition_digest,
    decision_digest: head.decision == null ? null : head.decision.decision_digest,
    disposition: head.decision == null ? null : head.decision.disposition,
    selected_reservation_request_digests: head.decision == null
      ? Object.freeze([])
      : head.decision.selected_reservation_request_digests,
    selected_ticket_digests: head.decision == null
      ? Object.freeze([])
      : head.decision.selected_ticket_digests,
    tickets: Object.freeze(head.queue.tickets.map(safeTicketProjection)),
    capacity,
  };
  return deepFreeze({ ...value, projection_digest: hashCanonicalJson(value) });
}

function commitReceipt(privateState, committedHead, status) {
  const decision = committedHead.decision;
  const value = {
    version: RESOURCE_ARBITER_COMMIT_RECEIPT_VERSION,
    commit_status: status,
    durability_assurance: RESOURCE_ARBITER_DURABILITY_ASSURANCE,
    production_attested: false,
    generation: committedHead.generation,
    head_digest: committedHead.head_digest,
    prior_head_digest: committedHead.prior_head_digest,
    state_digest: committedHead.state.state_digest,
    queue_digest: committedHead.queue.queue_digest,
    transition_digest: committedHead.transition_digest,
    decision_digest: decision.decision_digest,
    disposition: decision.disposition,
    fairness_class: decision.fairness_class,
    batch_key: decision.batch_key,
    selected_reservation_request_digests: decision.selected_reservation_request_digests,
    selected_ticket_digests: decision.selected_ticket_digests,
    capacity: capacityProjection(privateState.config, committedHead),
  };
  return deepFreeze({ ...value, commit_receipt_digest: hashCanonicalJson(value) });
}

function confirmProposedHead(privateState, expectedHead, proposedHead, casResult, casError) {
  let observed;
  try {
    observed = readExternalHead(privateState.port);
    if (observed !== null) assertHeadBinding(observed, privateState, "post-CAS arbiter head");
  } catch (readError) {
    if (casResult === false) throw readError;
    markAmbiguous(privateState);
    throw storeError("arbiter_state_ambiguous", "arbiter CAS outcome cannot be reconciled", readError);
  }
  if (observed && observed.head_digest === proposedHead.head_digest) {
    privateState.cached_head = observed;
    return commitReceipt(
      privateState,
      proposedHead,
      casResult === true && casError == null ? "committed" : "reconciled_response_loss",
    );
  }
  if (observed && observed.generation === proposedHead.generation + 1
      && observed.prior_head_digest === proposedHead.head_digest) {
    try {
      assertExactPhysicalResourceArbiterSuccessor(
        proposedHead,
        observed,
        privateState.config,
        "post-CAS arbiter successor",
      );
    } catch (cause) {
      markAmbiguous(privateState);
      throw storeError(
        "arbiter_head_fork",
        "post-CAS arbiter successor has invalid predecessor bindings",
        cause,
      );
    }
    privateState.cached_head = observed;
    return commitReceipt(privateState, proposedHead, "reconciled_response_loss");
  }
  if (observed && observed.head_digest === expectedHead.head_digest) {
    if (casError != null && casError.code === "arbiter_cas_response_unknown") {
      throw storeError("arbiter_state_unavailable", "arbiter CAS did not commit and its response was unavailable", casError);
    }
    markAmbiguous(privateState);
    throw storeError("arbiter_port_contract_violation", "arbiter CAS result contradicted the external head");
  }
  const relation = relationError(
    expectedHead,
    observed,
    privateState.config,
    "physical resource arbiter CAS",
  );
  if (relation.code !== "arbiter_cas_conflict") markAmbiguous(privateState);
  throw relation;
}

function commitPhysicalResourceArbiterTransitionUnguarded(store, input = {}) {
  assertPhysicalResourceArbiterStore(store);
  const privateState = STORE_PRIVATE.get(store);
  assertStoreMutable(privateState);
  const commit = normalizeCommitInput(input);
  let current = readExternalHead(privateState.port);
  if (current === null) {
    markAmbiguous(privateState);
    throw storeError("arbiter_head_rollback", "physical resource arbiter journal head disappeared");
  }
  assertHeadBinding(current, privateState);

  if (current.head_digest !== privateState.cached_head.head_digest) {
    const relation = relationError(
      privateState.cached_head,
      current,
      privateState.config,
      "physical resource arbiter store",
    );
    if (relation.code === "arbiter_cas_conflict" && isExactCommittedReplay(current, commit)) {
      privateState.cached_head = current;
      return commitReceipt(privateState, current, "reconciled_duplicate_commit");
    }
    if (relation.code !== "arbiter_cas_conflict") markAmbiguous(privateState);
    throw relation;
  }
  if (isExactCommittedReplay(current, commit)) {
    return commitReceipt(privateState, current, "reconciled_duplicate_commit");
  }
  if (!expectationMatchesHead(commit, current)) {
    if (commit.expected_generation > current.generation) {
      throw storeError("arbiter_expected_rollback", "commit expectation is ahead of the durable arbiter head");
    }
    if (commit.expected_generation < current.generation) {
      throw storeError("arbiter_stale_expectation", "commit expectation is stale and not an exact replay");
    }
    throw storeError("arbiter_expected_digest_drift", "commit expectation digests do not match the durable head");
  }

  const transition = transitionPhysicalResourceArbiter({
    config: privateState.config,
    state: current.state,
    queue: current.queue,
    commands: commit.commands,
  });
  if (transition.commands_digest !== commit.commands_digest) {
    throw storeError("arbiter_command_digest_drift", "normalized command digest drifted during transition");
  }
  const proposed = createTransitionHead(current, transition);
  let casResult = null;
  let casError = null;
  try {
    casResult = compareAndSetExternalHead(privateState.port, current, proposed);
  } catch (error) {
    casError = error;
  }
  return confirmProposedHead(privateState, current, proposed, casResult, casError);
}

function synchronizePhysicalResourceArbiterStoreUnguarded(store) {
  assertPhysicalResourceArbiterStore(store);
  const privateState = STORE_PRIVATE.get(store);
  assertStoreMutable(privateState);
  const observed = readExternalHead(privateState.port);
  if (observed === null) {
    markAmbiguous(privateState);
    throw storeError("arbiter_head_rollback", "physical resource arbiter journal head disappeared");
  }
  assertHeadBinding(observed, privateState);
  if (observed.head_digest === privateState.cached_head.head_digest) {
    return safeHeadProjection(privateState, observed);
  }
  if (observed.generation === privateState.cached_head.generation + 1
      && observed.prior_head_digest === privateState.cached_head.head_digest) {
    try {
      assertExactPhysicalResourceArbiterSuccessor(
        privateState.cached_head,
        observed,
        privateState.config,
        "physical resource arbiter synchronization successor",
      );
    } catch (cause) {
      markAmbiguous(privateState);
      throw storeError(
        "arbiter_head_fork",
        "physical resource arbiter synchronization observed an invalid direct successor",
        cause,
      );
    }
    privateState.cached_head = observed;
    return safeHeadProjection(privateState, observed);
  }
  const relation = relationError(
    privateState.cached_head,
    observed,
    privateState.config,
    "physical resource arbiter synchronization",
  );
  markAmbiguous(privateState);
  throw relation;
}

function commitPhysicalResourceArbiterTransition(store, input = {}) {
  assertPhysicalResourceArbiterStore(store);
  const privateState = STORE_PRIVATE.get(store);
  return withPhysicalResourceArbiterStoreOperation(privateState, "commit", () => (
    commitPhysicalResourceArbiterTransitionUnguarded(store, input)
  ));
}

function synchronizePhysicalResourceArbiterStore(store) {
  assertPhysicalResourceArbiterStore(store);
  const privateState = STORE_PRIVATE.get(store);
  return withPhysicalResourceArbiterStoreOperation(privateState, "synchronize", () => (
    synchronizePhysicalResourceArbiterStoreUnguarded(store)
  ));
}

function projectPhysicalResourceArbiterStore(store) {
  assertPhysicalResourceArbiterStore(store);
  const privateState = STORE_PRIVATE.get(store);
  return safeHeadProjection(privateState, privateState.cached_head);
}

function physicalResourceArbiterStoreReadiness(store) {
  assertPhysicalResourceArbiterStore(store);
  const privateState = STORE_PRIVATE.get(store);
  const capacity = capacityProjection(privateState.config, privateState.cached_head);
  return deepFreeze({
    version: RESOURCE_ARBITER_READINESS_VERSION,
    production_ready: false,
    production_attested: false,
    durability_assurance: RESOURCE_ARBITER_DURABILITY_ASSURANCE,
    observation_mode: "cached_last_confirmed_head",
    mutation_state: privateState.mutation_state,
    generation: privateState.cached_head.generation,
    head_digest: privateState.cached_head.head_digest,
    state_digest: privateState.cached_head.state.state_digest,
    queue_digest: privateState.cached_head.queue.queue_digest,
    capacity,
  });
}

function compactPhysicalResourceArbiterTombstones(store, input = {}) {
  assertPhysicalResourceArbiterStore(store);
  assertClosedObject(input, "physical_resource_arbiter_compaction", []);
  throw storeError(
    "arbiter_compaction_unavailable",
    "terminal tombstones cannot be deleted or request digests reused without a proof-preserving checkpoint contract",
  );
}

module.exports = {
  RESOURCE_ARBITER_CAS_EXPECTATION_VERSION,
  RESOURCE_ARBITER_COMMIT_RECEIPT_VERSION,
  RESOURCE_ARBITER_COMPACTION_CONTRACT,
  RESOURCE_ARBITER_COMPACTION_STATE,
  RESOURCE_ARBITER_DURABILITY_ASSURANCE,
  RESOURCE_ARBITER_JOURNAL_HEAD_VERSION,
  RESOURCE_ARBITER_READINESS_VERSION,
  RESOURCE_ARBITER_SAFE_PROJECTION_VERSION,
  RESOURCE_ARBITER_STATE_PORT_CONTRACT,
  RESOURCE_ARBITER_STATE_PORT_VERSION,
  RESOURCE_ARBITER_STORE_VERSION,
  assertPhysicalResourceArbiterStatePort,
  assertPhysicalResourceArbiterStore,
  commitPhysicalResourceArbiterTransition,
  compactPhysicalResourceArbiterTombstones,
  createPhysicalResourceArbiterStatePort,
  createPhysicalResourceArbiterStore,
  normalizePhysicalResourceArbiterDecision,
  normalizePhysicalResourceArbiterJournalHead,
  physicalResourceArbiterStoreReadiness,
  projectPhysicalResourceArbiterStore,
  synchronizePhysicalResourceArbiterStore,
};
