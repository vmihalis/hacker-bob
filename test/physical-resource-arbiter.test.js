"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
  PHYSICAL_RESOURCE_ARBITER_CONFIG_VERSION,
  PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION,
  PHYSICAL_RESOURCE_ARBITER_STATE_VERSION,
  PHYSICAL_RESOURCE_ARBITER_TRANSITION_VERSION,
  PHYSICAL_RESOURCE_QUEUE_TICKET_VERSION,
  initializePhysicalResourceArbiter,
  normalizePhysicalResourceArbiterConfig,
  normalizePhysicalResourceArbiterQueue,
  normalizePhysicalResourceArbiterState,
  normalizePhysicalResourceQueueTicket,
  transitionPhysicalResourceArbiter,
} = require("../mcp/lib/physical-resource-arbiter.js");
const {
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");

function digest(label) {
  return crypto.createHash("sha256").update(label).digest("hex");
}

function rawConfig(overrides = {}) {
  return {
    version: PHYSICAL_RESOURCE_ARBITER_CONFIG_VERSION,
    fairness_classes: ["alpha", "beta"],
    aging_threshold: 3,
    max_batch_size: 2,
    max_batch_burst: 4,
    max_queue_tickets: 128,
    ...overrides,
  };
}

function rawTicket(label, overrides = {}) {
  const ticketState = overrides.ticket_state || "ready";
  const ticket = {
    version: PHYSICAL_RESOURCE_QUEUE_TICKET_VERSION,
    reservation_request_digest: digest(`request:${label}`),
    resource_bundle_digest: digest(`bundle:${label}`),
    fairness_class: "alpha",
    batch_key: digest(`batch:${label}`),
    setup_cost_units: 10,
    enqueue_generation: 0,
    deferral_count: 0,
    ticket_state: ticketState,
    ...overrides,
  };
  if (["cancelled", "selected", "unschedulable"].includes(ticket.ticket_state)
      && ticket.terminal_generation == null) {
    ticket.terminal_generation = ticket.enqueue_generation;
  }
  return ticket;
}

function rawQueue(tickets) {
  return {
    version: PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION,
    tickets,
  };
}

function initialize(tickets, configOverrides = {}) {
  return initializePhysicalResourceArbiter({
    config: rawConfig(configOverrides),
    queue: rawQueue(tickets),
  });
}

function step(snapshot, commands = []) {
  return transitionPhysicalResourceArbiter({
    config: snapshot.config,
    state: snapshot.state,
    queue: snapshot.queue,
    commands,
  });
}

function advance(snapshot, commands = []) {
  const transition = step(snapshot, commands);
  return {
    config: snapshot.config,
    state: transition.next_state,
    queue: transition.next_queue,
    transition,
  };
}

function command(commandKind, reservationRequestDigest) {
  return {
    version: PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
    command_kind: commandKind,
    reservation_request_digest: reservationRequestDigest,
  };
}

function enqueue(ticket) {
  return {
    version: PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
    command_kind: "enqueue",
    ticket,
  };
}

function ticketByLabel(snapshot, label) {
  const requestDigest = digest(`request:${label}`);
  return snapshot.queue.tickets.find((ticket) => ticket.reservation_request_digest === requestDigest);
}

test("arbiter config is closed, sorted, hash-bound, and has an explicit burst ceiling", () => {
  const config = normalizePhysicalResourceArbiterConfig(rawConfig({
    fairness_classes: ["beta", "alpha"],
  }));
  assert.deepEqual(config.fairness_classes, ["alpha", "beta"]);
  assert.deepEqual(config, normalizePhysicalResourceArbiterConfig(config));
  assert.ok(Object.isFrozen(config));
  assert.throws(() => normalizePhysicalResourceArbiterConfig({
    ...config,
    aging_threshold: 4,
  }), /config_digest does not match/);
  assert.throws(() => normalizePhysicalResourceArbiterConfig(rawConfig({
    max_batch_size: 5,
    max_batch_burst: 4,
  })), /cannot exceed max_batch_burst/);
  assert.throws(() => normalizePhysicalResourceArbiterConfig({
    ...rawConfig(),
    priority_weights: { alpha: 100 },
  }), /unknown fields: priority_weights/);
  assert.throws(() => normalizePhysicalResourceArbiterConfig(rawConfig({
    fairness_classes: ["alpha", "alpha"],
  })), /must not contain duplicates/);
});

test("queue tickets bind only opaque request, bundle, class, batch, cost, and broker age coordinates", () => {
  const ticket = normalizePhysicalResourceQueueTicket(rawTicket("closed"));
  assert.equal(ticket.ticket_digest, hashCanonicalJson({
    version: ticket.version,
    reservation_request_digest: ticket.reservation_request_digest,
    resource_bundle_digest: ticket.resource_bundle_digest,
    fairness_class: ticket.fairness_class,
    batch_key: ticket.batch_key,
    setup_cost_units: ticket.setup_cost_units,
    enqueue_generation: ticket.enqueue_generation,
    deferral_count: ticket.deferral_count,
    ticket_state: ticket.ticket_state,
  }));
  assert.deepEqual(ticket, normalizePhysicalResourceQueueTicket(ticket));
  assert.ok(Object.isFrozen(ticket));
  for (const forbidden of ["priority", "enqueued_at", "raw_inventory", "fencing_token"]) {
    assert.throws(() => normalizePhysicalResourceQueueTicket({
      ...rawTicket("closed"),
      [forbidden]: "caller-controlled",
    }), new RegExp(`unknown fields: ${forbidden}`));
  }
  assert.throws(() => normalizePhysicalResourceQueueTicket({
    ...ticket,
    setup_cost_units: 11,
  }), /ticket_digest does not match/);
  assert.throws(() => normalizePhysicalResourceQueueTicket(rawTicket("bad-batch", {
    batch_key: "fast",
  })), /batch_key must be a lowercase SHA-256 digest/);
  assert.throws(() => normalizePhysicalResourceQueueTicket({
    ...rawTicket("active-terminal"),
    terminal_generation: 0,
  }), /unknown fields: terminal_generation/);
});

test("ticket variant selection does not execute getters and arrays reject holes or adornments", () => {
  let getterCalled = false;
  const hostile = rawTicket("getter");
  Object.defineProperty(hostile, "ticket_state", {
    enumerable: true,
    get() {
      getterCalled = true;
      return "ready";
    },
  });
  assert.throws(() => normalizePhysicalResourceQueueTicket(hostile), /must be an enumerable data field/);
  assert.equal(getterCalled, false);

  const sparse = [];
  sparse.length = 1;
  assert.throws(() => normalizePhysicalResourceArbiterQueue(rawQueue(sparse)), /tickets\[0\].*data field/);
  const adorned = [rawTicket("adorned")];
  adorned.priority = "first";
  assert.throws(() => normalizePhysicalResourceArbiterQueue(rawQueue(adorned)), /extra or symbol fields/);
});

test("queue normalization sorts by request digest and rejects request or ticket duplication", () => {
  const first = rawTicket("queue-a");
  const second = rawTicket("queue-b");
  const queue = normalizePhysicalResourceArbiterQueue(rawQueue([second, first]));
  assert.deepEqual(queue.tickets.map((ticket) => ticket.reservation_request_digest), [
    first.reservation_request_digest,
    second.reservation_request_digest,
  ].sort());
  assert.deepEqual(queue, normalizePhysicalResourceArbiterQueue(queue));
  assert.throws(() => normalizePhysicalResourceArbiterQueue(rawQueue([first, {
    ...second,
    reservation_request_digest: first.reservation_request_digest,
  }])), /duplicate reservation requests/);
});

test("initial state binds the exact config and queue with closed per-class batch cursors", () => {
  const initialized = initialize([
    rawTicket("init-ready"),
    rawTicket("init-blocked", { ticket_state: "blocked", fairness_class: "beta" }),
  ]);
  assert.equal(initialized.state.generation, 0);
  assert.equal(initialized.state.config_digest, initialized.config.config_digest);
  assert.equal(initialized.state.queue_digest, initialized.queue.queue_digest);
  assert.deepEqual(initialized.state.class_batch_cursors, [
    { fairness_class: "alpha", last_batch_key: null },
    { fairness_class: "beta", last_batch_key: null },
  ]);
  assert.equal(initialized.initialization_digest, hashCanonicalJson({
    version: initialized.version,
    config: initialized.config,
    queue: initialized.queue,
    state: initialized.state,
  }));
  assert.throws(() => initialize([rawTicket("unregistered", {
    fairness_class: "urgent",
  })]), /not registered by config/);
  assert.throws(() => initialize([rawTicket("pre-aged", {
    deferral_count: 1,
  })]), /must start at generation and deferral zero/);
  assert.throws(() => initialize([rawTicket("pre-terminal", {
    ticket_state: "cancelled",
  })]), /only initialize active tickets/);
});

test("exact repeat inputs produce byte-identical, canonically bound decisions and transitions", () => {
  const initialized = initialize([
    rawTicket("repeat-a"),
    rawTicket("repeat-b", { fairness_class: "beta" }),
  ]);
  const left = step(initialized);
  const right = step(initialized);
  assert.deepEqual(left, right);
  assert.equal(JSON.stringify(left), JSON.stringify(right));
  const transitionValue = { ...left };
  delete transitionValue.transition_digest;
  assert.equal(left.transition_digest, hashCanonicalJson(transitionValue));
  const decisionValue = { ...left.decision };
  delete decisionValue.decision_digest;
  assert.equal(left.decision.decision_digest, hashCanonicalJson(decisionValue));
  assert.equal(left.next_state.previous_state_digest, initialized.state.state_digest);
  assert.equal(left.next_state.applied_input_digest, left.input_digest);
});

test("blocked tickets receive no age credit and an idle cell does not advance round robin", () => {
  const initialized = initialize([
    rawTicket("blocked-only", { ticket_state: "blocked" }),
  ]);
  const idle = advance(initialized);
  assert.equal(idle.transition.decision.disposition, "idle");
  assert.equal(idle.state.last_served_fairness_class, null);
  assert.equal(ticketByLabel(idle, "blocked-only").deferral_count, 0);
  assert.deepEqual(idle.transition.decision.blocked_without_credit_ticket_digests, [
    ticketByLabel(idle, "blocked-only").ticket_digest,
  ]);

  const ready = advance(idle, [command("mark_ready", digest("request:blocked-only"))]);
  assert.equal(ready.transition.decision.disposition, "selected");
  assert.equal(ticketByLabel(ready, "blocked-only").ticket_state, "selected");
});

test("cancellation and unschedulable terminal tickets are permanent tombstones, not fairness credit", () => {
  const initialized = initialize([
    rawTicket("cancel-me", { ticket_state: "blocked" }),
    rawTicket("impossible", { ticket_state: "blocked", fairness_class: "beta" }),
  ]);
  const terminal = advance(initialized, [
    command("mark_unschedulable", digest("request:impossible")),
    command("cancel", digest("request:cancel-me")),
  ]);
  assert.equal(terminal.transition.decision.disposition, "idle");
  assert.equal(terminal.state.last_served_fairness_class, null);
  assert.equal(ticketByLabel(terminal, "cancel-me").ticket_state, "cancelled");
  assert.equal(ticketByLabel(terminal, "impossible").ticket_state, "unschedulable");
  assert.equal(ticketByLabel(terminal, "impossible").deferral_count, 0);
  assert.deepEqual(terminal.transition.decision.unschedulable_without_credit_ticket_digests, [
    ticketByLabel(terminal, "impossible").ticket_digest,
  ]);
  assert.throws(() => step(terminal, [command("mark_ready", digest("request:impossible"))]), /terminal/);
  assert.throws(() => step(terminal, [enqueue(rawTicket("impossible", {
    enqueue_generation: 2,
  }))]), /duplicate or terminal/);
});

test("one selection terminalizes the exact ticket and old active queues cannot be replayed", () => {
  const initialized = initialize([rawTicket("select-once")]);
  const selected = advance(initialized);
  const terminal = ticketByLabel(selected, "select-once");
  assert.equal(terminal.ticket_state, "selected");
  assert.equal(terminal.terminal_generation, 1);
  assert.deepEqual(selected.transition.decision.selected_ticket_digests, [
    initialized.queue.tickets[0].ticket_digest,
  ]);
  assert.throws(() => transitionPhysicalResourceArbiter({
    config: selected.config,
    state: selected.state,
    queue: initialized.queue,
    commands: [],
  }), /does not bind the exact input queue/);
  const later = advance(selected);
  assert.equal(ticketByLabel(later, "select-once").ticket_state, "selected");
  assert.equal(ticketByLabel(later, "select-once").deferral_count, 0);
});

test("a batch selects only exact compatible batch keys", () => {
  const compatibleKey = digest("batch:compatible");
  const initialized = initialize([
    rawTicket("compatible-a", { batch_key: compatibleKey, setup_cost_units: 0 }),
    rawTicket("compatible-b", { batch_key: compatibleKey, setup_cost_units: 0 }),
    rawTicket("incompatible", { batch_key: digest("batch:incompatible"), setup_cost_units: 50 }),
  ], {
    fairness_classes: ["alpha"],
    max_batch_size: 3,
    max_batch_burst: 3,
  });
  const transition = step(initialized);
  assert.deepEqual(new Set(transition.decision.selected_reservation_request_digests), new Set([
    digest("request:compatible-a"),
    digest("request:compatible-b"),
  ]));
  assert.equal(transition.decision.batch_key, compatibleKey);
  assert.equal(transition.decision.deferrals.length, 1);
  assert.equal(transition.decision.deferrals[0].reservation_request_digest, digest("request:incompatible"));
});

test("same-batch reuse is bounded before round robin serves another fairness class", () => {
  const alphaBatch = digest("batch:alpha-burst");
  const initialized = initialize([
    ...Array.from({ length: 5 }, (_, index) => rawTicket(`burst-alpha-${index}`, {
      fairness_class: "alpha",
      batch_key: alphaBatch,
    })),
    rawTicket("burst-beta", { fairness_class: "beta" }),
  ], {
    max_batch_size: 2,
    max_batch_burst: 3,
    aging_threshold: 100,
  });
  const first = advance(initialized);
  assert.equal(first.transition.decision.fairness_class, "alpha");
  assert.equal(first.transition.decision.selected_ticket_digests.length, 2);
  const second = advance(first);
  assert.equal(second.transition.decision.fairness_class, "alpha");
  assert.equal(second.transition.decision.continued_batch, true);
  assert.equal(second.transition.decision.selected_ticket_digests.length, 1);
  assert.equal(second.state.active_batch, null);
  const third = advance(second);
  assert.equal(third.transition.decision.fairness_class, "beta");
  assert.deepEqual(third.transition.decision.selected_reservation_request_digests, [
    digest("request:burst-beta"),
  ]);
});

test("per-class batch cursors stop a cheap compatible batch from resetting its burst", () => {
  const cheapBatch = digest("batch:cheap");
  const costlyBatch = digest("batch:costly");
  const initialized = initialize([
    ...Array.from({ length: 4 }, (_, index) => rawTicket(`cheap-${index}`, {
      batch_key: cheapBatch,
      setup_cost_units: 0,
    })),
    rawTicket("costly", { batch_key: costlyBatch, setup_cost_units: 1_000 }),
  ], {
    fairness_classes: ["alpha"],
    aging_threshold: 100,
    max_batch_size: 1,
    max_batch_burst: 2,
  });
  const first = advance(initialized);
  const second = advance(first);
  assert.equal(first.transition.decision.batch_key, cheapBatch);
  assert.equal(second.transition.decision.batch_key, cheapBatch);
  assert.equal(second.state.active_batch, null);
  const third = advance(second);
  assert.equal(third.transition.decision.batch_key, costlyBatch);
  assert.deepEqual(third.transition.decision.selected_reservation_request_digests, [
    digest("request:costly"),
  ]);
});

test("aging interrupts an otherwise reusable batch and serves the deferred batch", () => {
  const cheapBatch = digest("batch:aged-cheap");
  const agedBatch = digest("batch:aged-costly");
  const initialized = initialize([
    ...Array.from({ length: 3 }, (_, index) => rawTicket(`aged-cheap-${index}`, {
      batch_key: cheapBatch,
      setup_cost_units: 0,
    })),
    rawTicket("aged-costly", { batch_key: agedBatch, setup_cost_units: 1_000 }),
  ], {
    fairness_classes: ["alpha"],
    aging_threshold: 1,
    max_batch_size: 1,
    max_batch_burst: 4,
  });
  const first = advance(initialized);
  assert.equal(first.state.active_batch.batch_key, cheapBatch);
  const second = advance(first);
  assert.equal(second.transition.decision.continued_batch, false);
  assert.equal(second.transition.decision.batch_key, agedBatch);
  assert.deepEqual(second.transition.decision.selected_reservation_request_digests, [
    digest("request:aged-costly"),
  ]);
});

test("broker-owned age outranks a newly enqueued low-setup request", () => {
  const initialized = initialize([
    rawTicket("age-alpha-dummy", { setup_cost_units: 0 }),
    rawTicket("age-alpha-old", {
      batch_key: digest("batch:age-old"),
      setup_cost_units: 1_000,
    }),
    rawTicket("age-beta", { fairness_class: "beta" }),
  ], {
    aging_threshold: 1,
    max_batch_size: 1,
    max_batch_burst: 1,
  });
  const first = advance(initialized);
  assert.deepEqual(first.transition.decision.selected_reservation_request_digests, [
    digest("request:age-alpha-dummy"),
  ]);
  const second = advance(first, [enqueue(rawTicket("age-alpha-new", {
    setup_cost_units: 0,
    enqueue_generation: 2,
  }))]);
  assert.equal(second.transition.decision.fairness_class, "beta");
  assert.equal(ticketByLabel(second, "age-alpha-old").deferral_count, 2);
  assert.equal(ticketByLabel(second, "age-alpha-new").deferral_count, 1);
  const third = advance(second);
  assert.deepEqual(third.transition.decision.selected_reservation_request_digests, [
    digest("request:age-alpha-old"),
  ]);
});

test("command order cannot act as priority and one request cannot occupy two command cells", () => {
  const initialized = initialize([
    rawTicket("order-a", { ticket_state: "blocked" }),
    rawTicket("order-b", { ticket_state: "blocked" }),
  ], {
    fairness_classes: ["alpha"],
    max_batch_size: 1,
    max_batch_burst: 1,
  });
  const leftCommands = [
    command("mark_ready", digest("request:order-a")),
    command("mark_ready", digest("request:order-b")),
  ];
  const rightCommands = leftCommands.slice().reverse();
  assert.deepEqual(step(initialized, leftCommands), step(initialized, rightCommands));
  assert.throws(() => step(initialized, [
    command("mark_ready", digest("request:order-a")),
    command("cancel", digest("request:order-a")),
  ]), /must not mutate one reservation request more than once/);
  assert.throws(() => step(initialized, [{
    ...command("mark_ready", digest("request:order-a")),
    priority: "urgent",
  }]), /unknown fields: priority/);
});

test("enqueue generation and deferral coordinates cannot be forged by callers", () => {
  const initialized = initialize([]);
  assert.throws(() => step(initialized, [enqueue(rawTicket("wrong-generation", {
    enqueue_generation: 0,
  }))]), /must use the next generation and zero deferrals/);
  assert.throws(() => step(initialized, [enqueue(rawTicket("pre-aged-enqueue", {
    enqueue_generation: 1,
    deferral_count: 1,
  }))]), /must use the next generation and zero deferrals/);
  assert.throws(() => step(initialized, [enqueue(rawTicket("urgent-class", {
    fairness_class: "urgent",
    enqueue_generation: 1,
  }))]), /not registered by config/);
  assert.throws(() => step(initialized, [enqueue({
    ...rawTicket("timestamp", { enqueue_generation: 1 }),
    enqueued_at: "1970-01-01T00:00:00.000Z",
  })]), /unknown fields: enqueued_at/);
});

test("state validation rejects unreachable age even when caller recomputes unkeyed digests", () => {
  const initialized = initialize([rawTicket("unreachable")]);
  const forgedQueue = normalizePhysicalResourceArbiterQueue(rawQueue([
    rawTicket("unreachable", { deferral_count: 1 }),
  ]));
  const stateValue = { ...initialized.state };
  delete stateValue.state_digest;
  stateValue.queue_digest = forgedQueue.queue_digest;
  const forgedState = normalizePhysicalResourceArbiterState(stateValue);
  assert.throws(() => transitionPhysicalResourceArbiter({
    config: initialized.config,
    state: forgedState,
    queue: forgedQueue,
    commands: [],
  }), /deferral count is not reachable/);
});

test("active setup reuse must match durable cursor progress and a ready continuation", () => {
  const sharedBatch = digest("batch:active-invariant");
  const initialized = initialize([
    rawTicket("active-a", { batch_key: sharedBatch }),
    rawTicket("active-b", { batch_key: sharedBatch }),
  ], {
    fairness_classes: ["alpha"],
    max_batch_size: 1,
    max_batch_burst: 2,
  });
  const first = advance(initialized);
  assert.equal(first.state.active_batch.batch_key, sharedBatch);
  const forgedValue = { ...first.state };
  delete forgedValue.state_digest;
  forgedValue.class_batch_cursors = [{
    fairness_class: "alpha",
    last_batch_key: digest("batch:unrelated"),
  }];
  const forgedState = normalizePhysicalResourceArbiterState(forgedValue);
  assert.throws(() => transitionPhysicalResourceArbiter({
    config: first.config,
    state: forgedState,
    queue: first.queue,
    commands: [],
  }), /active batch must match its durable class batch cursor/);
});

test("config and queue drift fail before ordering and outputs contain no resource authority material", () => {
  const initialized = initialize([rawTicket("binding")]);
  const driftedConfig = normalizePhysicalResourceArbiterConfig(rawConfig({ aging_threshold: 4 }));
  assert.throws(() => transitionPhysicalResourceArbiter({
    config: driftedConfig,
    state: initialized.state,
    queue: initialized.queue,
    commands: [],
  }), /does not bind the exact arbiter config/);
  const emptyQueue = normalizePhysicalResourceArbiterQueue(rawQueue([]));
  assert.throws(() => transitionPhysicalResourceArbiter({
    config: initialized.config,
    state: initialized.state,
    queue: emptyQueue,
    commands: [],
  }), /does not bind the exact input queue/);
  const transition = step(initialized);
  const serialized = JSON.stringify(transition);
  for (const forbidden of ["raw_inventory", "fencing_token", "resource_allocation", "device_handle"]) {
    assert.equal(serialized.includes(forbidden), false);
  }
  assert.equal(transition.version, PHYSICAL_RESOURCE_ARBITER_TRANSITION_VERSION);
  assert.equal(transition.next_state.version, PHYSICAL_RESOURCE_ARBITER_STATE_VERSION);
});
