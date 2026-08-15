"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
  PHYSICAL_RESOURCE_ARBITER_CONFIG_VERSION,
  PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION,
  PHYSICAL_RESOURCE_ARBITER_TRANSITION_VERSION,
  PHYSICAL_RESOURCE_QUEUE_TICKET_VERSION,
  initializePhysicalResourceArbiter,
  normalizePhysicalResourceArbiterQueue,
  normalizePhysicalResourceArbiterState,
  normalizePhysicalResourceQueueTicket,
  transitionPhysicalResourceArbiter,
} = require("../../../mcp/domains/physical/physical-resource-arbiter.js");
const {
  RESOURCE_ARBITER_COMPACTION_CONTRACT,
  RESOURCE_ARBITER_DURABILITY_ASSURANCE,
  RESOURCE_ARBITER_JOURNAL_HEAD_VERSION,
  assertPhysicalResourceArbiterStatePort,
  commitPhysicalResourceArbiterTransition,
  compactPhysicalResourceArbiterTombstones,
  createPhysicalResourceArbiterStatePort,
  createPhysicalResourceArbiterStore,
  normalizePhysicalResourceArbiterDecision,
  normalizePhysicalResourceArbiterJournalHead,
  physicalResourceArbiterStoreReadiness,
  projectPhysicalResourceArbiterStore,
  synchronizePhysicalResourceArbiterStore,
} = require("../lib/resource-arbiter-store.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

function digest(label) {
  return crypto.createHash("sha256").update(label).digest("hex");
}

function clone(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function rawConfig(overrides = {}) {
  return {
    version: PHYSICAL_RESOURCE_ARBITER_CONFIG_VERSION,
    fairness_classes: ["alpha", "beta"],
    aging_threshold: 2,
    max_batch_size: 1,
    max_batch_burst: 2,
    max_queue_tickets: 32,
    ...overrides,
  };
}

function rawTicket(label, overrides = {}) {
  return {
    version: PHYSICAL_RESOURCE_QUEUE_TICKET_VERSION,
    reservation_request_digest: digest(`request:${label}`),
    resource_bundle_digest: digest(`bundle:${label}`),
    fairness_class: "alpha",
    batch_key: digest(`batch:${label}`),
    setup_cost_units: 10,
    enqueue_generation: 0,
    deferral_count: 0,
    ticket_state: "blocked",
    ...overrides,
  };
}

function rawQueue(tickets) {
  return {
    version: PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION,
    tickets,
  };
}

function command(kind, label) {
  return {
    version: PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
    command_kind: kind,
    reservation_request_digest: digest(`request:${label}`),
  };
}

function enqueueCommand(ticket) {
  return {
    version: PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
    command_kind: "enqueue",
    ticket,
  };
}

function createBackend() {
  const backend = {
    head: null,
    calls: { read: 0, cas: 0 },
    falseNext: false,
    throwBeforeNext: false,
    commitThenThrowNext: false,
    returnPromiseNext: false,
    trueWithoutCommitNext: false,
    throwReadNext: false,
    throwReadAfterNextCas: false,
    beforeNextRead: null,
    beforeNextCas: null,
    returnRaw: false,
    lastExpected: null,
    lastNext: null,
  };
  backend.read = () => {
    backend.calls.read += 1;
    if (backend.beforeNextRead) {
      const hook = backend.beforeNextRead;
      backend.beforeNextRead = null;
      hook();
    }
    if (backend.throwReadNext) {
      backend.throwReadNext = false;
      throw new Error("read outage");
    }
    return backend.returnRaw ? backend.head : clone(backend.head);
  };
  backend.cas = (expected, next) => {
    backend.calls.cas += 1;
    backend.lastExpected = clone(expected);
    backend.lastNext = clone(next);
    if (backend.beforeNextCas) {
      const hook = backend.beforeNextCas;
      backend.beforeNextCas = null;
      hook();
    }
    if (backend.throwBeforeNext) {
      backend.throwBeforeNext = false;
      throw new Error("CAS outage before commit");
    }
    const matches = expected === null
      ? backend.head === null
      : backend.head != null
        && expected.generation === backend.head.generation
        && expected.head_digest === backend.head.head_digest
        && expected.state_digest === backend.head.state.state_digest
        && expected.queue_digest === backend.head.queue.queue_digest
        && expected.config_digest === backend.head.config_digest;
    if (backend.returnPromiseNext) {
      backend.returnPromiseNext = false;
      return Promise.resolve(false);
    }
    if (backend.falseNext) {
      backend.falseNext = false;
      return false;
    }
    if (!matches) return false;
    if (backend.trueWithoutCommitNext) {
      backend.trueWithoutCommitNext = false;
      return true;
    }
    backend.head = clone(next);
    if (backend.throwReadAfterNextCas) {
      backend.throwReadAfterNextCas = false;
      backend.throwReadNext = true;
    }
    if (backend.commitThenThrowNext) {
      backend.commitThenThrowNext = false;
      throw new Error("response lost after commit");
    }
    return true;
  };
  return backend;
}

function createPort(backend, label = "default", domain = digest("arbiter-domain")) {
  return createPhysicalResourceArbiterStatePort({
    port_id: `arbiter-${label}`,
    journal_domain_digest: domain,
    read_head: backend.read,
    compare_and_set: backend.cas,
  });
}

function createFixture(options = {}) {
  const backend = options.backend || createBackend();
  const config = rawConfig(options.config || {});
  const queue = rawQueue(options.tickets || [
    rawTicket("a"),
    rawTicket("b", { fairness_class: "beta" }),
  ]);
  const port = createPort(backend, options.label || "fixture", options.domain);
  const store = createPhysicalResourceArbiterStore({ state_port: port, config, queue });
  return { backend, config, queue, port, store };
}

function commitInput(store, commands = []) {
  const projection = projectPhysicalResourceArbiterStore(store);
  return {
    expected_generation: projection.generation,
    expected_head_digest: projection.head_digest,
    expected_state_digest: projection.state_digest,
    expected_queue_digest: projection.queue_digest,
    commands,
  };
}

function headFromTransition(predecessor, transition) {
  return normalizePhysicalResourceArbiterJournalHead({
    version: RESOURCE_ARBITER_JOURNAL_HEAD_VERSION,
    journal_domain_digest: predecessor.journal_domain_digest,
    initialization_digest: predecessor.initialization_digest,
    config_digest: transition.config_digest,
    generation: transition.next_state.generation,
    prior_head_digest: predecessor.head_digest,
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

test("private synchronous state port hides callbacks and admits no public lookalike", () => {
  const backend = createBackend();
  const port = createPort(backend, "brand");
  assert.equal(assertPhysicalResourceArbiterStatePort(port), port);
  assert.equal(port.production_attested, false);
  assert.equal(port.durability_assurance, RESOURCE_ARBITER_DURABILITY_ASSURANCE);
  assert.equal("read_head" in port, false);
  assert.equal("compare_and_set" in port, false);
  assert.throws(() => assertPhysicalResourceArbiterStatePort({ ...port }), /private factory/);

  let getterCalled = false;
  const hostile = {
    port_id: "arbiter-hostile",
    journal_domain_digest: digest("hostile"),
    compare_and_set() {},
  };
  Object.defineProperty(hostile, "read_head", {
    enumerable: true,
    get() {
      getterCalled = true;
      return () => null;
    },
  });
  assert.throws(() => createPhysicalResourceArbiterStatePort(hostile), /enumerable data field/);
  assert.equal(getterCalled, false);
});

test("genesis is atomically published and exact lost genesis responses reconcile", () => {
  {
    const fx = createFixture();
    const projection = projectPhysicalResourceArbiterStore(fx.store);
    assert.equal(projection.generation, 0);
    assert.equal(fx.backend.calls.cas, 1);
    assert.equal(fx.backend.head.head_digest, projection.head_digest);
    assert.equal(fx.backend.head.state.state_digest, projection.state_digest);
    assert.equal(fx.backend.head.queue.queue_digest, projection.queue_digest);
  }
  {
    const backend = createBackend();
    backend.commitThenThrowNext = true;
    const fx = createFixture({ backend, label: "lost-genesis" });
    assert.equal(projectPhysicalResourceArbiterStore(fx.store).generation, 0);
    assert.equal(backend.calls.cas, 1);
  }
});

test("a genesis contender can attach to one directly verified concurrent successor", () => {
  const backend = createBackend();
  const config = rawConfig({ fairness_classes: ["alpha"] });
  const queue = rawQueue([rawTicket("genesis-race", { ticket_state: "ready" })]);
  let innerReceipt = null;
  backend.beforeNextCas = () => {
    const inner = createPhysicalResourceArbiterStore({
      state_port: createPort(backend, "genesis-inner"),
      config,
      queue,
    });
    innerReceipt = commitPhysicalResourceArbiterTransition(inner, commitInput(inner));
  };
  const outer = createPhysicalResourceArbiterStore({
    state_port: createPort(backend, "genesis-outer"),
    config,
    queue,
  });
  assert.equal(innerReceipt.generation, 1);
  assert.equal(projectPhysicalResourceArbiterStore(outer).head_digest, innerReceipt.head_digest);
});

test("a selection returns only after state, queue, and decision share one committed head", () => {
  const fx = createFixture();
  const input = commitInput(fx.store, [command("mark_ready", "a")]);
  const receipt = commitPhysicalResourceArbiterTransition(fx.store, input);
  assert.equal(receipt.commit_status, "committed");
  assert.equal(receipt.generation, 1);
  assert.deepEqual(receipt.selected_reservation_request_digests, [digest("request:a")]);
  assert.equal(fx.backend.head.head_digest, receipt.head_digest);
  assert.equal(fx.backend.head.state.state_digest, receipt.state_digest);
  assert.equal(fx.backend.head.queue.queue_digest, receipt.queue_digest);
  assert.equal(fx.backend.head.decision.decision_digest, receipt.decision_digest);
  assert.equal(fx.backend.head.transition_digest, receipt.transition_digest);
  assert.equal(fx.backend.head.decision.disposition, "selected");
  assert.deepEqual(fx.backend.lastExpected, {
    version: 1,
    journal_domain_digest: fx.backend.head.journal_domain_digest,
    config_digest: fx.store.config_digest,
    generation: input.expected_generation,
    head_digest: input.expected_head_digest,
    state_digest: input.expected_state_digest,
    queue_digest: input.expected_queue_digest,
  });
  assert.equal(fx.backend.lastNext.state.state_digest, receipt.state_digest);
  assert.equal(fx.backend.lastNext.queue.queue_digest, receipt.queue_digest);
  assert.equal(fx.backend.lastNext.decision.decision_digest, receipt.decision_digest);
});

test("response loss after an exact commit is reconciled idempotently", () => {
  const fx = createFixture();
  const input = commitInput(fx.store, [command("mark_ready", "a")]);
  fx.backend.commitThenThrowNext = true;
  const receipt = commitPhysicalResourceArbiterTransition(fx.store, input);
  assert.equal(receipt.commit_status, "reconciled_response_loss");
  assert.deepEqual(receipt.selected_reservation_request_digests, [digest("request:a")]);
  assert.equal(fx.backend.head.head_digest, receipt.head_digest);

  const duplicate = commitPhysicalResourceArbiterTransition(fx.store, input);
  assert.equal(duplicate.commit_status, "reconciled_duplicate_commit");
  assert.equal(duplicate.head_digest, receipt.head_digest);
  assert.deepEqual(duplicate.selected_ticket_digests, receipt.selected_ticket_digests);
});

test("cached ancestry is proven before duplicate replay can be reconciled", () => {
  const fx = createFixture({ label: "replay-ancestry" });
  const cachedGenesis = clone(fx.backend.head);
  const alternate = initializePhysicalResourceArbiter({
    config: fx.config,
    queue: rawQueue([
      rawTicket("a", { setup_cost_units: 11 }),
      rawTicket("b", { fairness_class: "beta" }),
    ]),
  });
  const commands = [command("mark_ready", "a")];
  const alternateTransition = transitionPhysicalResourceArbiter({
    config: alternate.config,
    state: alternate.state,
    queue: alternate.queue,
    commands,
  });
  fx.backend.head = clone(headFromTransition(cachedGenesis, alternateTransition));

  assert.throws(
    () => commitPhysicalResourceArbiterTransition(fx.store, {
      expected_generation: 0,
      expected_head_digest: cachedGenesis.head_digest,
      expected_state_digest: alternate.state.state_digest,
      expected_queue_digest: alternate.queue.queue_digest,
      commands,
    }),
    (error) => error.code === "arbiter_head_fork"
      && error.cause?.code === "arbiter_head_successor_invalid",
  );
  assert.equal(
    physicalResourceArbiterStoreReadiness(fx.store).mutation_state,
    "ambiguous_fail_closed",
  );
});

test("two contenders produce one CAS winner and a definitive conflicting loser", () => {
  const backend = createBackend();
  const config = rawConfig();
  const queue = rawQueue([
    rawTicket("a"),
    rawTicket("b", { fairness_class: "beta" }),
  ]);
  const winnerStore = createPhysicalResourceArbiterStore({
    state_port: createPort(backend, "winner"),
    config,
    queue,
  });
  const loserStore = createPhysicalResourceArbiterStore({
    state_port: createPort(backend, "loser"),
    config,
    queue,
  });
  const winnerInput = commitInput(winnerStore, [command("mark_ready", "a")]);
  const loserInput = commitInput(loserStore, [command("mark_ready", "b")]);
  let winnerReceipt = null;
  backend.beforeNextCas = () => {
    winnerReceipt = commitPhysicalResourceArbiterTransition(winnerStore, winnerInput);
  };
  assert.throws(
    () => commitPhysicalResourceArbiterTransition(loserStore, loserInput),
    (error) => error.code === "arbiter_cas_conflict",
  );
  assert.equal(winnerReceipt.commit_status, "committed");
  assert.equal(backend.head.head_digest, winnerReceipt.head_digest);
  assert.deepEqual(backend.head.decision.selected_reservation_request_digests, [digest("request:a")]);
});

test("an identical contender reconciles the winner instead of replaying its command", () => {
  const backend = createBackend();
  const config = rawConfig();
  const queue = rawQueue([rawTicket("a")]);
  const first = createPhysicalResourceArbiterStore({
    state_port: createPort(backend, "same-a"), config, queue,
  });
  const second = createPhysicalResourceArbiterStore({
    state_port: createPort(backend, "same-b"), config, queue,
  });
  const firstInput = commitInput(first, [command("mark_ready", "a")]);
  const secondInput = commitInput(second, [command("mark_ready", "a")]);
  const committed = commitPhysicalResourceArbiterTransition(first, firstInput);
  const reconciled = commitPhysicalResourceArbiterTransition(second, secondInput);
  assert.equal(reconciled.commit_status, "reconciled_duplicate_commit");
  assert.equal(reconciled.head_digest, committed.head_digest);
  assert.equal(backend.calls.cas, 2, "one genesis CAS plus one transition CAS");
});

test("throw-before-commit is retryable after exact readback while read outage performs no CAS", () => {
  const fx = createFixture();
  const input = commitInput(fx.store, [command("mark_ready", "a")]);
  fx.backend.throwBeforeNext = true;
  assert.throws(
    () => commitPhysicalResourceArbiterTransition(fx.store, input),
    (error) => error.code === "arbiter_state_unavailable",
  );
  assert.equal(projectPhysicalResourceArbiterStore(fx.store).generation, 0);
  const retried = commitPhysicalResourceArbiterTransition(fx.store, input);
  assert.equal(retried.commit_status, "committed");

  const fx2 = createFixture({ label: "read-outage" });
  const casCalls = fx2.backend.calls.cas;
  fx2.backend.throwReadNext = true;
  assert.throws(
    () => commitPhysicalResourceArbiterTransition(
      fx2.store,
      commitInput(fx2.store, [command("mark_ready", "a")]),
    ),
    (error) => error.code === "arbiter_state_unavailable",
  );
  assert.equal(fx2.backend.calls.cas, casCalls);
});

test("unreconciled CAS success or contradictory false becomes sticky ambiguous fail-closed", () => {
  {
    const fx = createFixture();
    fx.backend.throwReadAfterNextCas = true;
    assert.throws(
      () => commitPhysicalResourceArbiterTransition(
        fx.store,
        commitInput(fx.store, [command("mark_ready", "a")]),
      ),
      (error) => error.code === "arbiter_state_ambiguous",
    );
    assert.equal(physicalResourceArbiterStoreReadiness(fx.store).mutation_state, "ambiguous_fail_closed");
    assert.throws(
      () => commitPhysicalResourceArbiterTransition(fx.store, commitInput(fx.store)),
      (error) => error.code === "arbiter_state_ambiguous",
    );
  }
  {
    const fx = createFixture({ label: "false" });
    fx.backend.falseNext = true;
    assert.throws(
      () => commitPhysicalResourceArbiterTransition(
        fx.store,
        commitInput(fx.store, [command("mark_ready", "a")]),
      ),
      (error) => error.code === "arbiter_port_contract_violation",
    );
    assert.equal(physicalResourceArbiterStoreReadiness(fx.store).mutation_state, "ambiguous_fail_closed");
  }
  {
    const fx = createFixture({ label: "lying-true" });
    fx.backend.trueWithoutCommitNext = true;
    assert.throws(
      () => commitPhysicalResourceArbiterTransition(
        fx.store,
        commitInput(fx.store, [command("mark_ready", "a")]),
      ),
      (error) => error.code === "arbiter_port_contract_violation",
    );
  }
});

test("stale expectations and digest drift cannot be silently rebased", () => {
  const fx = createFixture();
  const old = commitInput(fx.store, [command("mark_ready", "a")]);
  commitPhysicalResourceArbiterTransition(fx.store, old);
  assert.throws(
    () => commitPhysicalResourceArbiterTransition(fx.store, {
      ...old,
      commands: [],
    }),
    (error) => error.code === "arbiter_stale_expectation",
  );
  const current = commitInput(fx.store);
  assert.throws(
    () => commitPhysicalResourceArbiterTransition(fx.store, {
      ...current,
      expected_state_digest: digest("wrong-state"),
    }),
    (error) => error.code === "arbiter_expected_digest_drift",
  );
});

test("external rollback and same-generation fork are rejected and fail closed", () => {
  const domain = digest("rollback-fork-domain");
  const backend = createBackend();
  const fx = createFixture({ backend, domain, label: "primary" });
  const genesis = clone(backend.head);
  commitPhysicalResourceArbiterTransition(
    fx.store,
    commitInput(fx.store, [command("mark_ready", "a")]),
  );
  backend.head = genesis;
  assert.throws(
    () => commitPhysicalResourceArbiterTransition(fx.store, commitInput(fx.store)),
    (error) => error.code === "arbiter_head_rollback",
  );

  const backendA = createBackend();
  const backendB = createBackend();
  const config = rawConfig();
  const queue = rawQueue([rawTicket("a"), rawTicket("b", { fairness_class: "beta" })]);
  const storeA = createPhysicalResourceArbiterStore({
    state_port: createPort(backendA, "fork-a", domain), config, queue,
  });
  const storeB = createPhysicalResourceArbiterStore({
    state_port: createPort(backendB, "fork-b", domain), config, queue,
  });
  commitPhysicalResourceArbiterTransition(storeA, commitInput(storeA, [command("mark_ready", "a")]));
  commitPhysicalResourceArbiterTransition(storeB, commitInput(storeB, [command("mark_ready", "b")]));
  backendA.head = clone(backendB.head);
  assert.throws(
    () => synchronizePhysicalResourceArbiterStore(storeA),
    (error) => error.code === "arbiter_head_fork",
  );
});

test("unverified generation gaps are rejected instead of skipping journal proof", () => {
  const backend = createBackend();
  const config = rawConfig({ fairness_classes: ["alpha"], max_batch_burst: 1 });
  const queue = rawQueue([
    rawTicket("gap-a", { ticket_state: "ready" }),
    rawTicket("gap-b", { ticket_state: "ready" }),
    rawTicket("gap-c", { ticket_state: "ready" }),
  ]);
  const stale = createPhysicalResourceArbiterStore({
    state_port: createPort(backend, "gap-stale"), config, queue,
  });
  const writer = createPhysicalResourceArbiterStore({
    state_port: createPort(backend, "gap-writer"), config, queue,
  });
  commitPhysicalResourceArbiterTransition(writer, commitInput(writer));
  commitPhysicalResourceArbiterTransition(writer, commitInput(writer));
  assert.throws(
    () => synchronizePhysicalResourceArbiterStore(stale),
    (error) => error.code === "arbiter_head_gap",
  );
});

test("head and decision digest drift are rejected before projection or mutation", () => {
  const fx = createFixture();
  commitPhysicalResourceArbiterTransition(
    fx.store,
    commitInput(fx.store, [command("mark_ready", "a")]),
  );
  const tampered = clone(fx.backend.head);
  tampered.decision.decision_digest = digest("tampered-decision");
  assert.throws(() => normalizePhysicalResourceArbiterJournalHead(tampered), /decision_digest does not match/);
  fx.backend.head = tampered;
  assert.throws(
    () => synchronizePhysicalResourceArbiterStore(fx.store),
    (error) => error.code === "arbiter_head_invalid",
  );
});

test("decision normalization binds exact selected sets, pre-terminal tickets, and deferral predecessors", () => {
  const sharedBatch = digest("decision-proof-batch");
  const selectedFx = createFixture({
    label: "decision-selected-proof",
    config: { fairness_classes: ["alpha"], max_batch_size: 2, max_batch_burst: 2 },
    tickets: [
      rawTicket("decision-a", { ticket_state: "ready", batch_key: sharedBatch }),
      rawTicket("decision-b", { ticket_state: "ready", batch_key: sharedBatch }),
    ],
  });
  commitPhysicalResourceArbiterTransition(selectedFx.store, commitInput(selectedFx.store));

  const omittedSelection = clone(selectedFx.backend.head);
  omittedSelection.decision.selected_reservation_request_digests.pop();
  omittedSelection.decision.selected_ticket_digests.pop();
  delete omittedSelection.decision.decision_digest;
  assert.throws(
    () => normalizePhysicalResourceArbiterJournalHead(omittedSelection),
    /selected request set does not exactly match/,
  );

  const forgedPreTerminal = clone(selectedFx.backend.head);
  forgedPreTerminal.decision.selected_ticket_digests[0] = digest("forged-pre-terminal");
  delete forgedPreTerminal.decision.decision_digest;
  assert.throws(
    () => normalizePhysicalResourceArbiterJournalHead(forgedPreTerminal),
    /does not bind its exact pre-terminal ticket/,
  );

  const wrongBatch = clone(selectedFx.backend.head);
  wrongBatch.decision.batch_key = digest("wrong-selected-batch");
  delete wrongBatch.decision.decision_digest;
  assert.throws(
    () => normalizePhysicalResourceArbiterJournalHead(wrongBatch),
    /does not match the decision class and batch/,
  );

  const deferredFx = createFixture({
    label: "decision-deferral-proof",
    tickets: [
      rawTicket("defer-a", { ticket_state: "ready" }),
      rawTicket("defer-b", { ticket_state: "ready", fairness_class: "beta" }),
    ],
  });
  commitPhysicalResourceArbiterTransition(deferredFx.store, commitInput(deferredFx.store));
  const forgedDeferral = clone(deferredFx.backend.head);
  assert.equal(forgedDeferral.decision.deferrals.length, 1);
  forgedDeferral.decision.deferrals[0].prior_ticket_digest = digest("forged-deferral-predecessor");
  delete forgedDeferral.decision.decision_digest;
  assert.throws(
    () => normalizePhysicalResourceArbiterJournalHead(forgedDeferral),
    /does not bind its exact predecessor ticket/,
  );
});

test("exact successor replay rejects a self-consistent selection beyond config batch bounds", () => {
  const backend = createBackend();
  const sharedBatch = digest("bounded-batch");
  const config = rawConfig({
    fairness_classes: ["alpha"],
    max_batch_size: 1,
    max_batch_burst: 2,
  });
  const queue = rawQueue([
    rawTicket("bounded-a", { ticket_state: "ready", batch_key: sharedBatch }),
    rawTicket("bounded-b", { ticket_state: "ready", batch_key: sharedBatch }),
  ]);
  const stale = createPhysicalResourceArbiterStore({
    state_port: createPort(backend, "bounded-stale"),
    config,
    queue,
  });
  const writer = createPhysicalResourceArbiterStore({
    state_port: createPort(backend, "bounded-writer"),
    config,
    queue,
  });
  commitPhysicalResourceArbiterTransition(writer, commitInput(writer));

  const validHead = clone(backend.head);
  const deferredTicket = validHead.queue.tickets.find((ticket) => ticket.ticket_state === "ready");
  assert.ok(deferredTicket);
  const preSelectionRaw = {
    ...deferredTicket,
    deferral_count: deferredTicket.deferral_count - 1,
  };
  delete preSelectionRaw.ticket_digest;
  const preSelectionTicket = normalizePhysicalResourceQueueTicket(preSelectionRaw);
  const selectedRaw = {
    ...preSelectionTicket,
    ticket_state: "selected",
    terminal_generation: validHead.generation,
  };
  delete selectedRaw.ticket_digest;
  const additionalSelectedTicket = normalizePhysicalResourceQueueTicket(selectedRaw);
  const forgedQueue = normalizePhysicalResourceArbiterQueue({
    version: PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION,
    tickets: validHead.queue.tickets.map((ticket) => (
      ticket.reservation_request_digest === deferredTicket.reservation_request_digest
        ? additionalSelectedTicket
        : ticket
    )),
  });
  const decisionRaw = clone(validHead.decision);
  delete decisionRaw.decision_digest;
  decisionRaw.selected_reservation_request_digests.push(
    additionalSelectedTicket.reservation_request_digest,
  );
  decisionRaw.selected_ticket_digests.push(preSelectionTicket.ticket_digest);
  decisionRaw.deferrals = [];
  decisionRaw.terminalized_tickets = forgedQueue.tickets
    .filter((ticket) => ticket.terminal_generation === validHead.generation)
    .map((ticket) => ({
      reservation_request_digest: ticket.reservation_request_digest,
      terminal_state: ticket.ticket_state,
      terminal_generation: ticket.terminal_generation,
      ticket_digest: ticket.ticket_digest,
    }));
  decisionRaw.active_batch_after = null;
  const forgedDecision = normalizePhysicalResourceArbiterDecision(decisionRaw);
  const stateRaw = clone(validHead.state);
  delete stateRaw.state_digest;
  stateRaw.queue_digest = forgedQueue.queue_digest;
  stateRaw.active_batch = null;
  const forgedState = normalizePhysicalResourceArbiterState(stateRaw);
  const transitionValue = {
    version: PHYSICAL_RESOURCE_ARBITER_TRANSITION_VERSION,
    input_digest: validHead.input_digest,
    input_state_digest: validHead.input_state_digest,
    input_queue_digest: validHead.input_queue_digest,
    config_digest: validHead.config_digest,
    commands_digest: validHead.commands_digest,
    decision: forgedDecision,
    next_queue: forgedQueue,
    next_state: forgedState,
  };
  const forgedHeadRaw = {
    ...validHead,
    transition_digest: hashCanonicalJson(transitionValue),
    decision: forgedDecision,
    state: forgedState,
    queue: forgedQueue,
  };
  delete forgedHeadRaw.head_digest;
  backend.head = clone(normalizePhysicalResourceArbiterJournalHead(forgedHeadRaw));

  assert.throws(
    () => synchronizePhysicalResourceArbiterStore(stale),
    (error) => error.code === "arbiter_head_fork"
      && error.cause?.code === "arbiter_head_successor_invalid",
  );
  assert.equal(
    physicalResourceArbiterStoreReadiness(stale).mutation_state,
    "ambiguous_fail_closed",
  );
});

test("every observed head must satisfy the config-bound state invariant", () => {
  const fx = createFixture({ label: "bound-state-invariant" });
  const malformedRaw = clone(fx.backend.head);
  delete malformedRaw.head_digest;
  delete malformedRaw.state.state_digest;
  malformedRaw.state.last_served_fairness_class = "unregistered";
  fx.backend.head = clone(normalizePhysicalResourceArbiterJournalHead(malformedRaw));

  assert.throws(
    () => synchronizePhysicalResourceArbiterStore(fx.store),
    (error) => error.code === "arbiter_head_binding_invalid",
  );
  assert.equal(
    physicalResourceArbiterStoreReadiness(fx.store).mutation_state,
    "ambiguous_fail_closed",
  );
});

test("terminal tombstone capacity is explicit and compaction refuses unsafe deletion or reuse", () => {
  const fx = createFixture({
    label: "capacity",
    config: { fairness_classes: ["alpha"], max_queue_tickets: 2 },
    tickets: [rawTicket("capacity-a"), rawTicket("capacity-b")],
  });
  commitPhysicalResourceArbiterTransition(fx.store, commitInput(fx.store, [
    command("cancel", "capacity-a"),
    command("mark_unschedulable", "capacity-b"),
  ]));
  const readiness = physicalResourceArbiterStoreReadiness(fx.store);
  assert.equal(readiness.capacity.capacity_state, "exhausted");
  assert.equal(readiness.capacity.terminal_tombstone_count, 2);
  assert.equal(readiness.capacity.remaining_ticket_capacity, 0);
  assert.equal(readiness.capacity.request_digest_reuse_allowed, false);
  assert.equal(readiness.capacity.compaction_contract, RESOURCE_ARBITER_COMPACTION_CONTRACT);
  assert.throws(
    () => compactPhysicalResourceArbiterTombstones(fx.store),
    (error) => error.code === "arbiter_compaction_unavailable",
  );
  assert.throws(() => commitPhysicalResourceArbiterTransition(fx.store, commitInput(fx.store, [
    enqueueCommand(rawTicket("capacity-new", { enqueue_generation: 2 })),
  ])), /max_queue_tickets/);
  assert.throws(() => commitPhysicalResourceArbiterTransition(fx.store, commitInput(fx.store, [
    enqueueCommand(rawTicket("capacity-a", { enqueue_generation: 2 })),
  ])), /duplicate or terminal/);
});

test("readiness is honest, callback-free, and projections expose no physical authority material", () => {
  const fx = createFixture();
  const reads = fx.backend.calls.read;
  const readiness = physicalResourceArbiterStoreReadiness(fx.store);
  const projection = projectPhysicalResourceArbiterStore(fx.store);
  assert.equal(readiness.production_ready, false);
  assert.equal(readiness.production_attested, false);
  assert.equal(readiness.durability_assurance, RESOURCE_ARBITER_DURABILITY_ASSURANCE);
  assert.equal(fx.backend.calls.read, reads);
  assert.equal(projection.tickets.length, 2);
  const serialized = JSON.stringify({ readiness, projection });
  for (const forbidden of [
    "raw_inventory",
    "fencing_token",
    "raw_fence",
    "lease_credential",
    "device_handle",
    "resource_allocation",
  ]) {
    assert.equal(serialized.includes(forbidden), false);
  }
});

test("getter, symbol, sparse, promise, and malformed callback surfaces fail closed", () => {
  const fx = createFixture();
  const symbol = Symbol("priority");
  const input = commitInput(fx.store, [command("mark_ready", "a")]);
  input[symbol] = "first";
  assert.throws(() => commitPhysicalResourceArbiterTransition(fx.store, input), /symbol fields/);

  const sparseCommands = [];
  sparseCommands.length = 1;
  const sparseInput = commitInput(fx.store, sparseCommands);
  assert.throws(() => commitPhysicalResourceArbiterTransition(fx.store, sparseInput), /commands\[0\].*data field/);

  const hostileHead = clone(fx.backend.head);
  let getterCalled = false;
  Object.defineProperty(hostileHead, "generation", {
    enumerable: true,
    get() {
      getterCalled = true;
      return 0;
    },
  });
  fx.backend.head = hostileHead;
  fx.backend.returnRaw = true;
  assert.throws(
    () => synchronizePhysicalResourceArbiterStore(fx.store),
    (error) => error.code === "arbiter_head_invalid",
  );
  assert.equal(getterCalled, false);

  const promiseBackend = createBackend();
  const promisePort = createPhysicalResourceArbiterStatePort({
    port_id: "arbiter-promise-read",
    journal_domain_digest: digest("promise-read"),
    read_head: () => Promise.resolve(null),
    compare_and_set: promiseBackend.cas,
  });
  assert.throws(
    () => createPhysicalResourceArbiterStore({
      state_port: promisePort,
      config: rawConfig(),
      queue: rawQueue([]),
    }),
    (error) => error.code === "arbiter_port_contract_violation",
  );

  const fx2 = createFixture({ label: "promise-cas" });
  fx2.backend.returnPromiseNext = true;
  assert.throws(
    () => commitPhysicalResourceArbiterTransition(
      fx2.store,
      commitInput(fx2.store, [command("mark_ready", "a")]),
    ),
    (error) => ["arbiter_state_unavailable", "arbiter_port_contract_violation"].includes(error.code),
  );
});

test("commit and synchronize reject same-store reentrancy across every state-port callback", () => {
  const fx = createFixture({ label: "reentrant-store" });
  const reentrantCodes = [];
  fx.backend.beforeNextRead = () => {
    try {
      synchronizePhysicalResourceArbiterStore(fx.store);
    } catch (error) {
      reentrantCodes.push(error.code);
    }
  };
  fx.backend.beforeNextCas = () => {
    try {
      commitPhysicalResourceArbiterTransition(fx.store, commitInput(fx.store));
    } catch (error) {
      reentrantCodes.push(error.code);
    }
  };
  const receipt = commitPhysicalResourceArbiterTransition(
    fx.store,
    commitInput(fx.store, [command("mark_ready", "a")]),
  );
  assert.equal(receipt.commit_status, "committed");

  fx.backend.beforeNextRead = () => {
    try {
      commitPhysicalResourceArbiterTransition(fx.store, commitInput(fx.store));
    } catch (error) {
      reentrantCodes.push(error.code);
    }
  };
  const synchronized = synchronizePhysicalResourceArbiterStore(fx.store);
  assert.equal(synchronized.head_digest, receipt.head_digest);
  assert.deepEqual(reentrantCodes, [
    "arbiter_state_reentrant_mutation",
    "arbiter_state_reentrant_mutation",
    "arbiter_state_reentrant_mutation",
  ]);

  const next = commitPhysicalResourceArbiterTransition(fx.store, commitInput(fx.store));
  assert.equal(next.generation, receipt.generation + 1, "operation guard must clear after completion");
});
