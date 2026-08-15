"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  PHYSICAL_RESOURCE_ARBITER_CONFIG_VERSION,
  PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION,
} = require("../../../mcp/domains/physical/physical-resource-arbiter.js");
const {
  normalizePhysicalReservationRequest,
  normalizePhysicalResourceBundle,
} = require("../../../mcp/lib/physical-resource-contract.js");
const {
  createPhysicalResourceArbiterStatePort,
  createPhysicalResourceArbiterStore,
  projectPhysicalResourceArbiterStore,
} = require("../lib/resource-arbiter-store.js");
const {
  createPhysicalResourceBundleResolverPort,
} = require("../lib/resource-reservations.js");
const {
  RESOURCE_ARBITER_ADMISSION_ISOLATION,
  admitPhysicalResourceArbiterRequest,
  assertPhysicalResourceArbiterAdmissionPort,
  createPhysicalResourceArbiterAdmissionPort,
  derivePhysicalResourceArbiterBatchKey,
  physicalResourceArbiterAdmissionReadiness,
  projectPhysicalResourceArbiterBatchSemantics,
  verifyPhysicalResourceArbiterAdmissionBinding,
} = require("../lib/resource-arbiter-admission.js");

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
    max_batch_size: 2,
    max_batch_burst: 4,
    max_queue_tickets: 32,
    ...overrides,
  };
}

function rawRequirement(overrides = {}) {
  return {
    alias: "reader",
    resource_kind: "instrument",
    candidate_resource_refs: ["instrument:ultra-a", "instrument:ultra-b"],
    ownership: "shared",
    capacity_units: 1,
    capability_refs: ["capability:hf.inventory"],
    requested_effect_digests: [digest("observe-only")],
    constraints: [],
    required_state_epoch_digest: digest("reader-state"),
    mode_ref: "mode:reader",
    workspace_ref: "workspace:slot-a",
    compatibility_ref: "compatibility:hf-read-only",
    ...overrides,
  };
}

function makeBundle(overrides = {}) {
  return normalizePhysicalResourceBundle({
    version: 1,
    bundle_id: "arbiter-admission-test",
    requirements: [rawRequirement()],
    attempt_budget: 2,
    duration_ms: 30_000,
    reservation_ttl_ms: 40_000,
    cooldown_ms: 5_000,
    preemption_policy: "before_effect_only",
    fairness_class: "alpha",
    batch_key: "physical:hf-reader",
    setup_cost_units: 7,
    spatial_envelope_ref: "spatial-envelope:shielded-bench",
    spatial_envelope_digest: digest("shielded-bench"),
    stimulus_sequence_ref: "stimulus-sequence:inventory-only",
    stimulus_sequence_digest: digest("inventory-only"),
    ...overrides,
  });
}

function makeRequest(bundle, overrides = {}) {
  return normalizePhysicalReservationRequest({
    version: 1,
    reservation_request_id: "reservation-request:arbiter-admission",
    node_id: "TG-cell-arbiter-admission",
    contract_hash: digest("contract"),
    source_graph_hash: digest("source-graph"),
    session_nucleus_hash: digest("session-nucleus"),
    experiment_ref: "experiment:physical-test",
    attempt_ref: "attempt:physical-test",
    owner_principal_ref: "principal:broker",
    execution_principal_ref: "principal:worker",
    resource_bundle_digest: bundle.resource_bundle_digest,
    requested_at: "2026-07-18T00:00:00.000Z",
    effect_not_before: "2026-07-18T00:00:01.000Z",
    effect_deadline: "2026-07-18T00:00:31.000Z",
    ...overrides,
  });
}

function createBackend() {
  const backend = {
    head: null,
    read_calls: 0,
    cas_calls: 0,
    before_next_read: null,
  };
  backend.read = () => {
    backend.read_calls += 1;
    if (backend.before_next_read) {
      const callback = backend.before_next_read;
      backend.before_next_read = null;
      callback();
    }
    return clone(backend.head);
  };
  backend.cas = (expected, next) => {
    backend.cas_calls += 1;
    const matches = expected === null
      ? backend.head === null
      : backend.head != null
        && expected.generation === backend.head.generation
        && expected.head_digest === backend.head.head_digest
        && expected.state_digest === backend.head.state.state_digest
        && expected.queue_digest === backend.head.queue.queue_digest
        && expected.config_digest === backend.head.config_digest;
    if (!matches) return false;
    backend.head = clone(next);
    return true;
  };
  return backend;
}

function createFixture(options = {}) {
  const backend = createBackend();
  const config = rawConfig(options.config);
  const statePort = createPhysicalResourceArbiterStatePort({
    port_id: options.state_port_id || "arbiter-admission-state",
    journal_domain_digest: digest(options.domain || "arbiter-admission-domain"),
    read_head: backend.read,
    compare_and_set: backend.cas,
  });
  const store = createPhysicalResourceArbiterStore({
    state_port: statePort,
    config,
    queue: {
      version: PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION,
      tickets: [],
    },
  });
  const bundle = options.bundle || makeBundle();
  let resolverCalls = 0;
  let resolveBundle = options.resolve_bundle || ((binding) => {
    resolverCalls += 1;
    assert.ok(Object.isFrozen(binding));
    assert.deepEqual(Object.keys(binding).sort(), [
      "reservation_request_digest",
      "resource_bundle_digest",
      "version",
    ]);
    return bundle;
  });
  const resolverPort = createPhysicalResourceBundleResolverPort({
    port_id: options.resolver_port_id || "arbiter_admission_resolver",
    resolve_bundle(binding) {
      return resolveBundle(binding);
    },
  });
  const admissionPort = createPhysicalResourceArbiterAdmissionPort({
    port_id: options.admission_port_id || "arbiter_admission",
    bundle_resolver_port: resolverPort,
    arbiter_store: store,
    arbiter_config: config,
    source_graph_hash: digest(options.source_graph || "source-graph"),
    session_nucleus_hash: digest(options.session_nucleus || "session-nucleus"),
  });
  return {
    admissionPort,
    backend,
    bundle,
    config,
    resolverPort,
    store,
    get resolverCalls() {
      return resolverCalls;
    },
    setResolver(callback) {
      resolveBundle = callback;
    },
  };
}

test("private admission port hides resolver/store capabilities and reports same-isolate non-readiness", () => {
  const fx = createFixture();
  assert.equal(assertPhysicalResourceArbiterAdmissionPort(fx.admissionPort), fx.admissionPort);
  assert.equal("bundle_resolver_port" in fx.admissionPort, false);
  assert.equal("arbiter_store" in fx.admissionPort, false);
  assert.equal(fx.admissionPort.production_attested, false);
  assert.equal(fx.admissionPort.isolation_assurance, RESOURCE_ARBITER_ADMISSION_ISOLATION);
  assert.equal(fx.admissionPort.source_graph_hash, digest("source-graph"));
  assert.equal(fx.admissionPort.session_nucleus_hash, digest("session-nucleus"));
  assert.throws(
    () => assertPhysicalResourceArbiterAdmissionPort({ ...fx.admissionPort }),
    /private factory/,
  );
  const readiness = physicalResourceArbiterAdmissionReadiness(fx.admissionPort);
  assert.equal(readiness.production_ready, false);
  assert.equal(readiness.production_attested, false);
  assert.equal(readiness.isolation_assurance, "same_isolate_weak_brand_only");
  assert.ok(readiness.blockers.includes("admission_brand_is_not_a_process_or_os_security_boundary"));
  assert.ok(readiness.blockers.includes(
    "admission_binding_is_not_authenticated_or_retained_by_a_durable_request_registry",
  ));
  assert.ok(Object.isFrozen(readiness));
  assert.ok(Object.isFrozen(readiness.blockers));
});

test("admission derives and durably commits an exact blocked bundle-bound ticket", () => {
  const fx = createFixture();
  const request = makeRequest(fx.bundle);
  const before = projectPhysicalResourceArbiterStore(fx.store);
  const receipt = admitPhysicalResourceArbiterRequest(fx.admissionPort, {
    reservation_request: request,
  });
  const after = projectPhysicalResourceArbiterStore(fx.store);

  assert.equal(fx.resolverCalls, 1);
  assert.equal(receipt.ticket.ticket_state, "blocked");
  assert.equal(receipt.ticket.enqueue_generation, before.generation + 1);
  assert.equal(receipt.ticket.fairness_class, fx.bundle.fairness_class);
  assert.equal(receipt.ticket.setup_cost_units, fx.bundle.setup_cost_units);
  assert.equal(receipt.ticket.resource_bundle_digest, fx.bundle.resource_bundle_digest);
  assert.equal(receipt.ticket.reservation_request_digest, request.reservation_request_digest);
  assert.equal(receipt.ticket.batch_key, derivePhysicalResourceArbiterBatchKey(fx.bundle));
  assert.match(receipt.ticket.batch_key, /^[a-f0-9]{64}$/);
  assert.notEqual(receipt.ticket.batch_key, fx.bundle.batch_key);
  assert.equal(receipt.binding.reservation_request_id, request.reservation_request_id);
  assert.equal(receipt.binding.node_id, request.node_id);
  assert.equal(receipt.binding.contract_hash, request.contract_hash);
  assert.equal(receipt.binding.source_graph_hash, request.source_graph_hash);
  assert.equal(receipt.binding.session_nucleus_hash, request.session_nucleus_hash);
  assert.equal(receipt.binding.resource_bundle_digest, request.resource_bundle_digest);
  assert.equal(receipt.binding.ticket_digest, receipt.ticket.ticket_digest);
  assert.equal(receipt.binding.batch_semantics_digest, receipt.ticket.batch_key);
  assert.equal(receipt.binding.enqueue_command_digest, receipt.command_digest);
  assert.equal(receipt.binding.commit_generation, receipt.commit_receipt.generation);
  assert.equal(receipt.binding.commit_head_digest, receipt.commit_receipt.head_digest);
  assert.equal(receipt.binding.commit_prior_head_digest, receipt.commit_receipt.prior_head_digest);
  assert.equal(receipt.binding.commit_state_digest, receipt.commit_receipt.state_digest);
  assert.equal(receipt.binding.commit_queue_digest, receipt.commit_receipt.queue_digest);
  assert.equal(receipt.binding.commit_transition_digest, receipt.commit_receipt.transition_digest);
  assert.equal(receipt.commit_receipt.generation, before.generation + 1);
  assert.equal(receipt.commit_receipt.prior_head_digest, before.head_digest);
  assert.equal(after.tickets.length, 1);
  assert.equal(after.tickets[0].ticket_digest, receipt.ticket.ticket_digest);
  assert.equal(after.tickets[0].ticket_state, "blocked");
  assert.deepEqual(receipt.commit_receipt.selected_reservation_request_digests, []);
  assert.ok(Object.isFrozen(receipt));
  assert.ok(Object.isFrozen(receipt.ticket));
  assert.ok(Object.isFrozen(receipt.binding));

  const durableCopy = clone(receipt);
  const verified = verifyPhysicalResourceArbiterAdmissionBinding(fx.admissionPort, {
    binding: durableCopy.binding,
    reservation_request: clone(request),
    resource_bundle: clone(fx.bundle),
    ticket: durableCopy.ticket,
    arbiter_commit: durableCopy.arbiter_commit,
  });
  assert.deepEqual(verified, receipt.binding);
  const driftedBinding = clone(durableCopy.binding);
  driftedBinding.commit_head_digest = digest("forged-commit-head");
  assert.throws(
    () => verifyPhysicalResourceArbiterAdmissionBinding(fx.admissionPort, {
      binding: driftedBinding,
      reservation_request: clone(request),
      resource_bundle: clone(fx.bundle),
      ticket: durableCopy.ticket,
      arbiter_commit: durableCopy.arbiter_commit,
    }),
    (error) => error.code === "resource_arbiter_admission_binding_invalid",
  );
});

test("batch derivation is order-stable and separates every setup compatibility coordinate", () => {
  const firstRequirement = rawRequirement({ alias: "a_" });
  const secondRequirement = rawRequirement({
    alias: "a0",
    candidate_resource_refs: ["instrument:ultra-c"],
  });
  const forward = makeBundle({ requirements: [firstRequirement, secondRequirement] });
  const reverse = makeBundle({ requirements: [secondRequirement, firstRequirement] });
  assert.equal(
    derivePhysicalResourceArbiterBatchKey(forward),
    derivePhysicalResourceArbiterBatchKey(reverse),
  );
  const codeUnitProjection = projectPhysicalResourceArbiterBatchSemantics(makeBundle({
    requirements: [rawRequirement({
      candidate_resource_refs: ["instrument:a_", "instrument:a0"],
      capability_refs: ["capability:a_", "capability:a0"],
    })],
  }));
  assert.deepEqual(
    codeUnitProjection.requirements[0].candidate_resource_refs,
    ["instrument:a0", "instrument:a_"],
  );
  assert.deepEqual(
    codeUnitProjection.requirements[0].capability_refs,
    ["capability:a0", "capability:a_"],
  );

  const base = makeBundle();
  const variants = [
    makeBundle({ batch_key: "physical:hf-reader-other" }),
    makeBundle({ setup_cost_units: 8 }),
    makeBundle({ requirements: [rawRequirement({ mode_ref: "mode:emulator" })] }),
    makeBundle({ requirements: [rawRequirement({ workspace_ref: "workspace:slot-b" })] }),
    makeBundle({ requirements: [rawRequirement({ compatibility_ref: "compatibility:hf-other" })] }),
    makeBundle({ requirements: [rawRequirement({ candidate_resource_refs: ["instrument:ultra-c"] })] }),
    makeBundle({ spatial_envelope_digest: digest("other-envelope") }),
    makeBundle({ stimulus_sequence_digest: digest("other-sequence") }),
  ];
  const baseKey = derivePhysicalResourceArbiterBatchKey(base);
  for (const variant of variants) assert.notEqual(derivePhysicalResourceArbiterBatchKey(variant), baseKey);

  const queueOnlyChange = makeBundle({
    bundle_id: "another-bundle-id",
    fairness_class: "beta",
    attempt_budget: 9,
    duration_ms: 20_000,
    reservation_ttl_ms: 35_000,
  });
  assert.equal(derivePhysicalResourceArbiterBatchKey(queueOnlyChange), baseKey);
  const projection = projectPhysicalResourceArbiterBatchSemantics(base);
  assert.equal(projection.batch_semantics_digest, baseKey);
  assert.equal(projection.requirements[0].mode_ref, "mode:reader");
  assert.equal(projection.requirements[0].workspace_ref, "workspace:slot-a");
});

test("caller scheduling fields, symbols, and accessors are rejected before resolution", () => {
  const fx = createFixture();
  const request = makeRequest(fx.bundle);
  for (const [field, value] of [
    ["fairness_class", "beta"],
    ["batch_key", digest("forged-batch")],
    ["setup_cost_units", 0],
    ["ticket_state", "ready"],
    ["enqueue_generation", 999],
  ]) {
    assert.throws(
      () => admitPhysicalResourceArbiterRequest(fx.admissionPort, {
        reservation_request: request,
        [field]: value,
      }),
      /unknown fields/,
    );
  }
  const symbolInput = { reservation_request: request };
  symbolInput[Symbol("forged")] = true;
  assert.throws(
    () => admitPhysicalResourceArbiterRequest(fx.admissionPort, symbolInput),
    /symbol fields/,
  );
  let getterCalled = false;
  const hostile = {};
  Object.defineProperty(hostile, "reservation_request", {
    enumerable: true,
    get() {
      getterCalled = true;
      return request;
    },
  });
  assert.throws(
    () => admitPhysicalResourceArbiterRequest(fx.admissionPort, hostile),
    /enumerable data field/,
  );
  assert.equal(getterCalled, false);
  assert.equal(fx.resolverCalls, 0);
  assert.equal(projectPhysicalResourceArbiterStore(fx.store).generation, 0);
});

test("bundle digest drift, asynchronous resolution, and forbidden fairness fail before commit", () => {
  {
    const expected = makeBundle();
    const drifted = makeBundle({ batch_key: "physical:drifted" });
    const fx = createFixture({ bundle: expected, resolve_bundle: () => drifted });
    assert.throws(
      () => admitPhysicalResourceArbiterRequest(fx.admissionPort, {
        reservation_request: makeRequest(expected),
      }),
      (error) => error.code === "resource_bundle_binding_drift",
    );
    assert.equal(projectPhysicalResourceArbiterStore(fx.store).generation, 0);
  }
  {
    const bundle = makeBundle();
    const fx = createFixture({ bundle, resolve_bundle: () => Promise.resolve(bundle) });
    assert.throws(
      () => admitPhysicalResourceArbiterRequest(fx.admissionPort, {
        reservation_request: makeRequest(bundle),
      }),
      /must be synchronous/,
    );
    assert.equal(projectPhysicalResourceArbiterStore(fx.store).generation, 0);
  }
  {
    const bundle = makeBundle({ fairness_class: "gamma" });
    const fx = createFixture({ bundle });
    assert.throws(
      () => admitPhysicalResourceArbiterRequest(fx.admissionPort, {
        reservation_request: makeRequest(bundle),
      }),
      (error) => error.code === "resource_arbiter_admission_fairness_forbidden",
    );
    assert.equal(projectPhysicalResourceArbiterStore(fx.store).generation, 0);
  }
});

test("admission port rejects a correctly normalized request from another graph or session", () => {
  const fx = createFixture();
  for (const request of [
    makeRequest(fx.bundle, { source_graph_hash: digest("other-source-graph") }),
    makeRequest(fx.bundle, { session_nucleus_hash: digest("other-session-nucleus") }),
  ]) {
    assert.throws(
      () => admitPhysicalResourceArbiterRequest(fx.admissionPort, { reservation_request: request }),
      (error) => error.code === "resource_arbiter_admission_session_drift",
    );
  }
  assert.equal(fx.resolverCalls, 0);
  assert.equal(projectPhysicalResourceArbiterStore(fx.store).generation, 0);
});

test("hostile thenable getters fail with an explicit callback-contract error and release admission", () => {
  const bundle = makeBundle();
  let thenGetterCalls = 0;
  const hostile = {};
  Object.defineProperty(hostile, "then", {
    enumerable: true,
    get() {
      thenGetterCalls += 1;
      throw new Error("hostile then getter");
    },
  });
  const fx = createFixture({ bundle, resolve_bundle: () => hostile });
  const request = makeRequest(bundle);
  assert.throws(
    () => admitPhysicalResourceArbiterRequest(fx.admissionPort, { reservation_request: request }),
    (error) => {
      assert.equal(error.code, "reservation_callback_contract_violation");
      assert.match(error.message, /hostile thenable/);
      return true;
    },
  );
  assert.equal(thenGetterCalls, 1);
  fx.setResolver(() => bundle);
  assert.equal(
    admitPhysicalResourceArbiterRequest(fx.admissionPort, { reservation_request: request })
      .ticket.ticket_state,
    "blocked",
  );
});

test("admission rejects resolver and state callback reentrancy and releases its guard", () => {
  {
    const bundle = makeBundle();
    let port;
    const fx = createFixture({
      bundle,
      resolve_bundle() {
        return admitPhysicalResourceArbiterRequest(port, {
          reservation_request: makeRequest(bundle),
        });
      },
    });
    port = fx.admissionPort;
    assert.throws(
      () => admitPhysicalResourceArbiterRequest(port, {
        reservation_request: makeRequest(bundle),
      }),
      (error) => error.code === "resource_arbiter_admission_reentrant",
    );
    fx.setResolver(() => bundle);
    const receipt = admitPhysicalResourceArbiterRequest(port, {
      reservation_request: makeRequest(bundle),
    });
    assert.equal(receipt.ticket.ticket_state, "blocked");
  }
  {
    const fx = createFixture({ admission_port_id: "arbiter_admission_state_reentry" });
    const request = makeRequest(fx.bundle, {
      reservation_request_id: "reservation-request:state-reentry",
      attempt_ref: "attempt:state-reentry",
    });
    fx.backend.before_next_read = () => {
      admitPhysicalResourceArbiterRequest(fx.admissionPort, { reservation_request: request });
    };
    assert.throws(
      () => admitPhysicalResourceArbiterRequest(fx.admissionPort, {
        reservation_request: request,
      }),
      (error) => {
        assert.equal(error.code, "arbiter_state_unavailable");
        assert.equal(error.cause.code, "resource_arbiter_admission_reentrant");
        return true;
      },
    );
    assert.equal(projectPhysicalResourceArbiterStore(fx.store).generation, 0);
  }
});

test("admission port rejects config drift and forged resolver/store lookalikes", () => {
  const fx = createFixture();
  assert.throws(
    () => createPhysicalResourceArbiterAdmissionPort({
      port_id: "arbiter_admission_wrong_config",
      bundle_resolver_port: fx.resolverPort,
      arbiter_store: fx.store,
      arbiter_config: rawConfig({ aging_threshold: 3 }),
      source_graph_hash: digest("source-graph"),
      session_nucleus_hash: digest("session-nucleus"),
    }),
    (error) => error.code === "resource_arbiter_admission_config_drift",
  );
  assert.throws(
    () => createPhysicalResourceArbiterAdmissionPort({
      port_id: "arbiter_admission_forged_resolver",
      bundle_resolver_port: { ...fx.resolverPort },
      arbiter_store: fx.store,
      arbiter_config: fx.config,
      source_graph_hash: digest("source-graph"),
      session_nucleus_hash: digest("session-nucleus"),
    }),
    /private factory/,
  );
  assert.throws(
    () => createPhysicalResourceArbiterAdmissionPort({
      port_id: "arbiter_admission_forged_store",
      bundle_resolver_port: fx.resolverPort,
      arbiter_store: { ...fx.store },
      arbiter_config: fx.config,
      source_graph_hash: digest("source-graph"),
      session_nucleus_hash: digest("session-nucleus"),
    }),
    /private factory/,
  );
});
