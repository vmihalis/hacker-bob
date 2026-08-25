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
} = require("../../../mcp/core/physical-resource-contracts.js");
const { hashCanonicalJson } = require("../../../mcp/core/verification/verification-contracts.js");
const {
  createPhysicalResourceArbiterStatePort,
  createPhysicalResourceArbiterStore,
  projectPhysicalResourceArbiterStore,
} = require("../lib/resource-arbiter-store.js");
const {
  createPhysicalResourceBundleResolverPort,
} = require("../lib/resource-reservations.js");
const {
  admitPhysicalResourceArbiterRequest,
  createPhysicalResourceArbiterAdmissionPort,
} = require("../lib/resource-arbiter-admission.js");
const {
  RESOURCE_REQUEST_REGISTRY_DURABILITY_ASSURANCE,
  RESOURCE_REQUEST_REGISTRY_ISOLATION_ASSURANCE,
  assertPhysicalResourceRequestRegistry,
  assertPhysicalResourceRequestRegistrySigner,
  assertPhysicalResourceRequestRegistryStatePort,
  createPhysicalResourceRequestRegistry,
  createPhysicalResourceRequestRegistrySigner,
  createPhysicalResourceRequestRegistryStatePort,
  finalizePhysicalResourceRequestRegistration,
  physicalResourceRequestRegistryReadiness,
  preparePhysicalResourceRequestRegistration,
  projectPhysicalResourceRequestRegistry,
  reconcilePhysicalResourceRequestRegistration,
  rehydratePhysicalResourceRequestRegistrationCapability,
} = require("../lib/resource-request-registry.js");

function digest(label) {
  return crypto.createHash("sha256").update(label).digest("hex");
}

function clone(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function config() {
  return {
    version: PHYSICAL_RESOURCE_ARBITER_CONFIG_VERSION,
    fairness_classes: ["alpha", "beta"],
    aging_threshold: 2,
    max_batch_size: 2,
    max_batch_burst: 4,
    max_queue_tickets: 32,
  };
}

function bundle(overrides = {}) {
  return normalizePhysicalResourceBundle({
    version: 1,
    bundle_id: "request-registry-test",
    requirements: [{
      alias: "reader",
      resource_kind: "instrument",
      candidate_resource_refs: ["instrument:ultra-a"],
      ownership: "shared",
      capacity_units: 1,
      capability_refs: ["capability:hf.inventory"],
      requested_effect_digests: [digest("observe-only")],
      constraints: [],
      required_state_epoch_digest: digest("reader-state"),
      mode_ref: "mode:reader",
      workspace_ref: "workspace:slot-a",
      compatibility_ref: "compatibility:hf-read-only",
    }],
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

function request(resourceBundle, suffix = "one", overrides = {}) {
  return normalizePhysicalReservationRequest({
    version: 1,
    reservation_request_id: `reservation-request:${suffix}`,
    node_id: `TG-cell-request-registry-${suffix}`,
    contract_hash: digest(`contract-${suffix}`),
    source_graph_hash: digest("source-graph"),
    session_nucleus_hash: digest("session-nucleus"),
    experiment_ref: "experiment:physical-test",
    attempt_ref: `attempt:physical-test-${suffix}`,
    owner_principal_ref: "principal:broker",
    execution_principal_ref: "principal:worker",
    resource_bundle_digest: resourceBundle.resource_bundle_digest,
    requested_at: "2026-07-18T00:00:00.000Z",
    effect_not_before: "2026-07-18T00:00:01.000Z",
    effect_deadline: "2026-07-18T00:00:31.000Z",
    ...overrides,
  });
}

function arbiterBackend() {
  const backend = { head: null };
  backend.read = () => clone(backend.head);
  backend.cas = (expected, next) => {
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

function registryBackend(initial = null) {
  const backend = {
    snapshot: initial == null
      ? { version: 1, state: null, checkpoint: null }
      : clone(initial),
    before_read: null,
    next_cas: null,
  };
  backend.read = () => {
    if (backend.before_read) {
      const callback = backend.before_read;
      backend.before_read = null;
      callback();
    }
    return clone(backend.snapshot);
  };
  backend.cas = (input) => {
    const mode = backend.next_cas;
    backend.next_cas = null;
    const current = backend.snapshot.checkpoint;
    const expected = input.expected_checkpoint;
    const matches = expected === null
      ? current === null
      : current != null && expected.checkpoint_digest === current.checkpoint_digest;
    const result = (disposition, observed = current) => ({
      version: 1,
      disposition,
      observed_checkpoint: clone(observed),
    });
    if (mode === "async") return Promise.resolve(result("ambiguous"));
    if (mode === "hostile") {
      const hostile = {};
      Object.defineProperty(hostile, "then", { get() { throw new Error("hostile then"); } });
      return hostile;
    }
    if (mode === "conflict" || !matches) return result("conflict");
    if (mode === "ambiguous_before") return result("ambiguous");
    backend.snapshot = {
      version: 1,
      state: clone(input.next_state),
      checkpoint: clone(input.next_checkpoint),
    };
    if (mode === "ambiguous_after") return result("ambiguous", input.next_checkpoint);
    return result("committed", input.next_checkpoint);
  };
  return backend;
}

function signerMaterial(epoch) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const signer = createPhysicalResourceRequestRegistrySigner({
    signer_id: `request_registry_signer_${epoch}`,
    key_id: `registry-key:epoch-${epoch}`,
    signer_epoch: epoch,
    private_key: privateKey,
  });
  return {
    privateKey,
    signer,
    trust: {
      key_id: signer.key_id,
      signer_epoch: epoch,
      public_key_digest: signer.public_key_digest,
      public_key: publicKey,
    },
  };
}

function authenticatedSuccessor(fx, records) {
  const previous = fx.backend.snapshot.state;
  const payload = {
    ...clone(previous.payload),
    generation: previous.payload.generation + 1,
    prior_head_digest: previous.head_digest,
    record_count: records.length,
    records_digest: hashCanonicalJson(records),
    records: clone(records),
    current_signer_key_id: fx.material.signer.key_id,
    current_signer_epoch: fx.material.signer.signer_epoch,
  };
  const stateDigest = hashCanonicalJson(payload);
  const authenticationBasis = {
    scheme: "ed25519",
    key_usage: "physical_resource_request_registry_signing",
    key_id: fx.material.signer.key_id,
    signer_epoch: fx.material.signer.signer_epoch,
    public_key_digest: fx.material.signer.public_key_digest,
    signed_payload_digest: stateDigest,
  };
  const signatureInput = hashCanonicalJson({
    domain: "hacker-bob/physical-resource-request-registry-state/v1",
    registry_domain_digest: digest("request-registry-domain"),
    payload,
    authentication: authenticationBasis,
  });
  const authentication = {
    ...authenticationBasis,
    signature: crypto.sign(
      null,
      Buffer.from(signatureInput, "hex"),
      fx.material.privateKey,
    ).toString("base64url"),
  };
  const envelope = { payload, authentication, state_digest: stateDigest };
  const state = { ...envelope, head_digest: hashCanonicalJson(envelope) };
  const checkpointValue = {
    version: 1,
    registry_id: payload.registry_id,
    registry_domain_digest: payload.registry_domain_digest,
    generation: payload.generation,
    head_digest: state.head_digest,
    state_digest: state.state_digest,
    records_digest: payload.records_digest,
    record_count: payload.record_count,
    current_signer_key_id: payload.current_signer_key_id,
    current_signer_epoch: payload.current_signer_epoch,
  };
  return {
    version: 1,
    state,
    checkpoint: {
      ...checkpointValue,
      checkpoint_digest: hashCanonicalJson(checkpointValue),
    },
  };
}

function registryOptions(fx, statePort, material, trustedSigners, restartCheckpoint) {
  return {
    registry_id: "physical_request_registry",
    registry_domain_digest: digest("request-registry-domain"),
    state_port: statePort,
    admission_port: fx.admissionPort,
    signer: material.signer,
    trusted_signers: trustedSigners,
    max_records: fx.maxRecords,
    ...(restartCheckpoint === undefined ? {} : { restart_checkpoint: restartCheckpoint }),
  };
}

function attachRegistry(fx, options = {}) {
  const backend = options.backend || registryBackend();
  const material = options.material || fx.material;
  const trustedSigners = options.trusted_signers || fx.trustedSigners;
  const statePort = createPhysicalResourceRequestRegistryStatePort({
    port_id: options.port_id || "request_registry_state",
    registry_domain_digest: digest("request-registry-domain"),
    read_current: backend.read,
    compare_and_set: backend.cas,
  });
  const registry = createPhysicalResourceRequestRegistry(registryOptions(
    fx,
    statePort,
    material,
    trustedSigners,
    options.restart_checkpoint,
  ));
  return { backend, material, registry, statePort, trustedSigners };
}

function fixture(options = {}) {
  const backend = arbiterBackend();
  const arbiterConfig = config();
  const statePort = createPhysicalResourceArbiterStatePort({
    port_id: "request_registry_arbiter_state",
    journal_domain_digest: digest("request-registry-arbiter-domain"),
    read_head: backend.read,
    compare_and_set: backend.cas,
  });
  const store = createPhysicalResourceArbiterStore({
    state_port: statePort,
    config: arbiterConfig,
    queue: { version: PHYSICAL_RESOURCE_ARBITER_QUEUE_VERSION, tickets: [] },
  });
  const resourceBundle = bundle();
  const resolver = createPhysicalResourceBundleResolverPort({
    port_id: "request_registry_bundle_resolver",
    resolve_bundle: ({ resource_bundle_digest: requested }) => {
      if (requested !== resourceBundle.resource_bundle_digest) throw new Error("unknown bundle");
      return resourceBundle;
    },
  });
  const admissionPort = createPhysicalResourceArbiterAdmissionPort({
    port_id: "request_registry_admission",
    bundle_resolver_port: resolver,
    arbiter_store: store,
    arbiter_config: arbiterConfig,
    source_graph_hash: digest("source-graph"),
    session_nucleus_hash: digest("session-nucleus"),
  });
  const material = options.material || signerMaterial(1);
  const fx = {
    admissionPort,
    arbiterBackend: backend,
    bundle: resourceBundle,
    material,
    maxRecords: options.max_records || 8,
    store,
    trustedSigners: options.trusted_signers || [material.trust],
  };
  Object.assign(fx, attachRegistry(fx));
  return fx;
}

function prepare(fx, reservationRequest = request(fx.bundle)) {
  return preparePhysicalResourceRequestRegistration(fx.registry, {
    reservation_request: reservationRequest,
    resource_bundle: fx.bundle,
  });
}

function finalize(fx, prepared, receipt) {
  return finalizePhysicalResourceRequestRegistration(fx.registry, {
    prepare_capability: prepared.prepare_capability,
    admission_binding: receipt.binding,
    ticket: receipt.ticket,
    arbiter_commit: receipt.arbiter_commit,
  });
}

test("registry hides signer/CAS authority and reports explicit non-readiness", () => {
  const fx = fixture();
  assert.equal(assertPhysicalResourceRequestRegistry(fx.registry), fx.registry);
  assert.equal(assertPhysicalResourceRequestRegistrySigner(fx.material.signer), fx.material.signer);
  assert.equal(assertPhysicalResourceRequestRegistryStatePort(fx.statePort), fx.statePort);
  assert.equal("private_key" in fx.material.signer, false);
  assert.equal("read_current" in fx.statePort, false);
  assert.equal("compare_and_set" in fx.statePort, false);
  assert.equal("signer" in fx.registry, false);
  assert.equal("state_port" in fx.registry, false);
  assert.equal("admission_port" in fx.registry, false);
  assert.throws(() => assertPhysicalResourceRequestRegistry({ ...fx.registry }), /private factory/);
  const projection = projectPhysicalResourceRequestRegistry(fx.registry);
  assert.equal("records" in projection, false);
  assert.equal("authentication" in projection, false);
  assert.equal(projection.record_count, 0);
  const readiness = physicalResourceRequestRegistryReadiness(fx.registry);
  assert.equal(readiness.production_ready, false);
  assert.equal(readiness.production_attested, false);
  assert.equal(readiness.durability_assurance, RESOURCE_REQUEST_REGISTRY_DURABILITY_ASSURANCE);
  assert.equal(readiness.isolation_assurance, RESOURCE_REQUEST_REGISTRY_ISOLATION_ASSURANCE);
  assert.deepEqual(readiness.blockers, [
    "registry_prepare_and_arbiter_enqueue_are_not_one_atomic_external_transaction",
    "registry_state_and_checkpoint_callback_durability_is_unattested",
    "registry_brand_and_signer_are_not_a_process_or_os_security_boundary",
    "prepared_records_require_arbiter_journal_reconciliation_after_crash",
    "proof_preserving_registry_compaction_is_not_implemented",
  ]);
});

test("prepare, external enqueue, finalize, and exact replay retain one authenticated join", () => {
  const fx = fixture();
  const reservationRequest = request(fx.bundle);
  const prepared = prepare(fx, reservationRequest);
  assert.equal(prepared.disposition, "created_prepared");
  assert.equal(prepared.registration.requires_arbiter_reconciliation, true);
  assert.equal(projectPhysicalResourceArbiterStore(fx.store).generation, 0);
  assert.equal(reconcilePhysicalResourceRequestRegistration(fx.registry, {
    reservation_request_id: reservationRequest.reservation_request_id,
    reservation_request_digest: reservationRequest.reservation_request_digest,
  }).registration_state, "prepared");

  const receipt = admitPhysicalResourceArbiterRequest(fx.admissionPort, {
    reservation_request: reservationRequest,
  });
  const finalized = finalize(fx, prepared, receipt);
  assert.equal(finalized.disposition, "created_finalized");
  assert.equal(finalized.registration.requires_arbiter_reconciliation, false);
  assert.equal(finalized.registration.ticket_digest, receipt.ticket.ticket_digest);
  assert.equal(finalized.registration.commit_head_digest, receipt.arbiter_commit.head_digest);
  assert.equal(fx.backend.snapshot.state.payload.records[0].authentication.scheme, "ed25519");
  assert.equal(fx.backend.snapshot.state.payload.records[0].payload.admission_binding.binding_digest,
    receipt.binding.binding_digest);

  assert.equal(finalize(fx, prepared, receipt).disposition, "existing_finalized");
  const replay = prepare(fx, clone(reservationRequest));
  assert.equal(replay.disposition, "existing_finalized");
  assert.equal(finalize(fx, replay, clone(receipt)).disposition, "existing_finalized");
  assert.equal(projectPhysicalResourceRequestRegistry(fx.registry).record_count, 1);
});

test("same request id drift conflicts and capacity exhaustion never evicts", () => {
  const fx = fixture({ max_records: 1 });
  const first = request(fx.bundle);
  prepare(fx, first);
  assert.throws(
    () => prepare(fx, request(fx.bundle, "one", {
      effect_deadline: "2026-07-18T00:00:32.000Z",
    })),
    (error) => error.code === "resource_request_registry_duplicate_conflict",
  );
  assert.throws(
    () => prepare(fx, request(fx.bundle, "two")),
    (error) => error.code === "resource_request_registry_capacity_exhausted",
  );
  assert.equal(projectPhysicalResourceRequestRegistry(fx.registry).record_count, 1);
  assert.equal(fx.backend.snapshot.state.payload.records[0].payload.reservation_request
    .reservation_request_digest, first.reservation_request_digest);

  fx.backend.snapshot = authenticatedSuccessor(fx, []);
  assert.throws(
    () => projectPhysicalResourceRequestRegistry(fx.registry),
    (error) => error.code === "resource_request_registry_history_rewrite",
  );
});

test("ambiguous commits reconcile exactly while stale commits fail closed", () => {
  const fx = fixture();
  const reservationRequest = request(fx.bundle);
  fx.backend.next_cas = "ambiguous_after";
  assert.throws(
    () => prepare(fx, reservationRequest),
    (error) => error.code === "resource_request_registry_cas_ambiguous",
  );
  assert.equal(projectPhysicalResourceArbiterStore(fx.store).generation, 0);
  const prepared = prepare(fx, reservationRequest);
  assert.equal(prepared.disposition, "existing_prepared");

  fx.backend.next_cas = "conflict";
  assert.throws(
    () => prepare(fx, request(fx.bundle, "two")),
    (error) => error.code === "resource_request_registry_cas_stale",
  );
  assert.equal(projectPhysicalResourceRequestRegistry(fx.registry).record_count, 1);

  const receipt = admitPhysicalResourceArbiterRequest(fx.admissionPort, {
    reservation_request: reservationRequest,
  });
  fx.backend.next_cas = "ambiguous_after";
  assert.throws(
    () => finalize(fx, prepared, receipt),
    (error) => error.code === "resource_request_registry_cas_ambiguous",
  );
  assert.equal(finalize(fx, prepared, receipt).disposition, "existing_finalized");
});

test("async, hostile, and reentrant state callbacks fail closed and release guards", () => {
  const fx = fixture();
  fx.backend.before_read = () => projectPhysicalResourceRequestRegistry(fx.registry);
  assert.throws(
    () => projectPhysicalResourceRequestRegistry(fx.registry),
    (error) => error.code === "resource_request_registry_reentrant",
  );
  assert.equal(projectPhysicalResourceRequestRegistry(fx.registry).generation, 0);

  for (const mode of ["async", "hostile"]) {
    const backend = registryBackend();
    backend.next_cas = mode;
    assert.throws(
      () => attachRegistry(fx, { backend, port_id: `request_registry_${mode}` }),
      (error) => error.code === "resource_request_registry_cas_ambiguous",
    );
    assert.equal(backend.snapshot.state, null);
  }

  const asyncReadPort = createPhysicalResourceRequestRegistryStatePort({
    port_id: "request_registry_async_read",
    registry_domain_digest: digest("request-registry-domain"),
    read_current: async () => ({ version: 1, state: null, checkpoint: null }),
    compare_and_set() { throw new Error("must not run"); },
  });
  assert.throws(
    () => createPhysicalResourceRequestRegistry(registryOptions(
      fx,
      asyncReadPort,
      fx.material,
      fx.trustedSigners,
      undefined,
    )),
    (error) => error.code === "resource_request_registry_state_unavailable",
  );

  let getterCalled = false;
  const hostileInput = { resource_bundle: fx.bundle };
  Object.defineProperty(hostileInput, "reservation_request", {
    enumerable: true,
    get() {
      getterCalled = true;
      return request(fx.bundle);
    },
  });
  assert.throws(() => preparePhysicalResourceRequestRegistration(fx.registry, hostileInput),
    /enumerable data field/);
  assert.equal(getterCalled, false);
});

test("restart checkpoints reject rollback, authenticated forks, and state tampering", () => {
  const fx = fixture();
  const genesis = clone(fx.backend.snapshot);
  prepare(fx, request(fx.bundle, "one"));
  const latest = clone(fx.backend.snapshot);
  const checkpoint = projectPhysicalResourceRequestRegistry(fx.registry).checkpoint;
  assert.ok(attachRegistry(fx, {
    backend: fx.backend,
    port_id: "request_registry_restart",
    restart_checkpoint: checkpoint,
  }).registry);
  assert.throws(
    () => attachRegistry(fx, { backend: fx.backend, port_id: "request_registry_no_anchor" }),
    (error) => error.code === "resource_request_registry_restart_checkpoint_required",
  );
  assert.throws(
    () => attachRegistry(fx, {
      backend: fx.backend,
      port_id: "request_registry_old_anchor",
      restart_checkpoint: genesis.checkpoint,
    }),
    (error) => error.code === "resource_request_registry_rollback",
  );

  fx.backend.snapshot = genesis;
  assert.throws(
    () => projectPhysicalResourceRequestRegistry(fx.registry),
    (error) => error.code === "resource_request_registry_rollback",
  );
  fx.backend.snapshot = latest;
  assert.equal(projectPhysicalResourceRequestRegistry(fx.registry).generation, 1);

  const alternateBackend = registryBackend(genesis);
  const alternate = attachRegistry(fx, {
    backend: alternateBackend,
    port_id: "request_registry_fork_writer",
    restart_checkpoint: genesis.checkpoint,
  });
  preparePhysicalResourceRequestRegistration(alternate.registry, {
    reservation_request: request(fx.bundle, "fork"),
    resource_bundle: fx.bundle,
  });
  fx.backend.snapshot = clone(alternateBackend.snapshot);
  assert.throws(
    () => projectPhysicalResourceRequestRegistry(fx.registry),
    (error) => error.code === "resource_request_registry_fork",
  );

  fx.backend.snapshot = latest;
  const tampered = clone(latest);
  const signature = tampered.state.authentication.signature;
  tampered.state.authentication.signature = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  fx.backend.snapshot = tampered;
  assert.throws(
    () => projectPhysicalResourceRequestRegistry(fx.registry),
    (error) => error.code === "resource_request_registry_state_invalid",
  );
});

test("signer rotation verifies old records and forbids a forward epoch rollback", () => {
  const fx = fixture();
  prepare(fx, request(fx.bundle, "old"));
  const epochOneSnapshot = clone(fx.backend.snapshot);
  const epochOneCheckpoint = clone(epochOneSnapshot.checkpoint);
  const epochTwo = signerMaterial(2);
  const rotated = attachRegistry(fx, {
    backend: fx.backend,
    material: epochTwo,
    trusted_signers: [fx.material.trust, epochTwo.trust],
    port_id: "request_registry_epoch_two",
    restart_checkpoint: epochOneCheckpoint,
  });
  preparePhysicalResourceRequestRegistration(rotated.registry, {
    reservation_request: request(fx.bundle, "new"),
    resource_bundle: fx.bundle,
  });
  assert.equal(projectPhysicalResourceRequestRegistry(rotated.registry).current_signer_epoch, 2);
  assert.deepEqual(fx.backend.snapshot.state.payload.records.map((record) => (
    record.authentication.signer_epoch
  )), [2, 1]);

  const oldWriterBackend = registryBackend(epochOneSnapshot);
  const oldWriter = attachRegistry(fx, {
    backend: oldWriterBackend,
    port_id: "request_registry_old_writer",
    restart_checkpoint: epochOneCheckpoint,
  });
  preparePhysicalResourceRequestRegistration(oldWriter.registry, {
    reservation_request: request(fx.bundle, "rollback"),
    resource_bundle: fx.bundle,
  });
  fx.backend.snapshot = clone(oldWriterBackend.snapshot);
  assert.throws(
    () => projectPhysicalResourceRequestRegistry(rotated.registry),
    (error) => error.code === "resource_request_registry_signer_rollback",
  );
});

test("finalize rejects admission drift and restart reconciliation never assumes enqueue", () => {
  const fx = fixture();
  const reservationRequest = request(fx.bundle);
  const prepared = prepare(fx, reservationRequest);
  const checkpoint = projectPhysicalResourceRequestRegistry(fx.registry).checkpoint;
  const receipt = admitPhysicalResourceArbiterRequest(fx.admissionPort, {
    reservation_request: reservationRequest,
  });
  const drifted = clone(receipt);
  drifted.binding.commit_head_digest = digest("forged-head");
  assert.throws(
    () => finalize(fx, prepared, drifted),
    (error) => error.code === "resource_arbiter_admission_binding_invalid",
  );
  assert.equal(reconcilePhysicalResourceRequestRegistration(fx.registry, {
    reservation_request_id: reservationRequest.reservation_request_id,
    reservation_request_digest: reservationRequest.reservation_request_digest,
  }).registration_state, "prepared");
  assert.throws(
    () => finalizePhysicalResourceRequestRegistration(fx.registry, {
      prepare_capability: { ...prepared.prepare_capability },
      admission_binding: receipt.binding,
      ticket: receipt.ticket,
      arbiter_commit: receipt.arbiter_commit,
    }),
    (error) => error.code === "resource_request_registry_capability_invalid",
  );

  const restarted = attachRegistry(fx, {
    backend: fx.backend,
    port_id: "request_registry_reconcile_restart",
    restart_checkpoint: checkpoint,
  });
  const reconciled = reconcilePhysicalResourceRequestRegistration(restarted.registry, {
    reservation_request_id: reservationRequest.reservation_request_id,
    reservation_request_digest: reservationRequest.reservation_request_digest,
  });
  assert.equal(reconciled.registration_state, "prepared");
  assert.equal(reconciled.requires_arbiter_reconciliation, true);
  const capability = rehydratePhysicalResourceRequestRegistrationCapability(restarted.registry, {
    reservation_request_id: reservationRequest.reservation_request_id,
    reservation_request_digest: reservationRequest.reservation_request_digest,
  });
  assert.equal(finalizePhysicalResourceRequestRegistration(restarted.registry, {
    prepare_capability: capability,
    admission_binding: receipt.binding,
    ticket: receipt.ticket,
    arbiter_commit: receipt.arbiter_commit,
  }).disposition, "created_finalized");
});
