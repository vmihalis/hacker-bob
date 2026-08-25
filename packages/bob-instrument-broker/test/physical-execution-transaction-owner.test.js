"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const physicalExecutionTransactionOwnerModule = require(
  "../lib/physical-execution-transaction-owner.js"
);
const {
  PHYSICAL_EXECUTION_TRANSACTION_OWNER_ASSURANCE,
  PHYSICAL_EXECUTION_TRANSACTION_OWNER_VERSION,
  PHYSICAL_EXECUTION_TRANSACTION_PHASES,
  PHYSICAL_EXECUTION_TRANSACTION_PROTOCOL,
  PHYSICAL_EXECUTION_TRANSACTION_RECORD_ASSURANCE,
  PRODUCTION_BLOCKERS,
  assertPhysicalExecutionTransactionOwner,
  assertPhysicalExecutionTransactionOwnerProductionReady,
  assertPhysicalExecutionTransactionPhaseSuccessor,
  assertPhysicalExecutionTransactionTransition,
  claimOrReadPhysicalExecutionTransaction,
  createPhysicalExecutionTransactionConformanceOwner,
  derivePhysicalExecutionTransactionRecovery,
  normalizePhysicalExecutionCompositeBinding,
  normalizePhysicalExecutionTransactionRecord,
  physicalExecutionTransactionOwnerReadiness,
  readPhysicalExecutionTerminalOutbox,
  readPhysicalExecutionTransaction,
  redeliverPhysicalExecutionTerminalOutbox,
  transitionPhysicalExecutionTransaction,
} = physicalExecutionTransactionOwnerModule;
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const VERSION = PHYSICAL_EXECUTION_TRANSACTION_OWNER_VERSION;
const PROTOCOL = PHYSICAL_EXECUTION_TRANSACTION_PROTOCOL;

function digest(label) {
  return hashCanonicalJson({ fixture: label });
}

function bindingInput(overrides = {}) {
  return {
    version: VERSION,
    protocol: PROTOCOL,
    transaction_ref: "transaction:test-0001",
    execution_lineage_digest: digest("execution-lineage"),
    session_nucleus_hash: digest("session-nucleus"),
    attempt_ref: "attempt:test-0001",
    replay_identity_digest: digest("replay-identity"),
    execution_request_digest: digest("execution-request"),
    authority_admission_digest: digest("authority-admission"),
    capability_grant_digest: digest("capability-grant"),
    commit_go_digest: digest("commit-go"),
    dispatch_admission_digest: digest("dispatch-admission"),
    provider_worker_vault_binding_digest: digest("provider-worker-vault-binding"),
    transaction_capability_digest: digest("transaction-capability"),
    resource_admission_digest: digest("resource-admission"),
    resource_fence_digest: digest("resource-fence"),
    lease_ref: "lease:test-0001",
    lease_digest: digest("lease"),
    bootstrap_sequence_digest: digest("bootstrap-sequence"),
    compiler_manifest_digest: digest("compiler-manifest"),
    compiler_registry_digest: digest("compiler-registry"),
    requested_effects_digest: digest("requested-effects"),
    compiled_operation_digest: digest("compiled-operation"),
    compiled_command_digest: digest("compiled-command"),
    active_command_input_digest: digest("active-command-input"),
    cleanup_command_input_digest: digest("cleanup-command-input"),
    native_launch_ticket_digest: digest("native-launch-ticket"),
    worker_bundle_digest: digest("worker-bundle"),
    worker_launch_digest: digest("worker-launch"),
    worker_fence_digest: digest("worker-fence"),
    transport_binding_digest: digest("transport-binding"),
    vault_ingest_capability_digest: digest("vault-ingest-capability"),
    artifact_allocation_digest: digest("artifact-allocation"),
    safety_plan_digest: digest("safety-plan"),
    cleanup_plan_digest: digest("cleanup-plan"),
    clock_identity_digest: digest("clock-identity"),
    deadline_binding_digest: digest("deadline-binding"),
    vault_reservation_ref: "vault-reservation:test-0001",
    vault_reservation_digest: digest("vault-reservation"),
    restoration_plan_digest: digest("restoration-plan"),
    terminal_projection_plan_digest: digest("terminal-projection-plan"),
    ...overrides,
  };
}

function ownerConfig(overrides = {}) {
  return {
    version: VERSION,
    kind: "physical_execution_transaction_conformance_owner_config",
    test_only: true,
    maximum_transactions: 16,
    simulate_claim_response_loss_once: false,
    simulate_transition_response_loss_generation: null,
    simulate_outbox_redelivery_response_loss_once: false,
    ...overrides,
  };
}

function createOwner(overrides = {}) {
  return createPhysicalExecutionTransactionConformanceOwner(ownerConfig(overrides));
}

function claimInput(binding) {
  return {
    version: VERSION,
    kind: "physical_execution_transaction_claim",
    binding,
  };
}

function readInput(binding) {
  return {
    version: VERSION,
    kind: "physical_execution_transaction_read",
    transaction_ref: binding.transaction_ref,
    execution_lineage_digest: binding.execution_lineage_digest,
    transaction_key_digest: binding.transaction_key_digest,
    composite_binding_digest: binding.composite_binding_digest,
  };
}

function recordInput(previous, phase, overrides = {}) {
  const generation = previous.generation + 1;
  const value = {
    version: VERSION,
    protocol: PROTOCOL,
    kind: "physical_execution_transaction_record",
    transaction_ref: previous.transaction_ref,
    execution_lineage_digest: previous.execution_lineage_digest,
    transaction_key_digest: previous.transaction_key_digest,
    composite_binding_digest: previous.composite_binding_digest,
    record_ref: `transaction-record:test-${generation}-${phase.toLowerCase()}`,
    generation,
    predecessor_record_digest: previous.record_digest,
    phase,
    claim_receipt_digest: previous.claim_receipt_digest,
    go_durable_receipt_digest: previous.go_durable_receipt_digest,
    effect_arm_receipt_digest: previous.effect_arm_receipt_digest,
    effect_disposition: "not_started",
    semantic_disposition: "unavailable",
    effect_evidence_digest: null,
    vault_artifact_ref: null,
    vault_receipt_digest: null,
    restoration_proof_digest: null,
    restoration_claim_digest: previous.restoration_claim_digest,
    terminal_disposition: "pending",
    terminal_proof_digest: null,
    no_effect_proof_digest: null,
    capabilities_closed: false,
    durability_assurance: PHYSICAL_EXECUTION_TRANSACTION_RECORD_ASSURANCE,
    durability_evidence_digest: null,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
  };
  if (phase === "GO_DURABLE") {
    value.go_durable_receipt_digest = digest(`go-durable-receipt-${generation}`);
  }
  if (phase === "EFFECT_ARMED") value.effect_disposition = "armed";
  if (phase === "EFFECT_ARMED") {
    value.effect_arm_receipt_digest = digest(`effect-arm-receipt-${generation}`);
  }
  if (phase === "EFFECT_RECORDED") {
    value.effect_disposition = "recorded";
    value.semantic_disposition = "validated_success";
    value.effect_evidence_digest = digest(`effect-evidence-${generation}`);
  }
  if (phase === "EFFECT_UNKNOWN") {
    value.effect_disposition = "ambiguous";
    value.semantic_disposition = "nonsemantic_raw_custody";
    value.effect_evidence_digest = digest(`effect-evidence-${generation}`);
  }
  if (phase === "VAULT_COMMITTED" || phase === "RESTORING" || phase === "TERMINAL") {
    value.effect_disposition = previous.effect_disposition;
    value.semantic_disposition = previous.semantic_disposition;
    value.effect_evidence_digest = previous.effect_evidence_digest;
    value.vault_artifact_ref = previous.vault_artifact_ref;
    value.vault_receipt_digest = previous.vault_receipt_digest;
  }
  if (phase === "VAULT_COMMITTED") {
    value.vault_artifact_ref = `artifact:v1:test-${generation}`;
    value.vault_receipt_digest = digest(`vault-receipt-${generation}`);
  }
  if (phase === "TERMINAL") {
    value.restoration_proof_digest = digest(`restoration-proof-${generation}`);
    value.terminal_proof_digest = digest(`terminal-proof-${generation}`);
    value.terminal_disposition = previous.semantic_disposition === "validated_success"
      ? "completed"
      : "ambiguous_quarantined";
    value.capabilities_closed = true;
  }
  if (phase === "RESTORING") {
    value.restoration_claim_digest = digest(`restoration-claim-${generation}`);
  }
  return { ...value, ...overrides };
}

function rejectedRecordInput(previous, overrides = {}) {
  return recordInput(previous, "TERMINAL", {
    effect_disposition: "rejected_no_effect",
    semantic_disposition: "rejected_no_effect",
    effect_evidence_digest: null,
    vault_artifact_ref: null,
    vault_receipt_digest: null,
    restoration_proof_digest: null,
    terminal_disposition: "rejected_no_effect",
    terminal_proof_digest: digest(`rejected-no-effect-${previous.generation + 1}`),
    no_effect_proof_digest: digest(`no-effect-proof-${previous.generation + 1}`),
    capabilities_closed: true,
    ...overrides,
  });
}

function normalizeNext(previous, phase, overrides = {}) {
  return normalizePhysicalExecutionTransactionRecord(recordInput(previous, phase, overrides));
}

function transitionInput(binding, previous, next) {
  return {
    version: VERSION,
    kind: "physical_execution_transaction_transition",
    transaction_ref: binding.transaction_ref,
    execution_lineage_digest: binding.execution_lineage_digest,
    transaction_key_digest: binding.transaction_key_digest,
    composite_binding_digest: binding.composite_binding_digest,
    expected_generation: previous.generation,
    expected_predecessor_record_digest: previous.record_digest,
    next_record: next,
  };
}

function commit(owner, binding, previous, next) {
  return transitionPhysicalExecutionTransaction(
    owner,
    transitionInput(binding, previous, next),
  );
}

function claimAndRead(owner, binding) {
  claimOrReadPhysicalExecutionTransaction(owner, claimInput(binding));
  return readPhysicalExecutionTransaction(owner, readInput(binding));
}

function completedChain(owner, binding, { ambiguous = false } = {}) {
  let record = claimAndRead(owner, binding);
  for (const phase of [
    "GO_DURABLE",
    "EFFECT_ARMED",
    ambiguous ? "EFFECT_UNKNOWN" : "EFFECT_RECORDED",
    "VAULT_COMMITTED",
    "RESTORING",
    "TERMINAL",
  ]) {
    const next = normalizeNext(record, phase);
    const receipt = commit(owner, binding, record, next);
    record = next;
    if (phase === "TERMINAL") return { record, receipt };
  }
  throw new Error("chain did not terminate");
}

function withoutDigest(record, changes) {
  const value = { ...record, ...changes };
  delete value.record_digest;
  return value;
}

function assertNoForbiddenSurface(value, path = "projection") {
  if (value === null || typeof value !== "object") return;
  assert.equal(Buffer.isBuffer(value), false, `${path} exposed bytes`);
  for (const key of Reflect.ownKeys(value)) {
    assert.equal(typeof key, "string", `${path} exposed a symbol`);
    assert.doesNotMatch(
      key,
      /(?:raw|bytes|path|frame|callback|module|provider_selector|signer|private_key|secret_key|key_material)/u,
      `${path}.${key} exposed a forbidden surface`,
    );
    const child = value[key];
    assert.notEqual(typeof child, "function", `${path}.${key} exposed a function`);
    assertNoForbiddenSurface(child, `${path}.${key}`);
  }
}

test("exports one exact pure phase-successor validator and accepts every legal edge", () => {
  const descriptor = Object.getOwnPropertyDescriptor(
    physicalExecutionTransactionOwnerModule,
    "assertPhysicalExecutionTransactionPhaseSuccessor",
  );
  assert.deepEqual(descriptor, {
    value: assertPhysicalExecutionTransactionPhaseSuccessor,
    writable: false,
    enumerable: true,
    configurable: false,
  });
  assert.equal(Object.isFrozen(physicalExecutionTransactionOwnerModule), true);

  const legalEdges = [
    ["CLAIMED", "GO_DURABLE"],
    ["CLAIMED", "TERMINAL"],
    ["GO_DURABLE", "EFFECT_ARMED"],
    ["GO_DURABLE", "TERMINAL"],
    ["EFFECT_ARMED", "EFFECT_RECORDED"],
    ["EFFECT_ARMED", "EFFECT_UNKNOWN"],
    ["EFFECT_RECORDED", "VAULT_COMMITTED"],
    ["EFFECT_UNKNOWN", "VAULT_COMMITTED"],
    ["VAULT_COMMITTED", "RESTORING"],
    ["RESTORING", "TERMINAL"],
  ];
  for (const [previousPhase, nextPhase] of legalEdges) {
    assert.equal(
      assertPhysicalExecutionTransactionPhaseSuccessor(previousPhase, nextPhase),
      nextPhase,
      `${previousPhase} -> ${nextPhase}`,
    );
  }
});

test("phase-successor validator rejects every illegal, skipped, and terminal edge", () => {
  const legalEdges = new Set([
    "CLAIMED>GO_DURABLE", "CLAIMED>TERMINAL",
    "GO_DURABLE>EFFECT_ARMED", "GO_DURABLE>TERMINAL",
    "EFFECT_ARMED>EFFECT_RECORDED", "EFFECT_ARMED>EFFECT_UNKNOWN",
    "EFFECT_RECORDED>VAULT_COMMITTED", "EFFECT_UNKNOWN>VAULT_COMMITTED",
    "VAULT_COMMITTED>RESTORING", "RESTORING>TERMINAL",
  ]);
  let checked = 0;
  for (const previousPhase of PHYSICAL_EXECUTION_TRANSACTION_PHASES) {
    for (const nextPhase of PHYSICAL_EXECUTION_TRANSACTION_PHASES) {
      if (legalEdges.has(`${previousPhase}>${nextPhase}`)) continue;
      assert.throws(
        () => assertPhysicalExecutionTransactionPhaseSuccessor(previousPhase, nextPhase),
        { code: "physical_execution_transaction_transition_illegal" },
        `${previousPhase} -> ${nextPhase}`,
      );
      checked += 1;
    }
  }
  assert.equal(checked, 54);
});

test("phase-successor validator rejects hostile values without observation or coercion", () => {
  let traps = 0;
  const hostileProxy = new Proxy(Object.create(null), {
    get() {
      traps += 1;
      throw new Error("must not observe proxy");
    },
    getPrototypeOf() {
      traps += 1;
      throw new Error("must not observe proxy prototype");
    },
  });
  let coercions = 0;
  const hostileStringObject = Object.create(String.prototype);
  Object.defineProperty(hostileStringObject, "valueOf", {
    enumerable: true,
    get() {
      coercions += 1;
      throw new Error("must not read coercion accessor");
    },
  });
  const hostileValues = [
    "",
    "NOT_A_PHASE",
    "__proto__",
    undefined,
    null,
    true,
    1,
    1n,
    Symbol("phase"),
    hostileProxy,
    hostileStringObject,
    () => "CLAIMED",
  ];
  for (const value of hostileValues) {
    assert.throws(
      () => assertPhysicalExecutionTransactionPhaseSuccessor(value, "GO_DURABLE"),
      { code: "physical_execution_transaction_predecessor_phase_invalid" },
    );
    assert.throws(
      () => assertPhysicalExecutionTransactionPhaseSuccessor("CLAIMED", value),
      { code: "physical_execution_transaction_successor_phase_invalid" },
    );
  }
  assert.equal(traps, 0);
  assert.equal(coercions, 0);

  const originalIndexOf = Array.prototype.indexOf;
  let result;
  let invalidPhaseError;
  try {
    Array.prototype.indexOf = () => {
      throw new Error("must use captured phase membership primitive");
    };
    result = assertPhysicalExecutionTransactionPhaseSuccessor("CLAIMED", "GO_DURABLE");
    try {
      assertPhysicalExecutionTransactionPhaseSuccessor("__proto__", "GO_DURABLE");
    } catch (error) {
      invalidPhaseError = error;
    }
  } finally {
    Array.prototype.indexOf = originalIndexOf;
  }
  assert.equal(result, "GO_DURABLE");
  assert.equal(
    invalidPhaseError.code,
    "physical_execution_transaction_predecessor_phase_invalid",
  );

  assert.throws(
    () => assertPhysicalExecutionTransactionPhaseSuccessor(),
    { code: "physical_execution_transaction_phase_successor_argument_count_invalid" },
  );
  assert.throws(
    () => assertPhysicalExecutionTransactionPhaseSuccessor("CLAIMED"),
    { code: "physical_execution_transaction_phase_successor_argument_count_invalid" },
  );
  assert.throws(
    () => assertPhysicalExecutionTransactionPhaseSuccessor(
      "CLAIMED",
      "GO_DURABLE",
      "ignored",
    ),
    { code: "physical_execution_transaction_phase_successor_argument_count_invalid" },
  );
});

test("normalizes one exact immutable provider-neutral composite binding and digest", () => {
  const basis = bindingInput();
  const normalized = normalizePhysicalExecutionCompositeBinding(basis);
  assert.equal(Object.isFrozen(normalized), true);
  assert.match(normalized.composite_binding_digest, /^[a-f0-9]{64}$/u);
  assert.match(normalized.transaction_key_digest, /^[a-f0-9]{64}$/u);
  assert.deepEqual(normalizePhysicalExecutionCompositeBinding(normalized), normalized);
  assert.equal(Object.hasOwn(normalized, "provider_id"), false);
  assert.equal(Object.hasOwn(normalized, "operation_id"), false);
  assert.equal(Object.hasOwn(normalized, "module_path"), false);
  assert.equal(Object.hasOwn(normalized, "signer"), false);
  const expectedTransactionKey = hashCanonicalJson({
    domain: "hacker-bob/physical-execution-transaction-key/v1",
    session_nucleus_hash: basis.session_nucleus_hash,
    execution_lineage_digest: basis.execution_lineage_digest,
  });
  assert.equal(normalized.transaction_key_digest, expectedTransactionKey);
  assert.equal(normalized.composite_binding_digest, hashCanonicalJson({
    domain: "hacker-bob/physical-execution-composite-binding/v1",
    ...basis,
    transaction_key_digest: expectedTransactionKey,
  }));

  assert.throws(
    () => normalizePhysicalExecutionCompositeBinding({
      ...normalized,
      composite_binding_digest: digest("wrong-binding"),
    }),
    { code: "physical_execution_composite_binding_digest_mismatch" },
  );
  assert.throws(
    () => normalizePhysicalExecutionCompositeBinding({
      ...normalized,
      transaction_key_digest: digest("wrong-transaction-key"),
    }),
    { code: "physical_execution_composite_binding_transaction_key_mismatch" },
  );
});

test("binding normalization rejects proxies, accessors, symbols, thenables, and forbidden fields", () => {
  const source = bindingInput();
  assert.throws(
    () => normalizePhysicalExecutionCompositeBinding(new Proxy(source, {})),
    { code: "physical_execution_composite_binding_must_be_closed_data" },
  );

  let getterInvoked = false;
  const accessor = { ...source };
  Object.defineProperty(accessor, "execution_lineage_digest", {
    enumerable: true,
    get() {
      getterInvoked = true;
      throw new Error("must not run");
    },
  });
  assert.throws(
    () => normalizePhysicalExecutionCompositeBinding(accessor),
    { code: "physical_execution_composite_binding_execution_lineage_digest_must_be_enumerable_data" },
  );
  assert.equal(getterInvoked, false);

  const symbolic = { ...source, [Symbol("secret")]: digest("secret") };
  assert.throws(
    () => normalizePhysicalExecutionCompositeBinding(symbolic),
    { code: "physical_execution_composite_binding_symbol_field_forbidden" },
  );
  for (const field of ["then", "raw_bytes", "device_path", "private_key", "callback", "module_path", "provider_id"]) {
    assert.throws(
      () => normalizePhysicalExecutionCompositeBinding({ ...source, [field]: () => {} }),
      { code: "physical_execution_composite_binding_unknown_field" },
    );
  }
});

test("normalizes exact immutable non-durable conformance records", () => {
  const owner = createOwner();
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  const record = claimAndRead(owner, binding);
  assert.equal(Object.isFrozen(record), true);
  assert.equal(record.phase, "CLAIMED");
  assert.equal(record.generation, 1);
  assert.equal(record.predecessor_record_digest, null);
  assert.equal(record.durability_assurance, PHYSICAL_EXECUTION_TRANSACTION_RECORD_ASSURANCE);
  assert.equal(record.durability_evidence_digest, null);
  assert.equal(record.production_ready, false);
  assert.deepEqual(normalizePhysicalExecutionTransactionRecord(record), record);

  assert.throws(
    () => normalizePhysicalExecutionTransactionRecord(withoutDigest(record, {
      durability_evidence_digest: digest("forged-durability"),
    })),
    { code: "physical_execution_transaction_record_conformance_assurance_invalid" },
  );
  assert.throws(
    () => normalizePhysicalExecutionTransactionRecord({ ...record, production_ready: true }),
    { code: "physical_execution_transaction_record_conformance_assurance_invalid" },
  );
});

test("record normalization rejects hostile objects and unknown effect surfaces", () => {
  const owner = createOwner();
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  const record = claimAndRead(owner, binding);
  assert.throws(
    () => normalizePhysicalExecutionTransactionRecord(new Proxy(record, {})),
    { code: "physical_execution_transaction_record_must_be_closed_data" },
  );
  let getterInvoked = false;
  const accessor = { ...record };
  Object.defineProperty(accessor, "phase", {
    enumerable: true,
    get() {
      getterInvoked = true;
      throw new Error("must not run");
    },
  });
  assert.throws(
    () => normalizePhysicalExecutionTransactionRecord(accessor),
    { code: "physical_execution_transaction_record_phase_must_be_enumerable_data" },
  );
  assert.equal(getterInvoked, false);
  assert.throws(
    () => normalizePhysicalExecutionTransactionRecord({ ...record, [Symbol("secret")]: true }),
    { code: "physical_execution_transaction_record_symbol_field_forbidden" },
  );
  for (const field of ["then", "response_bytes", "artifact_path", "key", "frame", "callback", "provider_selector", "signer"]) {
    assert.throws(
      () => normalizePhysicalExecutionTransactionRecord({ ...record, [field]: Buffer.from("x") }),
      { code: "physical_execution_transaction_record_unknown_field" },
    );
  }
});

test("public normalizers reject extra diagnostic labels without coercion or caller text", () => {
  const owner = createOwner();
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  const record = claimAndRead(owner, binding);
  const secret = "caller_secret_path";
  let invocations = 0;
  const hostileLabel = {
    [Symbol.toPrimitive]() {
      invocations += 1;
      return secret;
    },
  };
  Object.defineProperty(hostileLabel, "toString", {
    get() {
      invocations += 1;
      throw new Error("label getter must not run");
    },
  });
  let bindingError;
  let recordError;
  try {
    normalizePhysicalExecutionCompositeBinding(binding, hostileLabel);
  } catch (error) {
    bindingError = error;
  }
  try {
    normalizePhysicalExecutionTransactionRecord(record, hostileLabel);
  } catch (error) {
    recordError = error;
  }
  assert.equal(invocations, 0);
  assert.equal(
    bindingError.code,
    "physical_execution_composite_binding_argument_count_invalid",
  );
  assert.equal(
    recordError.code,
    "physical_execution_transaction_record_argument_count_invalid",
  );
  for (const error of [bindingError, recordError]) {
    assert.equal(error.message.includes(secret), false);
    assert.equal(error.code.includes(secret), false);
  }
});

test("validates every legal success, ambiguity, and pre-effect rejection edge", () => {
  const owner = createOwner();
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  let previous = claimAndRead(owner, binding);
  for (const phase of [
    "GO_DURABLE", "EFFECT_ARMED", "EFFECT_RECORDED",
    "VAULT_COMMITTED", "RESTORING", "TERMINAL",
  ]) {
    const next = normalizeNext(previous, phase);
    assert.equal(
      assertPhysicalExecutionTransactionTransition(previous, next).record_digest,
      next.record_digest,
    );
    previous = next;
  }
  assert.equal(previous.terminal_disposition, "completed");

  const ambiguousOwner = createOwner();
  const ambiguousBinding = normalizePhysicalExecutionCompositeBinding(bindingInput({
    transaction_ref: "transaction:test-ambiguous",
    execution_lineage_digest: digest("ambiguous-lineage"),
  }));
  previous = claimAndRead(ambiguousOwner, ambiguousBinding);
  for (const phase of [
    "GO_DURABLE", "EFFECT_ARMED", "EFFECT_UNKNOWN",
    "VAULT_COMMITTED", "RESTORING", "TERMINAL",
  ]) {
    const next = normalizeNext(previous, phase);
    assert.equal(
      assertPhysicalExecutionTransactionTransition(previous, next).record_digest,
      next.record_digest,
    );
    previous = next;
  }
  assert.equal(previous.terminal_disposition, "ambiguous_quarantined");
  assert.equal(previous.semantic_disposition, "nonsemantic_raw_custody");

  for (const rejectAfterGo of [false, true]) {
    const rejectOwner = createOwner();
    const suffix = rejectAfterGo ? "go" : "claim";
    const rejectBinding = normalizePhysicalExecutionCompositeBinding(bindingInput({
      transaction_ref: `transaction:test-reject-${suffix}`,
      execution_lineage_digest: digest(`reject-lineage-${suffix}`),
    }));
    let preEffect = claimAndRead(rejectOwner, rejectBinding);
    if (rejectAfterGo) preEffect = normalizeNext(preEffect, "GO_DURABLE");
    const rejected = normalizePhysicalExecutionTransactionRecord(rejectedRecordInput(preEffect));
    assert.equal(
      assertPhysicalExecutionTransactionTransition(preEffect, rejected).record_digest,
      rejected.record_digest,
    );
  }
});

test("rejects every phase edge outside the closed transition graph", () => {
  const owner = createOwner();
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  const phaseSamples = new Map();
  let previous = claimAndRead(owner, binding);
  phaseSamples.set(previous.phase, previous);
  for (const phase of [
    "GO_DURABLE", "EFFECT_ARMED", "EFFECT_RECORDED",
    "VAULT_COMMITTED", "RESTORING", "TERMINAL",
  ]) {
    previous = normalizeNext(previous, phase);
    phaseSamples.set(phase, previous);
  }
  const ambiguous = normalizePhysicalExecutionTransactionRecord(recordInput(
    phaseSamples.get("EFFECT_ARMED"),
    "EFFECT_UNKNOWN",
  ));
  phaseSamples.set("EFFECT_UNKNOWN", ambiguous);

  const legal = new Set([
    "CLAIMED>GO_DURABLE", "CLAIMED>TERMINAL",
    "GO_DURABLE>EFFECT_ARMED", "GO_DURABLE>TERMINAL",
    "EFFECT_ARMED>EFFECT_RECORDED", "EFFECT_ARMED>EFFECT_UNKNOWN",
    "EFFECT_RECORDED>VAULT_COMMITTED", "EFFECT_UNKNOWN>VAULT_COMMITTED",
    "VAULT_COMMITTED>RESTORING", "RESTORING>TERMINAL",
  ]);
  let checked = 0;
  for (const from of PHYSICAL_EXECUTION_TRANSACTION_PHASES) {
    for (const to of PHYSICAL_EXECUTION_TRANSACTION_PHASES) {
      if (legal.has(`${from}>${to}`)) continue;
      const prior = phaseSamples.get(from);
      const sample = phaseSamples.get(to);
      const candidate = normalizePhysicalExecutionTransactionRecord(withoutDigest(sample, {
        generation: prior.generation + 1,
        predecessor_record_digest: prior.record_digest,
        record_ref: `transaction-record:illegal-${from.toLowerCase()}-${to.toLowerCase()}`,
      }));
      assert.throws(
        () => assertPhysicalExecutionTransactionTransition(prior, candidate),
        { code: "physical_execution_transaction_transition_illegal" },
        `${from} -> ${to}`,
      );
      checked += 1;
    }
  }
  assert.equal(checked, 54);
});

test("requires exact predecessor generation and digest CAS", () => {
  const owner = createOwner();
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  const claimed = claimAndRead(owner, binding);
  const go = normalizeNext(claimed, "GO_DURABLE");
  assert.throws(
    () => assertPhysicalExecutionTransactionTransition(claimed, withoutDigest(go, {
      generation: 3,
    })),
    { code: "physical_execution_transaction_cas_mismatch" },
  );
  assert.throws(
    () => assertPhysicalExecutionTransactionTransition(claimed, withoutDigest(go, {
      predecessor_record_digest: digest("wrong-predecessor"),
    })),
    { code: "physical_execution_transaction_cas_mismatch" },
  );
});

test("every transaction commitment is immutable across its successor edges", () => {
  const owner = createOwner();
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  const claimed = claimAndRead(owner, binding);
  const go = normalizeNext(claimed, "GO_DURABLE");
  const armed = normalizeNext(go, "EFFECT_ARMED");
  const recorded = normalizeNext(armed, "EFFECT_RECORDED");
  const vaulted = normalizeNext(recorded, "VAULT_COMMITTED");
  const restoring = normalizeNext(vaulted, "RESTORING");
  const terminal = normalizeNext(restoring, "TERMINAL");

  const forks = [
    [claimed, go, { transaction_key_digest: digest("fork-transaction-key") },
      "physical_execution_transaction_key_fork"],
    [claimed, go, { claim_receipt_digest: digest("fork-claim") },
      "physical_execution_claim_receipt_fork"],
    [go, armed, { go_durable_receipt_digest: digest("fork-go") },
      "physical_execution_go_receipt_fork"],
    [armed, recorded, { effect_arm_receipt_digest: digest("fork-arm") },
      "physical_execution_effect_arm_receipt_fork"],
    [recorded, vaulted, { effect_evidence_digest: digest("fork-evidence") },
      "physical_execution_evidence_fork"],
    [vaulted, restoring, { vault_artifact_ref: "artifact:v1:forked" },
      "physical_execution_vault_fork"],
    [vaulted, restoring, { vault_receipt_digest: digest("fork-vault-receipt") },
      "physical_execution_vault_fork"],
    [restoring, terminal, { restoration_claim_digest: digest("fork-restoration-claim") },
      "physical_execution_restoration_claim_fork"],
  ];
  for (const [previous, next, mutation, code] of forks) {
    const candidate = normalizePhysicalExecutionTransactionRecord(withoutDigest(next, mutation));
    assert.throws(
      () => assertPhysicalExecutionTransactionTransition(previous, candidate),
      { code },
      code,
    );
  }

  const effectFork = normalizePhysicalExecutionTransactionRecord(withoutDigest(vaulted, {
    effect_disposition: "ambiguous",
    semantic_disposition: "nonsemantic_raw_custody",
  }));
  assert.throws(
    () => assertPhysicalExecutionTransactionTransition(recorded, effectFork),
    { code: "physical_execution_effect_fork" },
  );
});

test("strict pre-effect terminal proof cannot masquerade as success", () => {
  const owner = createOwner();
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  const claimed = claimAndRead(owner, binding);
  assert.throws(
    () => normalizePhysicalExecutionTransactionRecord(rejectedRecordInput(claimed, {
      terminal_proof_digest: null,
    })),
    { code: "physical_execution_transaction_record_terminal_proof_required" },
  );

  const forgedTerminal = normalizePhysicalExecutionTransactionRecord(recordInput(claimed, "TERMINAL", {
    go_durable_receipt_digest: digest("forged-go"),
    effect_arm_receipt_digest: digest("forged-arm"),
    effect_disposition: "recorded",
    semantic_disposition: "validated_success",
    effect_evidence_digest: digest("forged-effect"),
    vault_artifact_ref: "artifact:v1:forged",
    vault_receipt_digest: digest("forged-vault"),
    restoration_proof_digest: digest("forged-restoration"),
    restoration_claim_digest: digest("forged-restoration-claim"),
    terminal_disposition: "completed",
    terminal_proof_digest: digest("forged-terminal"),
  }));
  assert.throws(
    () => assertPhysicalExecutionTransactionTransition(claimed, forgedTerminal),
    { code: "physical_execution_go_receipt_fork" },
  );
});

test("an ambiguous effect can only remain nonsemantic raw custody", () => {
  const owner = createOwner();
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  const claimed = claimAndRead(owner, binding);
  const go = normalizeNext(claimed, "GO_DURABLE");
  const armed = normalizeNext(go, "EFFECT_ARMED");
  assert.throws(
    () => normalizePhysicalExecutionTransactionRecord(recordInput(armed, "EFFECT_UNKNOWN", {
      semantic_disposition: "validated_success",
    })),
    { code: "physical_execution_transaction_record_ambiguous_cannot_be_semantic_success" },
  );
  const unknown = normalizeNext(armed, "EFFECT_UNKNOWN");
  const vaulted = normalizeNext(unknown, "VAULT_COMMITTED");
  const restoring = normalizeNext(vaulted, "RESTORING");
  assert.throws(
    () => normalizePhysicalExecutionTransactionRecord(recordInput(restoring, "TERMINAL", {
      terminal_disposition: "completed",
    })),
    { code: "physical_execution_transaction_record_nonsemantic_terminal_must_be_quarantined" },
  );
});

test("recovery derivation never permits effect execution or retry once armed", () => {
  const owner = createOwner();
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  let record = claimAndRead(owner, binding);
  const projections = [derivePhysicalExecutionTransactionRecovery(record)];
  for (const phase of [
    "GO_DURABLE", "EFFECT_ARMED", "EFFECT_RECORDED",
    "VAULT_COMMITTED", "RESTORING", "TERMINAL",
  ]) {
    record = normalizeNext(record, phase);
    projections.push(derivePhysicalExecutionTransactionRecovery(record));
  }
  assert.equal(projections[0].effect_execution_permitted, false);
  assert.equal(projections[1].conformance_arm_transition_permitted, true);
  for (const projection of projections) {
    assert.equal(projection.effect_execution_permitted, false);
    assert.equal(projection.provider_effect_execution_permitted, false);
    assert.equal(projection.effect_retry_permitted, false);
  }
  for (const projection of projections.slice(2)) {
    assert.equal(projection.post_arm_execution_forbidden, true);
    assert.doesNotMatch(projection.recovery_action, /^record_effect_arm/u);
  }
});

test("private owner claim-or-read is exact, bounded, and rejects binding forks", () => {
  const owner = createOwner({ maximum_transactions: 1 });
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  assert.equal(assertPhysicalExecutionTransactionOwner(owner), owner);
  const first = claimOrReadPhysicalExecutionTransaction(owner, claimInput(binding));
  const second = claimOrReadPhysicalExecutionTransaction(owner, claimInput(binding));
  assert.equal(second, first);

  const bindingFork = normalizePhysicalExecutionCompositeBinding(bindingInput({
    lease_digest: digest("forked-lease"),
  }));
  assert.throws(
    () => claimOrReadPhysicalExecutionTransaction(owner, claimInput(bindingFork)),
    { code: "physical_execution_transaction_binding_fork" },
  );
  const lineageFork = normalizePhysicalExecutionCompositeBinding(bindingInput({
    transaction_ref: "transaction:test-lineage-fork",
  }));
  assert.throws(
    () => claimOrReadPhysicalExecutionTransaction(owner, claimInput(lineageFork)),
    { code: "physical_execution_transaction_lineage_fork" },
  );
  const another = normalizePhysicalExecutionCompositeBinding(bindingInput({
    transaction_ref: "transaction:test-capacity",
    execution_lineage_digest: digest("capacity-lineage"),
  }));
  assert.throws(
    () => claimOrReadPhysicalExecutionTransaction(owner, claimInput(another)),
    { code: "physical_execution_transaction_owner_capacity_exhausted" },
  );
  assert.throws(
    () => assertPhysicalExecutionTransactionOwner(Object.freeze({ ...owner })),
    { code: "physical_execution_transaction_owner_private_brand_required" },
  );
  let proxyTrapInvoked = false;
  const proxy = new Proxy(owner, {
    isExtensible() {
      proxyTrapInvoked = true;
      throw new Error("must not run");
    },
  });
  assert.throws(
    () => assertPhysicalExecutionTransactionOwner(proxy),
    { code: "physical_execution_transaction_owner_private_brand_required" },
  );
  assert.equal(proxyTrapInvoked, false);
});

test("fixed one-shot response loss commits first and exact retries read one record", () => {
  const owner = createOwner({
    simulate_claim_response_loss_once: true,
    simulate_transition_response_loss_generation: 2,
  });
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  assert.throws(
    () => claimOrReadPhysicalExecutionTransaction(owner, claimInput(binding)),
    { code: "physical_execution_transaction_claim_response_lost" },
  );
  const claimed = readPhysicalExecutionTransaction(owner, readInput(binding));
  const recoveredClaim = claimOrReadPhysicalExecutionTransaction(owner, claimInput(binding));
  assert.equal(recoveredClaim.head_record_digest, claimed.record_digest);
  assert.equal(recoveredClaim.receipt_digest, claimed.claim_receipt_digest);
  assert.equal(claimOrReadPhysicalExecutionTransaction(owner, claimInput(binding)), recoveredClaim);

  const go = normalizeNext(claimed, "GO_DURABLE");
  const request = transitionInput(binding, claimed, go);
  assert.throws(
    () => transitionPhysicalExecutionTransaction(owner, request),
    { code: "physical_execution_transaction_transition_response_lost" },
  );
  assert.equal(readPhysicalExecutionTransaction(owner, readInput(binding)).record_digest, go.record_digest);
  const recovered = transitionPhysicalExecutionTransaction(owner, request);
  assert.equal(recovered.record_digest, go.record_digest);
  assert.equal(transitionPhysicalExecutionTransaction(owner, request), recovered);

  const fork = normalizePhysicalExecutionTransactionRecord(withoutDigest(go, {
    record_ref: "transaction-record:test-fork",
  }));
  assert.throws(
    () => transitionPhysicalExecutionTransaction(owner, transitionInput(binding, claimed, fork)),
    { code: "physical_execution_transaction_cas_conflict" },
  );
});

test("owner transition rejects binding drift and stale or same-generation CAS forks", () => {
  const owner = createOwner();
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  const claimed = claimAndRead(owner, binding);
  const go = normalizeNext(claimed, "GO_DURABLE");
  commit(owner, binding, claimed, go);

  assert.throws(
    () => transitionPhysicalExecutionTransaction(owner, {
      ...transitionInput(binding, go, normalizeNext(go, "EFFECT_ARMED")),
      composite_binding_digest: digest("wrong-binding"),
    }),
    { code: "physical_execution_transaction_binding_fork" },
  );
  const armed = normalizeNext(go, "EFFECT_ARMED");
  assert.throws(
    () => transitionPhysicalExecutionTransaction(owner, {
      ...transitionInput(binding, go, armed),
      expected_predecessor_record_digest: digest("wrong-head"),
    }),
    { code: "physical_execution_transaction_expected_digest_fork" },
  );
  assert.throws(
    () => transitionPhysicalExecutionTransaction(owner, transitionInput(binding, claimed, armed)),
    { code: "physical_execution_transaction_cas_conflict" },
  );
});

test("terminal outbox identity is deterministic and readback/redelivery stays exact across lost ACK", () => {
  const owner = createOwner({ simulate_outbox_redelivery_response_loss_once: true });
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  const { record, receipt } = completedChain(owner, binding);
  assert.equal(record.phase, "TERMINAL");
  assert.match(receipt.outbox_ref, /^terminal-outbox:v1:[a-f0-9]{64}$/u);
  const query = {
    version: VERSION,
    kind: "physical_execution_terminal_outbox_read",
    transaction_ref: binding.transaction_ref,
    execution_lineage_digest: binding.execution_lineage_digest,
    transaction_key_digest: binding.transaction_key_digest,
    composite_binding_digest: binding.composite_binding_digest,
    outbox_ref: receipt.outbox_ref,
    outbox_digest: receipt.outbox_digest,
  };
  const readback = readPhysicalExecutionTerminalOutbox(owner, query);
  assert.equal(readPhysicalExecutionTerminalOutbox(owner, query), readback);
  assert.throws(
    () => redeliverPhysicalExecutionTerminalOutbox(owner, query),
    { code: "physical_execution_terminal_outbox_response_lost" },
  );
  assert.equal(redeliverPhysicalExecutionTerminalOutbox(owner, query), readback);
  assert.equal(redeliverPhysicalExecutionTerminalOutbox(owner, query), readback);

  const secondOwner = createOwner();
  const second = completedChain(secondOwner, binding);
  assert.equal(second.receipt.outbox_ref, receipt.outbox_ref);
  assert.equal(second.receipt.outbox_digest, receipt.outbox_digest);

  assert.throws(
    () => readPhysicalExecutionTerminalOutbox(owner, { ...query, outbox_digest: digest("wrong") }),
    { code: "physical_execution_terminal_outbox_identity_mismatch" },
  );
});

test("fixture enrollment is closed data and cannot smuggle callbacks or production claims", () => {
  for (const field of ["callback", "read", "write", "clock", "provider_selector", "module_path", "signer", "production_ready"]) {
    assert.throws(
      () => createPhysicalExecutionTransactionConformanceOwner({
        ...ownerConfig(),
        [field]: () => {},
      }),
      { code: "physical_execution_transaction_owner_config_unknown_field" },
    );
  }
  let getterInvoked = false;
  const accessor = ownerConfig();
  Object.defineProperty(accessor, "maximum_transactions", {
    enumerable: true,
    get() {
      getterInvoked = true;
      throw new Error("must not run");
    },
  });
  assert.throws(
    () => createPhysicalExecutionTransactionConformanceOwner(accessor),
    { code: "physical_execution_transaction_owner_config_maximum_transactions_must_be_enumerable_data" },
  );
  assert.equal(getterInvoked, false);
  assert.throws(
    () => createPhysicalExecutionTransactionConformanceOwner({ ...ownerConfig(), test_only: false }),
    { code: "physical_execution_transaction_owner_config_fixture_enrollment_required" },
  );
  assert.throws(
    () => createPhysicalExecutionTransactionConformanceOwner(new Proxy(ownerConfig(), {})),
    { code: "physical_execution_transaction_owner_config_must_be_closed_data" },
  );
});

test("post-import Map, Error, Number, and RegExp monkeypatches cannot redirect owner primitives", () => {
  const invalidPathBinding = bindingInput({ transaction_ref: "../../caller-controlled/path" });
  const invalidDigestBinding = bindingInput({ execution_lineage_digest: "not-a-digest" });
  const originalMap = globalThis.Map;
  const originalError = globalThis.Error;
  const originalIsSafeInteger = Number.isSafeInteger;
  const originalRegexpTest = RegExp.prototype.test;
  const originalRegexpExec = RegExp.prototype.exec;
  let record;
  let rejection;
  let pathRejection;
  let digestRejection;
  try {
    globalThis.Map = class HostileMap {
      constructor() {
        throw new originalError("hostile Map constructor invoked");
      }
    };
    globalThis.Error = class HostileError {
      constructor() {
        throw new originalError("hostile Error constructor invoked");
      }
    };
    Number.isSafeInteger = () => false;
    RegExp.prototype.test = () => false;
    RegExp.prototype.exec = () => ({});
    const owner = createOwner();
    const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
    record = claimAndRead(owner, binding);
    try {
      assertPhysicalExecutionTransactionOwnerProductionReady(owner);
    } catch (error) {
      rejection = error;
    }
    try {
      normalizePhysicalExecutionCompositeBinding(invalidPathBinding);
    } catch (error) {
      pathRejection = error;
    }
    try {
      normalizePhysicalExecutionCompositeBinding(invalidDigestBinding);
    } catch (error) {
      digestRejection = error;
    }
  } finally {
    globalThis.Map = originalMap;
    globalThis.Error = originalError;
    Number.isSafeInteger = originalIsSafeInteger;
    RegExp.prototype.test = originalRegexpTest;
    RegExp.prototype.exec = originalRegexpExec;
  }
  assert.equal(record.phase, "CLAIMED");
  assert.equal(rejection.code, "physical_execution_transaction_owner_production_unavailable");
  assert.equal(pathRejection.code, "physical_execution_composite_binding_transaction_ref_invalid");
  assert.equal(
    digestRejection.code,
    "physical_execution_composite_binding_execution_lineage_digest_invalid",
  );
});

test("post-import crypto and canonical-JSON monkeypatches cannot collapse binding forks", () => {
  const firstInput = bindingInput();
  const secondInput = bindingInput({ lease_digest: digest("collision-probe-lease") });
  const hashPrototype = crypto.Hash.prototype;
  const patchTargets = [
    [crypto, "createHash"],
    [hashPrototype, "update"],
    [hashPrototype, "digest"],
    [JSON, "stringify"],
    [Object, "keys"],
    [Array.prototype, "sort"],
  ];
  const descriptors = patchTargets.map(([target, property]) => (
    Object.getOwnPropertyDescriptor(target, property)
  ));
  let firstBinding;
  let secondBinding;
  let fork;
  const hostile = () => {
    throw new Error("mutable global hash primitive invoked");
  };
  try {
    for (const [target, property] of patchTargets) {
      Object.defineProperty(target, property, {
        value: hostile,
        writable: true,
        enumerable: false,
        configurable: true,
      });
    }
    firstBinding = normalizePhysicalExecutionCompositeBinding(firstInput);
    secondBinding = normalizePhysicalExecutionCompositeBinding(secondInput);
    const owner = createOwner();
    claimOrReadPhysicalExecutionTransaction(owner, claimInput(firstBinding));
    try {
      claimOrReadPhysicalExecutionTransaction(owner, claimInput(secondBinding));
    } catch (error) {
      fork = error;
    }
  } finally {
    for (let index = patchTargets.length - 1; index >= 0; index -= 1) {
      Object.defineProperty(patchTargets[index][0], patchTargets[index][1], descriptors[index]);
    }
  }
  assert.notEqual(firstBinding.composite_binding_digest, secondBinding.composite_binding_digest);
  assert.equal(firstBinding.transaction_key_digest, secondBinding.transaction_key_digest);
  assert.equal(fork.code, "physical_execution_transaction_binding_fork");
});

test("all public projections are bounded, redacted, and non-authorizing", () => {
  const owner = createOwner();
  const binding = normalizePhysicalExecutionCompositeBinding(bindingInput());
  const claim = claimOrReadPhysicalExecutionTransaction(owner, claimInput(binding));
  const record = readPhysicalExecutionTransaction(owner, readInput(binding));
  const recovery = derivePhysicalExecutionTransactionRecovery(record);
  const readiness = physicalExecutionTransactionOwnerReadiness(owner);
  assert.equal(owner.assurance, PHYSICAL_EXECUTION_TRANSACTION_OWNER_ASSURANCE);
  assert.equal(owner.kind, "physical_execution_transaction_conformance_owner");
  assert.equal(readiness.transaction_count, 1);
  assert.equal(readiness.production_ready, false);
  assert.equal(readiness.durability_attested, false);
  assert.equal(readiness.hardware_access_authorized, false);
  assert.equal(readiness.execution_authority, false);
  assert.equal(readiness.blockers, PRODUCTION_BLOCKERS);
  assert.equal(PRODUCTION_BLOCKERS.length >= 7, true);

  for (const projection of [owner, claim, record, recovery, readiness]) {
    assertNoForbiddenSurface(projection);
    assert.equal(JSON.stringify(projection).includes("/dev/"), false);
    assert.equal(JSON.stringify(projection).includes("BEGIN PRIVATE KEY"), false);
  }
  assert.throws(
    () => assertPhysicalExecutionTransactionOwnerProductionReady(owner),
    { code: "physical_execution_transaction_owner_production_unavailable" },
  );
});
