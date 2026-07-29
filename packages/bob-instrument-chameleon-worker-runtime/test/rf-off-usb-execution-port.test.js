"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const {
  compileHf14aProbe,
  encodeCompiledHf14aProbeForProviderWorker,
} = require("../lib/hf14a-probe-compiler.js");
const {
  acknowledgeRecoveredRfOffUsbExecution,
  acknowledgeRfOffUsbExecution,
  chameleonRfOffUsbExecutionRequestDigest,
  chameleonRfOffUsbProviderDescriptorDigest,
  createFixtureRfOffUsbEffectAdmissionPort,
  createFixtureRfOffUsbExecutionPort,
  executeRfOffUsbExecution,
  prepareRfOffUsbExecution,
  projectRfOffUsbExecutionPort,
  readRfOffUsbExecution,
  recoverRfOffUsbTerminal,
} = require("../lib/rf-off-usb-execution-port.js");
const {
  hashCanonicalJson,
} = require("../../bob-instrument-contracts/lib/verification-contracts.js");

const digest = (label) => hashCanonicalJson({ label });

function binding(overrides = {}) {
  const basis = {
    version: 1,
    provider_id: "chameleon_ultra",
    transport_kind: "usb_cdc",
    transport_variant: "fixture_conformance",
    session_id: "session:rf-off-fixture",
    session_nucleus_hash: digest("session-nucleus"),
    lease_id: "lease:rf-off-fixture",
    resource_ref: "instrument:chameleon-fixture",
    reservation_fencing_token_hash: digest("reservation-fence"),
    authority_fencing_token_digest: digest("authority-fence"),
    fencing_generation: 7,
    provider_descriptor_digest: "0".repeat(64),
    device_ref: "device:chameleon-fixture",
    device_identity_digest: digest("device-identity"),
    custody_ref: "custody:chameleon-fixture",
    custody_identity_digest: digest("custody-identity"),
    custody_epoch: 3,
    endpoint_identity_digest: digest("endpoint-identity"),
    worker_bundle_digest: digest("worker-bundle"),
    worker_launch_profile_digest: digest("worker-launch"),
    worker_fence_plan_digest: digest("worker-fence"),
    transport_profile_digest: digest("transport-profile"),
    durable_exchange_plan_digest: digest("durable-exchange"),
    terminal_receipt_recipient_digest: digest("terminal-recipient"),
    vault_reservation_handle: `vault-reservation:v1:${"A".repeat(43)}`,
    vault_reservation_digest: digest("vault-reservation"),
    vault_ingest_capability_digest: digest("vault-ingest"),
    vault_byte_limit: 64,
    dtr_control_model: "fixture_callback_unattested",
    rf_field_witness_model: "fixture_callback_unattested",
    ...overrides,
  };
  basis.provider_descriptor_digest = chameleonRfOffUsbProviderDescriptorDigest(basis);
  return basis;
}

function request(port, command, overrides = {}) {
  return {
    version: 1,
    kind: "chameleon_hf14a_probe_execution_request",
    execution_binding_digest: port.execution_binding_digest,
    authority_claim_digest: digest("authority-claim"),
    execution_lineage_digest: digest("execution-lineage"),
    attempt_ref: "attempt:rf-off-fixture",
    operation_id: "protocol.discovery_probe",
    requested_effects_digest: digest("requested-effects"),
    safety_supervisor_plan_digest: digest("safety-plan"),
    availability_evidence_digest: digest("availability-evidence"),
    availability_variant_digest: digest("availability-variant"),
    execution_claim_receipt_digest: digest("execution-claim-receipt"),
    deadline_fence_receipt_digest: digest("deadline-fence-receipt"),
    effect_deadline: "2026-07-20T10:00:00.000Z",
    compiled_command: command,
    ...overrides,
  };
}

function effectAdmission(port, executionRequest, options = {}) {
  const preparedRequestDigest = recoveryBinding(port, executionRequest).prepared_request_digest;
  const executionRequestDigest = chameleonRfOffUsbExecutionRequestDigest(
    port.execution_binding_digest,
    preparedRequestDigest,
  );
  return createFixtureRfOffUsbEffectAdmissionPort({
    version: 1,
    port_id: options.port_id || "fixture_rf_off_usb_effect_admission",
    test_only: true,
    execution_binding_digest: port.execution_binding_digest,
    prepared_request_digest: preparedRequestDigest,
    execution_request_digest: executionRequestDigest,
    assert_current(challenge) {
      if (typeof options.on_phase === "function") options.on_phase(challenge.phase);
      if (typeof options.result === "function") return options.result(challenge);
      const basis = {
        version: 1,
        kind: "chameleon_hf14a_probe_effect_admission",
        phase: challenge.phase,
        execution_binding_digest: challenge.execution_binding_digest,
        prepared_request_digest: challenge.prepared_request_digest,
        execution_request_digest: challenge.execution_request_digest,
        authority_claim_digest: executionRequest.authority_claim_digest,
        availability_evidence_digest: executionRequest.availability_evidence_digest,
        deadline_fence_receipt_digest: digest(`effect-admission-deadline:${challenge.phase}`),
        reservation_receipt_digest: digest(`effect-admission-reservation:${challenge.phase}`),
        effect_authorization_digest: digest(`effect-admission-authorization:${challenge.phase}`),
        authorized: true,
      };
      return {
        ...basis,
        effect_admission_receipt_digest: hashCanonicalJson({
          domain: "hacker-bob/chameleon-rf-off-usb-effect-admission/v1",
          ...basis,
        }),
      };
    },
  });
}

function createHarness(options = {}) {
  const calls = [];
  const exchangeStore = options.exchange_store || { value: null };
  let capturedRequestBytes = null;
  let capturedResponseBytes = null;
  let artifactBytes = null;
  const response = options.response || Buffer.from([0x11, 0x22, 0x33]);
  const portBinding = binding(options.binding);
  const port = createFixtureRfOffUsbExecutionPort({
    version: 1,
    port_id: options.port_id || "fixture_rf_off_usb_port",
    test_only: true,
    binding: portBinding,
    read_exchange() {
      calls.push("read");
      if (typeof options.read_exchange_override === "function") {
        return options.read_exchange_override();
      }
      return exchangeStore.value == null ? null : structuredClone(exchangeStore.value);
    },
    prepare_exchange(basis) {
      calls.push("prepare");
      exchangeStore.value = {
        ...basis,
        prepared_receipt_digest: hashCanonicalJson({
          domain: "hacker-bob/chameleon-rf-off-usb-prepared-receipt/v1",
          ...basis,
        }),
      };
      return structuredClone(exchangeStore.value);
    },
    commit_terminal(core) {
      calls.push("terminal");
      let committedCore = { ...core };
      if (options.tamper_terminal) {
        committedCore.response_byte_length += 1;
        const witnessBasis = { ...committedCore };
        delete witnessBasis.terminal_witness_digest;
        committedCore.terminal_witness_digest = hashCanonicalJson({
          domain: "hacker-bob/chameleon-rf-off-usb-terminal-witness/v1",
          ...witnessBasis,
        });
      }
      exchangeStore.value = {
        ...committedCore,
        durable_receipt_digest: digest("durable-terminal-receipt"),
        outbox_record_digest: digest("terminal-outbox"),
        outbox_delivery_state: "pending",
        outbox_ack_digest: null,
      };
      if (options.throw_after_terminal_commit) {
        throw new Error("lost terminal commit acknowledgement");
      }
      return structuredClone(exchangeStore.value);
    },
    ack_terminal(ack) {
      calls.push("ack");
      exchangeStore.value = {
        ...exchangeStore.value,
        outbox_delivery_state: "acknowledged",
        outbox_ack_digest: hashCanonicalJson({
          domain: "hacker-bob/chameleon-rf-off-usb-outbox-ack/v1",
          ...ack,
        }),
      };
      return structuredClone(exchangeStore.value);
    },
    observe_before() {
      calls.push("before");
      return {
        inventory_digest: digest("inventory-before"),
        endpoint_identity_digest: portBinding.endpoint_identity_digest,
        dtr_asserted: false,
        rf_field_state: "off",
        field_witness_digest: digest("field-before"),
      };
    },
    async open_transport() {
      calls.push("open");
      if (options.open_failure) throw new Error("open acknowledgement lost");
      return {
        opened: true,
        endpoint_identity_digest: portBinding.endpoint_identity_digest,
        dtr_asserted: false,
      };
    },
    async configure_transport() {
      calls.push("configure");
      return {
        configured: true,
        endpoint_identity_digest: portBinding.endpoint_identity_digest,
        dtr_asserted: options.assert_dtr === true,
      };
    },
    async transact_transport(query) {
      calls.push("transact");
      capturedRequestBytes = query.request_bytes;
      capturedResponseBytes = Buffer.from(response);
      return { response_bytes: capturedResponseBytes };
    },
    async commit_artifact_raw_custody(query) {
      calls.push("artifact");
      artifactBytes = query.response_bytes;
      const responseDigestBeforeMutation = crypto.createHash("sha256")
        .update(query.response_bytes).digest("hex");
      if (options.mutate_artifact_bytes) query.response_bytes.fill(0x99);
      const responseDigest = options.return_pre_mutation_artifact_receipt
        ? responseDigestBeforeMutation
        : crypto.createHash("sha256").update(query.response_bytes).digest("hex");
      return {
        artifact_handle: `artifact:v1:${"B".repeat(43)}`,
        response_digest: responseDigest,
        response_byte_length: query.response_bytes.length,
        vault_commit_receipt_digest: digest("vault-commit"),
        raw_custody_receipt_digest: digest("raw-custody"),
        vault_reservation_digest: portBinding.vault_reservation_digest,
        vault_ingest_capability_digest: portBinding.vault_ingest_capability_digest,
      };
    },
    observe_after() {
      calls.push("after");
      return {
        inventory_digest: digest("inventory-after"),
        endpoint_identity_digest: portBinding.endpoint_identity_digest,
        dtr_asserted: options.assert_dtr === true,
        rf_field_state: "off",
        field_witness_digest: digest("field-after"),
      };
    },
    async close_transport() {
      calls.push("close");
      return {
        closed: true,
        endpoint_identity_digest: portBinding.endpoint_identity_digest,
        dtr_asserted: false,
        rf_field_state: "off",
        terminal_rf_off_witness_digest: digest("terminal-field-off"),
        no_active_effects_witness_digest: digest("terminal-no-active-effects"),
        witness_qualified: false,
      };
    },
  });
  return {
    calls,
    exchangeStore,
    port,
    portBinding,
    get capturedRequestBytes() { return capturedRequestBytes; },
    get capturedResponseBytes() { return capturedResponseBytes; },
    get artifactBytes() { return artifactBytes; },
  };
}

function recoveryBinding(port, executionRequest) {
  const command = executionRequest.compiled_command;
  const prepared = {
    version: 1,
    kind: "chameleon_hf14a_probe_prepared",
    execution_binding_digest: port.execution_binding_digest,
    authority_claim_digest: executionRequest.authority_claim_digest,
    execution_lineage_digest: executionRequest.execution_lineage_digest,
    attempt_ref: executionRequest.attempt_ref,
    operation_id: executionRequest.operation_id,
    requested_effects_digest: executionRequest.requested_effects_digest,
    safety_supervisor_plan_digest: executionRequest.safety_supervisor_plan_digest,
    availability_evidence_digest: executionRequest.availability_evidence_digest,
    availability_variant_digest: executionRequest.availability_variant_digest,
    execution_claim_receipt_digest: executionRequest.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: executionRequest.deadline_fence_receipt_digest,
    effect_deadline: executionRequest.effect_deadline,
    compiled_command_id: command.compiled_command_id,
    compiled_command_capability_digest: command.compiled_command_capability_digest,
    compiled_operation_digest: command.compiled_operation_digest,
  };
  return {
    version: 1,
    kind: "chameleon_hf14a_probe_recovery_binding",
    ...Object.fromEntries(Object.entries(prepared).filter(([field]) => (
      !["kind"].includes(field)
    ))),
    prepared_request_digest: hashCanonicalJson(prepared),
  };
}

function resealTerminal(record) {
  const prepared = {
    version: record.version,
    kind: "chameleon_hf14a_probe_prepared",
    execution_binding_digest: record.execution_binding_digest,
    authority_claim_digest: record.authority_claim_digest,
    execution_lineage_digest: record.execution_lineage_digest,
    attempt_ref: record.attempt_ref,
    operation_id: record.operation_id,
    requested_effects_digest: record.requested_effects_digest,
    safety_supervisor_plan_digest: record.safety_supervisor_plan_digest,
    availability_evidence_digest: record.availability_evidence_digest,
    availability_variant_digest: record.availability_variant_digest,
    execution_claim_receipt_digest: record.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: record.deadline_fence_receipt_digest,
    effect_deadline: record.effect_deadline,
    compiled_command_id: record.compiled_command_id,
    compiled_command_capability_digest: record.compiled_command_capability_digest,
    compiled_operation_digest: record.compiled_operation_digest,
  };
  record.prepared_receipt_digest = hashCanonicalJson({
    domain: "hacker-bob/chameleon-rf-off-usb-prepared-receipt/v1",
    ...prepared,
  });
  const witness = { ...record };
  for (const field of [
    "terminal_witness_digest",
    "durable_receipt_digest",
    "outbox_record_digest",
    "outbox_delivery_state",
    "outbox_ack_digest",
  ]) delete witness[field];
  record.terminal_witness_digest = hashCanonicalJson({
    domain: "hacker-bob/chameleon-rf-off-usb-terminal-witness/v1",
    ...witness,
  });
  return record;
}

function assertScalarNullPrototypeProjection(value) {
  assert.equal(Object.getPrototypeOf(value), null);
  assert.equal(Object.getOwnPropertySymbols(value).length, 0);
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    assert.equal(descriptor.enumerable, true);
    assert.equal("get" in descriptor, false);
    assert.equal("set" in descriptor, false);
    assert.equal(Buffer.isBuffer(descriptor.value), false);
    assert.equal(ArrayBuffer.isView(descriptor.value), false);
    assert.equal(descriptor.value instanceof ArrayBuffer, false);
    if (descriptor.value !== null) assert.notEqual(typeof descriptor.value, "object");
  }
}

test("fixture worker durably prepares, owns byte custody, closes, commits terminal/outbox, and replays exactly", async () => {
  const harness = createHarness({ throw_after_terminal_commit: true });
  const command = encodeCompiledHf14aProbeForProviderWorker(compileHf14aProbe({
    version: 1,
    schema_id: "iso14443a.requa_atqa_v1",
  }));
  const executionRequest = request(harness.port, command);

  const prepared = prepareRfOffUsbExecution(harness.port, executionRequest);
  assert.equal(prepared.kind, "chameleon_hf14a_probe_prepared");
  const admissionPhases = [];
  const terminal = await executeRfOffUsbExecution(
    harness.port,
    executionRequest,
    effectAdmission(harness.port, executionRequest, {
      on_phase(phase) { admissionPhases.push(phase); },
    }),
  );
  assert.deepEqual(admissionPhases, ["pre_open", "pre_transact"]);
  assert.match(terminal.pre_open_admission_receipt_digest, /^[a-f0-9]{64}$/u);
  assert.match(terminal.pre_transact_admission_receipt_digest, /^[a-f0-9]{64}$/u);
  assert.equal(terminal.kind, "chameleon_hf14a_probe_terminal");
  assert.equal(terminal.outbox_delivery_state, "pending");
  assert.equal(terminal.rf_field_before, "off");
  assert.equal(terminal.rf_field_after, "off");
  assert.equal(terminal.rf_off_qualified, false);
  assert.equal(terminal.dtr_off_qualified, false);
  assert.equal(
    terminal.qualification_blocker_code,
    "independent_rf_field_off_native_witness_missing",
  );
  assert.equal(terminal.raw_response_bytes_projected, false);
  assertScalarNullPrototypeProjection(terminal);
  assert.deepEqual([...harness.capturedRequestBytes], new Array(harness.capturedRequestBytes.length).fill(0));
  assert.deepEqual([...harness.capturedResponseBytes], [0, 0, 0]);
  assert.deepEqual([...harness.artifactBytes], [0, 0, 0]);

  const acknowledged = acknowledgeRfOffUsbExecution(
    harness.port,
    executionRequest,
    digest("broker-settlement"),
  );
  assert.equal(acknowledged.outbox_delivery_state, "acknowledged");
  assert.match(acknowledged.outbox_ack_digest, /^[a-f0-9]{64}$/u);
  assertScalarNullPrototypeProjection(acknowledged);
  assert.deepEqual(readRfOffUsbExecution(harness.port, executionRequest), acknowledged);
  assert.throws(
    () => acknowledgeRfOffUsbExecution(
      harness.port,
      executionRequest,
      digest("cross-wired-broker-settlement"),
    ),
    (error) => error.code === "rf_off_usb_outbox_ack_crosswired",
  );

  const callCount = harness.calls.length;
  assert.deepEqual(await executeRfOffUsbExecution(
    harness.port,
    executionRequest,
    effectAdmission(harness.port, executionRequest),
  ), acknowledged);
  assert.equal(harness.calls.slice(callCount).every((entry) => entry === "read"), true);
  assert.deepEqual(harness.calls.slice(0, 11), [
    "read", "prepare", "read", "read", "before", "open", "configure",
    "transact", "artifact", "after", "close",
  ]);
});

test("effect admission ports are exact, privately branded, synchronous, and accessor-safe", async () => {
  const command = encodeCompiledHf14aProbeForProviderWorker(compileHf14aProbe({
    version: 1,
    schema_id: "iso14443a.requa_atqa_v1",
  }));

  const forged = createHarness();
  const forgedRequest = request(forged.port, command);
  prepareRfOffUsbExecution(forged.port, forgedRequest);
  await assert.rejects(
    () => executeRfOffUsbExecution(forged.port, forgedRequest, Object.freeze({
      execution_binding_digest: forged.port.execution_binding_digest,
    })),
    (error) => error.code === "rf_off_usb_effect_admission_untrusted",
  );
  assert.equal(forged.calls.includes("open"), false);

  let getterCalls = 0;
  const accessor = createHarness();
  const accessorRequest = request(accessor.port, command);
  prepareRfOffUsbExecution(accessor.port, accessorRequest);
  await assert.rejects(
    () => executeRfOffUsbExecution(
      accessor.port,
      accessorRequest,
      effectAdmission(accessor.port, accessorRequest, {
        result() {
          const result = {};
          Object.defineProperty(result, "then", {
            enumerable: true,
            get() {
              getterCalls += 1;
              return () => {};
            },
          });
          return result;
        },
      }),
    ),
    (error) => error.code === "rf_off_usb_contract_invalid",
  );
  assert.equal(getterCalls, 0);
  assert.equal(accessor.calls.includes("open"), false);

  const thenable = createHarness();
  const thenableRequest = request(thenable.port, command);
  prepareRfOffUsbExecution(thenable.port, thenableRequest);
  await assert.rejects(
    () => executeRfOffUsbExecution(
      thenable.port,
      thenableRequest,
      effectAdmission(thenable.port, thenableRequest, {
        result() { return Promise.resolve({}); },
      }),
    ),
    (error) => error.code === "rf_off_usb_durable_exchange_async",
  );
  assert.equal(thenable.calls.includes("open"), false);
});

test("cold worker restart recovers a pending terminal and ACKs without compiled command bytes", async () => {
  const first = createHarness();
  const command = encodeCompiledHf14aProbeForProviderWorker(compileHf14aProbe({
    version: 1,
    schema_id: "iso14443a.requa_atqa_v1",
  }));
  const executionRequest = request(first.port, command);
  prepareRfOffUsbExecution(first.port, executionRequest);
  const original = await executeRfOffUsbExecution(
    first.port,
    executionRequest,
    effectAdmission(first.port, executionRequest),
  );
  assert.equal(original.outbox_delivery_state, "pending");

  const restarted = createHarness({
    exchange_store: first.exchangeStore,
    binding: first.portBinding,
  });
  const recovery = recoveryBinding(restarted.port, executionRequest);
  const recovered = recoverRfOffUsbTerminal(restarted.port, recovery);
  assert.equal(recovered.terminal_witness_digest, original.terminal_witness_digest);
  assert.equal(recovered.outbox_delivery_state, "pending");
  assertScalarNullPrototypeProjection(recovered);

  const acknowledged = acknowledgeRecoveredRfOffUsbExecution(
    restarted.port,
    recovery,
    digest("cold-restart-broker-settlement"),
  );
  assert.equal(acknowledged.outbox_delivery_state, "acknowledged");
  assert.match(acknowledged.outbox_ack_digest, /^[a-f0-9]{64}$/u);
  assert.equal(restarted.calls.includes("open"), false);
  assert.throws(
    () => recoverRfOffUsbTerminal(restarted.port, {
      ...recovery,
      attempt_ref: "attempt:cross-wired-recovery",
    }),
    (error) => error.code === "rf_off_usb_recovery_crosswired",
  );
});

test("cold recovery binds every dynamic admission receipt and the full prepared request digest", async () => {
  const original = createHarness();
  const command = encodeCompiledHf14aProbeForProviderWorker(compileHf14aProbe({
    version: 1,
    schema_id: "iso14443a.requa_atqa_v1",
  }));
  const executionRequest = request(original.port, command);
  prepareRfOffUsbExecution(original.port, executionRequest);
  await executeRfOffUsbExecution(
    original.port,
    executionRequest,
    effectAdmission(original.port, executionRequest),
  );
  const expectedRecovery = recoveryBinding(original.port, executionRequest);
  const mutations = {
    availability_evidence_digest: digest("tampered-availability-evidence"),
    execution_claim_receipt_digest: digest("tampered-execution-claim-receipt"),
    deadline_fence_receipt_digest: digest("tampered-deadline-fence"),
    effect_deadline: "2026-07-20T10:01:00.000Z",
  };
  for (const [field, value] of Object.entries(mutations)) {
    const store = {
      value: resealTerminal({ ...original.exchangeStore.value, [field]: value }),
    };
    const restarted = createHarness({
      exchange_store: store,
      binding: original.portBinding,
    });
    assert.throws(
      () => recoverRfOffUsbTerminal(restarted.port, expectedRecovery),
      (error) => error.code === "rf_off_usb_recovery_crosswired",
      field,
    );
  }
  const wrongPreparedDigest = {
    ...expectedRecovery,
    prepared_request_digest: digest("cross-wired-prepared-request"),
  };
  const restarted = createHarness({
    exchange_store: original.exchangeStore,
    binding: original.portBinding,
  });
  assert.throws(
    () => recoverRfOffUsbTerminal(restarted.port, wrongPreparedDigest),
    (error) => error.code === "rf_off_usb_recovery_crosswired",
  );
});

test("cold recovery never invokes durable readback accessors and rejects proxies", () => {
  const baseline = createHarness();
  const command = encodeCompiledHf14aProbeForProviderWorker(compileHf14aProbe({
    version: 1,
    schema_id: "iso14443a.requa_atqa_v1",
  }));
  const executionRequest = request(baseline.port, command);
  const recovery = recoveryBinding(baseline.port, executionRequest);
  let getterCalls = 0;
  const accessorRecord = {};
  Object.defineProperty(accessorRecord, "kind", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "chameleon_hf14a_probe_terminal";
    },
  });
  const accessorHarness = createHarness({
    binding: baseline.portBinding,
    read_exchange_override: () => accessorRecord,
  });
  assert.throws(
    () => recoverRfOffUsbTerminal(accessorHarness.port, recovery),
    (error) => error.code === "rf_off_usb_durable_exchange_crosswired",
  );
  assert.equal(getterCalls, 0);

  const proxyHarness = createHarness({
    binding: baseline.portBinding,
    read_exchange_override: () => new Proxy({}, {}),
  });
  assert.throws(
    () => recoverRfOffUsbTerminal(proxyHarness.port, recovery),
    (error) => error.code === "rf_off_usb_durable_exchange_crosswired",
  );
});

test("current asserted-DTR custody truth is preserved as a typed production blocker", async () => {
  const harness = createHarness({
    assert_dtr: true,
    binding: {
      transport_variant: "current_custody_asserted_dtr",
      dtr_control_model: "asserted_after_activation",
    },
  });
  const projection = projectRfOffUsbExecutionPort(harness.port);
  assert.equal(projection.dtr_control_model, "asserted_after_activation");
  assert.equal(projection.target_rf_transmit, true);
  assert.equal(projection.rf_off_stage_qualified, false);
  assert.equal(projection.qualification_blocker_code, "current_usb_custody_dtr_asserted");
  const command = encodeCompiledHf14aProbeForProviderWorker(compileHf14aProbe({
    version: 1,
    schema_id: "iso14443a.wupa_atqa_v1",
  }));
  const executionRequest = request(harness.port, command);
  prepareRfOffUsbExecution(harness.port, executionRequest);
  const terminal = await executeRfOffUsbExecution(
    harness.port,
    executionRequest,
    effectAdmission(harness.port, executionRequest),
  );
  assert.equal(terminal.dtr_during_exchange_asserted, true);
  assert.equal(terminal.dtr_off_qualified, false);
  assert.equal(terminal.qualification_blocker_code, "current_usb_custody_dtr_asserted");
});

test("ambiguous open is fenced without consuming or retrying the compiled command", async () => {
  const harness = createHarness({ open_failure: true });
  const command = encodeCompiledHf14aProbeForProviderWorker(compileHf14aProbe({
    version: 1,
    schema_id: "iso14443a.requa_atqa_v1",
  }));
  const executionRequest = request(harness.port, command);
  prepareRfOffUsbExecution(harness.port, executionRequest);
  await assert.rejects(
    () => executeRfOffUsbExecution(
      harness.port,
      executionRequest,
      effectAdmission(harness.port, executionRequest),
    ),
    (error) => error.code === "rf_off_usb_execution_ambiguous",
  );
  await assert.rejects(
    () => executeRfOffUsbExecution(
      harness.port,
      executionRequest,
      effectAdmission(harness.port, executionRequest),
    ),
    (error) => error.code === "rf_off_usb_execution_fenced",
  );
  assert.equal(harness.calls.filter((entry) => entry === "open").length, 1);
  assert.equal(harness.calls.includes("transact"), false);
});

test("durable terminal callback cannot alter worker-owned artifact or witness fields", async () => {
  const harness = createHarness({ tamper_terminal: true });
  const command = encodeCompiledHf14aProbeForProviderWorker(compileHf14aProbe({
    version: 1,
    schema_id: "iso14443a.requa_atqa_v1",
  }));
  const executionRequest = request(harness.port, command);
  prepareRfOffUsbExecution(harness.port, executionRequest);
  await assert.rejects(
    () => executeRfOffUsbExecution(
      harness.port,
      executionRequest,
      effectAdmission(harness.port, executionRequest),
    ),
    (error) => error.code === "rf_off_usb_terminal_commit_crosswired",
  );
});

test("artifact custody callback cannot launder a mutated transport response", async () => {
  const harness = createHarness({ mutate_artifact_bytes: true });
  const command = encodeCompiledHf14aProbeForProviderWorker(compileHf14aProbe({
    version: 1,
    schema_id: "iso14443a.requa_atqa_v1",
  }));
  const executionRequest = request(harness.port, command);
  prepareRfOffUsbExecution(harness.port, executionRequest);
  await assert.rejects(
    () => executeRfOffUsbExecution(
      harness.port,
      executionRequest,
      effectAdmission(harness.port, executionRequest),
    ),
    (error) => error.code === "rf_off_usb_artifact_commit_crosswired",
  );
  assert.deepEqual([...harness.capturedResponseBytes], [0, 0, 0]);
  assert.deepEqual([...harness.artifactBytes], [0, 0, 0]);
});

test("artifact custody mutation cannot pass by returning the pre-mutation digest and length", async () => {
  const harness = createHarness({
    mutate_artifact_bytes: true,
    return_pre_mutation_artifact_receipt: true,
  });
  const command = encodeCompiledHf14aProbeForProviderWorker(compileHf14aProbe({
    version: 1,
    schema_id: "iso14443a.requa_atqa_v1",
  }));
  const executionRequest = request(harness.port, command);
  prepareRfOffUsbExecution(harness.port, executionRequest);
  await assert.rejects(
    () => executeRfOffUsbExecution(
      harness.port,
      executionRequest,
      effectAdmission(harness.port, executionRequest),
    ),
    (error) => error.code === "rf_off_usb_artifact_commit_crosswired",
  );
  assert.deepEqual([...harness.capturedResponseBytes], [0, 0, 0]);
  assert.deepEqual([...harness.artifactBytes], [0, 0, 0]);
});
