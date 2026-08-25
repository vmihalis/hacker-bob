"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const {
  CHAMELEON_SEMANTIC_MANIFEST,
  getChameleonAvailabilityVariant,
} = require("../lib/operations.js");
const {
  compileHf14aProbe,
  encodeCompiledHf14aProbeForProviderWorker,
} = require("../../bob-instrument-chameleon-worker-runtime/lib/hf14a-probe-compiler.js");
const {
  chameleonRfOffUsbProviderDescriptorDigest,
  createFixtureRfOffUsbExecutionPort,
} = require("../../bob-instrument-chameleon-worker-runtime/lib/rf-off-usb-execution-port.js");
const {
  FIXTURE_AUTHORITY_PROVIDER_ID,
  PROVIDER_COMMAND_REF,
  chameleonRfOffCommandInputRef,
  chameleonRfOffOperationDigest,
  chameleonRfOffParameterDigest,
  chameleonRfOffRequestedEffectsDigest,
  createChameleonRfOffUsbExecutor,
  createChameleonRfOffUsbRecoveryExecutor,
  createFixtureChameleonRfOffAvailabilityResolverPort,
  executeChameleonRfOffUsbProbe,
  projectChameleonRfOffUsbExecutor,
  projectChameleonRfOffUsbPreparedRecoveryBinding,
} = require("../lib/rf-off-usb-executor.js");
const {
  createDeterministicMockDispatchAuthorityPort,
} = require("../../../mcp/domains/physical/physical-dispatch-authority.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");
const {
  beginPhysicalResourceCleanup,
  completePhysicalResourceCleanup,
  quarantinePhysicalResourceReservation,
  readPhysicalResourceReservationProjection,
  rehydratePhysicalResourceReservationCredential,
} = require("../../bob-instrument-broker/lib/resource-reservations.js");
const {
  createPhysicalReservationFixture,
} = require("../../bob-instrument-broker/test/helpers/physical-reservation-fixture.js");

const digest = (label) => hashCanonicalJson({ label });

function authorityFenceDigest(rawFence) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-dispatch-authority-fencing-token/v1",
    fencing_token: rawFence,
  });
}

function workerBinding(reservation, rawAuthorityFence, overrides = {}) {
  const allocation = reservation.held.receipt.allocations[0];
  const basis = {
    version: 1,
    provider_id: "chameleon_ultra",
    transport_kind: "usb_cdc",
    transport_variant: "fixture_conformance",
    session_id: reservation.reservationBinding.session_id,
    session_nucleus_hash: reservation.reservationBinding.session_nucleus_hash,
    lease_id: "lease:chameleon-rf-off-fixture",
    resource_ref: allocation.resource_ref,
    reservation_fencing_token_hash: allocation.fencing_token_hash,
    authority_fencing_token_digest: authorityFenceDigest(rawAuthorityFence),
    fencing_generation: allocation.fencing_generation,
    provider_descriptor_digest: "0".repeat(64),
    device_ref: "device:chameleon-ultra-fixture",
    device_identity_digest: digest("chameleon-fixture-device"),
    custody_ref: "custody:chameleon-ultra-fixture",
    custody_identity_digest: digest("chameleon-fixture-custody"),
    custody_epoch: 4,
    endpoint_identity_digest: digest("chameleon-fixture-endpoint"),
    worker_bundle_digest: digest("chameleon-worker-bundle"),
    worker_launch_profile_digest: digest("chameleon-worker-launch"),
    worker_fence_plan_digest: digest("chameleon-worker-fence"),
    transport_profile_digest: digest("chameleon-usb-transport"),
    durable_exchange_plan_digest: digest("chameleon-durable-exchange"),
    terminal_receipt_recipient_digest: digest("chameleon-terminal-recipient"),
    vault_reservation_handle: `vault-reservation:v1:${"C".repeat(43)}`,
    vault_reservation_digest: digest("chameleon-vault-reservation"),
    vault_ingest_capability_digest: digest("chameleon-vault-ingest"),
    vault_byte_limit: 64,
    dtr_control_model: "fixture_callback_unattested",
    rf_field_witness_model: "fixture_callback_unattested",
    ...overrides,
  };
  basis.provider_descriptor_digest = chameleonRfOffUsbProviderDescriptorDigest(basis);
  return basis;
}

function createWorkerPort(binding, options = {}) {
  const exchangeStore = options.exchange_store || { value: null };
  const calls = [];
  const port = createFixtureRfOffUsbExecutionPort({
    version: 1,
    port_id: options.port_id || "broker_rf_off_fixture_worker",
    test_only: true,
    binding,
    read_exchange() {
      calls.push("read");
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
      if (typeof options.on_prepare === "function") options.on_prepare();
      return structuredClone(exchangeStore.value);
    },
    commit_terminal(core) {
      calls.push("terminal");
      exchangeStore.value = {
        ...core,
        durable_receipt_digest: digest("broker-fixture-durable-terminal"),
        outbox_record_digest: digest("broker-fixture-outbox"),
        outbox_delivery_state: "pending",
        outbox_ack_digest: null,
      };
      return structuredClone(exchangeStore.value);
    },
    ack_terminal(ack) {
      calls.push("ack");
      if (options.fail_ack_before_commit) throw new Error("fixture ACK unavailable before commit");
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
      if (typeof options.on_observe_before === "function") options.on_observe_before();
      return {
        inventory_digest: digest("worker-inventory-before"),
        endpoint_identity_digest: binding.endpoint_identity_digest,
        dtr_asserted: false,
        rf_field_state: "off",
        field_witness_digest: digest("worker-field-before"),
      };
    },
    async open_transport() {
      calls.push("open");
      if (options.fail_open) throw new Error("fixture open failed after possible acquisition");
      return {
        opened: true,
        endpoint_identity_digest: binding.endpoint_identity_digest,
        dtr_asserted: false,
      };
    },
    async configure_transport() {
      calls.push("configure");
      if (typeof options.on_configure === "function") options.on_configure();
      return {
        configured: true,
        endpoint_identity_digest: binding.endpoint_identity_digest,
        dtr_asserted: false,
      };
    },
    async transact_transport() {
      calls.push("transact");
      if (typeof options.on_transact === "function") options.on_transact();
      return { response_bytes: Buffer.from([0x44, 0x55]) };
    },
    async commit_artifact_raw_custody(query) {
      calls.push("artifact");
      return {
        artifact_handle: `artifact:v1:${"D".repeat(43)}`,
        response_digest: crypto.createHash("sha256").update(query.response_bytes).digest("hex"),
        response_byte_length: query.response_bytes.length,
        vault_commit_receipt_digest: digest("worker-vault-commit"),
        raw_custody_receipt_digest: digest("worker-raw-custody"),
        vault_reservation_digest: binding.vault_reservation_digest,
        vault_ingest_capability_digest: binding.vault_ingest_capability_digest,
      };
    },
    observe_after() {
      calls.push("after");
      return {
        inventory_digest: digest("worker-inventory-after"),
        endpoint_identity_digest: binding.endpoint_identity_digest,
        dtr_asserted: false,
        rf_field_state: "off",
        field_witness_digest: digest("worker-field-after"),
      };
    },
    async close_transport() {
      calls.push("close");
      return {
        closed: true,
        endpoint_identity_digest: binding.endpoint_identity_digest,
        dtr_asserted: false,
        rf_field_state: "off",
        terminal_rf_off_witness_digest: digest("worker-terminal-field-off"),
        no_active_effects_witness_digest: digest("worker-terminal-no-active-effects"),
        witness_qualified: false,
      };
    },
  });
  return { calls, exchangeStore, port };
}

function createAuthority(reservation, compiled, command, binding, rawFence, overrides = {}) {
  const lineage = {
    compiler_id: compiled.compiler_id,
    compiler_manifest_digest: compiled.compiler_manifest_digest,
    compiler_registry_digest: compiled.compiler_registry_digest,
    compiled_command_id: command.compiled_command_id,
    compiled_command_capability_digest: command.compiled_command_capability_digest,
    compiled_operation_digest: command.compiled_operation_digest,
    provider_command_ref: PROVIDER_COMMAND_REF,
    command_input_ref: chameleonRfOffCommandInputRef(command),
    command_input_digest: command.compiled_command_capability_digest,
    maximum_response_bytes: compiled.maximum_response_bytes,
    vault_reservation_handle: binding.vault_reservation_handle,
    vault_reservation_digest: binding.vault_reservation_digest,
    vault_ingest_capability_digest: binding.vault_ingest_capability_digest,
    vault_byte_limit: binding.vault_byte_limit,
    worker_bundle_digest: binding.worker_bundle_digest,
    worker_launch_profile_digest: binding.worker_launch_profile_digest,
    worker_fence_plan_digest: binding.worker_fence_plan_digest,
    transport_profile_digest: binding.transport_profile_digest,
    durable_exchange_plan_digest: binding.durable_exchange_plan_digest,
    terminal_receipt_recipient_digest: binding.terminal_receipt_recipient_digest,
    safety_supervisor_plan_digest: digest("broker-fixture-safety-plan"),
  };
  const availability = getChameleonAvailabilityVariant(
    "CU-HF-14A-COMPILED-PROBE",
    compiled.variant_id,
  );
  const assertion = {
    session_nucleus_hash: reservation.reservationBinding.session_nucleus_hash,
    signed_grant_digest: digest("broker-fixture-signed-grant"),
    execution_request_digest: digest("broker-fixture-execution-request"),
    experiment_plan_hash: digest("broker-fixture-experiment-plan"),
    execution_lineage_digest: hashCanonicalJson({ version: 1, ...lineage }),
    execution_principal_id: reservation.reservationBinding.execution_principal_ref,
    attempt_ref: reservation.reservationBinding.attempt_ref,
    instrument_ref: reservation.held.receipt.allocations[0].resource_ref,
    lease_id: binding.lease_id,
    fencing_token: rawFence,
    fencing_generation: binding.fencing_generation,
    operation_id: "protocol.discovery_probe",
    provider_id: FIXTURE_AUTHORITY_PROVIDER_ID,
    provider_descriptor_digest: binding.provider_descriptor_digest,
    effect_not_before: reservation.reservationBinding.effect_not_before,
    effect_deadline: reservation.reservationBinding.effect_deadline,
    session_id: reservation.reservationBinding.session_id,
    node_id: reservation.reservationBinding.node_id,
    contract_hash: reservation.reservationBinding.contract_hash,
    prep_token_hash: reservation.reservationBinding.prep_token_hash,
    dispatch_event_id: reservation.reservationBinding.dispatch_event_id,
    graph_context_hash: reservation.reservationBinding.graph_context_hash,
    resource_bundle_digest: reservation.reservationBinding.resource_bundle_digest,
    operation_digest: chameleonRfOffOperationDigest(),
    parameter_digest: chameleonRfOffParameterDigest(compiled),
    requested_effects_digest: chameleonRfOffRequestedEffectsDigest(compiled),
    physical_scope_axis_digest: digest("broker-fixture-scope-axis"),
    physical_scope_policy_id: "fixture_physical_scope",
    physical_scope_policy_digest: digest("broker-fixture-scope-policy"),
    physical_scope_projection_digest: digest("broker-fixture-scope-projection"),
    authority_epoch: 7,
    revocation_generation: 2,
    authority_resolution_digest: digest("broker-fixture-authority-resolution"),
    caller_role_id: "evaluator-physical-agent",
    requester_principal_id: "principal:broker-fixture-requester",
    ipc_peer_principal_id: "principal:broker-fixture-worker",
    capability_pack_id: "physical",
    capability_pack_version: "1",
    capability_pack_digest: digest("broker-fixture-capability-pack"),
    technique_cell_id: "physical-cell:rf-off-fixture",
    inventory_observation_ref: "inventory-observation:rf-off-fixture",
    inventory_observation_digest: digest("broker-fixture-inventory-observation"),
    assurance_profile_id: compiled.minimum_assurance_profile_id,
    assurance_claims_digest: digest("broker-fixture-assurance-claims"),
    provider_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    availability_variant_id: compiled.variant_id,
    availability_variant_digest: availability.availability_variant_digest,
    authorized_transition_set_digest: digest("broker-fixture-transition-set"),
    workspace_snapshot_ref: "workspace-snapshot:rf-off-fixture",
    workspace_snapshot_digest: digest("broker-fixture-workspace"),
    observer_plan_digest: digest("broker-fixture-observer"),
    control_plan_digest: digest("broker-fixture-control"),
    cleanup_plan_digest: digest("broker-fixture-cleanup"),
    ...lineage,
    ...overrides,
  };
  return {
    assertion,
    port: createDeterministicMockDispatchAuthorityPort({
      port_id: "deterministic_chameleon_rf_off_fixture_authority",
      session_nucleus_hash: assertion.session_nucleus_hash,
      provider_id: assertion.provider_id,
      provider_descriptor_digest: assertion.provider_descriptor_digest,
      execution_principal_id: assertion.execution_principal_id,
      test_only_execution_assertion: assertion,
    }),
  };
}

function availabilityProjection(reservation, compiled, binding, authority, overrides = {}) {
  const variant = getChameleonAvailabilityVariant(
    "CU-HF-14A-COMPILED-PROBE",
    compiled.variant_id,
  );
  return {
    version: 1,
    provider_id: "chameleon_ultra",
    capability_id: "CU-HF-14A-COMPILED-PROBE",
    variant_id: compiled.variant_id,
    availability_variant_digest: variant.availability_variant_digest,
    availability_projection_digest: digest("broker-fixture-availability-projection"),
    availability_qualification_digest: digest("broker-fixture-availability-qualification"),
    dependency_binding_digest: digest("broker-fixture-dependency-binding"),
    signed_evidence_digest: digest("broker-fixture-signed-availability"),
    evidence_current_state_digest: digest("broker-fixture-availability-current-state"),
    replay_receipt_digest: digest("broker-fixture-availability-replay"),
    device_identity_digest: binding.device_identity_digest,
    custody_id: binding.custody_ref,
    session_id: reservation.reservationBinding.session_id,
    authority_id: "authority:broker-fixture",
    authority_epoch: authority.assertion.authority_epoch,
    revocation_generation: authority.assertion.revocation_generation,
    authority_resolution_digest: authority.assertion.authority_resolution_digest,
    runtime_available: true,
    evidence_qualified: true,
    production_ready: false,
    hil_verified: false,
    ...overrides,
  };
}

function createFixture(options = {}) {
  let monotonicMs = 1_000;
  const clockControl = options.clock_control || { monotonic_ms: null };
  const reservation = createPhysicalReservationFixture({
    ...(options.reservation || {}),
    read_monotonic_ms: options.reservation?.read_monotonic_ms || (() => {
      if (clockControl.monotonic_ms != null) return clockControl.monotonic_ms;
      monotonicMs += 25;
      return monotonicMs;
    }),
  });
  const compiled = compileHf14aProbe({
    version: 1,
    schema_id: options.schema_id || "iso14443a.requa_atqa_v1",
  });
  const command = encodeCompiledHf14aProbeForProviderWorker(compiled);
  const rawFence = "chameleon-rf-off-fixture-authority-fence";
  const binding = workerBinding(reservation, rawFence, options.binding);
  const worker = createWorkerPort(binding, options.worker);
  const authority = createAuthority(
    reservation,
    compiled,
    command,
    binding,
    rawFence,
    options.authority,
  );
  let availability = availabilityProjection(
    reservation,
    compiled,
    binding,
    authority,
    options.availability,
  );
  let availabilityResolveCount = 0;
  const availabilityPort = createFixtureChameleonRfOffAvailabilityResolverPort({
    version: 1,
    port_id: "broker_rf_off_fixture_availability",
    test_only: true,
    resolve_current() {
      availabilityResolveCount += 1;
      if (typeof options.on_availability_resolve === "function") {
        options.on_availability_resolve(availabilityResolveCount);
      }
      return structuredClone(availability);
    },
  });
  const executor = createChameleonRfOffUsbExecutor({
    version: 1,
    compiled_probe: compiled,
    compiled_command: command,
    dispatch_authority_port: authority.port,
    reservation_authority: reservation.authority,
    reservation_credential: reservation.held.credential,
    reservation_binding: reservation.reservationBinding,
    resource_allocation: reservation.held.receipt.allocations[0],
    trusted_clock_port: reservation.clock.port,
    availability_resolver_port: availabilityPort,
    worker_execution_port: worker.port,
  });
  return {
    authority,
    binding,
    compiled,
    command,
    executor,
    reservation,
    worker,
    setAvailability(overrides) { availability = { ...availability, ...overrides }; },
    setClockMonotonic(value) { clockControl.monotonic_ms = value; },
  };
}

function rehydrateCurrentFixtureReservation(fixture) {
  const projection = readPhysicalResourceReservationProjection(
    fixture.reservation.authority,
    fixture.reservation.reservationBinding.reservation_ref,
  );
  return rehydratePhysicalResourceReservationCredential(
    fixture.reservation.authority,
    {
      reservation_ref: projection.reservation_ref,
      receipt_digest: projection.receipt_digest,
    },
  );
}

function quarantineCurrentFixtureReservation(fixture) {
  return quarantinePhysicalResourceReservation(
    fixture.reservation.authority,
    rehydrateCurrentFixtureReservation(fixture),
  );
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

test("broker executes the prepared worker slice, releases reservation, ACKs outbox, and replays exactly", async () => {
  const fixture = createFixture();
  const projection = projectChameleonRfOffUsbExecutor(fixture.executor);
  assert.equal(projection.production_ready, false);
  assert.equal(projection.rf_off_qualified, false);
  assert.equal(projection.target_rf_transmit, true);
  assert.equal(projection.rf_off_stage_qualified, false);
  assert.equal(projection.qualification_blocker_code, "independent_rf_field_off_native_witness_missing");

  const outcome = await executeChameleonRfOffUsbProbe(fixture.executor);
  assert.equal(outcome.terminal_state, "completed_cleanup_confirmed");
  assert.equal(outcome.raw_response_bytes_projected, false);
  assert.equal(outcome.production_ready, false);
  assert.equal(outcome.hil_verified, false);
  assert.equal(outcome.rf_off_qualified, false);
  assert.equal(outcome.target_rf_transmit, true);
  assert.equal(outcome.rf_off_stage_qualified, false);
  assert.equal(outcome.dtr_off_qualified, false);
  assert.match(outcome.outbox_ack_digest, /^[a-f0-9]{64}$/u);
  assertScalarNullPrototypeProjection(outcome);
  const terminalReservation = readPhysicalResourceReservationProjection(
    fixture.reservation.authority,
    fixture.reservation.reservationBinding.reservation_ref,
  );
  assert.equal(terminalReservation.state, "released");
  assert.equal(terminalReservation.effect_state, "cleanup");
  assert.equal(terminalReservation.broker_reservation_digest, outcome.final_reservation_digest);
  assert.deepEqual(fixture.worker.calls.filter((entry) => entry === "open"), ["open"]);

  const replay = await fixture.executor.execute();
  assert.strictEqual(replay, outcome);
  assert.deepEqual(fixture.worker.calls.filter((entry) => entry === "open"), ["open"]);
});

test("durable terminal replay remains available after the original deadline and availability expiry", async () => {
  const fixture = createFixture();
  const outcome = await fixture.executor.execute();
  fixture.setAvailability({ revocation_generation: 3 });
  fixture.setClockMonotonic(60_000);
  assert.strictEqual(await fixture.executor.execute(), outcome);
  assert.deepEqual(fixture.worker.calls.filter((entry) => entry === "open"), ["open"]);
});

test("post-terminal deadline overrun is classified and quarantined instead of normally released", async () => {
  const clockControl = { monotonic_ms: null };
  const fixture = createFixture({
    clock_control: clockControl,
    worker: {
      on_transact() { clockControl.monotonic_ms = 50_000; },
    },
  });
  const outcome = await fixture.executor.execute();
  assert.equal(outcome.terminal_state, "completed_deadline_overrun_quarantined");
  assert.equal(outcome.completion_deadline_status, "deadline_overrun");
  assert.equal(outcome.completion_deadline_overrun, true);
  assert.equal(outcome.reservation_terminal_state, "quarantined");
  const projection = readPhysicalResourceReservationProjection(
    fixture.reservation.authority,
    fixture.reservation.reservationBinding.reservation_ref,
  );
  assert.equal(projection.state, "quarantined");
});

test("unavailable completion clock leaves deadline compliance unproven and quarantines", async () => {
  let failNextClockRead = false;
  const fixture = createFixture({
    reservation: {
      read_monotonic_ms() {
        if (failNextClockRead) {
          failNextClockRead = false;
          throw new Error("fixture completion clock unavailable");
        }
        return 1_025;
      },
    },
    worker: {
      on_transact() { failNextClockRead = true; },
    },
  });
  const outcome = await fixture.executor.execute();
  assert.equal(outcome.terminal_state, "completed_clock_unavailable_quarantined");
  assert.equal(outcome.completion_deadline_status, "clock_unavailable");
  assert.equal(outcome.completion_deadline_overrun, null);
  assert.equal(outcome.completion_deadline_compliance_proven, false);
  assert.equal(outcome.reservation_terminal_state, "quarantined");
  const projection = readPhysicalResourceReservationProjection(
    fixture.reservation.authority,
    fixture.reservation.reservationBinding.reservation_ref,
  );
  assert.equal(projection.state, "quarantined");
});

test("cold broker restart settles a lost terminal ACK after grant and availability expiry", async () => {
  const workerOptions = { fail_ack_before_commit: true };
  const fixture = createFixture({ worker: workerOptions });
  const restartedAuthority = createAuthority(
    fixture.reservation,
    fixture.compiled,
    fixture.command,
    fixture.binding,
    "chameleon-rf-off-fixture-authority-fence",
  );
  await assert.rejects(
    () => fixture.executor.execute(),
    (error) => error.code === "rf_off_usb_outbox_ack_ambiguous",
  );
  const preparedBinding = projectChameleonRfOffUsbPreparedRecoveryBinding(fixture.executor);
  const released = readPhysicalResourceReservationProjection(
    fixture.reservation.authority,
    fixture.reservation.reservationBinding.reservation_ref,
  );
  assert.equal(released.state, "released");
  fixture.setAvailability({ revocation_generation: 99 });
  fixture.setClockMonotonic(60_000);

  const restartedWorker = createWorkerPort(fixture.binding, {
    exchange_store: fixture.worker.exchangeStore,
    port_id: "broker_rf_off_fixture_worker",
  });
  const recoveryExecutor = createChameleonRfOffUsbRecoveryExecutor({
    version: 1,
    compiled_probe: fixture.compiled,
    dispatch_authority_port: restartedAuthority.port,
    reservation_authority: fixture.reservation.authority,
    reservation_binding: fixture.reservation.reservationBinding,
    resource_allocation: fixture.reservation.held.receipt.allocations[0],
    worker_execution_port: restartedWorker.port,
    prepared_request_binding: preparedBinding,
  });
  const outcome = await recoveryExecutor.execute();
  assert.equal(outcome.terminal_state, "completed_cleanup_confirmed");
  assert.equal(outcome.completion_deadline_status, "deadline_compliance_unproven_recovery");
  assert.equal(outcome.completion_deadline_overrun, null);
  assert.equal(outcome.completion_deadline_compliance_proven, false);
  assert.equal(outcome.reservation_terminal_state, "released");
  assert.equal(restartedWorker.calls.includes("open"), false);
  assert.equal(restartedWorker.exchangeStore.value.outbox_delivery_state, "acknowledged");
});

test("ambiguous worker open is quarantined and cannot be retried", async () => {
  const fixture = createFixture({ worker: { fail_open: true } });
  await assert.rejects(
    () => fixture.executor.execute(),
    (error) => error.code === "chameleon_rf_off_execution_quarantined",
  );
  const projection = readPhysicalResourceReservationProjection(
    fixture.reservation.authority,
    fixture.reservation.reservationBinding.reservation_ref,
  );
  assert.equal(projection.state, "quarantined");
  assert.equal(fixture.worker.calls.filter((entry) => entry === "open").length, 1);
  await assert.rejects(() => fixture.executor.execute());
  assert.equal(fixture.worker.calls.filter((entry) => entry === "open").length, 1);
});

test("cross-wired device availability fails before reservation effect start", async () => {
  const fixture = createFixture();
  fixture.setAvailability({ device_identity_digest: digest("lookalike-device") });
  await assert.rejects(
    () => fixture.executor.execute(),
    (error) => error.code === "chameleon_rf_off_availability_crosswired",
  );
  const projection = readPhysicalResourceReservationProjection(
    fixture.reservation.authority,
    fixture.reservation.reservationBinding.reservation_ref,
  );
  assert.equal(projection.state, "held");
  assert.equal(projection.effect_state, "not_started");
  assert.equal(fixture.worker.calls.includes("open"), false);
});

test("availability drift after durable prepare quarantines without executing the worker effect", async () => {
  let fixture;
  fixture = createFixture({
    worker: {
      on_prepare() {
        fixture.setAvailability({
          evidence_current_state_digest: digest("revoked-after-prepare"),
        });
      },
    },
  });
  await assert.rejects(
    () => fixture.executor.execute(),
    (error) => error.code === "chameleon_rf_off_prepared_admission_drift_quarantined",
  );
  const projection = readPhysicalResourceReservationProjection(
    fixture.reservation.authority,
    fixture.reservation.reservationBinding.reservation_ref,
  );
  assert.equal(projection.state, "quarantined");
  assert.equal(fixture.worker.calls.includes("open"), false);
  assert.equal(fixture.worker.calls.includes("transact"), false);
});

test("availability drift after effect-start marking quarantines before the worker opens the device", async () => {
  let fixture;
  fixture = createFixture({
    on_availability_resolve(resolveCount) {
      if (resolveCount === 3) {
        fixture.setAvailability({
          evidence_current_state_digest: digest("revoked-after-effect-start-mark"),
        });
      }
    },
  });
  await assert.rejects(
    () => fixture.executor.execute(),
    (error) => error.code === "chameleon_rf_off_execution_quarantined",
  );
  const projection = readPhysicalResourceReservationProjection(
    fixture.reservation.authority,
    fixture.reservation.reservationBinding.reservation_ref,
  );
  assert.equal(projection.state, "quarantined");
  assert.equal(fixture.worker.calls.includes("open"), false);
  assert.equal(fixture.worker.calls.includes("transact"), false);
});

test("concurrent reservation quarantine after effect-start marking fences before worker open", async () => {
  let fixture;
  fixture = createFixture({
    on_availability_resolve(resolveCount) {
      if (resolveCount !== 3) return;
      const projection = readPhysicalResourceReservationProjection(
        fixture.reservation.authority,
        fixture.reservation.reservationBinding.reservation_ref,
      );
      const credential = rehydratePhysicalResourceReservationCredential(
        fixture.reservation.authority,
        {
          reservation_ref: projection.reservation_ref,
          receipt_digest: projection.receipt_digest,
        },
      );
      quarantinePhysicalResourceReservation(fixture.reservation.authority, credential);
    },
  });
  await assert.rejects(
    () => fixture.executor.execute(),
    (error) => error.code === "chameleon_rf_off_execution_quarantined"
      && error.cause?.code === "resource_reservation_credential_stale",
  );
  const projection = readPhysicalResourceReservationProjection(
    fixture.reservation.authority,
    fixture.reservation.reservationBinding.reservation_ref,
  );
  assert.equal(projection.state, "quarantined");
  assert.equal(fixture.worker.calls.includes("open"), false);
  assert.equal(fixture.worker.calls.includes("transact"), false);
});

test("concurrent reservation cleanup and release after effect-start marking fences before worker open", async () => {
  let fixture;
  fixture = createFixture({
    on_availability_resolve(resolveCount) {
      if (resolveCount !== 3) return;
      const initial = readPhysicalResourceReservationProjection(
        fixture.reservation.authority,
        fixture.reservation.reservationBinding.reservation_ref,
      );
      const startedCredential = rehydratePhysicalResourceReservationCredential(
        fixture.reservation.authority,
        {
          reservation_ref: initial.reservation_ref,
          receipt_digest: initial.receipt_digest,
        },
      );
      const begun = beginPhysicalResourceCleanup(
        fixture.reservation.authority,
        startedCredential,
        `cleanup-handoff:${"A".repeat(48)}`,
      );
      completePhysicalResourceCleanup(fixture.reservation.authority, begun.credential);
    },
  });
  await assert.rejects(
    () => fixture.executor.execute(),
    (error) => error.code === "chameleon_rf_off_execution_ambiguous"
      && error.cause?.code === "resource_reservation_credential_stale",
  );
  const projection = readPhysicalResourceReservationProjection(
    fixture.reservation.authority,
    fixture.reservation.reservationBinding.reservation_ref,
  );
  assert.equal(projection.state, "released");
  assert.equal(fixture.worker.calls.includes("open"), false);
  assert.equal(fixture.worker.calls.includes("transact"), false);
});

test("deadline advance in the final availability seam fences before worker open", async () => {
  const clockControl = { monotonic_ms: null };
  const fixture = createFixture({
    clock_control: clockControl,
    on_availability_resolve(resolveCount) {
      if (resolveCount === 3) clockControl.monotonic_ms = 50_000;
    },
  });
  await assert.rejects(
    () => fixture.executor.execute(),
    (error) => error.code === "chameleon_rf_off_execution_quarantined"
      && error.cause?.code === "reservation_effect_window_expired",
  );
  const projection = readPhysicalResourceReservationProjection(
    fixture.reservation.authority,
    fixture.reservation.reservationBinding.reservation_ref,
  );
  assert.equal(projection.state, "quarantined");
  assert.equal(fixture.worker.calls.includes("open"), false);
  assert.equal(fixture.worker.calls.includes("transact"), false);
});

test("quarantine from observe-before is rechecked synchronously before worker open", async () => {
  let fixture;
  fixture = createFixture({
    worker: {
      on_observe_before() { quarantineCurrentFixtureReservation(fixture); },
    },
  });
  await assert.rejects(
    () => fixture.executor.execute(),
    (error) => error.code === "chameleon_rf_off_execution_quarantined",
  );
  assert.equal(fixture.worker.calls.includes("before"), true);
  assert.equal(fixture.worker.calls.includes("open"), false);
  assert.equal(fixture.worker.calls.includes("transact"), false);
});

test("deadline advance from observe-before is rechecked synchronously before worker open", async () => {
  const clockControl = { monotonic_ms: null };
  const fixture = createFixture({
    clock_control: clockControl,
    worker: {
      on_observe_before() { clockControl.monotonic_ms = 50_000; },
    },
  });
  await assert.rejects(
    () => fixture.executor.execute(),
    (error) => error.code === "chameleon_rf_off_execution_quarantined",
  );
  assert.equal(fixture.worker.calls.includes("before"), true);
  assert.equal(fixture.worker.calls.includes("open"), false);
  assert.equal(fixture.worker.calls.includes("transact"), false);
});

test("availability revocation from observe-before is rechecked before worker open", async () => {
  let fixture;
  fixture = createFixture({
    worker: {
      on_observe_before() {
        fixture.setAvailability({
          evidence_current_state_digest: digest("revoked-during-observe-before"),
        });
      },
    },
  });
  await assert.rejects(
    () => fixture.executor.execute(),
    (error) => error.code === "chameleon_rf_off_execution_quarantined",
  );
  assert.equal(fixture.worker.calls.includes("before"), true);
  assert.equal(fixture.worker.calls.includes("open"), false);
  assert.equal(fixture.worker.calls.includes("transact"), false);
});

test("admission resolver cannot advance authority generation or deadline at either effect phase", async (t) => {
  for (const phase of ["pre_open", "pre_transact"]) {
    for (const drift of ["authority_revocation_generation", "deadline"]) {
      await t.test(`${phase}:${drift}`, async () => {
        const clockControl = { monotonic_ms: null };
        const resolution = phase === "pre_open" ? 4 : 5;
        let fixture;
        fixture = createFixture({
          clock_control: clockControl,
          on_availability_resolve(resolveCount) {
            if (resolveCount !== resolution) return;
            if (drift === "deadline") clockControl.monotonic_ms = 50_000;
            else fixture.setAvailability({ revocation_generation: 3 });
          },
        });
        await assert.rejects(
          () => fixture.executor.execute(),
          (error) => error.code === "chameleon_rf_off_execution_quarantined",
        );
        assert.equal(
          fixture.worker.calls.includes("open"),
          phase === "pre_transact",
        );
        assert.equal(fixture.worker.calls.includes("transact"), false);
        assert.equal(
          fixture.worker.calls.includes("close"),
          phase === "pre_transact",
        );
      });
    }
  }
});

test("configure-time reservation, deadline, and availability drift close without RF transact", async (t) => {
  for (const variant of ["quarantine", "deadline", "availability"]) {
    await t.test(variant, async () => {
      const clockControl = { monotonic_ms: null };
      let fixture;
      fixture = createFixture({
        clock_control: clockControl,
        worker: {
          on_configure() {
            if (variant === "quarantine") quarantineCurrentFixtureReservation(fixture);
            if (variant === "deadline") clockControl.monotonic_ms = 50_000;
            if (variant === "availability") {
              fixture.setAvailability({
                evidence_current_state_digest: digest("revoked-during-configure"),
              });
            }
          },
        },
      });
      await assert.rejects(
        () => fixture.executor.execute(),
        (error) => error.code === "chameleon_rf_off_execution_quarantined",
      );
      assert.equal(fixture.worker.calls.includes("open"), true);
      assert.equal(fixture.worker.calls.includes("configure"), true);
      assert.equal(fixture.worker.calls.includes("transact"), false);
      assert.equal(fixture.worker.calls.includes("close"), true);
    });
  }
});
