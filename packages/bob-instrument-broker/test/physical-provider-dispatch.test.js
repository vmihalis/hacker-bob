"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  assertPhysicalProviderDispatchCapability,
  armPhysicalProviderDispatchBeforeEffectCancellation,
  closePhysicalProviderDispatchBeforeEffectCancellation,
  createPhysicalProviderCommandAuthorizationPort,
  createPhysicalProviderCommandRegistry,
  createPhysicalProviderCommandRequest,
  createPhysicalProviderCompletionVerificationPort,
  createPhysicalProviderDispatchBridge,
  createPhysicalProviderDispatchBridgeWithCancellationCapability,
  createPhysicalProviderDispatchHeadFence,
  executePhysicalProviderDispatchComposition,
  normalizePhysicalProviderBinding,
  projectPhysicalProviderDispatchCompositionBinding,
  projectPhysicalProviderDispatchCancellation,
  resolvePhysicalProviderCommand,
  resolvePhysicalProviderCommandAuthorization,
} = require("../lib/physical-provider-dispatch.js");
const {
  readPhysicalResourceReservationProjection,
} = require("../lib/resource-reservations.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/lib/verification-contracts.js");
const {
  createProductionPhysicalTechniqueCompositionRoot,
} = require("../../../mcp/lib/physical-technique-composition-root.js");
const {
  createDeterministicMockDispatchAuthorityPort,
} = require("../../../mcp/lib/physical-dispatch-authority.js");
const {
  normalizePhysicalResourceBundle,
  normalizeResourceAllocation,
} = require("../../../mcp/lib/physical-resource-contract.js");
const {
  clone,
  createPhysicalReservationFixture,
  digest,
} = require("./helpers/physical-reservation-fixture.js");

const COMMAND_REF = "command:fake-read";
const SECOND_COMMAND_REF = "command:fake-status";

function providerResult(completion, label) {
  return {
    version: 1,
    completion,
    provider_result_digest: digest(label),
    provider_receipt_ref: `provider-receipt:${label}`,
  };
}

function providerBinding(overrides = {}) {
  return {
    version: 1,
    provider_id: "deterministic_fake_physical_provider",
    provider_descriptor_digest: digest("fake-provider-descriptor"),
    semantic_manifest_digest: digest("fake-semantic-manifest"),
    device_ref: "device:fake-physical-device",
    device_identity_digest: digest("fake-device-identity"),
    custody_ref: "custody:fake-worker-custody",
    custody_identity_digest: digest("fake-custody-identity"),
    custody_epoch: 7,
    ...overrides,
  };
}

function authorizationDefinition(
  commandKind,
  commandRef,
  label,
  requestedEffectsDigest,
  resourceBinding,
  executionAuthority = {},
) {
  return {
    command_kind: commandKind,
    command_ref: commandRef,
    operation_id: executionAuthority.operation_id || "fake.provider.command.v1",
    operation_digest: executionAuthority.operation_digest || digest("fake-provider-operation"),
    semantic_owner_ref: `semantic-owner:${label}`,
    semantic_owner_digest: digest(`${label}-semantic-owner`),
    requested_effect_digest: requestedEffectsDigest,
    requested_effects_digest: executionAuthority.requested_effects_digest
      || digest("fake-provider-requested-effects"),
    resource_alias: resourceBinding.resource_alias,
    resource_ref: resourceBinding.resource_ref,
    resource_requirement_digest: resourceBinding.resource_requirement_digest,
  };
}

function commandDefinition(commandAuthorization, execute) {
  return {
    command_authorization: commandAuthorization,
    execute,
  };
}

function completionEvidence(binding, claim, overrides = {}) {
  const completion = overrides.completion || claim.completion;
  const evidence = {
    version: 1,
    completion_binding_digest: overrides.completion_binding_digest
      || binding.completion_binding_digest,
    completion,
    effect_disposition: overrides.effect_disposition || (completion === "confirmed"
      ? "requested_effect_committed"
      : "requested_effect_not_applied"),
    provider_result_digest: overrides.provider_result_digest || claim.provider_result_digest,
    provider_receipt_ref: Object.hasOwn(overrides, "provider_receipt_ref")
      ? overrides.provider_receipt_ref
      : claim.provider_receipt_ref,
    committed_receipt_ref: overrides.committed_receipt_ref
      || `completion-receipt:${binding.completion_binding_digest.slice(0, 32)}`,
  };
  const receiptBasis = {
    domain: "hacker-bob/physical-provider-completion-receipt/v1",
    ...evidence,
  };
  evidence.committed_receipt_digest = overrides.committed_receipt_digest
    || hashCanonicalJson(receiptBasis);
  evidence.completion_evidence_digest = overrides.completion_evidence_digest
    || hashCanonicalJson({
      ...receiptBasis,
      domain: "hacker-bob/physical-provider-completion-evidence/v1",
      committed_receipt_digest: evidence.committed_receipt_digest,
    });
  return evidence;
}

function createCompletionVerificationHarness(options = {}) {
  const records = new Map();
  const calls = [];
  const readCounts = new Map();
  const port = createPhysicalProviderCompletionVerificationPort({
    port_id: options.port_id || "deterministic_completion_verifier",
    evidence_domain_digest: options.evidence_domain_digest
      || digest("deterministic-completion-evidence-domain"),
    read_committed(query) {
      const key = query.completion_binding.completion_binding_digest;
      const readCount = (readCounts.get(key) || 0) + 1;
      readCounts.set(key, readCount);
      calls.push({ kind: "read", query, read_count: readCount });
      if (typeof options.read_committed === "function") {
        return options.read_committed({
          calls,
          completionEvidence,
          query,
          read_count: readCount,
          records,
        });
      }
      const record = records.get(key);
      return record == null ? null : clone(record);
    },
    verify_and_commit(query) {
      calls.push({ kind: "verify", query });
      if (typeof options.verify_and_commit === "function") {
        return options.verify_and_commit({ calls, completionEvidence, query, records });
      }
      const key = query.completion_binding.completion_binding_digest;
      const record = completionEvidence(query.completion_binding, query.provider_claim);
      if (!records.has(key)) records.set(key, clone(record));
      return clone(records.get(key));
    },
  });
  return { calls, port, readCounts, records };
}

function createProviderHarness(options = {}) {
  let observedBinding = providerBinding();
  const completionVerificationPort = options.completion_verification_port
    || createCompletionVerificationHarness().port;
  const calls = [];
  const behavior = {
    command: options.command_behavior || "confirmed",
    second: options.second_behavior || "confirmed",
    cleanup: options.cleanup_behavior || "confirmed",
    fence: options.fence_behavior || "confirmed",
    quarantine: options.quarantine_behavior || "confirmed",
  };
  const requestedEffectsDigest = options.requested_effects_digest
    || options.resource_bundle.requirements[0].requested_effect_digests[0];
  const executionAuthority = options.execution_authority || {};
  const resourceBinding = options.resource_binding || {
    resource_alias: options.resource_bundle.requirements[0].alias,
    resource_ref: options.receipt_allocations[0].resource_ref,
    resource_requirement_digest: hashCanonicalJson(options.resource_bundle.requirements[0]),
  };

  function implementation(kind, label) {
    return async (request) => {
      calls.push({ kind, request });
      const expected = {
        provider_id: "deterministic_fake_physical_provider",
        provider_descriptor_digest: digest("fake-provider-descriptor"),
        semantic_manifest_digest: digest("fake-semantic-manifest"),
        device_ref: "device:fake-physical-device",
        device_identity_digest: digest("fake-device-identity"),
        custody_ref: "custody:fake-worker-custody",
        custody_identity_digest: digest("fake-custody-identity"),
        custody_epoch: 7,
        command_ref: request.command_projection.command_ref,
        operation_id: request.command_projection.operation_id,
        operation_digest: request.command_projection.operation_digest,
        semantic_owner_digest: request.command_projection.semantic_owner_digest,
        requested_effects_digest: request.command_projection.requested_effects_digest,
        requested_effect_digest: request.command_projection.requested_effect_digest,
        resource_alias: request.command_projection.resource_alias,
        resource_ref: request.command_projection.resource_ref,
        resource_requirement_digest: request.command_projection.resource_requirement_digest,
        allocation_digest: request.command_projection.allocation_digest,
        command_input_ref: request.command_input_ref,
        command_input_digest: request.command_input_digest,
      };
      assertPhysicalProviderDispatchCapability(request.dispatch_capability, expected);
      assert.match(
        request.dispatch_capability.active_admission_binding_digest,
        /^[a-f0-9]{64}$/u,
      );
      for (const field of [
        "requester_principal_id",
        "ipc_peer_principal_id",
        "inventory_observation_ref",
        "workspace_snapshot_ref",
      ]) {
        assert.equal(
          Object.hasOwn(request.dispatch_capability, field),
          false,
          `${field} must stay broker-private`,
        );
      }
      const selected = behavior[kind];
      if (selected === "throw") {
        const error = new Error(`${kind} provider failure`);
        error.code = `fake_${kind}_failure`;
        throw error;
      }
      if (selected === "timeout") return new Promise(() => {});
      return providerResult(selected, `${label}-${calls.length}`);
    };
  }

  const authorizations = [
    authorizationDefinition(
      "command",
      COMMAND_REF,
      "fake-read-owner",
      requestedEffectsDigest,
      resourceBinding,
      executionAuthority,
    ),
    authorizationDefinition(
      "command",
      SECOND_COMMAND_REF,
      "fake-status-owner",
      requestedEffectsDigest,
      resourceBinding,
      executionAuthority,
    ),
    authorizationDefinition(
      "cleanup",
      "command:fake-cleanup",
      "fake-cleanup-owner",
      requestedEffectsDigest,
      resourceBinding,
      executionAuthority,
    ),
    authorizationDefinition(
      "fence",
      "command:fake-fence",
      "fake-fence-owner",
      requestedEffectsDigest,
      resourceBinding,
      executionAuthority,
    ),
    authorizationDefinition(
      "quarantine",
      "command:fake-quarantine",
      "fake-quarantine-owner",
      requestedEffectsDigest,
      resourceBinding,
      executionAuthority,
    ),
  ];
  const normalizedBinding = normalizePhysicalProviderBinding(observedBinding);
  const commandAuthorizationPort = createPhysicalProviderCommandAuthorizationPort({
    port_id: "fake_physical_semantic_authority",
    semantic_authority_digest: executionAuthority.execution_request_digest
      || digest("fake-physical-semantic-authority"),
    authorization_epoch: 4,
    provider_binding_digest: normalizedBinding.provider_binding_digest,
    reservation_binding: {
      reservation_request_digest: options.reservation_binding.reservation_request_digest,
      node_id: options.reservation_binding.node_id,
      contract_hash: options.reservation_binding.contract_hash,
      source_graph_hash: options.reservation_binding.source_graph_hash,
      session_nucleus_hash: options.reservation_binding.session_nucleus_hash,
      resource_bundle_digest: options.reservation_binding.resource_bundle_digest,
      allocation_digest: options.reservation_binding.allocation_digest,
    },
    resource_bundle: options.resource_bundle,
    receipt_allocations: options.receipt_allocations,
    authorizations,
  });
  const authorization = (commandRef) => (
    resolvePhysicalProviderCommandAuthorization(commandAuthorizationPort, commandRef)
  );
  const registry = createPhysicalProviderCommandRegistry({
    provider_binding: observedBinding,
    command_authorization_port: commandAuthorizationPort,
    completion_verification_port: completionVerificationPort,
    observe_binding: () => clone(observedBinding),
    commands: [
      commandDefinition(authorization(COMMAND_REF), implementation("command", "command")),
      commandDefinition(
        authorization(SECOND_COMMAND_REF),
        implementation("second", "second"),
      ),
    ],
    compensation: {
      cleanup: commandDefinition(
        authorization("command:fake-cleanup"),
        implementation("cleanup", "cleanup"),
      ),
      fence: commandDefinition(
        authorization("command:fake-fence"),
        implementation("fence", "fence"),
      ),
      quarantine: commandDefinition(
        authorization("command:fake-quarantine"),
        implementation("quarantine", "quarantine"),
      ),
    },
  });
  return {
    behavior,
    calls,
    commandAuthorizationPort,
    registry,
    setObservedBinding(overrides) {
      observedBinding = providerBinding(overrides);
    },
  };
}

function createDispatchAuthority(reservation, overrides = {}) {
  const compiledCommandDigest = digest("fake-compiled-command");
  const executionLineage = {
    compiler_id: "closed_fake_compiler_v1",
    compiler_manifest_digest: digest("fake-compiler-manifest"),
    compiler_registry_digest: digest("fake-compiler-registry"),
    compiled_command_id: "compiled-command:fake-1",
    compiled_command_capability_digest: compiledCommandDigest,
    compiled_operation_digest: digest("fake-compiled-operation"),
    provider_command_ref: COMMAND_REF,
    command_input_ref: "command-input:fake-compiled-1",
    command_input_digest: compiledCommandDigest,
    maximum_response_bytes: 64,
    vault_reservation_handle: `vault-reservation:v1:${"C".repeat(43)}`,
    vault_reservation_digest: digest("fake-vault-reservation"),
    vault_ingest_capability_digest: digest("fake-vault-ingest"),
    vault_byte_limit: 64,
    worker_bundle_digest: digest("fake-worker-bundle"),
    worker_launch_profile_digest: digest("fake-worker-launch-profile"),
    worker_fence_plan_digest: digest("fake-worker-fence"),
    transport_profile_digest: digest("fake-transport-profile"),
    durable_exchange_plan_digest: digest("fake-durable-exchange-plan"),
    terminal_receipt_recipient_digest: digest("fake-terminal-recipient"),
    safety_supervisor_plan_digest: digest("fake-safety-plan"),
  };
  const assertion = {
    session_nucleus_hash: reservation.reservationBinding.session_nucleus_hash,
    signed_grant_digest: digest("fake-signed-active-grant"),
    execution_request_digest: digest("fake-signed-execution-request"),
    experiment_plan_hash: digest("fake-experiment-plan"),
    execution_lineage_digest: hashCanonicalJson({ version: 1, ...executionLineage }),
    execution_principal_id: reservation.reservationBinding.execution_principal_ref,
    attempt_ref: reservation.reservationBinding.attempt_ref,
    instrument_ref: reservation.held.receipt.allocations[0].resource_ref,
    lease_id: "fake-active-lease-1",
    fencing_token: "fake-active-fence-1",
    fencing_generation: 1,
    operation_id: "fake.provider.command.v1",
    provider_id: "deterministic_fake_physical_provider",
    provider_descriptor_digest: digest("fake-provider-descriptor"),
    effect_not_before: reservation.reservationBinding.effect_not_before,
    effect_deadline: reservation.reservationBinding.effect_deadline,
    session_id: reservation.reservationBinding.session_id,
    node_id: reservation.reservationBinding.node_id,
    contract_hash: reservation.reservationBinding.contract_hash,
    prep_token_hash: reservation.reservationBinding.prep_token_hash,
    dispatch_event_id: reservation.reservationBinding.dispatch_event_id,
    graph_context_hash: reservation.reservationBinding.graph_context_hash,
    resource_bundle_digest: reservation.reservationBinding.resource_bundle_digest,
    operation_digest: digest("fake-provider-operation"),
    parameter_digest: digest("fake-provider-parameters"),
    requested_effects_digest: digest("fake-provider-requested-effects"),
    physical_scope_axis_digest: digest("fake-physical-scope-axis"),
    physical_scope_policy_id: "fake_physical_scope_policy",
    physical_scope_policy_digest: digest("fake-physical-scope-policy"),
    physical_scope_projection_digest: digest("fake-physical-scope-projection"),
    authority_epoch: 1,
    revocation_generation: 0,
    authority_resolution_digest: digest("fake-authority-resolution"),
    caller_role_id: "evaluator-physical-agent",
    requester_principal_id: "principal:fake-requester-1",
    ipc_peer_principal_id: "principal:fake-ipc-peer-1",
    capability_pack_id: "physical",
    capability_pack_version: "1",
    capability_pack_digest: digest("fake-capability-pack"),
    technique_cell_id: "physical-cell:fake-cell-1",
    inventory_observation_ref: "inventory-observation:fake-inventory-1",
    inventory_observation_digest: digest("fake-inventory-observation"),
    assurance_profile_id: "fake_assurance_profile",
    assurance_claims_digest: digest("fake-assurance-claims"),
    provider_manifest_digest: digest("fake-provider-manifest"),
    availability_variant_id: "fake-availability-variant",
    availability_variant_digest: digest("fake-availability-variant"),
    authorized_transition_set_digest: digest("fake-authorized-transition-set"),
    workspace_snapshot_ref: "workspace-snapshot:fake-workspace-1",
    workspace_snapshot_digest: digest("fake-workspace-snapshot"),
    observer_plan_digest: digest("fake-observer-plan"),
    control_plan_digest: digest("fake-control-plan"),
    cleanup_plan_digest: digest("fake-cleanup-plan"),
    ...executionLineage,
    ...overrides,
  };
  const port = createDeterministicMockDispatchAuthorityPort({
    port_id: "deterministic_fake_provider_dispatch_authority",
    session_nucleus_hash: assertion.session_nucleus_hash,
    provider_id: assertion.provider_id,
    provider_descriptor_digest: assertion.provider_descriptor_digest,
    execution_principal_id: assertion.execution_principal_id,
    test_only_execution_assertion: assertion,
  });
  return { assertion, port };
}

function createBridgeParts(options = {}) {
  const reservation = createPhysicalReservationFixture(options.reservation);
  const completion = createCompletionVerificationHarness(options.completion);
  const dispatchAuthority = createDispatchAuthority(
    reservation,
    options.dispatch_authority_overrides,
  );
  const provider = createProviderHarness({
    ...options.provider,
    execution_authority: {
      ...dispatchAuthority.assertion,
      ...options.provider_execution_authority_overrides,
    },
    reservation_binding: reservation.reservationBinding,
    resource_bundle: reservation.bundle,
    receipt_allocations: reservation.held.receipt.allocations,
    completion_verification_port: completion.port,
  });
  const bridgeInput = {
    reservation_authority: reservation.authority,
    reservation_credential: reservation.held.credential,
    reservation_binding: reservation.reservationBinding,
    dispatch_head_fence: createPhysicalProviderDispatchHeadFence({
      reservation_binding: reservation.reservationBinding,
      run_while_current: options.run_while_current || ((invoke) => invoke()),
    }),
    command_registry: provider.registry,
    dispatch_authority_port: dispatchAuthority.port,
    provider_call_timeout_ms: options.timeout_ms || 50,
  };
  return { bridgeInput, completion, dispatchAuthority, provider, reservation };
}

function createBridgeFixture(options = {}) {
  const parts = createBridgeParts(options);
  return { ...parts, bridge: createPhysicalProviderDispatchBridge(parts.bridgeInput) };
}

function makeDispatch(bridge, registry, commandRef, label = commandRef.replace("command:", "")) {
  const command = resolvePhysicalProviderCommand(registry, commandRef);
  const capability = bridge.createDispatchCapability(command);
  const ordinary = command.command_kind === "command";
  const request = createPhysicalProviderCommandRequest(capability, {
    command_input_ref: ordinary ? capability.command_input_ref : `command-input:${label}`,
    command_input_digest: ordinary ? capability.command_input_digest : digest(`${label}-input`),
  });
  return { capability, command, request };
}

function assertNoRawFence(value, rawFence) {
  const encoded = JSON.stringify(value);
  assert.doesNotMatch(encoded, /raw[_-]?fence/iu);
  assert.equal(encoded.includes(rawFence), false);
}

test("composition projection is signed-admission bound, report-safe, and non-authorizing", async () => {
  const fx = createBridgeFixture();
  const projection = projectPhysicalProviderDispatchCompositionBinding(fx.bridge);
  assert.equal(projection.session_nucleus_hash, fx.dispatchAuthority.assertion.session_nucleus_hash);
  assert.equal(
    projection.physical_scope_axis_digest,
    fx.dispatchAuthority.assertion.physical_scope_axis_digest,
  );
  assert.equal(
    projection.execution_request_digest,
    fx.dispatchAuthority.assertion.execution_request_digest,
  );
  assert.equal(
    projection.execution_lineage_digest,
    fx.dispatchAuthority.assertion.execution_lineage_digest,
  );
  assert.equal(projection.dispatch_phase, "held");
  assert.equal(projection.production_qualification, "blocked");
  assert.deepEqual(projection.production_blockers, [
    "signed_active_dispatch_admission_missing",
    "production_trusted_clock_missing",
    "production_completion_evidence_owner_missing",
    "privately_branded_provider_worker_vault_registry_missing",
    "independent_cleanup_restoration_owner_missing",
    "hardware_in_loop_qualification_missing",
  ]);
  assert.match(projection.composition_binding_digest, /^[a-f0-9]{64}$/u);
  const encoded = JSON.stringify(projection);
  for (const forbidden of [
    "deterministic_fake_physical_provider",
    "provider_id",
    "command_ref",
    "command_input",
    "device_ref",
  ]) assert.equal(encoded.includes(forbidden), false, `projection leaked ${forbidden}`);
  await assert.rejects(
    () => executePhysicalProviderDispatchComposition(fx.bridge),
    (error) => error.code === "physical_provider_dispatch_composition_not_production",
  );
  const enrollmentBasis = {
    version: 1,
    kind: "production_physical_technique_enrollment",
    target_domain: "composition-fixture.physical-technique.example",
    family: "physical_observe",
    execution_ref: "physical-execution:composition-fixture",
    cell_ref: "physical-cell:composition-fixture",
    assignment_context_digest: digest("composition-assignment"),
    session_nucleus_hash: projection.session_nucleus_hash,
    physical_scope_axis_digest: projection.physical_scope_axis_digest,
    technique_cell_id: projection.technique_cell_id,
    signed_attempt_ref: projection.attempt_ref,
    attempt_ref: "physical-attempt:composition-fixture",
    technique_id: "credential.discovery",
    signed_grant_digest: projection.signed_grant_digest,
    execution_request_digest: projection.execution_request_digest,
    execution_lineage_digest: projection.execution_lineage_digest,
    composition_binding_digest: projection.composition_binding_digest,
  };
  const enrollment = {
    ...enrollmentBasis,
    admission_binding_digest: hashCanonicalJson({
      domain: "hacker-bob/production-physical-technique-composition-enrollment/v1",
      ...enrollmentBasis,
    }),
  };
  assert.throws(
    () => createProductionPhysicalTechniqueCompositionRoot({
      version: 1,
      enrollment,
      provider_dispatch_bridge: fx.bridge,
      provider_worker_vault_root: Object.freeze({ production_ready: true }),
      transaction_capability: Object.freeze({}),
    }),
    (error) => error.code === "physical_technique_provider_dispatch_not_production"
      && error.production_blockers.includes("production_completion_evidence_owner_missing")
      && error.production_blockers.includes("independent_cleanup_restoration_owner_missing"),
  );
  assert.equal(fx.bridge.snapshot().phase, "held");
  assert.equal(fx.provider.calls.length, 0);
});

test("one ordinary provider command starts the exact reservation and every later command is refused", async () => {
  const fx = createBridgeFixture();
  const before = readPhysicalResourceReservationProjection(
    fx.reservation.authority,
    fx.reservation.held.receipt.reservation_ref,
  );
  assert.equal(before.effect_state, "not_started");

  const first = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF);
  const preStartedReplay = makeDispatch(
    fx.bridge,
    fx.provider.registry,
    COMMAND_REF,
    "pre-start-replay",
  );
  assert.throws(
    () => makeDispatch(fx.bridge, fx.provider.registry, SECOND_COMMAND_REF),
    (error) => error.code === "physical_dispatch_compiled_command_drift",
  );
  assertNoRawFence(first.capability, fx.reservation.storedRawFence);
  assertNoRawFence(first.request, fx.reservation.storedRawFence);
  const outcome = await fx.bridge.dispatch(first.capability, first.request);
  assert.equal(outcome.kind, "confirmed");
  assert.equal(fx.provider.calls[0].kind, "command");
  assert.throws(
    () => assertPhysicalProviderDispatchCapability(
      fx.provider.calls[0].request.dispatch_capability,
    ),
    (error) => error.code === "physical_provider_dispatch_capability_inactive",
  );
  assertNoRawFence(outcome, fx.reservation.storedRawFence);

  const started = readPhysicalResourceReservationProjection(
    fx.reservation.authority,
    fx.reservation.held.receipt.reservation_ref,
  );
  assert.equal(started.effect_state, "started");
  await assert.rejects(
    () => fx.bridge.dispatch(preStartedReplay.capability, preStartedReplay.request),
    (error) => error.code === "physical_dispatch_capability_stale",
  );
  const second = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF);
  await assert.rejects(
    () => fx.bridge.dispatch(second.capability, second.request),
    (error) => error.code === "physical_dispatch_command_already_consumed",
  );
  assert.deepEqual(fx.provider.calls.map((call) => call.kind), ["command"]);
  assert.equal(fx.bridge.snapshot().command_sequence, 1);
  assertNoRawFence(fx.bridge.snapshot(), fx.reservation.storedRawFence);
  assert.deepEqual(fx.bridge.readiness(), {
    version: 1,
    production_ready: false,
    provider_id: "deterministic_fake_physical_provider",
    command_registry_digest: fx.provider.registry.command_registry_digest,
    reservation_ref: fx.reservation.held.receipt.reservation_ref,
    authority_enforcement: "per-command-reservation-and-private-active-fence-set-v1",
    semantic_effect_enforcement: "private-reservation-bound-command-authorization-port-v1",
    semantic_authority_assurance: "signed_execution_request_digest_exact",
    active_dispatch_authority_assurance: "deterministic_mock_dispatch_authority_only",
    durable_active_instrument_lease_fence_assurance:
      "durable_active_instrument_lease_fence_not_integrated",
    task_graph_dispatch_head_assurance:
      "cooperative_same_process_session_lock_revalidated_before_provider_entry_v1",
    task_graph_provider_entry_atomicity:
      "no_cross_process_or_crash_atomic_commit",
    provider_custody_enforcement: "same-process-callback-observation-unattested",
    completion_evidence_enforcement:
      "exact-reservation-fence-provider-device-custody-command-input-capability-effect-and-receipt-v1",
    completion_evidence_consistency:
      "synchronous-linearizable-strong-read-after-commit-v1",
    completion_evidence_backend_assurance: "caller_asserted_callback_backend_unattested",
    completion_evidence_production_ready: false,
    safety_compensation: "broker_fence_first_provider_cleanup_deferred",
    reason:
      "production_attested_durable_completion_backend_crash_atomic_task_graph_provider_handoff_durable_active_instrument_lease_fence_os_watchdog_cleanup_process_custody_and_hil_required",
  });
});

test("lookalike, wrong-command, effect, receipt, allocation, and private-fence bindings fail before start", async () => {
  for (const field of [
    "command_ref",
    "operation_id",
    "operation_digest",
    "semantic_owner_digest",
    "requested_effect_digest",
    "requested_effects_digest",
    "resource_alias",
    "resource_ref",
    "resource_requirement_digest",
    "admission_receipt_digest",
    "allocation_digest",
    "admission_credential_binding_digest",
    "execution_lineage_digest",
    "compiled_command_capability_digest",
    "provider_command_ref",
    "active_command_input_ref",
    "active_command_input_digest",
    "command_input_ref",
    "command_input_digest",
    "vault_reservation_digest",
    "worker_bundle_digest",
  ]) {
    const fx = createBridgeFixture();
    const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, `drift-${field}`);
    const drifted = clone(dispatch.request);
    drifted[field] = field === "command_ref"
      ? SECOND_COMMAND_REF
      : field === "operation_id"
        ? "fake.provider.wrong.v1"
      : field === "provider_command_ref"
        ? SECOND_COMMAND_REF
      : field === "command_input_ref"
        ? "command-input:wrong-active-input"
      : field === "active_command_input_ref"
        ? "command-input:wrong-signed-active-input"
      : field === "resource_alias"
        ? "wrong_alias"
        : field === "resource_ref"
          ? "instrument:wrong-resource"
          : digest(`wrong-${field}`);
    await assert.rejects(
      () => fx.bridge.dispatch(dispatch.capability, drifted),
      (error) => error.code === "physical_dispatch_request_drift"
        || (["command_input_ref", "command_input_digest"].includes(field)
          && error.code === "physical_dispatch_compiled_command_drift"),
      field,
    );
    const projection = readPhysicalResourceReservationProjection(
      fx.reservation.authority,
      fx.reservation.held.receipt.reservation_ref,
    );
    assert.equal(projection.effect_state, "not_started", field);
    assert.equal(fx.provider.calls.length, 0, field);
  }

  const fx = createBridgeFixture();
  const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "lookalike");
  await assert.rejects(
    () => fx.bridge.dispatch(Object.freeze(clone(dispatch.capability)), dispatch.request),
    (error) => error.code === "physical_dispatch_capability_untrusted",
  );
});

test("a command capability is bridge-bound and single-use", async () => {
  const first = createBridgeFixture();
  const second = createBridgeFixture();
  const dispatch = makeDispatch(first.bridge, first.provider.registry, COMMAND_REF, "bridge-bound");
  await assert.rejects(
    () => second.bridge.dispatch(dispatch.capability, dispatch.request),
    (error) => error.code === "physical_dispatch_capability_wrong_bridge",
  );
  assert.equal((await first.bridge.dispatch(dispatch.capability, dispatch.request)).kind, "confirmed");
  await assert.rejects(
    () => first.bridge.dispatch(dispatch.capability, dispatch.request),
    (error) => error.code === "physical_dispatch_capability_replayed",
  );
});

test("failed construction retains transfer authority and successful construction is one-shot", async () => {
  const parts = createBridgeParts();
  assert.throws(
    () => createPhysicalProviderDispatchBridge({
      ...parts.bridgeInput,
      reservation_binding: {
        ...parts.bridgeInput.reservation_binding,
        contract_hash: digest("failed-transfer-contract-drift"),
      },
    }),
    (error) => error.code === "physical_dispatch_head_fence_binding_drift",
  );
  const bridge = createPhysicalProviderDispatchBridge(parts.bridgeInput);
  assert.equal(bridge.snapshot().phase, "held");
  assert.throws(
    () => createPhysicalProviderDispatchBridge(parts.bridgeInput),
    /already claimed/,
  );

  const concurrent = createBridgeParts();
  const results = await Promise.allSettled([0, 1].map(async () => (
    createPhysicalProviderDispatchBridge(concurrent.bridgeInput)
  )));
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected").length, 1);
  assert.match(results.find((result) => result.status === "rejected").reason.message, /already claimed/);
});

test("before-effect cancellation custody is private, branded, one-shot, and bridge-terminal", async () => {
  const ordinary = createBridgeFixture();
  assert.deepEqual(Reflect.ownKeys(ordinary.bridge).sort(), [
    "cleanup",
    "completeCleanup",
    "createDispatchCapability",
    "dispatch",
    "readiness",
    "snapshot",
  ]);

  const parts = createBridgeParts();
  const transferred = createPhysicalProviderDispatchBridgeWithCancellationCapability(
    parts.bridgeInput,
  );
  assertNoRawFence(transferred, parts.reservation.storedRawFence);
  assert.equal(Object.hasOwn(transferred.dispatch_bridge, "cancel"), false);
  assert.throws(
    () => armPhysicalProviderDispatchBeforeEffectCancellation(
      Object.freeze({ ...transferred.cancellation_capability }),
    ),
    (error) => error.code === "physical_dispatch_cancellation_capability_untrusted",
  );

  const command = makeDispatch(
    transferred.dispatch_bridge,
    parts.provider.registry,
    COMMAND_REF,
    "cancelled-before-effect",
  );
  const armed = armPhysicalProviderDispatchBeforeEffectCancellation(
    transferred.cancellation_capability,
  );
  assert.equal(armed.cancellation_state, "armed");
  assert.equal(armed.bridge_phase, "cancellation_pending");
  assert.deepEqual(
    projectPhysicalProviderDispatchCancellation(transferred.cancellation_capability),
    armed,
  );
  const closed = closePhysicalProviderDispatchBeforeEffectCancellation(
    transferred.cancellation_capability,
  );
  assert.equal(closed.kind, "cancelled");
  assert.equal(closed.idempotent, false);
  assert.equal(closePhysicalProviderDispatchBeforeEffectCancellation(
    transferred.cancellation_capability,
  ).idempotent, true);
  assert.equal(transferred.dispatch_bridge.snapshot().phase, "cancelled");
  await assert.rejects(
    () => transferred.dispatch_bridge.dispatch(command.capability, command.request),
    (error) => error.code === "physical_dispatch_terminal",
  );
});

test("a definitive start failure retains private before-effect cancellation authority", async () => {
  const parts = createBridgeParts({
    reservation: {
      effect_deadline: "2026-07-18T00:00:20.000Z",
      inventory_expires_at: "2026-07-18T00:00:40.000Z",
    },
  });
  const transferred = createPhysicalProviderDispatchBridgeWithCancellationCapability(
    parts.bridgeInput,
  );
  const command = makeDispatch(
    transferred.dispatch_bridge,
    parts.provider.registry,
    COMMAND_REF,
    "expired-before-start",
  );
  parts.reservation.clock.set("2026-07-18T00:00:21.000Z");

  await assert.rejects(
    () => transferred.dispatch_bridge.dispatch(command.capability, command.request),
    (error) => ["reservation_effect_window_expired", "resource_reservation_expired"].includes(
      error.code,
    ),
  );
  assert.equal(transferred.dispatch_bridge.snapshot().phase, "held");
  assert.equal(parts.provider.calls.length, 0);

  const armed = armPhysicalProviderDispatchBeforeEffectCancellation(
    transferred.cancellation_capability,
  );
  assert.equal(armed.cancellation_state, "armed");
  const closed = closePhysicalProviderDispatchBeforeEffectCancellation(
    transferred.cancellation_capability,
  );
  assert.equal(closed.kind, "expired");
  assert.equal(closed.receipt.terminal_disposition, "expired_before_effect");
  assert.equal(transferred.dispatch_bridge.snapshot().phase, "expired");
});

test("graph, preparation, provider, allocation, session, and window authority drift fail closed", () => {
  for (const [field, value] of [
    ["graph_context_hash", digest("authority-wrong-graph-context")],
    ["prep_token_hash", digest("authority-wrong-prep-token")],
    ["dispatch_event_id", "authority-wrong-dispatch-event"],
    ["provider_descriptor_digest", digest("authority-wrong-provider")],
    ["instrument_ref", "instrument:authority-wrong-allocation"],
    ["resource_bundle_digest", digest("authority-wrong-bundle")],
    ["session_id", "authority-wrong-session"],
    ["attempt_ref", "attempt:authority-wrong-attempt"],
    ["execution_principal_id", "principal:authority-wrong-worker"],
    ["effect_deadline", "2026-07-18T00:00:44.000Z"],
  ]) {
    assert.throws(
      () => createBridgeFixture({ dispatch_authority_overrides: { [field]: value } }),
      /binding drift|exact reservation allocation/u,
      field,
    );
  }
  for (const [field, value] of [
    ["operation_id", "fake.provider.other.v1"],
    ["operation_digest", digest("provider-wrong-operation")],
    ["requested_effects_digest", digest("provider-wrong-effects")],
  ]) {
    assert.throws(
      () => createBridgeFixture({
        provider_execution_authority_overrides: { [field]: value },
      }),
      (error) => error.code === "physical_dispatch_command_authority_drift",
      field,
    );
  }
});

test("semantic/effect authorization is privately bound to the exact reservation and bundle", () => {
  const reservation = createPhysicalReservationFixture();
  const allocationDigest = hashCanonicalJson(reservation.held.receipt.allocations);
  assert.throws(
    () => createProviderHarness({
      reservation_binding: reservation.reservationBinding,
      resource_bundle: reservation.bundle,
      receipt_allocations: reservation.held.receipt.allocations,
      requested_effects_digest: digest("effect-not-in-resource-bundle"),
    }),
    (error) => error.code === "physical_command_effect_not_in_bundle",
  );
  const driftedAllocations = clone(reservation.held.receipt.allocations);
  driftedAllocations[0].fencing_generation += 1;
  assert.throws(
    () => createProviderHarness({
      reservation_binding: reservation.reservationBinding,
      resource_bundle: reservation.bundle,
      receipt_allocations: driftedAllocations,
    }),
    (error) => error.code === "physical_command_authorization_allocation_drift",
  );
  const exactResourceBinding = {
    resource_alias: reservation.bundle.requirements[0].alias,
    resource_ref: reservation.held.receipt.allocations[0].resource_ref,
    resource_requirement_digest: hashCanonicalJson(reservation.bundle.requirements[0]),
  };
  for (const resourceBinding of [
    { ...exactResourceBinding, resource_alias: "wrong_alias" },
    { ...exactResourceBinding, resource_ref: "instrument:wrong-resource" },
    { ...exactResourceBinding, resource_requirement_digest: digest("wrong-requirement") },
  ]) {
    assert.throws(
      () => createProviderHarness({
        reservation_binding: reservation.reservationBinding,
        resource_bundle: reservation.bundle,
        receipt_allocations: reservation.held.receipt.allocations,
        resource_binding: resourceBinding,
      }),
      (error) => error.code === "physical_command_resource_binding_drift",
    );
  }
  const driftedBinding = {
    ...reservation.reservationBinding,
    contract_hash: digest("wrong-command-authority-contract"),
  };
  const dispatchAuthority = createDispatchAuthority(reservation);
  const provider = createProviderHarness({
    execution_authority: dispatchAuthority.assertion,
    reservation_binding: driftedBinding,
    resource_bundle: reservation.bundle,
    receipt_allocations: reservation.held.receipt.allocations,
  });
  assert.throws(
    () => createPhysicalProviderDispatchBridge({
      reservation_authority: reservation.authority,
      reservation_credential: reservation.held.credential,
      reservation_binding: reservation.reservationBinding,
      dispatch_head_fence: createPhysicalProviderDispatchHeadFence({
        reservation_binding: reservation.reservationBinding,
        run_while_current: (invoke) => invoke(),
      }),
      command_registry: provider.registry,
      dispatch_authority_port: dispatchAuthority.port,
    }),
    (error) => error.code === "physical_command_authorization_reservation_drift",
  );
  const exact = resolvePhysicalProviderCommand(provider.registry, COMMAND_REF);
  const exactAuthorization = resolvePhysicalProviderCommandAuthorization(
    provider.commandAuthorizationPort,
    COMMAND_REF,
  );
  assert.equal(exact.allocation_digest, allocationDigest);
  assert.equal(exactAuthorization.allocation_digest, allocationDigest);
  assert.equal(
    exact.command_authorization_digest,
    exactAuthorization.command_authorization_digest,
  );
});

test("multi-instrument authorization cannot borrow an effect from another allocated alias", () => {
  const reservation = createPhysicalReservationFixture();
  const firstRequirement = clone(reservation.bundle.requirements[0]);
  const secondEffect = digest("second-instrument-only-effect");
  const secondRequirement = {
    ...clone(firstRequirement),
    alias: "instrument_b",
    candidate_resource_refs: ["instrument:provider-dispatch-device-b"],
    requested_effect_digests: [secondEffect],
    required_state_epoch_digest: digest("provider-dispatch-device-b-state"),
  };
  const bundleInput = clone(reservation.bundle);
  delete bundleInput.resource_bundle_digest;
  bundleInput.bundle_id = "provider-dispatch-multi-instrument-test";
  bundleInput.requirements = [firstRequirement, secondRequirement];
  const bundle = normalizePhysicalResourceBundle(bundleInput);
  const firstAllocation = normalizeResourceAllocation(
    reservation.held.receipt.allocations[0],
  );
  const secondAllocation = normalizeResourceAllocation({
    ...clone(firstAllocation),
    alias: secondRequirement.alias,
    resource_ref: secondRequirement.candidate_resource_refs[0],
    state_epoch_digest: secondRequirement.required_state_epoch_digest,
    fencing_generation: firstAllocation.fencing_generation + 1,
    fencing_token_hash: digest("second-instrument-fence"),
  });
  const allocations = [firstAllocation, secondAllocation];
  const binding = normalizePhysicalProviderBinding(providerBinding());
  const wrongResourceBinding = {
    resource_alias: firstRequirement.alias,
    resource_ref: firstAllocation.resource_ref,
    resource_requirement_digest: hashCanonicalJson(firstRequirement),
  };
  const authorizationFor = (kind, commandRef) => authorizationDefinition(
    kind,
    commandRef,
    `multi-${kind}`,
    secondEffect,
    wrongResourceBinding,
  );
  assert.throws(
    () => createPhysicalProviderCommandAuthorizationPort({
      port_id: "multi_instrument_semantic_authority",
      semantic_authority_digest: digest("multi-instrument-semantic-authority"),
      authorization_epoch: 1,
      provider_binding_digest: binding.provider_binding_digest,
      reservation_binding: {
        reservation_request_digest: reservation.request.reservation_request_digest,
        node_id: reservation.request.node_id,
        contract_hash: reservation.request.contract_hash,
        source_graph_hash: reservation.request.source_graph_hash,
        session_nucleus_hash: reservation.request.session_nucleus_hash,
        resource_bundle_digest: bundle.resource_bundle_digest,
        allocation_digest: hashCanonicalJson(allocations),
      },
      resource_bundle: bundle,
      receipt_allocations: allocations,
      authorizations: [
        authorizationFor("command", "command:multi-read"),
        authorizationFor("cleanup", "command:multi-cleanup"),
        authorizationFor("fence", "command:multi-fence"),
        authorizationFor("quarantine", "command:multi-quarantine"),
      ],
    }),
    (error) => error.code === "physical_command_effect_not_in_bundle",
  );
});

test("provider, device, and custody drift are fenced before provider entry", async () => {
  for (const [field, value] of [
    ["provider_descriptor_digest", digest("wrong-provider")],
    ["device_identity_digest", digest("wrong-device")],
    ["custody_identity_digest", digest("wrong-custody")],
  ]) {
    const fx = createBridgeFixture();
    fx.provider.setObservedBinding({ [field]: value });
    const command = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, `drift-${field}`);
    const outcome = await fx.bridge.dispatch(command.capability, command.request);
    assert.equal(outcome.kind, "fenced", field);
    assert.equal(outcome.reason_code, "physical_provider_binding_drift", field);
    assert.equal(fx.provider.calls.length, 0, field);
    const projection = readPhysicalResourceReservationProjection(
      fx.reservation.authority,
      fx.reservation.held.receipt.reservation_ref,
    );
    assert.equal(projection.state, "fenced", field);
  }
});

test("reservation authority is revalidated inside the scheduled provider-entry callback", async () => {
  {
    let dispatchClockReads = 0;
    let dispatching = false;
    let expiredInSchedulingGap = false;
    const fx = createBridgeFixture({
      reservation: {
        effect_deadline: "2026-07-18T00:00:45.000Z",
        inventory_expires_at: "2026-07-18T00:00:20.000Z",
        read_monotonic_ms: () => {
          if (!dispatching) return 1_000;
          dispatchClockReads += 1;
          if (dispatchClockReads === 2) {
            queueMicrotask(() => { expiredInSchedulingGap = true; });
          }
          return expiredInSchedulingGap ? 20_000 : 1_000;
        },
      },
    });
    const command = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "inventory-expired");
    dispatching = true;
    const outcome = await fx.bridge.dispatch(command.capability, command.request);
    assert.equal(outcome.kind, "quarantined");
    assert.equal(outcome.reason_code, "resource_inventory_expired");
    assert.equal(outcome.compensation.provider_action_confirmed, false);
    assert.equal(fx.provider.calls.length, 0);
    assert.ok(dispatchClockReads >= 3);
  }
  {
    let dispatchClockReads = 0;
    let dispatching = false;
    let expiredInSchedulingGap = false;
    const fx = createBridgeFixture({
      reservation: {
        effect_deadline: "2026-07-18T00:00:20.000Z",
        inventory_expires_at: "2026-07-18T00:00:40.000Z",
        read_monotonic_ms: () => {
          if (!dispatching) return 1_000;
          dispatchClockReads += 1;
          if (dispatchClockReads === 2) {
            queueMicrotask(() => { expiredInSchedulingGap = true; });
          }
          return expiredInSchedulingGap ? 20_000 : 1_000;
        },
      },
    });
    const command = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "deadline-expired");
    dispatching = true;
    const outcome = await fx.bridge.dispatch(command.capability, command.request);
    assert.equal(outcome.kind, "fenced");
    assert.equal(outcome.reason_code, "reservation_effect_window_expired");
    assert.equal(fx.provider.calls.length, 0);
    assert.ok(dispatchClockReads >= 3);
  }
});

test("provider throw fences, explicit ambiguity quarantines, and timeout remains fail-closed", async () => {
  {
    const fx = createBridgeFixture({ provider: { command_behavior: "throw" } });
    const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "throw");
    const outcome = await fx.bridge.dispatch(dispatch.capability, dispatch.request);
    assert.equal(outcome.kind, "fenced");
    assert.equal(outcome.compensation.kind, "fence");
    assert.equal(outcome.compensation.authority_transition_confirmed, true);
    assert.equal(outcome.compensation.provider_action_confirmed, false);
    assert.deepEqual(fx.provider.calls.map((call) => call.kind), ["command"]);
  }
  {
    const fx = createBridgeFixture({ provider: { command_behavior: "ambiguous" } });
    const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "ambiguous");
    const outcome = await fx.bridge.dispatch(dispatch.capability, dispatch.request);
    assert.equal(outcome.kind, "quarantined");
    assert.equal(outcome.compensation.kind, "quarantine");
    assert.equal(outcome.compensation.authority_transition_confirmed, true);
    assert.equal(outcome.compensation.provider_action_confirmed, false);
    assert.deepEqual(fx.provider.calls.map((call) => call.kind), ["command"]);
  }
  {
    const fx = createBridgeFixture({
      provider: { command_behavior: "timeout" },
      timeout_ms: 10,
    });
    const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "timeout");
    const outcome = await fx.bridge.dispatch(dispatch.capability, dispatch.request);
    assert.equal(outcome.kind, "quarantined");
    assert.equal(outcome.reason_code, "physical_provider_timeout");
    assert.equal(outcome.compensation.kind, "quarantine");
    assert.equal(fx.bridge.snapshot().pending_provider_call_count, 1);
  }
});

test("a provider's self-asserted confirmation is never final without verified durable evidence", async () => {
  const fx = createBridgeFixture({
    completion: {
      verify_and_commit: () => null,
    },
  });
  const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "missing-evidence");
  const outcome = await fx.bridge.dispatch(dispatch.capability, dispatch.request);
  assert.equal(outcome.kind, "quarantined");
  assert.equal(outcome.reason_code, "physical_provider_completion_evidence_missing");
  assert.equal(outcome.reconciliation_required, true);
  assert.deepEqual(fx.provider.calls.map((call) => call.kind), ["command"]);
  assert.equal(Object.hasOwn(outcome, "completion_evidence_digest"), false);
});

test("verified completion evidence binds every physical and command authority dimension", async () => {
  const fx = createBridgeFixture();
  const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "bound-evidence");
  const outcome = await fx.bridge.dispatch(dispatch.capability, dispatch.request);
  assert.equal(outcome.kind, "confirmed");
  assert.match(outcome.committed_receipt_ref, /^completion-receipt:/u);
  assert.match(outcome.committed_receipt_digest, /^[a-f0-9]{64}$/u);
  assert.match(outcome.completion_evidence_digest, /^[a-f0-9]{64}$/u);
  assert.equal(outcome.effect_disposition, "requested_effect_committed");
  const verification = fx.completion.calls.find((call) => call.kind === "verify");
  const binding = verification.query.completion_binding;
  for (const field of [
    "domain",
    "reservation_ref",
    "admission_receipt_digest",
    "effect_receipt_digest",
    "reservation_binding_digest",
    "effect_credential_binding_digest",
    "effect_authorization_digest",
    "task_graph_dispatch_head_fence_digest",
    "provider_id",
    "provider_binding_digest",
    "device_identity_digest",
    "custody_identity_digest",
    "custody_epoch",
    "command_ref",
    "command_projection_digest",
    "command_authorization_digest",
    "command_input_ref",
    "command_input_digest",
    "provider_dispatch_capability_digest",
    "requested_effect_digest",
    "requested_effects_digest",
    "experiment_plan_hash",
    "execution_lineage_digest",
    "compiler_id",
    "compiler_manifest_digest",
    "compiler_registry_digest",
    "compiled_command_id",
    "compiled_command_capability_digest",
    "compiled_operation_digest",
    "provider_command_ref",
    "active_command_input_ref",
    "active_command_input_digest",
    "maximum_response_bytes",
    "vault_reservation_handle",
    "vault_reservation_digest",
    "vault_ingest_capability_digest",
    "vault_byte_limit",
    "worker_bundle_digest",
    "worker_launch_profile_digest",
    "worker_fence_plan_digest",
    "transport_profile_digest",
    "durable_exchange_plan_digest",
    "terminal_receipt_recipient_digest",
    "safety_supervisor_plan_digest",
    "physical_scope_axis_digest",
    "physical_scope_policy_id",
    "physical_scope_policy_digest",
    "physical_scope_projection_digest",
    "authority_epoch",
    "revocation_generation",
    "authority_resolution_digest",
    "caller_role_id",
    "requester_principal_id",
    "ipc_peer_principal_id",
    "capability_pack_id",
    "capability_pack_version",
    "capability_pack_digest",
    "technique_cell_id",
    "inventory_observation_ref",
    "inventory_observation_digest",
    "assurance_profile_id",
    "assurance_claims_digest",
    "provider_manifest_digest",
    "availability_variant_id",
    "availability_variant_digest",
    "authorized_transition_set_digest",
    "workspace_snapshot_ref",
    "workspace_snapshot_digest",
    "observer_plan_digest",
    "control_plan_digest",
    "cleanup_plan_digest",
    "active_admission_binding_digest",
  ]) assert.ok(binding[field] != null, field);
  assert.equal(
    fx.completion.calls.filter((call) => call.kind === "read").length,
    2,
    "one pre-entry read and one strong post-commit readback",
  );
});

test("lost provider responses recover only the exact committed evidence and never replay hardware", async () => {
  const committedClaim = providerResult("confirmed", "lost-provider-response");
  const fx = createBridgeFixture({
    provider: { command_behavior: "throw" },
    completion: {
      read_committed: ({ completionEvidence: makeEvidence, query, read_count: readCount }) => (
        readCount === 1
          ? null
          : makeEvidence(query.completion_binding, committedClaim)
      ),
    },
  });
  const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "lost-response");
  const outcome = await fx.bridge.dispatch(dispatch.capability, dispatch.request);
  assert.equal(outcome.kind, "confirmed");
  assert.equal(outcome.provider_result_digest, committedClaim.provider_result_digest);
  assert.equal(outcome.completion_source, "durable_readback_after_provider_response_loss");
  assert.equal(outcome.reconciliation_required, false);
  assert.deepEqual(fx.provider.calls.map((call) => call.kind), ["command"]);
  assert.equal(fx.completion.calls.some((call) => call.kind === "verify"), false);
});

test("forged, lookalike, cross-command, and cross-reservation completion evidence fails closed", async () => {
  for (const [label, overrides] of [
    ["cross-command", { completion_binding_digest: digest("foreign-command-binding") }],
    ["cross-reservation", { completion_binding_digest: digest("foreign-reservation-binding") }],
    ["wrong-disposition", { effect_disposition: "requested_effect_not_applied" }],
    ["forged-receipt", { committed_receipt_digest: digest("forged-committed-receipt") }],
    ["forged-evidence", { completion_evidence_digest: digest("forged-completion-evidence") }],
    ["cross-claim", { provider_result_digest: digest("foreign-provider-result") }],
  ]) {
    const fx = createBridgeFixture({
      completion: {
        verify_and_commit: ({ completionEvidence: makeEvidence, query }) => makeEvidence(
          query.completion_binding,
          query.provider_claim,
          overrides,
        ),
      },
    });
    const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, label);
    const outcome = await fx.bridge.dispatch(dispatch.capability, dispatch.request);
    assert.equal(outcome.kind, "quarantined", label);
    assert.equal(outcome.reconciliation_required, true, label);
    assert.deepEqual(fx.provider.calls.map((call) => call.kind), ["command"], label);
  }

  const reservation = createPhysicalReservationFixture();
  const weakLookalike = Object.freeze({
    version: 1,
    port_id: "weak_completion_verifier",
    evidence_domain_digest: digest("weak-completion-domain"),
    consistency_contract: "eventually-consistent",
    durability_assurance: "none",
    production_ready: true,
  });
  assert.throws(
    () => createProviderHarness({
      completion_verification_port: weakLookalike,
      reservation_binding: reservation.reservationBinding,
      resource_bundle: reservation.bundle,
      receipt_allocations: reservation.held.receipt.allocations,
    }),
    (error) => error.code === "physical_provider_completion_port_untrusted",
  );
});

test("completion verification rejects asynchronous ports and weak commit acknowledgement", async () => {
  assert.throws(
    () => createPhysicalProviderCompletionVerificationPort({
      port_id: "async_completion_verifier",
      evidence_domain_digest: digest("async-completion-domain"),
      read_committed: async () => null,
      verify_and_commit: () => null,
    }),
    (error) => error.code === "physical_provider_completion_port_invalid",
  );

  {
    const fx = createBridgeFixture({
      completion: {
        read_committed: () => Promise.resolve(null),
      },
    });
    const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "thenable-read");
    const outcome = await fx.bridge.dispatch(dispatch.capability, dispatch.request);
    assert.equal(outcome.kind, "quarantined");
    assert.equal(outcome.reason_code, "physical_provider_completion_port_async");
    assert.equal(fx.provider.calls.length, 0);
  }

  {
    const fx = createBridgeFixture({
      completion: {
        verify_and_commit: ({ completionEvidence: makeEvidence, query }) => makeEvidence(
          query.completion_binding,
          query.provider_claim,
        ),
      },
    });
    const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "weak-commit");
    const outcome = await fx.bridge.dispatch(dispatch.capability, dispatch.request);
    assert.equal(outcome.kind, "quarantined");
    assert.equal(outcome.reason_code, "physical_provider_completion_not_durable");
    assert.deepEqual(fx.provider.calls.map((call) => call.kind), ["command"]);
  }
});

test("explicit cleanup is itself capability-gated and releases only after confirmed cleanup", async () => {
  const fx = createBridgeFixture();
  const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "cleanup-start");
  assert.equal((await fx.bridge.dispatch(dispatch.capability, dispatch.request)).kind, "confirmed");
  const cleanup = makeDispatch(
    fx.bridge,
    fx.provider.registry,
    fx.provider.registry.compensation.cleanup.command_ref,
    "cleanup",
  );
  const outcome = await fx.bridge.cleanup(cleanup.capability, cleanup.request);
  assert.equal(outcome.kind, "cleanup_pending");
  assert.equal(outcome.reason_code, "physical_cleanup_confirmed");
  assert.deepEqual(fx.provider.calls.map((call) => call.kind), ["command", "cleanup"]);
  const cleanupVerification = fx.completion.calls
    .filter((call) => call.kind === "verify")
    .at(-1);
  assert.equal(
    cleanupVerification.query.completion_binding.active_command_input_ref,
    dispatch.capability.command_input_ref,
  );
  assert.equal(
    cleanupVerification.query.completion_binding.active_command_input_digest,
    dispatch.capability.command_input_digest,
  );
  assert.equal(
    cleanupVerification.query.completion_binding.command_input_ref,
    cleanup.request.command_input_ref,
  );
  assert.notEqual(
    cleanupVerification.query.completion_binding.active_command_input_ref,
    cleanupVerification.query.completion_binding.command_input_ref,
  );
  fx.reservation.clock.set("2026-07-18T00:00:03.000Z");
  const released = await fx.bridge.completeCleanup();
  assert.equal(released.kind, "released");
  const projection = readPhysicalResourceReservationProjection(
    fx.reservation.authority,
    fx.reservation.held.receipt.reservation_ref,
  );
  assert.equal(projection.state, "released");
  assert.equal(projection.effect_state, "cleanup");
  assertNoRawFence(outcome, fx.reservation.storedRawFence);
});

test("cleanup cannot release custody from its own unverified confirmation", async () => {
  const fx = createBridgeFixture({
    completion: {
      verify_and_commit: ({ completionEvidence: makeEvidence, query, records }) => {
        if (query.completion_binding.command_kind === "cleanup") return null;
        const record = makeEvidence(query.completion_binding, query.provider_claim);
        records.set(query.completion_binding.completion_binding_digest, clone(record));
        return clone(record);
      },
    },
  });
  const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "cleanup-unverified-start");
  assert.equal((await fx.bridge.dispatch(dispatch.capability, dispatch.request)).kind, "confirmed");
  const cleanup = makeDispatch(
    fx.bridge,
    fx.provider.registry,
    fx.provider.registry.compensation.cleanup.command_ref,
    "cleanup-unverified",
  );
  const outcome = await fx.bridge.cleanup(cleanup.capability, cleanup.request);
  assert.equal(outcome.kind, "quarantined");
  assert.equal(outcome.reason_code, "physical_provider_completion_evidence_missing");
  assert.equal(outcome.reconciliation_required, true);
  assert.equal(fx.bridge.snapshot().phase, "quarantined");
  assert.deepEqual(fx.provider.calls.map((call) => call.kind), ["command", "cleanup"]);
});

test("confirmed-no-effect invokes registered cleanup and never exposes private raw fences", async () => {
  const fx = createBridgeFixture({ provider: { command_behavior: "confirmed_no_effect" } });
  const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "no-effect");
  const outcome = await fx.bridge.dispatch(dispatch.capability, dispatch.request);
  assert.equal(outcome.kind, "cleanup_pending");
  assert.equal(outcome.reason_code, "provider-confirmed-no-effect");
  assert.deepEqual(fx.provider.calls.map((call) => call.kind), ["command", "cleanup"]);
  fx.reservation.clock.set("2026-07-18T00:00:03.000Z");
  assert.equal((await fx.bridge.completeCleanup()).kind, "released");
  for (const value of [
    fx.provider.registry,
    dispatch.capability,
    dispatch.request,
    outcome,
    fx.bridge.snapshot(),
    fx.bridge.readiness(),
  ]) assertNoRawFence(value, fx.reservation.storedRawFence);
});

test("cleanup lifecycle transition failures return fail-closed reconciliation outcomes", async () => {
  {
    const fx = createBridgeFixture();
    const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "begin-failure");
    assert.equal((await fx.bridge.dispatch(dispatch.capability, dispatch.request)).kind, "confirmed");
    const cleanup = makeDispatch(
      fx.bridge,
      fx.provider.registry,
      fx.provider.registry.compensation.cleanup.command_ref,
      "begin-transition-failure",
    );
    fx.reservation.memory.throwBeforeNext = true;
    const outcome = await fx.bridge.cleanup(cleanup.capability, cleanup.request);
    assert.deepEqual(fx.provider.calls.map((call) => call.kind), ["command", "cleanup"]);
    assert.equal(outcome.kind, "ambiguous");
    assert.equal(outcome.reason_code, "reservation_terminal_transition_failed");
    assert.equal(outcome.reconciliation_required, true);
    assert.equal(fx.bridge.snapshot().phase, "ambiguous");
  }
  {
    const fx = createBridgeFixture();
    const dispatch = makeDispatch(fx.bridge, fx.provider.registry, COMMAND_REF, "complete-failure");
    assert.equal((await fx.bridge.dispatch(dispatch.capability, dispatch.request)).kind, "confirmed");
    const cleanup = makeDispatch(
      fx.bridge,
      fx.provider.registry,
      fx.provider.registry.compensation.cleanup.command_ref,
      "complete-transition-failure",
    );
    assert.equal((await fx.bridge.cleanup(cleanup.capability, cleanup.request)).kind, "cleanup_pending");
    fx.reservation.clock.set("2026-07-18T00:00:03.000Z");
    fx.reservation.memory.throwBeforeNext = true;
    const outcome = await fx.bridge.completeCleanup();
    assert.deepEqual(fx.provider.calls.map((call) => call.kind), ["command", "cleanup"]);
    assert.equal(outcome.kind, "ambiguous");
    assert.equal(outcome.reason_code, "reservation_terminal_transition_failed");
    assert.equal(outcome.reconciliation_required, true);
  }
});
