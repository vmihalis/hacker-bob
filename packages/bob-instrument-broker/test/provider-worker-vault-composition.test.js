"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  PROVIDER_WORKER_VAULT_CONFORMANCE_ASSURANCE,
  PROVIDER_WORKER_VAULT_PROTOCOL_FIXTURE_ASSURANCE,
  assertProviderWorkerVaultProductionPortSet,
  assertProviderWorkerVaultCompositionRoot,
  createProviderWorkerVaultCompositionRoot,
  createProviderWorkerVaultConformanceComponents,
  createProviderWorkerVaultConformanceTransactionCapability,
  createProviderWorkerVaultProductionProtocolFixtureComponents,
  normalizeProviderWorkerVaultExecutionLineage,
} = require("../lib/provider-worker-vault-composition.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/lib/verification-contracts.js");

const VERSION = 1;
const LINEAGE_DOMAIN = "hacker-bob/provider-worker-vault-execution-lineage/v1";
const ROOT_CAPABILITIES = new WeakMap();

function compiledDelegate(boundLineage) {
  return Object.freeze({
    version: VERSION,
    kind: "compiled_provider_command_capability",
    compiled_command_id: boundLineage.compiled_command_id,
    provider_id: boundLineage.provider_id,
    compiler_id: boundLineage.compiler_id,
    compiler_manifest_digest: boundLineage.compiler_manifest_digest,
    compiler_registry_digest: boundLineage.compiler_registry_digest,
    source_profile_digest: boundLineage.source_profile_digest,
    schema_id: boundLineage.schema_id,
    operation_id: boundLineage.operation_id,
    capability_id: boundLineage.capability_id,
    variant_id: boundLineage.variant_id,
    parameter_selector_id: boundLineage.parameter_selector_id,
    canonical_command_digest: boundLineage.canonical_command_digest,
    compiled_operation_digest: boundLineage.compiled_operation_digest,
    compiled_command_capability_digest: boundLineage.compiled_command_capability_digest,
    runtime_availability: boundLineage.runtime_availability,
    execution_authority: false,
    production_ready: false,
    toJSON() {
      throw new Error("compiled command fixture is opaque");
    },
  });
}

function digest(label) {
  return hashCanonicalJson({ fixture: label });
}

function signedRecord(domain, projection, digestField) {
  return {
    ...projection,
    [digestField]: hashCanonicalJson({ domain, ...projection }),
  };
}

function lineage(overrides = {}) {
  const basis = {
    version: VERSION,
    execution_ref: "execution:test-0001",
    experiment_plan_hash: digest("experiment-plan"),
    exchange_id: "exchange:test-0001",
    grant_envelope_digest: digest("grant-envelope"),
    grant_journal_entry_digest: digest("grant-journal"),
    go_envelope_digest: digest("go-envelope"),
    go_journal_entry_digest: digest("go-journal"),
    session_nucleus_hash: digest("session-nucleus"),
    task_id: "task:test-0001",
    attempt_id: "attempt:test-0001",
    lease_id: "lease:test-0001",
    resource_epoch: "17",
    resource_fence_digest: digest("resource-fence"),
    effect_deadline_monotonic_ns: "99000000000",
    provider_id: "provider:fixture-neutral",
    operation_id: "operation:hf14a-rf-off-probe",
    compiler_id: "compiler:hf14a-probe-v1",
    compiler_manifest_digest: digest("compiler-manifest"),
    compiler_registry_digest: digest("compiler-registry"),
    source_profile_digest: digest("source-profile"),
    schema_id: "schema:hf14a-probe-v1",
    capability_id: "capability:hf14a-probe",
    variant_id: "variant:rf-off",
    parameter_selector_id: "parameters:fixed-safe-probe",
    canonical_command_digest: digest("canonical-command"),
    compiled_operation_digest: digest("compiled-operation"),
    provider_command_ref: "provider-command:hf14a-probe",
    requested_effects_digest: digest("requested-effects"),
    safety_supervisor_plan_digest: digest("safety-supervisor-plan"),
    runtime_availability: "fixture_runtime_only",
    compiled_command_id: "compiled-command:test-0001",
    compiled_command_capability_digest: digest("compiled-command-capability"),
    expected_result_code: "hf14a_probe_ok",
    active_command_input_ref: "command-input:active-test-0001",
    active_command_input_digest: digest("active-command-input"),
    cleanup_command_input_ref: "command-input:cleanup-test-0001",
    cleanup_command_input_digest: digest("cleanup-command-input"),
    maximum_response_bytes: 1024,
    vault_reservation_handle: "vault-reservation:v1:test-0001",
    vault_reservation_digest: digest("vault-reservation"),
    vault_ingest_capability_digest: digest("vault-ingest-capability"),
    vault_byte_ceiling: 2048,
    worker_bundle_digest: digest("worker-bundle"),
    worker_launch_digest: digest("worker-launch"),
    worker_process_instance_digest: digest("worker-process-instance"),
    worker_fence_digest: digest("worker-fence"),
    transport_binding_digest: digest("transport-binding"),
    durable_exchange_plan_digest: digest("durable-exchange-plan"),
    terminal_receipt_recipient_digest: digest("terminal-recipient"),
    ...overrides,
  };
  return {
    ...basis,
    execution_lineage_digest: hashCanonicalJson({ domain: LINEAGE_DOMAIN, ...basis }),
  };
}

function mutateResult(options, name, result, request) {
  const mutation = options[name];
  if (mutation === "throw") throw new Error(`secret-${name}-failure`);
  return typeof mutation === "function" ? mutation(result, request) : result;
}

function createHarness(options = {}) {
  const calls = [];
  const durableState = options.durable_state || {
    claims: new Map(),
    terminals: new Map(),
  };
  const commandHandle = Object.freeze({ kind: "fixture_command_claim", id: "command-claim:1" });
  const workerHandle = Object.freeze({ kind: "fixture_worker", id: "worker:1" });
  const fenceHandle = Object.freeze({ kind: "fixture_worker_fence", id: "worker-fence:1" });

  const callbacks = {
    version: VERSION,
    redeem_grant(request) {
      calls.push({ step: "redeem", request });
      const l = request.lineage;
      return mutateResult(options, "redeem", signedRecord(
        "hacker-bob/provider-worker-vault-grant-redemption-receipt/v1",
        {
          version: VERSION,
          kind: "grant_redemption_receipt",
          execution_lineage_digest: l.execution_lineage_digest,
          exchange_id: l.exchange_id,
          grant_envelope_digest: l.grant_envelope_digest,
          grant_journal_entry_digest: l.grant_journal_entry_digest,
          go_envelope_digest: l.go_envelope_digest,
          go_journal_entry_digest: l.go_journal_entry_digest,
          active_command_input_ref: l.active_command_input_ref,
          active_command_input_digest: l.active_command_input_digest,
          cleanup_command_input_ref: l.cleanup_command_input_ref,
          cleanup_command_input_digest: l.cleanup_command_input_digest,
        },
        "receipt_digest",
      ), request);
    },
    claim_compiled_command(request) {
      calls.push({ step: "claim", request });
      const l = request.lineage;
      return mutateResult(options, "claim", {
        ...signedRecord(
          "hacker-bob/provider-worker-vault-compiled-command-claim/v1",
          {
            version: VERSION,
            kind: "compiled_command_claim_receipt",
            execution_lineage_digest: l.execution_lineage_digest,
            provider_id: l.provider_id,
            operation_id: l.operation_id,
            compiler_id: l.compiler_id,
            compiler_manifest_digest: l.compiler_manifest_digest,
            compiler_registry_digest: l.compiler_registry_digest,
            source_profile_digest: l.source_profile_digest,
            schema_id: l.schema_id,
            capability_id: l.capability_id,
            variant_id: l.variant_id,
            parameter_selector_id: l.parameter_selector_id,
            canonical_command_digest: l.canonical_command_digest,
            compiled_operation_digest: l.compiled_operation_digest,
            provider_command_ref: l.provider_command_ref,
            requested_effects_digest: l.requested_effects_digest,
            safety_supervisor_plan_digest: l.safety_supervisor_plan_digest,
            runtime_availability: l.runtime_availability,
            compiled_command_id: l.compiled_command_id,
            compiled_command_capability_digest: l.compiled_command_capability_digest,
            active_command_input_ref: l.active_command_input_ref,
            active_command_input_digest: l.active_command_input_digest,
            maximum_response_bytes: l.maximum_response_bytes,
          },
          "claim_receipt_digest",
        ),
        command_handle: commandHandle,
      }, request);
    },
    launch_worker(request) {
      calls.push({ step: "launch", request });
      const l = request.lineage;
      return mutateResult(options, "launch", {
        ...signedRecord(
          "hacker-bob/provider-worker-vault-worker-launch/v1",
          {
            version: VERSION,
            kind: "worker_launch_receipt",
            execution_lineage_digest: l.execution_lineage_digest,
            worker_bundle_digest: l.worker_bundle_digest,
            worker_launch_digest: l.worker_launch_digest,
            worker_process_instance_digest: l.worker_process_instance_digest,
          },
          "launch_receipt_digest",
        ),
        worker_handle: workerHandle,
      }, request);
    },
    assert_worker_fence(request) {
      calls.push({ step: "fence", request });
      const l = request.lineage;
      return mutateResult(options, "fence", {
        ...signedRecord(
          "hacker-bob/provider-worker-vault-worker-fence/v1",
          {
            version: VERSION,
            kind: "worker_fence_receipt",
            execution_lineage_digest: l.execution_lineage_digest,
            worker_launch_digest: l.worker_launch_digest,
            worker_fence_digest: l.worker_fence_digest,
            resource_fence_digest: l.resource_fence_digest,
            lease_id: l.lease_id,
            resource_epoch: l.resource_epoch,
            effect_deadline_monotonic_ns: l.effect_deadline_monotonic_ns,
            transport_binding_digest: l.transport_binding_digest,
          },
          "fence_receipt_digest",
        ),
        worker_fence_handle: fenceHandle,
      }, request);
    },
    execute_transport_into_reserved_vault(request) {
      calls.push({ step: "transport", request });
      const l = request.lineage;
      return mutateResult(options, "transport", signedRecord(
        "hacker-bob/provider-worker-vault-transport-reserved-vault-result/v1",
        {
          version: VERSION,
          kind: "transport_reserved_vault_result",
          execution_lineage_digest: l.execution_lineage_digest,
          transaction_ref: "transaction:test-0001",
          provider_id: l.provider_id,
          operation_id: l.operation_id,
          compiler_id: l.compiler_id,
          compiler_manifest_digest: l.compiler_manifest_digest,
          compiler_registry_digest: l.compiler_registry_digest,
          compiled_operation_digest: l.compiled_operation_digest,
          provider_command_ref: l.provider_command_ref,
          requested_effects_digest: l.requested_effects_digest,
          runtime_availability: l.runtime_availability,
          compiled_command_id: l.compiled_command_id,
          compiled_command_capability_digest: l.compiled_command_capability_digest,
          active_command_input_ref: l.active_command_input_ref,
          active_command_input_digest: l.active_command_input_digest,
          worker_launch_digest: l.worker_launch_digest,
          worker_fence_digest: l.worker_fence_digest,
          resource_fence_digest: l.resource_fence_digest,
          transport_binding_digest: l.transport_binding_digest,
          vault_reservation_handle: l.vault_reservation_handle,
          vault_reservation_digest: l.vault_reservation_digest,
          vault_ingest_capability_digest: l.vault_ingest_capability_digest,
          ...(options.protocol === true ? {
            execution_claim_receipt_digest: request.execution_claim_receipt_digest,
            deadline_fence_receipt_digest: request.deadline_fence_receipt_digest,
          } : {}),
          artifact_handle: "artifact:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          response_digest: digest("raw-response"),
          response_byte_length: 37,
          result_code: "hf14a_probe_ok",
          device_state_digest: digest("post-transaction-device-state"),
          vault_commit_receipt_digest: digest("vault-commit-receipt"),
          raw_response_custody_digest: digest("raw-response-custody"),
        },
        "transaction_receipt_digest",
      ), request);
    },
    cancel_before_effect(request) {
      calls.push({ step: "cancel", request });
      const l = request.lineage;
      return mutateResult(options, "cancel", signedRecord(
        "hacker-bob/provider-worker-vault-before-effect-cancellation/v1",
        {
          version: VERSION,
          kind: "before_effect_cancellation_receipt",
          execution_lineage_digest: l.execution_lineage_digest,
          active_command_input_ref: l.active_command_input_ref,
          active_command_input_digest: l.active_command_input_digest,
          cleanup_command_input_ref: l.cleanup_command_input_ref,
          cleanup_command_input_digest: l.cleanup_command_input_digest,
          effect_state: "no_effect",
          transport_fenced: true,
          capabilities_closed: true,
          worker_terminated: true,
          reservation_state: "released",
        },
        "cancellation_receipt_digest",
      ), request);
    },
    restore_after_effect(request) {
      calls.push({ step: `restore:${request.disposition}`, request });
      const l = request.lineage;
      const completed = request.disposition === "completed";
      return mutateResult(options, "restore", signedRecord(
        "hacker-bob/provider-worker-vault-post-effect-restoration/v1",
        {
          version: VERSION,
          kind: "post_effect_restoration_receipt",
          execution_lineage_digest: l.execution_lineage_digest,
          active_command_input_ref: l.active_command_input_ref,
          active_command_input_digest: l.active_command_input_digest,
          cleanup_command_input_ref: l.cleanup_command_input_ref,
          cleanup_command_input_digest: l.cleanup_command_input_digest,
          transaction_receipt_digest: completed
            ? request.transaction_result.transaction_receipt_digest : null,
          transport_fenced: true,
          capabilities_closed: true,
          restoration_state: completed ? "baseline_unchanged" : "quarantined",
          reservation_state: completed ? "consumed" : "quarantined",
        },
        "restoration_receipt_digest",
      ), request);
    },
    commit_terminal(request) {
      calls.push({ step: `terminal:${request.outcome.terminal_state}`, request });
      const l = request.lineage;
      const result = mutateResult(options, "terminal", signedRecord(
        "hacker-bob/provider-worker-vault-durable-terminal-commit/v1",
        {
          version: VERSION,
          kind: "durable_terminal_commit_receipt",
          execution_lineage_digest: l.execution_lineage_digest,
          outcome_digest: request.outcome.outcome_digest,
          terminal_state: request.outcome.terminal_state,
          durable_exchange_plan_digest: l.durable_exchange_plan_digest,
          terminal_receipt_recipient_digest: l.terminal_receipt_recipient_digest,
          terminal_receipt_ref: "terminal-receipt:test-0001",
          terminal_receipt_digest: digest(`terminal-receipt-${request.outcome.terminal_state}`),
          terminal_journal_entry_digest: digest("terminal-journal-entry"),
          outbox_entry_ref: "outbox-entry:test-0001",
          outbox_entry_digest: digest("outbox-entry"),
          outbox_acknowledgement_digest: digest("outbox-acknowledgement"),
          journal_head_digest: digest("journal-head"),
          outbox_head_digest: digest("outbox-head"),
          durability_head_digest: digest("durability-head"),
        },
        "commit_receipt_digest",
      ), request);
      if (options.protocol === true) {
        durableState.terminals.set(l.execution_lineage_digest, Object.freeze({
          outcome: request.outcome,
          commit: result,
        }));
      }
      return result;
    },
  };

  let components;
  if (options.protocol === true) {
    components = createProviderWorkerVaultProductionProtocolFixtureComponents({
      ...callbacks,
      claim_execution(request) {
        calls.push({ step: "durable-claim", request });
        const l = request.lineage;
        const prior = durableState.claims.get(l.execution_lineage_digest);
        const result = mutateResult(options, "durableClaim", signedRecord(
          "hacker-bob/provider-worker-vault-durable-execution-claim/v1",
          {
            version: VERSION,
            kind: "durable_execution_claim_receipt",
            execution_lineage_digest: l.execution_lineage_digest,
            attempt_id: l.attempt_id,
            execution_claim_ref: prior
              ? prior.execution_claim_ref : `execution-claim:${l.attempt_id}`,
            claim_generation: prior ? prior.claim_generation : "1",
            claim_disposition: prior ? "existing" : "new",
            claimed_at_monotonic_ns: prior ? prior.claimed_at_monotonic_ns : "70000000000",
          },
          "claim_receipt_digest",
        ), request);
        durableState.claims.set(l.execution_lineage_digest, result);
        return result;
      },
      readback_execution_claim(request) {
        calls.push({ step: "claim-readback", request });
        return mutateResult(
          options,
          "claimReadback",
          durableState.claims.get(request.lineage.execution_lineage_digest) || null,
          request,
        );
      },
      assert_effect_deadline_fence(request) {
        calls.push({ step: "deadline-fence", request });
        const l = request.lineage;
        return mutateResult(options, "deadline", signedRecord(
          "hacker-bob/provider-worker-vault-trusted-effect-deadline-fence/v1",
          {
            version: VERSION,
            kind: "trusted_effect_deadline_fence_receipt",
            execution_lineage_digest: l.execution_lineage_digest,
            effect_deadline_monotonic_ns: l.effect_deadline_monotonic_ns,
            resource_fence_digest: l.resource_fence_digest,
            worker_fence_digest: l.worker_fence_digest,
            transport_binding_digest: l.transport_binding_digest,
            live_observation_digest: digest("trusted-live-deadline-observation"),
          },
          "deadline_fence_receipt_digest",
        ), request);
      },
      assert_vault_ingest_receipt(request) {
        calls.push({ step: "vault-ingest", request });
        const l = request.lineage;
        const transaction = request.transaction_result;
        return mutateResult(options, "vaultIngest", signedRecord(
          "hacker-bob/provider-worker-vault-reserved-vault-ingest/v1",
          {
            version: VERSION,
            kind: "reserved_vault_ingest_receipt",
            execution_lineage_digest: l.execution_lineage_digest,
            vault_reservation_handle: l.vault_reservation_handle,
            vault_reservation_digest: l.vault_reservation_digest,
            vault_ingest_capability_digest: l.vault_ingest_capability_digest,
            execution_claim_receipt_digest: request.execution_claim_receipt_digest,
            deadline_fence_receipt_digest: request.deadline_fence_receipt_digest,
            artifact_handle: transaction.artifact_handle,
            response_digest: transaction.response_digest,
            response_byte_length: transaction.response_byte_length,
            transaction_receipt_digest: transaction.transaction_receipt_digest,
            vault_commit_receipt_digest: transaction.vault_commit_receipt_digest,
            raw_response_custody_digest: transaction.raw_response_custody_digest,
          },
          "ingest_receipt_digest",
        ), request);
      },
      readback_terminal_commit(request) {
        calls.push({ step: "terminal-readback", request });
        const stored = durableState.terminals.get(request.lineage.execution_lineage_digest);
        if (!stored) {
          return mutateResult(options, "terminalReadback", null, request);
        }
        const completed = stored.outcome.terminal_state === "completed";
        return mutateResult(options, "terminalReadback", signedRecord(
          "hacker-bob/provider-worker-vault-durable-terminal-readback/v1",
          {
            version: VERSION,
            kind: "durable_terminal_commit_readback",
            execution_lineage_digest: request.lineage.execution_lineage_digest,
            execution_claim_ref: stored.outcome.execution_claim_ref,
            execution_claim_generation: stored.outcome.execution_claim_generation,
            execution_claim_receipt_digest: stored.outcome.execution_claim_receipt_digest,
            outcome_digest: stored.outcome.outcome_digest,
            terminal_state: stored.outcome.terminal_state,
            terminal_commit_receipt_digest: stored.commit.commit_receipt_digest,
            artifact_handle: completed ? stored.outcome.artifact_handle : null,
            result_code: completed ? stored.outcome.transaction_result_code : null,
            response_byte_length: completed ? stored.outcome.response_byte_length : 0,
          },
          "readback_receipt_digest",
        ), request);
      },
    });
  } else {
    components = createProviderWorkerVaultConformanceComponents(callbacks);
  }
  return { calls, components, durableState };
}

function createRoot(options = {}, lineageOverrides = {}) {
  const harness = createHarness(options);
  const boundLineage = lineage(lineageOverrides);
  const compiledCommandDelegate = compiledDelegate(boundLineage);
  const transactionCapability = createProviderWorkerVaultConformanceTransactionCapability({
    version: VERSION,
    lineage: boundLineage,
    compiled_command_capability: compiledCommandDelegate,
  });
  const root = createProviderWorkerVaultCompositionRoot({
    version: VERSION,
    lineage: boundLineage,
    components: harness.components,
  });
  ROOT_CAPABILITIES.set(root, transactionCapability);
  return {
    ...harness,
    boundLineage,
    compiledCommandDelegate,
    root,
    transactionCapability,
  };
}

function executionInput(root) {
  return {
    version: VERSION,
    transaction_capability: ROOT_CAPABILITIES.get(root),
  };
}

function containsBytes(value, seen = new WeakSet()) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return true;
  if (value == null || (typeof value !== "object" && typeof value !== "function")) return false;
  if (seen.has(value)) return false;
  seen.add(value);
  return Reflect.ownKeys(value).some((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && "value" in descriptor && containsBytes(descriptor.value, seen);
  });
}

test("lineage is closed, self-digested, and keeps signed active input distinct from cleanup", () => {
  const normalized = normalizeProviderWorkerVaultExecutionLineage(lineage());
  assert.equal(Object.isFrozen(normalized), true);
  assert.notEqual(normalized.active_command_input_ref, normalized.cleanup_command_input_ref);
  assert.notEqual(normalized.active_command_input_digest, normalized.cleanup_command_input_digest);

  assert.throws(
    () => normalizeProviderWorkerVaultExecutionLineage(lineage({
      cleanup_command_input_digest: digest("active-command-input"),
    })),
    /active_and_cleanup_command_inputs_must_be_distinct/,
  );
  const drifted = lineage();
  drifted.worker_fence_digest = digest("redirected-fence");
  assert.throws(
    () => normalizeProviderWorkerVaultExecutionLineage(drifted),
    /execution_lineage_digest_mismatch/,
  );
  assert.throws(
    () => normalizeProviderWorkerVaultExecutionLineage({ ...lineage(), production_ready: true }),
    /field_set_invalid/,
  );
});

test("production execution fails before every callback and readiness names concrete custody gates", () => {
  const { calls, components, root } = createRoot();
  assertProviderWorkerVaultCompositionRoot(root);
  assert.equal(root.assurance, PROVIDER_WORKER_VAULT_CONFORMANCE_ASSURANCE);
  assert.throws(
    () => root.execute({ production_ready: true, hardware_access_authorized: true }),
    /provider_worker_vault_production_components_unavailable/,
  );
  assert.deepEqual(calls, []);
  assert.equal(root.snapshot().one_use_consumed, false);

  const readiness = root.readiness();
  assert.equal(readiness.production_ready, false);
  assert.equal(readiness.hardware_access_authorized, false);
  assert.equal(readiness.production_component_enrollment, "unavailable");
  assert.deepEqual(
    readiness.requirements.map((entry) => entry.blocker_code),
    [
      "native_grant_redemption_not_enrolled",
      "durable_cross_process_execution_claim_missing",
      "provider_neutral_worker_transaction_not_enrolled",
      "native_worker_launch_fence_not_enrolled",
      "native_deadline_preemption_not_enrolled",
      "reservation_scoped_vault_ingest_capability_missing",
      "durable_vault_ingest_receipt_missing",
      "external_vault_key_custodian_not_enrolled",
      "native_terminal_outbox_writer_not_enrolled",
      "independent_restoration_custodian_not_enrolled",
      "production_hil_evidence_missing",
    ],
  );

  assert.throws(
    () => createProviderWorkerVaultCompositionRoot({
      version: VERSION,
      lineage: lineage(),
      components: Object.freeze({ ...components, production_ready: true }),
    }),
    /components_untrusted/,
  );
});

test("one immutable lineage reaches grant, claim, launch, fence, direct vault result, restore, and terminal", async () => {
  const { calls, boundLineage, compiledCommandDelegate, root } = createRoot();
  const result = await root.exerciseConformance(executionInput(root));

  assert.deepEqual(calls.map((entry) => entry.step), [
    "redeem",
    "claim",
    "launch",
    "fence",
    "transport",
    "restore:completed",
    "terminal:completed",
  ]);
  for (const call of calls) {
    assert.equal(call.request.lineage.execution_lineage_digest, boundLineage.execution_lineage_digest);
    assert.equal(Object.isFrozen(call.request), true);
  }
  assert.equal(calls[1].request.lineage.cleanup_command_input_ref, undefined);
  assert.equal(calls[1].request.compiled_command_capability, compiledCommandDelegate);
  assert.equal(calls[4].request.lineage.cleanup_command_input_ref, undefined);
  assert.equal(calls[5].request.command_handle, undefined);
  assert.equal(calls[4].request.vault_sink.reservation_handle, boundLineage.vault_reservation_handle);
  assert.equal(calls[4].request.vault_sink.byte_ceiling, boundLineage.vault_byte_ceiling);
  assert.equal(calls[5].request.transaction_result.response_bytes, undefined);

  assert.deepEqual(Reflect.ownKeys(result), ["version", "kind", "artifact_handle", "summary"]);
  assert.equal(result.artifact_handle, "artifact:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  assert.deepEqual(result.summary, {
    terminal_state: "fixture_complete_non_authorizing",
    result_code: "hf14a_probe_ok",
    response_byte_length: 37,
  });
  assert.equal(containsBytes(result), false);
  assert.equal(JSON.stringify(result).includes("response_digest"), false);
  const terminalOutcome = calls[6].request.outcome;
  assert.equal(terminalOutcome.transaction_receipt_digest, calls[5].request.transaction_result.transaction_receipt_digest);
  assert.equal(terminalOutcome.vault_commit_receipt_digest, digest("vault-commit-receipt"));
  assert.equal(terminalOutcome.raw_response_custody_digest, digest("raw-response-custody"));
  assert.equal(terminalOutcome.vault_reservation_handle, boundLineage.vault_reservation_handle);
  assert.equal(root.snapshot().terminal_state, "completed");
  await assert.rejects(
    root.exerciseConformance(executionInput(root)),
    /provider_worker_vault_execution_replay_forbidden/,
  );
});

test("pre-effect callback failure is sanitized, cancelled, durably terminal, and never retried", async () => {
  const { calls, boundLineage, root } = createRoot({ claim: "throw" });
  await assert.rejects(
    root.exerciseConformance(executionInput(root)),
    (error) => {
      assert.equal(error.code, "provider_worker_vault_rejected_no_effect");
      assert.equal(error.message.includes("secret"), false);
      assert.equal(Object.hasOwn(error, "cause"), false);
      return true;
    },
  );
  assert.deepEqual(calls.map((entry) => entry.step), [
    "redeem", "claim", "cancel", "terminal:rejected_no_effect",
  ]);
  const cancel = calls[2].request;
  assert.equal(cancel.lineage.active_command_input_ref, boundLineage.active_command_input_ref);
  assert.equal(cancel.lineage.cleanup_command_input_ref, boundLineage.cleanup_command_input_ref);
  assert.notEqual(cancel.lineage.active_command_input_digest, cancel.lineage.cleanup_command_input_digest);
  assert.equal(calls.filter((entry) => entry.step === "claim").length, 1);
  assert.equal(root.snapshot().terminal_state, "rejected_no_effect");
});

test("hostile raw-byte and oversize transport results are quarantined after the effect boundary", async (t) => {
  await t.test("hidden raw bytes", async () => {
    let forbiddenResponseBytes;
    const { calls, root } = createRoot({
      transport(result) {
        forbiddenResponseBytes = Buffer.from("facility-credential-secret");
        Object.defineProperty(result, "response_bytes", {
          value: forbiddenResponseBytes,
          enumerable: false,
        });
        return result;
      },
    });
    await assert.rejects(
      root.exerciseConformance(executionInput(root)),
      /provider_worker_vault_ambiguous_quarantined/,
    );
    assert.deepEqual(calls.map((entry) => entry.step), [
      "redeem", "claim", "launch", "fence", "transport",
      "restore:ambiguous", "terminal:ambiguous_quarantined",
    ]);
    assert.deepEqual(
      forbiddenResponseBytes,
      Buffer.alloc(Buffer.byteLength("facility-credential-secret")),
    );
  });

  await t.test("response larger than command and sink ceilings", async () => {
    const { calls, root } = createRoot({
      transport(result) {
        const projection = { ...result, response_byte_length: 4096 };
        delete projection.transaction_receipt_digest;
        return signedRecord(
          "hacker-bob/provider-worker-vault-transport-reserved-vault-result/v1",
          projection,
          "transaction_receipt_digest",
        );
      },
    });
    await assert.rejects(
      root.exerciseConformance(executionInput(root)),
      /provider_worker_vault_ambiguous_quarantined/,
    );
    assert.equal(calls.some((entry) => entry.step === "restore:ambiguous"), true);
    assert.equal(root.snapshot().terminal_state, "ambiguous_quarantined");
  });

  await t.test("result summary cannot become a response-data side channel", async () => {
    const { calls, root } = createRoot({
      transport(result) {
        const projection = { ...result, result_code: "credential_bytes_encoded_here" };
        delete projection.transaction_receipt_digest;
        return signedRecord(
          "hacker-bob/provider-worker-vault-transport-reserved-vault-result/v1",
          projection,
          "transaction_receipt_digest",
        );
      },
    });
    await assert.rejects(
      root.exerciseConformance(executionInput(root)),
      /provider_worker_vault_ambiguous_quarantined/,
    );
    assert.equal(calls.at(-1).request.outcome.transaction_result_code, null);
    assert.equal(calls.at(-1).request.outcome.artifact_handle, null);
  });
});

test("worker fence drift never reaches the transport and uses before-effect cancellation", async () => {
  const { calls, root } = createRoot({
    fence(result) {
      return { ...result, resource_epoch: "18" };
    },
  });
  await assert.rejects(
    root.exerciseConformance(executionInput(root)),
    /provider_worker_vault_rejected_no_effect/,
  );
  assert.deepEqual(calls.map((entry) => entry.step), [
    "redeem", "claim", "launch", "fence", "cancel", "terminal:rejected_no_effect",
  ]);
  assert.equal(calls.some((entry) => entry.step === "transport"), false);
});

test("cleanup cannot substitute the signed active input and terminal uncertainty is one-shot", async () => {
  const { calls, root } = createRoot({
    restore(result, request) {
      if (request.disposition === "completed") {
        return {
          ...result,
          cleanup_command_input_ref: request.lineage.active_command_input_ref,
          cleanup_command_input_digest: request.lineage.active_command_input_digest,
        };
      }
      return result;
    },
    terminal: "throw",
  });
  await assert.rejects(
    root.exerciseConformance(executionInput(root)),
    /provider_worker_vault_terminal_commit_ambiguous/,
  );
  assert.equal(calls.filter((entry) => entry.step.startsWith("terminal:")).length, 1);
  assert.equal(calls.filter((entry) => entry.step.startsWith("restore:")).length, 1);
  assert.equal(root.snapshot().phase, "terminal_commit_uncertain");
  assert.equal(root.snapshot().reconciliation_required, true);
  await assert.rejects(
    root.exerciseConformance(executionInput(root)),
    /provider_worker_vault_execution_replay_forbidden/,
  );
});

test("component and execution surfaces reject callbacks, proxies, accessors, and byte-bearing capabilities", async () => {
  assert.throws(
    () => createProviderWorkerVaultConformanceComponents({
      version: VERSION,
      redeem_grant() {},
      claim_compiled_command() {},
      launch_worker() {},
      assert_worker_fence() {},
      execute_transport_into_reserved_vault() {},
      cancel_before_effect() {},
      restore_after_effect() {},
      commit_terminal: new Proxy(() => {}, {}),
    }),
    /callback_invalid/,
  );

  const { calls, root, boundLineage } = createRoot();
  assert.throws(
    () => createProviderWorkerVaultConformanceTransactionCapability({
      version: VERSION,
      lineage: boundLineage,
      compiled_command_capability: Object.freeze({
        capability_id: "byte-bearing",
        request_bytes: Buffer.from([1, 2, 3]),
      }),
    }),
    /byte_surface_forbidden/,
  );
  const dataView = new DataView(new ArrayBuffer(8));
  Object.freeze(dataView);
  assert.throws(
    () => createProviderWorkerVaultConformanceTransactionCapability({
      version: VERSION,
      lineage: boundLineage,
      compiled_command_capability: Object.freeze({ capability_id: "view-bearing", dataView }),
    }),
    /byte_surface_forbidden/,
  );
  await assert.rejects(
    root.exerciseConformance({
      version: VERSION,
      transaction_capability: Object.freeze({ production_ready: true }),
    }),
    /transaction_capability_untrusted/,
  );
  assert.deepEqual(calls, []);

  const accessorInput = { version: VERSION };
  Object.defineProperty(accessorInput, "transaction_capability", {
    enumerable: true,
    get() {
      throw new Error("getter must not execute");
    },
  });
  await assert.rejects(
    root.exerciseConformance(accessorInput),
    /must_be_data/,
  );
  assert.deepEqual(calls, []);
});

test("the lineage reservation is synchronous and rejects callback reentrancy", async () => {
  let root;
  let reentrantAttempt = null;
  const harness = createHarness({
    redeem(result) {
      reentrantAttempt = root.exerciseConformance(executionInput(root));
      return result;
    },
  });
  const boundLineage = lineage();
  root = createProviderWorkerVaultCompositionRoot({
    version: VERSION,
    lineage: boundLineage,
    components: harness.components,
  });
  ROOT_CAPABILITIES.set(root, createProviderWorkerVaultConformanceTransactionCapability({
    version: VERSION,
    lineage: boundLineage,
    compiled_command_capability: compiledDelegate(boundLineage),
  }));
  await root.exerciseConformance(executionInput(root));
  await assert.rejects(
    reentrantAttempt,
    /provider_worker_vault_execution_replay_forbidden/,
  );
  assert.equal(harness.calls.filter((entry) => entry.step === "redeem").length, 1);
});

test("two roots sharing one component custodian cannot redeem the same lineage twice", async () => {
  const harness = createHarness();
  const boundLineage = lineage();
  const roots = [0, 1].map(() => {
    const root = createProviderWorkerVaultCompositionRoot({
      version: VERSION,
      lineage: boundLineage,
      components: harness.components,
    });
    ROOT_CAPABILITIES.set(root, createProviderWorkerVaultConformanceTransactionCapability({
      version: VERSION,
      lineage: boundLineage,
      compiled_command_capability: compiledDelegate(boundLineage),
    }));
    return root;
  });
  await roots[0].exerciseConformance(executionInput(roots[0]));
  await assert.rejects(
    roots[1].exerciseConformance(executionInput(roots[1])),
    /provider_worker_vault_execution_replay_forbidden/,
  );
  assert.equal(harness.calls.filter((entry) => entry.step === "redeem").length, 1);
  assert.equal(roots[1].snapshot().one_use_consumed, false);
});

test("a lineage-bound transaction capability cannot be transplanted to another root", async () => {
  const { calls, root } = createRoot();
  const otherLineage = lineage({
    execution_ref: "execution:crosswire-0002",
    attempt_id: "attempt:crosswire-0002",
  });
  const crosswired = createProviderWorkerVaultConformanceTransactionCapability({
    version: VERSION,
    lineage: otherLineage,
    compiled_command_capability: compiledDelegate(otherLineage),
  });
  await assert.rejects(
    root.exerciseConformance({ version: VERSION, transaction_capability: crosswired }),
    /transaction_capability_untrusted/,
  );
  assert.deepEqual(calls, []);
  assert.equal(root.snapshot().one_use_consumed, false);
});

test("a hung transport is bounded, quarantined, restored once, and durably terminal", async () => {
  const { calls, root } = createRoot({
    transport() {
      return new Promise(() => {});
    },
  });
  const startedAt = Date.now();
  await assert.rejects(
    root.exerciseConformance(executionInput(root)),
    /provider_worker_vault_ambiguous_quarantined/,
  );
  assert.ok(Date.now() - startedAt < 1500);
  assert.deepEqual(calls.map((entry) => entry.step), [
    "redeem", "claim", "launch", "fence", "transport",
    "restore:ambiguous", "terminal:ambiguous_quarantined",
  ]);
  assert.equal(root.snapshot().reconciliation_required, false);
});

test("known transaction custody remains effect-completed when restoration becomes uncertain", async () => {
  const { calls, root } = createRoot({ restore: "throw" });
  await assert.rejects(
    root.exerciseConformance(executionInput(root)),
    /provider_worker_vault_ambiguous_quarantined/,
  );
  assert.deepEqual(calls.map((entry) => entry.step), [
    "redeem", "claim", "launch", "fence", "transport",
    "restore:completed", "terminal:ambiguous_quarantined",
  ]);
  const outcome = calls[6].request.outcome;
  assert.equal(outcome.effect_state, "effect_completed");
  assert.equal(outcome.transaction_result_code, "hf14a_probe_ok");
  assert.equal(outcome.cleanup_state, "failed_ambiguous");
  assert.equal(outcome.transaction_receipt_digest, calls[5].request.transaction_result.transaction_receipt_digest);
  assert.equal(outcome.vault_commit_receipt_digest, digest("vault-commit-receipt"));
});

test("the production protocol fixture stays non-authorizing and execute refuses before input", async () => {
  const { calls, root } = createRoot({ protocol: true });
  assert.equal(root.assurance, PROVIDER_WORKER_VAULT_PROTOCOL_FIXTURE_ASSURANCE);
  assert.equal(root.production_ready, false);
  assert.equal(root.hardware_access_authorized, false);
  assert.throws(
    () => root.execute(new Proxy({}, { ownKeys() { throw new Error("must not inspect"); } })),
    /provider_worker_vault_production_components_unavailable/,
  );
  assert.deepEqual(calls, []);
  assert.equal(root.snapshot().one_use_consumed, false);
  assert.equal(
    root.readiness().topology_status,
    "production_protocol_fixture_complete_non_authorizing",
  );

  const result = await root.exerciseConformance(executionInput(root));
  assert.equal(result.summary.terminal_state, "fixture_complete_non_authorizing");
});

test("the production protocol fixture binds claim, deadline, vault ingest, and terminal readback", async () => {
  const { calls, root } = createRoot({ protocol: true });
  const result = await root.exerciseConformance(executionInput(root));
  assert.deepEqual(calls.map((entry) => entry.step), [
    "durable-claim", "claim-readback", "redeem", "claim", "launch", "fence",
    "deadline-fence", "transport", "vault-ingest", "restore:completed",
    "terminal:completed", "terminal-readback",
  ]);
  const deadline = calls.find((entry) => entry.step === "deadline-fence");
  const transport = calls.find((entry) => entry.step === "transport");
  const vaultIngest = calls.find((entry) => entry.step === "vault-ingest");
  const terminal = calls.find((entry) => entry.step === "terminal:completed");
  const deadlineLineage = deadline.request.lineage;
  const expectedDeadlineReceipt = signedRecord(
    "hacker-bob/provider-worker-vault-trusted-effect-deadline-fence/v1",
    {
      version: VERSION,
      kind: "trusted_effect_deadline_fence_receipt",
      execution_lineage_digest: deadlineLineage.execution_lineage_digest,
      effect_deadline_monotonic_ns: deadlineLineage.effect_deadline_monotonic_ns,
      resource_fence_digest: deadlineLineage.resource_fence_digest,
      worker_fence_digest: deadlineLineage.worker_fence_digest,
      transport_binding_digest: deadlineLineage.transport_binding_digest,
      live_observation_digest: digest("trusted-live-deadline-observation"),
    },
    "deadline_fence_receipt_digest",
  );
  assert.equal(
    transport.request.deadline_fence_receipt_digest,
    expectedDeadlineReceipt.deadline_fence_receipt_digest,
  );
  assert.equal(
    vaultIngest.request.deadline_fence_receipt_digest,
    transport.request.deadline_fence_receipt_digest,
  );
  assert.equal(
    terminal.request.outcome.vault_ingest_receipt_digest,
    signedRecord(
      "hacker-bob/provider-worker-vault-reserved-vault-ingest/v1",
      {
        version: VERSION,
        kind: "reserved_vault_ingest_receipt",
        execution_lineage_digest: vaultIngest.request.lineage.execution_lineage_digest,
        vault_reservation_handle: vaultIngest.request.lineage.vault_reservation_handle,
        vault_reservation_digest: vaultIngest.request.lineage.vault_reservation_digest,
        vault_ingest_capability_digest: vaultIngest.request.lineage.vault_ingest_capability_digest,
        execution_claim_receipt_digest: vaultIngest.request.execution_claim_receipt_digest,
        deadline_fence_receipt_digest: vaultIngest.request.deadline_fence_receipt_digest,
        artifact_handle: vaultIngest.request.transaction_result.artifact_handle,
        response_digest: vaultIngest.request.transaction_result.response_digest,
        response_byte_length: vaultIngest.request.transaction_result.response_byte_length,
        transaction_receipt_digest:
          vaultIngest.request.transaction_result.transaction_receipt_digest,
        vault_commit_receipt_digest:
          vaultIngest.request.transaction_result.vault_commit_receipt_digest,
        raw_response_custody_digest:
          vaultIngest.request.transaction_result.raw_response_custody_digest,
      },
      "ingest_receipt_digest",
    ).ingest_receipt_digest,
  );
  assert.equal(result.artifact_handle, terminal.request.outcome.artifact_handle);
  assert.equal(containsBytes(result), false);
});

test("a restart reads the durable terminal and never repeats the physical effect", async () => {
  const harness = createHarness({ protocol: true });
  const boundLineage = lineage();
  function buildRoot() {
    const root = createProviderWorkerVaultCompositionRoot({
      version: VERSION,
      lineage: boundLineage,
      components: harness.components,
    });
    ROOT_CAPABILITIES.set(root, createProviderWorkerVaultConformanceTransactionCapability({
      version: VERSION,
      lineage: boundLineage,
      compiled_command_capability: compiledDelegate(boundLineage),
    }));
    return root;
  }
  const firstRoot = buildRoot();
  const firstResult = await firstRoot.exerciseConformance(executionInput(firstRoot));
  const firstCallCount = harness.calls.length;
  const secondRoot = buildRoot();
  const secondResult = await secondRoot.exerciseConformance(executionInput(secondRoot));

  assert.deepEqual(secondResult, firstResult);
  assert.deepEqual(harness.calls.slice(firstCallCount).map((entry) => entry.step), [
    "durable-claim", "claim-readback", "terminal-readback",
  ]);
  assert.equal(harness.calls.filter((entry) => entry.step === "transport").length, 1);
  assert.equal(harness.calls.filter((entry) => entry.step === "redeem").length, 1);
});

test("an existing claim without a durable terminal requires reconciliation without re-effect", async () => {
  const harness = createHarness({ protocol: true, terminal: "throw" });
  const boundLineage = lineage();
  function buildRoot() {
    const root = createProviderWorkerVaultCompositionRoot({
      version: VERSION,
      lineage: boundLineage,
      components: harness.components,
    });
    ROOT_CAPABILITIES.set(root, createProviderWorkerVaultConformanceTransactionCapability({
      version: VERSION,
      lineage: boundLineage,
      compiled_command_capability: compiledDelegate(boundLineage),
    }));
    return root;
  }
  const firstRoot = buildRoot();
  await assert.rejects(
    firstRoot.exerciseConformance(executionInput(firstRoot)),
    /provider_worker_vault_terminal_commit_ambiguous/,
  );
  const firstCallCount = harness.calls.length;
  const secondRoot = buildRoot();
  await assert.rejects(
    secondRoot.exerciseConformance(executionInput(secondRoot)),
    /provider_worker_vault_existing_execution_reconciliation_required/,
  );
  assert.deepEqual(harness.calls.slice(firstCallCount).map((entry) => entry.step), [
    "durable-claim", "claim-readback", "terminal-readback",
  ]);
  assert.equal(harness.calls.filter((entry) => entry.step === "transport").length, 1);
  assert.equal(secondRoot.snapshot().reconciliation_required, true);
});

test("booleans, callbacks, and protocol fixtures cannot forge the private production brand", () => {
  const { components } = createHarness({ protocol: true });
  assert.throws(
    () => assertProviderWorkerVaultProductionPortSet(components),
    /provider_worker_vault_production_port_set_untrusted/,
  );
  const forged = Object.freeze({
    version: VERSION,
    kind: "provider_worker_vault_production_port_set",
    assurance: "native_privately_branded_provider_worker_vault_composition_v1",
    production_ready: true,
    hardware_access_authorized: true,
    execution_authority: true,
    toJSON() { throw new Error("opaque"); },
  });
  assert.throws(
    () => assertProviderWorkerVaultProductionPortSet(forged),
    /provider_worker_vault_production_port_set_untrusted/,
  );
  assert.throws(
    () => createProviderWorkerVaultCompositionRoot({
      version: VERSION,
      lineage: lineage(),
      components: forged,
    }),
    /provider_worker_vault_components_untrusted/,
  );
});

test("trusted deadline drift cancels before transport and commits a durable rejection", async () => {
  const { calls, root } = createRoot({
    protocol: true,
    deadline(result) {
      const projection = { ...result, effect_deadline_monotonic_ns: "98000000000" };
      delete projection.deadline_fence_receipt_digest;
      return signedRecord(
        "hacker-bob/provider-worker-vault-trusted-effect-deadline-fence/v1",
        projection,
        "deadline_fence_receipt_digest",
      );
    },
  });
  await assert.rejects(
    root.exerciseConformance(executionInput(root)),
    /provider_worker_vault_rejected_no_effect/,
  );
  assert.equal(calls.some((entry) => entry.step === "transport"), false);
  assert.deepEqual(calls.map((entry) => entry.step), [
    "durable-claim", "claim-readback", "redeem", "claim", "launch", "fence",
    "deadline-fence", "cancel", "terminal:rejected_no_effect", "terminal-readback",
  ]);
});

test("vault ingest receipt drift quarantines a known effect and never returns an artifact", async () => {
  const { calls, root } = createRoot({
    protocol: true,
    vaultIngest(result) {
      const projection = { ...result, response_digest: digest("crosswired-vault-response") };
      delete projection.ingest_receipt_digest;
      return signedRecord(
        "hacker-bob/provider-worker-vault-reserved-vault-ingest/v1",
        projection,
        "ingest_receipt_digest",
      );
    },
  });
  await assert.rejects(
    root.exerciseConformance(executionInput(root)),
    /provider_worker_vault_ambiguous_quarantined/,
  );
  assert.deepEqual(calls.map((entry) => entry.step), [
    "durable-claim", "claim-readback", "redeem", "claim", "launch", "fence",
    "deadline-fence", "transport", "vault-ingest", "restore:ambiguous",
    "terminal:ambiguous_quarantined", "terminal-readback",
  ]);
  const terminal = calls.find((entry) => entry.step === "terminal:ambiguous_quarantined");
  assert.equal(terminal.request.outcome.effect_state, "effect_completed");
  assert.equal(terminal.request.outcome.vault_ingest_receipt_digest, null);
  assert.equal(root.snapshot().terminal_state, "ambiguous_quarantined");
});

test("terminal readback drift leaves a committed execution reconciliation-required", async () => {
  const { calls, root } = createRoot({
    protocol: true,
    terminalReadback(result) {
      const projection = {
        ...result,
        terminal_commit_receipt_digest: digest("crosswired-terminal-commit"),
      };
      delete projection.readback_receipt_digest;
      return signedRecord(
        "hacker-bob/provider-worker-vault-durable-terminal-readback/v1",
        projection,
        "readback_receipt_digest",
      );
    },
  });
  await assert.rejects(
    root.exerciseConformance(executionInput(root)),
    /provider_worker_vault_terminal_readback_ambiguous/,
  );
  assert.equal(calls.filter((entry) => entry.step === "transport").length, 1);
  assert.equal(calls.filter((entry) => entry.step === "terminal:completed").length, 1);
  assert.equal(root.snapshot().phase, "terminal_readback_uncertain");
  assert.equal(root.snapshot().terminal_state, "completed");
  assert.equal(root.snapshot().reconciliation_required, true);
});
