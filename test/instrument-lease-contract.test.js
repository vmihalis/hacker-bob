"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  acquireInstrumentLease,
  assertAttemptJournalAppend,
  assertDeadmanHeartbeatTransition,
  assertDurableOutboxAppend,
  assertOutboxJournalBinding,
  assertProviderAlignedJournalState,
  assertVerifiedRecoveryBootstrapProjection,
  beginInstrumentRestoration,
  evaluateSafetySupervisor,
  fenceInstrumentLease,
  isLeaseBlocking,
  MAX_SUPERVISOR_DEADMAN_WINDOW_MS,
  normalizeAttemptJournalEntry,
  normalizeDurableOutboxEntry,
  normalizeEffectDispatchRecord,
  normalizeProviderDispatchCredential,
  normalizeProviderDispatchRedemption,
  normalizeInstrumentLease,
  normalizeOutboxAcknowledgement,
  normalizeRecoveryWorkerBootstrap,
  normalizeSafetySupervisorContract,
  normalizeSignedDeadmanHeartbeat,
  normalizeSignedRestorationReceipt,
  normalizeSignedStopAcknowledgement,
  normalizeSignedStopRequest,
  projectVerifiedRecoveryWorkerBootstrap,
  projectVerifiedRestorationReceipt,
  projectVerifiedStopAcknowledgement,
  projectVerifiedStopRequest,
  providerDispatchFenceBindingDigest,
  reconcileStartupAttempt,
  releaseInstrumentLease,
  requestInstrumentLeaseStop,
  renewInstrumentLease,
} = require("../mcp/domains/physical/instrument-lease-contract.js");
const {
  buildNormalizedOperationRegistry,
} = require("../mcp/domains/physical/instrument-provider-contract.js");
const {
  normalizeCleanupCapability,
} = require("../mcp/domains/physical/physical-authority.js");
const {
  buildEffectTemplateRegistry,
} = require("../mcp/core/requested-effects.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function clone(value) {
  return structuredClone(value);
}

function signatureEnvelope(payload, key = "worker-stop-key-1", proof = "stop-1") {
  return {
    version: 1,
    method: "ed25519",
    signer_key_id: key,
    trust_root_epoch: 3,
    signed_payload_digest: hashCanonicalJson(payload),
    proof_ref: `auth-proof:${proof}`,
    proof_digest: digest(`proof-${proof}`),
  };
}

function trustedVerification(authentication, verifier = "physical-signature-verifier-v1") {
  return {
    version: 1,
    verified: true,
    method: authentication.method,
    signer_key_id: authentication.signer_key_id,
    trust_root_epoch: authentication.trust_root_epoch,
    verified_payload_digest: authentication.signed_payload_digest,
    verified_proof_digest: authentication.proof_digest,
    signature_verifier_id: verifier,
    signature_verdict_digest: digest(`${verifier}-verdict`),
  };
}

function fixture() {
  const effectRegistry = buildEffectTemplateRegistry([{
    version: 1,
    template_id: "instrument.configure.usb.v1",
    subject_kind: "instrument",
    action: "configure",
    channel: "usb",
    persistence: "persistent",
    bounds: {},
  }]);
  const operationRegistry = buildNormalizedOperationRegistry([{
    version: 1,
    operation_id: "representation.write",
    semantic_version: 1,
    parameters: {},
    public_summary_codes: [
      "operation_failed",
      "operation_inconclusive",
      "operation_refused",
      "operation_stopped",
      "operation_succeeded",
    ],
  }]);
  const executionRequestDigest = digest("active-execution-request");
  const lease = {
    version: 1,
    lease_id: "lease-ph-s7-1",
    instrument_ref: "instrument:owned-reader-1",
    owner_principal_id: "principal:broker-1",
    execution_principal_id: "principal:active-worker-1",
    terminal_receipt_recipient_principal_id: "principal:broker-1",
    terminal_receipt_idempotency_domain_digest: digest("terminal-recipient-domain"),
    attempt_ref: "attempt:physical-attempt-1",
    operation_id: "representation.write",
    execution_request_digest: executionRequestDigest,
    resource_bundle_digest: digest("resource-bundle"),
    fencing_token: "fence-token-1",
    fencing_generation: 1,
    state: "held",
    sequence: 0,
    acquired_at: "2026-07-18T00:00:00.000Z",
    updated_at: "2026-07-18T00:00:00.000Z",
    effect_not_before: "2026-07-18T00:00:00.000Z",
    effect_deadline: "2026-07-18T00:01:00.000Z",
    heartbeat_deadline: "2026-07-18T00:00:05.000Z",
    expires_at: "2026-07-18T00:01:00.000Z",
  };
  const effectTemplate = effectRegistry.get("instrument.configure.usb.v1");
  const cleanupCapability = normalizeCleanupCapability({
    version: 1,
    capability_kind: "cleanup",
    root_kind: "cleanup_safety",
    nondelegable: true,
    agent_requestable: false,
    safety_root_ref: "safety-root:physical-1",
    source_execution_request_digest: executionRequestDigest,
    session_id: "session-physical-1",
    instrument_ref: lease.instrument_ref,
    recovery_principal_id: "principal:cleanup-worker-1",
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    workspace_snapshot_ref: "workspace-snapshot:reader-1",
    workspace_snapshot_digest: digest("workspace-snapshot"),
    restore_operation_id: "instrument.restore.v1",
    restore_operation_digest: digest("restore-operation"),
    cleanup_plan_digest: digest("cleanup-plan"),
    terminal_emission_state: "inhibited",
    allowed_terminal_states: ["quarantined", "restored", "unknown_effect"],
    capability_nonce: "cleanup-capability-nonce-1",
    requested_effects: [{
      version: 1,
      template_id: effectTemplate.template_id,
      template_digest: effectTemplate.template_digest,
      subject_ref: lease.instrument_ref,
      subject_kind: effectTemplate.subject_kind,
      action: effectTemplate.action,
      channel: effectTemplate.channel,
      persistence: effectTemplate.persistence,
      bounds: {},
    }],
  }, effectRegistry);
  return {
    cleanupCapability,
    effectRegistry,
    executionRequestDigest,
    lease,
    operationRegistry,
  };
}

function mutationBindings(lease) {
  return {
    version: 1,
    lease_id: lease.lease_id,
    instrument_ref: lease.instrument_ref,
    owner_principal_id: lease.owner_principal_id,
    execution_principal_id: lease.execution_principal_id,
    fencing_token: lease.fencing_token,
    fencing_generation: lease.fencing_generation,
    expected_sequence: lease.sequence,
  };
}

function journal0(f) {
  return normalizeAttemptJournalEntry({
    version: 1,
    journal_entry_ref: "journal-entry:attempt-1-0",
    attempt_ref: f.lease.attempt_ref,
    instrument_ref: f.lease.instrument_ref,
    lease_id: f.lease.lease_id,
    fencing_token: f.lease.fencing_token,
    fencing_generation: f.lease.fencing_generation,
    operation_id: f.lease.operation_id,
    execution_request_digest: f.lease.execution_request_digest,
    experiment_plan_hash: digest("experiment-plan"),
    execution_lineage_digest: digest("execution-lineage"),
    authority_resolution_digest: digest("authority-resolution"),
    signed_grant_digest: digest("signed-grant"),
    replay_claim_digest: digest("grant-replay-claim"),
    replay_reservation_receipt_digest: digest("grant-replay-reservation-receipt"),
    provider_id: "contract_test_provider",
    provider_descriptor_digest: digest("provider-descriptor"),
    provider_request_digest: digest("provider-request"),
    cleanup_capability_digest: f.cleanupCapability.capability_digest,
    cleanup_plan_digest: f.cleanupCapability.cleanup_plan_digest,
    workspace_snapshot_ref: f.cleanupCapability.workspace_snapshot_ref,
    workspace_snapshot_digest: f.cleanupCapability.workspace_snapshot_digest,
    stop_contract_digest: digest("stop-contract"),
    state: "precommitted",
    provider_state: "created",
    provider_sequence: 0,
    effect_disposition: "not_dispatched",
    sequence: 0,
    previous_entry_digest: null,
    recorded_at: "2026-07-18T00:00:00.100Z",
    fsynced_at: "2026-07-18T00:00:00.110Z",
  });
}

function nextJournal(previous, state, providerState, effectDisposition, millis) {
  const providerSequence = providerState === previous.provider_state
    ? previous.provider_sequence
    : previous.provider_sequence + 1;
  const next = {
    ...previous,
    journal_entry_ref: `journal-entry:attempt-1-${previous.sequence + 1}`,
    state,
    provider_state: providerState,
    provider_sequence: providerSequence,
    effect_disposition: effectDisposition,
    sequence: previous.sequence + 1,
    previous_entry_digest: previous.journal_entry_digest,
    recorded_at: `2026-07-18T00:00:00.${String(millis).padStart(3, "0")}Z`,
    fsynced_at: `2026-07-18T00:00:00.${String(millis + 1).padStart(3, "0")}Z`,
  };
  delete next.journal_entry_digest;
  return assertAttemptJournalAppend(previous, next);
}

function report(f, state, sequence, effectDisposition) {
  const requiresReceipt = state !== "created";
  let publicResult = null;
  if (state === "acknowledged" || state === "refused") {
    publicResult = {
      version: 1,
      outcome: state === "acknowledged" ? "succeeded" : "refused",
      summary_code: state === "acknowledged" ? "operation_succeeded" : "operation_refused",
      artifact_refs: [],
      metric_counts: {},
    };
  }
  return {
    version: 1,
    attempt_ref: f.lease.attempt_ref,
    operation_id: f.lease.operation_id,
    request_digest: digest("provider-request"),
    state,
    sequence,
    effect_disposition: effectDisposition,
    receipt_ref: requiresReceipt ? `receipt:provider-${state}-${sequence}` : null,
    public_result: publicResult,
  };
}

function stopRequest(f) {
  const payload = {
    version: 1,
    stop_request_ref: "stop-request:attempt-1-stop-1",
    attempt_ref: f.lease.attempt_ref,
    instrument_ref: f.lease.instrument_ref,
    lease_id: f.lease.lease_id,
    fencing_token: f.lease.fencing_token,
    fencing_generation: f.lease.fencing_generation,
    operation_id: f.lease.operation_id,
    execution_request_digest: f.lease.execution_request_digest,
    authority_epoch: 7,
    revocation_generation: 3,
    issuer_principal_id: "principal:policy-issuer-1",
    reason: "revocation_generation_advanced",
    sequence: 9,
    nonce: "stop-nonce-1",
    requested_at: "2026-07-18T00:00:10.000Z",
    ack_deadline: "2026-07-18T00:00:12.000Z",
  };
  return { ...payload, authentication: signatureEnvelope(payload, "issuer-stop-key-1", "stop-request-1") };
}

function stopAcknowledgement(f, request, outcome = "stopped", acknowledgedAt = "2026-07-18T00:00:11.000Z") {
  const payload = {
    version: 1,
    stop_ack_ref: "stop-ack:attempt-1-stop-1",
    stop_request_digest: request.stop_request_digest,
    attempt_ref: request.attempt_ref,
    instrument_ref: request.instrument_ref,
    lease_id: request.lease_id,
    fencing_token: request.fencing_token,
    fencing_generation: request.fencing_generation,
    operation_id: request.operation_id,
    execution_request_digest: request.execution_request_digest,
    acknowledger_kind: "active_worker",
    acknowledger_principal_id: f.lease.execution_principal_id,
    observed_stop_sequence: request.sequence,
    outcome,
    emission_state: outcome === "cannot_confirm" ? "unknown" : "inhibited",
    provider_receipt_ref: "receipt:provider-stop-1",
    provider_receipt_digest: digest("provider-stop-receipt"),
    acknowledged_at: acknowledgedAt,
  };
  return { ...payload, authentication: signatureEnvelope(payload, "worker-stop-key-1", "stop-ack-1") };
}

function supervisor(f, containmentMode = "electronic") {
  return normalizeSafetySupervisorContract({
    version: 1,
    supervisor_ref: "safety-supervisor:attempt-1",
    supervisor_principal_id: "principal:safety-supervisor-1",
    supervisor_signer_key_id: "supervisor-cleanup-key-1",
    trust_root_epoch: 3,
    safety_root_ref: f.cleanupCapability.safety_root_ref,
    attempt_ref: f.lease.attempt_ref,
    instrument_ref: f.lease.instrument_ref,
    lease_id: f.lease.lease_id,
    fencing_token: f.lease.fencing_token,
    fencing_generation: f.lease.fencing_generation,
    operation_id: f.lease.operation_id,
    execution_request_digest: f.lease.execution_request_digest,
    worker_principal_id: f.lease.execution_principal_id,
    worker_heartbeat_signer_key_id: "worker-heartbeat-key-1",
    cleanup_capability_digest: f.cleanupCapability.capability_digest,
    authority_epoch: 7,
    revocation_generation: 2,
    heartbeat_interval_ms: 1000,
    miss_tolerance: 3,
    stop_ack_deadline_ms: 2000,
    containment_mode: containmentMode,
    containment_actions: containmentMode === "electronic"
      ? ["rf_interlock", "worker_kill"]
      : ["transport_close", "worker_kill"],
    operator_containment_plan_digest: containmentMode === "operator_containment"
      ? digest("operator-containment")
      : null,
  });
}

function heartbeat(f, supervisorContract) {
  const payload = {
    version: 1,
    heartbeat_ref: "heartbeat:attempt-1-1",
    supervisor_contract_digest: supervisorContract.supervisor_contract_digest,
    attempt_ref: f.lease.attempt_ref,
    instrument_ref: f.lease.instrument_ref,
    lease_id: f.lease.lease_id,
    fencing_token: f.lease.fencing_token,
    fencing_generation: f.lease.fencing_generation,
    operation_id: f.lease.operation_id,
    execution_request_digest: f.lease.execution_request_digest,
    worker_principal_id: f.lease.execution_principal_id,
    heartbeat_sequence: 1,
    authority_epoch: 7,
    revocation_generation: 2,
    emitted_at: "2026-07-18T00:00:01.000Z",
    valid_until: "2026-07-18T00:00:04.000Z",
  };
  return { ...payload, authentication: signatureEnvelope(payload, "worker-heartbeat-key-1", "heartbeat-1") };
}

function recoveryBootstrap(f) {
  const payload = {
    version: 1,
    bootstrap_ref: "recovery-bootstrap:attempt-1",
    bootstrap_source: "safety_supervisor",
    supervisor_principal_id: "principal:safety-supervisor-1",
    supervisor_signer_key_id: "supervisor-cleanup-key-1",
    trust_root_epoch: 3,
    recovery_principal_id: f.cleanupCapability.recovery_principal_id,
    recovery_receipt_signer_key_id: "cleanup-worker-key-1",
    safety_root_ref: f.cleanupCapability.safety_root_ref,
    safety_root_status: "trusted",
    cleanup_capability_digest: f.cleanupCapability.capability_digest,
    source_execution_request_digest: f.cleanupCapability.source_execution_request_digest,
    attempt_ref: f.lease.attempt_ref,
    instrument_ref: f.cleanupCapability.instrument_ref,
    enrolled_device_identity_digest: digest("enrolled-device"),
    provider_manifest_digest: digest("provider-manifest"),
    recovery_worker_binary_digest: digest("recovery-worker-binary"),
    lease_id: f.cleanupCapability.lease_id,
    fencing_token: f.cleanupCapability.fencing_token,
    fencing_generation: f.lease.fencing_generation,
    workspace_snapshot_ref: f.cleanupCapability.workspace_snapshot_ref,
    workspace_snapshot_digest: f.cleanupCapability.workspace_snapshot_digest,
    restore_operation_id: f.cleanupCapability.restore_operation_id,
    restore_operation_digest: f.cleanupCapability.restore_operation_digest,
    cleanup_plan_digest: f.cleanupCapability.cleanup_plan_digest,
    expected_terminal_state_digest: digest("expected-restored-state"),
    snapshot_materialization_capability_ref: "vault-capability:snapshot-attempt-1",
    snapshot_materialization_capability_digest: digest("snapshot-materialization-capability"),
    allowed_operation_ids: [f.cleanupCapability.restore_operation_id],
    allowed_materialization_refs: [f.cleanupCapability.workspace_snapshot_ref],
    agent_channel_enabled: false,
    administration_enabled: false,
    destruction_enabled: false,
    one_time: true,
    nonce: "recovery-bootstrap-nonce-1",
    not_before: "2026-07-18T00:00:12.000Z",
    expires_at: "2026-07-18T00:05:12.000Z",
  };
  return {
    ...payload,
    authentication: signatureEnvelope(payload, "supervisor-cleanup-key-1", "recovery-bootstrap-1"),
  };
}

test("instrument leases are exclusive, monotonic-fenced, renewable only by their exact owner, and residue remains blocking", () => {
  const f = fixture();
  const missingTerminalRecipientPolicy = { ...f.lease };
  delete missingTerminalRecipientPolicy.terminal_receipt_idempotency_domain_digest;
  assert.throws(
    () => normalizeInstrumentLease(missingTerminalRecipientPolicy),
    /missing fields: terminal_receipt_idempotency_domain_digest/,
  );
  const acquired = acquireInstrumentLease(f.lease, []);
  assert.equal(acquired.state, "held");
  assert.equal(Object.isFrozen(acquired), true);
  assert.equal(isLeaseBlocking(acquired), true);

  assert.throws(
    () => acquireInstrumentLease({ ...f.lease, lease_id: "lease-ph-s7-2", fencing_generation: 2 }, [acquired]),
    /instrument already bound/,
  );

  const renewed = renewInstrumentLease(acquired, {
    ...mutationBindings(acquired),
    renewed_at: "2026-07-18T00:00:30.000Z",
    heartbeat_deadline: "2026-07-18T00:01:03.000Z",
    expires_at: "2026-07-18T00:02:00.000Z",
  });
  assert.equal(renewed.sequence, 1);
  assert.throws(
    () => renewInstrumentLease(renewed, {
      ...mutationBindings(renewed),
      expected_sequence: 0,
      renewed_at: "2026-07-18T00:01:00.000Z",
      heartbeat_deadline: "2026-07-18T00:02:03.000Z",
      expires_at: "2026-07-18T00:03:00.000Z",
    }),
    /expected_sequence is stale/,
  );

  const fenced = fenceInstrumentLease(renewed, {
    ...mutationBindings(renewed),
    fenced_at: "2026-07-18T00:01:10.000Z",
    reason: "deadman_missed",
  });
  assert.equal(fenced.state, "fenced");
  const restoring = beginInstrumentRestoration(fenced, {
    ...mutationBindings(fenced),
    started_at: "2026-07-18T00:01:11.000Z",
    cleanup_capability_digest: f.cleanupCapability.capability_digest,
  });
  const quarantined = releaseInstrumentLease(restoring, {
    ...mutationBindings(restoring),
    closed_at: "2026-07-18T00:01:20.000Z",
    terminal_disposition: "unknown_effect",
    terminal_receipt_ref: "receipt:cleanup-unknown-1",
    terminal_receipt_digest: digest("cleanup-unknown"),
  });
  assert.equal(quarantined.state, "quarantined");
  assert.equal(isLeaseBlocking(quarantined), true);
  assert.throws(
    () => acquireInstrumentLease({ ...f.lease, lease_id: "lease-ph-s7-2", fencing_generation: 2 }, [quarantined]),
    /instrument already bound/,
  );

  const released = releaseInstrumentLease(acquired, {
    ...mutationBindings(acquired),
    closed_at: "2026-07-18T00:00:20.000Z",
    terminal_disposition: "confirmed_no_effect",
    terminal_receipt_ref: "receipt:no-effect-1",
    terminal_receipt_digest: digest("no-effect"),
  });
  const next = acquireInstrumentLease({
    ...f.lease,
    lease_id: "lease-ph-s7-2",
    fencing_token: "fence-token-2",
    fencing_generation: 2,
    acquired_at: "2026-07-18T00:00:21.000Z",
    updated_at: "2026-07-18T00:00:21.000Z",
    effect_not_before: "2026-07-18T00:00:21.000Z",
    effect_deadline: "2026-07-18T00:01:20.000Z",
    heartbeat_deadline: "2026-07-18T00:00:26.000Z",
    expires_at: "2026-07-18T00:01:20.000Z",
  }, [released]);
  assert.equal(next.fencing_generation, 2);
  const staleFenceCandidate = { ...next, fencing_generation: 1 };
  delete staleFenceCandidate.lease_digest;
  assert.throws(
    () => acquireInstrumentLease(staleFenceCandidate, [released]),
    /advance exactly once/,
  );
});

test("journal and outbox chains enforce fsync-before-effect and fsync-before-ack ordering", () => {
  const f = fixture();
  const precommitted = journal0(f);
  const admitted = nextJournal(precommitted, "admitted", "prepared", "not_dispatched", 120);
  const starting = nextJournal(admitted, "effect_starting", "prepared", "not_dispatched", 130);
  const providerSwap = {
    ...admitted,
    provider_id: "alternate_contract_provider",
  };
  delete providerSwap.journal_entry_digest;
  assert.throws(
    () => assertAttemptJournalAppend(precommitted, providerSwap),
    /provider_id binding drift/,
  );
  const grantSwap = {
    ...admitted,
    signed_grant_digest: digest("substituted-signed-grant"),
  };
  delete grantSwap.journal_entry_digest;
  assert.throws(
    () => assertAttemptJournalAppend(precommitted, grantSwap),
    /signed_grant_digest binding drift/,
  );
  const impossibleProviderSequence = {
    ...starting,
    provider_sequence: 2,
  };
  delete impossibleProviderSequence.journal_entry_digest;
  assert.throws(
    () => normalizeAttemptJournalEntry(impossibleProviderSequence),
    /provider_state prepared is inconsistent with provider_sequence 2/,
  );
  const dispatch = normalizeEffectDispatchRecord({
    version: 1,
    dispatch_event_ref: "dispatch-event:attempt-1",
    journal_entry_ref: starting.journal_entry_ref,
    journal_entry_digest: starting.journal_entry_digest,
    attempt_ref: starting.attempt_ref,
    instrument_ref: starting.instrument_ref,
    lease_id: starting.lease_id,
    fencing_token: starting.fencing_token,
    fencing_generation: starting.fencing_generation,
    operation_id: starting.operation_id,
    execution_request_digest: starting.execution_request_digest,
    provider_id: starting.provider_id,
    provider_descriptor_digest: starting.provider_descriptor_digest,
    provider_request_digest: digest("provider-request"),
    provider_sequence: starting.provider_sequence,
    dispatched_at: "2026-07-18T00:00:00.132Z",
  }, starting);
  assert.equal(dispatch.journal_entry_digest, starting.journal_entry_digest);
  assert.equal(dispatch.provider_id, starting.provider_id);
  assert.equal(dispatch.provider_descriptor_digest, starting.provider_descriptor_digest);
  assert.equal(dispatch.provider_sequence, 1);
  assert.throws(
    () => normalizeEffectDispatchRecord({
      ...dispatch,
      dispatch_record_digest: undefined,
      provider_descriptor_digest: digest("substituted-provider-descriptor"),
    }, starting),
    /provider_descriptor_digest binding drift/,
  );
  assert.throws(
    () => normalizeEffectDispatchRecord({
      ...dispatch,
      dispatch_record_digest: undefined,
      provider_sequence: 0,
    }, starting),
    /provider_sequence binding drift/,
  );
  assert.throws(
    () => normalizeEffectDispatchRecord({
      ...dispatch,
      dispatch_record_digest: undefined,
      dispatched_at: "2026-07-18T00:00:00.130Z",
    }, starting),
    /fsync-before-effect/,
  );

  const running = nextJournal(starting, "running", "dispatched", "ambiguous", 140);
  const effectRecorded = nextJournal(running, "effect_recorded", "acknowledged", "confirmed_effect", 150);
  assert.equal(effectRecorded.state, "effect_recorded");
  const ambiguousEffect = nextJournal(running, "ambiguous_effect", "ambiguous_effect", "ambiguous", 160);
  const reconciledNoEffect = nextJournal(
    ambiguousEffect,
    "reconciled_no_effect",
    "reconciled_no_effect",
    "confirmed_no_effect",
    170,
  );
  assert.equal(reconciledNoEffect.state, "reconciled_no_effect");
  const broken = {
    ...effectRecorded,
    journal_entry_ref: "journal-entry:attempt-1-broken",
    previous_entry_digest: digest("wrong-parent"),
  };
  delete broken.journal_entry_digest;
  assert.throws(() => assertAttemptJournalAppend(running, broken), /does not bind the prior row/);

  const outbox0 = normalizeDurableOutboxEntry({
    version: 1,
    outbox_entry_ref: "outbox-entry:attempt-1-0",
    attempt_ref: effectRecorded.attempt_ref,
    instrument_ref: effectRecorded.instrument_ref,
    lease_id: effectRecorded.lease_id,
    fencing_token: effectRecorded.fencing_token,
    fencing_generation: effectRecorded.fencing_generation,
    operation_id: effectRecorded.operation_id,
    execution_request_digest: effectRecorded.execution_request_digest,
    source_journal_entry_digest: effectRecorded.journal_entry_digest,
    payload_kind: "provider_report",
    payload_ref: "provider-report:attempt-1-ack",
    payload_digest: digest("provider-report-ack"),
    sequence: 0,
    previous_entry_digest: null,
    recorded_at: "2026-07-18T00:00:00.152Z",
    fsynced_at: "2026-07-18T00:00:00.153Z",
  });
  assert.equal(assertOutboxJournalBinding(outbox0, effectRecorded).outbox_entry_digest,
    outbox0.outbox_entry_digest);
  const unboundOutbox = {
    ...outbox0,
    source_journal_entry_digest: digest("unrelated-journal-row"),
  };
  delete unboundOutbox.outbox_entry_digest;
  assert.throws(
    () => assertOutboxJournalBinding(unboundOutbox, effectRecorded),
    /does not bind the journal row/,
  );
  const outbox1Input = {
    ...outbox0,
    outbox_entry_ref: "outbox-entry:attempt-1-1",
    source_journal_entry_digest: effectRecorded.journal_entry_digest,
    payload_kind: "worker_receipt",
    payload_ref: "receipt:worker-attempt-1",
    payload_digest: digest("worker-receipt"),
    sequence: 1,
    previous_entry_digest: outbox0.outbox_entry_digest,
    recorded_at: "2026-07-18T00:00:00.154Z",
    fsynced_at: "2026-07-18T00:00:00.155Z",
  };
  delete outbox1Input.outbox_entry_digest;
  const outbox1 = assertDurableOutboxAppend(outbox0, outbox1Input);
  const ack = normalizeOutboxAcknowledgement({
    version: 1,
    acknowledgement_ref: "outbox-ack:attempt-1-1",
    outbox_entry_ref: outbox1.outbox_entry_ref,
    outbox_entry_digest: outbox1.outbox_entry_digest,
    recipient_principal_id: "principal:broker-1",
    acknowledged_at: "2026-07-18T00:00:00.156Z",
  }, outbox1);
  assert.equal(ack.outbox_entry_digest, outbox1.outbox_entry_digest);
  assert.throws(
    () => normalizeOutboxAcknowledgement({
      ...ack,
      acknowledgement_digest: undefined,
      acknowledged_at: "2026-07-18T00:00:00.154Z",
    }, outbox1),
    /fsync-before-ack/,
  );

  assert.equal(
    assertProviderAlignedJournalState(
      starting,
      report(f, "acknowledged", 3, "confirmed_effect"),
      f.operationRegistry,
    ).state,
    "acknowledged",
  );
  assert.throws(
    () => assertProviderAlignedJournalState(
      starting,
      report(f, "prepared", 2, "not_dispatched"),
      f.operationRegistry,
    ),
    /prepared@2 is unreachable from journal state\/sequence prepared@1/,
  );
  const originalSetHas = Set.prototype.has;
  try {
    Set.prototype.has = () => true;
    assert.throws(
      () => assertProviderAlignedJournalState(
        starting,
        report(f, "prepared", 2, "not_dispatched"),
        f.operationRegistry,
      ),
      /prepared@2 is unreachable from journal state\/sequence prepared@1/,
    );
  } finally {
    Set.prototype.has = originalSetHas;
  }
  assert.throws(
    () => assertProviderAlignedJournalState(
      starting,
      report(f, "acknowledged", 0, "confirmed_effect"),
      f.operationRegistry,
    ),
    /acknowledged@0 is unreachable from journal state\/sequence prepared@1/,
  );
  assert.throws(
    () => assertProviderAlignedJournalState(
      effectRecorded,
      report(f, "prepared", 1, "not_dispatched"),
      f.operationRegistry,
    ),
    /unreachable/,
  );
});

test("provider dispatch credentials expose only exact durable bindings and redemption cannot drift", () => {
  const f = fixture();
  const precommitted = journal0(f);
  const admitted = nextJournal(precommitted, "admitted", "prepared", "not_dispatched", 120);
  const starting = nextJournal(admitted, "effect_starting", "prepared", "not_dispatched", 130);
  const fenceBindingDigest = providerDispatchFenceBindingDigest({
    runtime_id: `physical-runtime:v1:${digest("contract-runtime").slice(0, 32)}`,
    session_nucleus_hash: digest("contract-session-nucleus"),
    attempt_ref: starting.attempt_ref,
    instrument_ref: starting.instrument_ref,
    execution_principal_id: f.lease.execution_principal_id,
    lease_id: starting.lease_id,
    fencing_token: starting.fencing_token,
    fencing_generation: starting.fencing_generation,
    execution_request_digest: starting.execution_request_digest,
    provider_id: starting.provider_id,
    provider_descriptor_digest: starting.provider_descriptor_digest,
  });
  const credential = normalizeProviderDispatchCredential({
    version: 1,
    domain: "hacker-bob/provider-dispatch-credential/v1",
    credential_ref: "provider-dispatch-credential:contract-attempt-1",
    runtime_id: `physical-runtime:v1:${digest("contract-runtime").slice(0, 32)}`,
    session_nucleus_hash: digest("contract-session-nucleus"),
    dispatch_record_digest: digest("contract-dispatch-record"),
    journal_entry_ref: starting.journal_entry_ref,
    journal_entry_digest: starting.journal_entry_digest,
    attempt_ref: starting.attempt_ref,
    instrument_ref: starting.instrument_ref,
    execution_principal_id: f.lease.execution_principal_id,
    lease_id: starting.lease_id,
    fencing_generation: starting.fencing_generation,
    fence_binding_digest: fenceBindingDigest,
    effect_not_before: f.lease.effect_not_before,
    effect_deadline: f.lease.effect_deadline,
    operation_id: starting.operation_id,
    execution_request_digest: starting.execution_request_digest,
    experiment_plan_hash: starting.experiment_plan_hash,
    execution_lineage_digest: starting.execution_lineage_digest,
    provider_id: starting.provider_id,
    provider_descriptor_digest: starting.provider_descriptor_digest,
    provider_request_digest: starting.provider_request_digest,
    provider_state: "prepared",
    provider_sequence: starting.provider_sequence,
    store_generation: 5,
    store_head_event_digest: digest("contract-store-head"),
  });
  assert.equal(Object.hasOwn(credential, "fencing_token"), false);
  assert.equal(Object.hasOwn(credential, "signed_grant_digest"), false);
  assert.equal(credential.experiment_plan_hash, starting.experiment_plan_hash);
  assert.equal(credential.execution_lineage_digest, starting.execution_lineage_digest);
  assert.equal(JSON.stringify(credential).includes(starting.fencing_token), false);
  assert.notEqual(
    fenceBindingDigest,
    providerDispatchFenceBindingDigest({
      runtime_id: credential.runtime_id,
      session_nucleus_hash: credential.session_nucleus_hash,
      attempt_ref: starting.attempt_ref,
      instrument_ref: starting.instrument_ref,
      execution_principal_id: f.lease.execution_principal_id,
      lease_id: starting.lease_id,
      fencing_token: "different-contract-fence",
      fencing_generation: starting.fencing_generation,
      execution_request_digest: starting.execution_request_digest,
      provider_id: starting.provider_id,
      provider_descriptor_digest: starting.provider_descriptor_digest,
    }),
  );
  assert.throws(
    () => normalizeProviderDispatchCredential({ ...credential, fencing_token: starting.fencing_token }),
    /unknown fields: fencing_token/,
  );
  const { domain: _domain, version: _version, ...credentialFields } = credential;
  const redemption = normalizeProviderDispatchRedemption({
    version: 1,
    redemption_ref: "provider-dispatch-redemption:contract-attempt-1",
    ...credentialFields,
    redeemed_at: "2026-07-18T00:00:00.140Z",
  }, credential);
  assert.equal(redemption.credential_digest, credential.credential_digest);
  assert.equal(redemption.experiment_plan_hash, credential.experiment_plan_hash);
  assert.equal(redemption.execution_lineage_digest, credential.execution_lineage_digest);
  assert.throws(
    () => normalizeProviderDispatchCredential({
      ...credential,
      execution_lineage_digest: digest("redirected-execution-lineage"),
    }),
    /credential_digest does not match normalized content/,
  );
  assert.throws(
    () => normalizeProviderDispatchRedemption({
      ...redemption,
      redemption_digest: undefined,
      provider_request_digest: digest("redirected-provider-request"),
      credential_digest: digest("forged-credential"),
    }, credential),
    /credential_digest does not match normalized content|credential_digest binding drift/,
  );
});

test("signed stop request and acknowledgement are exact-operation bound and require trusted verification", () => {
  const f = fixture();
  const request = normalizeSignedStopRequest(stopRequest(f));
  assert.equal(requestInstrumentLeaseStop(
    f.lease,
    request,
    trustedVerification(request.authentication, "stop-request-verifier-v1"),
  ).state, "stop_requested");
  const verifiedRequest = projectVerifiedStopRequest(
    request,
    trustedVerification(request.authentication, "stop-request-verifier-v1"),
  );
  assert.equal(verifiedRequest.stop_request_digest, request.stop_request_digest);
  assert.equal(Object.isFrozen(verifiedRequest), true);

  assert.throws(
    () => projectVerifiedStopRequest(request, {
      ...trustedVerification(request.authentication),
      verified_payload_digest: digest("different-stop"),
    }),
    /does not match the signed envelope/,
  );
  const redirected = clone(request);
  redirected.operation_id = "representation.read";
  assert.throws(
    () => normalizeSignedStopRequest(redirected),
    /does not match normalized content|does not bind the normalized payload/,
  );

  const ack = normalizeSignedStopAcknowledgement(
    stopAcknowledgement(f, request),
    request,
    f.lease,
  );
  assert.equal(ack.deadline_met, true);
  const verifiedAck = projectVerifiedStopAcknowledgement(
    ack,
    request,
    f.lease,
    trustedVerification(ack.authentication, "stop-ack-verifier-v1"),
    trustedVerification(request.authentication, "stop-request-verifier-v1"),
  );
  assert.equal(verifiedAck.outcome, "stopped");

  const late = normalizeSignedStopAcknowledgement(
    stopAcknowledgement(f, request, "cannot_confirm", "2026-07-18T00:00:13.000Z"),
    request,
    f.lease,
  );
  assert.equal(late.deadline_met, false);
  assert.equal(late.emission_state, "unknown");
  assert.throws(
    () => normalizeSignedStopAcknowledgement({
      ...stopAcknowledgement(f, request, "cannot_confirm"),
      emission_state: "inhibited",
    }, request, f.lease),
    /must preserve unknown emission state/,
  );
});

test("the independent supervisor fails closed on deadman, worker, provider, epoch, and containment failures", () => {
  const f = fixture();
  const supervisorContract = supervisor(f);
  const heartbeatInput = heartbeat(f, supervisorContract);
  const normalizedHeartbeat = normalizeSignedDeadmanHeartbeat(heartbeatInput, supervisorContract);
  const heartbeat2Payload = {
    ...Object.fromEntries(Object.entries(normalizedHeartbeat).filter(([field]) => (
      !["heartbeat_digest", "authentication"].includes(field)
    ))),
    heartbeat_ref: "heartbeat:attempt-1-2",
    heartbeat_sequence: 2,
    emitted_at: "2026-07-18T00:00:02.000Z",
    valid_until: "2026-07-18T00:00:05.000Z",
  };
  const heartbeat2 = {
    ...heartbeat2Payload,
    authentication: signatureEnvelope(
      heartbeat2Payload,
      "worker-heartbeat-key-1",
      "heartbeat-2",
    ),
  };
  assert.equal(assertDeadmanHeartbeatTransition(
    normalizedHeartbeat,
    heartbeat2,
    supervisorContract,
  ).heartbeat_sequence, 2);
  const healthy = evaluateSafetySupervisor({
    supervisor_contract: supervisorContract,
    lease: f.lease,
    heartbeat: normalizedHeartbeat,
    heartbeat_verification: trustedVerification(normalizedHeartbeat.authentication, "heartbeat-verifier-v1"),
    observed_at: "2026-07-18T00:00:03.000Z",
    authority_epoch: 7,
    revocation_generation: 2,
    provider_reachable: true,
    worker_alive: true,
  });
  assert.equal(healthy.decision, "continue");
  assert.equal(healthy.automatic_retry_allowed, false);

  const heldPastDurableHeartbeatDeadline = evaluateSafetySupervisor({
    supervisor_contract: supervisorContract,
    lease: f.lease,
    heartbeat: null,
    heartbeat_verification: null,
    observed_at: "2026-07-18T00:00:05.001Z",
    authority_epoch: 7,
    revocation_generation: 2,
    provider_reachable: true,
    worker_alive: true,
  });
  assert.equal(heldPastDurableHeartbeatDeadline.decision, "stop_fence_cleanup");
  assert.deepEqual(heldPastDurableHeartbeatDeadline.reasons, ["deadman_missed"]);

  const leaseWithShortHeartbeatDeadline = normalizeInstrumentLease({
    ...f.lease,
    heartbeat_deadline: "2026-07-18T00:00:03.000Z",
  });
  assert.throws(
    () => evaluateSafetySupervisor({
      supervisor_contract: supervisorContract,
      lease: leaseWithShortHeartbeatDeadline,
      heartbeat: normalizedHeartbeat,
      heartbeat_verification: trustedVerification(
        normalizedHeartbeat.authentication,
        "heartbeat-verifier-v1",
      ),
      observed_at: "2026-07-18T00:00:02.000Z",
      authority_epoch: 7,
      revocation_generation: 2,
      provider_reachable: true,
      worker_alive: true,
    }),
    /cannot extend beyond the durable lease heartbeat deadline/,
  );

  for (const state of ["stop_requested", "fenced", "restoring", "released", "quarantined"]) {
    const terminal = ["released", "quarantined"].includes(state);
    const stateLease = normalizeInstrumentLease({
      ...f.lease,
      state,
      sequence: 1,
      updated_at: "2026-07-18T00:00:02.000Z",
      ...(terminal ? {
        closed_at: "2026-07-18T00:00:02.000Z",
        terminal_disposition: state === "released" ? "confirmed_no_effect" : "unknown_effect",
        terminal_receipt_ref: `receipt:${state}-attempt-1`,
        terminal_receipt_digest: digest(`${state}-attempt-1`),
      } : {}),
    });
    const evaluation = evaluateSafetySupervisor({
      supervisor_contract: supervisorContract,
      lease: stateLease,
      heartbeat: normalizedHeartbeat,
      heartbeat_verification: trustedVerification(
        normalizedHeartbeat.authentication,
        "heartbeat-verifier-v1",
      ),
      observed_at: "2026-07-18T00:00:03.000Z",
      authority_epoch: 7,
      revocation_generation: 2,
      provider_reachable: true,
      worker_alive: true,
    });
    assert.equal(
      evaluation.decision,
      terminal ? "inactive" : "stop_fence_cleanup",
      state,
    );
    assert.deepEqual(evaluation.reasons, [`lease_${state}`], state);
  }

  const failed = evaluateSafetySupervisor({
    supervisor_contract: supervisorContract,
    lease: f.lease,
    heartbeat: normalizedHeartbeat,
    heartbeat_verification: trustedVerification(normalizedHeartbeat.authentication, "heartbeat-verifier-v1"),
    observed_at: "2026-07-18T00:00:06.000Z",
    authority_epoch: 8,
    revocation_generation: 3,
    provider_reachable: false,
    worker_alive: false,
  });
  assert.equal(failed.decision, "stop_fence_cleanup");
  assert.deepEqual(failed.reasons, [
    "authority_epoch_drift",
    "deadman_missed",
    "provider_unreachable",
    "revocation_generation_drift",
    "worker_exit",
  ]);
  assert.throws(
    () => evaluateSafetySupervisor({
      supervisor_contract: supervisorContract,
      lease: f.lease,
      heartbeat: normalizedHeartbeat,
      heartbeat_verification: {
        ...trustedVerification(normalizedHeartbeat.authentication),
        verified_proof_digest: digest("forged-heartbeat-proof"),
      },
      observed_at: "2026-07-18T00:00:03.000Z",
      authority_epoch: 7,
      revocation_generation: 2,
      provider_reachable: true,
      worker_alive: true,
    }),
    /does not match the signed envelope/,
  );
  assert.throws(
    () => normalizeSafetySupervisorContract({
      ...supervisorContract,
      supervisor_contract_digest: undefined,
      containment_actions: ["worker_kill"],
    }),
    /independent device\/RF\/power action/,
  );
  assert.equal(supervisor(f, "operator_containment").containment_mode, "operator_containment");
});

test("safety-supervisor deadman policy has a fixed overflow-safe maximum window", () => {
  const f = fixture();
  const baseline = supervisor(f);
  const atLimit = {
    ...baseline,
    heartbeat_interval_ms: 10_000,
    miss_tolerance: MAX_SUPERVISOR_DEADMAN_WINDOW_MS / 10_000,
  };
  delete atLimit.supervisor_contract_digest;
  const normalizedAtLimit = normalizeSafetySupervisorContract(atLimit);
  assert.equal(
    normalizedAtLimit.heartbeat_interval_ms * normalizedAtLimit.miss_tolerance,
    MAX_SUPERVISOR_DEADMAN_WINDOW_MS,
  );

  for (const [heartbeatIntervalMs, missTolerance] of [
    [MAX_SUPERVISOR_DEADMAN_WINDOW_MS + 1, 1],
    [30_001, 2],
    [Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER],
  ]) {
    const unbounded = {
      ...baseline,
      heartbeat_interval_ms: heartbeatIntervalMs,
      miss_tolerance: missTolerance,
    };
    delete unbounded.supervisor_contract_digest;
    assert.throws(
      () => normalizeSafetySupervisorContract(unbounded),
      /deadman window must not exceed 60000 milliseconds/,
    );
  }
});

test("cleanup bootstrap can materialize only the precommitted snapshot and restoration never masks residue", () => {
  const f = fixture();
  const supervisorContract = supervisor(f);
  const bootstrap = normalizeRecoveryWorkerBootstrap(
    recoveryBootstrap(f),
    f.cleanupCapability,
    f.effectRegistry,
  );
  const verifiedBootstrap = projectVerifiedRecoveryWorkerBootstrap(
    bootstrap,
    f.cleanupCapability,
    f.effectRegistry,
    supervisorContract,
    trustedVerification(bootstrap.authentication, "recovery-bootstrap-verifier-v1"),
  );
  assert.equal(verifiedBootstrap.recovery_bootstrap_digest, bootstrap.recovery_bootstrap_digest);
  assert.equal(verifiedBootstrap.not_before, bootstrap.not_before);
  assert.deepEqual(
    assertVerifiedRecoveryBootstrapProjection(verifiedBootstrap),
    verifiedBootstrap,
  );
  assert.throws(
    () => assertVerifiedRecoveryBootstrapProjection(clone(verifiedBootstrap)),
    /was not issued by the recovery-bootstrap verifier/,
  );
  const detachedSupervisorInput = {
    ...supervisorContract,
    attempt_ref: "attempt:different-attempt",
  };
  delete detachedSupervisorInput.supervisor_contract_digest;
  const detachedSupervisor = normalizeSafetySupervisorContract(detachedSupervisorInput);
  assert.throws(
    () => projectVerifiedRecoveryWorkerBootstrap(
      bootstrap,
      f.cleanupCapability,
      f.effectRegistry,
      detachedSupervisor,
      trustedVerification(bootstrap.authentication, "recovery-bootstrap-verifier-v1"),
    ),
    /attempt_ref is detached from the supervisor/,
  );
  assert.deepEqual(bootstrap.allowed_operation_ids, [f.cleanupCapability.restore_operation_id]);
  assert.deepEqual(bootstrap.allowed_materialization_refs, [f.cleanupCapability.workspace_snapshot_ref]);
  assert.equal(bootstrap.agent_channel_enabled, false);
  assert.throws(
    () => normalizeRecoveryWorkerBootstrap({
      ...recoveryBootstrap(f),
      allowed_operation_ids: ["instrument.administer.v1"],
    }, f.cleanupCapability, f.effectRegistry),
    /precommitted restore operation/,
  );
  assert.throws(
    () => normalizeRecoveryWorkerBootstrap({
      ...recoveryBootstrap(f),
      safety_root_status: "compromised",
    }, f.cleanupCapability, f.effectRegistry),
    /compromise requires quarantine/,
  );

  const receiptPayload = {
    version: 1,
    restoration_receipt_ref: "receipt:restoration-attempt-1",
    recovery_bootstrap_digest: bootstrap.recovery_bootstrap_digest,
    cleanup_capability_digest: f.cleanupCapability.capability_digest,
    source_execution_request_digest: f.cleanupCapability.source_execution_request_digest,
    instrument_ref: f.cleanupCapability.instrument_ref,
    lease_id: f.cleanupCapability.lease_id,
    fencing_token: f.cleanupCapability.fencing_token,
    workspace_snapshot_ref: f.cleanupCapability.workspace_snapshot_ref,
    workspace_snapshot_digest: f.cleanupCapability.workspace_snapshot_digest,
    restore_operation_id: f.cleanupCapability.restore_operation_id,
    restore_operation_digest: f.cleanupCapability.restore_operation_digest,
    pre_restore_state_digest: digest("pre-restore-state"),
    expected_terminal_state_digest: bootstrap.expected_terminal_state_digest,
    observed_terminal_state_digest: bootstrap.expected_terminal_state_digest,
    terminal_state: "restored",
    provider_receipt_ref: "receipt:provider-restore-attempt-1",
    provider_receipt_digest: digest("provider-restore-receipt"),
    residual_state_ref: null,
    residual_state_digest: null,
    completed_at: "2026-07-18T00:00:20.000Z",
  };
  const receipt = normalizeSignedRestorationReceipt({
    ...receiptPayload,
    authentication: signatureEnvelope(receiptPayload, "cleanup-worker-key-1", "restoration-1"),
  }, bootstrap, f.cleanupCapability, f.effectRegistry);
  assert.equal(receipt.terminal_state, "restored");
  assert.equal(projectVerifiedRestorationReceipt(
    receipt,
    bootstrap,
    f.cleanupCapability,
    f.effectRegistry,
    supervisorContract,
    trustedVerification(receipt.authentication, "restoration-verifier-v1"),
    trustedVerification(bootstrap.authentication, "recovery-bootstrap-verifier-v1"),
  ).terminal_state, "restored");
  assert.throws(
    () => normalizeSignedRestorationReceipt({
      ...receiptPayload,
      terminal_state: "quarantined",
      authentication: signatureEnvelope({ ...receiptPayload, terminal_state: "quarantined" }),
    }, bootstrap, f.cleanupCapability, f.effectRegistry),
    /requires an explicit residual-state record/,
  );
  assert.throws(
    () => normalizeSignedRestorationReceipt({
      ...receiptPayload,
      observed_terminal_state_digest: digest("different-state"),
      authentication: signatureEnvelope({
        ...receiptPayload,
        observed_terminal_state_digest: digest("different-state"),
      }),
    }, bootstrap, f.cleanupCapability, f.effectRegistry),
    /requires exact expected terminal state/,
  );
});

test("startup reconciliation never retries ambiguous effects and requires intact cleanup authority", () => {
  const f = fixture();
  const supervisorContract = supervisor(f);
  const startupBootstrap = normalizeRecoveryWorkerBootstrap(
    recoveryBootstrap(f),
    f.cleanupCapability,
    f.effectRegistry,
  );
  const verifiedStartupBootstrap = projectVerifiedRecoveryWorkerBootstrap(
    startupBootstrap,
    f.cleanupCapability,
    f.effectRegistry,
    supervisorContract,
    trustedVerification(startupBootstrap.authentication, "recovery-bootstrap-verifier-v1"),
  );
  const precommitted = journal0(f);
  const preEffect = reconcileStartupAttempt({
    version: 1,
    reconciliation_ref: "startup-reconciliation:attempt-1-pre",
    observed_at: "2026-07-18T00:00:10.000Z",
    journal_head: precommitted,
    lease: f.lease,
    provider_report: report(f, "created", 0, "not_dispatched"),
    outbox_head: null,
    safety_root_status: "trusted",
    verified_recovery_bootstrap: null,
  }, f.operationRegistry);
  assert.equal(preEffect.action, "close_confirmed_no_effect");
  assert.equal(preEffect.automatic_retry_allowed, false);
  const reconciledNoEffectJournal = nextJournal(
    precommitted,
    "reconciled_no_effect",
    "refused",
    "confirmed_no_effect",
    115,
  );
  const terminalNoEffect = reconcileStartupAttempt({
    version: 1,
    reconciliation_ref: "startup-reconciliation:attempt-1-terminal-no-effect",
    observed_at: "2026-07-18T00:00:10.000Z",
    journal_head: reconciledNoEffectJournal,
    lease: f.lease,
    provider_report: report(f, "refused", 1, "confirmed_no_effect"),
    outbox_head: null,
    safety_root_status: "trusted",
    verified_recovery_bootstrap: null,
  }, f.operationRegistry);
  assert.equal(terminalNoEffect.action, "close_confirmed_no_effect");
  assert.equal(terminalNoEffect.terminal_state, "reconciled_no_effect");
  assert.equal(terminalNoEffect.requires_lease_closure, true);

  const admitted = nextJournal(precommitted, "admitted", "prepared", "not_dispatched", 120);
  const starting = nextJournal(admitted, "effect_starting", "prepared", "not_dispatched", 130);
  const ambiguous = reconcileStartupAttempt({
    version: 1,
    reconciliation_ref: "startup-reconciliation:attempt-1-ambiguous",
    observed_at: "2026-07-18T00:00:20.000Z",
    journal_head: starting,
    lease: f.lease,
    provider_report: report(f, "ambiguous_effect", 3, "ambiguous"),
    outbox_head: null,
    safety_root_status: "trusted",
    verified_recovery_bootstrap: verifiedStartupBootstrap,
  }, f.operationRegistry);
  assert.equal(ambiguous.action, "stop_reconcile_restore");
  assert.equal(ambiguous.requires_fence, true);
  assert.equal(ambiguous.requires_cleanup, true);
  assert.equal(ambiguous.automatic_retry_allowed, false);
  const staleAmbiguous = reconcileStartupAttempt({
    version: 1,
    reconciliation_ref: "startup-reconciliation:attempt-1-stale",
    observed_at: "2026-07-18T00:02:00.000Z",
    journal_head: starting,
    lease: f.lease,
    provider_report: report(f, "ambiguous_effect", 3, "ambiguous"),
    outbox_head: null,
    safety_root_status: "trusted",
    verified_recovery_bootstrap: verifiedStartupBootstrap,
  }, f.operationRegistry);
  assert.equal(staleAmbiguous.requires_fence, true);
  assert.equal(staleAmbiguous.reasons.includes("lease_expired"), true);
  assert.equal(staleAmbiguous.automatic_retry_allowed, false);

  const noRoot = reconcileStartupAttempt({
    version: 1,
    reconciliation_ref: "startup-reconciliation:attempt-1-no-root",
    observed_at: "2026-07-18T00:00:20.000Z",
    journal_head: starting,
    lease: f.lease,
    provider_report: report(f, "ambiguous_effect", 3, "ambiguous"),
    outbox_head: null,
    safety_root_status: "compromised",
    verified_recovery_bootstrap: verifiedStartupBootstrap,
  }, f.operationRegistry);
  assert.equal(noRoot.action, "quarantine");
  assert.equal(noRoot.terminal_state, "quarantined");
  assert.equal(noRoot.requires_cleanup, false);

  const acknowledged = reconcileStartupAttempt({
    version: 1,
    reconciliation_ref: "startup-reconciliation:attempt-1-acknowledged",
    observed_at: "2026-07-18T00:00:20.000Z",
    journal_head: starting,
    lease: f.lease,
    provider_report: report(f, "acknowledged", 3, "confirmed_effect"),
    outbox_head: null,
    safety_root_status: "trusted",
    verified_recovery_bootstrap: verifiedStartupBootstrap,
  }, f.operationRegistry);
  assert.equal(acknowledged.action, "resume_restore");
  assert.equal(acknowledged.automatic_retry_allowed, false);
});
