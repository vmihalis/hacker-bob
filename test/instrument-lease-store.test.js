"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const durableStoreCompatibilityModule = require("../mcp/lib/instrument-lease-store.js");
const durableStoreCanonicalModule = require(
  "../packages/bob-instrument-broker/lib/instrument-lease-store.js"
);
const {
  INSTRUMENT_LEASE_CHECKPOINT_FILE_MAX_BYTES,
  INSTRUMENT_LEASE_CHECKPOINT_PROJECTION_SCHEMA_VERSION,
  assertDurablePhysicalExecutionTransactionPort,
  assertDurableInstrumentLeaseBrokerPort,
  assertDurableInstrumentLeaseStore,
  assertDurableInstrumentProviderDispatchPort,
  assertDurableProviderDispatchCredential,
  assertInstrumentLeaseCheckpointAnchorPort,
  createDurableInstrumentLeaseBrokerPort,
  createDurableInstrumentLeaseStore,
  createDurableInstrumentProviderDispatchPort,
  createDurablePhysicalExecutionTransactionPort,
  createIdempotentOutboxRecipientPort,
  createInstrumentLeaseCheckpointAnchorPort,
  readDurableInstrumentLeaseBrokerClosureState,
} = durableStoreCompatibilityModule;
const {
  assertAttemptJournalAppend,
  normalizeAttemptJournalEntry,
  normalizeDurableOutboxEntry,
  normalizeEffectDispatchRecord,
  normalizeSafetySupervisorContract,
  providerDispatchFenceBindingDigest,
} = require("../mcp/lib/instrument-lease-contract.js");
const {
  canonicalJson,
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");
const {
  createDeterministicMockDispatchAuthorityPort,
} = require("../mcp/lib/physical-dispatch-authority.js");
const {
  normalizePhysicalExecutionCompositeBinding,
} = require("../packages/bob-instrument-broker/lib/physical-execution-transaction-owner.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function clone(value) {
  return value == null ? null : structuredClone(value);
}

class MemoryStateAnchor {
  constructor() {
    this.state = null;
    this.throwAfterCommit = false;
    this.hiddenReads = 0;
    this.rejectNext = false;
  }

  readState() {
    if (this.hiddenReads > 0) {
      this.hiddenReads -= 1;
      throw new Error("injected anchor read outage");
    }
    return clone(this.state);
  }

  compareAndSet(request) {
    const currentGeneration = this.state == null ? null : this.state.generation;
    const currentDigest = this.state == null ? null : this.state.head_event_digest;
    if (request.expected_generation !== currentGeneration
        || request.expected_head_event_digest !== currentDigest) {
      return false;
    }
    if (this.rejectNext) {
      this.rejectNext = false;
      return false;
    }
    this.state = clone(request.next_state);
    if (this.throwAfterCommit) {
      this.throwAfterCommit = false;
      this.hiddenReads = 1;
      throw new Error("injected commit response loss");
    }
    return true;
  }

  armAmbiguousCommit() {
    this.throwAfterCommit = true;
  }

  armRejectedCommit() {
    this.rejectNext = true;
  }
}

class MemoryCheckpointAnchor {
  constructor() {
    this.state = null;
    this.throwAfterCommit = false;
    this.hiddenReads = 0;
    this.rejectNext = false;
    this.hideReadAfterReject = false;
  }

  readState() {
    if (this.hiddenReads > 0) {
      this.hiddenReads -= 1;
      throw new Error("injected checkpoint anchor read outage");
    }
    return clone(this.state);
  }

  compareAndSet(request) {
    const currentGeneration = this.state == null ? null : this.state.checkpoint_generation;
    const currentDigest = this.state == null ? null : this.state.checkpoint_anchor_digest;
    if (request.expected_checkpoint_generation !== currentGeneration
        || request.expected_checkpoint_anchor_digest !== currentDigest) {
      return false;
    }
    if (this.rejectNext) {
      this.rejectNext = false;
      if (this.hideReadAfterReject) {
        this.hideReadAfterReject = false;
        this.hiddenReads = 1;
      }
      return false;
    }
    this.state = clone(request.next_state);
    if (this.throwAfterCommit) {
      this.throwAfterCommit = false;
      this.hiddenReads = 1;
      throw new Error("injected checkpoint commit response loss");
    }
    return true;
  }

  armAmbiguousCommit() {
    this.throwAfterCommit = true;
  }

  armRejectedCommit() {
    this.rejectNext = true;
  }

  armRejectedCommitWithReadOutage() {
    this.rejectNext = true;
    this.hideReadAfterReject = true;
  }
}

function makeClock(start = "2026-07-18T00:00:00.200Z") {
  let current = Date.parse(start);
  const clock = () => {
    const value = new Date(current);
    current += 1;
    return value;
  };
  clock.set = (timestamp) => { current = Date.parse(timestamp); };
  return clock;
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-instrument-lease-store-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const anchor = new MemoryStateAnchor();
  const sessionNucleusHash = digest("session-nucleus");
  const runtimeId = `physical-runtime:v1:${digest("runtime-enrollment").slice(0, 32)}`;
  const masterKey = crypto.createHash("sha256").update("lease-store-test-key").digest();
  const clock = makeClock();
  const open = (overrides = {}) => createDurableInstrumentLeaseStore({
    root,
    runtimeId,
    sessionNucleusHash,
    masterKey,
    stateAnchor: anchor,
    checkpointMode: "legacy_full_audit",
    now: clock,
    ...overrides,
  });
  const lease = {
    version: 1,
    lease_id: "lease-ph-s7-runtime-1",
    instrument_ref: "instrument:owned-reader-runtime-1",
    owner_principal_id: "principal:broker-runtime-1",
    execution_principal_id: "principal:active-worker-runtime-1",
    terminal_receipt_recipient_principal_id: "principal:broker-runtime-1",
    terminal_receipt_idempotency_domain_digest: digest("terminal-recipient-domain"),
    attempt_ref: "attempt:physical-runtime-1",
    operation_id: "representation.write",
    execution_request_digest: digest("execution-request"),
    resource_bundle_digest: digest("resource-bundle"),
    fencing_token: "fence-runtime-1",
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
  const journal = normalizeAttemptJournalEntry({
    version: 1,
    journal_entry_ref: "journal-entry:runtime-1-0",
    attempt_ref: lease.attempt_ref,
    instrument_ref: lease.instrument_ref,
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    fencing_generation: lease.fencing_generation,
    operation_id: lease.operation_id,
    execution_request_digest: lease.execution_request_digest,
    experiment_plan_hash: digest("experiment-plan"),
    execution_lineage_digest: digest("execution-lineage"),
    authority_resolution_digest: digest("authority-resolution"),
    signed_grant_digest: digest("signed-grant"),
    replay_claim_digest: digest("grant-replay-claim"),
    replay_reservation_receipt_digest: digest("grant-replay-reservation-receipt"),
    provider_id: "deterministic_store_test",
    provider_descriptor_digest: digest("provider-descriptor"),
    provider_request_digest: digest("provider-request"),
    cleanup_capability_digest: digest("cleanup-capability"),
    cleanup_plan_digest: digest("cleanup-plan"),
    workspace_snapshot_ref: "workspace-snapshot:runtime-1",
    workspace_snapshot_digest: digest("workspace-snapshot"),
    stop_contract_digest: digest("stop-contract"),
    state: "precommitted",
    provider_state: "created",
    provider_sequence: 0,
    effect_disposition: "not_dispatched",
    sequence: 0,
    previous_entry_digest: null,
    recorded_at: "2026-07-18T00:00:00.100Z",
    fsynced_at: "2026-07-18T00:00:00.101Z",
  });
  return { anchor, clock, journal, lease, masterKey, open, root, runtimeId, sessionNucleusHash };
}

function boundedFixture(t) {
  const f = fixture(t);
  const checkpointAnchor = new MemoryCheckpointAnchor();
  const checkpointPort = createInstrumentLeaseCheckpointAnchorPort({
    portId: "instrument-checkpoint-anchor-test-v1",
    readState: () => checkpointAnchor.readState(),
    compareAndSet: (request) => checkpointAnchor.compareAndSet(request),
  });
  const open = () => f.open({
    checkpointMode: "bounded_checkpoint",
    checkpointPort,
  });
  return { ...f, checkpointAnchor, checkpointPort, open };
}

function rewriteCurrentCheckpointProjection(f, mutateProjection) {
  const anchor = clone(f.checkpointAnchor.state);
  const checkpointPath = path.join(f.root, "checkpoints", anchor.checkpoint_file);
  const metadata = JSON.parse(fs.readFileSync(path.join(f.root, "runtime.json"), "utf8"));
  const envelope = JSON.parse(fs.readFileSync(checkpointPath, "utf8"));
  const fields = {
    version: 1,
    domain: "hacker-bob/instrument-lease-checkpoint-envelope/v1",
    runtime_id: anchor.runtime_id,
    session_nucleus_hash: anchor.session_nucleus_hash,
    checkpoint_generation: anchor.checkpoint_generation,
    prior_checkpoint_digest: anchor.prior_checkpoint_digest,
    event_generation: anchor.event_generation,
    event_head_digest: anchor.event_head_digest,
    projection_schema_version: anchor.projection_schema_version,
  };
  const aad = Buffer.from(canonicalJson(fields), "utf8");
  const checkpointKey = Buffer.from(crypto.hkdfSync(
    "sha256",
    f.masterKey,
    Buffer.from(metadata.kdf_salt, "base64"),
    Buffer.from(
      `bob-plane-ph-s7-checkpoint:${f.sessionNucleusHash}:${f.runtimeId}`,
      "utf8",
    ),
    32,
  ));
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    checkpointKey,
    Buffer.from(envelope.nonce, "base64"),
  );
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64")),
    decipher.final(),
  ]);
  const payload = JSON.parse(plaintext.toString("utf8"));
  plaintext.fill(0);
  mutateProjection(payload);
  delete payload.projection_digest;
  payload.projection_digest = hashCanonicalJson(payload);
  const replacementPlaintext = Buffer.from(canonicalJson(payload), "utf8");
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", checkpointKey, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(replacementPlaintext), cipher.final()]);
  replacementPlaintext.fill(0);
  checkpointKey.fill(0);
  const envelopeBasis = {
    ...fields,
    algorithm: "aes-256-gcm",
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    ciphertext_digest: crypto.createHash("sha256").update(ciphertext).digest("hex"),
    tag: cipher.getAuthTag().toString("base64"),
  };
  const replacementEnvelope = {
    ...envelopeBasis,
    checkpoint_envelope_digest: hashCanonicalJson(envelopeBasis),
  };
  fs.chmodSync(checkpointPath, 0o600);
  fs.writeFileSync(checkpointPath, `${canonicalJson(replacementEnvelope)}\n`);
  fs.chmodSync(checkpointPath, 0o400);
  const anchorBasis = {
    version: anchor.version,
    domain: anchor.domain,
    runtime_id: anchor.runtime_id,
    session_nucleus_hash: anchor.session_nucleus_hash,
    checkpoint_generation: anchor.checkpoint_generation,
    prior_checkpoint_digest: anchor.prior_checkpoint_digest,
    event_generation: anchor.event_generation,
    event_head_digest: anchor.event_head_digest,
    projection_schema_version: anchor.projection_schema_version,
    ciphertext_digest: replacementEnvelope.ciphertext_digest,
    checkpoint_envelope_digest: replacementEnvelope.checkpoint_envelope_digest,
    checkpoint_file: anchor.checkpoint_file,
  };
  f.checkpointAnchor.state = {
    ...anchorBasis,
    checkpoint_anchor_digest: hashCanonicalJson(anchorBasis),
  };
}

function nextJournal(previous, state, providerState, effectDisposition, millis) {
  const providerSequence = providerState === previous.provider_state
    ? previous.provider_sequence
    : previous.provider_sequence + 1;
  const candidate = {
    ...previous,
    journal_entry_ref: `journal-entry:runtime-1-${previous.sequence + 1}`,
    state,
    provider_state: providerState,
    provider_sequence: providerSequence,
    effect_disposition: effectDisposition,
    sequence: previous.sequence + 1,
    previous_entry_digest: previous.journal_entry_digest,
    recorded_at: `2026-07-18T00:00:00.${String(millis).padStart(3, "0")}Z`,
    fsynced_at: `2026-07-18T00:00:00.${String(millis + 1).padStart(3, "0")}Z`,
  };
  delete candidate.journal_entry_digest;
  return assertAttemptJournalAppend(previous, candidate);
}

function prepareEffect(store, f) {
  store.acquireLease(f.lease);
  store.appendJournal(f.journal);
  const admitted = nextJournal(f.journal, "admitted", "prepared", "not_dispatched", 120);
  store.appendJournal(admitted);
  const starting = nextJournal(admitted, "effect_starting", "prepared", "not_dispatched", 130);
  store.appendJournal(starting);
  const dispatch = normalizeEffectDispatchRecord({
    version: 1,
    dispatch_event_ref: "dispatch-event:runtime-1",
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
  return { admitted, dispatch, starting };
}

function providerEnrollment(f, overrides = {}) {
  return {
    provider_id: f.journal.provider_id,
    provider_descriptor_digest: f.journal.provider_descriptor_digest,
    execution_principal_id: f.lease.execution_principal_id,
    instrument_refs: [f.lease.instrument_ref],
    authority_port: createDeterministicMockDispatchAuthorityPort({
      port_id: "deterministic-store-test-authority-v1",
      session_nucleus_hash: f.sessionNucleusHash,
      provider_id: f.journal.provider_id,
      provider_descriptor_digest: f.journal.provider_descriptor_digest,
      execution_principal_id: f.lease.execution_principal_id,
    }),
    ...overrides,
  };
}

function providerExpected(starting, overrides = {}) {
  return {
    attempt_ref: starting.attempt_ref,
    instrument_ref: starting.instrument_ref,
    operation_id: starting.operation_id,
    provider_id: starting.provider_id,
    provider_descriptor_digest: starting.provider_descriptor_digest,
    dispatch_journal_ref: starting.journal_entry_ref,
    provider_request_digest: starting.provider_request_digest,
    expected_state: "prepared",
    expected_sequence: starting.provider_sequence,
    ...overrides,
  };
}

function transactionBinding(f, lease, journal, overrides = {}) {
  const seed = overrides.transaction_ref || journal.attempt_ref;
  const fenceDigest = providerDispatchFenceBindingDigest({
    runtime_id: f.runtimeId,
    session_nucleus_hash: f.sessionNucleusHash,
    attempt_ref: journal.attempt_ref,
    instrument_ref: journal.instrument_ref,
    execution_principal_id: lease.execution_principal_id,
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    fencing_generation: lease.fencing_generation,
    execution_request_digest: journal.execution_request_digest,
    provider_id: journal.provider_id,
    provider_descriptor_digest: journal.provider_descriptor_digest,
  });
  return {
    version: 1,
    protocol: "hacker-bob/physical-execution-transaction/v1",
    transaction_ref: `transaction:${digest(seed).slice(0, 32)}`,
    execution_lineage_digest: journal.execution_lineage_digest,
    session_nucleus_hash: f.sessionNucleusHash,
    attempt_ref: journal.attempt_ref,
    replay_identity_digest: digest(`${seed}:transaction-replay-identity`),
    execution_request_digest: journal.execution_request_digest,
    authority_admission_digest: digest(`${seed}:transaction-authority-admission`),
    capability_grant_digest: journal.signed_grant_digest,
    commit_go_digest: digest(`${seed}:transaction-commit-go`),
    dispatch_admission_digest: digest(`${seed}:transaction-dispatch-admission`),
    provider_worker_vault_binding_digest: digest(`${seed}:transaction-provider-worker-vault`),
    transaction_capability_digest: digest(`${seed}:transaction-capability`),
    resource_admission_digest: digest(`${seed}:transaction-resource-admission`),
    resource_fence_digest: fenceDigest,
    lease_ref: lease.lease_id,
    lease_digest: lease.lease_digest,
    bootstrap_sequence_digest: digest("transaction-bootstrap-sequence"),
    compiler_manifest_digest: digest("transaction-compiler-manifest"),
    compiler_registry_digest: digest("transaction-compiler-registry"),
    requested_effects_digest: digest("transaction-requested-effects"),
    compiled_operation_digest: digest("transaction-compiled-operation"),
    compiled_command_digest: digest("transaction-compiled-command"),
    active_command_input_digest: digest("transaction-active-command-input"),
    cleanup_command_input_digest: digest("transaction-cleanup-command-input"),
    native_launch_ticket_digest: digest(`${seed}:transaction-native-launch-ticket`),
    worker_bundle_digest: digest("transaction-worker-bundle"),
    worker_launch_digest: digest(`${seed}:transaction-worker-launch`),
    worker_fence_digest: digest(`${seed}:transaction-worker-fence`),
    transport_binding_digest: digest("transaction-transport-binding"),
    vault_ingest_capability_digest: digest(`${seed}:transaction-vault-ingest-capability`),
    artifact_allocation_digest: digest(`${seed}:transaction-artifact-allocation`),
    safety_plan_digest: digest("transaction-safety-plan"),
    cleanup_plan_digest: journal.cleanup_plan_digest,
    clock_identity_digest: digest("transaction-clock-identity"),
    deadline_binding_digest: digest("transaction-deadline-binding"),
    vault_reservation_ref: `vault-reservation:${digest(seed).slice(0, 32)}`,
    vault_reservation_digest: digest(`${seed}:transaction-vault-reservation`),
    restoration_plan_digest: digest("transaction-restoration-plan"),
    terminal_projection_plan_digest: digest("transaction-terminal-projection-plan"),
    ...overrides,
  };
}

function transactionRead(transaction) {
  return {
    version: 1,
    kind: "physical_execution_transaction_durable_read",
    transaction_ref: transaction.transaction_ref,
    execution_lineage_digest: transaction.execution_lineage_digest,
    transaction_key_digest: transaction.transaction_key_digest,
    composite_binding_digest: transaction.composite_binding_digest,
  };
}

function transactionVaultFact(transaction, binding, overrides = {}) {
  return {
    version: 1,
    kind: "physical_execution_transaction_vault_commit",
    transaction_ref: transaction.transaction_ref,
    execution_lineage_digest: transaction.execution_lineage_digest,
    transaction_key_digest: transaction.transaction_key_digest,
    composite_binding_digest: transaction.composite_binding_digest,
    effect_evidence_digest: digest("transaction-native-effect-evidence"),
    effect_disposition: "recorded",
    semantic_disposition: "validated_success",
    vault_artifact_ref: "artifact:lease-store-runtime-1",
    vault_receipt_digest: digest("transaction-vault-receipt"),
    vault_reservation_ref: binding.vault_reservation_ref,
    vault_reservation_digest: binding.vault_reservation_digest,
    ...overrides,
  };
}

function claimTransaction(store, f) {
  const held = store.acquireLease(f.lease);
  store.appendJournal(f.journal);
  const admitted = nextJournal(f.journal, "admitted", "prepared", "not_dispatched", 120);
  store.appendJournal(admitted);
  const port = createDurablePhysicalExecutionTransactionPort(store);
  const binding = transactionBinding(f, held, admitted);
  const claim = port.claim(binding);
  return { admitted, binding, claim, held, port };
}

function armClaimedTransaction(store, f, claimed) {
  const starting = nextJournal(
    claimed.admitted,
    "effect_starting",
    "prepared",
    "not_dispatched",
    130,
  );
  store.appendJournal(starting);
  const dispatch = normalizeEffectDispatchRecord({
    version: 1,
    dispatch_event_ref: `dispatch-event:transaction-${digest(starting.attempt_ref).slice(0, 32)}`,
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
    provider_request_digest: starting.provider_request_digest,
    provider_sequence: starting.provider_sequence,
    dispatched_at: "2026-07-18T00:00:00.132Z",
  }, starting);
  const committed = store.commitDispatch(dispatch);
  const providerPort = createDurableInstrumentProviderDispatchPort(store, providerEnrollment(f, {
    instrument_refs: [starting.instrument_ref],
  }));
  const permit = providerPort.redeem(
    committed.dispatch_credential,
    providerExpected(starting),
  );
  return { committed, dispatch, permit, providerPort, starting };
}

function secondaryLeaseJournal(f, suffix) {
  const lease = {
    ...f.lease,
    lease_id: `lease-ph-s7-${suffix}`,
    instrument_ref: `instrument:owned-reader-${suffix}`,
    attempt_ref: `attempt:${suffix}`,
    execution_request_digest: digest(`${suffix}:execution-request`),
    resource_bundle_digest: digest(`${suffix}:resource-bundle`),
    fencing_token: `fence-${suffix}`,
  };
  const journalInput = {
    ...f.journal,
    journal_entry_ref: `journal-entry:${suffix}-0`,
    attempt_ref: lease.attempt_ref,
    instrument_ref: lease.instrument_ref,
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    execution_request_digest: lease.execution_request_digest,
    experiment_plan_hash: digest(`${suffix}:experiment-plan`),
    execution_lineage_digest: digest(`${suffix}:execution-lineage`),
    authority_resolution_digest: digest(`${suffix}:authority-resolution`),
    signed_grant_digest: digest(`${suffix}:signed-grant`),
    replay_claim_digest: digest(`${suffix}:grant-replay-claim`),
    replay_reservation_receipt_digest: digest(`${suffix}:grant-replay-reservation`),
    provider_request_digest: digest(`${suffix}:provider-request`),
    cleanup_capability_digest: digest(`${suffix}:cleanup-capability`),
    cleanup_plan_digest: digest(`${suffix}:cleanup-plan`),
    workspace_snapshot_ref: `workspace-snapshot:${suffix}`,
    workspace_snapshot_digest: digest(`${suffix}:workspace-snapshot`),
    stop_contract_digest: digest(`${suffix}:stop-contract`),
  };
  delete journalInput.journal_entry_digest;
  return { lease, journal: normalizeAttemptJournalEntry(journalInput) };
}

function safetySupervisorContract(f, overrides = {}) {
  return normalizeSafetySupervisorContract({
    version: 1,
    supervisor_ref: "safety-supervisor:lease-store-runtime-1",
    supervisor_principal_id: "principal:safety-supervisor-runtime-1",
    supervisor_signer_key_id: "supervisor-signer-key-runtime-1",
    trust_root_epoch: 3,
    safety_root_ref: "safety-root:lease-store-runtime-1",
    attempt_ref: f.lease.attempt_ref,
    instrument_ref: f.lease.instrument_ref,
    lease_id: f.lease.lease_id,
    fencing_token: f.lease.fencing_token,
    fencing_generation: f.lease.fencing_generation,
    operation_id: f.lease.operation_id,
    execution_request_digest: f.lease.execution_request_digest,
    worker_principal_id: f.lease.execution_principal_id,
    worker_heartbeat_signer_key_id: "worker-heartbeat-key-runtime-1",
    cleanup_capability_digest: digest("cleanup-capability-runtime-1"),
    authority_epoch: 7,
    revocation_generation: 2,
    heartbeat_interval_ms: 1000,
    miss_tolerance: 3,
    stop_ack_deadline_ms: 2000,
    containment_mode: "electronic",
    containment_actions: ["rf_interlock", "worker_kill"],
    operator_containment_plan_digest: null,
    ...overrides,
  });
}

function fenceForSafety(store, f) {
  const held = store.snapshot().leases[0];
  const fencedAt = "2026-07-18T00:00:00.400Z";
  f.clock.set(fencedAt);
  return store.fenceLease({
    version: 1,
    lease_id: held.lease_id,
    instrument_ref: held.instrument_ref,
    owner_principal_id: held.owner_principal_id,
    execution_principal_id: held.execution_principal_id,
    fencing_token: held.fencing_token,
    fencing_generation: held.fencing_generation,
    expected_sequence: held.sequence,
    fenced_at: fencedAt,
    reason: "worker_exit",
  });
}

function enrollAndFence(store, f, overrides = {}) {
  const contract = safetySupervisorContract(f, overrides);
  store.registerSafetySupervisor(contract);
  const fenced = fenceForSafety(store, f);
  return { contract, fenced };
}

function claimContainment(store, contract, fenced, action) {
  return store.claimContainmentAction({
    version: 1,
    supervisor_contract_digest: contract.supervisor_contract_digest,
    action,
    fenced_lease_digest: fenced.lease_digest,
  });
}

function confirmContainment(store, claim, label) {
  return store.completeContainmentAction({
    version: 1,
    claim_digest: claim.state.claim_digest,
    outcome: "confirmed",
    receipt_digest: digest(label),
  });
}

test("durable store and broker-port brands reject shape-compatible impostors", (t) => {
  assert.equal(durableStoreCompatibilityModule, durableStoreCanonicalModule);
  const f = fixture(t);
  const store = f.open();
  assert.equal(assertDurableInstrumentLeaseStore(store), store);
  assert.equal(durableStoreCanonicalModule.assertDurableInstrumentLeaseStore(store), store);
  assert.throws(
    () => assertDurableInstrumentLeaseStore({}),
    /created by Bob's durable store factory/,
  );
  const frozenStoreClone = Object.freeze(Object.fromEntries(
    Object.entries(store).map(([name, method]) => [name, method]),
  ));
  assert.throws(
    () => assertDurableInstrumentLeaseStore(frozenStoreClone),
    /created by Bob's durable store factory/,
  );
  assert.throws(
    () => createDurableInstrumentLeaseBrokerPort(frozenStoreClone),
    /created by Bob's durable store factory/,
  );

  const port = createDurableInstrumentLeaseBrokerPort(store);
  assert.equal(assertDurableInstrumentLeaseBrokerPort(port), port);
  assert.equal(durableStoreCanonicalModule.assertDurableInstrumentLeaseBrokerPort(port), port);
  assert.equal(Object.isFrozen(port), true);
  assert.deepEqual(
    Object.keys(port).sort(),
    ["appendJournal", "commitDispatch", "snapshot"],
  );
  assert.equal(port.acquireLease, undefined);
  assert.equal(port.close, undefined);
  assert.equal(port.fenceLease, undefined);

  assert.throws(
    () => assertDurableInstrumentLeaseBrokerPort({}),
    /must attenuate a Bob durable store/,
  );
  const frozenPortClone = Object.freeze({
    appendJournal: port.appendJournal,
    commitDispatch: port.commitDispatch,
    snapshot: port.snapshot,
  });
  assert.throws(
    () => assertDurableInstrumentLeaseBrokerPort(frozenPortClone),
    /must attenuate a Bob durable store/,
  );
  const providerPort = createDurableInstrumentProviderDispatchPort(
    store,
    providerEnrollment(f),
  );
  assert.equal(assertDurableInstrumentProviderDispatchPort(providerPort), providerPort);
  assert.equal(Object.isFrozen(providerPort), true);
  assert.deepEqual(Object.keys(providerPort).sort(), ["consumeEffect", "redeem"]);
  assert.throws(
    () => assertDurableInstrumentProviderDispatchPort({
      consumeEffect: providerPort.consumeEffect,
      redeem: providerPort.redeem,
    }),
    /must be enrolled by a Bob durable store/,
  );
  assert.throws(
    () => createDurableInstrumentProviderDispatchPort(frozenStoreClone, providerEnrollment(f)),
    /created by Bob's durable store factory/,
  );
  const transactionPort = createDurablePhysicalExecutionTransactionPort(store);
  assert.equal(assertDurablePhysicalExecutionTransactionPort(transactionPort), transactionPort);
  assert.equal(Object.isFrozen(transactionPort), true);
  assert.deepEqual(Object.keys(transactionPort).sort(), ["claim", "commitVault", "read"]);
  assert.throws(
    () => assertDurablePhysicalExecutionTransactionPort(Object.freeze({
      claim: transactionPort.claim,
      commitVault: transactionPort.commitVault,
      read: transactionPort.read,
    })),
    /must attenuate a Bob durable store/,
  );
  assert.throws(
    () => createDurablePhysicalExecutionTransactionPort(frozenStoreClone),
    /created by Bob's durable store factory/,
  );
  const { authority_port: omittedAuthority, ...missingAuthorityEnrollment } = providerEnrollment(f);
  void omittedAuthority;
  assert.throws(
    () => createDurableInstrumentProviderDispatchPort(store, missingAuthorityEnrollment),
    /is missing fields: authority_port/,
  );
  const clonedAuthorityEnrollment = providerEnrollment(f);
  clonedAuthorityEnrollment.authority_port = structuredClone(
    clonedAuthorityEnrollment.authority_port,
  );
  assert.throws(
    () => createDurableInstrumentProviderDispatchPort(store, clonedAuthorityEnrollment),
    /must be created by Bob's authority factory/,
  );
  store.close();
});

test("transaction schema v2 activation survives a lost acknowledgement and creates a downgrade barrier", (t) => {
  const f = boundedFixture(t);
  let store = f.open();
  assert.equal(INSTRUMENT_LEASE_CHECKPOINT_PROJECTION_SCHEMA_VERSION, 2);
  assert.equal(f.checkpointAnchor.state.projection_schema_version, 1);
  const held = store.acquireLease(f.lease);
  store.appendJournal(f.journal);
  const admitted = nextJournal(f.journal, "admitted", "prepared", "not_dispatched", 120);
  store.appendJournal(admitted);
  const binding = transactionBinding(f, held, admitted);
  const port = createDurablePhysicalExecutionTransactionPort(store);
  f.anchor.armAmbiguousCommit();
  assert.throws(
    () => port.claim(binding),
    (error) => /commit outcome is ambiguous/.test(error.message),
  );
  assert.equal(f.anchor.state.minimum_reader_schema_version, 2);
  const readback = port.claim(binding);
  assert.equal(readback.already_committed, true);
  assert.equal(readback.transaction.ledger_state, "CLAIMED");
  assert.equal(readback.transaction.authoritative_phase, null);
  assert.equal(readback.transaction.provider_effect_execution_permitted, false);
  assert.equal(port.read(transactionRead(readback.transaction)).projection_digest,
    readback.transaction.projection_digest);
  assert.throws(() => port.claim(), /requires one binding/);
  assert.throws(() => port.read(transactionRead(readback.transaction), null), /requires one query/);
  store.checkpointNow();
  assert.equal(f.checkpointAnchor.state.projection_schema_version, 2);
  const expected = store.snapshot();
  store.close();

  store = f.open();
  assert.deepEqual(store.snapshot(), expected);
  store.close();

  const v2Anchor = clone(f.anchor.state);
  const downgraded = clone(v2Anchor);
  delete downgraded.minimum_reader_schema_version;
  f.anchor.state = downgraded;
  assert.throws(() => f.open(), /reader schema|external event anchor|bounded checkpoint tail/);
  f.anchor.state = v2Anchor;
});

test("a schema-v1 checkpoint cold-replays a v2 tail before publishing its downgrade barrier", (t) => {
  const f = boundedFixture(t);
  let store = f.open();
  const held = store.acquireLease(f.lease);
  store.appendJournal(f.journal);
  const admitted = nextJournal(f.journal, "admitted", "prepared", "not_dispatched", 120);
  store.appendJournal(admitted);
  store.checkpointNow();
  assert.equal(f.checkpointAnchor.state.projection_schema_version, 1);

  const port = createDurablePhysicalExecutionTransactionPort(store);
  const binding = transactionBinding(f, held, admitted);
  const claimed = port.claim(binding);
  assert.equal(f.anchor.state.minimum_reader_schema_version, 2);
  assert.equal(f.checkpointAnchor.state.projection_schema_version, 1);
  const expected = claimed.transaction;
  store.close();

  store = f.open();
  const replayedPort = createDurablePhysicalExecutionTransactionPort(store);
  assert.deepEqual(replayedPort.read(transactionRead(expected)), expected);
  assert.equal(f.checkpointAnchor.state.projection_schema_version, 1);
  store.checkpointNow();
  assert.equal(f.checkpointAnchor.state.projection_schema_version, 2);
  store.close();

  store = f.open();
  assert.deepEqual(
    createDurablePhysicalExecutionTransactionPort(store).read(transactionRead(expected)),
    expected,
  );
  store.close();
  const anchoredV2 = clone(f.anchor.state);
  const downgraded = clone(anchoredV2);
  delete downgraded.minimum_reader_schema_version;
  f.anchor.state = downgraded;
  assert.throws(() => f.open(), /reader schema|external event anchor|bounded checkpoint tail/);
  f.anchor.state = anchoredV2;
});

test("an active legacy dispatch blocks first transaction-schema activation", (t) => {
  const f = fixture(t);
  const store = f.open();
  const legacy = prepareEffect(store, f);
  store.commitDispatch(legacy.dispatch);
  const second = secondaryLeaseJournal(f, "transaction-legacy-activation-blocked");
  const held = store.acquireLease(second.lease);
  store.appendJournal(second.journal);
  const admitted = nextJournal(second.journal, "admitted", "prepared", "not_dispatched", 120);
  store.appendJournal(admitted);
  const generation = store.snapshot().generation;
  assert.throws(
    () => createDurablePhysicalExecutionTransactionPort(store)
      .claim(transactionBinding(f, held, admitted)),
    /cannot activate over an active legacy effect/,
  );
  assert.equal(store.snapshot().generation, generation);
  assert.equal(store.snapshot().projection_schema_version, 1);
  assert.equal(Object.prototype.hasOwnProperty.call(f.anchor.state, "minimum_reader_schema_version"), false);
  store.close();
});

test("vault commit lost acknowledgement reconciles exactly and rejects a retry fork", (t) => {
  const f = fixture(t);
  let store = f.open();
  const claimed = claimTransaction(store, f);
  armClaimedTransaction(store, f, claimed);
  const fact = transactionVaultFact(claimed.claim.transaction, claimed.binding);
  f.anchor.armAmbiguousCommit();
  assert.throws(
    () => claimed.port.commitVault(fact),
    /commit outcome is ambiguous/,
  );
  const exact = claimed.port.commitVault(fact);
  assert.equal(exact.already_committed, true);
  const generation = store.snapshot().generation;
  assert.throws(
    () => claimed.port.commitVault({
      ...fact,
      vault_artifact_ref: "artifact:lease-store-runtime-fork",
      vault_receipt_digest: digest("transaction-vault-receipt-fork"),
    }),
    /vault custody is one-shot/,
  );
  assert.equal(store.snapshot().generation, generation);
  const expected = claimed.port.read(transactionRead(claimed.claim.transaction));
  store.close();
  store = f.open();
  assert.deepEqual(
    createDurablePhysicalExecutionTransactionPort(store)
      .read(transactionRead(claimed.claim.transaction)),
    expected,
  );
  store.close();
});

test("transaction vault/effect facts join in either order without authorizing GO, arm, or retry", async (t) => {
  await t.test("vault fact first", (st) => {
    const f = boundedFixture(st);
    let store = f.open();
    const claimed = claimTransaction(store, f);
    const armed = armClaimedTransaction(store, f, claimed);
    assert.equal(
      claimed.port.read(transactionRead(claimed.claim.transaction)).ledger_state,
      "DISPATCH_REDEEMED_NONAUTHORITATIVE_ARM_CANDIDATE",
    );
    const committed = claimed.port.commitVault(
      transactionVaultFact(claimed.claim.transaction, claimed.binding),
    );
    assert.equal(committed.transaction.ledger_state, "VAULT_FACT_PENDING_EFFECT");
    const running = nextJournal(armed.starting, "running", "dispatched", "ambiguous", 140);
    store.appendJournal(running);
    const recorded = nextJournal(running, "effect_recorded", "acknowledged", "confirmed_effect", 150);
    store.appendJournal(recorded);
    const joined = claimed.port.read(transactionRead(claimed.claim.transaction));
    assert.equal(joined.ledger_state, "EFFECT_AND_VAULT_COMMITTED");
    assert.equal(joined.automatic_effect_retry_permitted, false);
    assert.equal(joined.authoritative_phase, null);
    store.checkpointNow();
    const expected = store.snapshot();
    store.close();
    store = f.open();
    assert.deepEqual(store.snapshot(), expected);
    assert.equal(
      createDurablePhysicalExecutionTransactionPort(store)
        .read(transactionRead(claimed.claim.transaction)).ledger_state,
      "EFFECT_AND_VAULT_COMMITTED",
    );
    store.close();
  });

  await t.test("effect fact first and ambiguous evidence remains nonsemantic", (st) => {
    const f = fixture(st);
    const store = f.open();
    const claimed = claimTransaction(store, f);
    const armed = armClaimedTransaction(store, f, claimed);
    const running = nextJournal(armed.starting, "running", "dispatched", "ambiguous", 140);
    store.appendJournal(running);
    const ambiguous = nextJournal(
      running,
      "ambiguous_effect",
      "ambiguous_effect",
      "ambiguous",
      150,
    );
    store.appendJournal(ambiguous);
    assert.equal(
      claimed.port.read(transactionRead(claimed.claim.transaction)).ledger_state,
      "EFFECT_FACT_PENDING_VAULT",
    );
    const generation = store.snapshot().generation;
    assert.throws(
      () => claimed.port.commitVault(transactionVaultFact(
        claimed.claim.transaction,
        claimed.binding,
        { effect_disposition: "ambiguous", semantic_disposition: "validated_success" },
      )),
      /cannot promote an ambiguous effect/,
    );
    assert.equal(store.snapshot().generation, generation);
    const committed = claimed.port.commitVault(transactionVaultFact(
      claimed.claim.transaction,
      claimed.binding,
      { effect_disposition: "ambiguous", semantic_disposition: "nonsemantic_raw_custody" },
    ));
    assert.equal(committed.transaction.ledger_state, "EFFECT_AND_VAULT_COMMITTED");
    assert.equal(committed.transaction.semantic_disposition, "nonsemantic_raw_custody");
    const exact = claimed.port.commitVault(transactionVaultFact(
      claimed.claim.transaction,
      claimed.binding,
      { effect_disposition: "ambiguous", semantic_disposition: "nonsemantic_raw_custody" },
    ));
    assert.equal(exact.already_committed, true);
    assert.equal(exact.transaction.projection_digest, committed.transaction.projection_digest);
    store.close();
  });
});

test("transaction activation refuses unclaimed dispatches and public projections redact private bindings", (t) => {
  const f = fixture(t);
  const store = f.open();
  const claimed = claimTransaction(store, f);
  const second = secondaryLeaseJournal(f, "transaction-unclaimed-2");
  store.acquireLease(second.lease);
  store.appendJournal(second.journal);
  const admitted = nextJournal(second.journal, "admitted", "prepared", "not_dispatched", 120);
  store.appendJournal(admitted);
  const starting = nextJournal(admitted, "effect_starting", "prepared", "not_dispatched", 130);
  store.appendJournal(starting);
  const dispatch = normalizeEffectDispatchRecord({
    version: 1,
    dispatch_event_ref: "dispatch-event:transaction-unclaimed-2",
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
    provider_request_digest: starting.provider_request_digest,
    provider_sequence: starting.provider_sequence,
    dispatched_at: "2026-07-18T00:00:00.132Z",
  }, starting);
  const generation = store.snapshot().generation;
  assert.throws(
    () => store.commitDispatch(dispatch),
    /schema-v2 effect dispatch requires a durable execution transaction claim/,
  );
  assert.equal(store.snapshot().generation, generation);

  const serialized = JSON.stringify(store.snapshot());
  for (const privateValue of [
    claimed.binding.native_launch_ticket_digest,
    claimed.binding.worker_bundle_digest,
    claimed.binding.worker_launch_digest,
    claimed.binding.vault_ingest_capability_digest,
    claimed.binding.vault_reservation_ref,
    claimed.binding.vault_reservation_digest,
  ]) {
    assert.equal(serialized.includes(privateValue), false);
  }
  const eventBytes = fs.readFileSync(
    path.join(f.root, "events", "000000000004.event.json"),
    "utf8",
  );
  assert.equal(eventBytes.includes(claimed.binding.native_launch_ticket_digest), false);
  assert.equal(eventBytes.includes(claimed.binding.vault_reservation_ref), false);
  store.close();
});

test("transaction claims reject reuse of every caller-independent single-use alias", (t) => {
  const f = fixture(t);
  const store = f.open();
  const first = claimTransaction(store, f);
  const aliases = [
    "replay_identity_digest",
    "authority_admission_digest",
    "commit_go_digest",
    "dispatch_admission_digest",
    "provider_worker_vault_binding_digest",
    "transaction_capability_digest",
    "resource_admission_digest",
    "native_launch_ticket_digest",
    "worker_launch_digest",
    "worker_fence_digest",
    "vault_ingest_capability_digest",
    "artifact_allocation_digest",
    "vault_reservation_ref",
    "vault_reservation_digest",
  ];
  for (const [index, field] of aliases.entries()) {
    const second = secondaryLeaseJournal(f, `transaction-alias-${index}`);
    const held = store.acquireLease(second.lease);
    store.appendJournal(second.journal);
    const admitted = nextJournal(second.journal, "admitted", "prepared", "not_dispatched", 120);
    store.appendJournal(admitted);
    const candidate = transactionBinding(f, held, admitted, {
      [field]: first.binding[field],
    });
    const generation = store.snapshot().generation;
    assert.throws(
      () => first.port.claim(candidate),
      new RegExp(`reuses ${field}`),
      field,
    );
    assert.equal(store.snapshot().generation, generation, field);
  }
  assert.equal(store.snapshot().execution_transactions.length, 1);
  store.close();
});

test("transaction vault artifact and receipt identities are globally one-shot", (t) => {
  const f = fixture(t);
  const store = f.open();
  const first = claimTransaction(store, f);
  armClaimedTransaction(store, f, first);

  const secondFixture = secondaryLeaseJournal(f, "transaction-vault-alias-2");
  const secondHeld = store.acquireLease(secondFixture.lease);
  store.appendJournal(secondFixture.journal);
  const secondAdmitted = nextJournal(
    secondFixture.journal,
    "admitted",
    "prepared",
    "not_dispatched",
    120,
  );
  store.appendJournal(secondAdmitted);
  const secondBinding = transactionBinding(f, secondHeld, secondAdmitted);
  const secondClaim = first.port.claim(secondBinding);
  const second = {
    admitted: secondAdmitted,
    binding: secondBinding,
    claim: secondClaim,
    held: secondHeld,
    port: first.port,
  };
  armClaimedTransaction(store, f, second);

  const firstFact = transactionVaultFact(first.claim.transaction, first.binding);
  first.port.commitVault(firstFact);
  const generation = store.snapshot().generation;
  assert.throws(
    () => second.port.commitVault(transactionVaultFact(
      second.claim.transaction,
      second.binding,
      {
        vault_artifact_ref: firstFact.vault_artifact_ref,
        vault_receipt_digest: digest("transaction-vault-alias-unique-receipt"),
      },
    )),
    /reuses vault_artifact_ref/,
  );
  assert.equal(store.snapshot().generation, generation);
  assert.throws(
    () => second.port.commitVault(transactionVaultFact(
      second.claim.transaction,
      second.binding,
      {
        vault_artifact_ref: "artifact:lease-store-runtime-2",
        vault_receipt_digest: firstFact.vault_receipt_digest,
      },
    )),
    /reuses vault_receipt_digest/,
  );
  assert.equal(store.snapshot().generation, generation);
  store.close();
});

test("transaction inputs reject inherited/accessor/proxy data and ignore ambient regex/hash patches", (t) => {
  const f = fixture(t);
  let store = f.open();
  const claimed = claimTransaction(store, f);
  armClaimedTransaction(store, f, claimed);
  const query = transactionRead(claimed.claim.transaction);
  const fact = transactionVaultFact(claimed.claim.transaction, claimed.binding);

  let getterCalls = 0;
  const accessorQuery = { ...query };
  Object.defineProperty(accessorQuery, "transaction_ref", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return query.transaction_ref;
    },
  });
  assert.throws(() => claimed.port.read(accessorQuery), /enumerable data property/);
  assert.equal(getterCalls, 0);

  let proxyTraps = 0;
  const proxyQuery = new Proxy(query, {
    get(target, field, receiver) {
      proxyTraps += 1;
      return Reflect.get(target, field, receiver);
    },
    getPrototypeOf(target) {
      proxyTraps += 1;
      return Reflect.getPrototypeOf(target);
    },
    ownKeys(target) {
      proxyTraps += 1;
      return Reflect.ownKeys(target);
    },
  });
  assert.throws(() => claimed.port.read(proxyQuery), /must be an object/);
  assert.equal(proxyTraps, 0);

  let vaultGetterCalls = 0;
  const accessorFact = { ...fact };
  Object.defineProperty(accessorFact, "transaction_ref", {
    enumerable: true,
    get() {
      vaultGetterCalls += 1;
      return fact.transaction_ref;
    },
  });
  assert.throws(() => claimed.port.commitVault(accessorFact), /enumerable data property/);
  assert.equal(vaultGetterCalls, 0);

  let vaultProxyTraps = 0;
  const proxyFact = new Proxy(fact, {
    get(target, field, receiver) {
      vaultProxyTraps += 1;
      return Reflect.get(target, field, receiver);
    },
    getPrototypeOf(target) {
      vaultProxyTraps += 1;
      return Reflect.getPrototypeOf(target);
    },
    ownKeys(target) {
      vaultProxyTraps += 1;
      return Reflect.ownKeys(target);
    },
  });
  assert.throws(() => claimed.port.commitVault(proxyFact), /must be an object/);
  assert.equal(vaultProxyTraps, 0);

  const identityOnlyFact = {
    version: fact.version,
    kind: fact.kind,
    transaction_ref: fact.transaction_ref,
    execution_lineage_digest: fact.execution_lineage_digest,
    transaction_key_digest: fact.transaction_key_digest,
    composite_binding_digest: fact.composite_binding_digest,
  };
  const inheritedFields = [
    "effect_evidence_digest",
    "effect_disposition",
    "semantic_disposition",
    "vault_artifact_ref",
    "vault_receipt_digest",
    "vault_reservation_ref",
    "vault_reservation_digest",
  ];
  const inheritedDescriptors = new Map(inheritedFields.map((field) => [
    field,
    Object.getOwnPropertyDescriptor(Object.prototype, field),
  ]));
  const generationBeforeHostileInputs = store.snapshot().generation;
  try {
    for (const field of inheritedFields) {
      Object.defineProperty(Object.prototype, field, {
        configurable: true,
        enumerable: false,
        writable: true,
        value: fact[field],
      });
    }
    assert.throws(
      () => claimed.port.commitVault(identityOnlyFact),
      /is missing fields/,
    );
  } finally {
    for (const field of inheritedFields) {
      const descriptor = inheritedDescriptors.get(field);
      if (descriptor == null) delete Object.prototype[field];
      else Object.defineProperty(Object.prototype, field, descriptor);
    }
  }
  assert.equal(store.snapshot().generation, generationBeforeHostileInputs);

  const originalRegexpTest = RegExp.prototype.test;
  try {
    RegExp.prototype.test = () => true;
    assert.throws(
      () => claimed.port.commitVault({
        ...fact,
        effect_evidence_digest: "not-a-sha256",
        vault_receipt_digest: "also-not-a-sha256",
      }),
      /lowercase SHA-256 digest/,
    );
    assert.throws(
      () => claimed.port.commitVault({
        ...fact,
        vault_artifact_ref: "artifact:!!!invalid!!!",
      }),
      /namespaced opaque reference/,
    );
  } finally {
    RegExp.prototype.test = originalRegexpTest;
  }
  assert.equal(store.snapshot().generation, generationBeforeHostileInputs);

  const originalCreateHash = crypto.createHash;
  try {
    crypto.createHash = () => ({
      update() { return this; },
      digest() { return "0".repeat(64); },
    });
    const committed = claimed.port.commitVault(fact);
    assert.equal(committed.transaction.vault_receipt_digest, fact.vault_receipt_digest);
  } finally {
    crypto.createHash = originalCreateHash;
  }
  const expected = claimed.port.read(query);
  store.close();
  store = f.open();
  assert.deepEqual(
    createDurablePhysicalExecutionTransactionPort(store).read(query),
    expected,
  );
  store.close();
});

test("durable writes ignore ambient canonicalization and chronology poisoning", (t) => {
  const f = fixture(t);
  let store = f.open();

  const originalRegexpTest = RegExp.prototype.test;
  let invalidFenceError;
  try {
    RegExp.prototype.test = () => true;
    assert.throws(
      () => store.acquireLease({
        ...f.lease,
        fencing_token: "!!!invalid-fence!!!",
      }),
      (error) => {
        invalidFenceError = error;
        return true;
      },
    );
  } finally {
    RegExp.prototype.test = originalRegexpTest;
  }
  assert.match(invalidFenceError.message, /bounded opaque token/);
  assert.equal(store.snapshot().generation, 0);

  const originalDateParseForLease = Date.parse;
  try {
    Date.parse = (value) => (value === "2026-07-18T00:00:00.040Z"
      ? originalDateParseForLease("2026-07-18T00:00:00.051Z")
      : originalDateParseForLease(value));
    assert.throws(
      () => store.acquireLease({
        ...f.lease,
        effect_not_before: "2026-07-18T00:00:00.050Z",
        effect_deadline: "2026-07-18T00:00:00.040Z",
      }),
      /effect window is not in required chronological order/,
    );
  } finally {
    Date.parse = originalDateParseForLease;
  }
  assert.equal(store.snapshot().generation, 0);

  const originalArraySort = Array.prototype.sort;
  const originalArrayReverse = Array.prototype.reverse;
  const originalNumberIsFinite = Number.isFinite;
  const originalNumberIsSafeInteger = Number.isSafeInteger;
  try {
    Array.prototype.sort = function hostileSort(compare) {
      Reflect.apply(originalArraySort, this, compare == null ? [] : [compare]);
      return Reflect.apply(originalArrayReverse, this, []);
    };
    Number.isFinite = () => true;
    Number.isSafeInteger = () => true;
    store.acquireLease(f.lease);
  } finally {
    Array.prototype.sort = originalArraySort;
    Number.isFinite = originalNumberIsFinite;
    Number.isSafeInteger = originalNumberIsSafeInteger;
  }
  assert.equal(store.snapshot().generation, 1);
  store.close();
  store = f.open();
  assert.equal(store.snapshot().generation, 1);

  f.clock.set("2026-07-18T00:00:00.199Z");
  const originalDateParse = Date.parse;
  try {
    Date.parse = (value) => (value === "2026-07-18T00:00:00.199Z"
      ? originalDateParse("2026-07-18T00:00:00.999Z")
      : originalDateParse(value));
    assert.throws(
      () => store.appendJournal(f.journal),
      /event clock moved backwards/,
    );
  } finally {
    Date.parse = originalDateParse;
  }
  assert.equal(store.snapshot().generation, 1);
  store.close();
  store = f.open();
  assert.equal(store.snapshot().generation, 1);
  store.close();
});

test("transaction terminality and campaign closure require every attempt outbox acknowledgement", async (t) => {
  const f = fixture(t);
  let store = f.open();
  const claimed = claimTransaction(store, f);
  let brokerPort = createDurableInstrumentLeaseBrokerPort(store);
  assert.deepEqual(
    {
      transactions: readDurableInstrumentLeaseBrokerClosureState(brokerPort)
        .execution_transaction_count,
      nonterminal: readDurableInstrumentLeaseBrokerClosureState(brokerPort)
        .nonterminal_execution_transaction_count,
      active: readDurableInstrumentLeaseBrokerClosureState(brokerPort).active_effect_count,
    },
    { transactions: 1, nonterminal: 1, active: 1 },
  );

  const terminal = nextJournal(
    claimed.admitted,
    "reconciled_no_effect",
    "refused",
    "confirmed_no_effect",
    140,
  );
  store.appendJournal(terminal);
  const pending = normalizeDurableOutboxEntry({
    version: 1,
    outbox_entry_ref: "outbox-entry:transaction-pending-0",
    attempt_ref: terminal.attempt_ref,
    instrument_ref: terminal.instrument_ref,
    lease_id: terminal.lease_id,
    fencing_token: terminal.fencing_token,
    fencing_generation: terminal.fencing_generation,
    operation_id: terminal.operation_id,
    execution_request_digest: terminal.execution_request_digest,
    source_journal_entry_digest: terminal.journal_entry_digest,
    payload_kind: "provider_report",
    payload_ref: "provider-report:transaction-pending",
    payload_digest: digest("transaction-pending-outbox"),
    sequence: 0,
    previous_entry_digest: null,
    recorded_at: "2026-07-18T00:00:00.150Z",
    fsynced_at: "2026-07-18T00:00:00.151Z",
  });
  store.appendOutbox(pending);
  const terminalReceiptInput = {
    ...pending,
    outbox_entry_ref: "outbox-entry:transaction-terminal-1",
    payload_kind: "provider_report",
    payload_ref: "receipt:transaction-terminal",
    payload_digest: digest("transaction-terminal-receipt"),
    sequence: 1,
    previous_entry_digest: pending.outbox_entry_digest,
    recorded_at: "2026-07-18T00:00:00.160Z",
    fsynced_at: "2026-07-18T00:00:00.161Z",
  };
  delete terminalReceiptInput.outbox_entry_digest;
  const terminalReceipt = normalizeDurableOutboxEntry(terminalReceiptInput);
  const recipient = createIdempotentOutboxRecipientPort({
    recipientPrincipalId: f.lease.terminal_receipt_recipient_principal_id,
    idempotencyDomainDigest: f.lease.terminal_receipt_idempotency_domain_digest,
    deliverOnce: async (command) => ({
      version: 1,
      acknowledgement_ref: `outbox-ack:transaction-${command.outbox_entry.sequence}`,
      outbox_entry_ref: command.outbox_entry.outbox_entry_ref,
      outbox_entry_digest: command.outbox_entry.outbox_entry_digest,
      recipient_principal_id: f.lease.terminal_receipt_recipient_principal_id,
      acknowledged_at: command.outbox_entry.sequence === 0
        ? "2026-07-18T00:00:00.190Z"
        : "2026-07-18T00:00:00.180Z",
    }),
  });
  await store.deliverOutbox(terminalReceipt, recipient);
  const current = store.snapshot().leases[0];
  const release = {
    version: 1,
    lease_id: current.lease_id,
    instrument_ref: current.instrument_ref,
    owner_principal_id: current.owner_principal_id,
    execution_principal_id: current.execution_principal_id,
    fencing_token: current.fencing_token,
    fencing_generation: current.fencing_generation,
    expected_sequence: current.sequence,
    closed_at: "2026-07-18T00:00:00.400Z",
    terminal_disposition: "confirmed_no_effect",
    terminal_receipt_ref: terminalReceipt.payload_ref,
    terminal_receipt_digest: terminalReceipt.payload_digest,
  };
  f.clock.set("2026-07-18T00:00:00.500Z");
  assert.throws(
    () => store.releaseLease(release),
    /every durable attempt outbox entry to be acknowledged/,
  );
  let projected = claimed.port.read(transactionRead(claimed.claim.transaction));
  assert.equal(projected.ledger_state, "CLAIMED");
  assert.equal(projected.pending_outbox_count, 1);
  let closure = readDurableInstrumentLeaseBrokerClosureState(brokerPort);
  assert.equal(closure.pending_outbox_count, 1);
  assert.equal(closure.active_effect_count, 1);

  await store.deliverOutbox(pending, recipient);
  store.releaseLease(release);
  projected = claimed.port.read(transactionRead(claimed.claim.transaction));
  assert.equal(projected.ledger_state, "TERMINAL");
  assert.equal(projected.pending_outbox_count, 0);
  closure = readDurableInstrumentLeaseBrokerClosureState(brokerPort);
  assert.equal(closure.execution_transaction_count, 1);
  assert.equal(closure.nonterminal_execution_transaction_count, 0);
  assert.equal(closure.pending_outbox_count, 0);
  assert.equal(closure.active_effect_count, 0);
  store.close();

  store = f.open();
  brokerPort = createDurableInstrumentLeaseBrokerPort(store);
  closure = readDurableInstrumentLeaseBrokerClosureState(brokerPort);
  assert.equal(closure.execution_transaction_count, 1);
  assert.equal(closure.nonterminal_execution_transaction_count, 0);
  assert.equal(closure.pending_outbox_count, 0);
  assert.equal(closure.active_effect_count, 0);
  store.close();
});

test("post-redemption vault custody remains writable through the safety reserve", (t) => {
  const f = fixture(t);
  const checkpointAnchor = new MemoryCheckpointAnchor();
  const checkpointPort = createInstrumentLeaseCheckpointAnchorPort({
    portId: "transaction-vault-safety-reserve-v2",
    readState: () => checkpointAnchor.readState(),
    compareAndSet: (request) => checkpointAnchor.compareAndSet(request),
    maxCheckpointPlaintextBytes: 1024,
  });
  const store = f.open({
    checkpointMode: "bounded_checkpoint",
    checkpointPort,
  });
  const claimed = claimTransaction(store, f);
  const ordinary = secondaryLeaseJournal(f, "transaction-capacity-refused");
  const ordinaryHeld = store.acquireLease(ordinary.lease);
  store.appendJournal(ordinary.journal);
  const ordinaryAdmitted = nextJournal(
    ordinary.journal,
    "admitted",
    "prepared",
    "not_dispatched",
    120,
  );
  store.appendJournal(ordinaryAdmitted);
  const ordinaryBinding = transactionBinding(f, ordinaryHeld, ordinaryAdmitted);
  armClaimedTransaction(store, f, claimed);
  assert.equal(store.checkpointReadiness().checkpoint_capacity_state, "exhausted");
  assert.equal(store.checkpointReadiness().admission_mode, "safety_reserve_only");
  const before = store.snapshot().generation;
  const committed = claimed.port.commitVault(
    transactionVaultFact(claimed.claim.transaction, claimed.binding),
  );
  assert.equal(committed.transaction.ledger_state, "VAULT_FACT_PENDING_EFFECT");
  assert.equal(store.snapshot().generation, before + 1);
  assert.throws(
    () => claimed.port.claim(ordinaryBinding),
    (error) => error.checkpoint_capacity_outcome === "exhausted",
  );
  store.close();
});

test("the broker port rejects surplus or missing arguments before invoking hooks", (t) => {
  const f = fixture(t);
  const store = f.open();
  let hookCalls = 0;
  const hookContexts = [];
  const port = createDurableInstrumentLeaseBrokerPort(store, {
    before_call: (context) => { hookCalls += 1; hookContexts.push(context); },
    after_call: (context) => { hookCalls += 1; hookContexts.push(context); },
  });

  for (const invoke of [
    () => port.appendJournal(),
    () => port.appendJournal(f.journal, f.journal),
    () => port.commitDispatch(),
    () => port.commitDispatch({}, {}),
    () => port.snapshot(undefined),
    () => port.snapshot({}, {}),
  ]) {
    assert.throws(invoke, /received an invalid argument count/);
  }
  assert.equal(hookCalls, 0, "rejected calls do not enter the fault-injection hooks");
  assert.equal(port.snapshot().generation, 0);
  assert.equal(hookCalls, 2);
  assert.deepEqual(hookContexts, [
    { version: 1, method: "snapshot" },
    { version: 1, method: "snapshot" },
  ]);
  assert.doesNotMatch(
    JSON.stringify(hookContexts),
    /argument|result|fencing|credential|grant|lease|journal|dispatch/,
  );
  store.close();
});

test("the attenuated broker snapshot redacts every raw fence while owner state stays exact", (t) => {
  const f = fixture(t);
  const store = f.open();
  store.acquireLease(f.lease);
  store.registerSafetySupervisor(safetySupervisorContract(f));
  store.appendJournal(f.journal);
  const admitted = nextJournal(f.journal, "admitted", "prepared", "not_dispatched", 120);
  store.appendJournal(admitted);
  const starting = nextJournal(admitted, "effect_starting", "prepared", "not_dispatched", 130);
  store.appendJournal(starting);
  const dispatch = normalizeEffectDispatchRecord({
    version: 1,
    dispatch_event_ref: "dispatch-event:broker-snapshot-redaction",
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
    provider_request_digest: starting.provider_request_digest,
    provider_sequence: starting.provider_sequence,
    dispatched_at: "2026-07-18T00:00:00.132Z",
  }, starting);
  store.commitDispatch(dispatch);
  const outbox = normalizeDurableOutboxEntry({
    version: 1,
    outbox_entry_ref: "outbox-entry:broker-snapshot-redaction-0",
    attempt_ref: starting.attempt_ref,
    instrument_ref: starting.instrument_ref,
    lease_id: starting.lease_id,
    fencing_token: starting.fencing_token,
    fencing_generation: starting.fencing_generation,
    operation_id: starting.operation_id,
    execution_request_digest: starting.execution_request_digest,
    source_journal_entry_digest: starting.journal_entry_digest,
    payload_kind: "provider_report",
    payload_ref: "provider-report:broker-snapshot-redaction",
    payload_digest: digest("broker-snapshot-redaction-payload"),
    sequence: 0,
    previous_entry_digest: null,
    recorded_at: "2026-07-18T00:00:00.134Z",
    fsynced_at: "2026-07-18T00:00:00.135Z",
  });
  store.appendOutbox(outbox);

  const owner = store.snapshot();
  const broker = createDurableInstrumentLeaseBrokerPort(store).snapshot();
  for (const field of [
    "leases",
    "journal_heads",
    "dispatches",
    "outbox_heads",
    "outbox_entries",
    "safety_supervisor_contracts",
  ]) {
    assert.equal(owner[field][0].fencing_token, f.lease.fencing_token, field);
    assert.equal(Object.prototype.hasOwnProperty.call(broker[field][0], "fencing_token"), false, field);
  }
  assert.equal(broker.generation, owner.generation);
  assert.equal(broker.head_event_digest, owner.head_event_digest);
  assert.equal(broker.leases[0].lease_digest, owner.leases[0].lease_digest);
  assert.equal(
    broker.journal_heads[0].journal_entry_digest,
    owner.journal_heads[0].journal_entry_digest,
  );
  assert.equal(
    broker.dispatches[0].dispatch_record_digest,
    owner.dispatches[0].dispatch_record_digest,
  );
  const serialized = JSON.stringify(broker);
  assert.equal(serialized.includes(f.lease.fencing_token), false);
  assert.equal(serialized.includes("fencing_token"), false);
  store.close();
});

test("broker-port hooks cannot replace results and response loss preserves the durable mutation", (t) => {
  const f = fixture(t);
  let store = f.open();
  store.acquireLease(f.lease);

  const beforeOverride = createDurableInstrumentLeaseBrokerPort(store, {
    before_call: ({ method }) => (method === "appendJournal" ? { accepted: true } : undefined),
  });
  assert.throws(
    () => beforeOverride.appendJournal(f.journal),
    /before_call must return undefined/,
  );
  assert.deepEqual(store.snapshot().journal_heads, []);

  const afterOverride = createDurableInstrumentLeaseBrokerPort(store, {
    after_call: ({ method }) => (method === "snapshot" ? { generation: 999 } : undefined),
  });
  assert.throws(
    () => afterOverride.snapshot(),
    /after_call must return undefined/,
  );

  const responseLoss = createDurableInstrumentLeaseBrokerPort(store, {
    after_call: ({ method }) => {
      if (method === "appendJournal") throw new Error("injected broker response loss");
    },
  });
  assert.throws(
    () => responseLoss.appendJournal(f.journal),
    /injected broker response loss/,
  );
  assert.equal(
    store.snapshot().journal_heads[0].journal_entry_digest,
    f.journal.journal_entry_digest,
    "the underlying append commits before an after-call response is lost",
  );
  store.close();

  store = f.open();
  assert.equal(
    store.snapshot().journal_heads[0].journal_entry_digest,
    f.journal.journal_entry_digest,
    "the response-lost mutation remains observable after restart",
  );
  store.close();
});

test("the durable lease store encrypts state, anchors every mutation, and refuses concurrent ownership", (t) => {
  const f = fixture(t);
  const store = f.open();
  assert.equal(store.acknowledgeOutbox, undefined, "raw acknowledgement mutation is not public");
  const acquired = store.acquireLease(f.lease);
  assert.equal(acquired.lease_id, f.lease.lease_id);
  assert.equal(f.anchor.state.generation, 1);

  const conflict = {
    ...f.lease,
    lease_id: "lease-ph-s7-runtime-2",
    attempt_ref: "attempt:physical-runtime-2",
    fencing_token: "fence-runtime-2",
    fencing_generation: 2,
  };
  assert.throws(() => store.acquireLease(conflict), /already bound by lease/);
  assert.throws(() => store.acquireLease({
    ...conflict,
    instrument_ref: "instrument:different-reader-runtime-2",
    fencing_generation: 1,
    attempt_ref: f.lease.attempt_ref,
  }), /attempt_ref has already been used/);
  assert.equal(store.snapshot().generation, 1, "a refused candidate does not grow the ledger");

  const eventPath = path.join(f.root, "events", "000000000001.event.json");
  const encoded = fs.readFileSync(eventPath, "utf8");
  assert.doesNotMatch(encoded, /owned-reader-runtime|lease-ph-s7-runtime|execution-request/);
  assert.equal(fs.statSync(eventPath).mode & 0o077, 0);
  store.close();
});

test("close is an idempotent terminal boundary and cannot publish zero-key events", (t) => {
  const f = fixture(t);
  const store = f.open();
  store.close();
  store.close();
  assert.throws(() => store.acquireLease(f.lease), /store is closed/);
  assert.throws(() => store.snapshot(), /store is closed/);
  assert.equal(f.anchor.state.generation, 0);
  assert.deepEqual(fs.readdirSync(path.join(f.root, "events")), []);

  const reopened = f.open();
  assert.equal(reopened.acquireLease(f.lease).state, "held");
  reopened.close();
});

test("dispatch intent is durably anchored, one-shot, and survives restart", (t) => {
  const f = fixture(t);
  const store = f.open();
  const { dispatch } = prepareEffect(store, f);
  const committed = store.commitDispatch(dispatch);
  assert.equal(f.anchor.state.generation, 5);
  assert.equal(committed.dispatch.dispatch_record_digest, dispatch.dispatch_record_digest);
  assert.equal(committed.already_committed, false);
  assert.equal(
    assertDurableProviderDispatchCredential(committed.dispatch_credential),
    committed.dispatch_credential,
  );
  assert.equal(Object.hasOwn(committed.dispatch_credential, "fencing_token"), false);
  assert.equal(Object.hasOwn(committed.dispatch_credential, "signed_grant_digest"), false);
  assert.equal(
    committed.dispatch_credential.experiment_plan_hash,
    f.journal.experiment_plan_hash,
  );
  assert.equal(
    committed.dispatch_credential.execution_lineage_digest,
    f.journal.execution_lineage_digest,
  );
  assert.equal(JSON.stringify(committed.dispatch_credential).includes(f.lease.fencing_token), false);
  const duplicate = store.commitDispatch(dispatch);
  assert.equal(duplicate.already_committed, true);
  assert.equal(duplicate.dispatch_credential, null, "an election replay never reissues authority");
  store.close();

  const reopened = f.open();
  assert.equal(reopened.snapshot().dispatches.length, 1);
  const recovered = reopened.commitDispatch(dispatch);
  assert.equal(recovered.already_committed, true);
  assert.equal(recovered.dispatch_credential, null, "restart never rehydrates authority");
  reopened.close();
});

test("dispatch refuses a journal without precommitted experiment and execution lineage", (t) => {
  const f = fixture(t);
  const legacyJournalInput = { ...f.journal };
  delete legacyJournalInput.experiment_plan_hash;
  delete legacyJournalInput.execution_lineage_digest;
  delete legacyJournalInput.journal_entry_digest;
  const legacy = {
    ...f,
    journal: normalizeAttemptJournalEntry(legacyJournalInput),
  };
  const store = f.open();
  const { dispatch } = prepareEffect(store, legacy);
  assert.throws(
    () => store.commitDispatch(dispatch),
    /requires precommitted execution lineage/,
  );
  assert.equal(store.snapshot().dispatches.length, 0);
  store.close();
});

test("hot projections avoid historical replay while authenticating the anchored head", (t) => {
  const f = fixture(t);
  const store = f.open();
  const { dispatch } = prepareEffect(store, f);
  store.commitDispatch(dispatch);
  assert.equal(store.snapshot().generation, 5);

  const originalOpenSync = fs.openSync;
  let eventReads = 0;
  fs.openSync = function countedOpenSync(filePath, flags, ...rest) {
    if (typeof filePath === "string"
        && /\/\d{12}\.event\.json$/.test(filePath)
        && (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR)) === 0) {
      eventReads += 1;
    }
    return originalOpenSync.call(this, filePath, flags, ...rest);
  };
  t.after(() => { fs.openSync = originalOpenSync; });
  assert.equal(store.snapshot().generation, 5);
  assert.equal(store.snapshot().generation, 5);
  assert.equal(eventReads, 2, "each hot read authenticates only the anchored head event");

  fs.openSync = originalOpenSync;
  const headPath = path.join(f.root, "events", "000000000005.event.json");
  fs.chmodSync(headPath, 0o600);
  fs.writeFileSync(headPath, "{\"forged\":true}\n", { mode: 0o600 });
  fs.chmodSync(headPath, 0o400);
  assert.throws(
    () => store.snapshot(),
    /bounded private regular file|authentication failed|invalid|unknown fields/,
  );
  store.close();
});

test("hot stores reconcile crash-left event publication siblings before every use", (t) => {
  const f = fixture(t);
  let store = f.open();
  store.acquireLease(f.lease);
  const eventsRoot = path.join(f.root, "events");
  const firstEventPath = path.join(eventsRoot, "000000000001.event.json");

  const linkedHeadSibling = path.join(
    eventsRoot,
    `.000000000001.event.json.pending-${process.pid}-${"a".repeat(24)}`,
  );
  fs.linkSync(firstEventPath, linkedHeadSibling);
  assert.equal(fs.statSync(firstEventPath).nlink, 2);
  assert.equal(store.readLease(f.lease.lease_id).lease_id, f.lease.lease_id);
  assert.equal(fs.existsSync(linkedHeadSibling), false, "linked published sibling is repaired hot");
  assert.equal(fs.statSync(firstEventPath).nlink, 1);

  const orphanNextSibling = path.join(
    eventsRoot,
    `.000000000002.event.json.pending-${process.pid}-${"b".repeat(24)}`,
  );
  fs.copyFileSync(firstEventPath, orphanNextSibling);
  fs.chmodSync(orphanNextSibling, 0o400);
  assert.equal(store.appendJournal(f.journal).journal_entry_digest, f.journal.journal_entry_digest);
  assert.equal(fs.existsSync(orphanNextSibling), false, "unpublished sibling is removed under lock");

  const conflictingSibling = path.join(
    eventsRoot,
    `.000000000002.event.json.pending-${process.pid}-${"c".repeat(24)}`,
  );
  fs.copyFileSync(firstEventPath, conflictingSibling);
  fs.chmodSync(conflictingSibling, 0o400);
  assert.throws(
    () => store.snapshot(),
    /conflicting publication sibling/,
    "a different inode beside an existing final is never guessed away",
  );
  fs.unlinkSync(conflictingSibling);
  assert.equal(store.snapshot().generation, 2);
  store.close();

  store = f.open();
  assert.equal(store.snapshot().generation, 2, "hot sibling repair leaves restart replayable");
  store.close();
});

test("an ambiguous dispatch anchor response reconciles without inventing a second dispatch", (t) => {
  const f = fixture(t);
  const store = f.open();
  const { dispatch } = prepareEffect(store, f);
  f.anchor.armAmbiguousCommit();
  assert.throws(() => store.commitDispatch(dispatch), /anchor commit outcome is ambiguous/);
  store.close();

  const recovered = f.open();
  assert.equal(recovered.snapshot().dispatches.length, 1);
  const replay = recovered.commitDispatch(dispatch);
  assert.equal(replay.already_committed, true);
  assert.equal(replay.dispatch_credential, null);
  recovered.close();
});

test("only the dispatch winner can redeem once and consume an opaque permit at a synchronous effect seam", (t) => {
  const f = fixture(t);
  const store = f.open();
  const { dispatch, starting } = prepareEffect(store, f);
  const committed = store.commitDispatch(dispatch);
  const credential = committed.dispatch_credential;
  const port = createDurableInstrumentProviderDispatchPort(store, providerEnrollment(f));
  const running = nextJournal(starting, "running", "dispatched", "ambiguous", 140);
  assert.throws(
    () => store.appendJournal(running),
    /requires a durable provider redemption/,
  );

  assert.throws(
    () => port.redeem(structuredClone(credential), providerExpected(starting)),
    /must be issued by a live Bob durable store/,
  );
  const permit = port.redeem(credential, providerExpected(starting));
  assert.deepEqual(Object.keys(permit), []);
  assert.equal(JSON.stringify(permit), "{}", "the effect permit has no serializable authority surface");
  assert.equal(store.snapshot().dispatch_redemptions.length, 1);
  assert.equal(f.anchor.state.generation, 6, "redemption is anchored before the effect callback");

  const siblingPort = createDurableInstrumentProviderDispatchPort(store, providerEnrollment(f));
  assert.throws(
    () => siblingPort.consumeEffect(permit, () => undefined),
    /was not issued to this provider dispatch port/,
  );
  assert.throws(
    () => port.consumeEffect(permit, async () => undefined),
    /cannot be async/,
  );
  let effects = 0;
  const result = port.consumeEffect(permit, () => {
    effects += 1;
    return "effect-written";
  });
  assert.equal(result, "effect-written");
  assert.equal(effects, 1);
  assert.throws(
    () => port.consumeEffect(permit, () => { effects += 1; }),
    /already been consumed/,
  );
  assert.throws(
    () => port.redeem(credential, providerExpected(starting)),
    /already been durably redeemed/,
  );
  assert.equal(effects, 1);
  assert.equal(store.appendJournal(running).state, "running");
  store.close();
});

test("provider redemption rejects cloned authority and every provider or prepared-state redirect", (t) => {
  const f = fixture(t);
  const store = f.open();
  const { dispatch, starting } = prepareEffect(store, f);
  const credential = store.commitDispatch(dispatch).dispatch_credential;

  for (const enrollment of [
    providerEnrollment(f, { provider_id: "redirected_store_provider" }),
    providerEnrollment(f, { provider_descriptor_digest: digest("redirected-provider-descriptor") }),
    providerEnrollment(f, { execution_principal_id: "principal:redirected-provider-worker" }),
    providerEnrollment(f, { instrument_refs: ["instrument:redirected-provider-device"] }),
  ]) {
    const port = createDurableInstrumentProviderDispatchPort(store, enrollment);
    assert.throws(
      () => port.redeem(credential, providerExpected(starting)),
      /binding drift|outside the enrolled provider port/,
    );
  }

  const port = createDurableInstrumentProviderDispatchPort(store, providerEnrollment(f));
  for (const expected of [
    providerExpected(starting, { attempt_ref: "attempt:redirected-provider-attempt" }),
    providerExpected(starting, { instrument_ref: "instrument:redirected-provider-device" }),
    providerExpected(starting, { operation_id: "representation.read" }),
    providerExpected(starting, { provider_id: "redirected_provider" }),
    providerExpected(starting, { provider_descriptor_digest: digest("redirected-provider") }),
    providerExpected(starting, { dispatch_journal_ref: "journal-entry:redirected-provider-dispatch" }),
    providerExpected(starting, { provider_request_digest: digest("redirected-provider-request") }),
    providerExpected(starting, { expected_sequence: starting.provider_sequence + 1 }),
  ]) {
    assert.throws(() => port.redeem(credential, expected), /binding drift/);
  }
  assert.throws(
    () => port.redeem(credential, providerExpected(starting, { expected_state: "created" })),
    /expected_state must be prepared/,
  );
  assert.equal(store.snapshot().dispatch_redemptions.length, 0);
  const permit = port.redeem(credential, providerExpected(starting));
  port.consumeEffect(permit, () => undefined);
  store.close();
});

test("fencing or deadline expiry between dispatch commit and provider redemption blocks the effect", (t) => {
  const fencedFixture = fixture(t);
  const fencedStore = fencedFixture.open();
  const { dispatch, starting } = prepareEffect(fencedStore, fencedFixture);
  const credential = fencedStore.commitDispatch(dispatch).dispatch_credential;
  const port = createDurableInstrumentProviderDispatchPort(
    fencedStore,
    providerEnrollment(fencedFixture),
  );
  const held = fencedStore.snapshot().leases[0];
  fencedFixture.clock.set("2026-07-18T00:00:00.400Z");
  fencedStore.fenceLease({
    version: 1,
    lease_id: held.lease_id,
    instrument_ref: held.instrument_ref,
    owner_principal_id: held.owner_principal_id,
    execution_principal_id: held.execution_principal_id,
    fencing_token: held.fencing_token,
    fencing_generation: held.fencing_generation,
    expected_sequence: held.sequence,
    fenced_at: "2026-07-18T00:00:00.400Z",
    reason: "revocation",
  });
  assert.throws(
    () => port.redeem(credential, providerExpected(starting)),
    /requires the current lease to remain held/,
  );
  assert.equal(fencedStore.snapshot().dispatch_redemptions.length, 0);
  fencedStore.close();

  const expiredFixture = fixture(t);
  const expiredStore = expiredFixture.open();
  const prepared = prepareEffect(expiredStore, expiredFixture);
  const expiredCredential = expiredStore.commitDispatch(prepared.dispatch).dispatch_credential;
  const expiredPort = createDurableInstrumentProviderDispatchPort(
    expiredStore,
    providerEnrollment(expiredFixture),
  );
  expiredFixture.clock.set(expiredFixture.lease.heartbeat_deadline);
  assert.throws(
    () => expiredPort.redeem(expiredCredential, providerExpected(prepared.starting)),
    /past the current lease heartbeat deadline/,
  );
  assert.equal(expiredStore.snapshot().dispatch_redemptions.length, 0);
  expiredStore.close();

  const authorityExpiredFixture = fixture(t);
  authorityExpiredFixture.lease.effect_deadline = "2026-07-18T00:00:01.000Z";
  authorityExpiredFixture.lease.heartbeat_deadline = "2026-07-18T00:00:02.000Z";
  authorityExpiredFixture.lease.expires_at = "2026-07-18T00:00:03.000Z";
  const authorityExpiredStore = authorityExpiredFixture.open();
  const authorityPrepared = prepareEffect(authorityExpiredStore, authorityExpiredFixture);
  const authorityCredential = authorityExpiredStore.commitDispatch(
    authorityPrepared.dispatch,
  ).dispatch_credential;
  const authorityPort = createDurableInstrumentProviderDispatchPort(
    authorityExpiredStore,
    providerEnrollment(authorityExpiredFixture),
  );
  authorityExpiredFixture.clock.set(authorityExpiredFixture.lease.effect_deadline);
  assert.throws(
    () => authorityPort.redeem(
      authorityCredential,
      providerExpected(authorityPrepared.starting),
    ),
    /past the immutable lease effect deadline/,
  );
  assert.equal(authorityExpiredStore.snapshot().dispatch_redemptions.length, 0);
  authorityExpiredStore.close();
});

test("permit consumption rechecks the live fence under the store lock before invoking the callback", (t) => {
  const f = fixture(t);
  const store = f.open();
  const { dispatch, starting } = prepareEffect(store, f);
  const credential = store.commitDispatch(dispatch).dispatch_credential;
  const port = createDurableInstrumentProviderDispatchPort(store, providerEnrollment(f));
  const permit = port.redeem(credential, providerExpected(starting));
  const held = store.snapshot().leases[0];
  f.clock.set("2026-07-18T00:00:00.400Z");
  store.fenceLease({
    version: 1,
    lease_id: held.lease_id,
    instrument_ref: held.instrument_ref,
    owner_principal_id: held.owner_principal_id,
    execution_principal_id: held.execution_principal_id,
    fencing_token: held.fencing_token,
    fencing_generation: held.fencing_generation,
    expected_sequence: held.sequence,
    fenced_at: "2026-07-18T00:00:00.400Z",
    reason: "revocation",
  });
  let effects = 0;
  assert.throws(
    () => port.consumeEffect(permit, () => { effects += 1; }),
    /requires the current lease to remain held/,
  );
  assert.equal(effects, 0);
  store.close();

  const deadlineFixture = fixture(t);
  deadlineFixture.lease.effect_deadline = "2026-07-18T00:00:01.000Z";
  deadlineFixture.lease.heartbeat_deadline = "2026-07-18T00:00:02.000Z";
  deadlineFixture.lease.expires_at = "2026-07-18T00:00:03.000Z";
  const deadlineStore = deadlineFixture.open();
  const deadlinePrepared = prepareEffect(deadlineStore, deadlineFixture);
  const deadlineCredential = deadlineStore.commitDispatch(
    deadlinePrepared.dispatch,
  ).dispatch_credential;
  const deadlinePort = createDurableInstrumentProviderDispatchPort(
    deadlineStore,
    providerEnrollment(deadlineFixture),
  );
  const deadlinePermit = deadlinePort.redeem(
    deadlineCredential,
    providerExpected(deadlinePrepared.starting),
  );
  deadlineFixture.clock.set(deadlineFixture.lease.effect_deadline);
  let lateEffects = 0;
  assert.throws(
    () => deadlinePort.consumeEffect(deadlinePermit, () => { lateEffects += 1; }),
    /past the immutable lease effect deadline/,
  );
  assert.equal(lateEffects, 0);
  deadlineStore.close();
});

test("restart and ambiguous redemption acknowledgement never recreate a credential or permit", (t) => {
  const f = fixture(t);
  let store = f.open();
  const { dispatch, starting } = prepareEffect(store, f);
  const credential = store.commitDispatch(dispatch).dispatch_credential;
  const oldPort = createDurableInstrumentProviderDispatchPort(store, providerEnrollment(f));
  store.close();

  store = f.open();
  const newPort = createDurableInstrumentProviderDispatchPort(store, providerEnrollment(f));
  assert.equal(store.commitDispatch(dispatch).dispatch_credential, null);
  assert.throws(
    () => newPort.redeem(credential, providerExpected(starting)),
    /not issued by this live durable store/,
  );
  assert.throws(
    () => oldPort.redeem(credential, providerExpected(starting)),
    /store is closed/,
  );
  store.close();

  const ambiguousFixture = fixture(t);
  store = ambiguousFixture.open();
  const ambiguousPrepared = prepareEffect(store, ambiguousFixture);
  const ambiguousCredential = store.commitDispatch(
    ambiguousPrepared.dispatch,
  ).dispatch_credential;
  const ambiguousPort = createDurableInstrumentProviderDispatchPort(
    store,
    providerEnrollment(ambiguousFixture),
  );
  ambiguousFixture.anchor.armAmbiguousCommit();
  assert.throws(
    () => ambiguousPort.redeem(
      ambiguousCredential,
      providerExpected(ambiguousPrepared.starting),
    ),
    /anchor commit outcome is ambiguous/,
  );
  store.close();
  store = ambiguousFixture.open();
  assert.equal(store.snapshot().dispatch_redemptions.length, 1);
  assert.equal(store.commitDispatch(ambiguousPrepared.dispatch).dispatch_credential, null);
  store.close();
});

test("a rejected anchor CAS is reported pending and never authorizes compensation", (t) => {
  const f = fixture(t);
  const store = f.open();
  f.anchor.armRejectedCommit();
  let failure;
  try {
    store.acquireLease(f.lease);
  } catch (error) {
    failure = error;
  }
  assert.ok(failure);
  assert.match(failure.message, /pending external anchor reconciliation/);
  assert.equal(failure.anchor_commit_outcome, "pending");
  assert.equal(f.anchor.state.generation, 0);
  assert.equal(fs.readdirSync(path.join(f.root, "events")).length, 1);

  const reconciled = store.snapshot();
  assert.equal(reconciled.generation, 1);
  assert.equal(f.anchor.state.generation, 1);
  assert.equal(store.acquireLease(f.lease).lease_id, f.lease.lease_id);
  store.close();
});

test("a fence or missed heartbeat closes durable dispatch admission", (t) => {
  const fencedFixture = fixture(t);
  const fencedStore = fencedFixture.open();
  const { dispatch: fencedDispatch } = prepareEffect(fencedStore, fencedFixture);
  const held = fencedStore.snapshot().leases[0];
  fencedFixture.clock.set("2026-07-18T00:00:00.400Z");
  fencedStore.fenceLease({
    version: 1,
    lease_id: held.lease_id,
    instrument_ref: held.instrument_ref,
    owner_principal_id: held.owner_principal_id,
    execution_principal_id: held.execution_principal_id,
    fencing_token: held.fencing_token,
    fencing_generation: held.fencing_generation,
    expected_sequence: held.sequence,
    fenced_at: "2026-07-18T00:00:00.400Z",
    reason: "revocation",
  });
  assert.throws(
    () => fencedStore.commitDispatch(fencedDispatch),
    /requires the current lease to remain held/,
  );
  assert.equal(fencedStore.snapshot().dispatches.length, 0);
  fencedStore.close();

  const expiredFixture = fixture(t);
  const expiredStore = expiredFixture.open();
  const { dispatch: expiredDispatch } = prepareEffect(expiredStore, expiredFixture);
  expiredFixture.clock.set("2026-07-18T00:00:06.000Z");
  assert.throws(
    () => expiredStore.commitDispatch(expiredDispatch),
    /past the current lease heartbeat deadline/,
  );
  assert.equal(expiredStore.snapshot().dispatches.length, 0);
  expiredStore.close();
});

test("safety-supervisor registration is idempotent and exactly bound to its lease", (t) => {
  const f = fixture(t);
  const store = f.open();
  store.acquireLease(f.lease);

  const detachedContracts = [
    { attempt_ref: "attempt:detached-runtime-1" },
    { instrument_ref: "instrument:detached-reader-runtime-1" },
    { lease_id: "lease-detached-runtime-1" },
    { fencing_token: "fence-detached-runtime-1" },
    { fencing_generation: 2 },
    { operation_id: "representation.read" },
    { execution_request_digest: digest("detached-execution-request") },
    { worker_principal_id: "principal:detached-worker-runtime-1" },
  ];
  for (const overrides of detachedContracts) {
    const detached = safetySupervisorContract(f, overrides);
    assert.throws(
      () => store.registerSafetySupervisor(detached),
      /binding drift|unknown lease/,
    );
  }
  assert.equal(f.anchor.state.generation, 1, "detached registrations publish no ledger event");

  const contract = safetySupervisorContract(f);
  const registered = store.registerSafetySupervisor(contract);
  assert.equal(registered.supervisor_contract_digest, contract.supervisor_contract_digest);
  assert.equal(f.anchor.state.generation, 2);
  assert.equal(
    store.registerSafetySupervisor(contract).supervisor_contract_digest,
    contract.supervisor_contract_digest,
  );
  assert.equal(f.anchor.state.generation, 2, "exact registration replay is idempotent");

  const conflicting = safetySupervisorContract(f, {
    supervisor_ref: "safety-supervisor:lease-store-runtime-conflict",
  });
  assert.throws(
    () => store.registerSafetySupervisor(conflicting),
    /already has a different safety-supervisor contract/,
  );
  assert.equal(f.anchor.state.generation, 2);
  store.close();
});

test("containment action claims are anchored, semantically unique, and cannot be reclaimed after restart", (t) => {
  const f = fixture(t);
  let store = f.open();
  store.acquireLease(f.lease);
  const { contract, fenced } = enrollAndFence(store, f);
  assert.equal(f.anchor.state.generation, 3);

  const first = claimContainment(store, contract, fenced, "rf_interlock");
  assert.equal(first.claimed, true);
  assert.equal(first.state.state, "claimed");
  assert.equal(f.anchor.state.generation, 4, "claim is externally anchored before effect");
  const repeated = claimContainment(store, contract, fenced, "rf_interlock");
  assert.equal(repeated.claimed, false);
  assert.equal(repeated.state.claim_digest, first.state.claim_digest);
  assert.equal(f.anchor.state.generation, 4);
  assert.throws(
    () => store.claimContainmentAction({
      version: 1,
      supervisor_contract_digest: contract.supervisor_contract_digest,
      action: "rf_interlock",
      fenced_lease_digest: digest("detached-fenced-lease"),
    }),
    /fenced_lease_digest binding drift/,
  );
  assert.throws(
    () => store.claimContainmentAction({
      version: 1,
      supervisor_contract_digest: contract.supervisor_contract_digest,
      action: "device_reset",
      fenced_lease_digest: fenced.lease_digest,
    }),
    /not precommitted/,
  );
  store.close();

  store = f.open();
  const recovered = claimContainment(store, contract, fenced, "rf_interlock");
  assert.equal(recovered.claimed, false, "a crash-left claim is never authorized a second time");
  assert.equal(recovered.state.state, "claimed");
  assert.equal(recovered.state.claim_digest, first.state.claim_digest);
  assert.equal(f.anchor.state.generation, 4);

  const independent = claimContainment(store, contract, fenced, "worker_kill");
  assert.equal(independent.claimed, true);
  assert.notEqual(independent.state.claim_digest, first.state.claim_digest);
  assert.deepEqual(
    store.snapshot().containment_action_states.map((state) => state.action).sort(),
    ["rf_interlock", "worker_kill"],
  );
  store.close();
});

test("containment completions are durable, idempotent, and terminal across reopen", (t) => {
  const f = fixture(t);
  let store = f.open();
  store.acquireLease(f.lease);
  const { contract, fenced } = enrollAndFence(store, f);
  const claim = claimContainment(store, contract, fenced, "rf_interlock");
  const completed = confirmContainment(store, claim, "durable-rf-interlock-receipt");
  assert.equal(completed.state, "completed");
  assert.equal(completed.outcome, "confirmed");
  assert.equal(completed.receipt_digest, digest("durable-rf-interlock-receipt"));
  assert.equal(f.anchor.state.generation, 5);
  store.close();

  store = f.open();
  const snapshot = store.snapshot();
  assert.equal(snapshot.containment_action_states[0].state, "completed");
  assert.equal(snapshot.containment_action_states[0].outcome, "confirmed");
  const duplicate = confirmContainment(store, claim, "durable-rf-interlock-receipt");
  assert.equal(duplicate.completed_at, completed.completed_at);
  assert.equal(f.anchor.state.generation, 5, "exact completion replay adds no event");
  assert.throws(
    () => store.completeContainmentAction({
      version: 1,
      claim_digest: claim.state.claim_digest,
      outcome: "ambiguous",
      receipt_digest: null,
    }),
    /already has a terminal durable outcome/,
  );
  assert.equal(f.anchor.state.generation, 5);
  store.close();
});

test("recovery claims require every precommitted containment action to be durably confirmed", (t) => {
  const f = fixture(t);
  const store = f.open();
  store.acquireLease(f.lease);
  const { contract, fenced } = enrollAndFence(store, f);
  const rfClaim = claimContainment(store, contract, fenced, "rf_interlock");
  confirmContainment(store, rfClaim, "confirmed-rf-before-recovery");

  const recoveryRequest = {
    version: 1,
    supervisor_contract_digest: contract.supervisor_contract_digest,
    verified_bootstrap_digest: digest("verified-recovery-bootstrap"),
  };
  assert.throws(
    () => store.claimRecoveryLaunch(recoveryRequest),
    /requires confirmed durable containment: worker_kill/,
  );
  const workerClaim = claimContainment(store, contract, fenced, "worker_kill");
  store.completeContainmentAction({
    version: 1,
    claim_digest: workerClaim.state.claim_digest,
    outcome: "unavailable",
    receipt_digest: null,
  });
  assert.throws(
    () => store.claimRecoveryLaunch(recoveryRequest),
    /requires confirmed durable containment: worker_kill/,
  );
  assert.equal(store.snapshot().recovery_launch_states.length, 0);
  store.close();
});

test("a recovery launch claim is one-shot and remains terminal across restart", (t) => {
  const f = fixture(t);
  let store = f.open();
  store.acquireLease(f.lease);
  const { contract, fenced } = enrollAndFence(store, f);
  for (const action of contract.containment_actions) {
    const actionClaim = claimContainment(store, contract, fenced, action);
    confirmContainment(store, actionClaim, `confirmed-${action}-before-recovery`);
  }
  const recoveryRequest = {
    version: 1,
    supervisor_contract_digest: contract.supervisor_contract_digest,
    verified_bootstrap_digest: digest("verified-recovery-bootstrap-one-shot"),
  };
  const claim = store.claimRecoveryLaunch(recoveryRequest);
  assert.equal(claim.claimed, true);
  assert.equal(claim.state.state, "claimed");
  const generationAfterClaim = f.anchor.state.generation;
  assert.equal(store.claimRecoveryLaunch(recoveryRequest).claimed, false);
  assert.equal(f.anchor.state.generation, generationAfterClaim);
  store.close();

  store = f.open();
  assert.equal(store.claimRecoveryLaunch(recoveryRequest).claimed, false);
  assert.throws(
    () => store.claimRecoveryLaunch({
      ...recoveryRequest,
      verified_bootstrap_digest: digest("alternate-recovery-bootstrap"),
    }),
    /already been durably claimed/,
  );
  const completionRequest = {
    version: 1,
    claim_digest: claim.state.claim_digest,
    outcome: "launched",
    launch_receipt_digest: digest("durable-recovery-launch-receipt"),
  };
  const completed = store.completeRecoveryLaunch(completionRequest);
  assert.equal(completed.state, "completed");
  assert.equal(completed.outcome, "launched");
  store.close();

  store = f.open();
  const recovered = store.snapshot().recovery_launch_states[0];
  assert.equal(recovered.state, "completed");
  assert.equal(recovered.launch_receipt_digest, completionRequest.launch_receipt_digest);
  assert.equal(
    store.completeRecoveryLaunch(completionRequest).completed_at,
    completed.completed_at,
  );
  assert.equal(f.anchor.state.generation, generationAfterClaim + 1);
  store.close();
});

test("provider results enter the durable outbox before delivery acknowledgement", async (t) => {
  const f = fixture(t);
  const store = f.open();
  const { dispatch, starting } = prepareEffect(store, f);
  const committed = store.commitDispatch(dispatch);
  const providerPort = createDurableInstrumentProviderDispatchPort(store, providerEnrollment(f));
  const permit = providerPort.redeem(
    committed.dispatch_credential,
    providerExpected(starting),
  );
  providerPort.consumeEffect(permit, () => undefined);
  const running = nextJournal(starting, "running", "dispatched", "ambiguous", 140);
  store.appendJournal(running);
  const effectRecorded = nextJournal(
    running,
    "effect_recorded",
    "acknowledged",
    "confirmed_effect",
    150,
  );
  store.appendJournal(effectRecorded);
  const outbox = normalizeDurableOutboxEntry({
    version: 1,
    outbox_entry_ref: "outbox-entry:runtime-1-0",
    attempt_ref: effectRecorded.attempt_ref,
    instrument_ref: effectRecorded.instrument_ref,
    lease_id: effectRecorded.lease_id,
    fencing_token: effectRecorded.fencing_token,
    fencing_generation: effectRecorded.fencing_generation,
    operation_id: effectRecorded.operation_id,
    execution_request_digest: effectRecorded.execution_request_digest,
    source_journal_entry_digest: effectRecorded.journal_entry_digest,
    payload_kind: "provider_report",
    payload_ref: "provider-report:runtime-1",
    payload_digest: digest("provider-report"),
    sequence: 0,
    previous_entry_digest: null,
    recorded_at: "2026-07-18T00:00:00.152Z",
    fsynced_at: "2026-07-18T00:00:00.153Z",
  });
  let deliveries = 0;
  const recipientReceipts = new Map();
  const recipientPort = createIdempotentOutboxRecipientPort({
    recipientPrincipalId: "principal:broker-runtime-1",
    idempotencyDomainDigest: digest("recipient-dedup-domain"),
    deliverOnce: async (command) => {
      const prior = recipientReceipts.get(command.idempotency_key);
      if (prior) return clone(prior);
      deliveries += 1;
      const durable = command.outbox_entry;
      const snapshot = store.snapshot();
      assert.equal(snapshot.outbox_heads[0].outbox_entry_digest, durable.outbox_entry_digest);
      assert.equal(
        f.anchor.state.generation,
        10,
        "outbox and recipient/domain binding anchors precede recipient delivery",
      );
      const acknowledgement = {
        version: 1,
        acknowledgement_ref: "outbox-ack:runtime-1-0",
        outbox_entry_ref: durable.outbox_entry_ref,
        outbox_entry_digest: durable.outbox_entry_digest,
        recipient_principal_id: "principal:broker-runtime-1",
        acknowledged_at: "2026-07-18T00:00:00.156Z",
      };
      // Deterministic contract double for recipient-side atomic dedup. It proves
      // key/binding behavior, not persistence across a real process restart.
      recipientReceipts.set(command.idempotency_key, clone(acknowledgement));
      return acknowledgement;
    },
  });
  await assert.rejects(
    store.deliverOutbox(outbox, async () => ({})),
    /branded idempotent recipient port/,
  );
  const [acknowledgement, concurrentAcknowledgement] = await Promise.all([
    store.deliverOutbox(outbox, recipientPort),
    store.deliverOutbox(outbox, recipientPort),
  ]);
  assert.equal(acknowledgement.outbox_entry_digest, outbox.outbox_entry_digest);
  assert.equal(
    concurrentAcknowledgement.acknowledgement_digest,
    acknowledgement.acknowledgement_digest,
  );
  assert.equal(f.anchor.state.generation, 11);
  assert.equal(deliveries, 1, "recipient-side digest dedup absorbs concurrent at-least-once delivery");

  const repeated = await store.deliverOutbox(outbox, recipientPort);
  assert.equal(repeated.acknowledgement_digest, acknowledgement.acknowledgement_digest);
  assert.equal(deliveries, 1, "a durable acknowledgement suppresses redelivery");
  let redirectedActions = 0;
  const redirectedPort = createIdempotentOutboxRecipientPort({
    recipientPrincipalId: "principal:redirected-recipient",
    idempotencyDomainDigest: digest("redirected-recipient-domain"),
    deliverOnce: async () => {
      redirectedActions += 1;
      return {};
    },
  });
  await assert.rejects(
    store.deliverOutbox(outbox, redirectedPort),
    /already bound to another recipient or dedup domain/,
  );
  assert.equal(redirectedActions, 0);
  assert.equal(f.anchor.state.generation, 11);
  store.close();
});

test("the idempotent outbox port rejects acknowledgements redirected across recipients", async () => {
  const port = createIdempotentOutboxRecipientPort({
    recipientPrincipalId: "principal:recipient-one",
    idempotencyDomainDigest: digest("recipient-one-domain"),
    deliverOnce: async (command) => ({
      version: 1,
      acknowledgement_ref: "outbox-ack:redirected",
      outbox_entry_ref: command.outbox_entry.outbox_entry_ref,
      outbox_entry_digest: command.idempotency_key,
      recipient_principal_id: "principal:recipient-two",
      acknowledged_at: "2026-07-18T00:00:00.156Z",
    }),
  });
  await assert.rejects(port.accept({
    version: 1,
    idempotency_key: "a".repeat(64),
    idempotency_domain_digest: digest("recipient-one-domain"),
    outbox_entry: {
      outbox_entry_digest: "a".repeat(64),
      outbox_entry_ref: "outbox-entry:redirect-test",
    },
  }), /violates the idempotency binding/);
});

test("terminal lease closure requires a matching journal and durable receipt before reuse", async (t) => {
  const f = fixture(t);
  const store = f.open();
  store.acquireLease(f.lease);
  store.appendJournal(f.journal);
  const terminal = nextJournal(
    f.journal,
    "reconciled_no_effect",
    "refused",
    "confirmed_no_effect",
    110,
  );
  store.appendJournal(terminal);
  const receiptRef = "receipt:runtime-no-effect-1";
  const receiptDigest = digest("runtime-no-effect-receipt");
  const current = store.snapshot().leases[0];
  const release = {
    version: 1,
    lease_id: current.lease_id,
    instrument_ref: current.instrument_ref,
    owner_principal_id: current.owner_principal_id,
    execution_principal_id: current.execution_principal_id,
    fencing_token: current.fencing_token,
    fencing_generation: current.fencing_generation,
    expected_sequence: current.sequence,
    closed_at: "2026-07-18T00:00:00.400Z",
    terminal_disposition: "confirmed_no_effect",
    terminal_receipt_ref: receiptRef,
    terminal_receipt_digest: receiptDigest,
  };
  f.clock.set("2026-07-18T00:00:00.500Z");
  assert.throws(() => store.releaseLease(release), /durable terminal receipt/);
  const outbox = normalizeDurableOutboxEntry({
    version: 1,
    outbox_entry_ref: "outbox-entry:runtime-terminal-0",
    attempt_ref: terminal.attempt_ref,
    instrument_ref: terminal.instrument_ref,
    lease_id: terminal.lease_id,
    fencing_token: terminal.fencing_token,
    fencing_generation: terminal.fencing_generation,
    operation_id: terminal.operation_id,
    execution_request_digest: terminal.execution_request_digest,
    source_journal_entry_digest: terminal.journal_entry_digest,
    payload_kind: "provider_report",
    payload_ref: receiptRef,
    payload_digest: receiptDigest,
    sequence: 0,
    previous_entry_digest: null,
    recorded_at: "2026-07-18T00:00:00.112Z",
    fsynced_at: "2026-07-18T00:00:00.113Z",
  });
  store.appendOutbox(outbox);
  const terminalRecipient = createIdempotentOutboxRecipientPort({
    recipientPrincipalId: "principal:broker-runtime-1",
    idempotencyDomainDigest: digest("terminal-recipient-domain"),
    deliverOnce: async (command) => ({
      version: 1,
      acknowledgement_ref: "outbox-ack:runtime-terminal-0",
      outbox_entry_ref: command.outbox_entry.outbox_entry_ref,
      outbox_entry_digest: command.outbox_entry.outbox_entry_digest,
      recipient_principal_id: "principal:broker-runtime-1",
      acknowledged_at: "2026-07-18T00:00:00.300Z",
    }),
  });
  await store.deliverOutbox(outbox, terminalRecipient);
  const released = store.releaseLease(release);
  assert.equal(released.state, "released");

  const successor = {
    ...f.lease,
    lease_id: "lease-ph-s7-runtime-successor",
    attempt_ref: "attempt:physical-runtime-successor",
    fencing_token: "fence-runtime-successor",
    fencing_generation: 2,
    acquired_at: "2026-07-18T00:00:00.500Z",
    updated_at: "2026-07-18T00:00:00.500Z",
    effect_not_before: "2026-07-18T00:00:00.500Z",
    effect_deadline: "2026-07-18T00:00:01.000Z",
    heartbeat_deadline: "2026-07-18T00:00:00.800Z",
    expires_at: "2026-07-18T00:00:01.000Z",
  };
  const acquired = store.acquireLease(successor);
  assert.equal(acquired.fencing_generation, 2);
  store.close();
});

test("a self-asserted owner recipient and arbitrary dedup domain cannot authorize terminal release", async (t) => {
  const f = fixture(t);
  const store = f.open();
  store.acquireLease(f.lease);
  store.appendJournal(f.journal);
  const terminal = nextJournal(
    f.journal,
    "reconciled_no_effect",
    "refused",
    "confirmed_no_effect",
    110,
  );
  store.appendJournal(terminal);
  const receiptRef = "receipt:self-asserted-terminal-recipient";
  const receiptDigest = digest("self-asserted-terminal-receipt");
  const current = store.snapshot().leases[0];
  const release = {
    version: 1,
    lease_id: current.lease_id,
    instrument_ref: current.instrument_ref,
    owner_principal_id: current.owner_principal_id,
    execution_principal_id: current.execution_principal_id,
    fencing_token: current.fencing_token,
    fencing_generation: current.fencing_generation,
    expected_sequence: current.sequence,
    closed_at: "2026-07-18T00:00:00.400Z",
    terminal_disposition: "confirmed_no_effect",
    terminal_receipt_ref: receiptRef,
    terminal_receipt_digest: receiptDigest,
  };
  const outbox = normalizeDurableOutboxEntry({
    version: 1,
    outbox_entry_ref: "outbox-entry:self-asserted-terminal-recipient",
    attempt_ref: terminal.attempt_ref,
    instrument_ref: terminal.instrument_ref,
    lease_id: terminal.lease_id,
    fencing_token: terminal.fencing_token,
    fencing_generation: terminal.fencing_generation,
    operation_id: terminal.operation_id,
    execution_request_digest: terminal.execution_request_digest,
    source_journal_entry_digest: terminal.journal_entry_digest,
    payload_kind: "provider_report",
    payload_ref: receiptRef,
    payload_digest: receiptDigest,
    sequence: 0,
    previous_entry_digest: null,
    recorded_at: "2026-07-18T00:00:00.112Z",
    fsynced_at: "2026-07-18T00:00:00.113Z",
  });
  const selfAssertedRecipient = createIdempotentOutboxRecipientPort({
    // The public factory currently lets arbitrary caller code assert the real
    // owner identity and invent a dedup domain. That structural assertion is
    // not an enrolled recipient transaction or an authority receipt.
    recipientPrincipalId: f.lease.owner_principal_id,
    idempotencyDomainDigest: digest("attacker-selected-terminal-domain"),
    deliverOnce: async (command) => ({
      version: 1,
      acknowledgement_ref: "outbox-ack:self-asserted-terminal-recipient",
      outbox_entry_ref: command.outbox_entry.outbox_entry_ref,
      outbox_entry_digest: command.outbox_entry.outbox_entry_digest,
      recipient_principal_id: f.lease.owner_principal_id,
      acknowledged_at: "2026-07-18T00:00:00.300Z",
    }),
  });
  f.clock.set("2026-07-18T00:00:00.500Z");
  await assert.rejects(async () => {
    await store.deliverOutbox(outbox, selfAssertedRecipient);
    store.releaseLease(release);
  });
  store.close();
});

test("external anchor rollback detection and descriptor checks fail closed", (t) => {
  const f = fixture(t);
  const store = f.open();
  store.acquireLease(f.lease);
  store.close();
  const eventPath = path.join(f.root, "events", "000000000001.event.json");
  const hardlinkPath = path.join(f.root, "event-copy");
  fs.linkSync(eventPath, hardlinkPath);
  assert.throws(() => f.open(), /bounded private regular file/);
  fs.unlinkSync(hardlinkPath);
  fs.unlinkSync(eventPath);
  assert.throws(() => f.open(), /rolled back behind its external anchor/);
});

test("full local-root loss cannot mint a fresh external anchor namespace", (t) => {
  const f = fixture(t);
  const store = f.open();
  store.acquireLease(f.lease);
  store.close();
  assert.equal(f.anchor.state.runtime_id, f.runtimeId);
  assert.equal(f.anchor.state.generation, 1);

  fs.rmSync(f.root, { recursive: true, force: true });
  fs.mkdirSync(f.root, { mode: 0o700 });
  assert.throws(() => f.open(), /rolled back behind its external anchor/);
  assert.equal(f.anchor.state.runtime_id, f.runtimeId);
  assert.equal(f.anchor.state.generation, 1);
});

test("checkpoint mode is explicit and its external CAS capability is private-branded", (t) => {
  const f = fixture(t);
  assert.throws(
    () => f.open({ checkpointMode: undefined }),
    /checkpointMode must be one of/,
  );

  const legacy = f.open();
  assert.deepEqual(legacy.checkpointReadiness(), {
    version: 1,
    checkpoint_mode: "legacy_full_audit",
    production_ready: false,
    bounded_recovery_ready: false,
    anchor_assurance: "unavailable",
    checkpoint_capacity_state: "not_configured",
    admission_mode: "normal",
    checkpoint_capacity_exhausted_at_event_generation: null,
    reason: "externally_anchored_encrypted_checkpoint_required",
    checkpoint_generation: null,
    checkpoint_event_generation: null,
    event_generation: 0,
    tail_event_count: null,
    tail_event_limit: 1024,
    checkpoint_interval_events: 512,
    checkpoint_plaintext_limit_bytes: null,
  });
  assert.throws(() => legacy.checkpointNow(), /requires an external checkpoint anchor port/);
  legacy.close();

  const checkpointAnchor = new MemoryCheckpointAnchor();
  const port = createInstrumentLeaseCheckpointAnchorPort({
    portId: "instrument-checkpoint-anchor-brand-test-v1",
    readState: () => checkpointAnchor.readState(),
    compareAndSet: (request) => checkpointAnchor.compareAndSet(request),
  });
  assert.equal(assertInstrumentLeaseCheckpointAnchorPort(port), port);
  assert.deepEqual(Object.keys(port).sort(), [
    "anchor_assurance",
    "contract",
    "max_checkpoint_plaintext_bytes",
    "port_id",
    "version",
  ]);
  assert.equal(port.anchor_assurance, "caller_asserted_callback_unattested");
  assert.equal(Object.isFrozen(port), true);
  assert.equal(port.readState, undefined);
  assert.equal(port.compareAndSet, undefined);
  assert.throws(
    () => assertInstrumentLeaseCheckpointAnchorPort(structuredClone(port)),
    /private factory/,
  );
  assert.throws(
    () => f.open({ checkpointMode: "bounded_checkpoint", checkpointPort: clone(port) }),
    /private factory/,
  );
  const migration = f.open({ checkpointMode: "legacy_full_audit", checkpointPort: port });
  assert.equal(migration.checkpointReadiness().production_ready, false);
  assert.deepEqual(migration.checkpointNow(), {
    version: 1,
    checkpoint_mode: "legacy_full_audit",
    production_ready: false,
    bounded_recovery_ready: false,
    anchor_assurance: "caller_asserted_callback_unattested",
    checkpoint_capacity_state: "within_limit",
    admission_mode: "normal",
    checkpoint_capacity_exhausted_at_event_generation: null,
    reason: "bounded_checkpoint_mode_required",
    checkpoint_generation: 1,
    checkpoint_event_generation: 0,
    event_generation: 0,
    tail_event_count: 0,
    tail_event_limit: 1024,
    checkpoint_interval_events: 512,
    checkpoint_plaintext_limit_bytes: 32 * 1024 * 1024,
  });
  migration.close();

  const bounded = f.open({ checkpointMode: "bounded_checkpoint", checkpointPort: port });
  assert.equal(checkpointAnchor.state.checkpoint_generation, 1);
  assert.equal(checkpointAnchor.state.event_generation, 0);
  assert.deepEqual(bounded.checkpointReadiness(), {
    version: 1,
    checkpoint_mode: "bounded_checkpoint",
    production_ready: false,
    bounded_recovery_ready: true,
    anchor_assurance: "caller_asserted_callback_unattested",
    checkpoint_capacity_state: "within_limit",
    admission_mode: "normal",
    checkpoint_capacity_exhausted_at_event_generation: null,
    reason: "external_checkpoint_anchor_attestation_required",
    checkpoint_generation: 1,
    checkpoint_event_generation: 0,
    event_generation: 0,
    tail_event_count: 0,
    tail_event_limit: 1024,
    checkpoint_interval_events: 512,
    checkpoint_plaintext_limit_bytes: 32 * 1024 * 1024,
  });
  bounded.close();
});

test("bounded restart authenticates an encrypted checkpoint and only its cold tail", (t) => {
  const f = boundedFixture(t);
  let store = f.open();
  store.acquireLease(f.lease);
  store.appendJournal(f.journal);
  const checkpoint = store.checkpointNow();
  assert.equal(checkpoint.checkpoint_generation, 2);
  assert.equal(checkpoint.checkpoint_event_generation, 2);
  assert.equal(checkpoint.tail_event_count, 0);
  const admitted = nextJournal(f.journal, "admitted", "prepared", "not_dispatched", 120);
  store.appendJournal(admitted);
  const expected = store.snapshot();
  const eventFiles = fs.readdirSync(path.join(f.root, "events")).sort();
  assert.deepEqual(eventFiles, [
    "000000000001.event.json",
    "000000000002.event.json",
    "000000000003.event.json",
  ]);
  const checkpointBytes = fs.readFileSync(
    path.join(f.root, "checkpoints", f.checkpointAnchor.state.checkpoint_file),
    "utf8",
  );
  assert.equal(checkpointBytes.includes(f.lease.lease_id), false);
  assert.equal(checkpointBytes.includes(f.lease.fencing_token), false);
  assert.equal(checkpointBytes.includes(f.lease.execution_request_digest), false);
  store.close();

  const originalOpenSync = fs.openSync;
  const eventReads = [];
  fs.openSync = function checkpointCountedOpenSync(filePath, flags, ...rest) {
    if (typeof filePath === "string"
        && /\/\d{12}\.event\.json$/.test(filePath)
        && (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR)) === 0) {
      eventReads.push(path.basename(filePath));
    }
    return originalOpenSync.call(this, filePath, flags, ...rest);
  };
  t.after(() => { fs.openSync = originalOpenSync; });
  store = f.open();
  assert.deepEqual(store.snapshot(), expected);
  fs.openSync = originalOpenSync;
  assert.equal(eventReads.includes("000000000001.event.json"), false);
  assert.equal(eventReads.includes("000000000002.event.json"), true);
  assert.equal(eventReads.includes("000000000003.event.json"), true);
  assert.deepEqual(fs.readdirSync(path.join(f.root, "events")).sort(), eventFiles);
  assert.deepEqual(store.checkpointReadiness(), {
    version: 1,
    checkpoint_mode: "bounded_checkpoint",
    production_ready: false,
    bounded_recovery_ready: true,
    anchor_assurance: "caller_asserted_callback_unattested",
    checkpoint_capacity_state: "within_limit",
    admission_mode: "normal",
    checkpoint_capacity_exhausted_at_event_generation: null,
    reason: "external_checkpoint_anchor_attestation_required",
    checkpoint_generation: 2,
    checkpoint_event_generation: 2,
    event_generation: 3,
    tail_event_count: 1,
    tail_event_limit: 1024,
    checkpoint_interval_events: 512,
    checkpoint_plaintext_limit_bytes: 32 * 1024 * 1024,
  });
  store.close();
});

test("checkpoint capacity exhaustion refuses ordinary work but preserves the safety reserve", (t) => {
  const f = fixture(t);
  const checkpointAnchor = new MemoryCheckpointAnchor();
  const checkpointPort = createInstrumentLeaseCheckpointAnchorPort({
    portId: "instrument-checkpoint-capacity-test-v1",
    readState: () => checkpointAnchor.readState(),
    compareAndSet: (request) => checkpointAnchor.compareAndSet(request),
    maxCheckpointPlaintextBytes: 1024,
  });
  const storeOptions = {
    checkpointMode: "bounded_checkpoint",
    checkpointPort,
    checkpointIntervalEvents: 2,
  };
  let store = f.open(storeOptions);
  assert.equal(checkpointAnchor.state.event_generation, 0, "genesis fits the enrolled capacity");

  store.acquireLease(f.lease);
  const fenced = fenceForSafety(store, f);
  assert.equal(fenced.state, "fenced", "the capacity exception cannot escape a safety callback");
  assert.equal(store.snapshot().generation, 2);
  assert.equal(checkpointAnchor.state.event_generation, 0, "the oversized checkpoint was not anchored");
  assert.deepEqual(store.checkpointReadiness(), {
    version: 1,
    checkpoint_mode: "bounded_checkpoint",
    production_ready: false,
    bounded_recovery_ready: true,
    anchor_assurance: "caller_asserted_callback_unattested",
    checkpoint_capacity_state: "exhausted",
    admission_mode: "safety_reserve_only",
    checkpoint_capacity_exhausted_at_event_generation: 2,
    reason: "checkpoint_capacity_exhausted",
    checkpoint_generation: 1,
    checkpoint_event_generation: 0,
    event_generation: 2,
    tail_event_count: 2,
    tail_event_limit: 1024,
    checkpoint_interval_events: 2,
    checkpoint_plaintext_limit_bytes: 1024,
  });

  assert.throws(
    () => store.acquireLease({
      ...f.lease,
      lease_id: "lease-checkpoint-capacity-ordinary-refused",
      instrument_ref: "instrument:checkpoint-capacity-ordinary-refused",
      attempt_ref: "attempt:checkpoint-capacity-ordinary-refused",
      fencing_token: "fence-checkpoint-capacity-ordinary-refused",
    }),
    (error) => error.checkpoint_capacity_outcome === "exhausted"
      && /ordinary events are refused/.test(error.message),
  );
  assert.equal(store.snapshot().generation, 2, "refused ordinary work leaves no event residue");

  const supervisor = store.registerSafetySupervisor(safetySupervisorContract(f));
  assert.equal(supervisor.lease_id, f.lease.lease_id);
  assert.equal(store.snapshot().generation, 3, "safety-reserve events remain durable");
  assert.equal(store.checkpointReadiness().admission_mode, "safety_reserve_only");
  store.close();

  store = f.open(storeOptions);
  assert.equal(store.snapshot().generation, 3);
  assert.equal(store.checkpointReadiness().checkpoint_capacity_state, "exhausted");
  assert.equal(store.checkpointReadiness().admission_mode, "safety_reserve_only");
  assert.equal(
    store.checkpointReadiness().checkpoint_capacity_exhausted_at_event_generation,
    3,
    "bounded restart rediscovers capacity exhaustion from the authenticated projection",
  );
  store.close();
});

test("automatic checkpoint handling never swallows anchor ambiguity", (t) => {
  const f = fixture(t);
  const checkpointAnchor = new MemoryCheckpointAnchor();
  const checkpointPort = createInstrumentLeaseCheckpointAnchorPort({
    portId: "instrument-checkpoint-auto-anchor-error-v1",
    readState: () => checkpointAnchor.readState(),
    compareAndSet: (request) => checkpointAnchor.compareAndSet(request),
  });
  const store = f.open({
    checkpointMode: "bounded_checkpoint",
    checkpointPort,
    checkpointIntervalEvents: 1,
  });
  checkpointAnchor.armAmbiguousCommit();
  assert.throws(
    () => store.acquireLease(f.lease),
    (error) => error.checkpoint_anchor_commit_outcome === "ambiguous"
      && /outcome is ambiguous/.test(error.message),
  );
  assert.equal(f.anchor.state.generation, 1, "the event commit remains externally anchored");
  assert.equal(checkpointAnchor.state.event_generation, 1, "the ambiguous CAS actually committed");
  assert.equal(store.snapshot().generation, 1, "the exact checkpoint reconciles on the next hot use");
  store.close();
});

test("bounded checkpoint rebuild preserves durable dispatch source and commit bindings", (t) => {
  const f = boundedFixture(t);
  let store = f.open();
  const { dispatch } = prepareEffect(store, f);
  const committed = store.commitDispatch(dispatch);
  assert.equal(committed.already_committed, false);
  store.checkpointNow();
  const expected = store.snapshot();
  assert.equal(
    expected.journal_heads[0].execution_lineage_digest,
    f.journal.execution_lineage_digest,
  );
  store.close();

  store = f.open();
  assert.deepEqual(store.snapshot(), expected);
  const duplicate = store.commitDispatch(dispatch);
  assert.equal(duplicate.already_committed, true);
  assert.equal(duplicate.dispatch_credential, null);
  store.close();
});

test("bounded checkpoint rebuild preserves safety containment and recovery state", (t) => {
  const f = boundedFixture(t);
  let store = f.open();
  store.acquireLease(f.lease);
  const { contract, fenced } = enrollAndFence(store, f);
  for (const action of contract.containment_actions) {
    const claim = claimContainment(store, contract, fenced, action);
    confirmContainment(store, claim, `checkpoint-${action}-receipt`);
  }
  const recovery = store.claimRecoveryLaunch({
    version: 1,
    supervisor_contract_digest: contract.supervisor_contract_digest,
    verified_bootstrap_digest: digest("checkpoint-recovery-bootstrap"),
  });
  store.completeRecoveryLaunch({
    version: 1,
    claim_digest: recovery.state.claim_digest,
    outcome: "launched",
    launch_receipt_digest: digest("checkpoint-recovery-launch-receipt"),
  });
  store.checkpointNow();
  const expected = store.snapshot();
  store.close();

  store = f.open();
  assert.deepEqual(store.snapshot(), expected);
  assert.equal(store.snapshot().containment_action_states.length, 2);
  assert.equal(store.snapshot().recovery_launch_states[0].state, "completed");
  store.close();
});

test("bounded checkpoint rebuild preserves outbox chains, delivery bindings, and acknowledgements", async (t) => {
  const f = boundedFixture(t);
  let store = f.open();
  store.acquireLease(f.lease);
  store.appendJournal(f.journal);
  const outbox = normalizeDurableOutboxEntry({
    version: 1,
    outbox_entry_ref: "outbox-entry:checkpoint-runtime-1-0",
    attempt_ref: f.journal.attempt_ref,
    instrument_ref: f.journal.instrument_ref,
    lease_id: f.journal.lease_id,
    fencing_token: f.journal.fencing_token,
    fencing_generation: f.journal.fencing_generation,
    operation_id: f.journal.operation_id,
    execution_request_digest: f.journal.execution_request_digest,
    source_journal_entry_digest: f.journal.journal_entry_digest,
    payload_kind: "provider_report",
    payload_ref: "provider-report:checkpoint-runtime-1",
    payload_digest: digest("checkpoint-provider-report"),
    sequence: 0,
    previous_entry_digest: null,
    recorded_at: "2026-07-18T00:00:00.102Z",
    fsynced_at: "2026-07-18T00:00:00.103Z",
  });
  const recipient = createIdempotentOutboxRecipientPort({
    recipientPrincipalId: "principal:broker-runtime-1",
    idempotencyDomainDigest: digest("checkpoint-recipient-domain"),
    deliverOnce: async (command) => ({
      version: 1,
      acknowledgement_ref: "outbox-ack:checkpoint-runtime-1-0",
      outbox_entry_ref: command.outbox_entry.outbox_entry_ref,
      outbox_entry_digest: command.outbox_entry.outbox_entry_digest,
      recipient_principal_id: "principal:broker-runtime-1",
      acknowledged_at: "2026-07-18T00:00:00.104Z",
    }),
  });
  await store.deliverOutbox(outbox, recipient);
  store.checkpointNow();
  const expected = store.snapshot();
  store.close();

  store = f.open();
  assert.deepEqual(store.snapshot(), expected);
  assert.equal(store.snapshot().outbox_entries.length, 1);
  assert.equal(store.snapshot().outbox_delivery_bindings.length, 1);
  assert.equal(store.snapshot().acknowledgements.length, 1);
  store.close();
});

test("checkpoint CAS rejection and response loss reconcile the exact crash-left file", (t) => {
  const f = boundedFixture(t);
  const store = f.open();
  store.acquireLease(f.lease);

  f.checkpointAnchor.armRejectedCommit();
  assert.throws(
    () => store.checkpointNow(),
    (error) => error.checkpoint_anchor_commit_outcome === "pending"
      && /pending external anchor reconciliation/.test(error.message),
  );
  assert.equal(f.checkpointAnchor.state.checkpoint_generation, 1);
  assert.equal(fs.readdirSync(path.join(f.root, "checkpoints")).length, 2);
  assert.equal(store.snapshot().generation, 1);
  assert.equal(f.checkpointAnchor.state.checkpoint_generation, 2);
  assert.equal(fs.readdirSync(path.join(f.root, "checkpoints")).length, 2);

  store.appendJournal(f.journal);
  f.checkpointAnchor.armAmbiguousCommit();
  assert.throws(
    () => store.checkpointNow(),
    (error) => error.checkpoint_anchor_commit_outcome === "ambiguous"
      && /outcome is ambiguous/.test(error.message),
  );
  assert.equal(f.checkpointAnchor.state.checkpoint_generation, 3);
  assert.equal(store.snapshot().generation, 2);
  assert.equal(store.checkpointReadiness().checkpoint_generation, 3);
  assert.deepEqual(fs.readdirSync(path.join(f.root, "checkpoints")).sort(), [
    "000000000001.checkpoint.json",
    "000000000002.checkpoint.json",
    "000000000003.checkpoint.json",
  ]);
  store.close();
});

test("a rejected genesis checkpoint CAS plus read outage is ambiguous, not pending", (t) => {
  const f = boundedFixture(t);
  f.checkpointAnchor.armRejectedCommitWithReadOutage();
  assert.throws(
    () => f.open(),
    (error) => error.checkpoint_anchor_commit_outcome === "ambiguous"
      && /outcome is ambiguous/.test(error.message),
  );
  assert.equal(f.checkpointAnchor.state, null);
  assert.deepEqual(fs.readdirSync(path.join(f.root, "checkpoints")), [
    "000000000001.checkpoint.json",
  ]);
});

test("checkpoint rollback, fork, corruption, descriptor abuse, and anchor outage fail closed", async (t) => {
  await t.test("hot rollback and fork", (st) => {
    const f = boundedFixture(st);
    const store = f.open();
    const genesis = clone(f.checkpointAnchor.state);
    store.acquireLease(f.lease);
    store.checkpointNow();
    const current = clone(f.checkpointAnchor.state);
    f.checkpointAnchor.state = genesis;
    assert.throws(() => store.snapshot(), /rolled back behind the live cache/);
    f.checkpointAnchor.state = { ...current, checkpoint_anchor_digest: digest("fork") };
    assert.throws(() => store.snapshot(), /checkpoint_anchor_digest is invalid/);
    f.checkpointAnchor.state = current;
    f.checkpointAnchor.hiddenReads = 1;
    assert.throws(() => store.snapshot(), /injected checkpoint anchor read outage/);
    store.close();
  });

  await t.test("missing current file", (st) => {
    const f = boundedFixture(st);
    const store = f.open();
    store.acquireLease(f.lease);
    store.checkpointNow();
    store.close();
    fs.unlinkSync(path.join(f.root, "checkpoints", f.checkpointAnchor.state.checkpoint_file));
    assert.throws(() => f.open(), /missing, duplicated, or non-contiguous|rolled back/);
  });

  await t.test("corrupted current file", (st) => {
    const f = boundedFixture(st);
    const store = f.open();
    store.acquireLease(f.lease);
    store.checkpointNow();
    store.close();
    const checkpointPath = path.join(
      f.root,
      "checkpoints",
      f.checkpointAnchor.state.checkpoint_file,
    );
    fs.chmodSync(checkpointPath, 0o600);
    fs.writeFileSync(checkpointPath, "{\"forged\":true}\n");
    fs.chmodSync(checkpointPath, 0o400);
    assert.throws(() => f.open(), /missing fields|unknown fields|digest is invalid/);
  });

  await t.test("oversize and hardlinked current files", (st) => {
    const oversize = boundedFixture(st);
    let store = oversize.open();
    store.close();
    let checkpointPath = path.join(
      oversize.root,
      "checkpoints",
      oversize.checkpointAnchor.state.checkpoint_file,
    );
    fs.chmodSync(checkpointPath, 0o600);
    fs.truncateSync(checkpointPath, INSTRUMENT_LEASE_CHECKPOINT_FILE_MAX_BYTES + 1);
    fs.chmodSync(checkpointPath, 0o400);
    assert.throws(() => oversize.open(), /not a bounded private regular file/);

    const hardlinked = boundedFixture(st);
    store = hardlinked.open();
    store.close();
    checkpointPath = path.join(
      hardlinked.root,
      "checkpoints",
      hardlinked.checkpointAnchor.state.checkpoint_file,
    );
    const secondLink = path.join(hardlinked.root, "checkpoint-copy");
    fs.linkSync(checkpointPath, secondLink);
    assert.throws(() => hardlinked.open(), /not a bounded private regular file/);

    const symlinked = boundedFixture(st);
    store = symlinked.open();
    store.close();
    checkpointPath = path.join(
      symlinked.root,
      "checkpoints",
      symlinked.checkpointAnchor.state.checkpoint_file,
    );
    fs.unlinkSync(checkpointPath);
    fs.symlinkSync(path.join(symlinked.root, "runtime.json"), checkpointPath);
    assert.throws(() => symlinked.open(), /ELOOP|symbolic links?/i);
  });

  await t.test("unknown and multiple unanchored files", (st) => {
    const unknown = boundedFixture(st);
    let store = unknown.open();
    store.close();
    fs.writeFileSync(path.join(unknown.root, "checkpoints", "unexpected"), "x", { mode: 0o400 });
    assert.throws(() => unknown.open(), /contains unknown entries/);

    const multiple = boundedFixture(st);
    store = multiple.open();
    store.close();
    const source = path.join(
      multiple.root,
      "checkpoints",
      multiple.checkpointAnchor.state.checkpoint_file,
    );
    fs.copyFileSync(source, path.join(multiple.root, "checkpoints", "000000000002.checkpoint.json"));
    fs.copyFileSync(source, path.join(multiple.root, "checkpoints", "000000000003.checkpoint.json"));
    fs.chmodSync(path.join(multiple.root, "checkpoints", "000000000002.checkpoint.json"), 0o400);
    fs.chmodSync(path.join(multiple.root, "checkpoints", "000000000003.checkpoint.json"), 0o400);
    assert.throws(() => multiple.open(), /multiple unanchored checkpoints/);
  });

  await t.test("checkpoint boundary and retained tail event corruption", (st) => {
    const boundary = boundedFixture(st);
    let store = boundary.open();
    store.acquireLease(boundary.lease);
    store.appendJournal(boundary.journal);
    store.checkpointNow();
    const admitted = nextJournal(
      boundary.journal,
      "admitted",
      "prepared",
      "not_dispatched",
      120,
    );
    store.appendJournal(admitted);
    store.close();
    let eventPath = path.join(boundary.root, "events", "000000000002.event.json");
    fs.chmodSync(eventPath, 0o600);
    fs.writeFileSync(eventPath, "{\"forged\":true}\n");
    fs.chmodSync(eventPath, 0o400);
    assert.throws(() => boundary.open(), /checkpoint event boundary|authentication failed|unknown fields/);

    const tail = boundedFixture(st);
    store = tail.open();
    store.acquireLease(tail.lease);
    store.checkpointNow();
    store.appendJournal(tail.journal);
    store.close();
    eventPath = path.join(tail.root, "events", "000000000002.event.json");
    fs.chmodSync(eventPath, 0o600);
    fs.writeFileSync(eventPath, "{\"forged\":true}\n");
    fs.chmodSync(eventPath, 0o400);
    assert.throws(() => tail.open(), /authentication failed|unknown fields|invalid/);
  });
});

test("checkpoint rebuild rejects a validly re-encrypted cross-projection inconsistency", (t) => {
  const f = boundedFixture(t);
  const store = f.open();
  store.acquireLease(f.lease);
  store.checkpointNow();
  store.close();
  rewriteCurrentCheckpointProjection(f, (payload) => {
    payload.event_keys = [];
  });
  assert.throws(
    () => f.open(),
    /event key set is incomplete or duplicated/,
  );
});

test("checkpoint rebuild rejects omitted or aliased transaction source facts", async (t) => {
  await t.test("omitted vault commit", (st) => {
    const f = boundedFixture(st);
    const store = f.open();
    const claimed = claimTransaction(store, f);
    armClaimedTransaction(store, f, claimed);
    claimed.port.commitVault(transactionVaultFact(
      claimed.claim.transaction,
      claimed.binding,
    ));
    store.checkpointNow();
    store.close();
    rewriteCurrentCheckpointProjection(f, (payload) => {
      payload.execution_transaction_vault_commits = [];
    });
    assert.throws(
      () => f.open(),
      /transaction vault projection is incomplete/,
    );
  });

  await t.test("one of two claims omitted", (st) => {
    const f = boundedFixture(st);
    const store = f.open();
    const first = claimTransaction(store, f);
    const second = secondaryLeaseJournal(f, "transaction-checkpoint-claim-2");
    const held = store.acquireLease(second.lease);
    store.appendJournal(second.journal);
    const admitted = nextJournal(second.journal, "admitted", "prepared", "not_dispatched", 120);
    store.appendJournal(admitted);
    first.port.claim(transactionBinding(f, held, admitted));
    store.checkpointNow();
    store.close();
    rewriteCurrentCheckpointProjection(f, (payload) => {
      payload.execution_transaction_claims.pop();
    });
    assert.throws(
      () => f.open(),
      /transaction claim projection is incomplete/,
    );
  });

  await t.test("two claims alias one source event", (st) => {
    const f = boundedFixture(st);
    const store = f.open();
    const first = claimTransaction(store, f);
    const second = secondaryLeaseJournal(f, "transaction-checkpoint-source-2");
    const held = store.acquireLease(second.lease);
    store.appendJournal(second.journal);
    const admitted = nextJournal(second.journal, "admitted", "prepared", "not_dispatched", 120);
    store.appendJournal(admitted);
    first.port.claim(transactionBinding(f, held, admitted));
    store.checkpointNow();
    store.close();
    rewriteCurrentCheckpointProjection(f, (payload) => {
      const [source, aliased] = payload.execution_transaction_claims;
      aliased.claim_event_generation = source.claim_event_generation;
      aliased.claim_event_digest = source.claim_event_digest;
      delete aliased.claim_digest;
      aliased.claim_digest = hashCanonicalJson(aliased);
    });
    assert.throws(
      () => f.open(),
      /reuses a durable source event/,
    );
  });

  await t.test("claim binding diverges from its retained event", (st) => {
    const f = boundedFixture(st);
    const store = f.open();
    claimTransaction(store, f);
    store.checkpointNow();
    store.close();
    rewriteCurrentCheckpointProjection(f, (payload) => {
      const claim = payload.execution_transaction_claims[0];
      const priorEventKey = `execution_transaction_claimed:${hashCanonicalJson(claim.binding)}`;
      const forgedBinding = {
        ...claim.binding,
        native_launch_ticket_digest: digest("forged-checkpoint-native-launch-ticket"),
      };
      delete forgedBinding.composite_binding_digest;
      claim.binding = structuredClone(normalizePhysicalExecutionCompositeBinding(forgedBinding));
      delete claim.claim_digest;
      claim.claim_digest = hashCanonicalJson(claim);
      const eventKeyIndex = payload.event_keys.indexOf(priorEventKey);
      assert.notEqual(eventKeyIndex, -1);
      payload.event_keys[eventKeyIndex]
        = `execution_transaction_claimed:${hashCanonicalJson(claim.binding)}`;
      payload.event_keys.sort();
    });
    assert.throws(
      () => f.open(),
      /conflicts with its retained durable source event/,
    );
  });
});

test("checkpoint rebuild rejects recovery detached from confirmed containment", (t) => {
  const f = boundedFixture(t);
  const store = f.open();
  store.acquireLease(f.lease);
  const { contract, fenced } = enrollAndFence(store, f);
  for (const action of contract.containment_actions) {
    confirmContainment(
      store,
      claimContainment(store, contract, fenced, action),
      `cross-invariant-${action}`,
    );
  }
  store.claimRecoveryLaunch({
    version: 1,
    supervisor_contract_digest: contract.supervisor_contract_digest,
    verified_bootstrap_digest: digest("cross-invariant-bootstrap"),
  });
  store.checkpointNow();
  store.close();
  rewriteCurrentCheckpointProjection(f, (payload) => {
    payload.containment_action_states[0].outcome = "failed";
    payload.containment_action_states[0].receipt_digest = null;
  });
  assert.throws(
    () => f.open(),
    /recovery lacks confirmed containment/,
  );
});

test("checkpoint rebuild rejects a dispatch detached from its current journal", (t) => {
  const f = boundedFixture(t);
  const store = f.open();
  const { dispatch } = prepareEffect(store, f);
  store.commitDispatch(dispatch);
  store.checkpointNow();
  store.close();

  rewriteCurrentCheckpointProjection(f, (payload) => {
    payload.journal_heads = [];
  });
  assert.throws(
    () => f.open(),
    /dispatch has no current journal/,
  );
});

test("checkpoint rebuild rejects an outbox detached from its current journal", (t) => {
  const f = boundedFixture(t);
  const store = f.open();
  store.acquireLease(f.lease);
  store.appendJournal(f.journal);
  store.appendOutbox(normalizeDurableOutboxEntry({
    version: 1,
    outbox_entry_ref: "outbox-entry:checkpoint-detached-journal-1",
    attempt_ref: f.journal.attempt_ref,
    instrument_ref: f.journal.instrument_ref,
    lease_id: f.journal.lease_id,
    fencing_token: f.journal.fencing_token,
    fencing_generation: f.journal.fencing_generation,
    operation_id: f.journal.operation_id,
    execution_request_digest: f.journal.execution_request_digest,
    source_journal_entry_digest: f.journal.journal_entry_digest,
    payload_kind: "provider_report",
    payload_ref: "provider-report:checkpoint-detached-journal-1",
    payload_digest: digest("checkpoint-detached-journal-payload"),
    sequence: 0,
    previous_entry_digest: null,
    recorded_at: "2026-07-18T00:00:00.102Z",
    fsynced_at: "2026-07-18T00:00:00.103Z",
  }));
  store.checkpointNow();
  store.close();

  rewriteCurrentCheckpointProjection(f, (payload) => {
    payload.journal_heads = [];
  });
  assert.throws(
    () => f.open(),
    /outbox entry has no current journal/,
  );
});

test("checkpoint rebuild rejects conflicting supervisors for one lease", (t) => {
  const f = boundedFixture(t);
  const store = f.open();
  store.acquireLease(f.lease);
  store.registerSafetySupervisor(safetySupervisorContract(f));
  store.checkpointNow();
  store.close();

  const conflicting = safetySupervisorContract(f, {
    supervisor_ref: "safety-supervisor:lease-store-runtime-conflict",
    supervisor_principal_id: "principal:safety-supervisor-runtime-conflict",
    supervisor_signer_key_id: "supervisor-signer-key-runtime-conflict",
  });
  rewriteCurrentCheckpointProjection(f, (payload) => {
    payload.safety_supervisor_contracts.push(clone(conflicting));
  });
  assert.throws(
    () => f.open(),
    /lease has conflicting safety supervisors/,
  );
});
