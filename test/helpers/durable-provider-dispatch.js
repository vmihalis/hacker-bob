"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  assertAttemptJournalAppend,
  normalizeAttemptJournalEntry,
  normalizeEffectDispatchRecord,
} = require("../../mcp/lib/instrument-lease-contract.js");
const {
  createDurableInstrumentLeaseStore,
  createDurableInstrumentProviderDispatchPort,
} = require("../../mcp/lib/instrument-lease-store.js");
const {
  createDeterministicMockDispatchAuthorityPort,
} = require("../../mcp/lib/physical-dispatch-authority.js");
const {
  hashCanonicalJson,
} = require("../../mcp/lib/verification-contracts.js");

function digest(label, value = null) {
  return hashCanonicalJson({ label, value });
}

function clone(value) {
  return value == null ? null : structuredClone(value);
}

class MemoryStateAnchor {
  constructor() {
    this.state = null;
  }

  readState() {
    return clone(this.state);
  }

  compareAndSet(request) {
    const generation = this.state == null ? null : this.state.generation;
    const head = this.state == null ? null : this.state.head_event_digest;
    if (request.expected_generation !== generation
        || request.expected_head_event_digest !== head) return false;
    this.state = clone(request.next_state);
    return true;
  }
}

function makeClock() {
  let current = Date.parse("2026-07-18T00:00:00.200Z");
  return () => {
    const result = new Date(current);
    current += 1;
    return result;
  };
}

function nextJournal(previous, state, providerState, providerSequence, millis) {
  const candidate = {
    ...previous,
    journal_entry_ref: `journal-entry:${digest("provider-test-journal", {
      attempt_ref: previous.attempt_ref,
      sequence: previous.sequence + 1,
      state,
    }).slice(0, 40)}`,
    state,
    provider_state: providerState,
    provider_sequence: providerSequence,
    effect_disposition: "not_dispatched",
    sequence: previous.sequence + 1,
    previous_entry_digest: previous.journal_entry_digest,
    recorded_at: `2026-07-18T00:00:00.${String(millis).padStart(3, "0")}Z`,
    fsynced_at: `2026-07-18T00:00:00.${String(millis + 1).padStart(3, "0")}Z`,
  };
  delete candidate.journal_entry_digest;
  return assertAttemptJournalAppend(previous, candidate);
}

function createDurableProviderDispatchHarness({
  descriptor,
  executionPrincipalId = "principal:deterministic-provider-worker-1",
  instrumentRefs = ["instrument:mock-owned-fixture-0001"],
} = {}) {
  if (!descriptor) throw new Error("durable provider dispatch harness requires a descriptor");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-provider-dispatch-harness-"));
  fs.chmodSync(root, 0o700);
  const runtimeSeed = digest("provider-dispatch-runtime", root);
  const sessionNucleusHash = digest("provider-dispatch-session", descriptor.descriptor_digest);
  const store = createDurableInstrumentLeaseStore({
    root,
    runtimeId: `physical-runtime:v1:${runtimeSeed.slice(0, 32)}`,
    sessionNucleusHash,
    masterKey: crypto.createHash("sha256").update(runtimeSeed).digest(),
    stateAnchor: new MemoryStateAnchor(),
    checkpointMode: "legacy_full_audit",
    now: makeClock(),
  });
  const port = createDurableInstrumentProviderDispatchPort(store, {
    provider_id: descriptor.provider_id,
    provider_descriptor_digest: descriptor.descriptor_digest,
    execution_principal_id: executionPrincipalId,
    instrument_refs: instrumentRefs,
    authority_port: createDeterministicMockDispatchAuthorityPort({
      port_id: "deterministic-provider-harness-authority-v1",
      session_nucleus_hash: sessionNucleusHash,
      provider_id: descriptor.provider_id,
      provider_descriptor_digest: descriptor.descriptor_digest,
      execution_principal_id: executionPrincipalId,
    }),
  });
  let closed = false;

  function authorize({ normalized_prepare: preparedRequest, prepared }) {
    if (!preparedRequest || !prepared) {
      throw new Error("durable provider dispatch authorization requires prepared request and report");
    }
    if (prepared.state !== "prepared"
        || prepared.attempt_ref !== preparedRequest.attempt_ref
        || prepared.operation_id !== preparedRequest.operation_id
        || prepared.request_digest !== preparedRequest.request_digest) {
      throw new Error("durable provider dispatch authorization requires an exact prepared report");
    }
    const suffix = digest("provider-dispatch-attempt", prepared.attempt_ref).slice(0, 24);
    const executionRequestDigest = digest("provider-execution-request", {
      attempt_ref: prepared.attempt_ref,
      provider_request_digest: prepared.request_digest,
    });
    const lease = {
      version: 1,
      lease_id: `lease-provider-test-${suffix}`,
      instrument_ref: preparedRequest.instrument_ref,
      owner_principal_id: "principal:deterministic-provider-broker-1",
      execution_principal_id: executionPrincipalId,
      terminal_receipt_recipient_principal_id: "principal:deterministic-provider-broker-1",
      terminal_receipt_idempotency_domain_digest: digest("provider-terminal-domain"),
      attempt_ref: prepared.attempt_ref,
      operation_id: prepared.operation_id,
      execution_request_digest: executionRequestDigest,
      resource_bundle_digest: digest("provider-resource-bundle", prepared.attempt_ref),
      fencing_token: `fence-provider-test-${suffix}`,
      fencing_generation: 1,
      state: "held",
      sequence: 0,
      acquired_at: "2026-07-18T00:00:00.000Z",
      updated_at: "2026-07-18T00:00:00.000Z",
      effect_not_before: "2026-07-18T00:00:00.000Z",
      effect_deadline: "2026-07-18T00:01:00.000Z",
      heartbeat_deadline: "2026-07-18T00:00:30.000Z",
      expires_at: "2026-07-18T00:01:00.000Z",
    };
    const initial = normalizeAttemptJournalEntry({
      version: 1,
      journal_entry_ref: `journal-entry:${digest("provider-test-journal-0", suffix).slice(0, 40)}`,
      attempt_ref: lease.attempt_ref,
      instrument_ref: lease.instrument_ref,
      lease_id: lease.lease_id,
      fencing_token: lease.fencing_token,
      fencing_generation: lease.fencing_generation,
      operation_id: lease.operation_id,
      execution_request_digest: lease.execution_request_digest,
      experiment_plan_hash: digest("provider-experiment-plan", prepared.attempt_ref),
      execution_lineage_digest: digest("provider-execution-lineage", {
        attempt_ref: prepared.attempt_ref,
        provider_request_digest: prepared.request_digest,
      }),
      authority_resolution_digest: digest("provider-authority-resolution", suffix),
      signed_grant_digest: digest("provider-signed-grant", suffix),
      replay_claim_digest: digest("provider-replay-claim", suffix),
      replay_reservation_receipt_digest: digest("provider-replay-reservation", suffix),
      provider_id: descriptor.provider_id,
      provider_descriptor_digest: descriptor.descriptor_digest,
      provider_request_digest: prepared.request_digest,
      cleanup_capability_digest: digest("provider-cleanup-capability", suffix),
      cleanup_plan_digest: digest("provider-cleanup-plan", suffix),
      workspace_snapshot_ref: `workspace-snapshot:provider-test-${suffix}`,
      workspace_snapshot_digest: digest("provider-workspace-snapshot", suffix),
      stop_contract_digest: digest("provider-stop-contract", suffix),
      state: "precommitted",
      provider_state: "created",
      provider_sequence: 0,
      effect_disposition: "not_dispatched",
      sequence: 0,
      previous_entry_digest: null,
      recorded_at: "2026-07-18T00:00:00.100Z",
      fsynced_at: "2026-07-18T00:00:00.101Z",
    });
    store.acquireLease(lease);
    store.appendJournal(initial);
    const admitted = nextJournal(initial, "admitted", "prepared", prepared.sequence, 120);
    store.appendJournal(admitted);
    const starting = nextJournal(admitted, "effect_starting", "prepared", prepared.sequence, 130);
    store.appendJournal(starting);
    const dispatch = normalizeEffectDispatchRecord({
      version: 1,
      dispatch_event_ref: `dispatch-event:provider-test-${suffix}`,
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
    if (committed.already_committed || !committed.dispatch_credential) {
      throw new Error("durable provider dispatch harness lost its winner credential");
    }
    return Object.freeze({
      dispatch_credential: committed.dispatch_credential,
      dispatch_journal_ref: starting.journal_entry_ref,
    });
  }

  function close() {
    if (closed) return;
    closed = true;
    store.close();
    fs.rmSync(root, { recursive: true, force: true });
  }

  return Object.freeze({ authorize, close, port, store });
}

module.exports = {
  createDurableProviderDispatchHarness,
};
