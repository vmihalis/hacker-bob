"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  createInstrumentContainmentPort,
  createInstrumentSafetySupervisor,
  createPrecommittedRecoveryLauncherPort,
  createSafetyObservationPort,
} = require("../mcp/lib/instrument-safety-supervisor.js");
const {
  normalizeSafetySupervisorContract,
  projectVerifiedRecoveryWorkerBootstrap,
} = require("../mcp/lib/instrument-lease-contract.js");
const {
  normalizeCleanupCapability,
} = require("../mcp/lib/physical-authority.js");
const {
  buildEffectTemplateRegistry,
} = require("../mcp/lib/requested-effects.js");
const {
  createDurableInstrumentLeaseStore,
} = require("../mcp/lib/instrument-lease-store.js");
const {
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");

function digest(label) {
  return hashCanonicalJson({ label });
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

function makeClock(start = "2026-07-18T00:00:00.000Z") {
  let current = Date.parse(start);
  const clock = () => new Date(current);
  clock.set = (timestamp) => { current = Date.parse(timestamp); };
  return clock;
}

function signatureEnvelope(payload, key = "worker-heartbeat-key-1", proof = "heartbeat-1") {
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

function trustedVerification(authentication) {
  return {
    version: 1,
    verified: true,
    method: authentication.method,
    signer_key_id: authentication.signer_key_id,
    trust_root_epoch: authentication.trust_root_epoch,
    verified_payload_digest: authentication.signed_payload_digest,
    verified_proof_digest: authentication.proof_digest,
    signature_verifier_id: "physical-heartbeat-verifier-v1",
    signature_verdict_digest: digest("heartbeat-verdict"),
  };
}

function fixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-safety-supervisor-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const anchor = new MemoryStateAnchor();
  const clock = makeClock();
  const masterKey = crypto.createHash("sha256").update("safety-supervisor-test-key").digest();
  const runtimeId = `physical-runtime:v1:${digest("safety-runtime-enrollment").slice(0, 32)}`;
  const sessionNucleusHash = digest("safety-supervisor-session");
  function openStore() {
    const opened = createDurableInstrumentLeaseStore({
      root,
      runtimeId,
      sessionNucleusHash,
      masterKey,
      stateAnchor: anchor,
      checkpointMode: "legacy_full_audit",
      now: clock,
    });
    t.after(() => opened.close());
    return opened;
  }
  const store = openStore();
  const lease = {
    version: 1,
    lease_id: "lease-safety-runtime-1",
    instrument_ref: "instrument:owned-fixture-1",
    owner_principal_id: "principal:physical-broker-1",
    execution_principal_id: "principal:active-worker-1",
    terminal_receipt_recipient_principal_id: "principal:physical-broker-1",
    terminal_receipt_idempotency_domain_digest: digest("terminal-recipient-domain"),
    attempt_ref: "attempt:safety-runtime-1",
    operation_id: "representation.write",
    execution_request_digest: digest("execution-request"),
    resource_bundle_digest: digest("resource-bundle"),
    fencing_token: "fence-safety-runtime-1",
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
  store.acquireLease(lease);
  const effectRegistry = buildEffectTemplateRegistry([{
    version: 1,
    template_id: "instrument.configure.usb.v1",
    subject_kind: "instrument",
    action: "configure",
    channel: "usb",
    persistence: "persistent",
    bounds: {},
  }]);
  const effectTemplate = effectRegistry.get("instrument.configure.usb.v1");
  const cleanupCapability = normalizeCleanupCapability({
    version: 1,
    capability_kind: "cleanup",
    root_kind: "cleanup_safety",
    nondelegable: true,
    agent_requestable: false,
    safety_root_ref: "safety-root:physical-1",
    source_execution_request_digest: lease.execution_request_digest,
    session_id: "session-safety-runtime-1",
    instrument_ref: lease.instrument_ref,
    recovery_principal_id: "principal:cleanup-worker-1",
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    workspace_snapshot_ref: "workspace-snapshot:owned-fixture-1",
    workspace_snapshot_digest: digest("workspace-snapshot"),
    restore_operation_id: "instrument.restore.v1",
    restore_operation_digest: digest("restore-operation"),
    cleanup_plan_digest: digest("cleanup-plan"),
    terminal_emission_state: "inhibited",
    allowed_terminal_states: ["quarantined", "restored", "unknown_effect"],
    capability_nonce: "cleanup-capability-safety-runtime-1",
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
  const contract = normalizeSafetySupervisorContract({
    version: 1,
    supervisor_ref: "safety-supervisor:safety-runtime-1",
    supervisor_principal_id: "principal:safety-supervisor-1",
    supervisor_signer_key_id: "supervisor-cleanup-key-1",
    trust_root_epoch: 3,
    safety_root_ref: cleanupCapability.safety_root_ref,
    attempt_ref: lease.attempt_ref,
    instrument_ref: lease.instrument_ref,
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    fencing_generation: lease.fencing_generation,
    operation_id: lease.operation_id,
    execution_request_digest: lease.execution_request_digest,
    worker_principal_id: lease.execution_principal_id,
    worker_heartbeat_signer_key_id: "worker-heartbeat-key-1",
    cleanup_capability_digest: cleanupCapability.capability_digest,
    authority_epoch: 7,
    revocation_generation: 2,
    heartbeat_interval_ms: options.watchdogMs || 1000,
    miss_tolerance: 3,
    stop_ack_deadline_ms: options.watchdogMs || 2000,
    containment_mode: "electronic",
    containment_actions: ["rf_interlock", "worker_kill"],
    operator_containment_plan_digest: null,
  });
  function heartbeat(sequence = 1, emittedAt = "2026-07-18T00:00:01.000Z", validUntil = "2026-07-18T00:00:04.000Z") {
    const payload = {
      version: 1,
      heartbeat_ref: `heartbeat:safety-runtime-${sequence}`,
      supervisor_contract_digest: contract.supervisor_contract_digest,
      attempt_ref: lease.attempt_ref,
      instrument_ref: lease.instrument_ref,
      lease_id: lease.lease_id,
      fencing_token: lease.fencing_token,
      fencing_generation: lease.fencing_generation,
      operation_id: lease.operation_id,
      execution_request_digest: lease.execution_request_digest,
      worker_principal_id: lease.execution_principal_id,
      heartbeat_sequence: sequence,
      authority_epoch: contract.authority_epoch,
      revocation_generation: contract.revocation_generation,
      emitted_at: emittedAt,
      valid_until: validUntil,
    };
    return {
      ...payload,
      authentication: signatureEnvelope(payload, "worker-heartbeat-key-1", `heartbeat-${sequence}`),
    };
  }
  const bootstrapPayload = {
    version: 1,
    bootstrap_ref: "recovery-bootstrap:safety-runtime-1",
    bootstrap_source: "safety_supervisor",
    supervisor_principal_id: contract.supervisor_principal_id,
    supervisor_signer_key_id: contract.supervisor_signer_key_id,
    trust_root_epoch: contract.trust_root_epoch,
    recovery_principal_id: cleanupCapability.recovery_principal_id,
    recovery_receipt_signer_key_id: "cleanup-worker-receipt-key-1",
    safety_root_ref: cleanupCapability.safety_root_ref,
    safety_root_status: "trusted",
    cleanup_capability_digest: cleanupCapability.capability_digest,
    source_execution_request_digest: cleanupCapability.source_execution_request_digest,
    attempt_ref: contract.attempt_ref,
    instrument_ref: cleanupCapability.instrument_ref,
    enrolled_device_identity_digest: digest("enrolled-device"),
    provider_manifest_digest: digest("provider-manifest"),
    recovery_worker_binary_digest: digest("recovery-worker-binary"),
    lease_id: cleanupCapability.lease_id,
    fencing_token: cleanupCapability.fencing_token,
    fencing_generation: contract.fencing_generation,
    workspace_snapshot_ref: cleanupCapability.workspace_snapshot_ref,
    workspace_snapshot_digest: cleanupCapability.workspace_snapshot_digest,
    restore_operation_id: cleanupCapability.restore_operation_id,
    restore_operation_digest: cleanupCapability.restore_operation_digest,
    cleanup_plan_digest: cleanupCapability.cleanup_plan_digest,
    expected_terminal_state_digest: digest("expected-terminal-state"),
    snapshot_materialization_capability_ref: "vault-capability:safety-runtime-1",
    snapshot_materialization_capability_digest: digest("snapshot-materialization-capability"),
    allowed_operation_ids: [cleanupCapability.restore_operation_id],
    allowed_materialization_refs: [cleanupCapability.workspace_snapshot_ref],
    agent_channel_enabled: false,
    administration_enabled: false,
    destruction_enabled: false,
    one_time: true,
    nonce: "recovery-bootstrap-safety-runtime-1",
    not_before: options.bootstrapNotBefore || "2026-07-18T00:00:01.000Z",
    expires_at: options.bootstrapExpiresAt || "2026-07-18T00:00:50.000Z",
  };
  const bootstrap = {
    ...bootstrapPayload,
    authentication: signatureEnvelope(
      bootstrapPayload,
      contract.supervisor_signer_key_id,
      "recovery-bootstrap",
    ),
  };
  const verifiedBootstrap = projectVerifiedRecoveryWorkerBootstrap(
    bootstrap,
    cleanupCapability,
    effectRegistry,
    contract,
    trustedVerification(bootstrap.authentication),
  );
  return {
    anchor,
    clock,
    contract,
    heartbeat,
    lease,
    masterKey,
    openStore,
    root,
    runtimeId,
    sessionNucleusHash,
    store,
    verifiedBootstrap,
  };
}

function boundAuthority(contract, overrides = {}) {
  return {
    supervisor_contract_digest: contract.supervisor_contract_digest,
    authority_epoch: contract.authority_epoch,
    revocation_generation: contract.revocation_generation,
    ...overrides,
  };
}

function boundProvider(contract, overrides = {}) {
  return {
    supervisor_contract_digest: contract.supervisor_contract_digest,
    instrument_ref: contract.instrument_ref,
    lease_id: contract.lease_id,
    fencing_token: contract.fencing_token,
    fencing_generation: contract.fencing_generation,
    operation_id: contract.operation_id,
    reachable: true,
    ...overrides,
  };
}

function boundWorker(contract, overrides = {}) {
  return {
    supervisor_contract_digest: contract.supervisor_contract_digest,
    worker_principal_id: contract.worker_principal_id,
    lease_id: contract.lease_id,
    fencing_token: contract.fencing_token,
    fencing_generation: contract.fencing_generation,
    alive: true,
    ...overrides,
  };
}

function observationPort(contract, overrides = {}) {
  return createSafetyObservationPort({
    readAuthorityState: overrides.readAuthorityState
      || (() => boundAuthority(contract)),
    readProviderState: overrides.readProviderState
      || (() => boundProvider(contract)),
    readWorkerState: overrides.readWorkerState
      || (() => boundWorker(contract)),
    verifyHeartbeat: overrides.verifyHeartbeat
      || ((value) => trustedVerification(value.authentication)),
  });
}

function confirmedContainment() {
  return createInstrumentContainmentPort({
    handlers: {
      rf_interlock: () => ({ outcome: "confirmed", receipt_digest: digest("rf-interlock") }),
      worker_kill: () => ({ outcome: "confirmed", receipt_digest: digest("worker-kill") }),
    },
  });
}

test("safety capabilities are closed and the runtime exposes no effectful provider surface", (t) => {
  const f = fixture(t);
  assert.throws(
    () => createSafetyObservationPort({
      readAuthorityState() {},
      readProviderState() {},
      readWorkerState() {},
      verifyHeartbeat() {},
      execute() {},
    }),
    /unknown fields: execute/,
  );
  assert.throws(
    () => createInstrumentContainmentPort({ handlers: { device_dfu() {} } }),
    /unknown containment actions: device_dfu/,
  );
  const supervisor = createInstrumentSafetySupervisor({
    store: f.store,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: confirmedContainment(),
    now: f.clock,
  });
  assert.deepEqual(Object.keys(supervisor).sort(), [
    "launchPrecommittedRecovery",
    "notifyWorkerExit",
    "poll",
    "reconcileStartup",
  ]);
  assert.equal(Object.keys(supervisor).some((name) => (
    /execute|maintain|admin|destroy/i.test(name)
  )), false);
});

test("a healthy signed heartbeat is verified from independent bound observations", async (t) => {
  const f = fixture(t);
  f.clock.set("2026-07-18T00:00:03.000Z");
  let verificationCalls = 0;
  let containmentCalls = 0;
  const supervisor = createInstrumentSafetySupervisor({
    store: f.store,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract, {
      verifyHeartbeat(value) {
        verificationCalls += 1;
        return trustedVerification(value.authentication);
      },
    }),
    containmentPort: createInstrumentContainmentPort({
      handlers: {
        rf_interlock() { containmentCalls += 1; },
        worker_kill() { containmentCalls += 1; },
      },
    }),
    now: f.clock,
  });
  const result = await supervisor.poll({ heartbeat: f.heartbeat() });
  assert.equal(result.evaluation.decision, "continue");
  assert.deepEqual(result.observation_failures, []);
  assert.equal(result.fence_status, "not_required");
  assert.equal(result.emission_state, "unknown");
  assert.equal(verificationCalls, 1);
  assert.equal(containmentCalls, 0);
  assert.equal(f.anchor.state.generation, 2, "constructor durably enrolls the supervisor contract");
});

test("a stop decision commits the external fence before exact containment and launches only the precommit", async (t) => {
  const f = fixture(t);
  f.clock.set("2026-07-18T00:00:06.000Z");
  const events = [];
  const containmentPort = createInstrumentContainmentPort({
    handlers: {
      rf_interlock(context) {
        assert.equal(
          f.anchor.state.generation,
          5,
          "external fence and all action claims precede containment",
        );
        assert.equal(f.store.snapshot().leases[0].state, "fenced");
        assert.equal(Object.isFrozen(context), true);
        events.push("rf_interlock");
        return { outcome: "confirmed", receipt_digest: digest("rf-interlock-receipt") };
      },
      worker_kill(context) {
        assert.equal(f.anchor.state.generation, 5);
        assert.equal(context.lease_id, f.lease.lease_id);
        events.push("worker_kill");
        return { outcome: "confirmed", receipt_digest: digest("worker-kill-receipt") };
      },
    },
  });
  const recoveryPort = createPrecommittedRecoveryLauncherPort({
    verifiedBootstrap: f.verifiedBootstrap,
    launch(...args) {
      assert.equal(args.length, 1, "launcher receives only the verified bootstrap");
      assert.equal(Object.isFrozen(args[0]), true);
      assert.equal(args[0].lease_id, f.lease.lease_id);
      assert.equal(Object.prototype.hasOwnProperty.call(args[0], "agent_parameters"), false);
      events.push("recovery");
      return { outcome: "launched", launch_receipt_digest: digest("launch-receipt") };
    },
  });
  const supervisor = createInstrumentSafetySupervisor({
    store: f.store,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract, {
      readWorkerState: () => boundWorker(f.contract, { alive: false }),
    }),
    containmentPort,
    recoveryLauncherPort: recoveryPort,
    now: f.clock,
  });
  const result = await supervisor.poll({ heartbeat: null });
  assert.equal(result.evaluation.decision, "stop_fence_cleanup");
  assert.equal(result.fence_status, "committed");
  assert.equal(result.lease_state, "fenced");
  assert.deepEqual(events, ["rf_interlock", "worker_kill", "recovery"]);
  assert.equal(result.containment_complete, true);
  assert.equal(result.recovery_launch.outcome, "launched");
  assert.equal(result.quarantine_required, false);
  assert.equal(result.emission_state, "unknown", "containment never fabricates inhibited emission");
  assert.equal(result.automatic_retry_allowed, false);
});

test("invalid heartbeat proof and detached observations fail closed; failed or missing containment stays quarantinable", async (t) => {
  const f = fixture(t);
  f.clock.set("2026-07-18T00:00:03.000Z");
  let recoveryCalls = 0;
  const recoveryPort = createPrecommittedRecoveryLauncherPort({
    verifiedBootstrap: f.verifiedBootstrap,
    launch() {
      recoveryCalls += 1;
      return { outcome: "launched", launch_receipt_digest: digest("should-not-launch") };
    },
  });
  const supervisor = createInstrumentSafetySupervisor({
    store: f.store,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract, {
      readAuthorityState: () => boundAuthority(f.contract, {
        supervisor_contract_digest: digest("detached-supervisor"),
      }),
      verifyHeartbeat(value) {
        return {
          ...trustedVerification(value.authentication),
          verified_proof_digest: digest("forged-proof"),
        };
      },
    }),
    containmentPort: createInstrumentContainmentPort({
      handlers: {
        rf_interlock() {
          return {
            outcome: "confirmed",
            receipt_digest: digest("unverified-interlock-claim"),
            emission_state: "inhibited",
          };
        },
        worker_kill() {
          return { outcome: "unavailable" };
        },
      },
    }),
    recoveryLauncherPort: recoveryPort,
    now: f.clock,
  });
  const result = await supervisor.poll({ heartbeat: f.heartbeat() });
  assert.equal(result.evaluation.decision, "stop_fence_cleanup");
  assert.deepEqual(result.observation_failures, [
    "authority_state_unavailable",
    "heartbeat_invalid",
  ]);
  assert.deepEqual(result.containment_results.map(({ action, outcome }) => ({ action, outcome })), [
    { action: "rf_interlock", outcome: "ambiguous" },
    { action: "worker_kill", outcome: "unavailable" },
  ]);
  assert.equal(result.lease_state, "fenced");
  assert.equal(result.containment_complete, false);
  assert.equal(result.recovery_launch, null);
  assert.equal(result.quarantine_required, true);
  assert.equal(result.emission_state, "unknown");
  assert.equal(recoveryCalls, 0);
});

test("a failed durable fence suppresses every provider, containment, and cleanup callback", async (t) => {
  const f = fixture(t);
  f.clock.set("2026-07-18T00:00:06.000Z");
  let calls = 0;
  const refusingStore = {
    snapshot: f.store.snapshot,
    readLease: f.store.readLease,
    fenceLease() { throw new Error("injected fence failure"); },
    registerSafetySupervisor: f.store.registerSafetySupervisor,
    claimContainmentAction: f.store.claimContainmentAction,
    completeContainmentAction: f.store.completeContainmentAction,
    claimRecoveryLaunch: f.store.claimRecoveryLaunch,
    completeRecoveryLaunch: f.store.completeRecoveryLaunch,
    runEffectOnce() { calls += 100; },
  };
  const supervisor = createInstrumentSafetySupervisor({
    store: refusingStore,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: createInstrumentContainmentPort({
      handlers: {
        rf_interlock() { calls += 1; },
        worker_kill() { calls += 1; },
      },
    }),
    recoveryLauncherPort: createPrecommittedRecoveryLauncherPort({
      verifiedBootstrap: f.verifiedBootstrap,
      launch() { calls += 1; },
    }),
    now: f.clock,
  });
  await assert.rejects(supervisor.poll({ heartbeat: null }), /injected fence failure/);
  assert.equal(calls, 0);
  assert.equal(f.store.snapshot().leases[0].state, "held");
});

test("startup and worker-exit races fence and contain once without touching dispatch", async (t) => {
  const f = fixture(t);
  f.clock.set("2026-07-18T00:00:03.000Z");
  const storeReads = [];
  const narrowStoreProbe = new Proxy(f.store, {
    get(target, property, receiver) {
      storeReads.push(property);
      return Reflect.get(target, property, receiver);
    },
  });
  const calls = [];
  const supervisor = createInstrumentSafetySupervisor({
    store: narrowStoreProbe,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: createInstrumentContainmentPort({
      handlers: {
        async rf_interlock() {
          calls.push("rf_interlock");
          await Promise.resolve();
          return { outcome: "confirmed", receipt_digest: digest("race-rf") };
        },
        worker_kill() {
          calls.push("worker_kill");
          return { outcome: "confirmed", receipt_digest: digest("race-kill") };
        },
      },
    }),
    recoveryLauncherPort: createPrecommittedRecoveryLauncherPort({
      verifiedBootstrap: f.verifiedBootstrap,
      launch() {
        calls.push("recovery");
        return { outcome: "launched", launch_receipt_digest: digest("race-launch") };
      },
    }),
    now: f.clock,
  });
  const [startup, workerExit] = await Promise.all([
    supervisor.reconcileStartup(),
    supervisor.notifyWorkerExit(),
  ]);
  assert.equal(startup.fence_status, "committed");
  assert.equal(workerExit.fence_status, "already_non_executable");
  assert.deepEqual(calls, ["rf_interlock", "worker_kill", "recovery"]);
  assert.deepEqual([...new Set(storeReads)].sort(), [
    "claimContainmentAction",
    "claimRecoveryLaunch",
    "completeContainmentAction",
    "completeRecoveryLaunch",
    "fenceLease",
    "readLease",
    "registerSafetySupervisor",
    "snapshot",
  ]);
  assert.equal(f.anchor.state.generation, 9);
  await assert.rejects(
    supervisor.reconcileStartup({ execute: "representation.write" }),
    /accepts no parameters/,
  );
  await assert.rejects(
    supervisor.launchPrecommittedRecovery({ operation_id: "instrument.administer.v1" }),
    /accepts no agent parameters/,
  );
  const sameLaunch = await supervisor.launchPrecommittedRecovery();
  assert.equal(sameLaunch.outcome, "launched");
  assert.deepEqual(calls, ["rf_interlock", "worker_kill", "recovery"]);
});

test("heartbeat sequence skips are rejected and cannot keep a worker lease alive", async (t) => {
  const f = fixture(t);
  f.clock.set("2026-07-18T00:00:03.000Z");
  const supervisor = createInstrumentSafetySupervisor({
    store: f.store,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: confirmedContainment(),
    now: f.clock,
  });
  const first = await supervisor.poll({ heartbeat: f.heartbeat() });
  assert.equal(first.evaluation.decision, "continue");
  const skipped = await supervisor.poll({
    heartbeat: f.heartbeat(
      3,
      "2026-07-18T00:00:02.000Z",
      "2026-07-18T00:00:05.000Z",
    ),
  });
  assert.equal(skipped.evaluation.decision, "stop_fence_cleanup");
  assert.deepEqual(skipped.observation_failures, ["heartbeat_invalid"]);
  assert.equal(skipped.lease_state, "fenced");
  assert.equal(skipped.quarantine_required, true);
});

test("a structurally altered recovery projection cannot enter the launcher port", (t) => {
  const f = fixture(t);
  const detached = {
    ...f.verifiedBootstrap,
    lease_id: "lease-detached-2",
  };
  assert.throws(
    () => createPrecommittedRecoveryLauncherPort({
      verifiedBootstrap: detached,
      launch() {},
    }),
    /was not issued by the recovery-bootstrap verifier/,
  );
});

test("an alien false fence is rejected before any containment or recovery effect", async (t) => {
  const f = fixture(t);
  f.clock.set("2026-07-18T00:00:06.000Z");
  let effects = 0;
  const current = f.store.snapshot().leases[0];
  const detachedFence = {
    ...current,
    attempt_ref: "attempt:alien-false-fence",
    state: "fenced",
    sequence: current.sequence + 1,
    updated_at: "2026-07-18T00:00:06.000Z",
  };
  delete detachedFence.lease_digest;
  const falseFenceStore = {
    ...f.store,
    fenceLease() { return detachedFence; },
  };
  const supervisor = createInstrumentSafetySupervisor({
    store: falseFenceStore,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: createInstrumentContainmentPort({
      handlers: {
        rf_interlock() { effects += 1; },
        worker_kill() { effects += 1; },
      },
    }),
    recoveryLauncherPort: createPrecommittedRecoveryLauncherPort({
      verifiedBootstrap: f.verifiedBootstrap,
      launch() { effects += 1; },
    }),
    now: f.clock,
  });

  await assert.rejects(
    supervisor.poll({ heartbeat: null }),
    /fenced_lease\.attempt_ref binding drift/,
  );
  assert.equal(effects, 0);
  assert.equal(f.store.snapshot().leases[0].state, "held");
});

test("prototype pollution cannot provide an omitted containment handler", (t) => {
  const f = fixture(t);
  let inheritedExecutions = 0;
  Object.defineProperty(Object.prototype, "worker_kill", {
    configurable: true,
    value() { inheritedExecutions += 1; },
  });
  try {
    const containmentPort = createInstrumentContainmentPort({
      handlers: {
        rf_interlock() {
          return { outcome: "confirmed", receipt_digest: digest("polluted-rf") };
        },
      },
    });
    assert.deepEqual(containmentPort.available_actions, ["rf_interlock"]);
    assert.throws(
      () => createInstrumentSafetySupervisor({
        store: f.store,
        supervisorContract: f.contract,
        observationPort: observationPort(f.contract),
        containmentPort,
        now: f.clock,
      }),
      /containment port is missing required actions: worker_kill/,
    );
  } finally {
    delete Object.prototype.worker_kill;
  }
  assert.equal(inheritedExecutions, 0);
});

test("a containment port missing any declared handler is rejected at construction", (t) => {
  const f = fixture(t);
  assert.throws(
    () => createInstrumentSafetySupervisor({
      store: f.store,
      supervisorContract: f.contract,
      observationPort: observationPort(f.contract),
      containmentPort: createInstrumentContainmentPort({
        handlers: {
          worker_kill() {
            return { outcome: "confirmed", receipt_digest: digest("only-worker-kill") };
          },
        },
      }),
      now: f.clock,
    }),
    /containment port is missing required actions: rf_interlock/,
  );
});

test("the safety clock is sampled after asynchronous observations settle", async (t) => {
  const f = fixture(t);
  f.clock.set("2026-07-18T00:00:03.000Z");
  const supervisor = createInstrumentSafetySupervisor({
    store: f.store,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract, {
      async readAuthorityState() {
        await Promise.resolve();
        f.clock.set("2026-07-18T00:00:06.000Z");
        return boundAuthority(f.contract);
      },
    }),
    containmentPort: confirmedContainment(),
    now: f.clock,
  });

  const result = await supervisor.poll({ heartbeat: f.heartbeat() });
  assert.equal(result.evaluation.observed_at, "2026-07-18T00:00:06.000Z");
  assert.equal(result.evaluation.decision, "stop_fence_cleanup");
  assert.ok(result.evaluation.reasons.includes("deadman_missed"));
  assert.equal(result.lease_state, "fenced");
});

test("containment crossing recovery expiry suppresses the precommitted launch", async (t) => {
  const f = fixture(t);
  f.clock.set("2026-07-18T00:00:06.000Z");
  let launches = 0;
  const supervisor = createInstrumentSafetySupervisor({
    store: f.store,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: createInstrumentContainmentPort({
      handlers: {
        rf_interlock() {
          f.clock.set("2026-07-18T00:00:51.000Z");
          return { outcome: "confirmed", receipt_digest: digest("expiry-rf") };
        },
        worker_kill() {
          return { outcome: "confirmed", receipt_digest: digest("expiry-kill") };
        },
      },
    }),
    recoveryLauncherPort: createPrecommittedRecoveryLauncherPort({
      verifiedBootstrap: f.verifiedBootstrap,
      launch() {
        launches += 1;
        return { outcome: "launched", launch_receipt_digest: digest("expired-launch") };
      },
    }),
    now: f.clock,
  });

  const result = await supervisor.poll({ heartbeat: null });
  assert.equal(result.containment_complete, true);
  assert.equal(result.recovery_launch.outcome, "unavailable");
  assert.equal(result.quarantine_required, true);
  assert.equal(launches, 0);
  assert.deepEqual(f.store.snapshot().recovery_launch_states, []);
});

test("recovery cannot launch before the verified bootstrap not_before", async (t) => {
  const f = fixture(t, {
    bootstrapNotBefore: "2026-07-18T00:00:10.000Z",
  });
  f.clock.set("2026-07-18T00:00:06.000Z");
  let launches = 0;
  const supervisor = createInstrumentSafetySupervisor({
    store: f.store,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: confirmedContainment(),
    recoveryLauncherPort: createPrecommittedRecoveryLauncherPort({
      verifiedBootstrap: f.verifiedBootstrap,
      launch() {
        launches += 1;
        return { outcome: "launched", launch_receipt_digest: digest("early-launch") };
      },
    }),
    now: f.clock,
  });

  const result = await supervisor.poll({ heartbeat: null });
  assert.equal(f.verifiedBootstrap.not_before, "2026-07-18T00:00:10.000Z");
  assert.equal(result.containment_complete, true);
  assert.equal(result.recovery_launch.outcome, "unavailable");
  assert.equal(result.quarantine_required, true);
  assert.equal(launches, 0);
  assert.deepEqual(f.store.snapshot().recovery_launch_states, []);
});

test("durable claims prevent duplicate containment and recovery across supervisors and restart", async (t) => {
  const f = fixture(t);
  const secondStore = f.openStore();
  f.clock.set("2026-07-18T00:00:06.000Z");
  const effects = { rf_interlock: 0, worker_kill: 0, recovery: 0 };
  function containmentPort() {
    return createInstrumentContainmentPort({
      handlers: {
        async rf_interlock() {
          effects.rf_interlock += 1;
          await Promise.resolve();
          return { outcome: "confirmed", receipt_digest: digest("multi-rf") };
        },
        async worker_kill() {
          effects.worker_kill += 1;
          await Promise.resolve();
          return { outcome: "confirmed", receipt_digest: digest("multi-kill") };
        },
      },
    });
  }
  function recoveryPort() {
    return createPrecommittedRecoveryLauncherPort({
      verifiedBootstrap: f.verifiedBootstrap,
      async launch() {
        effects.recovery += 1;
        await Promise.resolve();
        return { outcome: "launched", launch_receipt_digest: digest("multi-recovery") };
      },
    });
  }
  const first = createInstrumentSafetySupervisor({
    store: f.store,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: containmentPort(),
    recoveryLauncherPort: recoveryPort(),
    now: f.clock,
  });
  const second = createInstrumentSafetySupervisor({
    store: secondStore,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: containmentPort(),
    recoveryLauncherPort: recoveryPort(),
    now: f.clock,
  });

  await Promise.all([
    first.poll({ heartbeat: null }),
    second.poll({ heartbeat: null }),
  ]);
  assert.deepEqual(effects, { rf_interlock: 1, worker_kill: 1, recovery: 1 });

  secondStore.close();
  const restartedStore = f.openStore();
  const restarted = createInstrumentSafetySupervisor({
    store: restartedStore,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: containmentPort(),
    recoveryLauncherPort: recoveryPort(),
    now: f.clock,
  });
  const reconciled = await restarted.reconcileStartup();
  assert.equal(reconciled.containment_complete, true);
  assert.equal(reconciled.recovery_launch.outcome, "launched");
  assert.deepEqual(effects, { rf_interlock: 1, worker_kill: 1, recovery: 1 });
});

test("a lease renewal won during fencing is re-read and the renewed lease is fenced", async (t) => {
  const f = fixture(t);
  f.clock.set("2026-07-18T00:00:03.000Z");
  let injectedRenewal = false;
  const racingStore = {
    ...f.store,
    fenceLease(request) {
      if (!injectedRenewal) {
        injectedRenewal = true;
        f.clock.set("2026-07-18T00:00:04.000Z");
        f.store.renewLease({
          version: 1,
          lease_id: f.lease.lease_id,
          instrument_ref: f.lease.instrument_ref,
          owner_principal_id: f.lease.owner_principal_id,
          execution_principal_id: f.lease.execution_principal_id,
          fencing_token: f.lease.fencing_token,
          fencing_generation: f.lease.fencing_generation,
          expected_sequence: 0,
          renewed_at: "2026-07-18T00:00:04.000Z",
          heartbeat_deadline: "2026-07-18T00:00:08.000Z",
          expires_at: "2026-07-18T00:01:10.000Z",
        });
      }
      return f.store.fenceLease(request);
    },
  };
  const supervisor = createInstrumentSafetySupervisor({
    store: racingStore,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract, {
      readWorkerState: () => boundWorker(f.contract, { alive: false }),
    }),
    containmentPort: confirmedContainment(),
    now: f.clock,
  });

  const result = await supervisor.poll({ heartbeat: null });
  const fenced = f.store.snapshot().leases[0];
  assert.equal(injectedRenewal, true);
  assert.equal(result.fence_status, "committed");
  assert.equal(fenced.state, "fenced");
  assert.equal(fenced.sequence, 2);
  assert.equal(fenced.expires_at, "2026-07-18T00:01:10.000Z");
});

test("hung observation and containment handlers are watchdog-bounded independently", {
  timeout: 10_000,
}, async (t) => {
  const f = fixture(t, { watchdogMs: 20 });
  f.clock.set("2026-07-18T00:00:06.000Z");
  let workerKillCalls = 0;
  let lateInterlockSettled;
  const lateInterlockSettlement = new Promise((resolve) => {
    lateInterlockSettled = resolve;
  });
  const supervisor = createInstrumentSafetySupervisor({
    store: f.store,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract, {
      readAuthorityState: () => new Promise(() => {}),
    }),
    containmentPort: createInstrumentContainmentPort({
      handlers: {
        rf_interlock: () => new Promise((resolve) => {
          // A late positive acknowledgement is hostile: it must lose to the
          // 20 ms watchdog and cannot rewrite the durable ambiguous outcome.
          setTimeout(() => {
            resolve({ outcome: "confirmed", receipt_digest: digest("late-watchdog-interlock") });
            lateInterlockSettled();
          }, 200);
        }),
        worker_kill() {
          workerKillCalls += 1;
          return { outcome: "confirmed", receipt_digest: digest("watchdog-kill") };
        },
      },
    }),
    now: f.clock,
  });

  const result = await supervisor.poll({ heartbeat: null });
  assert.deepEqual(result.observation_failures, ["authority_state_unavailable"]);
  assert.deepEqual(result.containment_results.map(({ action, outcome }) => ({ action, outcome })), [
    { action: "rf_interlock", outcome: "ambiguous" },
    { action: "worker_kill", outcome: "confirmed" },
  ]);
  assert.equal(workerKillCalls, 1);
  assert.equal(result.containment_complete, false);
  assert.equal(result.quarantine_required, true);

  await lateInterlockSettlement;
  const durableInterlock = f.store.snapshot().containment_action_states.find(
    (state) => state.action === "rf_interlock",
  );
  assert.equal(durableInterlock.state, "completed");
  assert.equal(durableInterlock.outcome, "ambiguous");
  assert.equal(durableInterlock.receipt_digest, null);
});

test("containment effect then throw is durably ambiguous and is not retried after restart", async (t) => {
  const f = fixture(t);
  f.clock.set("2026-07-18T00:00:06.000Z");
  const effects = { rf_interlock: 0, worker_kill: 0 };
  const first = createInstrumentSafetySupervisor({
    store: f.store,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: createInstrumentContainmentPort({
      handlers: {
        rf_interlock() {
          effects.rf_interlock += 1;
          throw new Error("response lost after interlock effect");
        },
        worker_kill() {
          effects.worker_kill += 1;
          return { outcome: "confirmed", receipt_digest: digest("throw-kill") };
        },
      },
    }),
    now: f.clock,
  });

  const firstResult = await first.poll({ heartbeat: null });
  assert.deepEqual(firstResult.containment_results.map(({ action, outcome }) => ({ action, outcome })), [
    { action: "rf_interlock", outcome: "ambiguous" },
    { action: "worker_kill", outcome: "confirmed" },
  ]);
  const durableAmbiguity = f.store.snapshot().containment_action_states.find(
    (state) => state.action === "rf_interlock",
  );
  assert.equal(durableAmbiguity.state, "completed");
  assert.equal(durableAmbiguity.outcome, "ambiguous");

  const restartedStore = f.openStore();
  const restarted = createInstrumentSafetySupervisor({
    store: restartedStore,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: createInstrumentContainmentPort({
      handlers: {
        rf_interlock() { effects.rf_interlock += 100; },
        worker_kill() { effects.worker_kill += 100; },
      },
    }),
    now: f.clock,
  });
  const reconciled = await restarted.reconcileStartup();
  assert.equal(reconciled.containment_complete, false);
  assert.deepEqual(effects, { rf_interlock: 1, worker_kill: 1 });
});

test("recovery effect then throw is durably ambiguous and is not retried after restart", async (t) => {
  const f = fixture(t);
  f.clock.set("2026-07-18T00:00:06.000Z");
  const effects = { rf_interlock: 0, worker_kill: 0, recovery: 0 };
  function countedContainment(increment) {
    return createInstrumentContainmentPort({
      handlers: {
        rf_interlock() {
          effects.rf_interlock += increment;
          return { outcome: "confirmed", receipt_digest: digest("throw-recovery-rf") };
        },
        worker_kill() {
          effects.worker_kill += increment;
          return { outcome: "confirmed", receipt_digest: digest("throw-recovery-kill") };
        },
      },
    });
  }
  const first = createInstrumentSafetySupervisor({
    store: f.store,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: countedContainment(1),
    recoveryLauncherPort: createPrecommittedRecoveryLauncherPort({
      verifiedBootstrap: f.verifiedBootstrap,
      launch() {
        effects.recovery += 1;
        throw new Error("response lost after recovery launch");
      },
    }),
    now: f.clock,
  });

  const firstResult = await first.poll({ heartbeat: null });
  assert.equal(firstResult.recovery_launch.outcome, "ambiguous");
  assert.equal(f.store.snapshot().recovery_launch_states[0].state, "completed");
  assert.equal(f.store.snapshot().recovery_launch_states[0].outcome, "ambiguous");

  const restartedStore = f.openStore();
  const restarted = createInstrumentSafetySupervisor({
    store: restartedStore,
    supervisorContract: f.contract,
    observationPort: observationPort(f.contract),
    containmentPort: countedContainment(100),
    recoveryLauncherPort: createPrecommittedRecoveryLauncherPort({
      verifiedBootstrap: f.verifiedBootstrap,
      launch() {
        effects.recovery += 100;
        return { outcome: "launched", launch_receipt_digest: digest("retry-recovery") };
      },
    }),
    now: f.clock,
  });
  const reconciled = await restarted.reconcileStartup();
  assert.equal(reconciled.recovery_launch.outcome, "ambiguous");
  assert.deepEqual(effects, { rf_interlock: 1, worker_kill: 1, recovery: 1 });
});
