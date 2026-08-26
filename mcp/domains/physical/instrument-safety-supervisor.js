"use strict";

// Plane-PH PH-S7 independent safety-supervisor runtime.
//
// This module is deliberately not an MCP tool. It retains only a two-method
// view of the durable lease store, reads health through separately constructed
// observation capabilities, and can invoke only containment actions that were
// predeclared by the immutable supervisor contract. It has no provider execute,
// maintain, administration, destruction, or generic command surface.

const {
  CONTAINMENT_ACTIONS,
  assertVerifiedRecoveryBootstrapProjection,
  assertDeadmanHeartbeatTransition,
  evaluateSafetySupervisor,
  normalizeInstrumentLease,
  normalizeSafetySupervisorContract,
  normalizeSignedDeadmanHeartbeat,
} = require("./instrument-lease-contract.js");

const SAFETY_SUPERVISOR_RUNTIME_VERSION = 1;
const CONTAINMENT_OUTCOMES = Object.freeze(["ambiguous", "confirmed", "failed", "unavailable"]);
const RECOVERY_LAUNCH_OUTCOMES = Object.freeze(["ambiguous", "launched", "failed", "unavailable"]);
const HASH_PATTERN = /^[a-f0-9]{64}$/;

const observationPorts = new WeakMap();
const containmentPorts = new WeakMap();
const recoveryLauncherPorts = new WeakMap();

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, requiredFields, optionalFields = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const allowed = new Set([...requiredFields, ...optionalFields]);
  const unknown = Object.keys(value).filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = requiredFields.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  return value;
}

function assertFunction(value, label) {
  if (typeof value !== "function") throw new Error(`${label} must be a function`);
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertInteger(value, label, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new Error(`${label} must be a safe integer >= ${min}`);
  }
  return value;
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function assertCanonicalTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function sameBinding(actual, expected, fields, label) {
  for (const field of fields) {
    if (actual[field] !== expected[field]) throw new Error(`${label}.${field} binding drift`);
  }
  return actual;
}

function createSafetyObservationPort(input) {
  assertClosedObject(input, "safety_observation_port", [
    "readAuthorityState",
    "readProviderState",
    "readWorkerState",
    "verifyHeartbeat",
  ]);
  const implementation = Object.freeze({
    readAuthorityState: assertFunction(
      input.readAuthorityState,
      "safety_observation_port.readAuthorityState",
    ),
    readProviderState: assertFunction(
      input.readProviderState,
      "safety_observation_port.readProviderState",
    ),
    readWorkerState: assertFunction(
      input.readWorkerState,
      "safety_observation_port.readWorkerState",
    ),
    verifyHeartbeat: assertFunction(
      input.verifyHeartbeat,
      "safety_observation_port.verifyHeartbeat",
    ),
  });
  const port = Object.freeze({
    version: SAFETY_SUPERVISOR_RUNTIME_VERSION,
    capability_kind: "safety_observation",
  });
  observationPorts.set(port, implementation);
  return port;
}

function normalizeHandlerMap(input, label) {
  if (!isPlainObject(input)) throw new Error(`${label} must be an object`);
  const names = Object.keys(input).sort();
  const unknown = names.filter((name) => !CONTAINMENT_ACTIONS.includes(name));
  if (unknown.length > 0) throw new Error(`${label} has unknown containment actions: ${unknown.join(", ")}`);
  const handlers = Object.create(null);
  for (const name of names) handlers[name] = assertFunction(input[name], `${label}.${name}`);
  return { handlers: Object.freeze(handlers), names: Object.freeze(names) };
}

function createInstrumentContainmentPort(input) {
  assertClosedObject(input, "instrument_containment_port", ["handlers"]);
  const { handlers, names } = normalizeHandlerMap(
    input.handlers,
    "instrument_containment_port.handlers",
  );
  const port = Object.freeze({
    version: SAFETY_SUPERVISOR_RUNTIME_VERSION,
    capability_kind: "instrument_containment",
    available_actions: names,
  });
  containmentPorts.set(port, handlers);
  return port;
}

function createPrecommittedRecoveryLauncherPort(input) {
  assertClosedObject(input, "precommitted_recovery_launcher_port", [
    "verifiedBootstrap",
    "launch",
  ]);
  const bootstrap = assertVerifiedRecoveryBootstrapProjection(
    input.verifiedBootstrap,
    "precommitted_recovery_launcher_port.verifiedBootstrap",
  );
  const implementation = Object.freeze({
    bootstrap,
    launch: assertFunction(input.launch, "precommitted_recovery_launcher_port.launch"),
  });
  const port = Object.freeze({
    version: SAFETY_SUPERVISOR_RUNTIME_VERSION,
    capability_kind: "precommitted_recovery_launcher",
    verified_bootstrap_digest: bootstrap.verified_bootstrap_digest,
  });
  recoveryLauncherPorts.set(port, implementation);
  return port;
}

function normalizeAuthorityState(input, contract) {
  assertClosedObject(input, "authority_state", [
    "supervisor_contract_digest",
    "authority_epoch",
    "revocation_generation",
  ]);
  sameBinding(input, contract, ["supervisor_contract_digest"], "authority_state");
  return Object.freeze({
    authority_epoch: assertInteger(input.authority_epoch, "authority_state.authority_epoch", 1),
    revocation_generation: assertInteger(
      input.revocation_generation,
      "authority_state.revocation_generation",
    ),
  });
}

function normalizeProviderState(input, contract) {
  assertClosedObject(input, "provider_state", [
    "supervisor_contract_digest",
    "instrument_ref",
    "lease_id",
    "fencing_token",
    "fencing_generation",
    "operation_id",
    "reachable",
  ]);
  sameBinding(input, contract, [
    "supervisor_contract_digest",
    "instrument_ref",
    "lease_id",
    "fencing_token",
    "fencing_generation",
    "operation_id",
  ], "provider_state");
  return Object.freeze({ reachable: assertBoolean(input.reachable, "provider_state.reachable") });
}

function normalizeWorkerState(input, contract) {
  assertClosedObject(input, "worker_state", [
    "supervisor_contract_digest",
    "worker_principal_id",
    "lease_id",
    "fencing_token",
    "fencing_generation",
    "alive",
  ]);
  sameBinding(input, contract, [
    "supervisor_contract_digest",
    "worker_principal_id",
    "lease_id",
    "fencing_token",
    "fencing_generation",
  ], "worker_state");
  return Object.freeze({ alive: assertBoolean(input.alive, "worker_state.alive") });
}

function normalizeContainmentOutcome(input, action) {
  assertClosedObject(input, `containment_result.${action}`, ["outcome"], ["receipt_digest"]);
  if (!CONTAINMENT_OUTCOMES.includes(input.outcome)) {
    throw new Error(`containment_result.${action}.outcome is invalid`);
  }
  const receiptDigest = input.receipt_digest == null
    ? null
    : assertDigest(input.receipt_digest, `containment_result.${action}.receipt_digest`);
  if (input.outcome === "confirmed" && receiptDigest == null) {
    throw new Error(`containment_result.${action}.confirmed requires a receipt digest`);
  }
  return Object.freeze({ action, outcome: input.outcome, receipt_digest: receiptDigest });
}

function normalizeRecoveryLaunchOutcome(input, bootstrap) {
  assertClosedObject(input, "recovery_launch_result", ["outcome"], ["launch_receipt_digest"]);
  if (!RECOVERY_LAUNCH_OUTCOMES.includes(input.outcome)) {
    throw new Error("recovery_launch_result.outcome is invalid");
  }
  const launchReceiptDigest = input.launch_receipt_digest == null
    ? null
    : assertDigest(input.launch_receipt_digest, "recovery_launch_result.launch_receipt_digest");
  if (input.outcome === "launched" && launchReceiptDigest == null) {
    throw new Error("recovery_launch_result.launched requires a receipt digest");
  }
  return deepFreeze({
    outcome: input.outcome,
    verified_bootstrap_digest: bootstrap.verified_bootstrap_digest,
    launch_receipt_digest: launchReceiptDigest,
  });
}

function normalizeStorePort(store) {
  if (store == null || typeof store !== "object") {
    throw new Error("instrument_safety_supervisor.store must be an object");
  }
  // Deliberately discard all other store methods, including commitDispatch,
  // rather than retaining the broad store object in the runtime. Effect
  // execution belongs behind a separately minted device-owning fenced port.
  return Object.freeze({
    snapshot: assertFunction(store.snapshot, "instrument_safety_supervisor.store.snapshot").bind(store),
    readLease: assertFunction(
      store.readLease,
      "instrument_safety_supervisor.store.readLease",
    ).bind(store),
    fenceLease: assertFunction(
      store.fenceLease,
      "instrument_safety_supervisor.store.fenceLease",
    ).bind(store),
    registerSafetySupervisor: assertFunction(
      store.registerSafetySupervisor,
      "instrument_safety_supervisor.store.registerSafetySupervisor",
    ).bind(store),
    claimContainmentAction: assertFunction(
      store.claimContainmentAction,
      "instrument_safety_supervisor.store.claimContainmentAction",
    ).bind(store),
    completeContainmentAction: assertFunction(
      store.completeContainmentAction,
      "instrument_safety_supervisor.store.completeContainmentAction",
    ).bind(store),
    claimRecoveryLaunch: assertFunction(
      store.claimRecoveryLaunch,
      "instrument_safety_supervisor.store.claimRecoveryLaunch",
    ).bind(store),
    completeRecoveryLaunch: assertFunction(
      store.completeRecoveryLaunch,
      "instrument_safety_supervisor.store.completeRecoveryLaunch",
    ).bind(store),
  });
}

function observationContext(contract) {
  return deepFreeze({
    version: SAFETY_SUPERVISOR_RUNTIME_VERSION,
    supervisor_contract_digest: contract.supervisor_contract_digest,
    attempt_ref: contract.attempt_ref,
    instrument_ref: contract.instrument_ref,
    lease_id: contract.lease_id,
    fencing_token: contract.fencing_token,
    fencing_generation: contract.fencing_generation,
    operation_id: contract.operation_id,
    worker_principal_id: contract.worker_principal_id,
  });
}

function containmentContext(contract, evaluation, lease) {
  return deepFreeze({
    version: SAFETY_SUPERVISOR_RUNTIME_VERSION,
    supervisor_contract_digest: contract.supervisor_contract_digest,
    evaluation_digest: evaluation.evaluation_digest,
    attempt_ref: contract.attempt_ref,
    instrument_ref: contract.instrument_ref,
    lease_id: contract.lease_id,
    fencing_token: contract.fencing_token,
    fencing_generation: contract.fencing_generation,
    operation_id: contract.operation_id,
    fenced_lease_digest: lease.lease_digest,
  });
}

function fallbackDrift(value) {
  return value === 1 ? 2 : 1;
}

function fenceReason(trigger, reasons) {
  if (trigger === "startup") return "startup_reconciliation";
  if (trigger === "worker_exit" || reasons.includes("worker_exit")) return "worker_exit";
  if (reasons.includes("lease_expired")) return "lease_expired";
  if (reasons.includes("provider_unreachable")) return "provider_unreachable";
  if (reasons.includes("revocation_generation_drift")
      || reasons.includes("authority_epoch_drift")) return "revocation";
  return "deadman_missed";
}

function createInstrumentSafetySupervisor(input) {
  assertClosedObject(input, "instrument_safety_supervisor", [
    "store",
    "supervisorContract",
    "observationPort",
    "containmentPort",
  ], ["recoveryLauncherPort", "now"]);
  const store = normalizeStorePort(input.store);
  const contract = normalizeSafetySupervisorContract(
    input.supervisorContract,
    "instrument_safety_supervisor.supervisorContract",
  );
  const observations = observationPorts.get(input.observationPort);
  if (!observations) throw new Error("instrument_safety_supervisor.observationPort is not branded");
  const containment = containmentPorts.get(input.containmentPort);
  if (!containment) throw new Error("instrument_safety_supervisor.containmentPort is not branded");
  const undeclaredActions = Object.keys(containment).filter(
    (action) => !contract.containment_actions.includes(action),
  );
  if (undeclaredActions.length > 0) {
    throw new Error(
      `instrument_safety_supervisor containment port widens authority: ${undeclaredActions.join(", ")}`,
    );
  }
  const missingActions = contract.containment_actions.filter((action) => (
    !Object.prototype.hasOwnProperty.call(containment, action)
  ));
  if (missingActions.length > 0) {
    throw new Error(
      `instrument_safety_supervisor containment port is missing required actions: ${missingActions.join(", ")}`,
    );
  }
  const recovery = input.recoveryLauncherPort == null
    ? null
    : recoveryLauncherPorts.get(input.recoveryLauncherPort);
  if (input.recoveryLauncherPort != null && !recovery) {
    throw new Error("instrument_safety_supervisor.recoveryLauncherPort is not branded");
  }
  if (recovery != null) {
    sameBinding(recovery.bootstrap, contract, [
      "supervisor_contract_digest",
      "cleanup_capability_digest",
      "attempt_ref",
      "instrument_ref",
      "lease_id",
      "fencing_token",
      "fencing_generation",
      "supervisor_signer_key_id",
      "trust_root_epoch",
    ], "precommitted_recovery_bootstrap");
    if (recovery.bootstrap.source_execution_request_digest !== contract.execution_request_digest) {
      throw new Error(
        "precommitted_recovery_bootstrap.source_execution_request_digest binding drift",
      );
    }
  }
  const now = input.now == null ? () => new Date() : assertFunction(input.now, "instrument_safety_supervisor.now");
  const context = observationContext(contract);
  const containmentAttempts = new Map();
  let lastHeartbeat = null;
  let lastClockMillis = null;
  let queue = Promise.resolve();

  const registeredContract = store.registerSafetySupervisor(contract);
  if (registeredContract && typeof registeredContract.then === "function") {
    throw new Error("safety-supervisor registration must be durably committed synchronously");
  }
  const normalizedRegistration = normalizeSafetySupervisorContract(
    registeredContract,
    "instrument_safety_supervisor.registered_contract",
  );
  if (normalizedRegistration.supervisor_contract_digest !== contract.supervisor_contract_digest) {
    throw new Error("instrument safety supervisor store registered a detached contract");
  }

  function trustedNow() {
    const value = now();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
      throw new Error("instrument safety supervisor clock returned an invalid Date");
    }
    if (lastClockMillis != null && value.getTime() < lastClockMillis) {
      throw new Error("instrument safety supervisor clock moved backwards");
    }
    lastClockMillis = value.getTime();
    return assertCanonicalTimestamp(value.toISOString(), "instrument_safety_supervisor.observed_at");
  }

  function currentLease() {
    const candidate = store.readLease(contract.lease_id);
    if (!candidate) throw new Error("instrument safety supervisor lease is missing");
    const lease = normalizeInstrumentLease(candidate, "instrument_safety_supervisor.lease");
    sameBinding(lease, contract, [
      "attempt_ref",
      "instrument_ref",
      "lease_id",
      "fencing_token",
      "fencing_generation",
      "operation_id",
      "execution_request_digest",
    ], "instrument_safety_supervisor.lease");
    return lease;
  }

  const watchdogTimeoutMs = Math.max(
    1,
    Math.min(contract.heartbeat_interval_ms, contract.stop_ack_deadline_ms),
  );

  function boundedAwait(operation, label) {
    let timer = null;
    const timeout = new Promise((resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error(`${label} exceeded the safety watchdog deadline`)),
        watchdogTimeoutMs,
      );
    });
    return Promise.race([
      Promise.resolve().then(operation),
      timeout,
    ]).finally(() => clearTimeout(timer));
  }

  async function collectEvaluation(heartbeatInput, trigger) {
    const failures = [];
    const [authorityResult, providerResult, workerResult] = await Promise.allSettled([
      boundedAwait(() => observations.readAuthorityState(context), "authority observation"),
      boundedAwait(() => observations.readProviderState(context), "provider observation"),
      boundedAwait(() => observations.readWorkerState(context), "worker observation"),
    ]);
    let authority;
    let provider;
    let worker;
    try {
      if (authorityResult.status !== "fulfilled") throw authorityResult.reason;
      authority = normalizeAuthorityState(authorityResult.value, contract);
    } catch {
      failures.push("authority_state_unavailable");
      authority = {
        authority_epoch: fallbackDrift(contract.authority_epoch),
        revocation_generation: fallbackDrift(contract.revocation_generation),
      };
    }
    try {
      if (providerResult.status !== "fulfilled") throw providerResult.reason;
      provider = normalizeProviderState(providerResult.value, contract);
    } catch {
      failures.push("provider_state_unavailable");
      provider = { reachable: false };
    }
    try {
      if (workerResult.status !== "fulfilled") throw workerResult.reason;
      worker = normalizeWorkerState(workerResult.value, contract);
    } catch {
      failures.push("worker_state_unavailable");
      worker = { alive: false };
    }
    if (trigger === "worker_exit") worker = { alive: false };

    let heartbeat = null;
    let heartbeatVerification = null;
    if (heartbeatInput != null && trigger === "poll") {
      try {
        heartbeat = normalizeSignedDeadmanHeartbeat(
          heartbeatInput,
          contract,
          "instrument_safety_supervisor.heartbeat",
        );
        heartbeatVerification = await boundedAwait(
          () => observations.verifyHeartbeat(heartbeat),
          "heartbeat verification",
        );
        if (lastHeartbeat != null && heartbeat.heartbeat_digest !== lastHeartbeat.heartbeat_digest) {
          assertDeadmanHeartbeatTransition(lastHeartbeat, heartbeat, contract);
        }
      } catch {
        failures.push("heartbeat_invalid");
        heartbeat = null;
        heartbeatVerification = null;
      }
    }

    // Observations and signature verification are asynchronous authority
    // boundaries. Read both the durable lease and the monotonic clock only
    // after they settle so neither a renewal race nor a slow observer can
    // widen a stale execution window.
    const lease = currentLease();
    const observedAt = trustedNow();

    const evaluationInput = {
      supervisor_contract: contract,
      lease,
      heartbeat,
      heartbeat_verification: heartbeatVerification,
      observed_at: observedAt,
      authority_epoch: authority.authority_epoch,
      revocation_generation: authority.revocation_generation,
      provider_reachable: provider.reachable,
      worker_alive: worker.alive,
    };
    let evaluation;
    try {
      evaluation = evaluateSafetySupervisor(evaluationInput);
      if (heartbeat != null) lastHeartbeat = heartbeat;
    } catch {
      if (heartbeat == null) throw new Error("instrument safety supervisor evaluation failed closed");
      failures.push("heartbeat_invalid");
      heartbeat = null;
      heartbeatVerification = null;
      evaluation = evaluateSafetySupervisor({
        ...evaluationInput,
        heartbeat: null,
        heartbeat_verification: null,
      });
    }
    return Object.freeze({
      evaluation,
      lease,
      observed_at: observedAt,
      observation_failures: Object.freeze([...new Set(failures)].sort()),
    });
  }

  function durableFence(initialLease, reason) {
    let lease = initialLease;
    for (let attempt = 0; attempt < 16; attempt += 1) {
      if (["fenced", "restoring", "quarantined"].includes(lease.state)) {
        return Object.freeze({ lease, status: "already_non_executable" });
      }
      if (lease.state === "released") {
        return Object.freeze({ lease, status: "already_terminal" });
      }
      if (!["held", "stop_requested"].includes(lease.state)) {
        throw new Error(`instrument safety supervisor cannot fence lease state ${lease.state}`);
      }
      const fencedAt = trustedNow();
      const request = {
        version: 1,
        lease_id: lease.lease_id,
        instrument_ref: lease.instrument_ref,
        owner_principal_id: lease.owner_principal_id,
        execution_principal_id: lease.execution_principal_id,
        fencing_token: lease.fencing_token,
        fencing_generation: lease.fencing_generation,
        expected_sequence: lease.sequence,
        fenced_at: fencedAt,
        reason,
      };
      try {
        const fenced = store.fenceLease(request);
        if (fenced && typeof fenced.then === "function") {
          throw new Error("instrument lease fence must commit synchronously before containment");
        }
        const normalized = normalizeInstrumentLease(
          fenced,
          "instrument_safety_supervisor.fenced_lease",
        );
        sameBinding(normalized, lease, [
          "attempt_ref",
          "instrument_ref",
          "lease_id",
          "owner_principal_id",
          "execution_principal_id",
          "terminal_receipt_recipient_principal_id",
          "terminal_receipt_idempotency_domain_digest",
          "fencing_token",
          "fencing_generation",
          "operation_id",
          "execution_request_digest",
          "resource_bundle_digest",
          "acquired_at",
          "heartbeat_deadline",
          "expires_at",
        ], "instrument_safety_supervisor.fenced_lease");
        if (normalized.state !== "fenced"
            || normalized.sequence !== lease.sequence + 1
            || normalized.updated_at !== fencedAt) {
          throw new Error("instrument lease store returned a detached fence transition");
        }
        const anchored = currentLease();
        if (anchored.lease_digest !== normalized.lease_digest) {
          throw new Error("instrument lease store fence is absent from the durable snapshot");
        }
        return Object.freeze({ lease: anchored, status: "committed" });
      } catch (error) {
        // A renewal or another safety path may win the CAS. Re-read from the
        // durable projection: a non-executable winner is accepted, while an
        // executable renewal is fenced with its new exact sequence.
        let current;
        try { current = currentLease(); } catch { throw error; }
        if (["fenced", "restoring", "quarantined"].includes(current.state)) {
          return Object.freeze({ lease: current, status: "concurrently_committed" });
        }
        if (current.state === "released") {
          return Object.freeze({ lease: current, status: "already_terminal" });
        }
        if (!["held", "stop_requested"].includes(current.state)) throw error;
        if (current.lease_digest === lease.lease_digest) throw error;
        lease = current;
      }
    }
    throw new Error("instrument safety supervisor could not fence a churning lease");
  }

  async function containOnce(lease, evaluation) {
    const key = `${lease.lease_id}:${lease.fencing_generation}`;
    if (containmentAttempts.has(key)) return containmentAttempts.get(key);
    const pending = (async () => {
      const callContext = containmentContext(contract, evaluation, lease);
      // Anchor every action claim before invoking any external containment
      // capability. A surviving claim with no completion is intentionally
      // ambiguous and is never replayed after a crash or by another process.
      const claims = contract.containment_actions.map((action) => {
        const outcome = store.claimContainmentAction({
          version: SAFETY_SUPERVISOR_RUNTIME_VERSION,
          supervisor_contract_digest: contract.supervisor_contract_digest,
          action,
          fenced_lease_digest: lease.lease_digest,
        });
        if (outcome && typeof outcome.then === "function") {
          throw new Error("containment action claim must commit synchronously before the effect");
        }
        return { action, ...outcome };
      });
      const results = await Promise.all(claims.map(async ({ action, claimed, state }) => {
        if (state.state === "completed") {
          return normalizeContainmentOutcome({
            outcome: state.outcome,
            receipt_digest: state.receipt_digest,
          }, action);
        }
        if (!claimed) {
          return Object.freeze({ action, outcome: "ambiguous", receipt_digest: null });
        }
        const handler = Object.prototype.hasOwnProperty.call(containment, action)
          ? containment[action]
          : null;
        let effectOutcome;
        try {
          effectOutcome = normalizeContainmentOutcome(
            await boundedAwait(() => handler(callContext), `containment action ${action}`),
            action,
          );
        } catch {
          // Throw, timeout, malformed receipt, or lost response may all occur
          // after the physical action. They are ambiguity, never proof of no
          // effect and never a reason to auto-retry.
          effectOutcome = Object.freeze({ action, outcome: "ambiguous", receipt_digest: null });
        }
        try {
          const completed = store.completeContainmentAction({
            version: SAFETY_SUPERVISOR_RUNTIME_VERSION,
            claim_digest: state.claim_digest,
            outcome: effectOutcome.outcome,
            receipt_digest: effectOutcome.receipt_digest,
          });
          if (completed && typeof completed.then === "function") {
            throw new Error("containment completion must commit synchronously");
          }
          return normalizeContainmentOutcome({
            outcome: completed.outcome,
            receipt_digest: completed.receipt_digest,
          }, action);
        } catch {
          const durable = store.snapshot().containment_action_states.find((candidate) => (
            candidate.claim_digest === state.claim_digest && candidate.state === "completed"
          ));
          return durable
            ? normalizeContainmentOutcome({
              outcome: durable.outcome,
              receipt_digest: durable.receipt_digest,
            }, action)
            : Object.freeze({ action, outcome: "ambiguous", receipt_digest: null });
        }
      }));
      return deepFreeze({
        results,
        complete: results.length === contract.containment_actions.length
          && results.every((result) => result.outcome === "confirmed"),
      });
    })();
    // Claim before the first asynchronous action. A concurrent supervisor call
    // observes the same promise and cannot duplicate stop/reset/kill effects.
    containmentAttempts.set(key, pending);
    return pending;
  }

  function recoveryOutcomeFromState(state) {
    return normalizeRecoveryLaunchOutcome({
      outcome: state.outcome,
      launch_receipt_digest: state.launch_receipt_digest,
    }, recovery.bootstrap);
  }

  async function launchRecoveryOnce() {
    if (recovery == null) {
      return deepFreeze({
        outcome: "unavailable",
        verified_bootstrap_digest: null,
        launch_receipt_digest: null,
      });
    }
    // This time sample is deliberately after containment and immediately
    // before the durable launch claim. Slow containment cannot carry an
    // expired or future-dated cleanup bootstrap across its authority window.
    const observedAt = trustedNow();
    if (Date.parse(observedAt) < Date.parse(recovery.bootstrap.not_before)
        || Date.parse(observedAt) > Date.parse(recovery.bootstrap.expires_at)) {
      return deepFreeze({
        outcome: "unavailable",
        verified_bootstrap_digest: recovery.bootstrap.verified_bootstrap_digest,
        launch_receipt_digest: null,
      });
    }
    const claim = store.claimRecoveryLaunch({
      version: SAFETY_SUPERVISOR_RUNTIME_VERSION,
      supervisor_contract_digest: contract.supervisor_contract_digest,
      verified_bootstrap_digest: recovery.bootstrap.verified_bootstrap_digest,
    });
    if (claim && typeof claim.then === "function") {
      throw new Error("recovery launch claim must commit synchronously before the effect");
    }
    if (claim.state.state === "completed") return recoveryOutcomeFromState(claim.state);
    if (!claim.claimed) {
      return deepFreeze({
        outcome: "ambiguous",
        verified_bootstrap_digest: recovery.bootstrap.verified_bootstrap_digest,
        launch_receipt_digest: null,
      });
    }
    let effectOutcome;
    try {
      effectOutcome = normalizeRecoveryLaunchOutcome(
        await boundedAwait(
          () => recovery.launch(recovery.bootstrap),
          "precommitted recovery launch",
        ),
        recovery.bootstrap,
      );
    } catch {
      effectOutcome = deepFreeze({
        outcome: "ambiguous",
        verified_bootstrap_digest: recovery.bootstrap.verified_bootstrap_digest,
        launch_receipt_digest: null,
      });
    }
    try {
      const completed = store.completeRecoveryLaunch({
        version: SAFETY_SUPERVISOR_RUNTIME_VERSION,
        claim_digest: claim.state.claim_digest,
        outcome: effectOutcome.outcome,
        launch_receipt_digest: effectOutcome.launch_receipt_digest,
      });
      if (completed && typeof completed.then === "function") {
        throw new Error("recovery completion must commit synchronously");
      }
      return recoveryOutcomeFromState(completed);
    } catch {
      const durable = store.snapshot().recovery_launch_states.find((candidate) => (
        candidate.claim_digest === claim.state.claim_digest && candidate.state === "completed"
      ));
      return durable
        ? recoveryOutcomeFromState(durable)
        : deepFreeze({
          outcome: "ambiguous",
          verified_bootstrap_digest: recovery.bootstrap.verified_bootstrap_digest,
          launch_receipt_digest: null,
        });
    }
  }

  async function cycle(trigger, heartbeatInput) {
    const observed = await collectEvaluation(heartbeatInput, trigger);
    const { evaluation, lease } = observed;
    if (evaluation.decision !== "stop_fence_cleanup") {
      return deepFreeze({
        version: SAFETY_SUPERVISOR_RUNTIME_VERSION,
        trigger,
        evaluation,
        observation_failures: observed.observation_failures,
        fence_status: "not_required",
        lease_state: lease.state,
        containment_results: [],
        containment_complete: false,
        recovery_launch: null,
        quarantine_required: false,
        emission_state: "unknown",
        automatic_retry_allowed: false,
      });
    }
    const reason = fenceReason(trigger, evaluation.reasons);
    const fenced = durableFence(lease, reason);
    const containmentOutcome = await containOnce(fenced.lease, evaluation);
    const recoveryOutcome = containmentOutcome.complete
      ? await launchRecoveryOnce()
      : null;
    return deepFreeze({
      version: SAFETY_SUPERVISOR_RUNTIME_VERSION,
      trigger,
      evaluation,
      observation_failures: observed.observation_failures,
      fence_status: fenced.status,
      lease_state: fenced.lease.state,
      containment_results: containmentOutcome.results,
      containment_complete: containmentOutcome.complete,
      recovery_launch: recoveryOutcome,
      quarantine_required: !containmentOutcome.complete
        || recoveryOutcome == null
        || recoveryOutcome.outcome !== "launched",
      // Containment callbacks are not an observation/verifier plane. Even a
      // confirmed reset/kill receipt cannot synthesize inhibited RF/emission.
      emission_state: "unknown",
      automatic_retry_allowed: false,
    });
  }

  function enqueue(task) {
    const running = queue.then(task, task);
    queue = running.catch(() => {});
    return running;
  }

  function poll(inputValue) {
    if (arguments.length !== 1) {
      return Promise.reject(new Error("instrument safety supervisor poll accepts one closed input"));
    }
    try {
      assertClosedObject(inputValue, "instrument_safety_supervisor.poll", ["heartbeat"]);
    } catch (error) {
      return Promise.reject(error);
    }
    return enqueue(() => cycle("poll", cloneJson(inputValue.heartbeat)));
  }

  function notifyWorkerExit() {
    if (arguments.length !== 0) {
      return Promise.reject(new Error("instrument safety supervisor worker-exit path accepts no parameters"));
    }
    return enqueue(() => cycle("worker_exit", null));
  }

  function reconcileStartup() {
    if (arguments.length !== 0) {
      return Promise.reject(new Error("instrument safety supervisor startup path accepts no parameters"));
    }
    return enqueue(() => cycle("startup", null));
  }

  function launchPrecommittedRecovery() {
    if (arguments.length !== 0) {
      return Promise.reject(new Error("precommitted recovery launch accepts no agent parameters"));
    }
    return enqueue(async () => {
      const lease = currentLease();
      if (lease.state !== "fenced") {
        throw new Error("precommitted recovery requires the exact lease to remain durably fenced");
      }
      const snapshot = store.snapshot();
      const complete = contract.containment_actions.every((action) => (
        snapshot.containment_action_states.some((state) => (
          state.supervisor_contract_digest === contract.supervisor_contract_digest
          && state.action === action
          && state.state === "completed"
          && state.outcome === "confirmed"
        ))
      ));
      if (!complete) {
        throw new Error("precommitted recovery requires confirmed containment");
      }
      return launchRecoveryOnce();
    });
  }

  return Object.freeze({
    launchPrecommittedRecovery,
    notifyWorkerExit,
    poll,
    reconcileStartup,
  });
}

module.exports = {
  SAFETY_SUPERVISOR_RUNTIME_VERSION,
  createInstrumentContainmentPort,
  createInstrumentSafetySupervisor,
  createPrecommittedRecoveryLauncherPort,
  createSafetyObservationPort,
};
