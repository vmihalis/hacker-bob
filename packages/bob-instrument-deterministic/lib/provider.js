"use strict";

const {
  assertAttemptTransition,
  assertNoPublicByteMaterial,
  assertProviderAbiCompatible,
  assertProviderInterface,
  normalizeAttemptReport,
  normalizeCapabilitiesResponse,
  normalizeExecuteRequest,
  normalizeHealthRequest,
  normalizeHealthResponse,
  normalizeInventoryResponse,
  normalizePrepareRequest,
  normalizeProviderBootstrapReport,
  normalizeProviderBootstrapRequest,
  normalizeProviderDescriptor,
  normalizeReconcileRequest,
  normalizeRestoreRequest,
  normalizeSnapshotRequest,
  normalizeSnapshotResponse,
  normalizeStatusRequest,
  normalizeStopRequest,
} = require("../../../mcp/domains/physical/instrument-provider-contract.js");
const {
  assertDurableInstrumentProviderDispatchPort,
} = require("../../../mcp/domains/physical/instrument-lease-store.js");
const {
  assertInstrumentBootstrapProviderRedemptionPort,
} = require("../../../mcp/domains/physical/instrument-bootstrap-store.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const BOOTSTRAP_OPERATION_BY_METHOD = Object.freeze({
  inventory: "instrument.inventory",
  capabilities: "instrument.capabilities",
  health: "instrument.health",
});

const SCRIPT_OUTCOMES = Object.freeze([
  "success",
  "confirmed",
  "refusal",
  "refused",
  "corruption",
  "timeout",
  "disconnect",
  "unavailable",
  "ambiguous",
  "confirmed_effect",
  "confirmed_no_effect",
  "crash_after_dispatch",
  "stale_state",
  "restore_failure",
]);

const SCRIPT_METHODS = Object.freeze([
  "describe",
  "inventory",
  "capabilities",
  "prepare",
  "snapshot",
  "execute",
  "status",
  "stop",
  "reconcile",
  "restore",
  "health",
]);

const MAX_SCRIPT_EVENTS = 1024;
const MAX_ATTEMPTS = 1024;
const MAX_ATTEMPT_HISTORY = 32;
const STATE_STORES = new WeakMap();
let nextStateStoreId = 1;

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function scriptError(code, effectState) {
  const error = new Error(code);
  error.code = code;
  error.effect_state = effectState;
  return error;
}

function createDeterministicProviderStateStore() {
  const stateStore = Object.freeze({
    version: 1,
    store_id: `deterministic-provider-store-${String(nextStateStoreId).padStart(4, "0")}`,
  });
  nextStateStoreId += 1;
  STATE_STORES.set(stateStore, null);
  return stateStore;
}

function assertStateStore(stateStore) {
  if (!stateStore || !STATE_STORES.has(stateStore)) {
    throw new Error("state_store must be a closed deterministic provider state store");
  }
  return stateStore;
}

function defineDeterministicFaultScript(script) {
  if (!Array.isArray(script) || script.length > MAX_SCRIPT_EVENTS) {
    throw new Error(`deterministic provider script must be an array with at most ${MAX_SCRIPT_EVENTS} events`);
  }
  return Object.freeze(script.map((event, index) => {
    if (event == null || typeof event !== "object" || Array.isArray(event)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(event))) {
      throw new Error(`deterministic provider script[${index}] must be an object`);
    }
    if (Object.getOwnPropertySymbols(event).length > 0) {
      throw new Error(`deterministic provider script[${index}] cannot contain symbol fields`);
    }
    const unknown = Object.keys(event).filter((field) => !["method", "outcome"].includes(field));
    if (unknown.length > 0) {
      throw new Error(`deterministic provider script[${index}] has unknown fields: ${unknown.sort().join(", ")}`);
    }
    if (!SCRIPT_METHODS.includes(event.method)) {
      throw new Error(`deterministic provider script[${index}].method is not supported`);
    }
    if (!SCRIPT_OUTCOMES.includes(event.outcome)) {
      throw new Error(`deterministic provider script[${index}].outcome is not supported`);
    }
    if (event.outcome === "restore_failure" && event.method !== "restore") {
      throw new Error(`deterministic provider script[${index}].outcome restore_failure is valid only for restore`);
    }
    if (event.outcome === "crash_after_dispatch" && event.method !== "execute") {
      throw new Error(`deterministic provider script[${index}].outcome crash_after_dispatch is valid only for execute`);
    }
    if (["confirmed_effect", "confirmed_no_effect"].includes(event.outcome)
        && event.method !== "reconcile") {
      throw new Error(
        `deterministic provider script[${index}].outcome ${event.outcome} is valid only for reconcile`,
      );
    }
    return Object.freeze({ method: event.method, outcome: event.outcome });
  }));
}

function canonicalFaultOutcome(outcome) {
  if (outcome === "confirmed") return "success";
  if (outcome === "refused") return "refusal";
  return outcome;
}

function publicResult(operation, outcome, artifactRefs = []) {
  const preferred = {
    succeeded: "operation_succeeded",
    refused: "operation_refused",
    failed: "operation_failed",
    stopped: "operation_stopped",
    inconclusive: "operation_inconclusive",
  }[outcome];
  const summaryCode = operation.public_summary_codes.includes(preferred)
    ? preferred
    : operation.public_summary_codes[0];
  return {
    version: 1,
    outcome,
    summary_code: summaryCode,
    artifact_refs: artifactRefs,
    metric_counts: { observation_count: artifactRefs.length },
  };
}

function bootstrapObservationBasis(method, request, descriptor) {
  if (method === "inventory") {
    return {
      version: 1,
      operation_id: request.operation_id,
      instrument_ref: request.instrument_ref,
      inventory_ref: "inventory:mock-inventory-0001",
      descriptor_digest: descriptor.descriptor_digest,
      capabilities_digest: descriptor.capabilities_digest,
      connection_generation: request.connection_generation,
      status: "observed",
    };
  }
  if (method === "capabilities") {
    return {
      version: 1,
      operation_id: request.operation_id,
      descriptor_digest: descriptor.descriptor_digest,
      capabilities_digest: descriptor.capabilities_digest,
      declared_capability_count: descriptor.capabilities.length,
      connection_generation: request.connection_generation,
      status: "observed",
    };
  }
  return {
    version: 1,
    operation_id: request.operation_id,
    instrument_ref: request.instrument_ref,
    descriptor_digest: descriptor.descriptor_digest,
    connection_generation: request.connection_generation,
    status: "healthy",
  };
}

function bootstrapReport(request, redemption, method, descriptor, outcome) {
  const negative = outcome !== "succeeded";
  const observation = bootstrapObservationBasis(method, request, descriptor);
  const observationDigest = negative ? null : hashCanonicalJson({
    domain: "hacker-bob/deterministic-bootstrap-observation/v1",
    observation,
  });
  const responseDigest = negative ? null : hashCanonicalJson({
    domain: "hacker-bob/deterministic-bootstrap-response/v1",
    method,
    observation_digest: observationDigest,
    bootstrap_request_digest: request.bootstrap_request_digest,
  });
  const assuranceClaimsDigest = negative ? null : hashCanonicalJson({
    domain: "hacker-bob/deterministic-bootstrap-assurance/v1",
    provider_descriptor_digest: descriptor.descriptor_digest,
    operation_id: request.operation_id,
    connection_ref: request.connection_ref,
    connection_generation: request.connection_generation,
  });
  const invariantWitnessDigest = negative ? null : hashCanonicalJson({
    domain: "hacker-bob/deterministic-bootstrap-invariant-witness/v1",
    bootstrap_invariants_digest: request.bootstrap_invariants_digest,
    dispatch_redemption_digest: redemption.dispatch_redemption_digest,
    observation_digest: observationDigest,
  });
  const receiptDigest = hashCanonicalJson({
    domain: "hacker-bob/deterministic-bootstrap-receipt/v1",
    attempt_ref: request.attempt_ref,
    bootstrap_request_digest: request.bootstrap_request_digest,
    dispatch_redemption_digest: redemption.dispatch_redemption_digest,
    connection_generation: request.connection_generation,
    outcome,
    observation_digest: observationDigest,
    response_digest: responseDigest,
    observed_at: redemption.redeemed_at,
  });
  const report = {
    version: 1,
    attempt_ref: request.attempt_ref,
    operation_id: request.operation_id,
    bootstrap_intent_digest: request.bootstrap_intent_digest,
    bootstrap_request_digest: request.bootstrap_request_digest,
    signed_grant_digest: request.signed_grant_digest,
    replay_reservation_receipt_digest: request.replay_reservation_receipt_digest,
    dispatch_record_digest: request.dispatch_record_digest,
    dispatch_redemption_digest: redemption.dispatch_redemption_digest,
    connection_generation: request.connection_generation,
    outcome,
    observation_ref: negative
      ? null
      : `bootstrap-observation:deterministic-${observationDigest.slice(0, 40)}`,
    observation_digest: observationDigest,
    receipt_ref: `bootstrap-receipt:deterministic-${receiptDigest.slice(0, 40)}`,
    receipt_digest: receiptDigest,
    response_digest: responseDigest,
    observed_at: redemption.redeemed_at,
    assurance_claims_digest: assuranceClaimsDigest,
    invariant_witness_digest: invariantWitnessDigest,
  };
  assertNoPublicByteMaterial(report, "deterministic_bootstrap_report");
  return report;
}

class DeterministicInstrumentProvider {
  constructor({
    descriptor,
    operationRegistry,
    effectRegistry,
    providerDispatchPort,
    bootstrapProviderPort = null,
    script = [],
    stateStore = createDeterministicProviderStateStore(),
  }) {
    this.operationRegistry = operationRegistry;
    this.effectRegistry = effectRegistry;
    this.descriptorValue = normalizeProviderDescriptor(
      descriptor,
      operationRegistry,
      effectRegistry,
      "deterministic.descriptor",
    );
    this.script = defineDeterministicFaultScript(script);
    this.scriptIndex = 0;
    this.providerDispatchPort = assertDurableInstrumentProviderDispatchPort(providerDispatchPort);
    this.bootstrapProviderPort = this.descriptorValue.abi_version === 3
      ? assertInstrumentBootstrapProviderRedemptionPort(bootstrapProviderPort)
      : null;
    this.stateStore = assertStateStore(stateStore);
    const checkpoint = STATE_STORES.get(this.stateStore);
    if (checkpoint != null) {
      if (checkpoint.provider_id !== this.descriptorValue.provider_id
          || checkpoint.descriptor_digest !== this.descriptorValue.descriptor_digest
          || checkpoint.operation_registry_digest !== this.operationRegistry.registry_digest) {
        throw new Error("state_store is bound to a different provider descriptor or operation registry");
      }
      this.attempts = new Map(checkpoint.attempts.map((attempt) => [
        attempt.prepared.attempt_ref,
        cloneJson(attempt),
      ]));
      this.executeInvocations = new Set(checkpoint.execute_invocations);
    } else {
      this.attempts = new Map();
      this.executeInvocations = new Set();
      this._checkpoint();
    }
    this.fixedTime = "2026-07-18T00:00:00.000Z";
  }

  _checkpoint() {
    if (this.attempts.size > MAX_ATTEMPTS) {
      throw new Error(`deterministic provider supports at most ${MAX_ATTEMPTS} attempts per state store`);
    }
    const attempts = [...this.attempts.values()]
      .sort((left, right) => left.prepared.attempt_ref.localeCompare(right.prepared.attempt_ref))
      .map((attempt) => {
        if (!Array.isArray(attempt.history) || attempt.history.length > MAX_ATTEMPT_HISTORY) {
          throw new Error(`attempt history exceeds ${MAX_ATTEMPT_HISTORY} reports`);
        }
        return cloneJson(attempt);
      });
    const checkpoint = {
      version: 1,
      provider_id: this.descriptorValue.provider_id,
      descriptor_digest: this.descriptorValue.descriptor_digest,
      operation_registry_digest: this.operationRegistry.registry_digest,
      attempts,
      execute_invocations: [...this.executeInvocations].sort(),
    };
    assertNoPublicByteMaterial(checkpoint, "deterministic_provider_checkpoint");
    STATE_STORES.set(this.stateStore, cloneJson(checkpoint));
  }

  _event(method) {
    const next = this.script[this.scriptIndex];
    if (!next) return "success";
    if (next.method !== method) return "success";
    this.scriptIndex += 1;
    return canonicalFaultOutcome(next.outcome);
  }

  _operation(operationId) {
    const operation = this.operationRegistry.get(operationId);
    if (!operation) throw new Error(`mock received undeclared operation ${operationId}`);
    return operation;
  }

  _receipt(prepared, method, sequence) {
    return `receipt:mock-${prepared.request_digest.slice(0, 16)}-${method}-${String(sequence).padStart(4, "0")}`;
  }

  _report(prepared, state, sequence, effectDisposition, outcome = null, artifactRefs = []) {
    const operation = this._operation(prepared.operation_id);
    return {
      version: 1,
      attempt_ref: prepared.attempt_ref,
      operation_id: prepared.operation_id,
      request_digest: prepared.request_digest,
      state,
      sequence,
      effect_disposition: effectDisposition,
      receipt_ref: state === "created" ? null : this._receipt(prepared, state, sequence),
      public_result: outcome == null ? null : publicResult(operation, outcome, artifactRefs),
    };
  }

  _created(prepared) {
    return this._report(prepared, "created", 0, "not_dispatched");
  }

  _transition(attempt, next) {
    const normalized = assertAttemptTransition(attempt.report, next, this.operationRegistry);
    attempt.report = normalized;
    attempt.history.push(normalized);
    this._checkpoint();
    return cloneJson(normalized);
  }

  _lookup(input, method, { deferSequenceCheck = false } = {}) {
    const attempt = this.attempts.get(input.attempt_ref);
    if (!attempt) throw scriptError("provider_unknown_attempt", "not_dispatched");
    if (input.operation_id !== attempt.prepared.operation_id
        || input.request_digest !== attempt.prepared.request_digest) {
      throw scriptError("provider_attempt_binding_mismatch", "not_dispatched");
    }
    if (!deferSequenceCheck
        && Object.prototype.hasOwnProperty.call(input, "expected_sequence")
        && input.expected_sequence !== attempt.report.sequence) {
      throw scriptError("provider_stale_state", attempt.report.effect_disposition);
    }
    attempt.last_method = method;
    return attempt;
  }

  _bootstrapObservation(method, request) {
    const normalized = normalizeProviderBootstrapRequest(
      request,
      this.descriptorValue,
      `mock.${method}_bootstrap_request`,
    );
    if (normalized.operation_id !== BOOTSTRAP_OPERATION_BY_METHOD[method]) {
      throw new Error(
        `mock.${method}_bootstrap_request.operation_id must be ${BOOTSTRAP_OPERATION_BY_METHOD[method]}`,
      );
    }
    const redemption = this.bootstrapProviderPort.redeem(
      normalized.dispatch_credential,
      normalized,
    );
    const durableReport = this.bootstrapProviderPort.consumeBootstrapObservation(
      redemption.permit,
      (redemptionProjection) => {
        if (redemptionProjection !== redemption.redemption_projection) {
          throw new Error("bootstrap redemption projection identity drifted");
        }
        for (const field of [
          "attempt_ref",
          "dispatch_record_digest",
          "bootstrap_request_digest",
          "connection_ref",
          "connection_generation",
        ]) {
          if (redemptionProjection[field] !== normalized[field]) {
            throw new Error(`bootstrap redemption projection ${field} drifted`);
          }
        }
        const fault = this._event(method);
        if (["refusal", "unavailable"].includes(fault)) {
          return bootstrapReport(
            normalized,
            redemptionProjection,
            method,
            this.descriptorValue,
            "refused_no_effect",
          );
        }
        if (["timeout", "disconnect", "ambiguous", "stale_state"].includes(fault)) {
          return bootstrapReport(
            normalized,
            redemptionProjection,
            method,
            this.descriptorValue,
            "ambiguous",
          );
        }
        if (fault === "corruption") {
          return {
            ...bootstrapReport(
              normalized,
              redemptionProjection,
              method,
              this.descriptorValue,
              "succeeded",
            ),
            diagnostic_ref: "diagnostic:bootstrap-corruption-0001",
          };
        }
        return bootstrapReport(
          normalized,
          redemptionProjection,
          method,
          this.descriptorValue,
          "succeeded",
        );
      },
    );
    return normalizeProviderBootstrapReport(
      durableReport,
      normalized,
      `mock.${method}_bootstrap_report`,
    );
  }

  async describe() {
    const outcome = this._event("describe");
    if (outcome === "corruption") {
      return { ...cloneJson(this.descriptorValue), diagnostic_ref: "diagnostic:descriptor-corruption-0001" };
    }
    if (["timeout", "disconnect", "unavailable"].includes(outcome)) {
      throw scriptError(`provider_${outcome}`, "not_dispatched");
    }
    return cloneJson(this.descriptorValue);
  }

  async inventory(request) {
    if (this.descriptorValue.abi_version === 3) {
      return this._bootstrapObservation("inventory", request);
    }
    const normalized = normalizeHealthRequest(request, "mock.inventory_request");
    if (normalized.provider_id !== this.descriptorValue.provider_id
        || normalized.descriptor_digest !== this.descriptorValue.descriptor_digest) {
      throw scriptError("provider_descriptor_drift", "not_dispatched");
    }
    const outcome = this._event("inventory");
    if (["timeout", "disconnect", "unavailable"].includes(outcome)) {
      throw scriptError(`provider_${outcome}`, "not_dispatched");
    }
    const response = {
      version: 1,
      provider_id: this.descriptorValue.provider_id,
      instrument_ref: "instrument:mock-owned-fixture-0001",
      inventory_ref: "inventory:mock-inventory-0001",
      descriptor_digest: this.descriptorValue.descriptor_digest,
      capabilities_digest: this.descriptorValue.capabilities_digest,
      assurance_claims_digest: "a".repeat(64),
      observed_at: this.fixedTime,
      receipt_ref: "receipt:mock-inventory-0001",
    };
    if (outcome === "corruption") response.diagnostic_ref = "diagnostic:inventory-corruption-0001";
    return response;
  }

  async capabilities(request) {
    if (this.descriptorValue.abi_version === 3) {
      return this._bootstrapObservation("capabilities", request);
    }
    const normalized = normalizeHealthRequest(request, "mock.capabilities_request");
    if (normalized.provider_id !== this.descriptorValue.provider_id
        || normalized.descriptor_digest !== this.descriptorValue.descriptor_digest) {
      throw scriptError("provider_descriptor_drift", "not_dispatched");
    }
    const outcome = this._event("capabilities");
    if (["timeout", "disconnect", "unavailable"].includes(outcome)) {
      throw scriptError(`provider_${outcome}`, "not_dispatched");
    }
    const response = {
      version: 1,
      provider_id: this.descriptorValue.provider_id,
      descriptor_digest: this.descriptorValue.descriptor_digest,
      capabilities_digest: this.descriptorValue.capabilities_digest,
      capabilities: cloneJson(this.descriptorValue.capabilities),
    };
    if (outcome === "corruption") response.capabilities_digest = "0".repeat(64);
    return response;
  }

  async prepare(request) {
    const prepared = normalizePrepareRequest(request, {
      descriptor: this.descriptorValue,
      operation_registry: this.operationRegistry,
      effect_registry: this.effectRegistry,
    }, "mock.prepare_request");
    if (this.attempts.has(prepared.attempt_ref)) throw scriptError("provider_duplicate_attempt", "not_dispatched");
    const created = normalizeAttemptReport(this._created(prepared), this.operationRegistry, "mock.created_report");
    const attempt = { prepared, report: created, history: [created], last_method: "prepare" };
    this.attempts.set(prepared.attempt_ref, attempt);
    this._checkpoint();
    const outcome = this._event("prepare");
    if (["timeout", "disconnect", "unavailable"].includes(outcome)) {
      throw scriptError(`provider_${outcome}`, "not_dispatched");
    }
    if (outcome === "refusal") {
      return this._transition(attempt, this._report(prepared, "refused", 1, "confirmed_no_effect", "refused"));
    }
    const next = this._report(prepared, "prepared", outcome === "stale_state" ? 0 : 1, "not_dispatched");
    if (outcome === "stale_state") return next;
    const response = this._transition(attempt, next);
    if (outcome === "corruption") {
      response.diagnostic_ref = "diagnostic:prepare-corruption-0001";
    }
    return response;
  }

  async snapshot(request) {
    const normalized = normalizeSnapshotRequest(request, "mock.snapshot_request");
    const attempt = this._lookup(normalized, "snapshot");
    if (attempt.report.state !== "prepared" || normalized.expected_sequence !== attempt.report.sequence) {
      throw scriptError("provider_stale_state", attempt.report.effect_disposition);
    }
    if (normalized.instrument_ref !== attempt.prepared.instrument_ref) {
      throw scriptError("provider_instrument_binding_mismatch", "not_dispatched");
    }
    const outcome = this._event("snapshot");
    if (["timeout", "disconnect", "unavailable"].includes(outcome)) {
      throw scriptError(`provider_${outcome}`, "not_dispatched");
    }
    if (outcome === "refusal") throw scriptError("provider_snapshot_refused", "not_dispatched");
    const response = {
      version: 1,
      attempt_ref: normalized.attempt_ref,
      instrument_ref: normalized.instrument_ref,
      operation_id: normalized.operation_id,
      request_digest: normalized.request_digest,
      prepared_sequence: outcome === "stale_state"
        ? Math.max(0, normalized.expected_sequence - 1)
        : normalized.expected_sequence,
      snapshot_plan_digest: normalized.snapshot_plan_digest,
      snapshot_artifact_ref: "artifact:v1:mock-snapshot-0001",
      workspace_state_digest: "5".repeat(64),
      receipt_ref: "receipt:mock-snapshot-0001",
    };
    if (outcome === "corruption") response.diagnostic_ref = "diagnostic:snapshot-corruption-0001";
    if (outcome === "stale_state" || outcome === "corruption") return response;
    attempt.snapshot = normalizeSnapshotResponse(response, normalized, "mock.snapshot_response");
    this._checkpoint();
    return cloneJson(attempt.snapshot);
  }

  async execute(request) {
    const normalized = normalizeExecuteRequest(request, "mock.execute_request");
    const attempt = this._lookup(normalized, "execute", { deferSequenceCheck: true });
    if (this.executeInvocations.has(normalized.attempt_ref)) {
      throw scriptError("provider_execute_replay", attempt.report.effect_disposition);
    }
    if (normalized.expected_sequence !== attempt.report.sequence) {
      throw scriptError("provider_stale_state", attempt.report.effect_disposition);
    }
    if (attempt.report.state !== "prepared") throw scriptError("provider_stale_state", attempt.report.effect_disposition);
    const capability = this.descriptorValue.capabilities.find(
      (entry) => entry.capability_id === attempt.prepared.capability_id,
    );
    if (["required", "best_effort"].includes(capability.restore_policy) && !attempt.snapshot) {
      throw scriptError("provider_snapshot_missing", "not_dispatched");
    }
    const permit = this.providerDispatchPort.redeem(normalized.dispatch_credential, {
      attempt_ref: attempt.prepared.attempt_ref,
      instrument_ref: attempt.prepared.instrument_ref,
      operation_id: attempt.prepared.operation_id,
      provider_id: this.descriptorValue.provider_id,
      provider_descriptor_digest: this.descriptorValue.descriptor_digest,
      dispatch_journal_ref: normalized.dispatch_journal_ref,
      provider_request_digest: attempt.prepared.request_digest,
      expected_state: "prepared",
      expected_sequence: attempt.report.sequence,
    });
    return this.providerDispatchPort.consumeEffect(permit, () => {
      this.executeInvocations.add(normalized.attempt_ref);
      this._checkpoint();
      const outcome = this._event("execute");
      if (outcome === "refusal") {
        return this._transition(attempt, this._report(
          attempt.prepared,
          "refused",
          attempt.report.sequence + 1,
          "confirmed_no_effect",
          "refused",
        ));
      }
      if (outcome === "unavailable") {
        this._transition(attempt, this._report(
          attempt.prepared,
          "refused",
          attempt.report.sequence + 1,
          "confirmed_no_effect",
          "refused",
        ));
        throw scriptError("provider_unavailable", "confirmed_no_effect");
      }
      if (outcome === "stale_state") return cloneJson(attempt.report);
      const dispatched = this._report(
        attempt.prepared,
        "dispatched",
        attempt.report.sequence + 1,
        "ambiguous",
      );
      const dispatchedResponse = this._transition(attempt, dispatched);
      if (["timeout", "disconnect", "ambiguous", "crash_after_dispatch"].includes(outcome)) {
        const ambiguous = this._report(
          attempt.prepared,
          "ambiguous_effect",
          attempt.report.sequence + 1,
          "ambiguous",
        );
        this._transition(attempt, ambiguous);
        const code = outcome === "crash_after_dispatch" ? "provider_crash" : `provider_${outcome}`;
        throw scriptError(code, "ambiguous_effect");
      }
      if (outcome === "corruption") {
        const corrupted = cloneJson(dispatchedResponse);
        corrupted.diagnostic_ref = "diagnostic:execute-corruption-0001";
        return corrupted;
      }
      return dispatchedResponse;
    });
  }

  async status(request) {
    const normalized = normalizeStatusRequest(request, "mock.status_request");
    const attempt = this._lookup(normalized, "status");
    const outcome = this._event("status");
    if (["timeout", "disconnect", "unavailable"].includes(outcome)) {
      throw scriptError(`provider_${outcome}`, attempt.report.effect_disposition);
    }
    if (outcome === "stale_state") {
      const stale = cloneJson(attempt.report);
      stale.sequence = Math.max(0, stale.sequence - 1);
      return stale;
    }
    if (outcome === "corruption") {
      return { ...cloneJson(attempt.report), diagnostic_ref: "diagnostic:status-corruption-0001" };
    }
    if (outcome === "ambiguous" && attempt.report.state === "dispatched") {
      return this._transition(attempt, this._report(
        attempt.prepared,
        "ambiguous_effect",
        attempt.report.sequence + 1,
        "ambiguous",
      ));
    }
    if (attempt.report.state === "dispatched") {
      return this._transition(attempt, this._report(
        attempt.prepared,
        "acknowledged",
        attempt.report.sequence + 1,
        "confirmed_effect",
        "succeeded",
        ["artifact:v1:mock-artifact-0001"],
      ));
    }
    if (attempt.report.state === "stop_requested") {
      return this._transition(attempt, this._report(
        attempt.prepared,
        "stopped",
        attempt.report.sequence + 1,
        "confirmed_effect",
        "stopped",
      ));
    }
    return cloneJson(attempt.report);
  }

  async stop(request) {
    const normalized = normalizeStopRequest(request, "mock.stop_request");
    const attempt = this._lookup(normalized, "stop");
    if (!["prepared", "dispatched"].includes(attempt.report.state)) {
      throw scriptError("provider_stale_state", attempt.report.effect_disposition);
    }
    const outcome = this._event("stop");
    if (outcome === "stale_state") return cloneJson(attempt.report);
    const stopRequested = this._report(
      attempt.prepared,
      "stop_requested",
      attempt.report.sequence + 1,
      "ambiguous",
    );
    const response = this._transition(attempt, stopRequested);
    if (["timeout", "disconnect", "ambiguous", "unavailable"].includes(outcome)) {
      const ambiguous = this._report(
        attempt.prepared,
        "ambiguous_effect",
        attempt.report.sequence + 1,
        "ambiguous",
      );
      this._transition(attempt, ambiguous);
      throw scriptError(`provider_${outcome}`, "ambiguous_effect");
    }
    if (outcome === "corruption") {
      return { ...response, diagnostic_ref: "diagnostic:stop-corruption-0001" };
    }
    return response;
  }

  async reconcile(request) {
    const normalized = normalizeReconcileRequest(request, "mock.reconcile_request");
    const attempt = this._lookup(normalized, "reconcile");
    if (attempt.report.state !== "ambiguous_effect") {
      throw scriptError("provider_reconcile_requires_ambiguity", attempt.report.effect_disposition);
    }
    const outcome = this._event("reconcile");
    if (outcome === "stale_state") return cloneJson(attempt.report);
    if (outcome === "ambiguous") return cloneJson(attempt.report);
    if (["timeout", "disconnect", "unavailable"].includes(outcome)) {
      const unknown = this._report(
        attempt.prepared,
        "unknown_effect",
        attempt.report.sequence + 1,
        "unknown",
      );
      this._transition(attempt, unknown);
      throw scriptError(`provider_${outcome}`, "unknown_effect");
    }
    if (outcome === "corruption") {
      return { ...cloneJson(attempt.report), diagnostic_ref: "diagnostic:reconcile-corruption-0001" };
    }
    if (outcome === "confirmed_effect") {
      return this._transition(attempt, this._report(
        attempt.prepared,
        "acknowledged",
        attempt.report.sequence + 1,
        "confirmed_effect",
        "succeeded",
        ["artifact:v1:mock-reconciled-artifact-0001"],
      ));
    }
    return this._transition(attempt, this._report(
      attempt.prepared,
      "reconciled_no_effect",
      attempt.report.sequence + 1,
      "confirmed_no_effect",
      "inconclusive",
    ));
  }

  async restore(request) {
    const normalized = normalizeRestoreRequest(request, "mock.restore_request");
    const attempt = this._lookup(normalized, "restore");
    if (!["acknowledged", "stopped"].includes(attempt.report.state)) {
      throw scriptError("provider_restore_requires_effect", attempt.report.effect_disposition);
    }
    if (!attempt.snapshot) throw scriptError("provider_snapshot_missing", attempt.report.effect_disposition);
    if (normalized.snapshot_artifact_ref !== attempt.snapshot.snapshot_artifact_ref
        || normalized.expected_workspace_state_digest !== attempt.snapshot.workspace_state_digest) {
      throw scriptError("provider_snapshot_binding_mismatch", attempt.report.effect_disposition);
    }
    const outcome = this._event("restore");
    if (outcome === "stale_state") return cloneJson(attempt.report);
    if (outcome === "restore_failure") {
      return this._transition(attempt, this._report(
        attempt.prepared,
        "quarantined",
        attempt.report.sequence + 1,
        "confirmed_effect",
        "failed",
      ));
    }
    if (["timeout", "disconnect", "unavailable"].includes(outcome)) {
      const quarantined = this._report(
        attempt.prepared,
        "quarantined",
        attempt.report.sequence + 1,
        "unknown",
        "failed",
      );
      this._transition(attempt, quarantined);
      throw scriptError(`provider_${outcome}`, "unknown_effect");
    }
    if (outcome === "corruption") {
      return { ...cloneJson(attempt.report), diagnostic_ref: "diagnostic:restore-corruption-0001" };
    }
    return this._transition(attempt, this._report(
      attempt.prepared,
      "restored",
      attempt.report.sequence + 1,
      "confirmed_effect",
      "succeeded",
    ));
  }

  async health(request) {
    if (this.descriptorValue.abi_version === 3) {
      return this._bootstrapObservation("health", request);
    }
    const normalized = normalizeHealthRequest(request, "mock.health_request");
    if (normalized.provider_id !== this.descriptorValue.provider_id
        || normalized.descriptor_digest !== this.descriptorValue.descriptor_digest) {
      throw scriptError("provider_descriptor_drift", "not_dispatched");
    }
    const outcome = this._event("health");
    if (outcome === "timeout" || outcome === "disconnect") {
      throw scriptError(`provider_${outcome}`, "not_dispatched");
    }
    const unavailable = outcome === "refusal" || outcome === "unavailable";
    const response = {
      version: 1,
      provider_id: this.descriptorValue.provider_id,
      descriptor_digest: this.descriptorValue.descriptor_digest,
      status: unavailable ? "unavailable" : "healthy",
      summary_codes: [unavailable ? "provider_unavailable" : "provider_healthy"],
      checked_at: this.fixedTime,
      receipt_ref: "receipt:mock-health-0001",
    };
    if (outcome === "corruption") response.diagnostic_ref = "diagnostic:health-corruption-0001";
    return response;
  }
}

async function runProviderConformance({
  authorizeDispatch,
  authorizeBootstrap = null,
  provider,
  operationRegistry,
  effectRegistry,
  prepareRequest,
  snapshotPlanDigest = "c".repeat(64),
  restorePlanDigest = "b".repeat(64),
}) {
  assertProviderInterface(provider);
  if (typeof authorizeDispatch !== "function") {
    throw new Error("provider conformance requires a durable dispatch authorizer callback");
  }
  const descriptor = normalizeProviderDescriptor(
    await provider.describe(),
    operationRegistry,
    effectRegistry,
    "conformance.descriptor",
  );
  assertProviderAbiCompatible(descriptor);
  let capabilities;
  let inventory;
  let health;
  if (descriptor.abi_version === 3) {
    if (typeof authorizeBootstrap !== "function") {
      throw new Error("ABI-v3 provider conformance requires a durable bootstrap authorizer callback");
    }
    const callBootstrap = async (method) => {
      const operationId = BOOTSTRAP_OPERATION_BY_METHOD[method];
      const capability = descriptor.capabilities.find(
        (entry) => entry.operation_id === operationId,
      );
      if (!capability) throw new Error(`provider does not declare bootstrap operation ${operationId}`);
      const request = normalizeProviderBootstrapRequest(
        await authorizeBootstrap(Object.freeze({
          descriptor,
          method,
          operation_id: operationId,
          operation_digest: capability.operation_digest,
        })),
        descriptor,
        `conformance.${method}_bootstrap_request`,
      );
      return normalizeProviderBootstrapReport(
        await provider[method](request),
        request,
        `conformance.${method}_bootstrap_report`,
      );
    };
    capabilities = await callBootstrap("capabilities");
    inventory = await callBootstrap("inventory");
    health = await callBootstrap("health");
  } else {
    const descriptorRequest = normalizeHealthRequest({
      version: 1,
      provider_id: descriptor.provider_id,
      descriptor_digest: descriptor.descriptor_digest,
    }, "conformance.descriptor_request");
    capabilities = normalizeCapabilitiesResponse(
      await provider.capabilities(descriptorRequest),
      descriptor,
      "conformance.capabilities",
    );
    inventory = normalizeInventoryResponse(
      await provider.inventory(descriptorRequest),
      descriptor,
      "conformance.inventory",
    );
    health = normalizeHealthResponse(
      await provider.health(descriptorRequest),
      descriptor,
      "conformance.health",
    );
  }
  const normalizedPrepare = normalizePrepareRequest(prepareRequest, {
    descriptor,
    operation_registry: operationRegistry,
    effect_registry: effectRegistry,
  }, "conformance.prepare_request");
  const operation = operationRegistry.get(normalizedPrepare.operation_id);
  const capability = descriptor.capabilities.find(
    (entry) => entry.capability_id === normalizedPrepare.capability_id,
  );
  const created = normalizeAttemptReport({
    version: 1,
    attempt_ref: normalizedPrepare.attempt_ref,
    operation_id: normalizedPrepare.operation_id,
    request_digest: normalizedPrepare.request_digest,
    state: "created",
    sequence: 0,
    effect_disposition: "not_dispatched",
    receipt_ref: null,
    public_result: null,
  }, operationRegistry, "conformance.created");
  const prepared = normalizeAttemptReport(
    await provider.prepare(prepareRequest),
    operationRegistry,
    "conformance.prepared",
  );
  assertAttemptTransition(created, prepared, operationRegistry);
  if (prepared.state === "refused") {
    return Object.freeze({
      descriptor,
      capabilities,
      inventory,
      health,
      capability,
      operation,
      snapshot: null,
      terminal: prepared,
    });
  }
  let snapshot = null;
  if (["required", "best_effort"].includes(capability.restore_policy)) {
    const snapshotRequest = normalizeSnapshotRequest({
      version: 1,
      attempt_ref: prepared.attempt_ref,
      instrument_ref: normalizedPrepare.instrument_ref,
      operation_id: prepared.operation_id,
      request_digest: prepared.request_digest,
      expected_state: "prepared",
      expected_sequence: prepared.sequence,
      snapshot_plan_digest: snapshotPlanDigest,
    }, "conformance.snapshot_request");
    snapshot = normalizeSnapshotResponse(
      await provider.snapshot(snapshotRequest),
      snapshotRequest,
      "conformance.snapshot",
    );
  }
  const dispatchAuthorization = authorizeDispatch(Object.freeze({
    descriptor,
    normalized_prepare: normalizedPrepare,
    prepared,
  }));
  if (!dispatchAuthorization || typeof dispatchAuthorization !== "object"
      || !Object.isFrozen(dispatchAuthorization)
      || !dispatchAuthorization.dispatch_credential
      || typeof dispatchAuthorization.dispatch_journal_ref !== "string") {
    throw new Error("provider conformance dispatch authorizer returned an invalid authority projection");
  }
  const executeRequest = normalizeExecuteRequest({
    version: 1,
    attempt_ref: prepared.attempt_ref,
    operation_id: prepared.operation_id,
    request_digest: prepared.request_digest,
    expected_state: "prepared",
    expected_sequence: prepared.sequence,
    dispatch_journal_ref: dispatchAuthorization.dispatch_journal_ref,
    dispatch_credential: dispatchAuthorization.dispatch_credential,
  });
  const dispatched = normalizeAttemptReport(
    await provider.execute(executeRequest),
    operationRegistry,
    "conformance.dispatched",
  );
  assertAttemptTransition(prepared, dispatched, operationRegistry);
  if (dispatched.state === "refused") {
    return Object.freeze({ descriptor, capabilities, inventory, health, capability, operation, snapshot, terminal: dispatched });
  }
  const acknowledged = normalizeAttemptReport(await provider.status({
    version: 1,
    attempt_ref: dispatched.attempt_ref,
    operation_id: dispatched.operation_id,
    request_digest: dispatched.request_digest,
  }), operationRegistry, "conformance.acknowledged");
  assertAttemptTransition(dispatched, acknowledged, operationRegistry);
  if (!["required", "best_effort"].includes(capability.restore_policy)) {
    return Object.freeze({ descriptor, capabilities, inventory, health, capability, operation, snapshot, terminal: acknowledged });
  }
  const restored = normalizeAttemptReport(await provider.restore({
    version: 1,
    attempt_ref: acknowledged.attempt_ref,
    operation_id: acknowledged.operation_id,
    request_digest: acknowledged.request_digest,
    expected_sequence: acknowledged.sequence,
    snapshot_artifact_ref: snapshot.snapshot_artifact_ref,
    expected_workspace_state_digest: snapshot.workspace_state_digest,
    restore_plan_digest: restorePlanDigest,
  }), operationRegistry, "conformance.restored");
  assertAttemptTransition(acknowledged, restored, operationRegistry);
  return Object.freeze({ descriptor, capabilities, inventory, health, capability, operation, snapshot, terminal: restored });
}

module.exports = {
  DeterministicInstrumentProvider,
  SCRIPT_METHODS,
  SCRIPT_OUTCOMES,
  createDeterministicProviderStateStore,
  defineDeterministicFaultScript,
  runProviderConformance,
};
