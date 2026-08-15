"use strict";

// Provider-neutral PH-S4 dispatch kernel. This module owns provider method
// references and the only execute call surface. It never imports a device
// provider, transport, serial implementation, or hardware-specific command.

const {
  PROVIDER_CALL_VERSION,
  PROVIDER_METHODS,
  assertAttemptTransition,
  assertNoPublicByteMaterial,
  assertProviderActiveAbiCompatible,
  assertProviderInterface,
  normalizeAttemptReport,
  normalizeExecuteRequest,
  normalizePrepareRequest,
  normalizeProviderDescriptor,
  normalizeReconcileRequest,
  normalizeSnapshotRequest,
  normalizeSnapshotResponse,
  normalizeStatusRequest,
} = require("./provider-contract.js");
const {
  ATTEMPT_JOURNAL_VERSION,
  EFFECT_DISPATCH_VERSION,
  assertProviderAlignedJournalState,
  normalizeAttemptJournalEntry,
  normalizeEffectDispatchRecord,
  normalizeInstrumentLease,
} = require("../../../mcp/domains/physical/instrument-lease-contract.js");
const {
  assertDurableInstrumentLeaseBrokerPort,
} = require("./instrument-lease-store.js");
const {
  normalizeOpaqueRef,
} = require("../../../mcp/domains/physical/physical-quantities.js");
const {
  assertVerifiedActivePhysicalExecutionGrant,
} = require("../../../mcp/domains/physical/physical-authority.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const BROKER_VERSION = 1;
const BROKER_OUTCOME_VALUES = Object.freeze([
  "confirmed",
  "rejected",
  "ambiguous",
  "unavailable",
]);
const MAX_PROVIDERS = 64;
const MAX_ADMISSIONS = 1024;
const MAX_INSTRUMENTS_PER_PROVIDER = 256;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = Object.keys(value).filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertToken(value, label) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)) {
    throw new Error(`${label} must be a bounded opaque token`);
  }
  return value;
}

function grantFencingTokenCandidate(grantProjection, label) {
  if (grantProjection == null || typeof grantProjection !== "object"
      || Array.isArray(grantProjection)) {
    throw new Error(`${label} must be a verified active grant projection`);
  }
  const descriptor = Object.getOwnPropertyDescriptor(grantProjection, "fencing_token");
  if (!descriptor || descriptor.enumerable !== true
      || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
    throw new Error(`${label}.fencing_token must be an enumerable data property`);
  }
  return assertToken(descriptor.value, `${label}.fencing_token`);
}

function rehydrateLeaseFence(record, fencingToken, label) {
  if (!record || !Object.prototype.hasOwnProperty.call(record, "lease_digest")
      || Object.prototype.hasOwnProperty.call(record, "fencing_token")) {
    throw new Error(`${label} must be a redacted digest-bound durable lease`);
  }
  return normalizeInstrumentLease({ ...record, fencing_token: fencingToken }, label);
}

function rehydrateJournalFence(record, fencingToken, label) {
  if (!record || !Object.prototype.hasOwnProperty.call(record, "journal_entry_digest")
      || Object.prototype.hasOwnProperty.call(record, "fencing_token")) {
    throw new Error(`${label} must be a redacted digest-bound durable journal`);
  }
  return normalizeAttemptJournalEntry({ ...record, fencing_token: fencingToken }, label);
}

function assertInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function bindProviderMethods(provider) {
  assertProviderInterface(provider);
  const methods = {};
  for (const method of PROVIDER_METHODS) methods[method] = provider[method].bind(provider);
  return Object.freeze(methods);
}

function attenuateLeaseStore(store) {
  assertDurableInstrumentLeaseBrokerPort(store);
  const methods = {};
  for (const name of ["appendJournal", "commitDispatch", "snapshot"]) {
    if (typeof store[name] !== "function") throw new Error(`lease_store.${name} must be a function`);
    methods[name] = store[name].bind(store);
  }
  return Object.freeze(methods);
}

function providerErrorCode(error) {
  if (error && error.code === "broker_provider_timeout") return "provider_timeout";
  if (error && typeof error.code === "string" && IDENTIFIER_PATTERN.test(error.code)) return error.code;
  return "provider_unavailable";
}

function brokerError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function assertProviderTransition(previous, next, operationRegistry) {
  try {
    return assertAttemptTransition(previous, next, operationRegistry);
  } catch (cause) {
    const error = brokerError("provider_invalid_transition", cause.message);
    Object.defineProperty(error, "cause", { value: cause });
    throw error;
  }
}

function assertProviderJournalAlignment(journal, report, operationRegistry) {
  try {
    return assertProviderAlignedJournalState(journal, report, operationRegistry);
  } catch (cause) {
    const error = brokerError("provider_invalid_transition", cause.message);
    Object.defineProperty(error, "cause", { value: cause });
    throw error;
  }
}

function createInstrumentBroker(input = {}) {
  assertClosedObject(
    input,
    "instrument_broker",
    [
      "operation_registry",
      "effect_registry",
      "lease_store",
      "grant_verifier",
      "execution_principal_id",
      "providers",
      "admissions",
    ],
    ["now", "provider_call_timeout_ms"],
  );
  const operationRegistry = input.operation_registry;
  const effectRegistry = input.effect_registry;
  if (!operationRegistry || typeof operationRegistry.get !== "function"
      || typeof operationRegistry.ids !== "function"
      || typeof operationRegistry.registry_digest !== "string") {
    throw new Error("instrument_broker.operation_registry must be a closed operation registry");
  }
  if (!effectRegistry || typeof effectRegistry.get !== "function") {
    throw new Error("instrument_broker.effect_registry must be a closed effect registry");
  }
  const grantVerifier = input.grant_verifier;
  const store = attenuateLeaseStore(input.lease_store);
  const executionPrincipalId = normalizeOpaqueRef(
    input.execution_principal_id,
    "instrument_broker.execution_principal_id",
    { prefix: "principal" },
  );
  const now = input.now == null ? () => new Date() : input.now;
  if (typeof now !== "function") throw new Error("instrument_broker.now must be a function");
  const providerCallTimeoutMs = input.provider_call_timeout_ms == null
    ? 30_000
    : assertInteger(input.provider_call_timeout_ms, "provider_call_timeout_ms", 1, 600_000);

  if (!Array.isArray(input.providers) || input.providers.length < 1
      || input.providers.length > MAX_PROVIDERS) {
    throw new Error(`instrument_broker.providers must contain 1-${MAX_PROVIDERS} entries`);
  }
  const providersByDescriptor = new WeakMap();
  const providersByInstrument = new Map();
  const providerRecords = [];
  for (let index = 0; index < input.providers.length; index += 1) {
    const registration = input.providers[index];
    assertClosedObject(
      registration,
      `instrument_broker.providers[${index}]`,
      ["provider_projection", "provider", "instrument_refs"],
    );
    const descriptor = registration.provider_projection;
    assertProviderActiveAbiCompatible(descriptor);
    if (descriptor.operation_registry_digest !== operationRegistry.registry_digest) {
      throw new Error(`instrument_broker.providers[${index}] operation registry drift`);
    }
    if (providersByDescriptor.has(descriptor)) {
      throw new Error("instrument_broker.providers cannot repeat a provider projection");
    }
    const unsupportedCapability = descriptor.capabilities.find((capability) => (
      capability.restore_policy !== "not_required"
      || capability.stop_semantics !== "not_applicable"
    ));
    if (unsupportedCapability) {
      throw new Error(
        `instrument broker v${BROKER_VERSION} cannot own capability ${unsupportedCapability.capability_id}`
        + " until stop/restoration dispatch is durably implemented",
      );
    }
    if (!Array.isArray(registration.instrument_refs) || registration.instrument_refs.length < 1
        || registration.instrument_refs.length > MAX_INSTRUMENTS_PER_PROVIDER) {
      throw new Error(
        `instrument_broker.providers[${index}].instrument_refs must contain 1-${MAX_INSTRUMENTS_PER_PROVIDER} entries`,
      );
    }
    const instrumentRefs = registration.instrument_refs.map((instrumentRef, instrumentIndex) => (
      normalizeOpaqueRef(
        instrumentRef,
        `instrument_broker.providers[${index}].instrument_refs[${instrumentIndex}]`,
        { prefix: "instrument" },
      )
    ));
    if (new Set(instrumentRefs).size !== instrumentRefs.length) {
      throw new Error(`instrument_broker.providers[${index}].instrument_refs cannot contain duplicates`);
    }
    const record = {
      descriptor,
      descriptor_checked: false,
      instrument_refs: Object.freeze([...instrumentRefs].sort()),
      methods: bindProviderMethods(registration.provider),
    };
    for (const instrumentRef of instrumentRefs) {
      if (providersByInstrument.has(instrumentRef)) {
        throw new Error(`instrument ${instrumentRef} is assigned to multiple providers`);
      }
      providersByInstrument.set(instrumentRef, record);
    }
    providersByDescriptor.set(descriptor, record);
    providerRecords.push(record);
  }

  if (!Array.isArray(input.admissions) || input.admissions.length < 1
      || input.admissions.length > MAX_ADMISSIONS) {
    throw new Error(`instrument_broker.admissions must contain 1-${MAX_ADMISSIONS} entries`);
  }
  const initialSnapshot = store.snapshot();
  const admissionsByGrant = new WeakMap();
  const admissionIds = new Set();
  const admittedAttemptRefs = new Set();
  const admittedLeaseIds = new Set();
  for (let index = 0; index < input.admissions.length; index += 1) {
    const admission = input.admissions[index];
    assertClosedObject(
      admission,
      `instrument_broker.admissions[${index}]`,
      ["grant_projection", "provider_projection", "lease_id"],
    );
    const providerRecord = providersByDescriptor.get(admission.provider_projection);
    if (!providerRecord) {
      throw new Error(`instrument_broker.admissions[${index}] provider projection is not registered`);
    }
    const leaseId = assertToken(admission.lease_id, `instrument_broker.admissions[${index}].lease_id`);
    const leaseValue = initialSnapshot.leases.find((candidate) => candidate.lease_id === leaseId);
    if (!leaseValue) throw new Error(`instrument_broker.admissions[${index}] lease is not durable`);
    const fencingToken = grantFencingTokenCandidate(
      admission.grant_projection,
      `instrument_broker.admissions[${index}].grant_projection`,
    );
    const lease = rehydrateLeaseFence(
      leaseValue,
      fencingToken,
      `instrument_broker.admissions[${index}].durable_lease`,
    );
    if (lease.execution_principal_id !== executionPrincipalId) {
      throw new Error(`instrument_broker.admissions[${index}] durable lease execution principal drift`);
    }
    const journalValue = initialSnapshot.journal_heads.find((candidate) => (
      candidate.attempt_ref === lease.attempt_ref
    ));
    if (!journalValue) {
      throw new Error(`instrument_broker.admissions[${index}] precommitted journal is not durable`);
    }
    const journal = rehydrateJournalFence(
      journalValue,
      fencingToken,
      `instrument_broker.admissions[${index}].durable_journal`,
    );
    if (journal.state !== "precommitted" || journal.sequence !== 0
        || journal.provider_sequence !== 0
        || journal.lease_id !== lease.lease_id
        || journal.instrument_ref !== lease.instrument_ref
        || journal.operation_id !== lease.operation_id
        || journal.execution_request_digest !== lease.execution_request_digest
        || journal.experiment_plan_hash == null
        || journal.execution_lineage_digest == null
        || journal.provider_id !== providerRecord.descriptor.provider_id
        || journal.provider_descriptor_digest !== providerRecord.descriptor.descriptor_digest
        || journal.fencing_token !== lease.fencing_token
        || journal.fencing_generation !== lease.fencing_generation) {
      throw new Error(`instrument_broker.admissions[${index}] durable precommit binding drift`);
    }
    const operation = operationRegistry.get(lease.operation_id);
    if (!operation) {
      throw new Error(`instrument_broker.admissions[${index}] durable lease operation is not registered`);
    }
    const attemptId = lease.attempt_ref.slice("attempt:".length);
    const grantExpectedBindings = deepFreeze({
      execution_request_digest: lease.execution_request_digest,
      authority_resolution_digest: journal.authority_resolution_digest,
      execution_principal_id: executionPrincipalId,
      provider_id: providerRecord.descriptor.provider_id,
      provider_descriptor_digest: providerRecord.descriptor.descriptor_digest,
      instrument_ref: lease.instrument_ref,
      operation_id: lease.operation_id,
      operation_digest: operation.operation_digest,
      attempt_id: attemptId,
      experiment_plan_hash: journal.experiment_plan_hash,
      execution_lineage_digest: journal.execution_lineage_digest,
      lease_id: lease.lease_id,
      fencing_token: fencingToken,
      fencing_generation: lease.fencing_generation,
      resource_bundle_digest: lease.resource_bundle_digest,
    });
    const grant = assertVerifiedActivePhysicalExecutionGrant(
      admission.grant_projection,
      grantVerifier,
      grantExpectedBindings,
    );
    if (Date.parse(lease.effect_not_before) < Date.parse(grant.not_before)
        || Date.parse(lease.effect_deadline) > Date.parse(grant.expires_at)) {
      throw new Error(
        `instrument_broker.admissions[${index}] durable lease effect window exceeds the signed grant`,
      );
    }
    for (const [field, expected] of [
      ["signed_grant_digest", journal.signed_grant_digest],
      ["replay_claim_digest", journal.replay_claim_digest],
      ["replay_reservation_receipt_digest", journal.replay_reservation_receipt_digest],
      ["workspace_snapshot_digest", journal.workspace_snapshot_digest],
      ["cleanup_plan_digest", journal.cleanup_plan_digest],
    ]) {
      if (grant[field] !== expected) {
        throw new Error(`instrument_broker.admissions[${index}] durable grant ${field} drift`);
      }
    }
    if (!providerRecord.instrument_refs.includes(grant.instrument_ref)) {
      throw new Error(`instrument_broker.admissions[${index}] instrument is not assigned to its provider`);
    }
    const admissionId = `${lease.attempt_ref}:${grant.projection_digest}`;
    if (admissionIds.has(admissionId) || admittedAttemptRefs.has(lease.attempt_ref)
        || admittedLeaseIds.has(lease.lease_id)
        || admissionsByGrant.has(admission.grant_projection)) {
      throw new Error("instrument_broker.admissions cannot duplicate an attempt, lease, or grant binding");
    }
    admissionIds.add(admissionId);
    admittedAttemptRefs.add(lease.attempt_ref);
    admittedLeaseIds.add(lease.lease_id);
    admissionsByGrant.set(admission.grant_projection, Object.freeze({
      grant,
      grant_expected_bindings: grantExpectedBindings,
      lease_digest: lease.lease_digest,
      lease_id: lease.lease_id,
      fencing_generation: lease.fencing_generation,
      initial_journal_entry_ref: journal.journal_entry_ref,
      initial_journal_entry_digest: journal.journal_entry_digest,
      provider_id: journal.provider_id,
      provider_descriptor_digest: journal.provider_descriptor_digest,
      prepared_provider_sequence: journal.provider_sequence + 1,
      provider_request_digest: journal.provider_request_digest,
      provider_projection: admission.provider_projection,
      provider_record: providerRecord,
    }));
  }

  const busyInstruments = new Set();
  const pendingProviderCalls = new Map();
  let closed = false;
  let lastNowMs = null;

  function nowIso() {
    const value = now();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
      throw new Error("instrument broker clock returned an invalid Date");
    }
    if (lastNowMs != null && value.getTime() < lastNowMs) {
      throw new Error("instrument broker clock moved backwards");
    }
    lastNowMs = value.getTime();
    return value.toISOString();
  }

  function outcome(kind, context, reasonCode, options = {}) {
    if (!BROKER_OUTCOME_VALUES.includes(kind)) throw new Error(`unsupported broker outcome ${kind}`);
    const value = {
      version: BROKER_VERSION,
      kind,
      reason_code: assertIdentifier(reasonCode, "broker_outcome.reason_code"),
      attempt_ref: context.lease.attempt_ref,
      instrument_ref: context.lease.instrument_ref,
      operation_id: context.lease.operation_id,
      execution_request_digest: context.lease.execution_request_digest,
      provider_id: context.provider.descriptor.provider_id,
      provider_request_digest: context.prepare == null ? null : context.prepare.request_digest,
      lease_id: context.lease.lease_id,
      fencing_generation: context.lease.fencing_generation,
      journal_entry_digest: options.journal_entry_digest || null,
      dispatch_record_digest: options.dispatch_record_digest || null,
      provider_receipt_ref: options.provider_receipt_ref || null,
      public_result: options.public_result || null,
      reconciliation_required: kind === "ambiguous",
    };
    assertNoPublicByteMaterial(value, "broker_outcome");
    return deepFreeze(value);
  }

  function requireAdmission(request, label, { requireLiveGrant = true } = {}) {
    assertClosedObject(
      request,
      label,
      [
        "grant_projection",
        "provider_projection",
        "lease_id",
        "prepare_request",
      ],
    );
    const admission = admissionsByGrant.get(request.grant_projection);
    if (!admission || admission.provider_projection !== request.provider_projection
        || admission.lease_id !== request.lease_id) {
      throw new Error(`${label} requires the exact broker-enrolled grant, provider, and lease projections`);
    }
    const currentTime = Date.parse(nowIso());
    if (requireLiveGrant) {
      assertVerifiedActivePhysicalExecutionGrant(
        request.grant_projection,
        grantVerifier,
        admission.grant_expected_bindings,
      );
    }
    if (requireLiveGrant && (currentTime < Date.parse(admission.grant.not_before)
        || currentTime >= Date.parse(admission.grant.expires_at))) {
      throw new Error(`${label} grant is outside its enrolled validity window`);
    }
    const prepare = normalizePrepareRequest(request.prepare_request, {
      descriptor: admission.provider_record.descriptor,
      operation_registry: operationRegistry,
      effect_registry: effectRegistry,
    }, `${label}.prepare_request`);
    const providerPrepareRequest = { ...prepare };
    delete providerPrepareRequest.request_digest;
    const grant = admission.grant;
    for (const [field, expected] of [
      ["instrument_ref", grant.instrument_ref],
      ["operation_id", grant.operation_id],
      ["operation_digest", grant.operation_digest],
    ]) {
      if (prepare[field] !== expected) throw new Error(`${label}.prepare_request ${field} grant drift`);
    }
    if (hashCanonicalJson(prepare.parameters) !== grant.parameter_digest) {
      throw new Error(`${label}.prepare_request parameters drift from the grant`);
    }
    if (hashCanonicalJson(prepare.requested_effects) !== grant.requested_effects_digest) {
      throw new Error(`${label}.prepare_request effects drift from the grant`);
    }
    if (prepare.journal_entry_ref !== admission.initial_journal_entry_ref
        || prepare.request_digest !== admission.provider_request_digest) {
      throw new Error(`${label}.prepare_request does not match the durable precommit`);
    }
    const snapshot = store.snapshot();
    const leaseValue = snapshot.leases.find((candidate) => candidate.lease_id === admission.lease_id);
    if (!leaseValue) throw new Error(`${label} durable lease is unavailable`);
    const lease = rehydrateLeaseFence(
      leaseValue,
      grant.fencing_token,
      `${label}.durable_lease`,
    );
    if (Date.parse(lease.effect_deadline) > Date.parse(prepare.execution_deadline)
        || Date.parse(lease.effect_not_before) >= Date.parse(prepare.execution_deadline)) {
      throw new Error(`${label} durable lease effect window exceeds the prepare execution deadline`);
    }
    for (const [field, expected] of [
      ["attempt_ref", prepare.attempt_ref],
      ["instrument_ref", grant.instrument_ref],
      ["operation_id", grant.operation_id],
      ["execution_request_digest", grant.execution_request_digest],
      ["execution_principal_id", executionPrincipalId],
      ["fencing_token", grant.fencing_token],
      ["fencing_generation", admission.fencing_generation],
      ["resource_bundle_digest", grant.resource_bundle_digest],
    ]) {
      if (lease[field] !== expected) throw new Error(`${label} durable lease ${field} drift`);
    }
    return {
      admission,
      grant,
      lease,
      prepare,
      provider_prepare_request: deepFreeze(providerPrepareRequest),
      provider: admission.provider_record,
      snapshot,
    };
  }

  async function callProvider(context, method, argument) {
    const callPromise = Promise.resolve().then(() => context.provider.methods[method](argument));
    let timer = null;
    const timeoutPromise = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        const error = new Error(`provider ${method} exceeded the broker call deadline`);
        error.code = "broker_provider_timeout";
        Object.defineProperty(error, "pending_provider_call", { value: callPromise });
        reject(error);
      }, providerCallTimeoutMs);
    });
    try {
      return await Promise.race([callPromise, timeoutPromise]);
    } finally {
      clearTimeout(timer);
    }
  }

  async function ensureDescriptor(context) {
    if (context.provider.descriptor_checked) return;
    const described = await callProvider(context, "describe");
    const normalized = normalizeProviderDescriptor(
      described,
      operationRegistry,
      effectRegistry,
      "broker.provider_descriptor",
    );
    if (normalized.provider_id !== context.provider.descriptor.provider_id
        || normalized.descriptor_digest !== context.provider.descriptor.descriptor_digest) {
      throw new Error("provider descriptor drifted from the enrolled projection");
    }
    context.provider.descriptor_checked = true;
  }

  function currentAttemptState(context) {
    const snapshot = store.snapshot();
    const leaseValue = snapshot.leases.find((candidate) => candidate.lease_id === context.lease.lease_id);
    if (!leaseValue) throw new Error("durable lease disappeared");
    const lease = rehydrateLeaseFence(
      leaseValue,
      context.grant.fencing_token,
      "instrument_broker.current_attempt.lease",
    );
    const journalValue = snapshot.journal_heads.find((entry) => (
      entry.attempt_ref === lease.attempt_ref
    )) || null;
    const journal = journalValue == null
      ? null
      : rehydrateJournalFence(
        journalValue,
        context.grant.fencing_token,
        "instrument_broker.current_attempt.journal",
      );
    const dispatchValue = snapshot.dispatches.find((entry) => (
      entry.attempt_ref === lease.attempt_ref
    )) || null;
    const dispatch = dispatchValue;
    return { dispatch, journal, lease, snapshot };
  }

  function assertExecutableFence(context, lease, label) {
    try {
      assertVerifiedActivePhysicalExecutionGrant(
        context.grant,
        grantVerifier,
        context.admission.grant_expected_bindings,
      );
    } catch (cause) {
      const error = brokerError(
        "authorization_revalidation_failed",
        `${label} active grant revalidation failed`,
      );
      Object.defineProperty(error, "cause", { value: cause });
      throw error;
    }
    for (const field of [
      "lease_id",
      "instrument_ref",
      "attempt_ref",
      "operation_id",
      "execution_request_digest",
      "execution_principal_id",
      "fencing_token",
      "fencing_generation",
      "resource_bundle_digest",
      "effect_not_before",
      "effect_deadline",
    ]) {
      if (lease[field] !== context.lease[field]) {
        throw brokerError("stale_fence", `${label} ${field} drift`);
      }
    }
    if (lease.state !== "held") {
      throw brokerError("lease_not_executable", `${label} lease is ${lease.state}, not held`);
    }
    const observed = Date.parse(nowIso());
    if (observed >= Date.parse(lease.heartbeat_deadline) || observed >= Date.parse(lease.expires_at)) {
      throw brokerError("lease_not_executable", `${label} lease effect window has expired`);
    }
    if (observed < Date.parse(context.grant.not_before)
        || observed >= Date.parse(context.grant.expires_at)) {
      throw brokerError("authorization_window_expired", `${label} grant effect window has expired`);
    }
    if (observed >= Date.parse(context.prepare.execution_deadline)) {
      throw brokerError("authorization_window_expired", `${label} prepare execution deadline has expired`);
    }
  }

  function nextJournal(previousInput, state, providerState, effectDisposition, providerSequence) {
    const previous = normalizeAttemptJournalEntry(previousInput);
    const sequence = previous.sequence + 1;
    const timestamp = nowIso();
    const basis = {
      ...previous,
      journal_entry_ref: `journal-entry:${hashCanonicalJson({
        attempt_ref: previous.attempt_ref,
        sequence,
        state,
        provider_state: providerState,
        provider_sequence: providerSequence,
      }).slice(0, 40)}`,
      state,
      provider_state: providerState,
      provider_sequence: providerSequence,
      effect_disposition: effectDisposition,
      sequence,
      previous_entry_digest: previous.journal_entry_digest,
      recorded_at: timestamp,
      fsynced_at: timestamp,
    };
    delete basis.journal_entry_digest;
    return normalizeAttemptJournalEntry(basis);
  }

  function appendJournalRecover(entry) {
    try {
      return store.appendJournal(entry);
    } catch (error) {
      const snapshot = store.snapshot();
      const observed = snapshot.journal_heads.find((candidate) => (
        candidate.attempt_ref === entry.attempt_ref
      ));
      const hydrated = observed == null
        ? null
        : rehydrateJournalFence(
          observed,
          entry.fencing_token,
          "instrument_broker.append_journal_recovery",
        );
      if (hydrated && hydrated.journal_entry_digest === entry.journal_entry_digest) return hydrated;
      throw error;
    }
  }

  function validateReport(context, raw, label) {
    const report = normalizeAttemptReport(raw, operationRegistry, label);
    for (const [field, expected] of [
      ["attempt_ref", context.prepare.attempt_ref],
      ["operation_id", context.prepare.operation_id],
      ["request_digest", context.prepare.request_digest],
    ]) {
      if (report[field] !== expected) throw new Error(`${label}.${field} provider binding drift`);
    }
    return report;
  }

  function createdReport(context) {
    return normalizeAttemptReport({
      version: PROVIDER_CALL_VERSION,
      attempt_ref: context.prepare.attempt_ref,
      operation_id: context.prepare.operation_id,
      request_digest: context.prepare.request_digest,
      state: "created",
      sequence: 0,
      effect_disposition: "not_dispatched",
      receipt_ref: null,
      public_result: null,
    }, operationRegistry);
  }

  async function prepareAttempt(context, journal) {
    let report;
    if (journal.state === "precommitted") {
      let prepareError = null;
      try {
        report = validateReport(
          context,
          await callProvider(context, "prepare", context.provider_prepare_request),
          "broker.prepare_report",
        );
      } catch (error) {
        if (error && error.pending_provider_call) throw error;
        prepareError = error;
        try {
          report = validateReport(context, await callProvider(context, "status", normalizeStatusRequest({
            version: PROVIDER_CALL_VERSION,
            attempt_ref: context.prepare.attempt_ref,
            operation_id: context.prepare.operation_id,
            request_digest: context.prepare.request_digest,
          })), "broker.prepare_recovery_status_report");
        } catch (statusError) {
          if (statusError && statusError.pending_provider_call) throw statusError;
          throw prepareError;
        }
      }
      report = assertProviderTransition(createdReport(context), report, operationRegistry);
      if (report.state === "refused") {
        const rejected = nextJournal(
          journal,
          "reconciled_no_effect",
          "refused",
          "confirmed_no_effect",
          report.sequence,
        );
        const durable = appendJournalRecover(rejected);
        return { outcome: outcome("rejected", context, "provider_refused", {
          journal_entry_digest: durable.journal_entry_digest,
          provider_receipt_ref: report.receipt_ref,
          public_result: report.public_result,
        }) };
      }
      if (report.state !== "prepared") throw new Error("provider prepare did not reach prepared or refused");
      journal = appendJournalRecover(nextJournal(
        journal,
        "admitted",
        "prepared",
        "not_dispatched",
        report.sequence,
      ));
    } else if (journal.state === "admitted") {
      report = validateReport(context, await callProvider(context, "status", normalizeStatusRequest({
        version: PROVIDER_CALL_VERSION,
        attempt_ref: context.prepare.attempt_ref,
        operation_id: context.prepare.operation_id,
        request_digest: context.prepare.request_digest,
      })), "broker.resume_status_report");
      report = assertProviderJournalAlignment(journal, report, operationRegistry);
      if (report.state !== "prepared") {
        throw new Error(`durable admitted attempt provider state is ${report.state}, not prepared`);
      }
    } else if (journal.state === "effect_starting") {
      report = validateReport(context, await callProvider(context, "status", normalizeStatusRequest({
        version: PROVIDER_CALL_VERSION,
        attempt_ref: context.prepare.attempt_ref,
        operation_id: context.prepare.operation_id,
        request_digest: context.prepare.request_digest,
      })), "broker.effect_starting_status_report");
      report = assertProviderJournalAlignment(journal, report, operationRegistry);
      if (report.state !== "prepared") {
        throw new Error(`durable effect_starting attempt provider state is ${report.state}, not prepared`);
      }
      return { journal, report };
    } else {
      throw new Error(`attempt journal state ${journal.state} is not dispatchable`);
    }

    const capability = context.provider.descriptor.capabilities.find((candidate) => (
      candidate.capability_id === context.prepare.capability_id
    ));
    if (!capability) throw new Error("provider capability disappeared after request normalization");
    if (capability.restore_policy !== "not_required") {
      if (context.grant.snapshot_plan_digest == null) {
        throw new Error("restorable provider capability requires a grant-bound snapshot_plan_digest");
      }
      const snapshotRequest = normalizeSnapshotRequest({
        version: PROVIDER_CALL_VERSION,
        attempt_ref: context.prepare.attempt_ref,
        instrument_ref: context.prepare.instrument_ref,
        operation_id: context.prepare.operation_id,
        request_digest: context.prepare.request_digest,
        expected_state: "prepared",
        expected_sequence: report.sequence,
        snapshot_plan_digest: context.grant.snapshot_plan_digest,
      });
      normalizeSnapshotResponse(
        await callProvider(context, "snapshot", snapshotRequest),
        snapshotRequest,
        "broker.snapshot_response",
      );
    }
    const starting = nextJournal(
      journal,
      "effect_starting",
      "prepared",
      "not_dispatched",
      report.sequence,
    );
    return { journal: appendJournalRecover(starting), report };
  }

  function makeDispatch(context, journal) {
    const dispatchedAt = nowIso();
    const dispatch = normalizeEffectDispatchRecord({
      version: EFFECT_DISPATCH_VERSION,
      dispatch_event_ref: `dispatch-event:${hashCanonicalJson({
        attempt_ref: context.prepare.attempt_ref,
        provider_id: context.provider.descriptor.provider_id,
        provider_descriptor_digest: context.provider.descriptor.descriptor_digest,
        provider_request_digest: context.prepare.request_digest,
        provider_sequence: journal.provider_sequence,
      }).slice(0, 40)}`,
      journal_entry_ref: journal.journal_entry_ref,
      journal_entry_digest: journal.journal_entry_digest,
      attempt_ref: journal.attempt_ref,
      instrument_ref: journal.instrument_ref,
      lease_id: journal.lease_id,
      fencing_token: journal.fencing_token,
      fencing_generation: journal.fencing_generation,
      operation_id: journal.operation_id,
      execution_request_digest: journal.execution_request_digest,
      provider_id: context.provider.descriptor.provider_id,
      provider_descriptor_digest: context.provider.descriptor.descriptor_digest,
      provider_request_digest: context.prepare.request_digest,
      provider_sequence: journal.provider_sequence,
      dispatched_at: dispatchedAt,
    }, journal);
    return { dispatch };
  }

  function makeExecuteRequest(context, journal, dispatchCredential) {
    return normalizeExecuteRequest({
      version: PROVIDER_CALL_VERSION,
      attempt_ref: context.prepare.attempt_ref,
      operation_id: context.prepare.operation_id,
      request_digest: context.prepare.request_digest,
      expected_state: "prepared",
      expected_sequence: journal.provider_sequence,
      dispatch_journal_ref: journal.journal_entry_ref,
      dispatch_credential: dispatchCredential,
    });
  }

  function appendConfirmedReport(context, headInput, report) {
    let head = normalizeAttemptJournalEntry(headInput);
    if (head.state === "reconciled_no_effect"
        && ["refused", "reconciled_no_effect"].includes(report.state)) {
      return outcome("rejected", context, "reconciled_no_effect", {
        journal_entry_digest: head.journal_entry_digest,
        provider_receipt_ref: report.receipt_ref,
        public_result: report.public_result,
      });
    }
    if (["quarantined", "unknown_effect"].includes(report.state)) {
      if (head.state !== report.state) {
        head = appendJournalRecover(nextJournal(
          head,
          report.state,
          report.state,
          report.effect_disposition,
          report.sequence,
        ));
      }
      return outcome("ambiguous", context, `provider_${report.state}`, {
        journal_entry_digest: head.journal_entry_digest,
        provider_receipt_ref: report.receipt_ref,
        public_result: report.public_result,
      });
    }
    if (report.state === "acknowledged") {
      if (head.state === "effect_starting") {
        head = appendJournalRecover(nextJournal(
          head,
          "running",
          "dispatched",
          "ambiguous",
          report.sequence - 1,
        ));
      }
      if (head.state === "running") {
        head = appendJournalRecover(nextJournal(
          head,
          "effect_recorded",
          "acknowledged",
          "confirmed_effect",
          report.sequence,
        ));
      } else if (head.state === "ambiguous_effect") {
        head = appendJournalRecover(nextJournal(
          head,
          "restoring",
          "acknowledged",
          "confirmed_effect",
          report.sequence,
        ));
      }
      if (!["effect_recorded", "restoring", "restored", "irreversible_authorized"].includes(head.state)) {
        throw new Error(`cannot durably project acknowledged provider state from ${head.state}`);
      }
      return outcome("confirmed", context, "provider_acknowledged", {
        journal_entry_digest: head.journal_entry_digest,
        provider_receipt_ref: report.receipt_ref,
        public_result: report.public_result,
      });
    }
    if (["refused", "reconciled_no_effect"].includes(report.state)) {
      if (!["precommitted", "admitted", "effect_starting", "ambiguous_effect"].includes(head.state)) {
        return outcome("ambiguous", context, "journal_reconciliation_gap", {
          journal_entry_digest: head.journal_entry_digest,
          provider_receipt_ref: report.receipt_ref,
          public_result: report.public_result,
        });
      }
      head = appendJournalRecover(nextJournal(
        head,
        "reconciled_no_effect",
        report.state,
        "confirmed_no_effect",
        report.sequence,
      ));
      return outcome("rejected", context, "reconciled_no_effect", {
        journal_entry_digest: head.journal_entry_digest,
        provider_receipt_ref: report.receipt_ref,
        public_result: report.public_result,
      });
    }
    if (report.state === "dispatched" && head.state === "effect_starting") {
      head = appendJournalRecover(nextJournal(
        head,
        "running",
        "dispatched",
        "ambiguous",
        report.sequence,
      ));
    }
    return outcome("ambiguous", context, `provider_${report.state}`, {
      journal_entry_digest: head.journal_entry_digest,
      provider_receipt_ref: report.receipt_ref,
    });
  }

  function durableNoEffectOutcome(context, durable) {
    return outcome("rejected", context, "reconciled_no_effect", {
      journal_entry_digest: durable.journal.journal_entry_digest,
      dispatch_record_digest: durable.dispatch ? durable.dispatch.dispatch_record_digest : null,
    });
  }

  async function executeOnce(request) {
    if (closed) throw new Error("instrument broker is closed");
    const context = requireAdmission(request, "broker.execute_once");
    if (busyInstruments.has(context.lease.instrument_ref)) {
      return outcome("ambiguous", context, "dispatch_in_progress");
    }
    busyInstruments.add(context.lease.instrument_ref);
    let pendingCall = null;
    try {
      let durable = currentAttemptState(context);
      if (!durable.journal) throw new Error("broker.execute_once requires a durable precommitted journal");
      if (durable.journal.attempt_ref !== context.prepare.attempt_ref
          || durable.journal.execution_request_digest !== context.grant.execution_request_digest
          || durable.journal.provider_id !== context.provider.descriptor.provider_id
          || durable.journal.provider_descriptor_digest !== context.provider.descriptor.descriptor_digest
          || durable.journal.provider_request_digest !== context.prepare.request_digest) {
        throw new Error("broker.execute_once precommitted journal binding drift");
      }
      if (durable.journal.state === "reconciled_no_effect") {
        return durableNoEffectOutcome(context, durable);
      }
      try {
        assertExecutableFence(context, durable.lease, "broker.execute_once");
      } catch (error) {
        return outcome("unavailable", context, "lease_not_executable", {
          journal_entry_digest: durable.journal ? durable.journal.journal_entry_digest : null,
          dispatch_record_digest: durable.dispatch ? durable.dispatch.dispatch_record_digest : null,
        });
      }
      if (durable.dispatch) {
        if (durable.dispatch.provider_id !== context.provider.descriptor.provider_id
            || durable.dispatch.provider_descriptor_digest !== context.provider.descriptor.descriptor_digest
            || durable.dispatch.provider_sequence !== context.admission.prepared_provider_sequence
            || durable.dispatch.provider_request_digest !== context.prepare.request_digest) {
          throw new Error("durable dispatch provider binding drift");
        }
        return outcome("ambiguous", context, "dispatch_already_committed", {
          journal_entry_digest: durable.journal.journal_entry_digest,
          dispatch_record_digest: durable.dispatch.dispatch_record_digest,
        });
      }
      try {
        await ensureDescriptor(context);
        const prepared = await prepareAttempt(context, durable.journal);
        if (prepared.outcome) return prepared.outcome;
        durable = currentAttemptState(context);
        const journal = normalizeAttemptJournalEntry(prepared.journal || durable.journal);
        if (journal.state !== "effect_starting") {
          throw new Error("broker did not durably reach effect_starting before dispatch");
        }
        assertExecutableFence(context, durable.lease, "broker.pre_dispatch_fence");
        const { dispatch } = makeDispatch(context, journal);
        let committed;
        try {
          committed = store.commitDispatch(dispatch);
        } catch (error) {
          const observed = currentAttemptState(context);
          if (observed.dispatch) {
            if (observed.dispatch.provider_request_digest !== context.prepare.request_digest
                || observed.dispatch.provider_id !== context.provider.descriptor.provider_id
                || observed.dispatch.provider_descriptor_digest
                  !== context.provider.descriptor.descriptor_digest
                || observed.dispatch.provider_sequence !== journal.provider_sequence
                || observed.dispatch.execution_request_digest !== context.grant.execution_request_digest) {
              return outcome("ambiguous", context, "dispatch_binding_conflict", {
                journal_entry_digest: journal.journal_entry_digest,
                dispatch_record_digest: observed.dispatch.dispatch_record_digest,
              });
            }
            const exactClaim = observed.dispatch.dispatch_record_digest === dispatch.dispatch_record_digest;
            return outcome("ambiguous", context, exactClaim
              ? "dispatch_commit_ack_lost"
              : "dispatch_election_lost", {
              journal_entry_digest: journal.journal_entry_digest,
              dispatch_record_digest: observed.dispatch.dispatch_record_digest,
            });
          }
          return outcome("unavailable", context, "dispatch_commit_unavailable", {
            journal_entry_digest: journal.journal_entry_digest,
          });
        }
        if (committed.already_committed) {
          return outcome("ambiguous", context, "dispatch_already_committed", {
            journal_entry_digest: journal.journal_entry_digest,
            dispatch_record_digest: committed.dispatch.dispatch_record_digest,
          });
        }
        if (!committed.dispatch_credential) {
          throw brokerError(
            "dispatch_credential_unavailable",
            "durable dispatch winner did not receive provider execution authority",
          );
        }
        const afterClaim = currentAttemptState(context);
        try {
          assertExecutableFence(context, afterClaim.lease, "broker.claimed_dispatch_fence");
        } catch (error) {
          const noEffect = appendJournalRecover(nextJournal(
            journal,
            "reconciled_no_effect",
            "prepared",
            "confirmed_no_effect",
            journal.provider_sequence,
          ));
          return outcome("rejected", context, "fence_won_before_provider", {
            journal_entry_digest: noEffect.journal_entry_digest,
            dispatch_record_digest: dispatch.dispatch_record_digest,
          });
        }
        const executeRequest = makeExecuteRequest(
          context,
          journal,
          committed.dispatch_credential,
        );
        let report;
        try {
          report = validateReport(
            context,
            await callProvider(context, "execute", executeRequest),
            "broker.execute_report",
          );
          report = assertProviderTransition(prepared.report, report, operationRegistry);
          if (!["dispatched", "refused"].includes(report.state)) {
            throw brokerError(
              "provider_invalid_transition",
              `provider execute reached unexpected state ${report.state}`,
            );
          }
        } catch (error) {
          if (error && error.pending_provider_call) {
            pendingCall = Promise.resolve(error.pending_provider_call).catch(() => undefined);
          }
          return outcome("ambiguous", context, providerErrorCode(error), {
            journal_entry_digest: journal.journal_entry_digest,
            dispatch_record_digest: dispatch.dispatch_record_digest,
          });
        }
        const settled = appendConfirmedReport(context, journal, report);
        return deepFreeze({ ...settled, dispatch_record_digest: dispatch.dispatch_record_digest });
      } catch (error) {
        if (error && error.pending_provider_call) {
          pendingCall = Promise.resolve(error.pending_provider_call).catch(() => undefined);
        }
        durable = currentAttemptState(context);
        const kind = durable.dispatch ? "ambiguous" : "unavailable";
        return outcome(kind, context, providerErrorCode(error), {
          journal_entry_digest: durable.journal ? durable.journal.journal_entry_digest : null,
          dispatch_record_digest: durable.dispatch ? durable.dispatch.dispatch_record_digest : null,
        });
      }
    } finally {
      if (pendingCall) {
        pendingProviderCalls.set(context.lease.instrument_ref, pendingCall);
        pendingCall.finally(() => {
          pendingProviderCalls.delete(context.lease.instrument_ref);
          busyInstruments.delete(context.lease.instrument_ref);
        });
      } else {
        busyInstruments.delete(context.lease.instrument_ref);
      }
    }
  }

  async function reconcile(request) {
    if (closed) throw new Error("instrument broker is closed");
    assertClosedObject(request, "broker.reconcile", [
      "grant_projection",
      "provider_projection",
      "lease_id",
      "prepare_request",
      "observation_ref",
    ]);
    const observationRef = normalizeOpaqueRef(
      request.observation_ref,
      "broker.reconcile.observation_ref",
      { prefix: "observation" },
    );
    const context = requireAdmission({
      grant_projection: request.grant_projection,
      provider_projection: request.provider_projection,
      lease_id: request.lease_id,
      prepare_request: request.prepare_request,
    }, "broker.reconcile", { requireLiveGrant: false });
    if (busyInstruments.has(context.lease.instrument_ref)) {
      return outcome("ambiguous", context, "dispatch_in_progress");
    }
    busyInstruments.add(context.lease.instrument_ref);
    let pendingCall = null;
    try {
      let durable = currentAttemptState(context);
      if (durable.journal && durable.journal.state === "reconciled_no_effect") {
        return durableNoEffectOutcome(context, durable);
      }
      if (!durable.dispatch) {
        return outcome("unavailable", context, "dispatch_not_committed", {
          journal_entry_digest: durable.journal ? durable.journal.journal_entry_digest : null,
        });
      }
      if (durable.dispatch.provider_id !== context.provider.descriptor.provider_id
          || durable.dispatch.provider_descriptor_digest !== context.provider.descriptor.descriptor_digest
          || durable.dispatch.provider_sequence !== context.admission.prepared_provider_sequence
          || durable.dispatch.provider_request_digest !== context.prepare.request_digest) {
        throw new Error("broker.reconcile durable provider binding drift");
      }
      try {
        await ensureDescriptor(context);
        let report = validateReport(context, await callProvider(context, "status", normalizeStatusRequest({
          version: PROVIDER_CALL_VERSION,
          attempt_ref: context.prepare.attempt_ref,
          operation_id: context.prepare.operation_id,
          request_digest: context.prepare.request_digest,
        })), "broker.status_report");
        report = assertProviderJournalAlignment(durable.journal, report, operationRegistry);
        if (report.state === "ambiguous_effect") {
          durable = currentAttemptState(context);
          if (["effect_starting", "running", "stop_requested"].includes(durable.journal.state)) {
            appendJournalRecover(nextJournal(
              durable.journal,
              "ambiguous_effect",
              "ambiguous_effect",
              "ambiguous",
              report.sequence,
            ));
          }
          const reconcileRequest = normalizeReconcileRequest({
            version: PROVIDER_CALL_VERSION,
            attempt_ref: context.prepare.attempt_ref,
            operation_id: context.prepare.operation_id,
            request_digest: context.prepare.request_digest,
            expected_sequence: report.sequence,
            observation_ref: observationRef,
          });
          const reconciledReport = validateReport(
            context,
            await callProvider(context, "reconcile", reconcileRequest),
            "broker.reconcile_report",
          );
          report = assertProviderTransition(report, reconciledReport, operationRegistry);
        }
        durable = currentAttemptState(context);
        const settled = appendConfirmedReport(context, durable.journal, report);
        return deepFreeze({
          ...settled,
          dispatch_record_digest: durable.dispatch.dispatch_record_digest,
        });
      } catch (error) {
        if (error && error.pending_provider_call) {
          pendingCall = Promise.resolve(error.pending_provider_call).catch(() => undefined);
        }
        durable = currentAttemptState(context);
        return outcome("ambiguous", context, providerErrorCode(error), {
          journal_entry_digest: durable.journal ? durable.journal.journal_entry_digest : null,
          dispatch_record_digest: durable.dispatch.dispatch_record_digest,
        });
      }
    } finally {
      if (pendingCall) {
        pendingProviderCalls.set(context.lease.instrument_ref, pendingCall);
        pendingCall.finally(() => {
          pendingProviderCalls.delete(context.lease.instrument_ref);
          busyInstruments.delete(context.lease.instrument_ref);
        });
      } else {
        busyInstruments.delete(context.lease.instrument_ref);
      }
    }
  }

  function snapshot() {
    return Object.freeze({
      version: BROKER_VERSION,
      closed,
      provider_count: providerRecords.length,
      admission_count: admissionIds.size,
      busy_instrument_count: busyInstruments.size,
      pending_provider_call_count: pendingProviderCalls.size,
      provider_ids: Object.freeze(providerRecords.map((record) => record.descriptor.provider_id).sort()),
      operation_registry_digest: operationRegistry.registry_digest,
      execution_principal_id: executionPrincipalId,
    });
  }

  function close() {
    if (closed) return Object.freeze({ already_closed: true });
    closed = true;
    return Object.freeze({ already_closed: false });
  }

  return Object.freeze({ close, executeOnce, reconcile, snapshot });
}

module.exports = {
  BROKER_OUTCOME_VALUES,
  INSTRUMENT_BROKER_VERSION: BROKER_VERSION,
  MAX_BROKER_ADMISSIONS: MAX_ADMISSIONS,
  MAX_BROKER_PROVIDERS: MAX_PROVIDERS,
  createInstrumentBroker,
};
