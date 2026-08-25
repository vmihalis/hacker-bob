"use strict";

const { types: utilTypes } = require("node:util");

// Provider-neutral ABI-v3 bootstrap broker. This path is deliberately separate
// from the active lease/snapshot/resource broker and never fabricates those
// bindings. It dispatches only the three closed read-only bootstrap methods.

const {
  PROVIDER_BOOTSTRAP_ABI_VERSION,
  PROVIDER_METHODS,
  assertNoPublicByteMaterial,
  assertProviderBootstrapAbiCompatible,
  assertProviderInterface,
  normalizeProviderBootstrapIntent,
  normalizeProviderBootstrapReport,
  normalizeProviderBootstrapRequest,
  normalizeProviderDescriptor,
} = require("./provider-contract.js");
const {
  normalizeInstrumentBootstrapPrecommitRequest,
} = require("../../../mcp/domains/physical/instrument-bootstrap-contract.js");
const {
  assertInstrumentBootstrapCustodyBinding,
  assertInstrumentBootstrapCustodyBindingForBrokerPort,
  assertInstrumentBootstrapCustodyProjection,
  assertInstrumentBootstrapBrokerPort,
  readInstrumentBootstrapCustodyProjection,
} = require("../../../mcp/domains/physical/instrument-bootstrap-store.js");
const {
  normalizeOpaqueRef,
} = require("../../../mcp/domains/physical/physical-quantities.js");
const {
  assertVerifiedPhysicalBootstrapGrant,
} = require("../../../mcp/domains/physical/physical-authority.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const INSTRUMENT_BOOTSTRAP_BROKER_VERSION = 1;
const MAX_BOOTSTRAP_PROVIDERS = 64;
const MAX_BOOTSTRAP_INSTRUMENTS_PER_PROVIDER = 256;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const METHOD_BY_OPERATION = Object.freeze({
  "instrument.inventory": "inventory",
  "instrument.capabilities": "capabilities",
  "instrument.health": "health",
});
const GRANT_ADMISSION_DATA_FIELDS = Object.freeze([
  "session_nucleus_hash",
  "physical_scope_axis_digest",
  "execution_principal_id",
  "instrument_ref",
  "enrollment_candidate_ref",
  "provider_id",
  "provider_descriptor_digest",
  "provider_binary_digest",
  "transport_digest",
  "bootstrap_manifest_digest",
  "bootstrap_invariants_digest",
  "operation_id",
  "operation_digest",
  "execution_request_digest",
  "authority_resolution_digest",
  "signed_grant_digest",
  "replay_claim_digest",
  "replay_reservation_receipt_digest",
  "not_before",
  "expires_at",
  "projection_digest",
]);

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || utilTypes.isProxy(value)
      || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be a plain object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = keys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !keys.includes(field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const field of keys) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertInteger(value, label, min, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${label} must be a safe integer from ${min} through ${max}`);
  }
  return value;
}

function assertGrantAdmissionData(input) {
  if (!isPlainObject(input) || !Object.isFrozen(input)) {
    throw new Error("bootstrap grant projection must be a frozen plain object");
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  for (const field of GRANT_ADMISSION_DATA_FIELDS) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new Error(`bootstrap grant projection.${field} must be an enumerable data field`);
    }
  }
  return input;
}

function brokerError(code, message, cause = null) {
  const error = new Error(message);
  error.code = code;
  if (cause) Object.defineProperty(error, "cause", { value: cause });
  return error;
}

function bindProviderMethods(provider) {
  assertProviderInterface(provider);
  const methods = {};
  for (const method of PROVIDER_METHODS) methods[method] = provider[method].bind(provider);
  return Object.freeze(methods);
}

function assertBootstrapCapabilities(descriptor, label) {
  const byOperation = new Map();
  for (const capability of descriptor.capabilities) {
    if (!Object.prototype.hasOwnProperty.call(METHOD_BY_OPERATION, capability.operation_id)) continue;
    if (byOperation.has(capability.operation_id)) {
      throw new Error(`${label} declares more than one ${capability.operation_id} capability`);
    }
    if (capability.idempotency !== "read_only_idempotent"
        || capability.stop_semantics !== "not_applicable"
        || capability.restore_policy !== "not_required"
        || capability.worst_case_effects.some((effect) => (
          effect.action !== "observe"
          || effect.persistence !== "none"
          || effect.channel === "rf"
        ))) {
      throw new Error(`${label} ${capability.operation_id} capability is not a local read-only bootstrap observation`);
    }
    byOperation.set(capability.operation_id, capability);
  }
  return byOperation;
}

function attenuateStore(storeInput) {
  const store = assertInstrumentBootstrapBrokerPort(storeInput);
  const methods = {};
  for (const method of [
    "precommitAttempt",
    "commitDispatch",
    "markAmbiguous",
    "readAttempt",
    "snapshot",
  ]) {
    if (typeof store[method] !== "function") {
      throw new Error(`instrument bootstrap store port lacks ${method}`);
    }
    methods[method] = store[method].bind(store);
  }
  return Object.freeze(methods);
}

function sampleConnection(instrument, label) {
  let result;
  try {
    result = assertInstrumentBootstrapCustodyProjection(
      readInstrumentBootstrapCustodyProjection(instrument.custody_binding),
    );
  } catch (cause) {
    throw brokerError("bootstrap_connection_unavailable", `${label} failed`, cause);
  }
  if (result.connected !== true) {
    throw brokerError("bootstrap_connection_unavailable", `${label} is not connected`);
  }
  return result;
}

function deriveAttemptRef(grant) {
  const digest = hashCanonicalJson({
    domain: "hacker-bob/instrument-bootstrap-broker-attempt/v1",
    session_nucleus_hash: grant.session_nucleus_hash,
    execution_request_digest: grant.execution_request_digest,
    signed_grant_digest: grant.signed_grant_digest,
    provider_descriptor_digest: grant.provider_descriptor_digest,
    instrument_ref: grant.instrument_ref,
    operation_id: grant.operation_id,
  });
  return `bootstrap-attempt:v1:${digest}`;
}

function terminalResult(attempt) {
  const terminalKind = attempt.provider_report
    ? "provider_report"
    : attempt.durable_ambiguity
      ? "durable_ambiguity"
      : null;
  const result = {
    version: INSTRUMENT_BOOTSTRAP_BROKER_VERSION,
    attempt_ref: attempt.attempt_ref,
    state: attempt.state,
    outcome: attempt.state,
    reason_code: attempt.terminal_reason_code,
    recovery_disposition: attempt.recovery_disposition,
    bootstrap_intent_digest: attempt.bootstrap_intent_digest,
    bootstrap_request_digest: attempt.dispatch
      ? attempt.dispatch.bootstrap_request_digest : null,
    dispatch_record_digest: attempt.dispatch
      ? attempt.dispatch.dispatch_record_digest : null,
    custody_binding_digest: attempt.custody_binding_digest,
    connection_ref: attempt.connection_ref,
    connection_generation: attempt.connection_generation,
    terminal_kind: terminalKind,
    provider_report: attempt.provider_report,
    durable_ambiguity: attempt.durable_ambiguity,
  };
  assertNoPublicByteMaterial(result, "instrument_bootstrap_broker.result");
  return deepFreeze(result);
}

function unavailableResult(context, attempt, reasonCode) {
  const result = {
    version: INSTRUMENT_BOOTSTRAP_BROKER_VERSION,
    attempt_ref: context.attempt_ref,
    state: attempt ? attempt.state : "not_started",
    outcome: "unavailable",
    reason_code: reasonCode,
    recovery_disposition: attempt ? attempt.recovery_disposition : null,
    bootstrap_intent_digest: attempt ? attempt.bootstrap_intent_digest
      : context.intent ? context.intent.bootstrap_intent_digest : null,
    bootstrap_request_digest: attempt && attempt.dispatch
      ? attempt.dispatch.bootstrap_request_digest : null,
    dispatch_record_digest: attempt && attempt.dispatch
      ? attempt.dispatch.dispatch_record_digest : null,
    custody_binding_digest: attempt ? attempt.custody_binding_digest
      : context.connection ? context.connection.custody_binding_digest : null,
    connection_ref: context.connection ? context.connection.connection_ref
      : attempt ? attempt.connection_ref : null,
    connection_generation: context.connection
      ? context.connection.connection_generation
      : attempt ? attempt.connection_generation : null,
    terminal_kind: null,
    provider_report: null,
    durable_ambiguity: null,
  };
  assertNoPublicByteMaterial(result, "instrument_bootstrap_broker.result");
  return deepFreeze(result);
}

function createInstrumentBootstrapBroker(input = {}) {
  assertClosedObject(input, "instrument_bootstrap_broker", [
    "operation_registry",
    "effect_registry",
    "bootstrap_store",
    "grant_verifier",
    "execution_principal_id",
    "providers",
  ], ["provider_call_timeout_ms"]);
  const operationRegistry = input.operation_registry;
  const effectRegistry = input.effect_registry;
  if (!operationRegistry || typeof operationRegistry.get !== "function"
      || typeof operationRegistry.ids !== "function"
      || typeof operationRegistry.registry_digest !== "string") {
    throw new Error("instrument_bootstrap_broker.operation_registry must be a closed registry");
  }
  if (!effectRegistry || typeof effectRegistry.get !== "function") {
    throw new Error("instrument_bootstrap_broker.effect_registry must be a closed registry");
  }
  const bootstrapStorePort = assertInstrumentBootstrapBrokerPort(input.bootstrap_store);
  const store = attenuateStore(bootstrapStorePort);
  const grantVerifier = input.grant_verifier;
  const executionPrincipalId = normalizeOpaqueRef(
    input.execution_principal_id,
    "instrument_bootstrap_broker.execution_principal_id",
    { prefix: "principal" },
  );
  const providerCallTimeoutMs = input.provider_call_timeout_ms == null
    ? 30_000
    : assertInteger(
      input.provider_call_timeout_ms,
      "instrument_bootstrap_broker.provider_call_timeout_ms",
      1,
      600_000,
    );
  if (!Array.isArray(input.providers) || input.providers.length < 1
      || input.providers.length > MAX_BOOTSTRAP_PROVIDERS) {
    throw new Error(`instrument_bootstrap_broker.providers must contain 1-${MAX_BOOTSTRAP_PROVIDERS} entries`);
  }

  const providersByDescriptor = new WeakMap();
  const providersByInstrument = new Map();
  const providerRecords = [];
  for (let index = 0; index < input.providers.length; index += 1) {
    const registration = input.providers[index];
    const label = `instrument_bootstrap_broker.providers[${index}]`;
    assertClosedObject(registration, label, [
      "provider_projection",
      "provider",
      "provider_binary_digest",
      "transport_digest",
      "bootstrap_manifest_digest",
      "bootstrap_invariants_digest",
      "instruments",
    ]);
    const descriptor = registration.provider_projection;
    // This check deliberately precedes binding or invoking any provider method.
    assertProviderBootstrapAbiCompatible(descriptor);
    if (descriptor.operation_registry_digest !== operationRegistry.registry_digest) {
      throw new Error(`${label} operation registry drift`);
    }
    if (providersByDescriptor.has(descriptor)) {
      throw new Error(`${label} repeats a provider projection`);
    }
    const providerBinaryDigest = assertDigest(
      registration.provider_binary_digest,
      `${label}.provider_binary_digest`,
    );
    const transportDigest = assertDigest(registration.transport_digest, `${label}.transport_digest`);
    const bootstrapManifestDigest = assertDigest(
      registration.bootstrap_manifest_digest,
      `${label}.bootstrap_manifest_digest`,
    );
    const bootstrapInvariantsDigest = assertDigest(
      registration.bootstrap_invariants_digest,
      `${label}.bootstrap_invariants_digest`,
    );
    if (!Array.isArray(registration.instruments) || registration.instruments.length < 1
        || registration.instruments.length > MAX_BOOTSTRAP_INSTRUMENTS_PER_PROVIDER) {
      throw new Error(`${label}.instruments must contain 1-${MAX_BOOTSTRAP_INSTRUMENTS_PER_PROVIDER} entries`);
    }
    const bootstrapCapabilities = assertBootstrapCapabilities(descriptor, label);
    const record = {
      descriptor,
      descriptor_checked: false,
      methods: bindProviderMethods(registration.provider),
      bootstrap_capabilities: bootstrapCapabilities,
      provider_binary_digest: providerBinaryDigest,
      transport_digest: transportDigest,
      bootstrap_manifest_digest: bootstrapManifestDigest,
      bootstrap_invariants_digest: bootstrapInvariantsDigest,
      instruments: new Map(),
    };
    for (let instrumentIndex = 0; instrumentIndex < registration.instruments.length; instrumentIndex += 1) {
      const raw = registration.instruments[instrumentIndex];
      const instrumentLabel = `${label}.instruments[${instrumentIndex}]`;
      assertClosedObject(raw, instrumentLabel, [
        "instrument_ref",
        "enrollment_candidate_ref",
        "custody_binding",
      ]);
      const instrument = Object.freeze({
        instrument_ref: normalizeOpaqueRef(raw.instrument_ref, `${instrumentLabel}.instrument_ref`, {
          prefix: "instrument",
        }),
        enrollment_candidate_ref: normalizeOpaqueRef(
          raw.enrollment_candidate_ref,
          `${instrumentLabel}.enrollment_candidate_ref`,
          { prefix: "enrollment-candidate" },
        ),
        custody_binding: assertInstrumentBootstrapCustodyBindingForBrokerPort(
          assertInstrumentBootstrapCustodyBinding(raw.custody_binding),
          bootstrapStorePort,
        ),
      });
      if (record.instruments.has(instrument.instrument_ref)
          || providersByInstrument.has(instrument.instrument_ref)) {
        throw new Error(`instrument ${instrument.instrument_ref} is registered more than once`);
      }
      record.instruments.set(instrument.instrument_ref, instrument);
      providersByInstrument.set(instrument.instrument_ref, record);
    }
    providersByDescriptor.set(descriptor, record);
    providerRecords.push(record);
  }

  const inFlight = new Map();
  const instrumentsInFlight = new Map();
  const instrumentQuarantines = new Map();
  let closed = false;

  function quarantineInstrument(context, reasonCode, pendingCall) {
    const instrumentRef = context.instrument.instrument_ref;
    if (instrumentQuarantines.has(instrumentRef)) return;
    const quarantine = {
      instrument_ref: instrumentRef,
      attempt_ref: context.attempt_ref,
      provider_id: context.provider.descriptor.provider_id,
      reason_code: reasonCode,
      provider_call_pending: true,
      provider_call_settled_after_timeout: false,
    };
    instrumentQuarantines.set(instrumentRef, quarantine);
    Promise.resolve(pendingCall).then(
      () => {
        quarantine.provider_call_pending = false;
        quarantine.provider_call_settled_after_timeout = true;
      },
      () => {
        quarantine.provider_call_pending = false;
        quarantine.provider_call_settled_after_timeout = true;
      },
    );
  }

  function expectedGrantBindings(record, grant) {
    return Object.freeze({
      execution_request_digest: grant.execution_request_digest,
      provider_id: record.descriptor.provider_id,
      provider_descriptor_digest: record.descriptor.descriptor_digest,
      bootstrap_manifest_digest: record.bootstrap_manifest_digest,
      provider_binary_digest: record.provider_binary_digest,
      transport_digest: record.transport_digest,
      operation_id: grant.operation_id,
      operation_digest: grant.operation_digest,
      bootstrap_invariants_digest: record.bootstrap_invariants_digest,
    });
  }

  function assertLiveGrant(context, label) {
    try {
      assertVerifiedPhysicalBootstrapGrant(
        context.grant,
        grantVerifier,
        context.expected_grant_bindings,
      );
    } catch (cause) {
      throw brokerError(
        "bootstrap_authorization_revalidation_failed",
        `${label} bootstrap grant revalidation failed`,
        cause,
      );
    }
  }

  function requireContext(request) {
    assertClosedObject(request, "instrument_bootstrap_broker.execute_once", [
      "grant_projection",
      "provider_projection",
    ]);
    const record = providersByDescriptor.get(request.provider_projection);
    if (!record) throw new Error("bootstrap provider projection is not registered by exact identity");
    // Prove every field used for routing is inert before reading any of it.
    // The verifier assertion below remains the authority/provenance check.
    const grant = assertGrantAdmissionData(request.grant_projection);
    const instrument = grant && providersByInstrument.get(grant.instrument_ref) === record
      ? record.instruments.get(grant.instrument_ref) : null;
    if (!instrument) throw new Error("bootstrap grant instrument is not registered to this provider");
    const capability = record.bootstrap_capabilities.get(grant.operation_id);
    if (!capability || !METHOD_BY_OPERATION[grant.operation_id]
        || capability.operation_digest !== grant.operation_digest) {
      throw new Error("bootstrap grant operation is not exactly declared by the provider");
    }
    const context = {
      grant,
      provider: record,
      instrument,
      capability,
      method: METHOD_BY_OPERATION[grant.operation_id],
      expected_grant_bindings: expectedGrantBindings(record, grant),
      attempt_ref: deriveAttemptRef(grant),
      connection: null,
      intent: null,
    };
    assertLiveGrant(context, "broker admission");
    for (const [field, expected] of [
      ["provider_id", record.descriptor.provider_id],
      ["provider_descriptor_digest", record.descriptor.descriptor_digest],
      ["provider_binary_digest", record.provider_binary_digest],
      ["transport_digest", record.transport_digest],
      ["bootstrap_manifest_digest", record.bootstrap_manifest_digest],
      ["bootstrap_invariants_digest", record.bootstrap_invariants_digest],
      ["execution_principal_id", executionPrincipalId],
      ["instrument_ref", instrument.instrument_ref],
      ["enrollment_candidate_ref", instrument.enrollment_candidate_ref],
    ]) {
      if (grant[field] !== expected) throw new Error(`bootstrap grant ${field} registration drift`);
    }
    return context;
  }

  async function callProvider(record, method, argument) {
    const call = Promise.resolve().then(() => record.methods[method](argument));
    let timer;
    const timeout = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        const error = brokerError(
          "bootstrap_provider_timeout",
          `bootstrap provider ${method} exceeded its call deadline`,
        );
        Object.defineProperty(error, "pending_provider_call", { value: call });
        reject(error);
      }, providerCallTimeoutMs);
    });
    try { return await Promise.race([call, timeout]); }
    finally { clearTimeout(timer); }
  }

  async function ensureDescriptor(context) {
    if (context.provider.descriptor_checked) return;
    const emitted = await callProvider(context.provider, "describe");
    const descriptor = normalizeProviderDescriptor(
      emitted,
      operationRegistry,
      effectRegistry,
      "instrument_bootstrap_broker.provider_descriptor",
    );
    if (descriptor.provider_id !== context.provider.descriptor.provider_id
        || descriptor.descriptor_digest !== context.provider.descriptor.descriptor_digest) {
      throw new Error("bootstrap provider descriptor drifted from registration");
    }
    context.provider.descriptor_checked = true;
  }

  function buildPrecommit(context) {
    const grant = context.grant;
    const intent = normalizeProviderBootstrapIntent({
      version: 1,
      call_kind: "bootstrap",
      attempt_ref: context.attempt_ref,
      session_nucleus_hash: grant.session_nucleus_hash,
      physical_scope_axis_digest: grant.physical_scope_axis_digest,
      execution_principal_id: executionPrincipalId,
      instrument_ref: context.instrument.instrument_ref,
      enrollment_candidate_ref: context.instrument.enrollment_candidate_ref,
      provider_id: context.provider.descriptor.provider_id,
      provider_descriptor_digest: context.provider.descriptor.descriptor_digest,
      provider_binary_digest: context.provider.provider_binary_digest,
      transport_digest: context.provider.transport_digest,
      bootstrap_manifest_digest: context.provider.bootstrap_manifest_digest,
      bootstrap_invariants_digest: context.provider.bootstrap_invariants_digest,
      operation_id: grant.operation_id,
      operation_digest: context.capability.operation_digest,
      execution_request_digest: grant.execution_request_digest,
      authority_resolution_digest: grant.authority_resolution_digest,
      signed_grant_digest: grant.signed_grant_digest,
      replay_claim_digest: grant.replay_claim_digest,
      replay_reservation_receipt_digest: grant.replay_reservation_receipt_digest,
      connection_ref: context.connection.connection_ref,
      connection_generation: context.connection.connection_generation,
      grant_not_before: grant.not_before,
      grant_expires_at: grant.expires_at,
    }, context.provider.descriptor);
    context.intent = intent;
    return normalizeInstrumentBootstrapPrecommitRequest({
      provider_abi_version: PROVIDER_BOOTSTRAP_ABI_VERSION,
      ...intent,
      bootstrap_grant_projection_digest: assertDigest(
        grant.projection_digest,
        "bootstrap grant projection_digest",
      ),
      custody_binding_digest: context.connection.custody_binding_digest,
    });
  }

  function exactAttempt(attempt, precommit) {
    if (!attempt) throw new Error("durable bootstrap attempt disappeared");
    for (const [field, expected] of Object.entries(precommit)) {
      if (attempt[field] !== expected) throw new Error(`durable bootstrap attempt ${field} drift`);
    }
    return attempt;
  }

  function assertAttemptGrantBinding(context, attempt) {
    const grant = context.grant;
    for (const [field, expected] of [
      ["provider_abi_version", PROVIDER_BOOTSTRAP_ABI_VERSION],
      ["attempt_ref", context.attempt_ref],
      ["session_nucleus_hash", grant.session_nucleus_hash],
      ["physical_scope_axis_digest", grant.physical_scope_axis_digest],
      ["execution_principal_id", executionPrincipalId],
      ["instrument_ref", context.instrument.instrument_ref],
      ["enrollment_candidate_ref", context.instrument.enrollment_candidate_ref],
      ["provider_id", context.provider.descriptor.provider_id],
      ["provider_descriptor_digest", context.provider.descriptor.descriptor_digest],
      ["provider_binary_digest", context.provider.provider_binary_digest],
      ["transport_digest", context.provider.transport_digest],
      ["bootstrap_manifest_digest", context.provider.bootstrap_manifest_digest],
      ["bootstrap_invariants_digest", context.provider.bootstrap_invariants_digest],
      ["operation_id", grant.operation_id],
      ["operation_digest", context.capability.operation_digest],
      ["execution_request_digest", grant.execution_request_digest],
      ["authority_resolution_digest", grant.authority_resolution_digest],
      ["signed_grant_digest", grant.signed_grant_digest],
      ["replay_claim_digest", grant.replay_claim_digest],
      ["replay_reservation_receipt_digest", grant.replay_reservation_receipt_digest],
      ["connection_ref", context.connection.connection_ref],
      ["connection_generation", context.connection.connection_generation],
      ["custody_binding_digest", context.connection.custody_binding_digest],
      ["grant_not_before", grant.not_before],
      ["grant_expires_at", grant.expires_at],
      ["bootstrap_grant_projection_digest", grant.projection_digest],
    ]) {
      if (attempt[field] !== expected) throw new Error(`durable bootstrap attempt ${field} drift`);
    }
    return attempt;
  }

  function recoverTerminalOrAmbiguous(context, reasonCode) {
    let attempt = store.readAttempt(context.attempt_ref);
    if (attempt && ["succeeded", "refused_no_effect", "ambiguous"].includes(attempt.state)) {
      return terminalResult(attempt);
    }
    if (!attempt || !["dispatch_committed", "redeemed"].includes(attempt.state)) {
      return unavailableResult(context, attempt, reasonCode);
    }
    try {
      attempt = store.markAmbiguous({
        version: 1,
        attempt_ref: attempt.attempt_ref,
        expected_attempt_digest: attempt.attempt_digest,
        reason_code: reasonCode,
      });
    } catch (error) {
      const observed = store.readAttempt(context.attempt_ref);
      if (observed && ["succeeded", "refused_no_effect", "ambiguous"].includes(observed.state)) {
        return terminalResult(observed);
      }
      throw brokerError(
        "bootstrap_ambiguity_commit_failed",
        "bootstrap ambiguity could not be durably committed",
        error,
      );
    }
    return terminalResult(attempt);
  }

  async function execute(context) {
    let pendingProviderCall = null;
    try {
      let attempt = store.readAttempt(context.attempt_ref);
      if (attempt) {
        try {
          context.connection = sampleConnection(
            context.instrument,
            "broker bootstrap durable replay custody",
          );
        } catch {
          return unavailableResult(context, attempt, "custody_revalidation_failed");
        }
        assertAttemptGrantBinding(context, attempt);
      }
      if (attempt && ["succeeded", "refused_no_effect", "ambiguous"].includes(attempt.state)) {
        return terminalResult(attempt);
      }
      if (attempt && ["dispatch_committed", "redeemed"].includes(attempt.state)) {
        return recoverTerminalOrAmbiguous(context, "dispatch_recovered_without_credential");
      }
      try {
        await ensureDescriptor(context);
      } catch (error) {
        if (error && error.pending_provider_call) {
          pendingProviderCall = Promise.resolve(error.pending_provider_call).catch(() => undefined);
          quarantineInstrument(context, "provider_describe_timeout", error.pending_provider_call);
        }
        return unavailableResult(
          context,
          attempt,
          error && error.code === "bootstrap_provider_timeout"
            ? "provider_descriptor_timeout"
            : "provider_descriptor_unavailable",
        );
      }
      try {
        assertLiveGrant(context, "broker precommit");
        const observedConnection = sampleConnection(
          context.instrument,
          "broker bootstrap precommit connection",
        );
        if (attempt && observedConnection.connection_generation !== attempt.connection_generation) {
          return unavailableResult(context, attempt, "connection_generation_drift");
        }
        context.connection = observedConnection;
      } catch (error) {
        return unavailableResult(
          context,
          attempt,
          error.code === "bootstrap_authorization_revalidation_failed"
            ? "authorization_revalidation_failed"
            : "connection_revalidation_failed",
        );
      }
      const precommit = buildPrecommit(context);
      try {
        attempt = exactAttempt(store.precommitAttempt(precommit, context.connection), precommit);
      } catch (error) {
        const observed = store.readAttempt(context.attempt_ref);
        if (!observed) return unavailableResult(context, null, "precommit_unavailable");
        attempt = exactAttempt(observed, precommit);
      }
      if (["succeeded", "refused_no_effect", "ambiguous"].includes(attempt.state)) {
        return terminalResult(attempt);
      }
      if (["dispatch_committed", "redeemed"].includes(attempt.state)) {
        return recoverTerminalOrAmbiguous(context, "dispatch_recovered_without_credential");
      }
      try {
        assertLiveGrant(context, "broker pre-dispatch");
        const currentConnection = sampleConnection(
          context.instrument,
          "broker bootstrap pre-dispatch connection",
        );
        if (currentConnection.connection_generation
            !== context.connection.connection_generation) {
          return unavailableResult(context, attempt, "connection_generation_drift");
        }
        if (currentConnection.connection_ref !== context.connection.connection_ref
            || currentConnection.custody_binding_digest
              !== context.connection.custody_binding_digest) {
          return unavailableResult(context, attempt, "custody_binding_drift");
        }
        context.connection = currentConnection;
      } catch (error) {
        return unavailableResult(
          context,
          attempt,
          error.code === "bootstrap_authorization_revalidation_failed"
            ? "authorization_revalidation_failed"
            : "connection_revalidation_failed",
        );
      }

      let committed;
      try {
        committed = store.commitDispatch({
          version: 1,
          attempt_ref: attempt.attempt_ref,
          expected_durable_attempt_binding_digest: precommit.durable_attempt_binding_digest,
        }, context.connection);
      } catch (error) {
        return recoverTerminalOrAmbiguous(context, "dispatch_commit_ack_lost");
      }
      if (committed.already_committed || !committed.dispatch_credential) {
        return recoverTerminalOrAmbiguous(context, "dispatch_recovered_without_credential");
      }
      if (!committed.dispatch
          || committed.dispatch.bootstrap_intent_digest !== precommit.bootstrap_intent_digest
          || committed.dispatch.custody_binding_digest !== precommit.custody_binding_digest
          || committed.dispatch.connection_ref !== precommit.connection_ref
          || committed.dispatch.connection_generation !== precommit.connection_generation) {
        return recoverTerminalOrAmbiguous(context, "dispatch_binding_drift");
      }
      const providerRequest = normalizeProviderBootstrapRequest({
        ...context.intent,
        dispatch_record_digest: committed.dispatch.dispatch_record_digest,
        dispatch_credential: committed.dispatch_credential,
      }, context.provider.descriptor);
      if (providerRequest.bootstrap_request_digest !== committed.dispatch.bootstrap_request_digest) {
        return recoverTerminalOrAmbiguous(context, "provider_request_digest_drift");
      }

      let returned;
      try {
        returned = await callProvider(context.provider, context.method, providerRequest);
      } catch (error) {
        if (error && error.pending_provider_call) {
          pendingProviderCall = Promise.resolve(error.pending_provider_call).catch(() => undefined);
          quarantineInstrument(context, "provider_call_timeout", error.pending_provider_call);
        }
        return recoverTerminalOrAmbiguous(
          context,
          error && error.code === "bootstrap_provider_timeout"
            ? "provider_timeout"
            : "provider_error",
        );
      }
      try {
        normalizeProviderBootstrapReport(
          returned,
          providerRequest,
          "instrument_bootstrap_broker.provider_report",
        );
      } catch (error) {
        return recoverTerminalOrAmbiguous(context, "provider_report_invalid");
      }
      const durable = store.readAttempt(context.attempt_ref);
      if (!durable || !["succeeded", "refused_no_effect", "ambiguous"].includes(durable.state)) {
        return recoverTerminalOrAmbiguous(context, "provider_terminal_not_durable");
      }
      if (durable.provider_report
          && hashCanonicalJson(durable.provider_report) !== hashCanonicalJson(returned)) {
        return recoverTerminalOrAmbiguous(context, "provider_report_durable_drift");
      }
      return terminalResult(durable);
    } finally {
      if (pendingProviderCall) pendingProviderCall.catch(() => undefined);
    }
  }

  async function executeOnce(request) {
    if (closed) throw new Error("instrument bootstrap broker is closed");
    const context = requireContext(request);
    const current = inFlight.get(context.attempt_ref);
    if (current) return current;
    const quarantine = instrumentQuarantines.get(context.instrument.instrument_ref);
    if (quarantine && quarantine.attempt_ref !== context.attempt_ref) {
      return unavailableResult(context, null, "instrument_provider_call_quarantined");
    }
    const occupyingAttempt = instrumentsInFlight.get(context.instrument.instrument_ref);
    if (occupyingAttempt && occupyingAttempt !== context.attempt_ref) {
      return unavailableResult(context, null, "instrument_bootstrap_busy");
    }
    const promise = execute(context);
    inFlight.set(context.attempt_ref, promise);
    instrumentsInFlight.set(context.instrument.instrument_ref, context.attempt_ref);
    try { return await promise; }
    finally {
      inFlight.delete(context.attempt_ref);
      if (instrumentsInFlight.get(context.instrument.instrument_ref) === context.attempt_ref) {
        instrumentsInFlight.delete(context.instrument.instrument_ref);
      }
    }
  }

  function snapshot() {
    const durable = store.snapshot();
    return deepFreeze({
      version: INSTRUMENT_BOOTSTRAP_BROKER_VERSION,
      closed,
      provider_count: providerRecords.length,
      instrument_count: providersByInstrument.size,
      in_flight_count: inFlight.size,
      instrument_in_flight_count: instrumentsInFlight.size,
      instrument_quarantine_count: instrumentQuarantines.size,
      instrument_quarantines: [...instrumentQuarantines.values()]
        .sort((left, right) => left.instrument_ref.localeCompare(right.instrument_ref))
        .map((entry) => ({ ...entry })),
      execution_principal_id: executionPrincipalId,
      durable_generation: durable.generation,
      durable_attempt_count: durable.attempts.length,
    });
  }

  function close() {
    if (closed) return Object.freeze({ already_closed: true });
    closed = true;
    return Object.freeze({ already_closed: false });
  }

  return Object.freeze({ close, executeOnce, snapshot });
}

module.exports = {
  INSTRUMENT_BOOTSTRAP_BROKER_VERSION,
  MAX_BOOTSTRAP_INSTRUMENTS_PER_PROVIDER,
  MAX_BOOTSTRAP_PROVIDERS,
  createInstrumentBootstrapBroker,
};
