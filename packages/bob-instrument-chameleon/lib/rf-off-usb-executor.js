"use strict";

// Broker-owned composition root for one closed Chameleon HF14A active-field
// probe. The historical "RF-off" name means terminal field-off is required;
// this operation transmits RF and can never satisfy an effectless RF-off stage.
// worker port owns transport and byte custody; this module owns exact signed
// admission, reservation/fence, clock/deadline, availability, cleanup, and
// terminal-outbox joins. No constructor in this file can claim production:
// current worker ports lack an independently qualified RF-field-off witness,
// strict DTR-off native custody, real vault isolation, and HIL evidence.

const { types: utilTypes } = require("node:util");

const {
  assertCompiledHf14aProbe,
  assertCompiledHf14aProviderCommand,
} = require("../../bob-instrument-chameleon-worker-runtime/lib/hf14a-probe-compiler.js");
const {
  acknowledgeRecoveredRfOffUsbExecution,
  assertRfOffUsbExecutionPort,
  chameleonRfOffUsbExecutionRequestDigest,
  createFixtureRfOffUsbEffectAdmissionPort,
  executeRfOffUsbExecution,
  prepareRfOffUsbExecution,
  projectRfOffUsbExecutionPort,
  recoverRfOffUsbTerminal,
} = require("../../bob-instrument-chameleon-worker-runtime/lib/rf-off-usb-execution-port.js");
const {
  CHAMELEON_SEMANTIC_MANIFEST,
  getChameleonAvailabilityVariant,
  getChameleonOperation,
  resolveChameleonAvailability,
  resolveProductionShapedChameleonAvailabilityEvidence,
} = require("./operations.js");
const {
  assertChameleonAvailabilityEvidenceBackendPort,
} = require("./availability-evidence-backend.js");
const {
  assertNoPublicByteMaterial,
} = require("../../bob-instrument-contracts/lib/instrument-provider-contract.js");
const {
  hashCanonicalJson,
} = require("../../bob-instrument-contracts/lib/verification-contracts.js");
const {
  assertCurrentPhysicalDispatchExecutionAuthorityClaim,
  claimPhysicalDispatchExecutionAuthority,
  projectCurrentPhysicalDispatchExecutionAuthority,
  takePhysicalDispatchExecutionAuthorityClaimOwnership,
} = require("../../../mcp/lib/physical-dispatch-authority.js");
const {
  normalizeResourceAllocation,
} = require("../../../mcp/lib/physical-resource-contract.js");
const {
  assertPhysicalTrustedClockPort,
  samplePhysicalTrustedClock,
} = require("../../../mcp/lib/physical-trusted-clock.js");
const {
  assertCurrentPhysicalResourceReservationCredential,
  assertPhysicalResourceEffectAuthorizedNow,
  assertPhysicalResourceReservationAuthority,
  beginPhysicalResourceCleanup,
  completePhysicalResourceCleanup,
  markPhysicalResourceEffectStarted,
  physicalResourceReservationReadiness,
  projectPhysicalResourceReservationInventory,
  quarantinePhysicalResourceReservation,
  readPhysicalResourceReservationProjection,
  rehydratePhysicalResourceReservationCredential,
} = require("../../bob-instrument-broker/lib/resource-reservations.js");

const CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION = 1;
const PROVIDER_ID = "chameleon_ultra";
const FIXTURE_AUTHORITY_PROVIDER_ID = "deterministic_chameleon_ultra_fixture";
const CAPABILITY_ID = "CU-HF-14A-COMPILED-PROBE";
const OPERATION_ID = "protocol.discovery_probe";
const PROVIDER_COMMAND_REF = "command:chameleon-hf14a-closed-probe-v1";
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const AVAILABILITY_PORTS = new WeakSet();
const AVAILABILITY_STATE = new WeakMap();
const EXECUTORS = new WeakSet();
const EXECUTOR_STATE = new WeakMap();

const AVAILABILITY_FIELDS = Object.freeze([
  "version",
  "provider_id",
  "capability_id",
  "variant_id",
  "availability_variant_digest",
  "availability_projection_digest",
  "availability_qualification_digest",
  "dependency_binding_digest",
  "signed_evidence_digest",
  "evidence_current_state_digest",
  "replay_receipt_digest",
  "device_identity_digest",
  "custody_id",
  "session_id",
  "authority_id",
  "authority_epoch",
  "revocation_generation",
  "authority_resolution_digest",
  "runtime_available",
  "evidence_qualified",
  "production_ready",
  "hil_verified",
]);

const RESERVATION_BINDING_FIELDS = Object.freeze([
  "reservation_ref",
  "receipt_digest",
  "reservation_request_digest",
  "node_id",
  "contract_hash",
  "source_graph_hash",
  "session_nucleus_hash",
  "resource_bundle_digest",
  "allocation_plan_digest",
  "allocation_digest",
  "attempt_ref",
  "execution_principal_ref",
  "effect_not_before",
  "effect_deadline",
  "session_id",
  "prep_token_hash",
  "dispatch_event_id",
  "graph_context_hash",
]);

const PREPARED_RECOVERY_BINDING_FIELDS = Object.freeze([
  "version",
  "kind",
  "execution_binding_digest",
  "authority_claim_digest",
  "execution_lineage_digest",
  "attempt_ref",
  "operation_id",
  "requested_effects_digest",
  "safety_supervisor_plan_digest",
  "availability_evidence_digest",
  "availability_variant_digest",
  "execution_claim_receipt_digest",
  "deadline_fence_receipt_digest",
  "effect_deadline",
  "compiled_command_id",
  "compiled_command_capability_digest",
  "compiled_operation_digest",
  "prepared_request_digest",
]);

function executorError(code, message = code, cause = null) {
  const error = new Error(message);
  error.code = code;
  if (cause != null) Object.defineProperty(error, "cause", { value: cause });
  return error;
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw executorError("chameleon_rf_off_contract_invalid", `${label} must be an exact object`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  const allowed = new Set([...required, ...optional]);
  const unknown = keys.filter((key) => typeof key !== "string" || !allowed.has(key));
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(descriptors, field));
  if (unknown.length > 0 || missing.length > 0) {
    throw executorError("chameleon_rf_off_contract_invalid", `${label} fields are not exact`);
  }
  const output = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw executorError("chameleon_rf_off_contract_invalid", `${label}.${key} must be an enumerable data field`);
    }
    output[key] = descriptor.value;
  }
  return output;
}

function digest(value, label) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw executorError("chameleon_rf_off_contract_invalid", `${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function token(value, label) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)) {
    throw executorError("chameleon_rf_off_contract_invalid", `${label} must be a bounded token`);
  }
  return value;
}

function integer(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw executorError("chameleon_rf_off_contract_invalid", `${label} must be an integer >= ${minimum}`);
  }
  return value;
}

function nullRecord(input) {
  const output = Object.create(null);
  for (const [field, value] of Object.entries(input)) {
    Object.defineProperty(output, field, {
      value,
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }
  return Object.freeze(output);
}

function normalizeAvailability(input, compiled, worker, { fixture }) {
  const value = exactObject(input, "chameleon_rf_off_availability", AVAILABILITY_FIELDS);
  if (value.version !== CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION
      || value.provider_id !== PROVIDER_ID || value.capability_id !== CAPABILITY_ID
      || value.variant_id !== compiled.variant_id
      || value.device_identity_digest !== worker.device_identity_digest
      || value.custody_id !== worker.custody_ref
      || value.session_id !== worker.session_id) {
    throw executorError("chameleon_rf_off_availability_crosswired", "availability evidence is bound to another provider/device/custody/session/variant");
  }
  const reviewed = getChameleonAvailabilityVariant(CAPABILITY_ID, compiled.variant_id);
  if (!reviewed || value.availability_variant_digest !== reviewed.availability_variant_digest) {
    throw executorError("chameleon_rf_off_availability_variant_drift", "availability variant is not the reviewed manifest variant");
  }
  for (const field of [
    "availability_variant_digest", "availability_projection_digest",
    "availability_qualification_digest", "dependency_binding_digest",
    "signed_evidence_digest", "evidence_current_state_digest",
    "replay_receipt_digest", "device_identity_digest", "authority_resolution_digest",
  ]) digest(value[field], `availability.${field}`);
  token(value.custody_id, "availability.custody_id");
  token(value.session_id, "availability.session_id");
  token(value.authority_id, "availability.authority_id");
  integer(value.authority_epoch, "availability.authority_epoch", 1);
  integer(value.revocation_generation, "availability.revocation_generation", 0);
  if (value.runtime_available !== true || value.evidence_qualified !== true) {
    throw executorError("chameleon_rf_off_availability_unqualified", "signed availability does not qualify the closed probe variant");
  }
  if (!fixture && value.production_ready !== true) {
    throw executorError("chameleon_rf_off_availability_not_production", "production availability evidence is not ready");
  }
  if (typeof value.production_ready !== "boolean" || value.hil_verified !== false) {
    throw executorError("chameleon_rf_off_availability_invalid", "availability production/HIL claims are invalid");
  }
  const normalized = nullRecord(Object.fromEntries(AVAILABILITY_FIELDS.map((field) => [field, value[field]])));
  return nullRecord({
    ...normalized,
    availability_evidence_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-rf-off-usb-availability-binding/v1",
      ...normalized,
    }),
  });
}

function createFixtureChameleonRfOffAvailabilityResolverPort(input = {}) {
  const value = exactObject(input, "fixture_chameleon_rf_off_availability_resolver", [
    "version", "port_id", "test_only", "resolve_current",
  ]);
  if (value.version !== CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION || value.test_only !== true
      || typeof value.resolve_current !== "function" || utilTypes.isProxy(value.resolve_current)) {
    throw executorError("chameleon_rf_off_availability_fixture_only", "availability fixture resolver is test-only and synchronous");
  }
  const port = nullRecord({
    version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
    kind: "fixture_chameleon_rf_off_availability_resolver",
    port_id: token(value.port_id, "availability_resolver.port_id"),
    test_only: true,
    production_ready: false,
    execution_authority: false,
  });
  AVAILABILITY_PORTS.add(port);
  AVAILABILITY_STATE.set(port, { fixture: true, resolve: value.resolve_current });
  return port;
}

function createChameleonRfOffAvailabilityResolverPort(input = {}) {
  const value = exactObject(input, "chameleon_rf_off_availability_resolver", [
    "version", "port_id", "backend_port", "resolution", "alternative_selections",
  ]);
  if (value.version !== CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION) {
    throw executorError("chameleon_rf_off_contract_invalid", "availability resolver version drifted");
  }
  const backend = assertChameleonAvailabilityEvidenceBackendPort(value.backend_port);
  const port = nullRecord({
    version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
    kind: "production_shaped_chameleon_rf_off_availability_resolver",
    port_id: token(value.port_id, "availability_resolver.port_id"),
    test_only: false,
    production_ready: backend.production_ready === true,
    execution_authority: false,
  });
  AVAILABILITY_PORTS.add(port);
  AVAILABILITY_STATE.set(port, {
    fixture: false,
    resolve() {
      const evidence = resolveProductionShapedChameleonAvailabilityEvidence(
        backend,
        value.resolution,
      );
      const availability = resolveChameleonAvailability({
        version: 1,
        provider_id: PROVIDER_ID,
        evidence_projection: evidence,
        alternative_selections: value.alternative_selections,
      });
      return { evidence, availability };
    },
  });
  return port;
}

function assertAvailabilityResolver(port) {
  if (!port || utilTypes.isProxy(port) || !Object.isFrozen(port)
      || Object.getPrototypeOf(port) !== null || !AVAILABILITY_PORTS.has(port)
      || !AVAILABILITY_STATE.has(port)) {
    throw executorError("chameleon_rf_off_availability_resolver_untrusted", "availability requires a privately branded resolver");
  }
  return port;
}

function resolveAvailability(portInput, compiled, worker, authority) {
  const port = assertAvailabilityResolver(portInput);
  const state = AVAILABILITY_STATE.get(port);
  let raw;
  try {
    raw = state.resolve(nullRecord({
      version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
      provider_id: PROVIDER_ID,
      capability_id: CAPABILITY_ID,
      variant_id: compiled.variant_id,
      device_identity_digest: worker.device_identity_digest,
      custody_id: worker.custody_ref,
      session_id: worker.session_id,
      authority_epoch: authority.authority_epoch,
      revocation_generation: authority.revocation_generation,
      authority_resolution_digest: authority.authority_resolution_digest,
    }));
  } catch (cause) {
    throw executorError("chameleon_rf_off_availability_resolution_failed", "current signed availability resolution failed", cause);
  }
  if (utilTypes.isPromise(raw)) {
    throw executorError("chameleon_rf_off_availability_async", "availability resolution must be synchronous at the effect seam");
  }
  let projection;
  if (state.fixture) {
    projection = raw;
  } else {
    const availability = raw?.availability;
    const evidence = raw?.evidence;
    const variant = availability?.variants?.find((entry) => (
      entry.capability_id === CAPABILITY_ID && entry.variant_id === compiled.variant_id
    ));
    if (!variant || !evidence) {
      throw executorError("chameleon_rf_off_availability_unqualified", "resolved availability omitted the closed probe variant");
    }
    projection = {
      version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
      provider_id: PROVIDER_ID,
      capability_id: CAPABILITY_ID,
      variant_id: compiled.variant_id,
      availability_variant_digest: variant.availability_variant_digest,
      availability_projection_digest: availability.availability_projection_digest,
      availability_qualification_digest: variant.availability_qualification_digest,
      dependency_binding_digest: variant.dependency_binding_digest,
      signed_evidence_digest: evidence.signed_evidence_digest,
      evidence_current_state_digest: evidence.current_state_digest,
      replay_receipt_digest: hashCanonicalJson(evidence.replay_receipt),
      device_identity_digest: availability.device_identity_digest,
      custody_id: availability.custody_id,
      session_id: availability.session_id,
      authority_id: availability.authority_id,
      authority_epoch: availability.authority_epoch,
      revocation_generation: availability.revocation_generation,
      authority_resolution_digest: availability.authority_resolution_digest,
      runtime_available: variant.runtime_available,
      evidence_qualified: variant.evidence_qualified,
      production_ready: variant.production_ready,
      hil_verified: false,
    };
  }
  const normalized = normalizeAvailability(projection, compiled, worker, { fixture: state.fixture });
  for (const field of ["authority_epoch", "revocation_generation", "authority_resolution_digest"]) {
    if (normalized[field] !== authority[field]) {
      throw executorError("chameleon_rf_off_availability_authority_drift", `availability ${field} drifted from current grant authority`);
    }
  }
  return normalized;
}

function assertPreparedAvailabilityStillCurrent(prepared, current) {
  for (const field of [...AVAILABILITY_FIELDS, "availability_evidence_digest"]) {
    if (current[field] !== prepared[field]) {
      throw executorError(
        "chameleon_rf_off_prepared_availability_drift",
        `availability ${field} changed after durable prepare`,
      );
    }
  }
}

function commandInputRef(command) {
  assertCompiledHf14aProviderCommand(command);
  return commandInputRefUnchecked(command);
}

function commandInputRefUnchecked(command) {
  return `command-input:${command.compiled_command_capability_digest.slice(0, 48)}`;
}

function parameterDigest(compiledInput) {
  const compiled = assertCompiledHf14aProbe(compiledInput);
  return hashCanonicalJson({
    version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
    schema_id: compiled.schema_id,
    variant_id: compiled.variant_id,
    parameter_selector_id: compiled.parameter_selector_id,
  });
}

function requestedEffectsDigest(compiledInput) {
  const compiled = assertCompiledHf14aProbe(compiledInput);
  return hashCanonicalJson({
    operation_id: compiled.operation_id,
    effect_profile_refs: compiled.effect_profile_refs,
    target_state_transition: compiled.target_state_transition,
    field_end_policy: compiled.field_end_policy,
  });
}

function operationDigest() {
  const operation = getChameleonOperation(OPERATION_ID);
  if (!operation) throw new Error("reviewed Chameleon discovery operation is missing");
  return hashCanonicalJson({ operation_id: OPERATION_ID, ...operation });
}

function validateStaticAuthority(authority, compiled, command, worker, reservation, allocation) {
  const variant = getChameleonAvailabilityVariant(CAPABILITY_ID, compiled.variant_id);
  const acceptedFixture = authority.authority_mode === "deterministic_mock"
    && authority.provider_id === FIXTURE_AUTHORITY_PROVIDER_ID && worker.test_only === true;
  if (authority.provider_id !== PROVIDER_ID && !acceptedFixture) {
    throw executorError("chameleon_rf_off_provider_lookalike", "dispatch grant provider is not the exact Chameleon provider");
  }
  const exact = {
    session_id: worker.session_id,
    session_nucleus_hash: worker.session_nucleus_hash,
    attempt_ref: reservation.attempt_ref,
    instrument_ref: allocation.resource_ref,
    lease_id: worker.lease_id,
    fencing_generation: allocation.fencing_generation,
    provider_descriptor_digest: worker.provider_descriptor_digest,
    operation_id: OPERATION_ID,
    operation_digest: operationDigest(),
    parameter_digest: parameterDigest(compiled),
    requested_effects_digest: requestedEffectsDigest(compiled),
    provider_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    availability_variant_id: compiled.variant_id,
    availability_variant_digest: variant?.availability_variant_digest,
    compiler_id: compiled.compiler_id,
    compiler_manifest_digest: compiled.compiler_manifest_digest,
    compiler_registry_digest: compiled.compiler_registry_digest,
    compiled_command_id: command.compiled_command_id,
    compiled_command_capability_digest: command.compiled_command_capability_digest,
    compiled_operation_digest: command.compiled_operation_digest,
    provider_command_ref: PROVIDER_COMMAND_REF,
    command_input_ref: commandInputRefUnchecked(command),
    command_input_digest: command.compiled_command_capability_digest,
    maximum_response_bytes: compiled.maximum_response_bytes,
    vault_reservation_handle: worker.vault_reservation_handle,
    vault_reservation_digest: worker.vault_reservation_digest,
    vault_ingest_capability_digest: worker.vault_ingest_capability_digest,
    vault_byte_limit: worker.vault_byte_limit,
    worker_bundle_digest: worker.worker_bundle_digest,
    worker_launch_profile_digest: worker.worker_launch_profile_digest,
    worker_fence_plan_digest: worker.worker_fence_plan_digest,
    transport_profile_digest: worker.transport_profile_digest,
    durable_exchange_plan_digest: worker.durable_exchange_plan_digest,
    terminal_receipt_recipient_digest: worker.terminal_receipt_recipient_digest,
  };
  for (const [field, expected] of Object.entries(exact)) {
    if (authority[field] !== expected) {
      throw executorError("chameleon_rf_off_authority_crosswired", `signed dispatch authority ${field} drifted`);
    }
  }
  if (authority.fencing_token_digest !== worker.authority_fencing_token_digest
      || allocation.fencing_token_hash !== worker.reservation_fencing_token_hash
      || allocation.fencing_generation !== worker.fencing_generation
      || allocation.resource_ref !== worker.resource_ref) {
    throw executorError("chameleon_rf_off_fence_crosswired", "authority/reservation/worker fencing tuple drifted");
  }
  if (authority.effect_not_before !== reservation.effect_not_before
      || authority.effect_deadline !== reservation.effect_deadline
      || authority.resource_bundle_digest !== reservation.resource_bundle_digest
      || authority.node_id !== reservation.node_id
      || authority.contract_hash !== reservation.contract_hash
      || authority.graph_context_hash !== reservation.graph_context_hash) {
    throw executorError("chameleon_rf_off_reservation_crosswired", "signed grant drifted from the exact reservation/attempt window");
  }
  return acceptedFixture;
}

function authorityClaimDigest(authority) {
  return authority.authority_claim_digest || authority.authority_projection_digest;
}

function recoveryAuthority(authorityProjection) {
  return Object.freeze({
    ...authorityProjection,
    authority_claim_digest: digest(
      authorityProjection.authority_projection_digest,
      "authority.authority_projection_digest",
    ),
  });
}

function recoveryCommandMetadata(authority) {
  return Object.freeze({
    compiled_command_id: authority.compiled_command_id,
    compiled_command_capability_digest: authority.compiled_command_capability_digest,
    compiled_operation_digest: authority.compiled_operation_digest,
  });
}

function preparedRecoveryDigest(binding) {
  const prepared = {
    version: binding.version,
    kind: "chameleon_hf14a_probe_prepared",
    execution_binding_digest: binding.execution_binding_digest,
    authority_claim_digest: binding.authority_claim_digest,
    execution_lineage_digest: binding.execution_lineage_digest,
    attempt_ref: binding.attempt_ref,
    operation_id: binding.operation_id,
    requested_effects_digest: binding.requested_effects_digest,
    safety_supervisor_plan_digest: binding.safety_supervisor_plan_digest,
    availability_evidence_digest: binding.availability_evidence_digest,
    availability_variant_digest: binding.availability_variant_digest,
    execution_claim_receipt_digest: binding.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: binding.deadline_fence_receipt_digest,
    effect_deadline: binding.effect_deadline,
    compiled_command_id: binding.compiled_command_id,
    compiled_command_capability_digest: binding.compiled_command_capability_digest,
    compiled_operation_digest: binding.compiled_operation_digest,
  };
  return hashCanonicalJson(prepared);
}

function recoveryBindingFromRequest(state, authority, request) {
  const command = state.compiled_command || recoveryCommandMetadata(authority);
  const basis = {
    version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
    kind: "chameleon_hf14a_probe_recovery_binding",
    execution_binding_digest: state.worker.execution_binding_digest,
    authority_claim_digest: authorityClaimDigest(authority),
    execution_lineage_digest: authority.execution_lineage_digest,
    attempt_ref: authority.attempt_ref,
    operation_id: OPERATION_ID,
    requested_effects_digest: authority.requested_effects_digest,
    safety_supervisor_plan_digest: authority.safety_supervisor_plan_digest,
    availability_evidence_digest: request.availability_evidence_digest,
    availability_variant_digest: authority.availability_variant_digest,
    execution_claim_receipt_digest: request.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: request.deadline_fence_receipt_digest,
    effect_deadline: authority.effect_deadline,
    compiled_command_id: command.compiled_command_id,
    compiled_command_capability_digest: command.compiled_command_capability_digest,
    compiled_operation_digest: command.compiled_operation_digest,
  };
  return nullRecord({ ...basis, prepared_request_digest: preparedRecoveryDigest(basis) });
}

function normalizePreparedRecoveryBinding(input, state, authority) {
  const value = exactObject(
    input,
    "chameleon_rf_off_prepared_recovery_binding",
    PREPARED_RECOVERY_BINDING_FIELDS,
  );
  const command = state.compiled_command || recoveryCommandMetadata(authority);
  const exact = {
    version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
    kind: "chameleon_hf14a_probe_recovery_binding",
    execution_binding_digest: state.worker.execution_binding_digest,
    authority_claim_digest: authorityClaimDigest(authority),
    execution_lineage_digest: authority.execution_lineage_digest,
    attempt_ref: authority.attempt_ref,
    operation_id: OPERATION_ID,
    requested_effects_digest: authority.requested_effects_digest,
    safety_supervisor_plan_digest: authority.safety_supervisor_plan_digest,
    availability_variant_digest: authority.availability_variant_digest,
    effect_deadline: authority.effect_deadline,
    compiled_command_id: command.compiled_command_id,
    compiled_command_capability_digest: command.compiled_command_capability_digest,
    compiled_operation_digest: command.compiled_operation_digest,
  };
  for (const [field, expected] of Object.entries(exact)) {
    if (value[field] !== expected) {
      throw executorError("chameleon_rf_off_recovery_crosswired", `prepared recovery ${field} drifted`);
    }
  }
  for (const field of [
    "availability_evidence_digest",
    "execution_claim_receipt_digest",
    "deadline_fence_receipt_digest",
    "prepared_request_digest",
  ]) digest(value[field], `prepared_recovery.${field}`);
  if (typeof value.effect_deadline !== "string"
      || Number.isNaN(Date.parse(value.effect_deadline))
      || new Date(value.effect_deadline).toISOString() !== value.effect_deadline
      || preparedRecoveryDigest(value) !== value.prepared_request_digest) {
    throw executorError("chameleon_rf_off_recovery_crosswired", "prepared recovery request digest or deadline drifted");
  }
  return nullRecord(Object.fromEntries(
    PREPARED_RECOVERY_BINDING_FIELDS.map((field) => [field, value[field]]),
  ));
}

function createRecoveryBinding(state, authority) {
  if (state.prepared_request_binding == null) {
    if (state.execution_request == null) {
      throw executorError(
        "chameleon_rf_off_recovery_binding_missing",
        "terminal recovery requires the externally retained prepared request binding",
      );
    }
    state.prepared_request_binding = recoveryBindingFromRequest(
      state,
      authority,
      state.execution_request,
    );
  }
  return state.prepared_request_binding;
}

function assertClosedFixtureAssuranceTuple({
  fixtureAuthority,
  worker,
  availabilityPort = null,
  reservationAuthority,
  recoveryOnly = false,
}) {
  const readiness = physicalResourceReservationReadiness(reservationAuthority);
  const availabilityState = availabilityPort == null ? null : AVAILABILITY_STATE.get(availabilityPort);
  const exactFixtureTuple = fixtureAuthority === true
    && worker.test_only === true
    && readiness.production_ready === false
    && (recoveryOnly === true || (
      availabilityPort.test_only === true
      && availabilityState?.fixture === true
    ));
  if (!exactFixtureTuple) {
    throw executorError(
      "chameleon_rf_off_mixed_assurance_rejected",
      "the current executor only admits an all-fixture authority/worker/availability/reservation tuple",
    );
  }
}

function sampleDeadline(state, authority) {
  let sample;
  try {
    sample = samplePhysicalTrustedClock(state.trusted_clock_port);
  } catch (cause) {
    throw executorError("chameleon_rf_off_trusted_clock_failed", "trusted clock could not be sampled", cause);
  }
  if (Date.parse(sample.trusted_utc_earliest) < Date.parse(authority.effect_not_before)) {
    throw executorError("chameleon_rf_off_effect_not_yet_valid", "effect window has not opened");
  }
  if (Date.parse(sample.trusted_utc_latest) >= Date.parse(authority.effect_deadline)) {
    throw executorError("chameleon_rf_off_deadline_expired", "effect deadline has expired");
  }
  const basis = {
    authority_claim_digest: authority.authority_claim_digest,
    authority_resolution_digest: authority.authority_resolution_digest,
    effect_not_before: authority.effect_not_before,
    effect_deadline: authority.effect_deadline,
    clock_id: sample.clock_id,
    monotonic_epoch_id: sample.monotonic_epoch_id,
    monotonic_ms: sample.monotonic_ms,
    trusted_utc_earliest: sample.trusted_utc_earliest,
    trusted_utc_latest: sample.trusted_utc_latest,
    signed_mapping_digest: sample.signed_mapping_digest,
    clock_authority_epoch: sample.authority_epoch,
    clock_revocation_generation: sample.revocation_generation,
  };
  return nullRecord({
    ...basis,
    deadline_fence_receipt_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-rf-off-usb-deadline-fence/v1",
      ...basis,
    }),
  });
}

function sampleCompletionDeadline(state, authority) {
  let sample = null;
  let status = "clock_unavailable";
  try {
    sample = samplePhysicalTrustedClock(state.trusted_clock_port);
    status = Date.parse(sample.trusted_utc_latest) >= Date.parse(authority.effect_deadline)
      ? "deadline_overrun"
      : "within_window";
  } catch {}
  const basis = sample == null ? {
    authority_claim_digest: authorityClaimDigest(authority),
    effect_deadline: authority.effect_deadline,
    completion_deadline_status: status,
  } : {
    authority_claim_digest: authorityClaimDigest(authority),
    effect_deadline: authority.effect_deadline,
    completion_deadline_status: status,
    clock_id: sample.clock_id,
    monotonic_epoch_id: sample.monotonic_epoch_id,
    monotonic_ms: sample.monotonic_ms,
    trusted_utc_earliest: sample.trusted_utc_earliest,
    trusted_utc_latest: sample.trusted_utc_latest,
    signed_mapping_digest: sample.signed_mapping_digest,
    clock_authority_epoch: sample.authority_epoch,
    clock_revocation_generation: sample.revocation_generation,
  };
  const clockAvailable = sample != null;
  return nullRecord({
    completion_deadline_status: status,
    completion_deadline_overrun: clockAvailable ? status !== "within_window" : null,
    completion_deadline_compliance_proven: clockAvailable,
    completion_requires_quarantine: status !== "within_window",
    completion_fence_receipt_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-rf-off-usb-completion-fence/v1",
      ...basis,
    }),
  });
}

function recoveredCompletionClassification(terminal, finalState = null) {
  const status = "deadline_compliance_unproven_recovery";
  return nullRecord({
    completion_deadline_status: status,
    completion_deadline_overrun: null,
    completion_deadline_compliance_proven: false,
    completion_requires_quarantine: finalState !== "released",
    completion_fence_receipt_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-rf-off-usb-recovered-completion-fence/v1",
      terminal_witness_digest: terminal.terminal_witness_digest,
      deadline_fence_receipt_digest: terminal.deadline_fence_receipt_digest,
      effect_deadline: terminal.effect_deadline,
      completion_deadline_status: status,
    }),
  });
}

function assertInitialReservation(state) {
  const credential = assertCurrentPhysicalResourceReservationCredential(
    state.reservation_authority,
    state.credential,
  );
  const projection = readPhysicalResourceReservationProjection(
    state.reservation_authority,
    state.reservation_binding.reservation_ref,
  );
  if (credential.state !== "held" || credential.effect_state !== "not_started"
      || credential.reservation_ref !== state.reservation_binding.reservation_ref
      || credential.receipt_digest !== state.reservation_binding.receipt_digest
      || projection == null || projection.state !== "held"
      || projection.effect_state !== "not_started"
      || projection.allocation_count !== 1
      || projection.allocation_digest !== hashCanonicalJson([state.allocation])
      || projection.reservation_request_digest
        !== state.reservation_binding.reservation_request_digest) {
    throw executorError("chameleon_rf_off_reservation_stale", "exact held single-instrument reservation is no longer current");
  }
}

function assertFenceHighWater(state) {
  const inventory = projectPhysicalResourceReservationInventory(state.reservation_authority);
  const resource = inventory.resources.find((entry) => entry.resource_ref === state.allocation.resource_ref);
  if (!resource || resource.state_epoch_digest !== state.allocation.state_epoch_digest
      || resource.fencing_generation < state.allocation.fencing_generation
      || (state.final_fencing_generation != null
        && resource.fencing_generation < state.final_fencing_generation)) {
    throw executorError("chameleon_rf_off_fence_high_water_drift", "resource fencing high-water moved backwards or cross-wired");
  }
  return resource.fencing_generation;
}

function assertPostEffectStartAdmission(state) {
  const authorization = assertPhysicalResourceEffectAuthorizedNow(
    state.reservation_authority,
    state.credential,
  );
  const projection = readPhysicalResourceReservationProjection(
    state.reservation_authority,
    state.reservation_binding.reservation_ref,
  );
  const inventory = projectPhysicalResourceReservationInventory(state.reservation_authority);
  const resource = inventory.resources.find((entry) => (
    entry.resource_ref === state.allocation.resource_ref
  ));
  const exactAuthorization = {
    reservation_ref: state.reservation_binding.reservation_ref,
    reservation_request_digest: state.reservation_binding.reservation_request_digest,
    node_id: state.reservation_binding.node_id,
    contract_hash: state.reservation_binding.contract_hash,
    source_graph_hash: state.reservation_binding.source_graph_hash,
    session_nucleus_hash: state.reservation_binding.session_nucleus_hash,
    attempt_ref: state.reservation_binding.attempt_ref,
    execution_principal_ref: state.reservation_binding.execution_principal_ref,
    resource_bundle_digest: state.reservation_binding.resource_bundle_digest,
    allocation_plan_digest: state.reservation_binding.allocation_plan_digest,
    allocation_digest: hashCanonicalJson([state.allocation]),
    effect_deadline: state.reservation_binding.effect_deadline,
  };
  if (Object.entries(exactAuthorization).some(([field, expected]) => (
    authorization[field] !== expected
  )) || projection == null || projection.state !== "held"
      || projection.effect_state !== "started"
      || projection.reservation_ref !== state.reservation_binding.reservation_ref
      || projection.receipt_digest !== authorization.receipt_digest
      || projection.reservation_request_digest
        !== state.reservation_binding.reservation_request_digest
      || projection.resource_bundle_digest !== state.reservation_binding.resource_bundle_digest
      || projection.source_graph_hash !== state.reservation_binding.source_graph_hash
      || projection.allocation_plan_digest !== state.reservation_binding.allocation_plan_digest
      || projection.allocation_count !== 1
      || projection.allocation_digest !== hashCanonicalJson([state.allocation])
      || state.allocation.ownership !== "exclusive"
      || resource == null || resource.availability !== "available"
      || resource.state_epoch_digest !== state.allocation.state_epoch_digest
      || resource.fencing_generation !== state.allocation.fencing_generation) {
    throw executorError(
      "chameleon_rf_off_post_start_admission_drift",
      "exact held/started reservation and exclusive resource fence are no longer current",
    );
  }
  return authorization;
}

function createBrokerEffectAdmissionPort(state, authority, preparedAvailability) {
  const preparedRequestDigest = state.prepared_request_binding?.prepared_request_digest;
  const executionRequestDigest = chameleonRfOffUsbExecutionRequestDigest(
    state.worker.execution_binding_digest,
    preparedRequestDigest,
  );
  return createFixtureRfOffUsbEffectAdmissionPort({
    version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
    port_id: `effect-admission:${preparedRequestDigest.slice(0, 32)}`,
    test_only: true,
    execution_binding_digest: state.worker.execution_binding_digest,
    prepared_request_digest: preparedRequestDigest,
    execution_request_digest: executionRequestDigest,
    assert_current(challengeInput) {
      const challenge = exactObject(
        challengeInput,
        "chameleon_rf_off_worker_effect_admission_challenge",
        [
          "version",
          "kind",
          "phase",
          "execution_binding_digest",
          "prepared_request_digest",
          "execution_request_digest",
        ],
      );
      if (challenge.version !== CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION
          || challenge.kind !== "chameleon_hf14a_probe_effect_admission_challenge"
          || !["pre_open", "pre_transact"].includes(challenge.phase)
          || challenge.execution_binding_digest !== state.worker.execution_binding_digest
          || challenge.prepared_request_digest !== preparedRequestDigest
          || challenge.execution_request_digest !== executionRequestDigest) {
        throw executorError(
          "chameleon_rf_off_effect_admission_crosswired",
          "worker effect admission challenge drifted from the prepared execution",
        );
      }
      const currentAvailability = resolveAvailability(
        state.availability_port,
        state.compiled_probe,
        state.worker,
        authority,
      );
      // The availability resolver is the last externally supplied admission
      // seam. It may synchronously change other live authority/clock state, so
      // reassert both only after it returns.
      const currentAuthority = assertCurrentPhysicalDispatchExecutionAuthorityClaim(
        state.authority_claim,
        state.authority_owner,
      );
      const deadline = sampleDeadline(state, currentAuthority);
      assertPreparedAvailabilityStillCurrent(preparedAvailability, currentAvailability);
      // Keep the reservation assertion last. No callback or await may occur
      // between this exact check and the worker's corresponding open/transact
      // invocation.
      const effectAuthorization = assertPostEffectStartAdmission(state);
      const basis = {
        version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
        kind: "chameleon_hf14a_probe_effect_admission",
        phase: challenge.phase,
        execution_binding_digest: challenge.execution_binding_digest,
        prepared_request_digest: preparedRequestDigest,
        execution_request_digest: executionRequestDigest,
        authority_claim_digest: authorityClaimDigest(currentAuthority),
        availability_evidence_digest: currentAvailability.availability_evidence_digest,
        deadline_fence_receipt_digest: deadline.deadline_fence_receipt_digest,
        reservation_receipt_digest: effectAuthorization.receipt_digest,
        effect_authorization_digest: effectAuthorization.effect_authorization_digest,
        authorized: true,
      };
      return nullRecord({
        ...basis,
        effect_admission_receipt_digest: hashCanonicalJson({
          domain: "hacker-bob/chameleon-rf-off-usb-effect-admission/v1",
          ...basis,
        }),
      });
    },
  });
}

function createExecutionRequest(state, authority, availability, deadline) {
  const executionClaimReceiptDigest = hashCanonicalJson({
    domain: "hacker-bob/chameleon-rf-off-usb-execution-claim-receipt/v1",
    authority_claim_digest: authority.authority_claim_digest,
    execution_lineage_digest: authority.execution_lineage_digest,
    reservation_ref: state.reservation_binding.reservation_ref,
    reservation_request_digest: state.reservation_binding.reservation_request_digest,
    lease_id: authority.lease_id,
    resource_ref: authority.instrument_ref,
    fencing_token_digest: authority.fencing_token_digest,
    fencing_generation: authority.fencing_generation,
  });
  return {
    version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
    kind: "chameleon_hf14a_probe_execution_request",
    execution_binding_digest: state.worker.execution_binding_digest,
    authority_claim_digest: authority.authority_claim_digest,
    execution_lineage_digest: authority.execution_lineage_digest,
    attempt_ref: authority.attempt_ref,
    operation_id: OPERATION_ID,
    requested_effects_digest: authority.requested_effects_digest,
    safety_supervisor_plan_digest: authority.safety_supervisor_plan_digest,
    availability_evidence_digest: availability.availability_evidence_digest,
    availability_variant_digest: availability.availability_variant_digest,
    execution_claim_receipt_digest: executionClaimReceiptDigest,
    deadline_fence_receipt_digest: deadline.deadline_fence_receipt_digest,
    effect_deadline: authority.effect_deadline,
    compiled_command: state.compiled_command,
  };
}

function recordFinalReservation(state, projection) {
  if (state.final_reservation_digest != null
      && projection.broker_reservation_digest !== state.final_reservation_digest) {
    throw executorError("chameleon_rf_off_cleanup_replay_drift", "terminal reservation projection changed across replay");
  }
  state.final_reservation_digest = projection.broker_reservation_digest;
  state.final_receipt_digest = projection.receipt_digest;
  state.final_fencing_generation = assertFenceHighWater(state);
  return projection;
}

function quarantineCurrentReservation(state, projectionInput = null) {
  let projection = projectionInput || readPhysicalResourceReservationProjection(
    state.reservation_authority,
    state.reservation_binding.reservation_ref,
  );
  if (!projection) return null;
  if (projection.state === "quarantined") return recordFinalReservation(state, projection);
  if (!["held", "cleanup_pending"].includes(projection.state)) return null;
  try {
    state.credential = rehydratePhysicalResourceReservationCredential(
      state.reservation_authority,
      { reservation_ref: projection.reservation_ref, receipt_digest: projection.receipt_digest },
    );
    const quarantined = quarantinePhysicalResourceReservation(
      state.reservation_authority,
      state.credential,
    );
    state.credential = null;
    projection = quarantined.reservation_projection;
    return recordFinalReservation(state, projection);
  } catch {
    return null;
  }
}

function reconcileTerminalReservation(state, terminal, { quarantineIfStarted }) {
  let projection = readPhysicalResourceReservationProjection(
    state.reservation_authority,
    state.reservation_binding.reservation_ref,
  );
  if (!projection) throw executorError("chameleon_rf_off_cleanup_ambiguous", "reservation disappeared during cleanup reconciliation");
  if (projection.state === "held" && projection.effect_state === "not_started") {
    const quarantined = quarantineCurrentReservation(state, projection);
    throw executorError(
      quarantined == null
        ? "chameleon_rf_off_terminal_before_effect_ambiguous"
        : "chameleon_rf_off_terminal_before_effect_quarantined",
      quarantined == null
        ? "terminal record exists without effect start and quarantine was ambiguous"
        : "terminal record exists without effect start; the inconsistent reservation was quarantined",
    );
  }
  if (projection.state === "held" && projection.effect_state === "started") {
    if (quarantineIfStarted) {
      const quarantined = quarantineCurrentReservation(state, projection);
      if (quarantined == null) {
        throw executorError("chameleon_rf_off_quarantine_ambiguous", "terminal recovery/deadline overrun could not quarantine the resource");
      }
      return quarantined;
    }
    state.credential = rehydratePhysicalResourceReservationCredential(
      state.reservation_authority,
      { reservation_ref: projection.reservation_ref, receipt_digest: projection.receipt_digest },
    );
    try {
      const begun = beginPhysicalResourceCleanup(
        state.reservation_authority,
        state.credential,
        `cleanup-handoff:${terminal.terminal_witness_digest.slice(0, 48)}`,
      );
      state.credential = begun.credential;
      projection = begun.reservation_projection;
    } catch (cause) {
      const quarantined = quarantineCurrentReservation(state);
      if (quarantined != null) return quarantined;
      throw executorError(
        "chameleon_rf_off_cleanup_ambiguous",
        "cleanup begin failed and the reservation could not be quarantined",
        cause,
      );
    }
  }
  if (projection.state === "cleanup_pending" && projection.effect_state === "cleanup") {
    state.credential = rehydratePhysicalResourceReservationCredential(
      state.reservation_authority,
      { reservation_ref: projection.reservation_ref, receipt_digest: projection.receipt_digest },
    );
    try {
      const completed = completePhysicalResourceCleanup(
        state.reservation_authority,
        state.credential,
      );
      state.credential = null;
      projection = completed.reservation_projection;
    } catch (cause) {
      const quarantined = quarantineCurrentReservation(state);
      if (quarantined != null) return quarantined;
      throw executorError(
        "chameleon_rf_off_cleanup_ambiguous",
        "cleanup completion failed and the reservation could not be quarantined",
        cause,
      );
    }
  }
  const released = projection.state === "released" && projection.effect_state === "cleanup";
  if (!released && projection.state !== "quarantined") {
    throw executorError("chameleon_rf_off_cleanup_ambiguous", "reservation is not terminally released or quarantined after reconciliation");
  }
  return recordFinalReservation(state, projection);
}

function safeQuarantine(state) {
  return quarantineCurrentReservation(state) != null;
}

function createChameleonRfOffUsbExecutor(input = {}) {
  const value = exactObject(input, "chameleon_rf_off_usb_executor", [
    "version",
    "compiled_probe",
    "compiled_command",
    "dispatch_authority_port",
    "reservation_authority",
    "reservation_credential",
    "reservation_binding",
    "resource_allocation",
    "trusted_clock_port",
    "availability_resolver_port",
    "worker_execution_port",
  ]);
  if (value.version !== CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION) {
    throw executorError("chameleon_rf_off_contract_invalid", "executor version drifted");
  }
  const compiled = assertCompiledHf14aProbe(value.compiled_probe);
  const command = assertCompiledHf14aProviderCommand(value.compiled_command);
  if (command.compiled_operation_digest !== compiled.compiled_operation_digest
      || command.variant_id !== compiled.variant_id
      || command.parameter_selector_id !== compiled.parameter_selector_id) {
    throw executorError("chameleon_rf_off_compiled_command_crosswired", "compiled probe and private command capability drifted");
  }
  const reservationAuthority = assertPhysicalResourceReservationAuthority(value.reservation_authority);
  const trustedClock = assertPhysicalTrustedClockPort(value.trusted_clock_port);
  const workerPort = assertRfOffUsbExecutionPort(value.worker_execution_port);
  const worker = projectRfOffUsbExecutionPort(workerPort);
  const availabilityPort = assertAvailabilityResolver(value.availability_resolver_port);
  const reservationBinding = exactObject(
    value.reservation_binding,
    "chameleon_rf_off_reservation_binding",
    RESERVATION_BINDING_FIELDS,
  );
  const allocation = normalizeResourceAllocation(value.resource_allocation);
  if (reservationBinding.allocation_digest !== hashCanonicalJson([allocation])) {
    throw executorError("chameleon_rf_off_reservation_crosswired", "resource allocation does not match the reservation binding");
  }
  const initialCredential = assertCurrentPhysicalResourceReservationCredential(
    reservationAuthority,
    value.reservation_credential,
  );
  if (initialCredential.reservation_ref !== reservationBinding.reservation_ref
      || initialCredential.receipt_digest !== reservationBinding.receipt_digest) {
    throw executorError("chameleon_rf_off_reservation_crosswired", "credential belongs to another reservation");
  }
  const authorityProjection = projectCurrentPhysicalDispatchExecutionAuthority(
    value.dispatch_authority_port,
  );
  const fixtureAuthority = validateStaticAuthority(
    authorityProjection,
    compiled,
    command,
    worker,
    reservationBinding,
    allocation,
  );
  if (worker.execution_binding_digest !== value.worker_execution_port.execution_binding_digest) {
    throw executorError("chameleon_rf_off_worker_crosswired", "worker projection binding drifted");
  }
  assertClosedFixtureAssuranceTuple({
    fixtureAuthority,
    worker,
    availabilityPort,
    reservationAuthority,
  });
  const authorityOwner = Object.freeze({});
  const authorityClaim = claimPhysicalDispatchExecutionAuthority(value.dispatch_authority_port);
  takePhysicalDispatchExecutionAuthorityClaimOwnership(authorityClaim, authorityOwner);
  const state = {
    compiled_probe: compiled,
    compiled_command: command,
    reservation_authority: reservationAuthority,
    credential: value.reservation_credential,
    reservation_binding: Object.freeze({ ...reservationBinding }),
    allocation,
    trusted_clock_port: trustedClock,
    availability_port: availabilityPort,
    worker_port: workerPort,
    worker,
    authority_claim: authorityClaim,
    authority_owner: authorityOwner,
    fixture_authority: fixtureAuthority,
    in_flight: false,
    final_reservation_digest: null,
    final_receipt_digest: null,
    final_fencing_generation: null,
    outcome: null,
    execution_request: null,
    prepared_request_binding: null,
    recovery_only: false,
  };
  assertInitialReservation(state);
  const executor = Object.freeze({
    version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
    kind: "chameleon_rf_off_usb_executor",
    execute() { return executeChameleonRfOffUsbProbe(executor); },
    snapshot() { return projectChameleonRfOffUsbExecutor(executor); },
  });
  EXECUTORS.add(executor);
  EXECUTOR_STATE.set(executor, state);
  return executor;
}

function createChameleonRfOffUsbRecoveryExecutor(input = {}) {
  const value = exactObject(input, "chameleon_rf_off_usb_recovery_executor", [
    "version",
    "compiled_probe",
    "dispatch_authority_port",
    "reservation_authority",
    "reservation_binding",
    "resource_allocation",
    "worker_execution_port",
    "prepared_request_binding",
  ]);
  if (value.version !== CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION) {
    throw executorError("chameleon_rf_off_contract_invalid", "recovery executor version drifted");
  }
  const compiled = assertCompiledHf14aProbe(value.compiled_probe);
  const reservationAuthority = assertPhysicalResourceReservationAuthority(value.reservation_authority);
  const workerPort = assertRfOffUsbExecutionPort(value.worker_execution_port);
  const worker = projectRfOffUsbExecutionPort(workerPort);
  const reservationBinding = exactObject(
    value.reservation_binding,
    "chameleon_rf_off_reservation_binding",
    RESERVATION_BINDING_FIELDS,
  );
  const allocation = normalizeResourceAllocation(value.resource_allocation);
  if (reservationBinding.allocation_digest !== hashCanonicalJson([allocation])) {
    throw executorError("chameleon_rf_off_reservation_crosswired", "recovery allocation does not match its reservation binding");
  }
  const authority = recoveryAuthority(projectCurrentPhysicalDispatchExecutionAuthority(
    value.dispatch_authority_port,
  ));
  const command = recoveryCommandMetadata(authority);
  const fixtureAuthority = validateStaticAuthority(
    authority,
    compiled,
    command,
    worker,
    reservationBinding,
    allocation,
  );
  if (worker.execution_binding_digest !== workerPort.execution_binding_digest) {
    throw executorError("chameleon_rf_off_worker_crosswired", "recovery worker projection binding drifted");
  }
  assertClosedFixtureAssuranceTuple({
    fixtureAuthority,
    worker,
    reservationAuthority,
    recoveryOnly: true,
  });
  const reservationProjection = readPhysicalResourceReservationProjection(
    reservationAuthority,
    reservationBinding.reservation_ref,
  );
  if (!reservationProjection
      || reservationProjection.reservation_request_digest
        !== reservationBinding.reservation_request_digest
      || reservationProjection.allocation_digest !== hashCanonicalJson([allocation])) {
    throw executorError("chameleon_rf_off_reservation_crosswired", "recovery reservation lineage is missing or cross-wired");
  }
  const state = {
    compiled_probe: compiled,
    compiled_command: null,
    reservation_authority: reservationAuthority,
    credential: null,
    reservation_binding: Object.freeze({ ...reservationBinding }),
    allocation,
    trusted_clock_port: null,
    availability_port: null,
    worker_port: workerPort,
    worker,
    authority_claim: authority,
    authority_owner: null,
    fixture_authority: fixtureAuthority,
    in_flight: false,
    final_reservation_digest: null,
    final_receipt_digest: null,
    final_fencing_generation: null,
    outcome: null,
    execution_request: null,
    prepared_request_binding: null,
    recovery_only: true,
  };
  state.prepared_request_binding = normalizePreparedRecoveryBinding(
    value.prepared_request_binding,
    state,
    authority,
  );
  const executor = Object.freeze({
    version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
    kind: "chameleon_rf_off_usb_recovery_executor",
    execute() { return executeChameleonRfOffUsbProbe(executor); },
    snapshot() { return projectChameleonRfOffUsbExecutor(executor); },
  });
  EXECUTORS.add(executor);
  EXECUTOR_STATE.set(executor, state);
  return executor;
}

function assertExecutor(input) {
  if (!input || utilTypes.isProxy(input) || !Object.isFrozen(input)
      || !EXECUTORS.has(input) || !EXECUTOR_STATE.has(input)) {
    throw executorError("chameleon_rf_off_executor_untrusted", "RF-off execution requires a privately branded broker executor");
  }
  return input;
}

function projectChameleonRfOffUsbExecutor(executorInput) {
  const executor = assertExecutor(executorInput);
  const state = EXECUTOR_STATE.get(executor);
  const authority = state.recovery_only
    ? state.authority_claim
    : assertCurrentPhysicalDispatchExecutionAuthorityClaim(
      state.authority_claim,
      state.authority_owner,
    );
  return nullRecord({
    version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
    kind: "chameleon_rf_off_usb_executor_projection",
    authority_claim_digest: authority.authority_claim_digest,
    execution_lineage_digest: authority.execution_lineage_digest,
    attempt_ref: authority.attempt_ref,
    reservation_ref: state.reservation_binding.reservation_ref,
    lease_id: authority.lease_id,
    resource_ref: authority.instrument_ref,
    worker_execution_binding_digest: state.worker.execution_binding_digest,
    compiled_operation_digest: state.compiled_probe.compiled_operation_digest,
    phase: state.outcome == null
      ? (state.in_flight ? "in_flight" : (state.recovery_only ? "recovery_ready" : "ready"))
      : "completed",
    production_ready: false,
    hil_verified: false,
    rf_off_qualified: false,
    target_rf_transmit: true,
    rf_off_stage_qualified: false,
    dtr_off_qualified: false,
    qualification_blocker_code: state.worker.qualification_blocker_code,
  });
}

function projectChameleonRfOffUsbPreparedRecoveryBinding(executorInput) {
  const executor = assertExecutor(executorInput);
  const state = EXECUTOR_STATE.get(executor);
  if (state.prepared_request_binding == null) {
    throw executorError(
      "chameleon_rf_off_recovery_binding_missing",
      "prepared recovery binding is unavailable before durable effect preparation",
    );
  }
  return state.prepared_request_binding;
}

function verifyCompletedReplay(state, terminal) {
  if (terminal == null
      || terminal.terminal_witness_digest !== state.outcome.terminal_witness_digest
      || terminal.outbox_ack_digest !== state.outcome.outbox_ack_digest) {
    throw executorError("chameleon_rf_off_replay_drift", "durable terminal/outbox changed across replay");
  }
  const projection = readPhysicalResourceReservationProjection(
    state.reservation_authority,
    state.reservation_binding.reservation_ref,
  );
  if (!projection || projection.broker_reservation_digest !== state.final_reservation_digest
      || projection.receipt_digest !== state.final_receipt_digest) {
    throw executorError("chameleon_rf_off_cleanup_replay_drift", "reservation terminal changed across replay");
  }
  assertFenceHighWater(state);
  return state.outcome;
}

function settleTerminal(state, authority, terminal, { executedNow }) {
  const before = readPhysicalResourceReservationProjection(
    state.reservation_authority,
    state.reservation_binding.reservation_ref,
  );
  if (!before) {
    throw executorError("chameleon_rf_off_cleanup_ambiguous", "reservation disappeared before terminal settlement");
  }
  let completion;
  if (executedNow) {
    completion = sampleCompletionDeadline(state, authority);
  } else if (["released", "cleanup_pending"].includes(before.state)) {
    completion = recoveredCompletionClassification(terminal, "released");
  } else {
    completion = recoveredCompletionClassification(terminal, before.state);
  }
  const finalReservation = reconcileTerminalReservation(state, terminal, {
    quarantineIfStarted: completion.completion_requires_quarantine,
  });
  const settlementBasis = {
    version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
    authority_claim_digest: authorityClaimDigest(authority),
    execution_lineage_digest: authority.execution_lineage_digest,
    availability_evidence_digest: terminal.availability_evidence_digest,
    terminal_witness_digest: terminal.terminal_witness_digest,
    durable_receipt_digest: terminal.durable_receipt_digest,
    outbox_record_digest: terminal.outbox_record_digest,
    final_reservation_digest: finalReservation.broker_reservation_digest,
    final_receipt_digest: finalReservation.receipt_digest,
    final_fencing_generation: state.final_fencing_generation,
  };
  const brokerSettlementDigest = hashCanonicalJson({
    domain: "hacker-bob/chameleon-rf-off-usb-broker-settlement/v1",
    ...settlementBasis,
  });
  const acknowledged = acknowledgeRecoveredRfOffUsbExecution(
    state.worker_port,
    createRecoveryBinding(state, authority),
    brokerSettlementDigest,
  );
  const released = finalReservation.state === "released";
  const terminalState = released
    ? "completed_cleanup_confirmed"
    : (completion.completion_deadline_status === "deadline_overrun"
      ? "completed_deadline_overrun_quarantined"
      : (completion.completion_deadline_status === "clock_unavailable"
        ? "completed_clock_unavailable_quarantined"
        : (executedNow ? "completed_cleanup_failure_quarantined" : "completed_recovery_quarantined")));
  const outcomeBasis = {
    version: CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
    kind: "chameleon_rf_off_usb_probe_outcome",
    terminal_state: terminalState,
    broker_disposition_code: released ? "cleanup_confirmed" : "resource_quarantined",
    reservation_terminal_state: finalReservation.state,
    provider_id: PROVIDER_ID,
    authority_claim_digest: authorityClaimDigest(authority),
    execution_lineage_digest: authority.execution_lineage_digest,
    attempt_ref: authority.attempt_ref,
    reservation_ref: state.reservation_binding.reservation_ref,
    lease_id: authority.lease_id,
    resource_ref: authority.instrument_ref,
    fencing_generation: authority.fencing_generation,
    availability_evidence_digest: acknowledged.availability_evidence_digest,
    availability_variant_digest: acknowledged.availability_variant_digest,
    compiled_command_capability_digest: authority.compiled_command_capability_digest,
    compiled_operation_digest: authority.compiled_operation_digest,
    safety_supervisor_plan_digest: authority.safety_supervisor_plan_digest,
    deadline_fence_receipt_digest: acknowledged.deadline_fence_receipt_digest,
    completion_deadline_status: completion.completion_deadline_status,
    completion_deadline_overrun: completion.completion_deadline_overrun,
    completion_deadline_compliance_proven:
      completion.completion_deadline_compliance_proven,
    completion_fence_receipt_digest: completion.completion_fence_receipt_digest,
    artifact_handle: acknowledged.artifact_handle,
    response_digest: acknowledged.response_digest,
    response_byte_length: acknowledged.response_byte_length,
    vault_commit_receipt_digest: acknowledged.vault_commit_receipt_digest,
    raw_custody_receipt_digest: acknowledged.raw_custody_receipt_digest,
    endpoint_identity_digest: acknowledged.endpoint_identity_digest,
    inventory_before_digest: acknowledged.inventory_before_digest,
    inventory_after_digest: acknowledged.inventory_after_digest,
    dtr_before_open_asserted: acknowledged.dtr_before_open_asserted,
    dtr_during_exchange_asserted: acknowledged.dtr_during_exchange_asserted,
    dtr_after_close_asserted: acknowledged.dtr_after_close_asserted,
    terminal_rf_off_witness_digest: acknowledged.terminal_rf_off_witness_digest,
    no_active_effects_witness_digest: acknowledged.no_active_effects_witness_digest,
    terminal_witness_digest: acknowledged.terminal_witness_digest,
    durable_receipt_digest: acknowledged.durable_receipt_digest,
    outbox_record_digest: acknowledged.outbox_record_digest,
    outbox_ack_digest: acknowledged.outbox_ack_digest,
    broker_settlement_digest: brokerSettlementDigest,
    final_reservation_digest: finalReservation.broker_reservation_digest,
    final_receipt_digest: finalReservation.receipt_digest,
    final_fencing_generation: state.final_fencing_generation,
    raw_response_bytes_projected: false,
    target_rf_transmit: true,
    rf_off_stage_qualified: false,
    production_ready: false,
    hil_verified: false,
    rf_off_qualified: false,
    dtr_off_qualified: false,
    qualification_blocker_code: acknowledged.qualification_blocker_code,
  };
  const outcome = nullRecord({
    ...outcomeBasis,
    outcome_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-rf-off-usb-outcome/v1",
      ...outcomeBasis,
    }),
  });
  assertNoPublicByteMaterial(outcome, "chameleon_rf_off_usb_probe_outcome");
  if (Object.getPrototypeOf(outcome) !== null) {
    throw executorError("chameleon_rf_off_public_projection_unsafe", "broker outcome prototype must be null");
  }
  state.outcome = outcome;
  return outcome;
}

function recoverTerminalBeforeAdmission(state, authority) {
  if (state.prepared_request_binding == null && state.execution_request == null) return null;
  try {
    return recoverRfOffUsbTerminal(
      state.worker_port,
      createRecoveryBinding(state, authority),
    );
  } catch (cause) {
    if (cause?.code !== "rf_off_usb_prepared_recovery_requires_quarantine") throw cause;
    const quarantined = safeQuarantine(state);
    throw executorError(
      quarantined
        ? "chameleon_rf_off_prepared_recovery_quarantined"
        : "chameleon_rf_off_prepared_recovery_ambiguous",
      quarantined
        ? "prepared worker intent after restart was conservatively quarantined without replay"
        : "prepared worker intent could not be terminally reconciled",
      cause,
    );
  }
}

async function executeChameleonRfOffUsbProbe(executorInput) {
  const executor = assertExecutor(executorInput);
  const state = EXECUTOR_STATE.get(executor);
  if (state.in_flight) throw executorError("chameleon_rf_off_in_progress", "RF-off probe is already in flight");
  state.in_flight = true;
  try {
    const recoveryAuthorityValue = state.authority_claim;
    const recovered = recoverTerminalBeforeAdmission(state, recoveryAuthorityValue);
    if (state.outcome != null) return verifyCompletedReplay(state, recovered);
    if (recovered != null) {
      return settleTerminal(state, recoveryAuthorityValue, recovered, { executedNow: false });
    }
    if (state.recovery_only) {
      throw executorError("chameleon_rf_off_recovery_terminal_missing", "durable terminal disappeared before recovery");
    }

    const authority = assertCurrentPhysicalDispatchExecutionAuthorityClaim(
      state.authority_claim,
      state.authority_owner,
    );
    validateStaticAuthority(
      authority,
      state.compiled_probe,
      state.compiled_command,
      state.worker,
      state.reservation_binding,
      state.allocation,
    );
    const deadline = sampleDeadline(state, authority);
    const availability = resolveAvailability(
      state.availability_port,
      state.compiled_probe,
      state.worker,
      authority,
    );
    assertFenceHighWater(state);
    const request = createExecutionRequest(state, authority, availability, deadline);
    state.execution_request = request;
    state.prepared_request_binding = recoveryBindingFromRequest(state, authority, request);
    const preparedOrTerminal = prepareRfOffUsbExecution(state.worker_port, request);
    let terminal;
    let executedNow = false;
    if (preparedOrTerminal.kind === "chameleon_hf14a_probe_prepared") {
      try {
        assertCurrentPhysicalDispatchExecutionAuthorityClaim(
          state.authority_claim,
          state.authority_owner,
        );
        sampleDeadline(state, authority);
        const effectAvailability = resolveAvailability(
          state.availability_port,
          state.compiled_probe,
          state.worker,
          authority,
        );
        assertPreparedAvailabilityStillCurrent(availability, effectAvailability);
        assertFenceHighWater(state);
        assertInitialReservation(state);
      } catch (cause) {
        const quarantined = safeQuarantine(state);
        throw executorError(
          quarantined
            ? "chameleon_rf_off_prepared_admission_drift_quarantined"
            : "chameleon_rf_off_prepared_admission_drift_ambiguous",
          quarantined
            ? "authority/availability/deadline/fence drift after prepare quarantined the resource"
            : "prepared effect admission drift could not be terminally reconciled",
          cause,
        );
      }
      const started = markPhysicalResourceEffectStarted(
        state.reservation_authority,
        state.credential,
      );
      state.credential = started.credential;
      try {
        assertCurrentPhysicalDispatchExecutionAuthorityClaim(
          state.authority_claim,
          state.authority_owner,
        );
        sampleDeadline(state, authority);
        const finalEffectAvailability = resolveAvailability(
          state.availability_port,
          state.compiled_probe,
          state.worker,
          authority,
        );
        assertPreparedAvailabilityStillCurrent(availability, finalEffectAvailability);
        // Availability resolution is an external synchronous seam. Re-run the
        // revocable/deadline checks after it, then make the exact held+started
        // reservation/fence assertion the final broker operation before the
        // worker can open the device. A terminal transition or fence advance
        // must never be treated as a merely higher valid high-water here.
        assertCurrentPhysicalDispatchExecutionAuthorityClaim(
          state.authority_claim,
          state.authority_owner,
        );
        assertPostEffectStartAdmission(state);
        const effectAdmissionPort = createBrokerEffectAdmissionPort(
          state,
          authority,
          availability,
        );
        terminal = await executeRfOffUsbExecution(
          state.worker_port,
          request,
          effectAdmissionPort,
        );
        executedNow = true;
      } catch (cause) {
        const quarantined = safeQuarantine(state);
        throw executorError(
          quarantined ? "chameleon_rf_off_execution_quarantined" : "chameleon_rf_off_execution_ambiguous",
          quarantined
            ? "RF-off worker failure was fenced and the resource quarantined"
            : "RF-off worker failure could not be safely reconciled",
          cause,
        );
      }
    } else {
      terminal = preparedOrTerminal;
    }
    return settleTerminal(state, authority, terminal, { executedNow });
  } finally {
    state.in_flight = false;
  }
}

module.exports = Object.freeze({
  CHAMELEON_RF_OFF_USB_EXECUTOR_VERSION,
  FIXTURE_AUTHORITY_PROVIDER_ID,
  PROVIDER_COMMAND_REF,
  chameleonRfOffCommandInputRef: commandInputRef,
  chameleonRfOffOperationDigest: operationDigest,
  chameleonRfOffParameterDigest: parameterDigest,
  chameleonRfOffRequestedEffectsDigest: requestedEffectsDigest,
  createChameleonRfOffAvailabilityResolverPort,
  createChameleonRfOffUsbExecutor,
  createChameleonRfOffUsbRecoveryExecutor,
  createFixtureChameleonRfOffAvailabilityResolverPort,
  executeChameleonRfOffUsbProbe,
  projectChameleonRfOffUsbPreparedRecoveryBinding,
  projectChameleonRfOffUsbExecutor,
});
