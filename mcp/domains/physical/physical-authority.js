"use strict";

// Plane-PH PH-S2 owns the provider-neutral authority contract. It normalizes
// unsigned MCP-side requests and verifies signed bootstrap and active grants
// through injected trust, clock, and atomic replay dependencies. It never holds
// signing keys, opens an instrument, dispatches an operation, or exposes
// signature material in provider/broker projections.

const {
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");
const {
  normalizePhysicalScopeNucleusAxis,
} = require("../../core/governance/index.js");
const {
  EFFECT_ACTIONS,
  EFFECT_CHANNELS,
  EFFECT_PERSISTENCE_VALUES,
  EFFECT_SUBJECT_KINDS,
  EFFECT_SURFACE_VALUES,
  normalizeRequestedEffects,
} = require("../../core/requested-effects.js");
const {
  normalizeOpaqueRef,
} = require("./physical-quantities.js");
const {
  assertPhysicalTrustedClockPort,
  assertPhysicalTrustedClockTimestampNonFuture,
  assertPhysicalTrustedClockValidityWindow,
  samplePhysicalTrustedClock,
  TRUSTED_CLOCK_PORT_MODE,
} = require("./physical-trusted-clock.js");

const PHYSICAL_EXECUTION_REQUEST_VERSION = 1;
const PHYSICAL_EFFECT_AUTHORITY_VERSION = 1;
const CLEANUP_CAPABILITY_VERSION = 1;
const CLEANUP_INVOCATION_VERSION = 1;
const ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION = 1;
const ACTIVE_PHYSICAL_EXECUTION_LINEAGE_VERSION = 1;
const ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN = "hacker-bob/physical-active-execution-grant/v1";
const ACTIVE_PHYSICAL_EXECUTION_GRANT_KEY_USAGE = "physical_active_grant_signing";
const ACTIVE_GRANT_REPLAY_RESERVATION_VERSION = 1;
const PHYSICAL_BOOTSTRAP_GRANT_VERSION = 1;
const PHYSICAL_BOOTSTRAP_GRANT_DOMAIN = "hacker-bob/physical-bootstrap-grant/v1";
const PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE = "physical_bootstrap_grant_signing";
const BOOTSTRAP_GRANT_REPLAY_RESERVATION_VERSION = 1;
const SIGNED_TRUSTED_CLOCK_MODE = TRUSTED_CLOCK_PORT_MODE;
const DETERMINISTIC_TEST_CLOCK_MODE = "deterministic_test_clock";
const PHYSICAL_GRANT_TRUSTED_CLOCK_MODES = Object.freeze([
  SIGNED_TRUSTED_CLOCK_MODE,
  DETERMINISTIC_TEST_CLOCK_MODE,
]);

const PHYSICAL_GRANT_KINDS = Object.freeze([
  "bootstrap",
  "preparation",
  "active",
  "maintenance",
]);
const REQUEST_PATH_VALUES = Object.freeze(["mcp", "operator_control"]);
const AUTHORITY_DECISIONS = Object.freeze(["allow", "deny"]);
const TERMINAL_CUSTODY_VALUES = Object.freeze(["operator", "quarantine", "disposal"]);
const CLEANUP_TERMINAL_STATE_VALUES = Object.freeze(["restored", "quarantined", "unknown_effect"]);
const ACTIVE_GRANT_REPLAY_RESERVATION_DISPOSITIONS = Object.freeze(["created", "existing_same"]);
const BOOTSTRAP_GRANT_REPLAY_RESERVATION_DISPOSITIONS = Object.freeze(["created", "existing_same"]);

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const ED25519_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const ACTIVE_GRANT_VERIFIERS = new WeakSet();
const ACTIVE_GRANT_VERIFIER_STATE = new WeakMap();
const VERIFIED_ACTIVE_GRANT_PROJECTIONS = new WeakSet();
const VERIFIED_ACTIVE_GRANT_PROJECTION_STATE = new WeakMap();
const BOOTSTRAP_GRANT_VERIFIERS = new WeakSet();
const BOOTSTRAP_GRANT_VERIFIER_STATE = new WeakMap();
const VERIFIED_BOOTSTRAP_GRANT_PROJECTIONS = new WeakSet();
const VERIFIED_BOOTSTRAP_GRANT_PROJECTION_STATE = new WeakMap();

const COMMON_REQUEST_FIELDS = Object.freeze([
  "version",
  "grant_kind",
  "session_id",
  "session_nucleus_hash",
  "caller_role_id",
  "requester_principal_id",
  "ipc_peer_principal_id",
  "execution_principal_id",
  "instrument_ref",
  "operation_id",
  "parameter_digest",
  "authority_epoch",
  "revocation_generation",
  "nonce",
  "sequence",
  "not_before",
  "expires_at",
  "requested_effects",
]);

const DERIVED_REQUEST_FIELDS = Object.freeze([
  "request_path",
  "requested_effects_digest",
  "execution_request_digest",
]);

const BOOTSTRAP_FIELDS = Object.freeze([
  "enrollment_candidate_ref",
  "bootstrap_manifest_digest",
  "provider_binary_digest",
  "transport_digest",
  "rf_state",
]);

const PREPARATION_FIELDS = Object.freeze([
  "bootstrap_receipt_ref",
  "bootstrap_execution_request_digest",
  "bootstrap_inventory_observation_ref",
  "bootstrap_inventory_digest",
  "assurance_profile_id",
  "assurance_claims_digest",
  "provider_manifest_digest",
  "preparation_plan_digest",
  "snapshot_plan_digest",
  "rf_state",
]);

const ACTIVE_FIELDS = Object.freeze([
  "node_id",
  "contract_hash",
  "prep_token_hash",
  "dispatch_event_id",
  "graph_context_hash",
  "capability_pack_id",
  "capability_pack_version",
  "capability_pack_digest",
  "technique_cell_id",
  "attempt_id",
  "experiment_plan_hash",
  "inventory_observation_ref",
  "inventory_observation_digest",
  "assurance_profile_id",
  "assurance_claims_digest",
  "provider_manifest_digest",
  "availability_variant_id",
  "availability_variant_digest",
  "authorized_transition_set_digest",
  "resource_bundle_digest",
  "fencing_token",
  "lease_id",
  "workspace_snapshot_ref",
  "workspace_snapshot_digest",
  "observer_plan_digest",
  "control_plan_digest",
  "cleanup_plan_digest",
  "execution_lineage",
]);

const ACTIVE_EXECUTION_LINEAGE_FIELDS = Object.freeze([
  "version",
  "compiler_id",
  "compiler_manifest_digest",
  "compiler_registry_digest",
  "compiled_command_id",
  "compiled_command_capability_digest",
  "compiled_operation_digest",
  "provider_command_ref",
  "command_input_ref",
  "command_input_digest",
  "maximum_response_bytes",
  "vault_reservation_handle",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
  "vault_byte_limit",
  "worker_bundle_digest",
  "worker_launch_profile_digest",
  "worker_fence_plan_digest",
  "transport_profile_digest",
  "durable_exchange_plan_digest",
  "terminal_receipt_recipient_digest",
  "safety_supervisor_plan_digest",
]);

const MAINTENANCE_FIELDS = Object.freeze([
  "owned_fixture_ref",
  "ownership_attestation_digest",
  "pre_state_ref",
  "pre_state_digest",
  "backup_ref",
  "backup_digest",
  "exact_state_delta_digest",
  "expected_terminal_state_digest",
  "post_operation_inventory_plan_digest",
  "assurance_invalidation_plan_digest",
  "recovery_or_quarantine_plan_digest",
  "hil_plan_digest",
  "terminal_custody",
]);

const FIELDS_BY_GRANT_KIND = Object.freeze({
  bootstrap: BOOTSTRAP_FIELDS,
  preparation: PREPARATION_FIELDS,
  active: ACTIVE_FIELDS,
  maintenance: MAINTENANCE_FIELDS,
});

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

function assertClosedObject(value, label, requiredFields, optionalFields = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const allowed = new Set([...requiredFields, ...optionalFields]);
  const unknown = Object.keys(value).filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = requiredFields.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  return value;
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function assertToken(value, label) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)) {
    throw new Error(`${label} must be a bounded opaque token`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertInteger(value, label, { min = 0 } = {}) {
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
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  const canonical = new Date(value).toISOString();
  if (canonical !== value) throw new Error(`${label} must use canonical UTC ISO-8601 form`);
  return value;
}

function normalizeGrantVerifierClock(input, label) {
  const hasPort = Object.prototype.hasOwnProperty.call(input, "trusted_clock_port");
  const hasDeterministicClock = Object.prototype.hasOwnProperty.call(input, "trusted_now");
  if (hasPort === hasDeterministicClock) {
    throw new Error(
      `${label} requires exactly one of trusted_clock_port or deterministic trusted_now`,
    );
  }
  if (hasPort) {
    const port = assertPhysicalTrustedClockPort(input.trusted_clock_port);
    return Object.freeze({
      mode: SIGNED_TRUSTED_CLOCK_MODE,
      trusted_clock_port: port,
      trusted_now: null,
    });
  }
  if (typeof input.trusted_now !== "function") {
    throw new Error(`${label}.trusted_now must be a function`);
  }
  return Object.freeze({
    mode: DETERMINISTIC_TEST_CLOCK_MODE,
    trusted_clock_port: null,
    trusted_now: input.trusted_now,
  });
}

function readGrantVerifierClock(verifierState, rollbackLabel) {
  if (verifierState.trusted_clock_mode === SIGNED_TRUSTED_CLOCK_MODE) {
    const sample = samplePhysicalTrustedClock(verifierState.trusted_clock_port);
    const observed = Object.freeze({
      mode: SIGNED_TRUSTED_CLOCK_MODE,
      now: sample.trusted_utc,
      now_ms: Date.parse(sample.trusted_utc),
      earliest: sample.trusted_utc_earliest,
      earliest_ms: Date.parse(sample.trusted_utc_earliest),
      latest: sample.trusted_utc_latest,
      latest_ms: Date.parse(sample.trusted_utc_latest),
      uncertainty_ms: sample.max_uncertainty_ms,
      port_id: verifierState.trusted_clock_port.port_id,
      sample,
    });
    verifierState.last_trusted_clock_observation = observed;
    return observed;
  }
  const now = assertCanonicalTimestamp(verifierState.trusted_now(), "trusted_now");
  const nowMs = Date.parse(now);
  if (verifierState.last_trusted_now_ms != null && nowMs < verifierState.last_trusted_now_ms) {
    throw new Error(rollbackLabel);
  }
  verifierState.last_trusted_now_ms = nowMs;
  const observed = Object.freeze({
    mode: DETERMINISTIC_TEST_CLOCK_MODE,
    now,
    now_ms: nowMs,
    earliest: now,
    earliest_ms: nowMs,
    latest: now,
    latest_ms: nowMs,
    uncertainty_ms: 0,
    port_id: null,
    sample: null,
  });
  verifierState.last_trusted_clock_observation = observed;
  return observed;
}

function assertGrantVerifierValidityWindow(observed, payload, grantLabel) {
  if (observed.mode === SIGNED_TRUSTED_CLOCK_MODE) {
    if (observed.earliest_ms < Date.parse(payload.not_before)) {
      throw new Error(`${grantLabel} is not yet valid`);
    }
    if (observed.latest_ms >= Date.parse(payload.expires_at)) {
      throw new Error(`${grantLabel} has expired`);
    }
    assertPhysicalTrustedClockValidityWindow(observed.sample, {
      not_before: payload.not_before,
      expires_at: payload.expires_at,
    }, `${grantLabel} validity window`);
    return;
  }
  if (observed.now_ms < Date.parse(payload.not_before)) {
    throw new Error(`${grantLabel} is not yet valid`);
  }
  if (observed.now_ms >= Date.parse(payload.expires_at)) {
    throw new Error(`${grantLabel} has expired`);
  }
}

function assertGrantVerifierTimestampNonFuture(observed, timestampValue, timestampLabel, errorMessage) {
  if (observed.mode === SIGNED_TRUSTED_CLOCK_MODE) {
    if (Date.parse(timestampValue) > observed.earliest_ms) throw new Error(errorMessage);
    assertPhysicalTrustedClockTimestampNonFuture(observed.sample, timestampValue, timestampLabel);
    return;
  }
  if (Date.parse(timestampValue) > observed.now_ms) throw new Error(errorMessage);
}

function projectGrantVerifierClock(observed) {
  const projection = {
    trusted_clock_mode: observed.mode,
    // `verified_at` is a claimed past timestamp, so it uses the conservative
    // lower bound. The midpoint remains available only as labeled provenance.
    verified_at: observed.earliest,
    verified_clock_center: observed.now,
    verified_at_earliest: observed.earliest,
    verified_at_latest: observed.latest,
    verified_clock_uncertainty_ms: observed.uncertainty_ms,
  };
  if (observed.mode === SIGNED_TRUSTED_CLOCK_MODE) {
    Object.assign(projection, {
      verified_clock_port_id: observed.port_id,
      verified_clock_id: observed.sample.clock_id,
      verified_clock_monotonic_epoch_id: observed.sample.monotonic_epoch_id,
      verified_clock_mapping_generation: observed.sample.mapping_generation,
      verified_clock_mapping_digest: observed.sample.signed_mapping_digest,
      verified_clock_trust_root_epoch: observed.sample.trust_root_epoch,
      verified_clock_authority_epoch: observed.sample.authority_epoch,
      verified_clock_revocation_generation: observed.sample.revocation_generation,
    });
  }
  return Object.freeze(projection);
}

function assertDerivedDigest(input, field, actual, label) {
  if (!Object.prototype.hasOwnProperty.call(input, field)) return;
  assertDigest(input[field], `${label}.${field}`);
  if (input[field] !== actual) throw new Error(`${label}.${field} does not match the normalized request`);
}

function normalizeRequestedEffectSet(input, registry, label) {
  const effects = normalizeRequestedEffects(input, registry, label);
  if (effects.length === 0) throw new Error(`${label} must contain at least one exact requested effect`);
  return effects;
}

function assertInstrumentSubject(effect, instrumentRef, label) {
  if (effect.subject_kind !== "instrument" || effect.subject_ref !== instrumentRef) {
    throw new Error(`${label} must bind exactly to instrument ${instrumentRef}`);
  }
}

function normalizeCommonRequest(input, registry, requestPath, label) {
  if (input.version !== PHYSICAL_EXECUTION_REQUEST_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_EXECUTION_REQUEST_VERSION}`);
  }
  const grantKind = assertEnum(input.grant_kind, PHYSICAL_GRANT_KINDS, `${label}.grant_kind`);
  const normalizedRequestPath = assertEnum(requestPath, REQUEST_PATH_VALUES, "requestPath");
  if (grantKind === "maintenance" && normalizedRequestPath !== "operator_control") {
    throw new Error(`${label}.grant_kind maintenance is operator-only and unavailable on the MCP request path`);
  }
  if (grantKind !== "maintenance" && normalizedRequestPath !== "mcp") {
    throw new Error(`${label}.grant_kind ${grantKind} is only accepted on the MCP request path`);
  }
  if (
    Object.prototype.hasOwnProperty.call(input, "request_path")
    && input.request_path !== normalizedRequestPath
  ) {
    throw new Error(`${label}.request_path does not match the trusted request path`);
  }

  const notBefore = assertCanonicalTimestamp(input.not_before, `${label}.not_before`);
  const expiresAt = assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(expiresAt) <= Date.parse(notBefore)) {
    throw new Error(`${label}.expires_at must be after ${label}.not_before`);
  }

  const requestedEffects = normalizeRequestedEffectSet(
    input.requested_effects,
    registry,
    `${label}.requested_effects`,
  );
  const requestedEffectsDigest = hashCanonicalJson(requestedEffects);
  assertDerivedDigest(input, "requested_effects_digest", requestedEffectsDigest, label);

  return {
    version: PHYSICAL_EXECUTION_REQUEST_VERSION,
    grant_kind: grantKind,
    request_path: normalizedRequestPath,
    session_id: assertToken(input.session_id, `${label}.session_id`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    caller_role_id: assertToken(input.caller_role_id, `${label}.caller_role_id`),
    requester_principal_id: normalizeOpaqueRef(
      input.requester_principal_id,
      `${label}.requester_principal_id`,
      { prefix: "principal" },
    ),
    ipc_peer_principal_id: normalizeOpaqueRef(
      input.ipc_peer_principal_id,
      `${label}.ipc_peer_principal_id`,
      { prefix: "principal" },
    ),
    execution_principal_id: normalizeOpaqueRef(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      { prefix: "principal" },
    ),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, { prefix: "instrument" }),
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    parameter_digest: assertDigest(input.parameter_digest, `${label}.parameter_digest`),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, { min: 1 }),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
      { min: 0 },
    ),
    nonce: assertToken(input.nonce, `${label}.nonce`),
    sequence: assertInteger(input.sequence, `${label}.sequence`, { min: 1 }),
    not_before: notBefore,
    expires_at: expiresAt,
    requested_effects: requestedEffects,
    requested_effects_digest: requestedEffectsDigest,
  };
}

function normalizeBootstrapRequest(input, registry, requestPath, label) {
  const common = normalizeCommonRequest(input, registry, requestPath, label);
  if (input.rf_state !== "off") throw new Error(`${label}.rf_state must be off`);
  for (let index = 0; index < common.requested_effects.length; index += 1) {
    const effect = common.requested_effects[index];
    const effectLabel = `${label}.requested_effects[${index}]`;
    assertInstrumentSubject(effect, common.instrument_ref, effectLabel);
    if (effect.action !== "observe" || effect.persistence !== "none" || effect.channel === "rf") {
      throw new Error(`${effectLabel} must be instrument-local, read-only, non-RF, and non-persistent`);
    }
  }
  return {
    ...common,
    enrollment_candidate_ref: normalizeOpaqueRef(
      input.enrollment_candidate_ref,
      `${label}.enrollment_candidate_ref`,
      { prefix: "enrollment-candidate" },
    ),
    bootstrap_manifest_digest: assertDigest(
      input.bootstrap_manifest_digest,
      `${label}.bootstrap_manifest_digest`,
    ),
    provider_binary_digest: assertDigest(input.provider_binary_digest, `${label}.provider_binary_digest`),
    transport_digest: assertDigest(input.transport_digest, `${label}.transport_digest`),
    rf_state: "off",
  };
}

function normalizePreparationRequest(input, registry, requestPath, label) {
  const common = normalizeCommonRequest(input, registry, requestPath, label);
  if (input.rf_state !== "off") throw new Error(`${label}.rf_state must be off`);
  for (let index = 0; index < common.requested_effects.length; index += 1) {
    const effect = common.requested_effects[index];
    const effectLabel = `${label}.requested_effects[${index}]`;
    assertInstrumentSubject(effect, common.instrument_ref, effectLabel);
    if (
      !["observe", "configure"].includes(effect.action)
      || effect.channel === "rf"
      || effect.persistence === "irreversible"
    ) {
      throw new Error(`${effectLabel} must remain RF-off and instrument-local without irreversible effects`);
    }
  }
  return {
    ...common,
    bootstrap_receipt_ref: normalizeOpaqueRef(
      input.bootstrap_receipt_ref,
      `${label}.bootstrap_receipt_ref`,
      { prefix: "bootstrap-receipt" },
    ),
    bootstrap_execution_request_digest: assertDigest(
      input.bootstrap_execution_request_digest,
      `${label}.bootstrap_execution_request_digest`,
    ),
    bootstrap_inventory_observation_ref: normalizeOpaqueRef(
      input.bootstrap_inventory_observation_ref,
      `${label}.bootstrap_inventory_observation_ref`,
      { prefix: "inventory-observation" },
    ),
    bootstrap_inventory_digest: assertDigest(
      input.bootstrap_inventory_digest,
      `${label}.bootstrap_inventory_digest`,
    ),
    assurance_profile_id: assertToken(input.assurance_profile_id, `${label}.assurance_profile_id`),
    assurance_claims_digest: assertDigest(input.assurance_claims_digest, `${label}.assurance_claims_digest`),
    provider_manifest_digest: assertDigest(input.provider_manifest_digest, `${label}.provider_manifest_digest`),
    preparation_plan_digest: assertDigest(input.preparation_plan_digest, `${label}.preparation_plan_digest`),
    snapshot_plan_digest: assertDigest(input.snapshot_plan_digest, `${label}.snapshot_plan_digest`),
    rf_state: "off",
  };
}

function normalizeActiveExecutionLineage(
  input,
  label = "active_physical_execution_lineage",
) {
  assertClosedObject(input, label, ACTIVE_EXECUTION_LINEAGE_FIELDS, [
    "execution_lineage_digest",
  ]);
  if (input.version !== ACTIVE_PHYSICAL_EXECUTION_LINEAGE_VERSION) {
    throw new Error(
      `${label}.version must be ${ACTIVE_PHYSICAL_EXECUTION_LINEAGE_VERSION}`,
    );
  }
  const maximumResponseBytes = assertInteger(
    input.maximum_response_bytes,
    `${label}.maximum_response_bytes`,
    { min: 1 },
  );
  const vaultByteLimit = assertInteger(
    input.vault_byte_limit,
    `${label}.vault_byte_limit`,
    { min: 1 },
  );
  if (maximumResponseBytes > 16 * 1024 * 1024 || vaultByteLimit > 16 * 1024 * 1024) {
    throw new Error(`${label} response and vault byte limits must not exceed 16 MiB`);
  }
  if (maximumResponseBytes > vaultByteLimit) {
    throw new Error(`${label}.vault_byte_limit cannot strand the maximum provider response`);
  }
  const compiledCommandCapabilityDigest = assertDigest(
    input.compiled_command_capability_digest,
    `${label}.compiled_command_capability_digest`,
  );
  const commandInputDigest = assertDigest(
    input.command_input_digest,
    `${label}.command_input_digest`,
  );
  if (commandInputDigest !== compiledCommandCapabilityDigest) {
    throw new Error(
      `${label}.command_input_digest must be the exact compiled command capability digest`,
    );
  }
  const basis = {
    version: ACTIVE_PHYSICAL_EXECUTION_LINEAGE_VERSION,
    compiler_id: assertIdentifier(input.compiler_id, `${label}.compiler_id`),
    compiler_manifest_digest: assertDigest(
      input.compiler_manifest_digest,
      `${label}.compiler_manifest_digest`,
    ),
    compiler_registry_digest: assertDigest(
      input.compiler_registry_digest,
      `${label}.compiler_registry_digest`,
    ),
    compiled_command_id: normalizeOpaqueRef(
      input.compiled_command_id,
      `${label}.compiled_command_id`,
      { prefix: "compiled-command" },
    ),
    compiled_command_capability_digest: compiledCommandCapabilityDigest,
    compiled_operation_digest: assertDigest(
      input.compiled_operation_digest,
      `${label}.compiled_operation_digest`,
    ),
    provider_command_ref: normalizeOpaqueRef(
      input.provider_command_ref,
      `${label}.provider_command_ref`,
      { prefix: "command" },
    ),
    command_input_ref: normalizeOpaqueRef(
      input.command_input_ref,
      `${label}.command_input_ref`,
      { prefix: "command-input" },
    ),
    command_input_digest: commandInputDigest,
    maximum_response_bytes: maximumResponseBytes,
    vault_reservation_handle: normalizeOpaqueRef(
      input.vault_reservation_handle,
      `${label}.vault_reservation_handle`,
      { prefix: "vault-reservation" },
    ),
    vault_reservation_digest: assertDigest(
      input.vault_reservation_digest,
      `${label}.vault_reservation_digest`,
    ),
    vault_ingest_capability_digest: assertDigest(
      input.vault_ingest_capability_digest,
      `${label}.vault_ingest_capability_digest`,
    ),
    vault_byte_limit: vaultByteLimit,
    worker_bundle_digest: assertDigest(
      input.worker_bundle_digest,
      `${label}.worker_bundle_digest`,
    ),
    worker_launch_profile_digest: assertDigest(
      input.worker_launch_profile_digest,
      `${label}.worker_launch_profile_digest`,
    ),
    worker_fence_plan_digest: assertDigest(
      input.worker_fence_plan_digest,
      `${label}.worker_fence_plan_digest`,
    ),
    transport_profile_digest: assertDigest(
      input.transport_profile_digest,
      `${label}.transport_profile_digest`,
    ),
    durable_exchange_plan_digest: assertDigest(
      input.durable_exchange_plan_digest,
      `${label}.durable_exchange_plan_digest`,
    ),
    terminal_receipt_recipient_digest: assertDigest(
      input.terminal_receipt_recipient_digest,
      `${label}.terminal_receipt_recipient_digest`,
    ),
    safety_supervisor_plan_digest: assertDigest(
      input.safety_supervisor_plan_digest,
      `${label}.safety_supervisor_plan_digest`,
    ),
  };
  const executionLineageDigest = hashCanonicalJson(basis);
  assertDerivedDigest(input, "execution_lineage_digest", executionLineageDigest, label);
  return deepFreeze({ ...basis, execution_lineage_digest: executionLineageDigest });
}

function normalizeActiveRequest(input, registry, requestPath, label) {
  const common = normalizeCommonRequest(input, registry, requestPath, label);
  for (let index = 0; index < common.requested_effects.length; index += 1) {
    const effect = common.requested_effects[index];
    const effectLabel = `${label}.requested_effects[${index}]`;
    if (effect.subject_kind === "instrument") {
      assertInstrumentSubject(effect, common.instrument_ref, effectLabel);
      if (["administer", "destroy"].includes(effect.action)) {
        throw new Error(`${effectLabel} requires a separate operator maintenance request`);
      }
    }
  }
  return {
    ...common,
    node_id: assertToken(input.node_id, `${label}.node_id`),
    contract_hash: assertDigest(input.contract_hash, `${label}.contract_hash`),
    prep_token_hash: assertDigest(input.prep_token_hash, `${label}.prep_token_hash`),
    dispatch_event_id: assertToken(input.dispatch_event_id, `${label}.dispatch_event_id`),
    graph_context_hash: assertDigest(input.graph_context_hash, `${label}.graph_context_hash`),
    capability_pack_id: assertToken(input.capability_pack_id, `${label}.capability_pack_id`),
    capability_pack_version: assertToken(input.capability_pack_version, `${label}.capability_pack_version`),
    capability_pack_digest: assertDigest(input.capability_pack_digest, `${label}.capability_pack_digest`),
    technique_cell_id: assertToken(input.technique_cell_id, `${label}.technique_cell_id`),
    attempt_id: assertToken(input.attempt_id, `${label}.attempt_id`),
    experiment_plan_hash: assertDigest(input.experiment_plan_hash, `${label}.experiment_plan_hash`),
    inventory_observation_ref: normalizeOpaqueRef(
      input.inventory_observation_ref,
      `${label}.inventory_observation_ref`,
      { prefix: "inventory-observation" },
    ),
    inventory_observation_digest: assertDigest(
      input.inventory_observation_digest,
      `${label}.inventory_observation_digest`,
    ),
    assurance_profile_id: assertToken(input.assurance_profile_id, `${label}.assurance_profile_id`),
    assurance_claims_digest: assertDigest(input.assurance_claims_digest, `${label}.assurance_claims_digest`),
    provider_manifest_digest: assertDigest(input.provider_manifest_digest, `${label}.provider_manifest_digest`),
    availability_variant_id: assertToken(input.availability_variant_id, `${label}.availability_variant_id`),
    availability_variant_digest: assertDigest(
      input.availability_variant_digest,
      `${label}.availability_variant_digest`,
    ),
    authorized_transition_set_digest: assertDigest(
      input.authorized_transition_set_digest,
      `${label}.authorized_transition_set_digest`,
    ),
    resource_bundle_digest: assertDigest(input.resource_bundle_digest, `${label}.resource_bundle_digest`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    workspace_snapshot_ref: normalizeOpaqueRef(
      input.workspace_snapshot_ref,
      `${label}.workspace_snapshot_ref`,
      { prefix: "workspace-snapshot" },
    ),
    workspace_snapshot_digest: assertDigest(
      input.workspace_snapshot_digest,
      `${label}.workspace_snapshot_digest`,
    ),
    observer_plan_digest: assertDigest(input.observer_plan_digest, `${label}.observer_plan_digest`),
    control_plan_digest: assertDigest(input.control_plan_digest, `${label}.control_plan_digest`),
    cleanup_plan_digest: assertDigest(input.cleanup_plan_digest, `${label}.cleanup_plan_digest`),
    execution_lineage: normalizeActiveExecutionLineage(
      input.execution_lineage,
      `${label}.execution_lineage`,
    ),
  };
}

function normalizeMaintenanceRequest(input, registry, requestPath, label) {
  const common = normalizeCommonRequest(input, registry, requestPath, label);
  if (common.caller_role_id !== "operator") {
    throw new Error(`${label}.caller_role_id must be operator for maintenance`);
  }
  const ownedFixtureRef = normalizeOpaqueRef(
    input.owned_fixture_ref,
    `${label}.owned_fixture_ref`,
    { prefix: "instrument" },
  );
  if (ownedFixtureRef !== common.instrument_ref) {
    throw new Error(`${label}.owned_fixture_ref must match ${label}.instrument_ref`);
  }

  let hasMaintenanceEffect = false;
  let hasDestroyEffect = false;
  for (let index = 0; index < common.requested_effects.length; index += 1) {
    const effect = common.requested_effects[index];
    const effectLabel = `${label}.requested_effects[${index}]`;
    assertInstrumentSubject(effect, ownedFixtureRef, effectLabel);
    if (!["observe", "configure", "administer", "destroy"].includes(effect.action) || effect.channel === "rf") {
      throw new Error(`${effectLabel} must be a local owned-fixture maintenance effect`);
    }
    if (effect.persistence === "irreversible" && effect.action !== "destroy") {
      throw new Error(`${effectLabel} may be irreversible only when the exact action is destroy`);
    }
    if (["configure", "administer", "destroy"].includes(effect.action)) hasMaintenanceEffect = true;
    if (effect.action === "destroy") {
      hasDestroyEffect = true;
      if (effect.persistence !== "irreversible") {
        throw new Error(`${effectLabel} destroy must declare irreversible persistence`);
      }
    }
  }
  if (!hasMaintenanceEffect) {
    throw new Error(`${label}.requested_effects must contain an exact configure, administer, or destroy effect`);
  }

  const terminalCustody = assertEnum(
    input.terminal_custody,
    TERMINAL_CUSTODY_VALUES,
    `${label}.terminal_custody`,
  );
  if (hasDestroyEffect && !["quarantine", "disposal"].includes(terminalCustody)) {
    throw new Error(`${label}.terminal_custody must be quarantine or disposal after destroy`);
  }

  return {
    ...common,
    owned_fixture_ref: ownedFixtureRef,
    ownership_attestation_digest: assertDigest(
      input.ownership_attestation_digest,
      `${label}.ownership_attestation_digest`,
    ),
    pre_state_ref: normalizeOpaqueRef(input.pre_state_ref, `${label}.pre_state_ref`, { prefix: "pre-state" }),
    pre_state_digest: assertDigest(input.pre_state_digest, `${label}.pre_state_digest`),
    backup_ref: normalizeOpaqueRef(input.backup_ref, `${label}.backup_ref`, { prefix: "backup" }),
    backup_digest: assertDigest(input.backup_digest, `${label}.backup_digest`),
    exact_state_delta_digest: assertDigest(
      input.exact_state_delta_digest,
      `${label}.exact_state_delta_digest`,
    ),
    expected_terminal_state_digest: assertDigest(
      input.expected_terminal_state_digest,
      `${label}.expected_terminal_state_digest`,
    ),
    post_operation_inventory_plan_digest: assertDigest(
      input.post_operation_inventory_plan_digest,
      `${label}.post_operation_inventory_plan_digest`,
    ),
    assurance_invalidation_plan_digest: assertDigest(
      input.assurance_invalidation_plan_digest,
      `${label}.assurance_invalidation_plan_digest`,
    ),
    recovery_or_quarantine_plan_digest: assertDigest(
      input.recovery_or_quarantine_plan_digest,
      `${label}.recovery_or_quarantine_plan_digest`,
    ),
    hil_plan_digest: assertDigest(input.hil_plan_digest, `${label}.hil_plan_digest`),
    terminal_custody: terminalCustody,
  };
}

function normalizePhysicalExecutionRequest(input, registry, options = {}) {
  if (!isPlainObject(options)) throw new Error("physical execution request options must be an object");
  assertClosedObject(options, "physical execution request options", [], ["requestPath", "label"]);
  const label = options.label || "physical_execution_request";
  if (!isPlainObject(input)) throw new Error(`${label} must be an object`);

  const grantKind = input.grant_kind;
  if (grantKind === "cleanup") {
    throw new Error(`${label}.grant_kind cleanup is not an agent-requestable grant; use a separately rooted capability`);
  }
  assertEnum(grantKind, PHYSICAL_GRANT_KINDS, `${label}.grant_kind`);
  assertClosedObject(
    input,
    label,
    [...COMMON_REQUEST_FIELDS, ...FIELDS_BY_GRANT_KIND[grantKind]],
    DERIVED_REQUEST_FIELDS,
  );

  const requestPath = options.requestPath || "mcp";
  let normalized;
  if (grantKind === "bootstrap") normalized = normalizeBootstrapRequest(input, registry, requestPath, label);
  else if (grantKind === "preparation") normalized = normalizePreparationRequest(input, registry, requestPath, label);
  else if (grantKind === "active") normalized = normalizeActiveRequest(input, registry, requestPath, label);
  else normalized = normalizeMaintenanceRequest(input, registry, requestPath, label);

  const executionRequestDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "execution_request_digest", executionRequestDigest, label);
  return deepFreeze({ ...normalized, execution_request_digest: executionRequestDigest });
}

function normalizeMcpPhysicalExecutionRequest(input, registry, options = {}) {
  if (!isPlainObject(options)) throw new Error("MCP physical request options must be an object");
  assertClosedObject(options, "MCP physical request options", [], ["label"]);
  return normalizePhysicalExecutionRequest(input, registry, { ...options, requestPath: "mcp" });
}

function normalizeOperatorMaintenanceRequest(input, registry, options = {}) {
  if (!isPlainObject(options)) throw new Error("operator maintenance request options must be an object");
  assertClosedObject(options, "operator maintenance request options", [], ["label"]);
  if (!isPlainObject(input) || input.grant_kind !== "maintenance") {
    throw new Error("operator maintenance request must use grant_kind maintenance");
  }
  return normalizePhysicalExecutionRequest(input, registry, { ...options, requestPath: "operator_control" });
}

function physicalExecutionRequestDigest(input, registry, options = {}) {
  return normalizePhysicalExecutionRequest(input, registry, options).execution_request_digest;
}

// Active grants cross the authority/process boundary as signed envelopes. The
// signature and trust material are consumed here and deliberately omitted from
// the broker-facing projection. A projection is useful only with the exact
// verifier instance that issued it; copying a self-hashed JSON object cannot
// manufacture the private WeakSet/WeakMap provenance.
const ACTIVE_GRANT_PAYLOAD_FIELDS = Object.freeze([
  "version",
  "grant_kind",
  "grant_ref",
  "session_id",
  "session_nucleus_hash",
  "physical_scope_axis_digest",
  "physical_scope_policy_id",
  "physical_scope_policy_digest",
  "physical_scope_projection_digest",
  "authority_epoch",
  "revocation_generation",
  "execution_request_digest",
  "request_nonce",
  "request_sequence",
  "execution_principal_id",
  "provider_id",
  "provider_descriptor_digest",
  "instrument_ref",
  "operation_id",
  "operation_digest",
  "parameter_digest",
  "requested_effects_digest",
  "authority_decision",
  "authority_reason",
  "authority_resolution_digest",
  "attempt_id",
  "experiment_plan_hash",
  "execution_lineage_digest",
  "resource_bundle_digest",
  "lease_id",
  "fencing_token",
  "fencing_generation",
  "workspace_snapshot_digest",
  "cleanup_plan_digest",
  "not_before",
  "expires_at",
]);

const ACTIVE_GRANT_AUTHENTICATION_FIELDS = Object.freeze([
  "version",
  "method",
  "trust_root_id",
  "trust_root_epoch",
  "trust_registry_digest",
  "issuer_principal_id",
  "issuer_key_id",
  "issuer_epoch",
  "issuer_public_key_digest",
  "signed_at",
  "signed_payload_digest",
]);

const ACTIVE_GRANT_BROKER_BINDING_FIELDS = Object.freeze([
  "execution_request_digest",
  "authority_resolution_digest",
  "execution_principal_id",
  "provider_id",
  "provider_descriptor_digest",
  "instrument_ref",
  "operation_id",
  "operation_digest",
  "attempt_id",
  "experiment_plan_hash",
  "execution_lineage_digest",
  "lease_id",
  "fencing_token",
  "fencing_generation",
  "resource_bundle_digest",
]);

function normalizeActiveGrantPayload(input, label = "active_physical_execution_grant.payload") {
  assertClosedObject(input, label, ACTIVE_GRANT_PAYLOAD_FIELDS);
  if (input.version !== ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION) {
    throw new Error(`${label}.version must be ${ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION}`);
  }
  if (input.grant_kind !== "active") throw new Error(`${label}.grant_kind must be active`);
  const notBefore = assertCanonicalTimestamp(input.not_before, `${label}.not_before`);
  const expiresAt = assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(expiresAt) <= Date.parse(notBefore)) {
    throw new Error(`${label}.expires_at must be after ${label}.not_before`);
  }
  return deepFreeze({
    version: ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION,
    grant_kind: "active",
    grant_ref: normalizeOpaqueRef(input.grant_ref, `${label}.grant_ref`, { prefix: "physical-grant" }),
    session_id: assertToken(input.session_id, `${label}.session_id`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    physical_scope_axis_digest: assertDigest(
      input.physical_scope_axis_digest,
      `${label}.physical_scope_axis_digest`,
    ),
    physical_scope_policy_id: assertIdentifier(
      input.physical_scope_policy_id,
      `${label}.physical_scope_policy_id`,
    ),
    physical_scope_policy_digest: assertDigest(
      input.physical_scope_policy_digest,
      `${label}.physical_scope_policy_digest`,
    ),
    physical_scope_projection_digest: assertDigest(
      input.physical_scope_projection_digest,
      `${label}.physical_scope_projection_digest`,
    ),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, { min: 1 }),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
      { min: 0 },
    ),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    request_nonce: assertToken(input.request_nonce, `${label}.request_nonce`),
    request_sequence: assertInteger(input.request_sequence, `${label}.request_sequence`, { min: 1 }),
    execution_principal_id: normalizeOpaqueRef(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      { prefix: "principal" },
    ),
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    operation_id: assertIdentifier(input.operation_id, `${label}.operation_id`),
    operation_digest: assertDigest(input.operation_digest, `${label}.operation_digest`),
    parameter_digest: assertDigest(input.parameter_digest, `${label}.parameter_digest`),
    requested_effects_digest: assertDigest(
      input.requested_effects_digest,
      `${label}.requested_effects_digest`,
    ),
    authority_decision: assertEnum(input.authority_decision, ["allow"], `${label}.authority_decision`),
    authority_reason: assertEnum(input.authority_reason, ["exact_allow"], `${label}.authority_reason`),
    authority_resolution_digest: assertDigest(
      input.authority_resolution_digest,
      `${label}.authority_resolution_digest`,
    ),
    attempt_id: assertToken(input.attempt_id, `${label}.attempt_id`),
    experiment_plan_hash: assertDigest(
      input.experiment_plan_hash,
      `${label}.experiment_plan_hash`,
    ),
    execution_lineage_digest: assertDigest(
      input.execution_lineage_digest,
      `${label}.execution_lineage_digest`,
    ),
    resource_bundle_digest: assertDigest(
      input.resource_bundle_digest,
      `${label}.resource_bundle_digest`,
    ),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    fencing_generation: assertInteger(
      input.fencing_generation,
      `${label}.fencing_generation`,
      { min: 1 },
    ),
    workspace_snapshot_digest: assertDigest(
      input.workspace_snapshot_digest,
      `${label}.workspace_snapshot_digest`,
    ),
    cleanup_plan_digest: assertDigest(input.cleanup_plan_digest, `${label}.cleanup_plan_digest`),
    not_before: notBefore,
    expires_at: expiresAt,
  });
}

function normalizeActiveGrantAuthenticationBasis(
  input,
  payloadDigest,
  label = "active_physical_execution_grant.authentication",
) {
  assertClosedObject(input, label, ACTIVE_GRANT_AUTHENTICATION_FIELDS);
  if (input.version !== ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION) {
    throw new Error(`${label}.version must be ${ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION}`);
  }
  if (input.method !== "ed25519") throw new Error(`${label}.method must be ed25519`);
  const normalized = {
    version: ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION,
    method: "ed25519",
    trust_root_id: normalizeOpaqueRef(input.trust_root_id, `${label}.trust_root_id`, {
      prefix: "trust-root",
    }),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, { min: 1 }),
    trust_registry_digest: assertDigest(input.trust_registry_digest, `${label}.trust_registry_digest`),
    issuer_principal_id: normalizeOpaqueRef(
      input.issuer_principal_id,
      `${label}.issuer_principal_id`,
      { prefix: "principal" },
    ),
    issuer_key_id: normalizeOpaqueRef(input.issuer_key_id, `${label}.issuer_key_id`, {
      prefix: "signer-key",
    }),
    issuer_epoch: assertInteger(input.issuer_epoch, `${label}.issuer_epoch`, { min: 1 }),
    issuer_public_key_digest: assertDigest(
      input.issuer_public_key_digest,
      `${label}.issuer_public_key_digest`,
    ),
    signed_at: assertCanonicalTimestamp(input.signed_at, `${label}.signed_at`),
    signed_payload_digest: assertDigest(
      input.signed_payload_digest,
      `${label}.signed_payload_digest`,
    ),
  };
  if (normalized.signed_payload_digest !== payloadDigest) {
    throw new Error(`${label}.signed_payload_digest does not bind the normalized grant payload`);
  }
  return deepFreeze(normalized);
}

function activePhysicalExecutionGrantSignatureInputDigest(payloadInput, authenticationInput) {
  const payload = normalizeActiveGrantPayload(payloadInput);
  const payloadDigest = hashCanonicalJson(payload);
  const authentication = normalizeActiveGrantAuthenticationBasis(authenticationInput, payloadDigest);
  return hashCanonicalJson({
    domain: ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN,
    version: ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION,
    kind: "active_physical_execution_grant",
    payload,
    authentication,
  });
}

function assertCanonicalEd25519Signature(value, label) {
  if (typeof value !== "string" || !ED25519_SIGNATURE_PATTERN.test(value)) {
    throw new Error(`${label} must be a canonical 86-character Ed25519 base64url signature`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    throw new Error(`${label} must use canonical Ed25519 base64url encoding`);
  }
  return value;
}

function normalizeSignedActivePhysicalExecutionGrant(
  input,
  label = "active_physical_execution_grant",
) {
  assertClosedObject(
    input,
    label,
    ["version", "kind", "domain", "payload", "authentication"],
    ["grant_envelope_digest"],
  );
  if (input.version !== ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION) {
    throw new Error(`${label}.version must be ${ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION}`);
  }
  if (input.kind !== "active_physical_execution_grant") {
    throw new Error(`${label}.kind must be active_physical_execution_grant`);
  }
  if (input.domain !== ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN) {
    throw new Error(`${label}.domain does not match the active physical grant signature domain`);
  }
  const payload = normalizeActiveGrantPayload(input.payload, `${label}.payload`);
  const grantPayloadDigest = hashCanonicalJson(payload);
  assertClosedObject(
    input.authentication,
    `${label}.authentication`,
    [...ACTIVE_GRANT_AUTHENTICATION_FIELDS, "signature"],
  );
  const authenticationBasis = normalizeActiveGrantAuthenticationBasis(
    Object.fromEntries(ACTIVE_GRANT_AUTHENTICATION_FIELDS.map((field) => [field, input.authentication[field]])),
    grantPayloadDigest,
    `${label}.authentication`,
  );
  const signature = assertCanonicalEd25519Signature(
    input.authentication.signature,
    `${label}.authentication.signature`,
  );
  const signatureInputDigest = activePhysicalExecutionGrantSignatureInputDigest(
    payload,
    authenticationBasis,
  );
  const authentication = deepFreeze({ ...authenticationBasis, signature });
  const signedEnvelope = {
    version: ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION,
    kind: "active_physical_execution_grant",
    domain: ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN,
    payload,
    authentication,
  };
  const grantEnvelopeDigest = hashCanonicalJson(signedEnvelope);
  assertDerivedDigest(input, "grant_envelope_digest", grantEnvelopeDigest, label);
  return deepFreeze({
    ...signedEnvelope,
    grant_payload_digest: grantPayloadDigest,
    signature_input_digest: signatureInputDigest,
    grant_envelope_digest: grantEnvelopeDigest,
  });
}

function normalizeCurrentActiveGrantAuthority(input, label = "current_active_grant_authority") {
  assertClosedObject(input, label, [
    "version",
    "session_id",
    "session_nucleus_hash",
    "execution_request_digest",
    "physical_scope_axis",
    "authority_decision",
    "authority_reason",
    "authority_resolution_digest",
    "trust_root_id",
    "trust_root_epoch",
    "trust_registry_digest",
    "trust_root_trusted",
    "trust_root_revoked",
    "issuer_principal_id",
    "issuer_key_id",
    "issuer_epoch",
    "issuer_public_key_digest",
    "key_usage",
    "issuer_trusted",
    "issuer_revoked",
  ]);
  if (input.version !== ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION) {
    throw new Error(`${label}.version must be ${ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION}`);
  }
  const trustRootTrusted = assertBoolean(input.trust_root_trusted, `${label}.trust_root_trusted`);
  const trustRootRevoked = assertBoolean(input.trust_root_revoked, `${label}.trust_root_revoked`);
  const issuerTrusted = assertBoolean(input.issuer_trusted, `${label}.issuer_trusted`);
  const issuerRevoked = assertBoolean(input.issuer_revoked, `${label}.issuer_revoked`);
  if (!trustRootTrusted || trustRootRevoked) throw new Error(`${label} trust root is not currently usable`);
  if (!issuerTrusted || issuerRevoked) throw new Error(`${label} issuer is not currently usable`);
  return deepFreeze({
    version: ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION,
    session_id: assertToken(input.session_id, `${label}.session_id`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    physical_scope_axis: normalizePhysicalScopeNucleusAxis(input.physical_scope_axis),
    authority_decision: assertEnum(input.authority_decision, ["allow"], `${label}.authority_decision`),
    authority_reason: assertEnum(input.authority_reason, ["exact_allow"], `${label}.authority_reason`),
    authority_resolution_digest: assertDigest(
      input.authority_resolution_digest,
      `${label}.authority_resolution_digest`,
    ),
    trust_root_id: normalizeOpaqueRef(input.trust_root_id, `${label}.trust_root_id`, {
      prefix: "trust-root",
    }),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, { min: 1 }),
    trust_registry_digest: assertDigest(input.trust_registry_digest, `${label}.trust_registry_digest`),
    trust_root_trusted: true,
    trust_root_revoked: false,
    issuer_principal_id: normalizeOpaqueRef(
      input.issuer_principal_id,
      `${label}.issuer_principal_id`,
      { prefix: "principal" },
    ),
    issuer_key_id: normalizeOpaqueRef(input.issuer_key_id, `${label}.issuer_key_id`, {
      prefix: "signer-key",
    }),
    issuer_epoch: assertInteger(input.issuer_epoch, `${label}.issuer_epoch`, { min: 1 }),
    issuer_public_key_digest: assertDigest(
      input.issuer_public_key_digest,
      `${label}.issuer_public_key_digest`,
    ),
    key_usage: assertEnum(
      input.key_usage,
      [ACTIVE_PHYSICAL_EXECUTION_GRANT_KEY_USAGE],
      `${label}.key_usage`,
    ),
    issuer_trusted: true,
    issuer_revoked: false,
  });
}

function createActivePhysicalExecutionGrantVerifier(input) {
  assertClosedObject(input, "active_physical_execution_grant_verifier", [
    "verifier_id",
    "resolve_current_authority",
    "verify_ed25519",
    "reserve_replay",
  ], ["trusted_clock_port", "trusted_now"]);
  for (const field of ["resolve_current_authority", "verify_ed25519", "reserve_replay"]) {
    if (typeof input[field] !== "function") {
      throw new Error(`active_physical_execution_grant_verifier.${field} must be a function`);
    }
  }
  const clock = normalizeGrantVerifierClock(input, "active_physical_execution_grant_verifier");
  const verifier = Object.freeze({
    version: ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION,
    verifier_id: assertIdentifier(
      input.verifier_id,
      "active_physical_execution_grant_verifier.verifier_id",
    ),
    trusted_clock_mode: clock.mode,
    trusted_clock_port_id: clock.trusted_clock_port == null
      ? null
      : clock.trusted_clock_port.port_id,
  });
  ACTIVE_GRANT_VERIFIERS.add(verifier);
  ACTIVE_GRANT_VERIFIER_STATE.set(verifier, {
    trusted_clock_mode: clock.mode,
    trusted_clock_port: clock.trusted_clock_port,
    trusted_now: clock.trusted_now,
    resolve_current_authority: input.resolve_current_authority,
    verify_ed25519: input.verify_ed25519,
    reserve_replay: input.reserve_replay,
    last_trusted_now_ms: null,
    last_trusted_clock_observation: null,
    projected_grant_refs: new Set(),
    projected_execution_requests: new Set(),
  });
  return verifier;
}

function assertActiveGrantVerifier(input) {
  if (!input || !ACTIVE_GRANT_VERIFIERS.has(input) || !ACTIVE_GRANT_VERIFIER_STATE.has(input)) {
    throw new Error("active physical execution grant verifier must be a configured Bob verifier");
  }
  return input;
}

function readActiveGrantTrustedClock(verifierState) {
  return readGrantVerifierClock(
    verifierState,
    "trusted clock moved backwards while verifying an active physical grant",
  );
}

function normalizeActiveGrantReplayClaim(input, label = "active_grant_replay_claim") {
  assertClosedObject(input, label, [
    "version",
    "grant_ref",
    "signed_grant_digest",
    "execution_request_digest",
    "session_nucleus_hash",
    "provider_descriptor_digest",
    "attempt_id",
    "lease_id",
    "fencing_token_digest",
    "fencing_generation",
    "expires_at",
  ]);
  if (input.version !== ACTIVE_GRANT_REPLAY_RESERVATION_VERSION) {
    throw new Error(`${label}.version must be ${ACTIVE_GRANT_REPLAY_RESERVATION_VERSION}`);
  }
  return deepFreeze({
    version: ACTIVE_GRANT_REPLAY_RESERVATION_VERSION,
    grant_ref: normalizeOpaqueRef(input.grant_ref, `${label}.grant_ref`, { prefix: "physical-grant" }),
    signed_grant_digest: assertDigest(input.signed_grant_digest, `${label}.signed_grant_digest`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    attempt_id: assertToken(input.attempt_id, `${label}.attempt_id`),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token_digest: assertDigest(input.fencing_token_digest, `${label}.fencing_token_digest`),
    fencing_generation: assertInteger(
      input.fencing_generation,
      `${label}.fencing_generation`,
      { min: 1 },
    ),
    expires_at: assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`),
  });
}

function normalizeActiveGrantReplayReservationResult(
  input,
  expectedClaim,
  label = "active_grant_replay_reservation",
) {
  assertClosedObject(input, label, ["version", "disposition", "reservation_receipt"]);
  if (input.version !== ACTIVE_GRANT_REPLAY_RESERVATION_VERSION) {
    throw new Error(`${label}.version must be ${ACTIVE_GRANT_REPLAY_RESERVATION_VERSION}`);
  }
  const disposition = assertEnum(
    input.disposition,
    ACTIVE_GRANT_REPLAY_RESERVATION_DISPOSITIONS,
    `${label}.disposition`,
  );
  const receiptInput = input.reservation_receipt;
  assertClosedObject(
    receiptInput,
    `${label}.reservation_receipt`,
    [
      "version",
      "reservation_ref",
      "replay_claim",
      "replay_claim_digest",
      "generation",
      "previous_receipt_digest",
      "reserved_at",
      "fsynced_at",
    ],
    ["receipt_digest"],
  );
  if (receiptInput.version !== ACTIVE_GRANT_REPLAY_RESERVATION_VERSION) {
    throw new Error(
      `${label}.reservation_receipt.version must be ${ACTIVE_GRANT_REPLAY_RESERVATION_VERSION}`,
    );
  }
  const replayClaim = normalizeActiveGrantReplayClaim(
    receiptInput.replay_claim,
    `${label}.reservation_receipt.replay_claim`,
  );
  if (hashCanonicalJson(replayClaim) !== hashCanonicalJson(expectedClaim)) {
    throw new Error(`${label}.reservation_receipt replay claim does not match the verified grant`);
  }
  const replayClaimDigest = hashCanonicalJson(replayClaim);
  if (assertDigest(
    receiptInput.replay_claim_digest,
    `${label}.reservation_receipt.replay_claim_digest`,
  ) !== replayClaimDigest) {
    throw new Error(`${label}.reservation_receipt.replay_claim_digest does not match its claim`);
  }
  const reservedAt = assertCanonicalTimestamp(
    receiptInput.reserved_at,
    `${label}.reservation_receipt.reserved_at`,
  );
  const fsyncedAt = assertCanonicalTimestamp(
    receiptInput.fsynced_at,
    `${label}.reservation_receipt.fsynced_at`,
  );
  if (Date.parse(fsyncedAt) < Date.parse(reservedAt)) {
    throw new Error(`${label}.reservation_receipt.fsynced_at must not precede reserved_at`);
  }
  const receipt = {
    version: ACTIVE_GRANT_REPLAY_RESERVATION_VERSION,
    reservation_ref: normalizeOpaqueRef(
      receiptInput.reservation_ref,
      `${label}.reservation_receipt.reservation_ref`,
      { prefix: "grant-replay-reservation" },
    ),
    replay_claim: replayClaim,
    replay_claim_digest: replayClaimDigest,
    generation: assertInteger(
      receiptInput.generation,
      `${label}.reservation_receipt.generation`,
      { min: 1 },
    ),
    previous_receipt_digest: receiptInput.previous_receipt_digest == null
      ? null
      : assertDigest(
        receiptInput.previous_receipt_digest,
        `${label}.reservation_receipt.previous_receipt_digest`,
      ),
    reserved_at: reservedAt,
    fsynced_at: fsyncedAt,
  };
  if (receipt.generation === 1 && receipt.previous_receipt_digest !== null) {
    throw new Error(`${label}.reservation_receipt generation 1 cannot have a previous receipt`);
  }
  if (receipt.generation > 1 && receipt.previous_receipt_digest === null) {
    throw new Error(`${label}.reservation_receipt generation >1 requires a previous receipt`);
  }
  const receiptDigest = hashCanonicalJson(receipt);
  assertDerivedDigest(receiptInput, "receipt_digest", receiptDigest, `${label}.reservation_receipt`);
  return deepFreeze({
    version: ACTIVE_GRANT_REPLAY_RESERVATION_VERSION,
    disposition,
    reservation_receipt: deepFreeze({ ...receipt, receipt_digest: receiptDigest }),
  });
}

function normalizeActiveGrantProjectionBindings(input) {
  assertClosedObject(input, "active_grant_projection_bindings", [
    "execution_request",
    "effect_registry",
    "provider_id",
    "provider_descriptor_digest",
    "operation_digest",
    "fencing_generation",
  ]);
  const request = normalizeMcpPhysicalExecutionRequest(input.execution_request, input.effect_registry, {
    label: "active_grant_projection_bindings.execution_request",
  });
  if (request.grant_kind !== "active") {
    throw new Error("active grant projection requires an active physical execution request");
  }
  return {
    request,
    provider_id: assertIdentifier(input.provider_id, "active_grant_projection_bindings.provider_id"),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      "active_grant_projection_bindings.provider_descriptor_digest",
    ),
    operation_digest: assertDigest(
      input.operation_digest,
      "active_grant_projection_bindings.operation_digest",
    ),
    fencing_generation: assertInteger(
      input.fencing_generation,
      "active_grant_projection_bindings.fencing_generation",
      { min: 1 },
    ),
  };
}

function assertExactActiveGrantBindings(actual, expected, fields, label) {
  for (const field of fields) {
    if (actual[field] !== expected[field]) {
      throw new Error(`${label}.${field} does not match the trusted execution binding`);
    }
  }
}

function activeGrantAuthenticationBasis(authentication) {
  return deepFreeze(Object.fromEntries(
    ACTIVE_GRANT_AUTHENTICATION_FIELDS.map((field) => [field, authentication[field]]),
  ));
}

function resolveAndAssertCurrentActiveGrant(payload, authentication, verifierState) {
  const resolverQuery = deepFreeze({
    version: ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION,
    domain: ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN,
    grant_kind: "active",
    key_usage: ACTIVE_PHYSICAL_EXECUTION_GRANT_KEY_USAGE,
    grant_ref: payload.grant_ref,
    session_id: payload.session_id,
    session_nucleus_hash: payload.session_nucleus_hash,
    execution_request_digest: payload.execution_request_digest,
  });
  const current = normalizeCurrentActiveGrantAuthority(
    verifierState.resolve_current_authority(resolverQuery),
  );
  const observed = readActiveGrantTrustedClock(verifierState);
  const axis = current.physical_scope_axis;
  assertExactActiveGrantBindings(payload, {
    session_id: current.session_id,
    session_nucleus_hash: current.session_nucleus_hash,
    execution_request_digest: current.execution_request_digest,
    physical_scope_axis_digest: axis.axis_digest,
    physical_scope_policy_id: axis.policy_id,
    physical_scope_policy_digest: axis.policy_digest,
    physical_scope_projection_digest: axis.projection_digest,
    authority_epoch: axis.authority_epoch,
    revocation_generation: axis.revocation_generation,
    authority_decision: current.authority_decision,
    authority_reason: current.authority_reason,
    authority_resolution_digest: current.authority_resolution_digest,
  }, [
    "session_id",
    "session_nucleus_hash",
    "execution_request_digest",
    "physical_scope_axis_digest",
    "physical_scope_policy_id",
    "physical_scope_policy_digest",
    "physical_scope_projection_digest",
    "authority_epoch",
    "revocation_generation",
    "authority_decision",
    "authority_reason",
    "authority_resolution_digest",
  ], "active_physical_execution_grant.current_authority");

  assertExactActiveGrantBindings(authentication, current, [
    "trust_root_id",
    "trust_root_epoch",
    "trust_registry_digest",
    "issuer_principal_id",
    "issuer_key_id",
    "issuer_epoch",
    "issuer_public_key_digest",
  ], "active_physical_execution_grant.current_trust");

  if (current.key_usage !== ACTIVE_PHYSICAL_EXECUTION_GRANT_KEY_USAGE) {
    throw new Error("active_physical_execution_grant.current_trust.key_usage is not authorized");
  }
  assertGrantVerifierTimestampNonFuture(
    observed,
    authentication.signed_at,
    "active_physical_execution_grant.authentication.signed_at",
    "active physical execution grant was signed in the future",
  );
  if (Date.parse(authentication.signed_at) >= Date.parse(payload.expires_at)) {
    throw new Error("active physical execution grant was signed after its authority window");
  }
  assertGrantVerifierValidityWindow(observed, payload, "active physical execution grant");
  return { current, observed, resolverQuery };
}

function buildActiveGrantReplayClaim(grant) {
  return normalizeActiveGrantReplayClaim({
    version: ACTIVE_GRANT_REPLAY_RESERVATION_VERSION,
    grant_ref: grant.payload.grant_ref,
    signed_grant_digest: grant.grant_envelope_digest,
    execution_request_digest: grant.payload.execution_request_digest,
    session_nucleus_hash: grant.payload.session_nucleus_hash,
    provider_descriptor_digest: grant.payload.provider_descriptor_digest,
    attempt_id: grant.payload.attempt_id,
    lease_id: grant.payload.lease_id,
    fencing_token_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-fencing-token/v1",
      fencing_token: grant.payload.fencing_token,
    }),
    fencing_generation: grant.payload.fencing_generation,
    expires_at: grant.payload.expires_at,
  });
}

function reserveActiveGrantReplay(verifierState, replayClaim) {
  try {
    return normalizeActiveGrantReplayReservationResult(
      verifierState.reserve_replay(replayClaim),
      replayClaim,
    );
  } catch (cause) {
    const error = new Error("active physical execution grant replay reservation failed closed");
    Object.defineProperty(error, "cause", { value: cause });
    throw error;
  }
}

function projectVerifiedActivePhysicalExecutionGrant(input, verifierInput, bindingsInput) {
  const verifier = assertActiveGrantVerifier(verifierInput);
  const verifierState = ACTIVE_GRANT_VERIFIER_STATE.get(verifier);
  const grant = normalizeSignedActivePhysicalExecutionGrant(input);
  const bindings = normalizeActiveGrantProjectionBindings(bindingsInput);
  const request = bindings.request;
  const authenticationBasis = activeGrantAuthenticationBasis(grant.authentication);
  const live = resolveAndAssertCurrentActiveGrant(
    grant.payload,
    authenticationBasis,
    verifierState,
  );
  const { current } = live;

  const signatureVerified = verifierState.verify_ed25519(deepFreeze({
    version: ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION,
    method: "ed25519",
    key_usage: ACTIVE_PHYSICAL_EXECUTION_GRANT_KEY_USAGE,
    signature_input_digest: grant.signature_input_digest,
    signature: grant.authentication.signature,
    trust_root_id: current.trust_root_id,
    trust_root_epoch: current.trust_root_epoch,
    trust_registry_digest: current.trust_registry_digest,
    issuer_principal_id: current.issuer_principal_id,
    issuer_key_id: current.issuer_key_id,
    issuer_epoch: current.issuer_epoch,
    issuer_public_key_digest: current.issuer_public_key_digest,
  }));
  if (signatureVerified !== true) {
    throw new Error("active physical execution grant Ed25519 signature verification failed");
  }

  assertExactActiveGrantBindings(grant.payload, {
    grant_kind: request.grant_kind,
    session_id: request.session_id,
    session_nucleus_hash: request.session_nucleus_hash,
    authority_epoch: request.authority_epoch,
    revocation_generation: request.revocation_generation,
    execution_request_digest: request.execution_request_digest,
    request_nonce: request.nonce,
    request_sequence: request.sequence,
    execution_principal_id: request.execution_principal_id,
    provider_id: bindings.provider_id,
    provider_descriptor_digest: bindings.provider_descriptor_digest,
    instrument_ref: request.instrument_ref,
    operation_id: request.operation_id,
    operation_digest: bindings.operation_digest,
    parameter_digest: request.parameter_digest,
    requested_effects_digest: request.requested_effects_digest,
    attempt_id: request.attempt_id,
    experiment_plan_hash: request.experiment_plan_hash,
    execution_lineage_digest: request.execution_lineage.execution_lineage_digest,
    resource_bundle_digest: request.resource_bundle_digest,
    lease_id: request.lease_id,
    fencing_token: request.fencing_token,
    fencing_generation: bindings.fencing_generation,
    workspace_snapshot_digest: request.workspace_snapshot_digest,
    cleanup_plan_digest: request.cleanup_plan_digest,
    not_before: request.not_before,
    expires_at: request.expires_at,
  }, [
    "grant_kind",
    "session_id",
    "session_nucleus_hash",
    "authority_epoch",
    "revocation_generation",
    "execution_request_digest",
    "request_nonce",
    "request_sequence",
    "execution_principal_id",
    "provider_id",
    "provider_descriptor_digest",
    "instrument_ref",
    "operation_id",
    "operation_digest",
    "parameter_digest",
    "requested_effects_digest",
    "attempt_id",
    "experiment_plan_hash",
    "execution_lineage_digest",
    "resource_bundle_digest",
    "lease_id",
    "fencing_token",
    "fencing_generation",
    "workspace_snapshot_digest",
    "cleanup_plan_digest",
    "not_before",
    "expires_at",
  ], "active_physical_execution_grant.execution_request");
  if (verifierState.projected_grant_refs.has(grant.payload.grant_ref)
      || verifierState.projected_execution_requests.has(grant.payload.execution_request_digest)) {
    throw new Error("active physical execution grant replay was rejected");
  }

  const replayClaim = buildActiveGrantReplayClaim(grant);
  const replayClaimDigest = hashCanonicalJson(replayClaim);
  const replayReservation = reserveActiveGrantReplay(verifierState, replayClaim);
  if (replayReservation.disposition !== "created") {
    throw new Error(
      "active physical execution grant existing replay reservation requires unavailable durable admission rehydration",
    );
  }
  const reservationReceipt = replayReservation.reservation_receipt;
  const reservationObserved = readActiveGrantTrustedClock(verifierState);
  assertGrantVerifierValidityWindow(
    reservationObserved,
    grant.payload,
    "active physical execution grant",
  );
  assertGrantVerifierTimestampNonFuture(
    reservationObserved,
    reservationReceipt.fsynced_at,
    "active_grant_replay_reservation.fsynced_at",
    "active physical execution grant replay reservation is outside its trusted effect window",
  );
  if (Date.parse(reservationReceipt.reserved_at) < Date.parse(grant.payload.not_before)
      || Date.parse(reservationReceipt.fsynced_at) >= Date.parse(grant.payload.expires_at)) {
    throw new Error("active physical execution grant replay reservation is outside its trusted effect window");
  }
  verifierState.projected_grant_refs.add(grant.payload.grant_ref);
  verifierState.projected_execution_requests.add(grant.payload.execution_request_digest);

  const projection = {
    ...grant.payload,
    signed_grant_digest: grant.grant_envelope_digest,
    grant_payload_digest: grant.grant_payload_digest,
    signed_at: grant.authentication.signed_at,
    ...projectGrantVerifierClock(reservationObserved),
    verified_trust_root_id: current.trust_root_id,
    verified_trust_root_epoch: current.trust_root_epoch,
    verified_trust_registry_digest: current.trust_registry_digest,
    verified_issuer_principal_id: current.issuer_principal_id,
    verified_issuer_key_id: current.issuer_key_id,
    verified_issuer_epoch: current.issuer_epoch,
    verified_issuer_public_key_digest: current.issuer_public_key_digest,
    signature_verifier_id: verifier.verifier_id,
    replay_claim_digest: replayClaimDigest,
    replay_reservation_ref: reservationReceipt.reservation_ref,
    replay_reservation_generation: reservationReceipt.generation,
    replay_reservation_receipt_digest: reservationReceipt.receipt_digest,
  };
  const verifiedProjection = deepFreeze({
    ...projection,
    projection_digest: hashCanonicalJson(projection),
  });
  VERIFIED_ACTIVE_GRANT_PROJECTIONS.add(verifiedProjection);
  VERIFIED_ACTIVE_GRANT_PROJECTION_STATE.set(verifiedProjection, Object.freeze({
    verifier,
    payload: grant.payload,
    authentication_basis: authenticationBasis,
    replay_reservation_receipt: reservationReceipt,
    trusted_clock_observation: reservationObserved,
  }));
  return verifiedProjection;
}

function assertVerifiedActivePhysicalExecutionGrant(input, verifierInput, expectedBindings) {
  const verifier = assertActiveGrantVerifier(verifierInput);
  const projectionState = input == null ? null : VERIFIED_ACTIVE_GRANT_PROJECTION_STATE.get(input);
  if (!input || !VERIFIED_ACTIVE_GRANT_PROJECTIONS.has(input)
      || !projectionState || projectionState.verifier !== verifier) {
    throw new Error("active physical execution grant projection was not issued by the configured verifier");
  }
  assertClosedObject(
    expectedBindings,
    "active_grant_expected_bindings",
    ACTIVE_GRANT_BROKER_BINDING_FIELDS,
  );
  assertExactActiveGrantBindings(
    input,
    expectedBindings,
    ACTIVE_GRANT_BROKER_BINDING_FIELDS,
    "active_physical_execution_grant.broker_binding",
  );
  resolveAndAssertCurrentActiveGrant(
    projectionState.payload,
    projectionState.authentication_basis,
    ACTIVE_GRANT_VERIFIER_STATE.get(verifier),
  );
  return input;
}

// Bootstrap grants use a distinct signature domain and key usage from active
// effects. They authorize only a pre-enrollment, read-only request and bind the
// exact provider implementation and transport facts that a provider-specific
// attenuator must independently confirm. Signature material and authority
// records never cross into the verified projection.
const BOOTSTRAP_GRANT_PAYLOAD_FIELDS = Object.freeze([
  "version",
  "grant_kind",
  "grant_ref",
  "session_id",
  "session_nucleus_hash",
  "physical_scope_axis_digest",
  "physical_scope_policy_id",
  "physical_scope_policy_digest",
  "physical_scope_projection_digest",
  "authority_epoch",
  "revocation_generation",
  "execution_request_digest",
  "request_nonce",
  "request_sequence",
  "caller_role_id",
  "requester_principal_id",
  "ipc_peer_principal_id",
  "execution_principal_id",
  "provider_id",
  "provider_descriptor_digest",
  "instrument_ref",
  "enrollment_candidate_ref",
  "bootstrap_manifest_digest",
  "provider_binary_digest",
  "transport_digest",
  "operation_id",
  "operation_digest",
  "parameter_digest",
  "requested_effects_digest",
  "bootstrap_invariants_digest",
  "rf_state",
  "authority_decision",
  "authority_reason",
  "authority_resolution_digest",
  "not_before",
  "expires_at",
]);

const BOOTSTRAP_GRANT_AUTHENTICATION_FIELDS = Object.freeze([
  "version",
  "method",
  "key_usage",
  "trust_root_id",
  "trust_root_epoch",
  "trust_registry_digest",
  "issuer_principal_id",
  "issuer_key_id",
  "issuer_epoch",
  "issuer_public_key_digest",
  "signed_at",
  "signed_payload_digest",
]);

const BOOTSTRAP_GRANT_ATTENUATION_BINDING_FIELDS = Object.freeze([
  "execution_request_digest",
  "provider_id",
  "provider_descriptor_digest",
  "bootstrap_manifest_digest",
  "provider_binary_digest",
  "transport_digest",
  "operation_id",
  "operation_digest",
  "bootstrap_invariants_digest",
]);

function normalizeBootstrapGrantPayload(input, label = "physical_bootstrap_grant.payload") {
  assertClosedObject(input, label, BOOTSTRAP_GRANT_PAYLOAD_FIELDS);
  if (input.version !== PHYSICAL_BOOTSTRAP_GRANT_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_BOOTSTRAP_GRANT_VERSION}`);
  }
  if (input.grant_kind !== "bootstrap") throw new Error(`${label}.grant_kind must be bootstrap`);
  const notBefore = assertCanonicalTimestamp(input.not_before, `${label}.not_before`);
  const expiresAt = assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(expiresAt) <= Date.parse(notBefore)) {
    throw new Error(`${label}.expires_at must be after ${label}.not_before`);
  }
  if (input.rf_state !== "off") throw new Error(`${label}.rf_state must be off`);
  return deepFreeze({
    version: PHYSICAL_BOOTSTRAP_GRANT_VERSION,
    grant_kind: "bootstrap",
    grant_ref: normalizeOpaqueRef(input.grant_ref, `${label}.grant_ref`, { prefix: "physical-grant" }),
    session_id: assertToken(input.session_id, `${label}.session_id`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    physical_scope_axis_digest: assertDigest(
      input.physical_scope_axis_digest,
      `${label}.physical_scope_axis_digest`,
    ),
    physical_scope_policy_id: assertIdentifier(
      input.physical_scope_policy_id,
      `${label}.physical_scope_policy_id`,
    ),
    physical_scope_policy_digest: assertDigest(
      input.physical_scope_policy_digest,
      `${label}.physical_scope_policy_digest`,
    ),
    physical_scope_projection_digest: assertDigest(
      input.physical_scope_projection_digest,
      `${label}.physical_scope_projection_digest`,
    ),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, { min: 1 }),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
      { min: 0 },
    ),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    request_nonce: assertToken(input.request_nonce, `${label}.request_nonce`),
    request_sequence: assertInteger(input.request_sequence, `${label}.request_sequence`, { min: 1 }),
    caller_role_id: assertIdentifier(input.caller_role_id, `${label}.caller_role_id`),
    requester_principal_id: normalizeOpaqueRef(
      input.requester_principal_id,
      `${label}.requester_principal_id`,
      { prefix: "principal" },
    ),
    ipc_peer_principal_id: normalizeOpaqueRef(
      input.ipc_peer_principal_id,
      `${label}.ipc_peer_principal_id`,
      { prefix: "principal" },
    ),
    execution_principal_id: normalizeOpaqueRef(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      { prefix: "principal" },
    ),
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    enrollment_candidate_ref: normalizeOpaqueRef(
      input.enrollment_candidate_ref,
      `${label}.enrollment_candidate_ref`,
      { prefix: "enrollment-candidate" },
    ),
    bootstrap_manifest_digest: assertDigest(
      input.bootstrap_manifest_digest,
      `${label}.bootstrap_manifest_digest`,
    ),
    provider_binary_digest: assertDigest(
      input.provider_binary_digest,
      `${label}.provider_binary_digest`,
    ),
    transport_digest: assertDigest(input.transport_digest, `${label}.transport_digest`),
    operation_id: assertIdentifier(input.operation_id, `${label}.operation_id`),
    operation_digest: assertDigest(input.operation_digest, `${label}.operation_digest`),
    parameter_digest: assertDigest(input.parameter_digest, `${label}.parameter_digest`),
    requested_effects_digest: assertDigest(
      input.requested_effects_digest,
      `${label}.requested_effects_digest`,
    ),
    bootstrap_invariants_digest: assertDigest(
      input.bootstrap_invariants_digest,
      `${label}.bootstrap_invariants_digest`,
    ),
    rf_state: "off",
    authority_decision: assertEnum(input.authority_decision, ["allow"], `${label}.authority_decision`),
    authority_reason: assertEnum(input.authority_reason, ["exact_allow"], `${label}.authority_reason`),
    authority_resolution_digest: assertDigest(
      input.authority_resolution_digest,
      `${label}.authority_resolution_digest`,
    ),
    not_before: notBefore,
    expires_at: expiresAt,
  });
}

function normalizeBootstrapGrantAuthenticationBasis(
  input,
  payloadDigest,
  label = "physical_bootstrap_grant.authentication",
) {
  assertClosedObject(input, label, BOOTSTRAP_GRANT_AUTHENTICATION_FIELDS);
  if (input.version !== PHYSICAL_BOOTSTRAP_GRANT_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_BOOTSTRAP_GRANT_VERSION}`);
  }
  if (input.method !== "ed25519") throw new Error(`${label}.method must be ed25519`);
  const normalized = {
    version: PHYSICAL_BOOTSTRAP_GRANT_VERSION,
    method: "ed25519",
    key_usage: assertEnum(
      input.key_usage,
      [PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE],
      `${label}.key_usage`,
    ),
    trust_root_id: normalizeOpaqueRef(input.trust_root_id, `${label}.trust_root_id`, {
      prefix: "trust-root",
    }),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, { min: 1 }),
    trust_registry_digest: assertDigest(input.trust_registry_digest, `${label}.trust_registry_digest`),
    issuer_principal_id: normalizeOpaqueRef(
      input.issuer_principal_id,
      `${label}.issuer_principal_id`,
      { prefix: "principal" },
    ),
    issuer_key_id: normalizeOpaqueRef(input.issuer_key_id, `${label}.issuer_key_id`, {
      prefix: "signer-key",
    }),
    issuer_epoch: assertInteger(input.issuer_epoch, `${label}.issuer_epoch`, { min: 1 }),
    issuer_public_key_digest: assertDigest(
      input.issuer_public_key_digest,
      `${label}.issuer_public_key_digest`,
    ),
    signed_at: assertCanonicalTimestamp(input.signed_at, `${label}.signed_at`),
    signed_payload_digest: assertDigest(input.signed_payload_digest, `${label}.signed_payload_digest`),
  };
  if (normalized.signed_payload_digest !== payloadDigest) {
    throw new Error(`${label}.signed_payload_digest does not bind the normalized grant payload`);
  }
  return deepFreeze(normalized);
}

function physicalBootstrapGrantSignatureInputDigest(payloadInput, authenticationInput) {
  const payload = normalizeBootstrapGrantPayload(payloadInput);
  const payloadDigest = hashCanonicalJson(payload);
  const authentication = normalizeBootstrapGrantAuthenticationBasis(authenticationInput, payloadDigest);
  return hashCanonicalJson({
    domain: PHYSICAL_BOOTSTRAP_GRANT_DOMAIN,
    version: PHYSICAL_BOOTSTRAP_GRANT_VERSION,
    kind: "physical_bootstrap_grant",
    payload,
    authentication,
  });
}

function normalizeSignedPhysicalBootstrapGrant(input, label = "physical_bootstrap_grant") {
  assertClosedObject(
    input,
    label,
    ["version", "kind", "domain", "payload", "authentication"],
    ["grant_envelope_digest"],
  );
  if (input.version !== PHYSICAL_BOOTSTRAP_GRANT_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_BOOTSTRAP_GRANT_VERSION}`);
  }
  if (input.kind !== "physical_bootstrap_grant") {
    throw new Error(`${label}.kind must be physical_bootstrap_grant`);
  }
  if (input.domain !== PHYSICAL_BOOTSTRAP_GRANT_DOMAIN) {
    throw new Error(`${label}.domain does not match the physical bootstrap grant signature domain`);
  }
  const payload = normalizeBootstrapGrantPayload(input.payload, `${label}.payload`);
  const grantPayloadDigest = hashCanonicalJson(payload);
  assertClosedObject(
    input.authentication,
    `${label}.authentication`,
    [...BOOTSTRAP_GRANT_AUTHENTICATION_FIELDS, "signature"],
  );
  const authenticationBasis = normalizeBootstrapGrantAuthenticationBasis(
    Object.fromEntries(
      BOOTSTRAP_GRANT_AUTHENTICATION_FIELDS.map((field) => [field, input.authentication[field]]),
    ),
    grantPayloadDigest,
    `${label}.authentication`,
  );
  const signature = assertCanonicalEd25519Signature(
    input.authentication.signature,
    `${label}.authentication.signature`,
  );
  const signatureInputDigest = physicalBootstrapGrantSignatureInputDigest(payload, authenticationBasis);
  const authentication = deepFreeze({ ...authenticationBasis, signature });
  const signedEnvelope = {
    version: PHYSICAL_BOOTSTRAP_GRANT_VERSION,
    kind: "physical_bootstrap_grant",
    domain: PHYSICAL_BOOTSTRAP_GRANT_DOMAIN,
    payload,
    authentication,
  };
  const grantEnvelopeDigest = hashCanonicalJson(signedEnvelope);
  assertDerivedDigest(input, "grant_envelope_digest", grantEnvelopeDigest, label);
  return deepFreeze({
    ...signedEnvelope,
    grant_payload_digest: grantPayloadDigest,
    signature_input_digest: signatureInputDigest,
    grant_envelope_digest: grantEnvelopeDigest,
  });
}

const CURRENT_BOOTSTRAP_AUTHORITY_OPERATION_FIELDS = Object.freeze([
  "caller_role_id",
  "requester_principal_id",
  "ipc_peer_principal_id",
  "execution_principal_id",
  "provider_id",
  "provider_descriptor_digest",
  "instrument_ref",
  "enrollment_candidate_ref",
  "bootstrap_manifest_digest",
  "provider_binary_digest",
  "transport_digest",
  "operation_id",
  "operation_digest",
  "parameter_digest",
  "requested_effects_digest",
  "bootstrap_invariants_digest",
]);

function normalizeCurrentPhysicalBootstrapGrantAuthority(
  input,
  label = "current_physical_bootstrap_grant_authority",
) {
  assertClosedObject(input, label, [
    "version",
    "session_id",
    "session_nucleus_hash",
    "execution_request_digest",
    "physical_scope_axis",
    ...CURRENT_BOOTSTRAP_AUTHORITY_OPERATION_FIELDS,
    "authority_decision",
    "authority_reason",
    "authority_resolution_digest",
    "trust_root_id",
    "trust_root_epoch",
    "trust_registry_digest",
    "trust_root_trusted",
    "trust_root_revoked",
    "issuer_principal_id",
    "issuer_key_id",
    "issuer_epoch",
    "issuer_public_key_digest",
    "key_usage",
    "issuer_trusted",
    "issuer_revoked",
  ]);
  if (input.version !== PHYSICAL_BOOTSTRAP_GRANT_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_BOOTSTRAP_GRANT_VERSION}`);
  }
  const trustRootTrusted = assertBoolean(input.trust_root_trusted, `${label}.trust_root_trusted`);
  const trustRootRevoked = assertBoolean(input.trust_root_revoked, `${label}.trust_root_revoked`);
  const issuerTrusted = assertBoolean(input.issuer_trusted, `${label}.issuer_trusted`);
  const issuerRevoked = assertBoolean(input.issuer_revoked, `${label}.issuer_revoked`);
  if (!trustRootTrusted || trustRootRevoked) throw new Error(`${label} trust root is not currently usable`);
  if (!issuerTrusted || issuerRevoked) throw new Error(`${label} issuer is not currently usable`);
  return deepFreeze({
    version: PHYSICAL_BOOTSTRAP_GRANT_VERSION,
    session_id: assertToken(input.session_id, `${label}.session_id`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    physical_scope_axis: normalizePhysicalScopeNucleusAxis(input.physical_scope_axis),
    caller_role_id: assertIdentifier(input.caller_role_id, `${label}.caller_role_id`),
    requester_principal_id: normalizeOpaqueRef(
      input.requester_principal_id,
      `${label}.requester_principal_id`,
      { prefix: "principal" },
    ),
    ipc_peer_principal_id: normalizeOpaqueRef(
      input.ipc_peer_principal_id,
      `${label}.ipc_peer_principal_id`,
      { prefix: "principal" },
    ),
    execution_principal_id: normalizeOpaqueRef(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      { prefix: "principal" },
    ),
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    enrollment_candidate_ref: normalizeOpaqueRef(
      input.enrollment_candidate_ref,
      `${label}.enrollment_candidate_ref`,
      { prefix: "enrollment-candidate" },
    ),
    bootstrap_manifest_digest: assertDigest(
      input.bootstrap_manifest_digest,
      `${label}.bootstrap_manifest_digest`,
    ),
    provider_binary_digest: assertDigest(
      input.provider_binary_digest,
      `${label}.provider_binary_digest`,
    ),
    transport_digest: assertDigest(input.transport_digest, `${label}.transport_digest`),
    operation_id: assertIdentifier(input.operation_id, `${label}.operation_id`),
    operation_digest: assertDigest(input.operation_digest, `${label}.operation_digest`),
    parameter_digest: assertDigest(input.parameter_digest, `${label}.parameter_digest`),
    requested_effects_digest: assertDigest(
      input.requested_effects_digest,
      `${label}.requested_effects_digest`,
    ),
    bootstrap_invariants_digest: assertDigest(
      input.bootstrap_invariants_digest,
      `${label}.bootstrap_invariants_digest`,
    ),
    authority_decision: assertEnum(input.authority_decision, ["allow"], `${label}.authority_decision`),
    authority_reason: assertEnum(input.authority_reason, ["exact_allow"], `${label}.authority_reason`),
    authority_resolution_digest: assertDigest(
      input.authority_resolution_digest,
      `${label}.authority_resolution_digest`,
    ),
    trust_root_id: normalizeOpaqueRef(input.trust_root_id, `${label}.trust_root_id`, {
      prefix: "trust-root",
    }),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, { min: 1 }),
    trust_registry_digest: assertDigest(input.trust_registry_digest, `${label}.trust_registry_digest`),
    trust_root_trusted: true,
    trust_root_revoked: false,
    issuer_principal_id: normalizeOpaqueRef(
      input.issuer_principal_id,
      `${label}.issuer_principal_id`,
      { prefix: "principal" },
    ),
    issuer_key_id: normalizeOpaqueRef(input.issuer_key_id, `${label}.issuer_key_id`, {
      prefix: "signer-key",
    }),
    issuer_epoch: assertInteger(input.issuer_epoch, `${label}.issuer_epoch`, { min: 1 }),
    issuer_public_key_digest: assertDigest(
      input.issuer_public_key_digest,
      `${label}.issuer_public_key_digest`,
    ),
    key_usage: assertEnum(input.key_usage, [PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE], `${label}.key_usage`),
    issuer_trusted: true,
    issuer_revoked: false,
  });
}

function createPhysicalBootstrapGrantVerifier(input) {
  assertClosedObject(input, "physical_bootstrap_grant_verifier", [
    "verifier_id",
    "resolve_current_authority",
    "verify_ed25519",
    "reserve_replay",
  ], ["trusted_clock_port", "trusted_now"]);
  for (const field of ["resolve_current_authority", "verify_ed25519", "reserve_replay"]) {
    if (typeof input[field] !== "function") {
      throw new Error(`physical_bootstrap_grant_verifier.${field} must be a function`);
    }
  }
  const clock = normalizeGrantVerifierClock(input, "physical_bootstrap_grant_verifier");
  const verifier = Object.freeze({
    version: PHYSICAL_BOOTSTRAP_GRANT_VERSION,
    verifier_id: assertIdentifier(input.verifier_id, "physical_bootstrap_grant_verifier.verifier_id"),
    trusted_clock_mode: clock.mode,
    trusted_clock_port_id: clock.trusted_clock_port == null
      ? null
      : clock.trusted_clock_port.port_id,
  });
  BOOTSTRAP_GRANT_VERIFIERS.add(verifier);
  BOOTSTRAP_GRANT_VERIFIER_STATE.set(verifier, {
    trusted_clock_mode: clock.mode,
    trusted_clock_port: clock.trusted_clock_port,
    trusted_now: clock.trusted_now,
    resolve_current_authority: input.resolve_current_authority,
    verify_ed25519: input.verify_ed25519,
    reserve_replay: input.reserve_replay,
    last_trusted_now_ms: null,
    last_trusted_clock_observation: null,
    projected_grant_refs: new Set(),
    projected_execution_requests: new Set(),
  });
  return verifier;
}

function assertPhysicalBootstrapGrantVerifier(input) {
  if (!input || !BOOTSTRAP_GRANT_VERIFIERS.has(input)
      || !BOOTSTRAP_GRANT_VERIFIER_STATE.has(input)) {
    throw new Error("physical bootstrap grant verifier must be a configured Bob verifier");
  }
  return input;
}

function readBootstrapGrantTrustedClock(verifierState) {
  return readGrantVerifierClock(
    verifierState,
    "trusted clock moved backwards while verifying a physical bootstrap grant",
  );
}

function assertExactBootstrapGrantBindings(actual, expected, fields, label) {
  for (const field of fields) {
    if (actual[field] !== expected[field]) {
      throw new Error(`${label}.${field} does not match the trusted bootstrap binding`);
    }
  }
}

function bootstrapGrantAuthenticationBasis(authentication) {
  return deepFreeze(Object.fromEntries(
    BOOTSTRAP_GRANT_AUTHENTICATION_FIELDS.map((field) => [field, authentication[field]]),
  ));
}

function resolveAndAssertCurrentBootstrapGrant(payload, authentication, verifierState) {
  const resolverQuery = deepFreeze({
    version: PHYSICAL_BOOTSTRAP_GRANT_VERSION,
    domain: PHYSICAL_BOOTSTRAP_GRANT_DOMAIN,
    grant_kind: "bootstrap",
    key_usage: PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE,
    grant_ref: payload.grant_ref,
    session_id: payload.session_id,
    session_nucleus_hash: payload.session_nucleus_hash,
    execution_request_digest: payload.execution_request_digest,
    provider_id: payload.provider_id,
    provider_descriptor_digest: payload.provider_descriptor_digest,
    bootstrap_manifest_digest: payload.bootstrap_manifest_digest,
    provider_binary_digest: payload.provider_binary_digest,
    transport_digest: payload.transport_digest,
    operation_id: payload.operation_id,
    operation_digest: payload.operation_digest,
    bootstrap_invariants_digest: payload.bootstrap_invariants_digest,
  });
  const current = normalizeCurrentPhysicalBootstrapGrantAuthority(
    verifierState.resolve_current_authority(resolverQuery),
  );
  const observed = readBootstrapGrantTrustedClock(verifierState);
  const axis = current.physical_scope_axis;
  assertExactBootstrapGrantBindings(payload, {
    session_id: current.session_id,
    session_nucleus_hash: current.session_nucleus_hash,
    execution_request_digest: current.execution_request_digest,
    physical_scope_axis_digest: axis.axis_digest,
    physical_scope_policy_id: axis.policy_id,
    physical_scope_policy_digest: axis.policy_digest,
    physical_scope_projection_digest: axis.projection_digest,
    authority_epoch: axis.authority_epoch,
    revocation_generation: axis.revocation_generation,
    authority_decision: current.authority_decision,
    authority_reason: current.authority_reason,
    authority_resolution_digest: current.authority_resolution_digest,
    ...Object.fromEntries(
      CURRENT_BOOTSTRAP_AUTHORITY_OPERATION_FIELDS.map((field) => [field, current[field]]),
    ),
  }, [
    "session_id",
    "session_nucleus_hash",
    "execution_request_digest",
    "physical_scope_axis_digest",
    "physical_scope_policy_id",
    "physical_scope_policy_digest",
    "physical_scope_projection_digest",
    "authority_epoch",
    "revocation_generation",
    ...CURRENT_BOOTSTRAP_AUTHORITY_OPERATION_FIELDS,
    "authority_decision",
    "authority_reason",
    "authority_resolution_digest",
  ], "physical_bootstrap_grant.current_authority");
  assertExactBootstrapGrantBindings(authentication, current, [
    "key_usage",
    "trust_root_id",
    "trust_root_epoch",
    "trust_registry_digest",
    "issuer_principal_id",
    "issuer_key_id",
    "issuer_epoch",
    "issuer_public_key_digest",
  ], "physical_bootstrap_grant.current_trust");
  assertGrantVerifierTimestampNonFuture(
    observed,
    authentication.signed_at,
    "physical_bootstrap_grant.authentication.signed_at",
    "physical bootstrap grant was signed in the future",
  );
  if (Date.parse(authentication.signed_at) >= Date.parse(payload.expires_at)) {
    throw new Error("physical bootstrap grant was signed after its authority window");
  }
  assertGrantVerifierValidityWindow(observed, payload, "physical bootstrap grant");
  return { current, observed, resolverQuery };
}

function normalizeBootstrapGrantProjectionBindings(input) {
  assertClosedObject(input, "bootstrap_grant_projection_bindings", [
    "execution_request",
    "effect_registry",
    "provider_id",
    "provider_descriptor_digest",
    "operation_digest",
    "bootstrap_invariants_digest",
  ]);
  const request = normalizeMcpPhysicalExecutionRequest(input.execution_request, input.effect_registry, {
    label: "bootstrap_grant_projection_bindings.execution_request",
  });
  if (request.grant_kind !== "bootstrap") {
    throw new Error("bootstrap grant projection requires a bootstrap physical execution request");
  }
  return deepFreeze({
    request,
    provider_id: assertIdentifier(input.provider_id, "bootstrap_grant_projection_bindings.provider_id"),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      "bootstrap_grant_projection_bindings.provider_descriptor_digest",
    ),
    operation_digest: assertDigest(
      input.operation_digest,
      "bootstrap_grant_projection_bindings.operation_digest",
    ),
    bootstrap_invariants_digest: assertDigest(
      input.bootstrap_invariants_digest,
      "bootstrap_grant_projection_bindings.bootstrap_invariants_digest",
    ),
  });
}

function normalizeBootstrapGrantReplayClaim(input, label = "bootstrap_grant_replay_claim") {
  assertClosedObject(input, label, [
    "version",
    "grant_ref",
    "signed_grant_digest",
    "execution_request_digest",
    "session_nucleus_hash",
    "provider_id",
    "provider_descriptor_digest",
    "bootstrap_manifest_digest",
    "provider_binary_digest",
    "transport_digest",
    "operation_id",
    "operation_digest",
    "bootstrap_invariants_digest",
    "instrument_ref",
    "enrollment_candidate_ref",
    "request_nonce",
    "request_sequence",
    "expires_at",
  ]);
  if (input.version !== BOOTSTRAP_GRANT_REPLAY_RESERVATION_VERSION) {
    throw new Error(`${label}.version must be ${BOOTSTRAP_GRANT_REPLAY_RESERVATION_VERSION}`);
  }
  return deepFreeze({
    version: BOOTSTRAP_GRANT_REPLAY_RESERVATION_VERSION,
    grant_ref: normalizeOpaqueRef(input.grant_ref, `${label}.grant_ref`, { prefix: "physical-grant" }),
    signed_grant_digest: assertDigest(input.signed_grant_digest, `${label}.signed_grant_digest`),
    execution_request_digest: assertDigest(
      input.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    bootstrap_manifest_digest: assertDigest(
      input.bootstrap_manifest_digest,
      `${label}.bootstrap_manifest_digest`,
    ),
    provider_binary_digest: assertDigest(
      input.provider_binary_digest,
      `${label}.provider_binary_digest`,
    ),
    transport_digest: assertDigest(input.transport_digest, `${label}.transport_digest`),
    operation_id: assertIdentifier(input.operation_id, `${label}.operation_id`),
    operation_digest: assertDigest(input.operation_digest, `${label}.operation_digest`),
    bootstrap_invariants_digest: assertDigest(
      input.bootstrap_invariants_digest,
      `${label}.bootstrap_invariants_digest`,
    ),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    enrollment_candidate_ref: normalizeOpaqueRef(
      input.enrollment_candidate_ref,
      `${label}.enrollment_candidate_ref`,
      { prefix: "enrollment-candidate" },
    ),
    request_nonce: assertToken(input.request_nonce, `${label}.request_nonce`),
    request_sequence: assertInteger(input.request_sequence, `${label}.request_sequence`, { min: 1 }),
    expires_at: assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`),
  });
}

function normalizeBootstrapGrantReplayReservationResult(
  input,
  expectedClaim,
  label = "bootstrap_grant_replay_reservation",
) {
  assertClosedObject(input, label, ["version", "disposition", "reservation_receipt"]);
  if (input.version !== BOOTSTRAP_GRANT_REPLAY_RESERVATION_VERSION) {
    throw new Error(`${label}.version must be ${BOOTSTRAP_GRANT_REPLAY_RESERVATION_VERSION}`);
  }
  const disposition = assertEnum(
    input.disposition,
    BOOTSTRAP_GRANT_REPLAY_RESERVATION_DISPOSITIONS,
    `${label}.disposition`,
  );
  const receiptInput = input.reservation_receipt;
  assertClosedObject(receiptInput, `${label}.reservation_receipt`, [
    "version",
    "reservation_ref",
    "replay_claim",
    "replay_claim_digest",
    "generation",
    "previous_receipt_digest",
    "reserved_at",
    "fsynced_at",
  ], ["receipt_digest"]);
  if (receiptInput.version !== BOOTSTRAP_GRANT_REPLAY_RESERVATION_VERSION) {
    throw new Error(
      `${label}.reservation_receipt.version must be ${BOOTSTRAP_GRANT_REPLAY_RESERVATION_VERSION}`,
    );
  }
  const replayClaim = normalizeBootstrapGrantReplayClaim(
    receiptInput.replay_claim,
    `${label}.reservation_receipt.replay_claim`,
  );
  if (hashCanonicalJson(replayClaim) !== hashCanonicalJson(expectedClaim)) {
    throw new Error(`${label}.reservation_receipt replay claim does not match the verified grant`);
  }
  const replayClaimDigest = hashCanonicalJson(replayClaim);
  if (assertDigest(
    receiptInput.replay_claim_digest,
    `${label}.reservation_receipt.replay_claim_digest`,
  ) !== replayClaimDigest) {
    throw new Error(`${label}.reservation_receipt.replay_claim_digest does not match its claim`);
  }
  const reservedAt = assertCanonicalTimestamp(
    receiptInput.reserved_at,
    `${label}.reservation_receipt.reserved_at`,
  );
  const fsyncedAt = assertCanonicalTimestamp(
    receiptInput.fsynced_at,
    `${label}.reservation_receipt.fsynced_at`,
  );
  if (Date.parse(fsyncedAt) < Date.parse(reservedAt)) {
    throw new Error(`${label}.reservation_receipt.fsynced_at must not precede reserved_at`);
  }
  const generation = assertInteger(
    receiptInput.generation,
    `${label}.reservation_receipt.generation`,
    { min: 1 },
  );
  const previousReceiptDigest = receiptInput.previous_receipt_digest == null
    ? null
    : assertDigest(
      receiptInput.previous_receipt_digest,
      `${label}.reservation_receipt.previous_receipt_digest`,
    );
  if (generation === 1 && previousReceiptDigest !== null) {
    throw new Error(`${label}.reservation_receipt generation 1 cannot have a previous receipt`);
  }
  if (generation > 1 && previousReceiptDigest === null) {
    throw new Error(`${label}.reservation_receipt generation >1 requires a previous receipt`);
  }
  const receipt = {
    version: BOOTSTRAP_GRANT_REPLAY_RESERVATION_VERSION,
    reservation_ref: normalizeOpaqueRef(
      receiptInput.reservation_ref,
      `${label}.reservation_receipt.reservation_ref`,
      { prefix: "bootstrap-grant-replay-reservation" },
    ),
    replay_claim: replayClaim,
    replay_claim_digest: replayClaimDigest,
    generation,
    previous_receipt_digest: previousReceiptDigest,
    reserved_at: reservedAt,
    fsynced_at: fsyncedAt,
  };
  const receiptDigest = hashCanonicalJson(receipt);
  assertDerivedDigest(receiptInput, "receipt_digest", receiptDigest, `${label}.reservation_receipt`);
  return deepFreeze({
    version: BOOTSTRAP_GRANT_REPLAY_RESERVATION_VERSION,
    disposition,
    reservation_receipt: deepFreeze({ ...receipt, receipt_digest: receiptDigest }),
  });
}

function buildBootstrapGrantReplayClaim(grant) {
  return normalizeBootstrapGrantReplayClaim({
    version: BOOTSTRAP_GRANT_REPLAY_RESERVATION_VERSION,
    grant_ref: grant.payload.grant_ref,
    signed_grant_digest: grant.grant_envelope_digest,
    execution_request_digest: grant.payload.execution_request_digest,
    session_nucleus_hash: grant.payload.session_nucleus_hash,
    provider_id: grant.payload.provider_id,
    provider_descriptor_digest: grant.payload.provider_descriptor_digest,
    bootstrap_manifest_digest: grant.payload.bootstrap_manifest_digest,
    provider_binary_digest: grant.payload.provider_binary_digest,
    transport_digest: grant.payload.transport_digest,
    operation_id: grant.payload.operation_id,
    operation_digest: grant.payload.operation_digest,
    bootstrap_invariants_digest: grant.payload.bootstrap_invariants_digest,
    instrument_ref: grant.payload.instrument_ref,
    enrollment_candidate_ref: grant.payload.enrollment_candidate_ref,
    request_nonce: grant.payload.request_nonce,
    request_sequence: grant.payload.request_sequence,
    expires_at: grant.payload.expires_at,
  });
}

function reserveBootstrapGrantReplay(verifierState, replayClaim) {
  try {
    return normalizeBootstrapGrantReplayReservationResult(
      verifierState.reserve_replay(replayClaim),
      replayClaim,
    );
  } catch (cause) {
    const error = new Error("physical bootstrap grant replay reservation failed closed");
    Object.defineProperty(error, "cause", { value: cause });
    throw error;
  }
}

function projectVerifiedPhysicalBootstrapGrant(input, verifierInput, bindingsInput) {
  const verifier = assertPhysicalBootstrapGrantVerifier(verifierInput);
  const verifierState = BOOTSTRAP_GRANT_VERIFIER_STATE.get(verifier);
  const grant = normalizeSignedPhysicalBootstrapGrant(input);
  const bindings = normalizeBootstrapGrantProjectionBindings(bindingsInput);
  const request = bindings.request;
  const authenticationBasis = bootstrapGrantAuthenticationBasis(grant.authentication);
  const live = resolveAndAssertCurrentBootstrapGrant(grant.payload, authenticationBasis, verifierState);
  const { current } = live;
  const signatureVerified = verifierState.verify_ed25519(deepFreeze({
    version: PHYSICAL_BOOTSTRAP_GRANT_VERSION,
    method: "ed25519",
    key_usage: PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE,
    signature_input_digest: grant.signature_input_digest,
    signature: grant.authentication.signature,
    trust_root_id: current.trust_root_id,
    trust_root_epoch: current.trust_root_epoch,
    trust_registry_digest: current.trust_registry_digest,
    issuer_principal_id: current.issuer_principal_id,
    issuer_key_id: current.issuer_key_id,
    issuer_epoch: current.issuer_epoch,
    issuer_public_key_digest: current.issuer_public_key_digest,
  }));
  if (signatureVerified !== true) {
    throw new Error("physical bootstrap grant Ed25519 signature verification failed");
  }
  assertExactBootstrapGrantBindings(grant.payload, {
    grant_kind: request.grant_kind,
    session_id: request.session_id,
    session_nucleus_hash: request.session_nucleus_hash,
    authority_epoch: request.authority_epoch,
    revocation_generation: request.revocation_generation,
    execution_request_digest: request.execution_request_digest,
    request_nonce: request.nonce,
    request_sequence: request.sequence,
    caller_role_id: request.caller_role_id,
    requester_principal_id: request.requester_principal_id,
    ipc_peer_principal_id: request.ipc_peer_principal_id,
    execution_principal_id: request.execution_principal_id,
    provider_id: bindings.provider_id,
    provider_descriptor_digest: bindings.provider_descriptor_digest,
    instrument_ref: request.instrument_ref,
    enrollment_candidate_ref: request.enrollment_candidate_ref,
    bootstrap_manifest_digest: request.bootstrap_manifest_digest,
    provider_binary_digest: request.provider_binary_digest,
    transport_digest: request.transport_digest,
    operation_id: request.operation_id,
    operation_digest: bindings.operation_digest,
    parameter_digest: request.parameter_digest,
    requested_effects_digest: request.requested_effects_digest,
    bootstrap_invariants_digest: bindings.bootstrap_invariants_digest,
    rf_state: request.rf_state,
    not_before: request.not_before,
    expires_at: request.expires_at,
  }, [
    "grant_kind",
    "session_id",
    "session_nucleus_hash",
    "authority_epoch",
    "revocation_generation",
    "execution_request_digest",
    "request_nonce",
    "request_sequence",
    "caller_role_id",
    "requester_principal_id",
    "ipc_peer_principal_id",
    "execution_principal_id",
    "provider_id",
    "provider_descriptor_digest",
    "instrument_ref",
    "enrollment_candidate_ref",
    "bootstrap_manifest_digest",
    "provider_binary_digest",
    "transport_digest",
    "operation_id",
    "operation_digest",
    "parameter_digest",
    "requested_effects_digest",
    "bootstrap_invariants_digest",
    "rf_state",
    "not_before",
    "expires_at",
  ], "physical_bootstrap_grant.execution_request");
  if (verifierState.projected_grant_refs.has(grant.payload.grant_ref)
      || verifierState.projected_execution_requests.has(grant.payload.execution_request_digest)) {
    throw new Error("physical bootstrap grant replay was rejected");
  }
  const replayClaim = buildBootstrapGrantReplayClaim(grant);
  const replayClaimDigest = hashCanonicalJson(replayClaim);
  const replayReservation = reserveBootstrapGrantReplay(verifierState, replayClaim);
  if (replayReservation.disposition !== "created") {
    throw new Error(
      "physical bootstrap grant existing replay reservation requires unavailable durable admission rehydration",
    );
  }
  const reservationReceipt = replayReservation.reservation_receipt;
  const reservationObserved = readBootstrapGrantTrustedClock(verifierState);
  assertGrantVerifierValidityWindow(
    reservationObserved,
    grant.payload,
    "physical bootstrap grant",
  );
  assertGrantVerifierTimestampNonFuture(
    reservationObserved,
    reservationReceipt.fsynced_at,
    "bootstrap_grant_replay_reservation.fsynced_at",
    "physical bootstrap grant replay reservation is outside its trusted effect window",
  );
  if (Date.parse(reservationReceipt.reserved_at) < Date.parse(grant.payload.not_before)
      || Date.parse(reservationReceipt.reserved_at) < Date.parse(grant.authentication.signed_at)
      || Date.parse(reservationReceipt.fsynced_at) >= Date.parse(grant.payload.expires_at)) {
    throw new Error("physical bootstrap grant replay reservation is outside its trusted effect window");
  }
  verifierState.projected_grant_refs.add(grant.payload.grant_ref);
  verifierState.projected_execution_requests.add(grant.payload.execution_request_digest);
  const projection = {
    ...grant.payload,
    request_path: request.request_path,
    requested_effects: request.requested_effects,
    signed_grant_digest: grant.grant_envelope_digest,
    grant_payload_digest: grant.grant_payload_digest,
    signed_at: grant.authentication.signed_at,
    ...projectGrantVerifierClock(reservationObserved),
    verified_trust_root_id: current.trust_root_id,
    verified_trust_root_epoch: current.trust_root_epoch,
    verified_trust_registry_digest: current.trust_registry_digest,
    verified_issuer_principal_id: current.issuer_principal_id,
    verified_issuer_key_id: current.issuer_key_id,
    verified_issuer_epoch: current.issuer_epoch,
    verified_issuer_public_key_digest: current.issuer_public_key_digest,
    signature_verifier_id: verifier.verifier_id,
    replay_claim_digest: replayClaimDigest,
    replay_reservation_ref: reservationReceipt.reservation_ref,
    replay_reservation_generation: reservationReceipt.generation,
    replay_reservation_receipt_digest: reservationReceipt.receipt_digest,
  };
  const verifiedProjection = deepFreeze({
    ...projection,
    projection_digest: hashCanonicalJson(projection),
  });
  VERIFIED_BOOTSTRAP_GRANT_PROJECTIONS.add(verifiedProjection);
  VERIFIED_BOOTSTRAP_GRANT_PROJECTION_STATE.set(verifiedProjection, Object.freeze({
    verifier,
    payload: grant.payload,
    authentication_basis: authenticationBasis,
    replay_reservation_receipt: reservationReceipt,
    trusted_clock_observation: reservationObserved,
  }));
  return verifiedProjection;
}

function assertVerifiedPhysicalBootstrapGrant(input, verifierInput, expectedBindings) {
  const verifier = assertPhysicalBootstrapGrantVerifier(verifierInput);
  const projectionState = input == null ? null : VERIFIED_BOOTSTRAP_GRANT_PROJECTION_STATE.get(input);
  if (!input || !VERIFIED_BOOTSTRAP_GRANT_PROJECTIONS.has(input)
      || !projectionState || projectionState.verifier !== verifier) {
    throw new Error("physical bootstrap grant projection was not issued by the configured verifier");
  }
  assertClosedObject(
    expectedBindings,
    "physical_bootstrap_grant_expected_bindings",
    BOOTSTRAP_GRANT_ATTENUATION_BINDING_FIELDS,
  );
  assertExactBootstrapGrantBindings(
    input,
    expectedBindings,
    BOOTSTRAP_GRANT_ATTENUATION_BINDING_FIELDS,
    "physical_bootstrap_grant.attenuation_binding",
  );
  resolveAndAssertCurrentBootstrapGrant(
    projectionState.payload,
    projectionState.authentication_basis,
    BOOTSTRAP_GRANT_VERIFIER_STATE.get(verifier),
  );
  return input;
}

function normalizeStringEnumSet(value, values, label) {
  if (!Array.isArray(value) || value.length === 0) throw new Error(`${label} must be a non-empty array`);
  const normalized = value.map((entry, index) => assertEnum(entry, values, `${label}[${index}]`));
  const sorted = [...new Set(normalized)].sort();
  if (sorted.length !== normalized.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze(sorted);
}

function assertCleanupEffects(effects, instrumentRef, label) {
  for (let index = 0; index < effects.length; index += 1) {
    const effect = effects[index];
    const effectLabel = `${label}[${index}]`;
    assertInstrumentSubject(effect, instrumentRef, effectLabel);
    if (
      !["observe", "configure"].includes(effect.action)
      || ["administer", "destroy"].includes(effect.action)
      || effect.persistence === "irreversible"
      || effect.channel === "rf"
    ) {
      throw new Error(`${effectLabel} exceeds the precommitted local snapshot/restore surface`);
    }
  }
}

const CLEANUP_CAPABILITY_FIELDS = Object.freeze([
  "version",
  "capability_kind",
  "root_kind",
  "nondelegable",
  "agent_requestable",
  "safety_root_ref",
  "source_execution_request_digest",
  "session_id",
  "instrument_ref",
  "recovery_principal_id",
  "lease_id",
  "fencing_token",
  "workspace_snapshot_ref",
  "workspace_snapshot_digest",
  "restore_operation_id",
  "restore_operation_digest",
  "cleanup_plan_digest",
  "terminal_emission_state",
  "allowed_terminal_states",
  "capability_nonce",
  "requested_effects",
]);

const CLEANUP_CAPABILITY_DERIVED_FIELDS = Object.freeze([
  "requested_effects_digest",
  "capability_digest",
]);

function normalizeCleanupCapability(input, registry, label = "cleanup_capability") {
  assertClosedObject(
    input,
    label,
    CLEANUP_CAPABILITY_FIELDS,
    CLEANUP_CAPABILITY_DERIVED_FIELDS,
  );
  if (input.version !== CLEANUP_CAPABILITY_VERSION) {
    throw new Error(`${label}.version must be ${CLEANUP_CAPABILITY_VERSION}`);
  }
  if (input.capability_kind !== "cleanup") throw new Error(`${label}.capability_kind must be cleanup`);
  if (input.root_kind !== "cleanup_safety") throw new Error(`${label}.root_kind must be cleanup_safety`);
  if (input.nondelegable !== true) throw new Error(`${label}.nondelegable must be true`);
  if (input.agent_requestable !== false) throw new Error(`${label}.agent_requestable must be false`);
  if (input.terminal_emission_state !== "inhibited") {
    throw new Error(`${label}.terminal_emission_state must be inhibited`);
  }

  const instrumentRef = normalizeOpaqueRef(
    input.instrument_ref,
    `${label}.instrument_ref`,
    { prefix: "instrument" },
  );
  const effects = normalizeRequestedEffectSet(input.requested_effects, registry, `${label}.requested_effects`);
  assertCleanupEffects(effects, instrumentRef, `${label}.requested_effects`);
  const requestedEffectsDigest = hashCanonicalJson(effects);
  assertDerivedDigest(input, "requested_effects_digest", requestedEffectsDigest, label);

  const normalized = {
    version: CLEANUP_CAPABILITY_VERSION,
    capability_kind: "cleanup",
    root_kind: "cleanup_safety",
    nondelegable: true,
    agent_requestable: false,
    safety_root_ref: normalizeOpaqueRef(input.safety_root_ref, `${label}.safety_root_ref`, { prefix: "safety-root" }),
    source_execution_request_digest: assertDigest(
      input.source_execution_request_digest,
      `${label}.source_execution_request_digest`,
    ),
    session_id: assertToken(input.session_id, `${label}.session_id`),
    instrument_ref: instrumentRef,
    recovery_principal_id: normalizeOpaqueRef(
      input.recovery_principal_id,
      `${label}.recovery_principal_id`,
      { prefix: "principal" },
    ),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    workspace_snapshot_ref: normalizeOpaqueRef(
      input.workspace_snapshot_ref,
      `${label}.workspace_snapshot_ref`,
      { prefix: "workspace-snapshot" },
    ),
    workspace_snapshot_digest: assertDigest(
      input.workspace_snapshot_digest,
      `${label}.workspace_snapshot_digest`,
    ),
    restore_operation_id: assertToken(input.restore_operation_id, `${label}.restore_operation_id`),
    restore_operation_digest: assertDigest(input.restore_operation_digest, `${label}.restore_operation_digest`),
    cleanup_plan_digest: assertDigest(input.cleanup_plan_digest, `${label}.cleanup_plan_digest`),
    terminal_emission_state: "inhibited",
    allowed_terminal_states: normalizeStringEnumSet(
      input.allowed_terminal_states,
      CLEANUP_TERMINAL_STATE_VALUES,
      `${label}.allowed_terminal_states`,
    ),
    capability_nonce: assertToken(input.capability_nonce, `${label}.capability_nonce`),
    requested_effects: effects,
    requested_effects_digest: requestedEffectsDigest,
  };
  const capabilityDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "capability_digest", capabilityDigest, label);
  return deepFreeze({ ...normalized, capability_digest: capabilityDigest });
}

const CLEANUP_INVOCATION_FIELDS = Object.freeze([
  "version",
  "capability_digest",
  "safety_root_ref",
  "recovery_principal_id",
  "source_execution_request_digest",
  "instrument_ref",
  "lease_id",
  "fencing_token",
  "workspace_snapshot_ref",
  "workspace_snapshot_digest",
  "restore_operation_id",
  "restore_operation_digest",
  "cleanup_plan_digest",
  "terminal_emission_state",
  "requested_effects",
]);

const CLEANUP_INVOCATION_DERIVED_FIELDS = Object.freeze([
  "requested_effects_digest",
  "cleanup_invocation_digest",
]);

function normalizeCleanupInvocation(input, capabilityInput, registry, label = "cleanup_invocation") {
  assertClosedObject(
    input,
    label,
    CLEANUP_INVOCATION_FIELDS,
    CLEANUP_INVOCATION_DERIVED_FIELDS,
  );
  if (input.version !== CLEANUP_INVOCATION_VERSION) {
    throw new Error(`${label}.version must be ${CLEANUP_INVOCATION_VERSION}`);
  }
  const capability = normalizeCleanupCapability(capabilityInput, registry);
  const effects = normalizeRequestedEffectSet(input.requested_effects, registry, `${label}.requested_effects`);
  assertCleanupEffects(effects, capability.instrument_ref, `${label}.requested_effects`);
  const requestedEffectsDigest = hashCanonicalJson(effects);
  assertDerivedDigest(input, "requested_effects_digest", requestedEffectsDigest, label);

  const normalized = {
    version: CLEANUP_INVOCATION_VERSION,
    capability_digest: assertDigest(input.capability_digest, `${label}.capability_digest`),
    safety_root_ref: normalizeOpaqueRef(input.safety_root_ref, `${label}.safety_root_ref`, { prefix: "safety-root" }),
    recovery_principal_id: normalizeOpaqueRef(
      input.recovery_principal_id,
      `${label}.recovery_principal_id`,
      { prefix: "principal" },
    ),
    source_execution_request_digest: assertDigest(
      input.source_execution_request_digest,
      `${label}.source_execution_request_digest`,
    ),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, { prefix: "instrument" }),
    lease_id: assertToken(input.lease_id, `${label}.lease_id`),
    fencing_token: assertToken(input.fencing_token, `${label}.fencing_token`),
    workspace_snapshot_ref: normalizeOpaqueRef(
      input.workspace_snapshot_ref,
      `${label}.workspace_snapshot_ref`,
      { prefix: "workspace-snapshot" },
    ),
    workspace_snapshot_digest: assertDigest(
      input.workspace_snapshot_digest,
      `${label}.workspace_snapshot_digest`,
    ),
    restore_operation_id: assertToken(input.restore_operation_id, `${label}.restore_operation_id`),
    restore_operation_digest: assertDigest(input.restore_operation_digest, `${label}.restore_operation_digest`),
    cleanup_plan_digest: assertDigest(input.cleanup_plan_digest, `${label}.cleanup_plan_digest`),
    terminal_emission_state: input.terminal_emission_state,
    requested_effects: effects,
    requested_effects_digest: requestedEffectsDigest,
  };

  const exactBindings = [
    "capability_digest",
    "safety_root_ref",
    "recovery_principal_id",
    "source_execution_request_digest",
    "instrument_ref",
    "lease_id",
    "fencing_token",
    "workspace_snapshot_ref",
    "workspace_snapshot_digest",
    "restore_operation_id",
    "restore_operation_digest",
    "cleanup_plan_digest",
    "terminal_emission_state",
    "requested_effects_digest",
  ];
  for (const field of exactBindings) {
    const expected = field === "capability_digest" ? capability.capability_digest : capability[field];
    if (normalized[field] !== expected) {
      throw new Error(`${label}.${field} widens or redirects the cleanup capability`);
    }
  }

  const cleanupInvocationDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "cleanup_invocation_digest", cleanupInvocationDigest, label);
  return deepFreeze({ ...normalized, cleanup_invocation_digest: cleanupInvocationDigest });
}

const EFFECT_TUPLE_FIELDS = Object.freeze([
  "version",
  "grant_kind",
  "session_id",
  "session_nucleus_hash",
  "authority_epoch",
  "revocation_generation",
  "caller_role_id",
  "requester_principal_id",
  "ipc_peer_principal_id",
  "execution_principal_id",
  "instrument_ref",
  "operation_id",
  "parameter_digest",
  "template_id",
  "template_digest",
  "subject_ref",
  "subject_kind",
  "action",
  "channel",
  "persistence",
  "bounds_digest",
]);

function normalizePhysicalEffectAuthorityTuple(input, label = "physical_effect_tuple") {
  assertClosedObject(input, label, EFFECT_TUPLE_FIELDS, ["tuple_digest"]);
  if (input.version !== PHYSICAL_EFFECT_AUTHORITY_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_EFFECT_AUTHORITY_VERSION}`);
  }
  const subjectKind = assertEnum(input.subject_kind, EFFECT_SUBJECT_KINDS, `${label}.subject_kind`);
  const action = assertEnum(input.action, EFFECT_ACTIONS, `${label}.action`);
  if (!EFFECT_SURFACE_VALUES.includes(`${subjectKind}.${action}`)) {
    throw new Error(`${label} has an unsupported subject/action surface ${subjectKind}.${action}`);
  }
  const normalized = {
    version: PHYSICAL_EFFECT_AUTHORITY_VERSION,
    grant_kind: assertEnum(input.grant_kind, PHYSICAL_GRANT_KINDS, `${label}.grant_kind`),
    session_id: assertToken(input.session_id, `${label}.session_id`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, { min: 1 }),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
      { min: 0 },
    ),
    caller_role_id: assertToken(input.caller_role_id, `${label}.caller_role_id`),
    requester_principal_id: normalizeOpaqueRef(
      input.requester_principal_id,
      `${label}.requester_principal_id`,
      { prefix: "principal" },
    ),
    ipc_peer_principal_id: normalizeOpaqueRef(
      input.ipc_peer_principal_id,
      `${label}.ipc_peer_principal_id`,
      { prefix: "principal" },
    ),
    execution_principal_id: normalizeOpaqueRef(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      { prefix: "principal" },
    ),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, { prefix: "instrument" }),
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    parameter_digest: assertDigest(input.parameter_digest, `${label}.parameter_digest`),
    template_id: assertToken(input.template_id, `${label}.template_id`),
    template_digest: assertDigest(input.template_digest, `${label}.template_digest`),
    subject_ref: normalizeOpaqueRef(input.subject_ref, `${label}.subject_ref`, { prefix: subjectKind }),
    subject_kind: subjectKind,
    action,
    channel: assertEnum(input.channel, EFFECT_CHANNELS, `${label}.channel`),
    persistence: assertEnum(input.persistence, EFFECT_PERSISTENCE_VALUES, `${label}.persistence`),
    bounds_digest: assertDigest(input.bounds_digest, `${label}.bounds_digest`),
  };
  const tupleDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "tuple_digest", tupleDigest, label);
  return deepFreeze({ ...normalized, tuple_digest: tupleDigest });
}

function buildPhysicalEffectAuthorityTuples(input, registry, options = {}) {
  const request = normalizePhysicalExecutionRequest(input, registry, options);
  return Object.freeze(request.requested_effects.map((effect) => normalizePhysicalEffectAuthorityTuple({
    version: PHYSICAL_EFFECT_AUTHORITY_VERSION,
    grant_kind: request.grant_kind,
    session_id: request.session_id,
    session_nucleus_hash: request.session_nucleus_hash,
    authority_epoch: request.authority_epoch,
    revocation_generation: request.revocation_generation,
    caller_role_id: request.caller_role_id,
    requester_principal_id: request.requester_principal_id,
    ipc_peer_principal_id: request.ipc_peer_principal_id,
    execution_principal_id: request.execution_principal_id,
    instrument_ref: request.instrument_ref,
    operation_id: request.operation_id,
    parameter_digest: request.parameter_digest,
    template_id: effect.template_id,
    template_digest: effect.template_digest,
    subject_ref: effect.subject_ref,
    subject_kind: effect.subject_kind,
    action: effect.action,
    channel: effect.channel,
    persistence: effect.persistence,
    bounds_digest: hashCanonicalJson(effect.bounds),
  })));
}

function normalizePhysicalEffectAuthorityRule(input, label = "physical_effect_authority_rule") {
  assertClosedObject(input, label, ["version", "rule_id", "decision", "tuple"], ["rule_digest"]);
  if (input.version !== PHYSICAL_EFFECT_AUTHORITY_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_EFFECT_AUTHORITY_VERSION}`);
  }
  const normalized = {
    version: PHYSICAL_EFFECT_AUTHORITY_VERSION,
    rule_id: assertToken(input.rule_id, `${label}.rule_id`),
    decision: assertEnum(input.decision, AUTHORITY_DECISIONS, `${label}.decision`),
    tuple: normalizePhysicalEffectAuthorityTuple(input.tuple, `${label}.tuple`),
  };
  const ruleDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "rule_digest", ruleDigest, label);
  return deepFreeze({ ...normalized, rule_digest: ruleDigest });
}

function normalizePhysicalEffectAuthorityRules(input, label = "physical_effect_authority_rules") {
  if (!Array.isArray(input) || input.length > 4096) {
    throw new Error(`${label} must be an array with at most 4096 entries`);
  }
  const rules = input.map((rule, index) => normalizePhysicalEffectAuthorityRule(rule, `${label}[${index}]`));
  const ruleIds = rules.map((rule) => rule.rule_id);
  if (new Set(ruleIds).size !== ruleIds.length) throw new Error(`${label} must not contain duplicate rule IDs`);
  const decisionTupleKeys = rules.map((rule) => `${rule.decision}:${rule.tuple.tuple_digest}`);
  if (new Set(decisionTupleKeys).size !== decisionTupleKeys.length) {
    throw new Error(`${label} must not repeat the same decision for an exact tuple`);
  }
  return Object.freeze([...rules].sort((left, right) => left.rule_id.localeCompare(right.rule_id)));
}

function resolveNormalizedPhysicalEffectAuthority(tuple, rules) {
  const matching = rules.filter((rule) => rule.tuple.tuple_digest === tuple.tuple_digest);
  const denies = matching.filter((rule) => rule.decision === "deny");
  const allows = matching.filter((rule) => rule.decision === "allow");
  const decision = denies.length > 0 ? "deny" : allows.length > 0 ? "allow" : "deny";
  const reason = denies.length > 0 ? "explicit_deny" : allows.length > 0 ? "exact_allow" : "no_exact_allow";
  const normalized = {
    version: PHYSICAL_EFFECT_AUTHORITY_VERSION,
    tuple_digest: tuple.tuple_digest,
    decision,
    reason,
    matched_rule_ids: Object.freeze(matching.map((rule) => rule.rule_id).sort()),
    matched_rule_digests: Object.freeze(matching.map((rule) => rule.rule_digest).sort()),
  };
  return deepFreeze({ ...normalized, resolution_digest: hashCanonicalJson(normalized) });
}

function resolvePhysicalEffectAuthority(tupleInput, ruleInputs) {
  const tuple = normalizePhysicalEffectAuthorityTuple(tupleInput);
  const rules = normalizePhysicalEffectAuthorityRules(ruleInputs);
  return resolveNormalizedPhysicalEffectAuthority(tuple, rules);
}

function resolvePhysicalRequestAuthority(input, registry, ruleInputs, options = {}) {
  const request = normalizePhysicalExecutionRequest(input, registry, options);
  const tuples = buildPhysicalEffectAuthorityTuples(request, registry, {
    requestPath: request.request_path,
  });
  const rules = normalizePhysicalEffectAuthorityRules(ruleInputs);
  const effectResults = Object.freeze(tuples.map((tuple) => resolveNormalizedPhysicalEffectAuthority(tuple, rules)));
  const explicitDeny = effectResults.some((result) => result.reason === "explicit_deny");
  const missingAllow = effectResults.some((result) => result.reason === "no_exact_allow");
  const normalized = {
    version: PHYSICAL_EFFECT_AUTHORITY_VERSION,
    execution_request_digest: request.execution_request_digest,
    decision: explicitDeny || missingAllow ? "deny" : "allow",
    reason: explicitDeny ? "explicit_deny" : missingAllow ? "no_exact_allow" : "exact_allow",
    effect_results: effectResults,
  };
  return deepFreeze({ ...normalized, resolution_digest: hashCanonicalJson(normalized) });
}

module.exports = {
  ACTIVE_GRANT_REPLAY_RESERVATION_DISPOSITIONS,
  ACTIVE_GRANT_REPLAY_RESERVATION_VERSION,
  ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN,
  ACTIVE_PHYSICAL_EXECUTION_GRANT_KEY_USAGE,
  ACTIVE_PHYSICAL_EXECUTION_GRANT_VERSION,
  ACTIVE_PHYSICAL_EXECUTION_LINEAGE_VERSION,
  AUTHORITY_DECISIONS,
  BOOTSTRAP_GRANT_REPLAY_RESERVATION_DISPOSITIONS,
  BOOTSTRAP_GRANT_REPLAY_RESERVATION_VERSION,
  CLEANUP_CAPABILITY_VERSION,
  CLEANUP_INVOCATION_VERSION,
  CLEANUP_TERMINAL_STATE_VALUES,
  PHYSICAL_EFFECT_AUTHORITY_VERSION,
  PHYSICAL_BOOTSTRAP_GRANT_DOMAIN,
  PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE,
  PHYSICAL_BOOTSTRAP_GRANT_VERSION,
  PHYSICAL_EXECUTION_REQUEST_VERSION,
  PHYSICAL_GRANT_KINDS,
  PHYSICAL_GRANT_TRUSTED_CLOCK_MODES,
  REQUEST_PATH_VALUES,
  TERMINAL_CUSTODY_VALUES,
  activePhysicalExecutionGrantSignatureInputDigest,
  assertVerifiedActivePhysicalExecutionGrant,
  assertVerifiedPhysicalBootstrapGrant,
  buildPhysicalEffectAuthorityTuples,
  createActivePhysicalExecutionGrantVerifier,
  createPhysicalBootstrapGrantVerifier,
  normalizeCleanupCapability,
  normalizeCleanupInvocation,
  normalizeActiveExecutionLineage,
  normalizeMcpPhysicalExecutionRequest,
  normalizeOperatorMaintenanceRequest,
  normalizePhysicalEffectAuthorityRule,
  normalizePhysicalEffectAuthorityRules,
  normalizePhysicalEffectAuthorityTuple,
  normalizePhysicalExecutionRequest,
  physicalExecutionRequestDigest,
  physicalBootstrapGrantSignatureInputDigest,
  projectVerifiedActivePhysicalExecutionGrant,
  projectVerifiedPhysicalBootstrapGrant,
  resolvePhysicalEffectAuthority,
  resolvePhysicalRequestAuthority,
};
