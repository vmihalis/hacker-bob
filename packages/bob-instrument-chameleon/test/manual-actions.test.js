"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const manual = require("../lib/manual-actions.js");
const {
  CHAMELEON_MANUAL_ACTION_HIL_PLAN_DIGEST,
  beginChameleonManualAction,
  buildChameleonManualActionSignerRegistry,
  chameleonManualActionExpectedOutcomeDigest,
  chameleonManualActionParameterDigest,
  chameleonManualActionRuntimeReadiness,
  completeChameleonManualAction,
  createChameleonManualActionAcknowledgementPayload,
  createChameleonManualActionCompletionContext,
  createChameleonManualActionCompletionPayload,
  createChameleonManualActionRuntime,
  describeChameleonManualActions,
  manualActionSignatureInputDigest,
  projectChameleonManualActionCleanupPayload,
  projectChameleonManualActionExecutionPayload,
  projectChameleonManualActionObservationPayload,
  reserveChameleonManualAction,
} = manual;
const {
  CHAMELEON_SEMANTIC_MANIFEST,
  getChameleonOperation,
} = require("../lib/operations.js");
const {
  CHAMELEON_SLOT_COUNT,
  createChameleonStateRestoreResult,
  createChameleonStateSnapshot,
  createChameleonStateTransition,
} = require("../lib/state-stewardship.js");
const {
  ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN,
  activePhysicalExecutionGrantSignatureInputDigest,
  createActivePhysicalExecutionGrantVerifier,
  normalizeMcpPhysicalExecutionRequest,
  projectVerifiedActivePhysicalExecutionGrant,
} = require("../../../mcp/domains/physical/physical-authority.js");
const {
  attemptAllocationBindingDigest,
  buildPhysicalObserverEnrollmentRegistry,
  buildPhysicalReceiptTrustRegistry,
  createPhysicalAllocationIssuer,
  executionConsumptionBindingDigest,
  normalizePhysicalExperimentPlan,
  normalizePhysicalExperimentRowPayload,
  observationConsumptionBindingDigest,
  observerAttemptBindingDigest,
} = require("../../../mcp/domains/physical/physical-experiment-contract.js");
const {
  buildDurableReceiptTrustRegistry,
} = require("../../../mcp/core/executed-evidence-registry.js");
const {
  normalizePhysicalScopeNucleusAxis,
} = require("../../../mcp/core/governance/index.js");
const {
  buildEffectTemplateRegistry,
} = require("../../../mcp/core/requested-effects.js");
const {
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
  samplePhysicalTrustedClock,
} = require("../../../mcp/domains/physical/physical-trusted-clock.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const CAPABILITY_ID = "CU-ADMIN-FIELD-GENERATOR-INVOKE";
const CLONE_CAPABILITY_ID = "CU-ADMIN-BUTTON-CLONE-INVOKE";
const BASE_MS = Date.parse("2026-07-18T12:00:00.000Z");
const PROVIDER_DESCRIPTOR_DIGEST = digest("manual-provider-descriptor");
const PROVIDER_MANIFEST_DIGEST = digest("manual-provider-manifest");
const LEASE_ID = "lease-manual-action-1";
const FENCING_GENERATION = 3;

function digest(label) {
  return hashCanonicalJson({ label });
}

function at(offsetMs) {
  return new Date(BASE_MS + offsetMs).toISOString();
}

function artifact(label) {
  return `artifact:v1:${crypto.createHash("sha256").update(label).digest("base64url")}`;
}

function pemPair() {
  const pair = crypto.generateKeyPairSync("ed25519");
  return {
    pair,
    publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }),
    privateKeyPem: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

function clockFixture() {
  const pair = crypto.generateKeyPairSync("ed25519");
  const payload = {
    version: 1,
    clock_id: "physical-clock:manual-action-test",
    monotonic_epoch_id: digest("manual-action-monotonic-epoch"),
    mapping_generation: 1,
    reference_monotonic_ms: 1_000,
    reference_utc: at(0),
    max_uncertainty_ms: 0,
    not_before: at(-60_000),
    expires_at: at(120_000),
    trust_root_epoch: 2,
    authority_epoch: 4,
    revocation_generation: 0,
    signer_key_id: "clock-key:manual-action-test",
    signer_public_key_digest: publicKeyDigest(pair.publicKey),
  };
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockMappingSigningMessage(payloadDigest),
    pair.privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: TRUSTED_CLOCK_MAPPING_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  const mapping = { ...basis, signed_mapping_digest: hashCanonicalJson(basis) };
  const trust = {
    version: 1,
    trusted: true,
    revoked: false,
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    current_mapping_generation: 1,
    current_signed_mapping_digest: mapping.signed_mapping_digest,
    trust_root_epoch: 2,
    authority_epoch: 4,
    revocation_generation: 0,
    signer_key_id: payload.signer_key_id,
    signer_public_key_digest: payload.signer_public_key_digest,
    public_key: pair.publicKey,
  };
  const control = { offsetMs: 0 };
  const port = createPhysicalTrustedClockPort({
    port_id: "manual_action_test_clock",
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: 0,
    read_monotonic_ms: () => 1_000 + control.offsetMs,
    read_signed_mapping: () => mapping,
    resolve_current_trust: () => trust,
  });
  return {
    sample(offsetMs) {
      control.offsetMs = offsetMs;
      return samplePhysicalTrustedClock(port);
    },
  };
}

function effectTemplateDefinition() {
  const reference = (refPrefix = null) => ({
    kind: "reference", required: true, ...(refPrefix == null ? {} : { ref_prefix: refPrefix }),
  });
  return {
    version: 1,
    template_id: "environment.manual-rf-field",
    subject_kind: "environment",
    action: "transmit",
    channel: "rf",
    persistence: "ephemeral",
    bounds: {
      instrument_ref: reference("instrument"),
      duration_ms: { kind: "integer", required: true, min: 1, max: 10_000 },
      attempt_limit: { kind: "integer", required: true, min: 1, max: 1 },
      frequency_band: { kind: "enum", required: true, values: ["hf_13_56mhz"] },
      power_ceiling: { kind: "number", required: true, min: 0, max: 1 },
      duty_cycle: { kind: "number", required: true, min: 0, max: 1 },
      zone_ref: reference("zone"),
      containment_plan_ref: reference("containment-plan"),
      execution_deadline: { kind: "timestamp", required: true },
      spatial_envelope_ref: reference(),
      stimulus_sequence_ref: reference(),
      operator_receipt_ref: reference("manual-operator-receipt"),
      witness_receipt_ref: reference("manual-witness-receipt"),
    },
  };
}

function cloneEffectTemplateDefinitions() {
  const reference = (refPrefix = null) => ({
    kind: "reference", required: true, ...(refPrefix == null ? {} : { ref_prefix: refPrefix }),
  });
  const sharedRfBounds = {
    instrument_ref: reference("instrument"),
    target_ref: reference("target"),
    duration_ms: { kind: "integer", required: true, min: 1, max: 10_000 },
    attempt_limit: { kind: "integer", required: true, min: 1, max: 1 },
    frequency_band: { kind: "enum", required: true, values: ["hf_13_56mhz"] },
    power_ceiling: { kind: "number", required: true, min: 0, max: 1 },
    duty_cycle: { kind: "number", required: true, min: 0, max: 1 },
    zone_ref: reference("zone"),
    containment_plan_ref: reference("containment-plan"),
    execution_deadline: { kind: "timestamp", required: true },
    spatial_envelope_ref: reference(),
    stimulus_sequence_ref: reference(),
    operator_receipt_ref: reference("manual-operator-receipt"),
    witness_receipt_ref: reference("manual-witness-receipt"),
  };
  return [{
    version: 1,
    template_id: "target.manual-rf-discovery",
    subject_kind: "target",
    action: "transmit",
    channel: "rf",
    persistence: "ephemeral",
    bounds: sharedRfBounds,
  }, {
    version: 1,
    template_id: "instrument.manual-configure",
    subject_kind: "instrument",
    action: "configure",
    channel: "manual",
    persistence: "persistent",
    bounds: {
      instrument_ref: reference("instrument"),
      cleanup_plan_digest: {
        kind: "enum", required: true, values: [digest("manual-cleanup-plan")],
      },
      operator_receipt_ref: reference("manual-operator-receipt"),
      witness_receipt_ref: reference("manual-witness-receipt"),
    },
  }];
}

function requestedEffect(registry) {
  const template = registry.get("environment.manual-rf-field");
  return {
    version: 1,
    template_id: template.template_id,
    template_digest: template.template_digest,
    subject_ref: "environment:shielded-fixture",
    subject_kind: template.subject_kind,
    action: template.action,
    channel: template.channel,
    persistence: template.persistence,
    bounds: {
      instrument_ref: "instrument:chameleon-ultra-manual-1",
      duration_ms: 2_000,
      attempt_limit: 1,
      frequency_band: "hf_13_56mhz",
      power_ceiling: 0.25,
      duty_cycle: 0.5,
      zone_ref: "zone:shielded-fixture",
      containment_plan_ref: "containment-plan:manual-action-1",
      execution_deadline: at(10_000),
      spatial_envelope_ref: "envelope:manual-action-1",
      stimulus_sequence_ref: "sequence:manual-action-1",
      operator_receipt_ref: "manual-operator-receipt:field-generator-1",
      witness_receipt_ref: "manual-witness-receipt:field-generator-1",
    },
  };
}

function cloneRequestedEffects(registry) {
  const receiptBounds = {
    operator_receipt_ref: "manual-operator-receipt:clone-action-1",
    witness_receipt_ref: "manual-witness-receipt:clone-action-1",
  };
  const targetTemplate = registry.get("target.manual-rf-discovery");
  const instrumentTemplate = registry.get("instrument.manual-configure");
  return [{
    version: 1,
    template_id: targetTemplate.template_id,
    template_digest: targetTemplate.template_digest,
    subject_ref: "target:owned-manual-load",
    subject_kind: targetTemplate.subject_kind,
    action: targetTemplate.action,
    channel: targetTemplate.channel,
    persistence: targetTemplate.persistence,
    bounds: {
      instrument_ref: "instrument:chameleon-ultra-manual-1",
      target_ref: "target:owned-manual-load",
      duration_ms: 2_000,
      attempt_limit: 1,
      frequency_band: "hf_13_56mhz",
      power_ceiling: 0.25,
      duty_cycle: 0.5,
      zone_ref: "zone:shielded-fixture",
      containment_plan_ref: "containment-plan:manual-action-1",
      execution_deadline: at(10_000),
      spatial_envelope_ref: "envelope:manual-action-1",
      stimulus_sequence_ref: "sequence:manual-action-1",
      ...receiptBounds,
    },
  }, {
    version: 1,
    template_id: instrumentTemplate.template_id,
    template_digest: instrumentTemplate.template_digest,
    subject_ref: "instrument:chameleon-ultra-manual-1",
    subject_kind: instrumentTemplate.subject_kind,
    action: instrumentTemplate.action,
    channel: instrumentTemplate.channel,
    persistence: instrumentTemplate.persistence,
    bounds: {
      instrument_ref: "instrument:chameleon-ultra-manual-1",
      cleanup_plan_digest: digest("manual-cleanup-plan"),
      ...receiptBounds,
    },
  }];
}

function observerRegistry({ positiveSourceKind = "sensor" } = {}) {
  const positiveSourceRef = positiveSourceKind === "sensor"
    ? "sensor:external-rf-monitor"
    : "operator:external-rf-monitor";
  return buildPhysicalObserverEnrollmentRegistry([{
    observer_enrollment_ref: "observer-enrollment:manual-witness",
    observer_identity_ref: "observer:manual-witness",
    signer_key_id: "signer-key:manual-witness",
    source_kind: positiveSourceKind,
    source_ref: positiveSourceRef,
    source_assurance_scheme: "signed-rf-monitor-v1",
    trust_domain_ref: "trust-domain:manual-witness",
    independence_domain_ref: "independence-domain:manual-witness",
    external_outcome_allowed: true,
    valid_from: at(-60_000),
    expires_at: at(120_000),
    revoked: false,
  }, {
    observer_enrollment_ref: "observer-enrollment:manual-control",
    observer_identity_ref: "observer:manual-control",
    signer_key_id: "signer-key:manual-control",
    source_kind: "sensor",
    source_ref: "sensor:external-rf-control",
    source_assurance_scheme: "signed-rf-monitor-v1",
    trust_domain_ref: "trust-domain:manual-control",
    independence_domain_ref: "independence-domain:manual-control",
    external_outcome_allowed: true,
    valid_from: at(-60_000),
    expires_at: at(120_000),
    revoked: false,
  }]);
}

function receiptRuntime() {
  const physicalKeys = pemPair();
  const evidenceKeys = pemPair();
  const physicalRegistry = buildPhysicalReceiptTrustRegistry({
    version: 1,
    registry_id: "manual-action-physical-receipts",
    issuers: [{
      issuer_key_id: "signer-key:manual-physical-ledger",
      issuer_epoch: 1,
      public_key_pem: physicalKeys.publicKeyPem,
      valid_from: at(-60_000),
      expires_at: at(120_000),
      trusted: true,
      revoked: false,
    }],
  });
  const evidenceRegistry = buildDurableReceiptTrustRegistry({
    version: 1,
    registry_id: "manual-action-evidence-receipts",
    issuers: [{
      issuer_key_id: "signer-key:manual-evidence",
      issuer_epoch: 1,
      signature_scheme: "ed25519",
      public_key_pem: evidenceKeys.publicKeyPem,
      receipt_kinds: ["executed_evidence_verification", "physical_verifier_execution"],
      valid_from: at(-60_000),
      expires_at: at(120_000),
      trusted: true,
      revoked: false,
    }],
  });
  const allocationReceipts = new Map();
  const consumptionReceipts = new Map();
  const issuer = createPhysicalAllocationIssuer({
    registry: physicalRegistry,
    issuer_key_id: "signer-key:manual-physical-ledger",
    issuer_epoch: 1,
    private_key_pem: physicalKeys.privateKeyPem,
    now: () => at(6_000),
    reserve_unique_batch: () => true,
    consume_unique: () => true,
    commit_receipt(receipt) {
      if (receipt.kind === "attempt_allocation") {
        allocationReceipts.set(receipt.body.binding_digest, receipt);
      } else {
        consumptionReceipts.set(receipt.body.subject_ref, receipt);
      }
      return true;
    },
    resolve_allocation_receipt({ binding_digest: bindingDigest }) {
      return allocationReceipts.get(bindingDigest) || null;
    },
    resolve_consumption_receipt({ subject_ref: subjectRef }) {
      return consumptionReceipts.get(subjectRef) || null;
    },
  });
  return { physicalRegistry, evidenceRegistry, issuer };
}

function observerPlan(kind, registry, overrides = {}) {
  const witness = kind === "positive";
  const enrollmentRef = witness
    ? "observer-enrollment:manual-witness"
    : "observer-enrollment:manual-control";
  const enrollment = registry.get(enrollmentRef);
  const observer = {
    observer_id: witness ? "manual-witness" : "manual-control",
    observer_identity_ref: witness ? "observer:manual-witness" : "observer:manual-control",
    observer_enrollment_ref: enrollmentRef,
    source_kind: enrollment.source_kind,
    source_ref: enrollment.source_ref,
    source_assurance_scheme: enrollment.source_assurance_scheme,
    required_trust_domain_ref: enrollment.trust_domain_ref,
    required_independence_domain_ref: enrollment.independence_domain_ref,
    challenge_nonce: witness ? "AAAAAAAAAAAAAAAAAAAAAA" : "BBBBBBBBBBBBBBBBBBBBBB",
    attempt_binding_digest: digest(`${kind}:placeholder`),
    external_outcome: true,
    ...overrides,
  };
  return {
    ...observer,
    attempt_binding_digest: observerAttemptBindingDigest({
      session_nucleus_hash: digest("manual-session-nucleus"),
      experiment_id: "manual-field-generator-differential",
      task_id: "PH-P9-TASK-1",
      attempt_id: "manual-attempt-1",
      execution_request_digest: digest("manual-plan-execution-request"),
      cohort_kind: kind,
      cohort_execution_request_digest: digest(`manual-${kind}-cohort-request`),
      stimulus_plan_ref: `stimulus-plan:manual-${kind}`,
      stimulus_plan_digest: digest(`manual-${kind}-stimulus`),
      observer_enrollment_digest: enrollment.enrollment_digest,
      signer_key_id: enrollment.signer_key_id,
      ...observer,
    }),
  };
}

function assuranceClaims() {
  const body = {
    identity_enrollment: digest("manual-identity-enrollment"),
    firmware_provenance: digest("manual-firmware-provenance"),
    command_surface_conformance: digest("manual-command-conformance"),
    transport_trust: digest("manual-transport-trust"),
  };
  return { ...body, claims_digest: hashCanonicalJson(body) };
}

function planFixture(observerEnrollmentRegistry, receipts, effectRegistry, capabilityId = CAPABILITY_ID) {
  const effects = capabilityId === CLONE_CAPABILITY_ID
    ? cloneRequestedEffects(effectRegistry)
    : [requestedEffect(effectRegistry)];
  const positiveObserver = observerPlan("positive", observerEnrollmentRegistry);
  const controlObserver = observerPlan("control", observerEnrollmentRegistry);
  const positive = {
    kind: "positive",
    stimulus_plan_ref: "stimulus-plan:manual-positive",
    stimulus_plan_digest: digest("manual-positive-stimulus"),
    cohort_execution_request_digest: digest("manual-positive-cohort-request"),
    grant_ref: "grant:manual-positive",
    execution_identity: "execution:manual-positive",
    expected_outcome_digest: chameleonManualActionExpectedOutcomeDigest(capabilityId),
    observer_plan: [positiveObserver],
  };
  const control = {
    kind: "control",
    stimulus_plan_ref: "stimulus-plan:manual-control",
    stimulus_plan_digest: digest("manual-control-stimulus"),
    cohort_execution_request_digest: digest("manual-control-cohort-request"),
    grant_ref: "grant:manual-control",
    execution_identity: "execution:manual-control",
    expected_outcome_digest: digest("manual-control-rf-off"),
    observer_plan: [controlObserver],
  };
  const allocationBody = {
    version: 1,
    session_nucleus_hash: digest("manual-session-nucleus"),
    experiment_id: "manual-field-generator-differential",
    task_id: "PH-P9-TASK-1",
    attempt_id: "manual-attempt-1",
    execution_request_digest: digest("manual-plan-execution-request"),
    cohort_bindings: [positive, control].map((cohort) => ({
      cohort_kind: cohort.kind,
      cohort_execution_request_digest: cohort.cohort_execution_request_digest,
      grant_ref: cohort.grant_ref,
      execution_identity: cohort.execution_identity,
      challenge_nonces: cohort.observer_plan.map((observer) => observer.challenge_nonce),
    })),
  };
  allocationBody.binding_digest = attemptAllocationBindingDigest(allocationBody);
  const input = {
    version: 1,
    experiment_id: allocationBody.experiment_id,
    task_id: allocationBody.task_id,
    attempt_id: allocationBody.attempt_id,
    session_nucleus_hash: allocationBody.session_nucleus_hash,
    node_id: "PH-P9",
    contract_hash: digest("manual-node-contract"),
    execution_request_digest: allocationBody.execution_request_digest,
    hypothesis_ref: "hypothesis:manual-rf-field",
    claim_predicate_digest: digest("manual-claim-predicate"),
    expected_positive_outcome_digest: positive.expected_outcome_digest,
    expected_control_outcome_digest: control.expected_outcome_digest,
    verifier_template_id: "physical.manual-action-differential",
    verifier_template_version: 1,
    verifier_template_digest: digest("manual-verifier-template"),
    decision_rule_digest: digest("manual-decision-rule"),
    observation_window: {
      start_rule: "execution_ended",
      max_duration_ms: 10_000,
      max_clock_offset_abs_ms: 1_000,
      max_clock_uncertainty_ms: 100,
    },
    retry_policy: {
      fresh_attempt_and_challenge: true,
      max_attempts: 2,
      retry_on: ["inconclusive", "observer_unavailable"],
    },
    trust_registry_digest: digest("manual-experiment-trust"),
    executed_evidence_registry_digest: digest("manual-executed-evidence-registry"),
    evidence_receipt_registry_digest: receipts.evidenceRegistry.registry_digest,
    evidence_receipt_issuer_key_id: "signer-key:manual-evidence",
    evidence_receipt_issuer_epoch: 1,
    observer_enrollment_registry_digest: observerEnrollmentRegistry.registry_digest,
    physical_receipt_registry_digest: receipts.physicalRegistry.registry_digest,
    allocation_issuer_key_id: "signer-key:manual-physical-ledger",
    allocation_issuer_epoch: 1,
    append_issuer_key_id: "signer-key:manual-physical-ledger",
    append_issuer_epoch: 1,
    attempt_allocation_receipt: receipts.issuer.issueAttemptAllocation(allocationBody),
    ingestion_policy: { max_future_skew_ms: 100, max_ingestion_delay_ms: 10_000 },
    consumption_registry_digest: receipts.physicalRegistry.registry_digest,
    consumption_issuer_key_id: "signer-key:manual-physical-ledger",
    consumption_issuer_epoch: 1,
    instrument_ref: "instrument:chameleon-ultra-manual-1",
    instrument_identity_ref: "instrument-identity:chameleon-ultra-manual-1",
    instrument_inventory_ref: "inventory:chameleon-ultra-manual-1",
    assurance_profile_id: "enrolled_source_pinned",
    instrument_assurance_claims: assuranceClaims(),
    provider_manifest_digest: PROVIDER_MANIFEST_DIGEST,
    source_asset_ref: "source:owned-manual-fixture",
    target_asset_ref: "target:owned-manual-load",
    operation_id: "instrument.manual_action",
    parameter_digest: chameleonManualActionParameterDigest(capabilityId),
    requested_effects_registry_digest: effectRegistry.registry_digest,
    requested_effects: effects,
    requested_effects_digest: hashCanonicalJson(effects),
    positive_cohort: positive,
    control_cohort: control,
    controls: [{
      kind: "negative",
      plan_ref: control.stimulus_plan_ref,
      plan_digest: control.stimulus_plan_digest,
    }],
    cleanup_plan_digest: digest("manual-cleanup-plan"),
  };
  return normalizePhysicalExperimentPlan(input, "physical_experiment_plan", {
    observerEnrollmentRegistry,
    physicalReceiptRegistry: receipts.physicalRegistry,
    evidenceReceiptRegistry: receipts.evidenceRegistry,
    trustedNow: at(6_000),
  });
}

function settings() {
  return {
    animation_config_digest: digest("manual-setting-animation"),
    ble_pairing_config_digest: digest("manual-setting-ble"),
    button_a_config_digest: digest("manual-setting-button-a"),
    button_b_config_digest: digest("manual-setting-button-b"),
    detection_config_digest: digest("manual-setting-detection"),
    hf_emulator_config_digest: digest("manual-setting-hf"),
    lf_emulator_config_digest: digest("manual-setting-lf"),
    reader_profile_config_digest: digest("manual-setting-reader"),
  };
}

function slots() {
  return Array.from({ length: CHAMELEON_SLOT_COUNT }, (_, index) => ({
    slot_index: index + 1,
    slot_revision: 0,
    slot_status: "empty",
    hf_enabled: false,
    lf_enabled: false,
    hf_type_id: null,
    lf_type_id: null,
    metadata_artifact_handle: null,
    content_artifact_handle: null,
  }));
}

function occupiedSlots() {
  const values = slots();
  values[0] = {
    slot_index: 1,
    slot_revision: 1,
    slot_status: "occupied",
    hf_enabled: true,
    lf_enabled: false,
    hf_type_id: "mifare_classic",
    lf_type_id: null,
    metadata_artifact_handle: artifact("manual-clone-slot-metadata"),
    content_artifact_handle: artifact("manual-clone-slot-content"),
  };
  return values;
}

function snapshotInput(kind, stateEpoch, handleLabel, overrides = {}) {
  const operationId = overrides.operationId || "instrument.manual_action";
  const operation = getChameleonOperation(operationId);
  return {
    version: 1,
    snapshot_kind: kind,
    instrument_ref: "instrument:chameleon-ultra-manual-1",
    instrument_identity_digest: digest("manual-instrument-identity"),
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: PROVIDER_DESCRIPTOR_DIGEST,
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    assurance_profile_id: "enrolled_source_pinned",
    assurance_claims_digest: digest("manual-assurance-claims"),
    assurance_epoch: 1,
    assurance_status: "valid",
    assurance_invalidation_reason: null,
    state_epoch: stateEpoch,
    active_mode: overrides.activeMode || "rf_off",
    enabled_slot: overrides.enabledSlot == null ? null : overrides.enabledSlot,
    slots: overrides.slotState || slots(),
    settings: overrides.settingState || settings(),
    log_state: {
      log_generation: 1,
      origin_cursor_ref: "log-cursor:manual-origin",
      tail_cursor_ref: "log-cursor:manual-origin",
      retained_event_count: 0,
      overflow_count: 0,
      overflow_status: "none",
    },
    lease_id: LEASE_ID,
    fencing_generation: FENCING_GENERATION,
    operation_id: operationId,
    operation_contract_digest: operation.operation_contract_digest,
    attempt_ref: overrides.attemptRef || "attempt:manual-attempt-1",
    snapshot_artifact_handle: kind === "observed" ? artifact(handleLabel) : null,
    snapshot_plan_digest: digest("manual-snapshot-plan"),
  };
}

function activeGrantFixture(plan, preSnapshot, effectRegistry) {
  const compiledCommandDigest = digest("manual-compiled-command");
  const request = normalizeMcpPhysicalExecutionRequest({
    version: 1,
    grant_kind: "active",
    session_id: "manual-session-1",
    session_nucleus_hash: plan.session_nucleus_hash,
    caller_role_id: "orchestrator",
    requester_principal_id: "principal:manual-requester",
    ipc_peer_principal_id: "principal:manual-broker",
    execution_principal_id: "principal:manual-provider-worker",
    instrument_ref: plan.instrument_ref,
    operation_id: plan.operation_id,
    parameter_digest: plan.parameter_digest,
    authority_epoch: 4,
    revocation_generation: 0,
    nonce: "manual-active-grant-nonce-1",
    sequence: 1,
    not_before: at(0),
    expires_at: at(60_000),
    requested_effects: plan.requested_effects,
    node_id: "PH-P9",
    contract_hash: digest("manual-node-contract"),
    prep_token_hash: digest("manual-prep-token"),
    dispatch_event_id: "manual-dispatch-event-1",
    graph_context_hash: digest("manual-graph-context"),
    capability_pack_id: "physical.chameleon.v1",
    capability_pack_version: "1.0.0",
    capability_pack_digest: digest("manual-capability-pack"),
    technique_cell_id: "physical.manual-field-generator",
    attempt_id: plan.attempt_id,
    experiment_plan_hash: plan.plan_hash,
    inventory_observation_ref: "inventory-observation:manual-1",
    inventory_observation_digest: digest("manual-inventory-observation"),
    assurance_profile_id: plan.assurance_profile_id,
    assurance_claims_digest: plan.instrument_assurance_claims.claims_digest,
    provider_manifest_digest: plan.provider_manifest_digest,
    availability_variant_id: "manual-field-generator-v1",
    availability_variant_digest: digest("manual-availability-variant"),
    authorized_transition_set_digest: digest("manual-transition-set"),
    resource_bundle_digest: digest("manual-resource-bundle"),
    fencing_token: "manual-fencing-token-1",
    lease_id: LEASE_ID,
    workspace_snapshot_ref: "workspace-snapshot:manual-pre-state",
    workspace_snapshot_digest: preSnapshot.snapshot_digest,
    observer_plan_digest: digest("manual-observer-plan"),
    control_plan_digest: digest("manual-control-plan"),
    cleanup_plan_digest: plan.cleanup_plan_digest,
    execution_lineage: {
      version: 1,
      compiler_id: "closed_manual_action_compiler_v1",
      compiler_manifest_digest: digest("manual-compiler-manifest"),
      compiler_registry_digest: digest("manual-compiler-registry"),
      compiled_command_id: "compiled-command:manual-action-1",
      compiled_command_capability_digest: compiledCommandDigest,
      compiled_operation_digest: getChameleonOperation("instrument.manual_action").operation_contract_digest,
      provider_command_ref: "command:manual-action-1",
      command_input_ref: "command-input:manual-action-1",
      command_input_digest: compiledCommandDigest,
      maximum_response_bytes: 1,
      vault_reservation_handle: `vault-reservation:v1:${"M".repeat(43)}`,
      vault_reservation_digest: digest("manual-vault-reservation"),
      vault_ingest_capability_digest: digest("manual-vault-ingest"),
      vault_byte_limit: 1,
      worker_bundle_digest: digest("manual-worker-bundle"),
      worker_launch_profile_digest: digest("manual-launch-profile"),
      worker_fence_plan_digest: digest("manual-worker-fence"),
      transport_profile_digest: digest("manual-transport-profile"),
      durable_exchange_plan_digest: digest("manual-durable-exchange"),
      terminal_receipt_recipient_digest: digest("manual-terminal-recipient"),
      safety_supervisor_plan_digest: digest("manual-safety-plan"),
    },
  }, effectRegistry);
  const scopeAxis = normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "manual-physical-scope-v1",
    policy_digest: digest("manual-scope-policy"),
    projection_version: 1,
    projection_digest: digest("manual-scope-projection"),
    provenance_digest: digest("manual-scope-provenance"),
    compatibility_digest: digest("manual-scope-compatibility"),
    transition_receipt_registry_digest: digest("manual-transition-receipts"),
    authority_epoch: request.authority_epoch,
    revocation_generation: request.revocation_generation,
  });
  const pair = crypto.generateKeyPairSync("ed25519");
  const authority = {
    version: 1,
    session_id: request.session_id,
    session_nucleus_hash: request.session_nucleus_hash,
    execution_request_digest: request.execution_request_digest,
    physical_scope_axis: scopeAxis,
    authority_decision: "allow",
    authority_reason: "exact_allow",
    authority_resolution_digest: digest("manual-authority-resolution"),
    trust_root_id: "trust-root:manual-authority",
    trust_root_epoch: 2,
    trust_registry_digest: digest("manual-authority-trust-registry"),
    trust_root_trusted: true,
    trust_root_revoked: false,
    issuer_principal_id: "principal:manual-authority-issuer",
    issuer_key_id: "signer-key:manual-authority",
    issuer_epoch: 1,
    issuer_public_key_digest: publicKeyDigest(pair.publicKey),
    key_usage: "physical_active_grant_signing",
    issuer_trusted: true,
    issuer_revoked: false,
  };
  let now = at(2_000);
  const verifier = createActivePhysicalExecutionGrantVerifier({
    verifier_id: "manual_action_active_grant_verifier",
    trusted_now: () => now,
    resolve_current_authority: () => authority,
    verify_ed25519({ signature_input_digest: signatureInputDigest, signature }) {
      return crypto.verify(
        null,
        Buffer.from(signatureInputDigest, "hex"),
        pair.publicKey,
        Buffer.from(signature, "base64url"),
      );
    },
    reserve_replay(claim) {
      const body = {
        version: 1,
        reservation_ref: "grant-replay-reservation:manual-action-1",
        replay_claim: claim,
        replay_claim_digest: hashCanonicalJson(claim),
        generation: 1,
        previous_receipt_digest: null,
        reserved_at: at(1_500),
        fsynced_at: at(1_500),
      };
      return {
        version: 1,
        disposition: "created",
        reservation_receipt: { ...body, receipt_digest: hashCanonicalJson(body) },
      };
    },
  });
  const operationDigest = getChameleonOperation("instrument.manual_action").operation_contract_digest;
  const payload = {
    version: 1,
    grant_kind: "active",
    grant_ref: "physical-grant:manual-action-1",
    session_id: request.session_id,
    session_nucleus_hash: request.session_nucleus_hash,
    physical_scope_axis_digest: scopeAxis.axis_digest,
    physical_scope_policy_id: scopeAxis.policy_id,
    physical_scope_policy_digest: scopeAxis.policy_digest,
    physical_scope_projection_digest: scopeAxis.projection_digest,
    authority_epoch: request.authority_epoch,
    revocation_generation: request.revocation_generation,
    execution_request_digest: request.execution_request_digest,
    request_nonce: request.nonce,
    request_sequence: request.sequence,
    execution_principal_id: request.execution_principal_id,
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: PROVIDER_DESCRIPTOR_DIGEST,
    instrument_ref: request.instrument_ref,
    operation_id: request.operation_id,
    operation_digest: operationDigest,
    parameter_digest: request.parameter_digest,
    requested_effects_digest: request.requested_effects_digest,
    authority_decision: authority.authority_decision,
    authority_reason: authority.authority_reason,
    authority_resolution_digest: authority.authority_resolution_digest,
    attempt_id: request.attempt_id,
    experiment_plan_hash: request.experiment_plan_hash,
    execution_lineage_digest: request.execution_lineage.execution_lineage_digest,
    resource_bundle_digest: request.resource_bundle_digest,
    lease_id: request.lease_id,
    fencing_token: request.fencing_token,
    fencing_generation: FENCING_GENERATION,
    workspace_snapshot_digest: request.workspace_snapshot_digest,
    cleanup_plan_digest: request.cleanup_plan_digest,
    not_before: request.not_before,
    expires_at: request.expires_at,
  };
  const authentication = {
    version: 1,
    method: "ed25519",
    trust_root_id: authority.trust_root_id,
    trust_root_epoch: authority.trust_root_epoch,
    trust_registry_digest: authority.trust_registry_digest,
    issuer_principal_id: authority.issuer_principal_id,
    issuer_key_id: authority.issuer_key_id,
    issuer_epoch: authority.issuer_epoch,
    issuer_public_key_digest: authority.issuer_public_key_digest,
    signed_at: at(1_000),
    signed_payload_digest: hashCanonicalJson(payload),
  };
  const signatureInputDigest = activePhysicalExecutionGrantSignatureInputDigest(payload, authentication);
  const signedGrant = {
    version: 1,
    kind: "active_physical_execution_grant",
    domain: ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN,
    payload,
    authentication: {
      ...authentication,
      signature: crypto.sign(
        null,
        Buffer.from(signatureInputDigest, "hex"),
        pair.privateKey,
      ).toString("base64url"),
    },
  };
  const projection = projectVerifiedActivePhysicalExecutionGrant(signedGrant, verifier, {
    execution_request: request,
    effect_registry: effectRegistry,
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: PROVIDER_DESCRIPTOR_DIGEST,
    operation_digest: operationDigest,
    fencing_generation: FENCING_GENERATION,
  });
  return { projection, request, verifier, setNow: (value) => { now = value; } };
}

function manualSignerRegistry(keys, enrollmentRegistry, overrides = {}) {
  const operator = {
    version: 1,
    signer_role: "operator",
    signer_key_id: "signer-key:manual-operator",
    signer_principal_ref: "principal:manual-operator",
    public_key_pem: keys.operator.publicKeyPem,
    trust_root_epoch: 1,
    trust_domain_ref: "trust-domain:manual-operator",
    independence_domain_ref: "independence-domain:manual-operator",
    observer_enrollment_ref: null,
    valid_from: at(-60_000),
    expires_at: at(120_000),
    trusted: true,
    revoked: false,
    ...overrides.operator,
  };
  const witness = {
    version: 1,
    signer_role: "witness",
    signer_key_id: "signer-key:manual-witness",
    signer_principal_ref: "principal:manual-witness",
    public_key_pem: keys.witness.publicKeyPem,
    trust_root_epoch: 1,
    trust_domain_ref: "trust-domain:manual-witness",
    independence_domain_ref: "independence-domain:manual-witness",
    observer_enrollment_ref: "observer-enrollment:manual-witness",
    valid_from: at(-60_000),
    expires_at: at(120_000),
    trusted: true,
    revoked: false,
    ...overrides.witness,
  };
  assert.ok(enrollmentRegistry.get(witness.observer_enrollment_ref));
  return buildChameleonManualActionSignerRegistry({
    version: 1,
    registry_id: "manual_action_test_signers",
    signers: [operator, witness],
  });
}

function signManualPayload(payload, key, signerKeyId, signedAt) {
  const payloadDigest = hashCanonicalJson(payload);
  const signatureInputDigest = manualActionSignatureInputDigest({
    version: 1,
    purpose: payload.purpose,
    signer_key_id: signerKeyId,
    trust_root_epoch: 1,
    signed_at: signedAt,
    payload_digest: payloadDigest,
  });
  return {
    version: 1,
    purpose: payload.purpose,
    signer_key_id: signerKeyId,
    trust_root_epoch: 1,
    signed_at: signedAt,
    payload,
    payload_digest: payloadDigest,
    signature_input_digest: signatureInputDigest,
    signature: crypto.sign(
      null,
      Buffer.from(signatureInputDigest, "hex"),
      key.pair.privateKey,
    ).toString("base64url"),
  };
}

function createScenario({
  begin = true,
  observerSourceKind = "sensor",
  signerOverrides = {},
  capabilityId = CAPABILITY_ID,
} = {}) {
  const clock = clockFixture();
  const observerEnrollmentRegistry = observerRegistry({ positiveSourceKind: observerSourceKind });
  const receipts = receiptRuntime();
  const effectDefinitions = capabilityId === CLONE_CAPABILITY_ID
    ? cloneEffectTemplateDefinitions()
    : [effectTemplateDefinition()];
  const effectRegistry = buildEffectTemplateRegistry(effectDefinitions);
  const plan = planFixture(observerEnrollmentRegistry, receipts, effectRegistry, capabilityId);
  const pre = createChameleonStateSnapshot(
    snapshotInput("observed", 1, "manual-pre-state"),
    clock.sample(1_000),
  );
  const grant = activeGrantFixture(plan, pre, effectRegistry);
  const keys = { operator: pemPair(), witness: pemPair() };
  const signerRegistry = manualSignerRegistry(keys, observerEnrollmentRegistry, signerOverrides);
  const runtime = createChameleonManualActionRuntime({
    version: 1,
    runtime_id: "manual_action_test_runtime",
    signer_registry: signerRegistry,
    observer_enrollment_registry: observerEnrollmentRegistry,
    active_grant_verifier: grant.verifier,
    challenge_ttl_ms: 5_000,
  });
  const reservation = reserveChameleonManualAction(runtime, {
    version: 1,
    capability_id: capabilityId,
    cohort_kind: "positive",
    operator_signer_key_id: "signer-key:manual-operator",
    witness_signer_key_id: "signer-key:manual-witness",
    witness_observer_id: "manual-witness",
    rf_off_deadline: at(10_000),
  }, plan, grant.projection, pre, clock.sample(2_000));
  if (!begin) return {
    clock, observerEnrollmentRegistry, receipts, effectRegistry, plan, pre, grant, keys,
    signerRegistry, runtime, reservation,
  };
  const operatorAckPayload = createChameleonManualActionAcknowledgementPayload(
    reservation,
    "operator",
    at(2_100),
  );
  const witnessAckPayload = createChameleonManualActionAcknowledgementPayload(
    reservation,
    "witness",
    at(2_200),
  );
  const operatorAck = signManualPayload(
    operatorAckPayload,
    keys.operator,
    "signer-key:manual-operator",
    at(2_300),
  );
  const witnessAck = signManualPayload(
    witnessAckPayload,
    keys.witness,
    "signer-key:manual-witness",
    at(2_400),
  );
  grant.setNow(at(2_500));
  const execution = beginChameleonManualAction(runtime, reservation, {
    version: 1,
    operator_acknowledgement: operatorAck,
    witness_acknowledgement: witnessAck,
  }, clock.sample(3_000));
  return {
    clock, observerEnrollmentRegistry, receipts, effectRegistry, plan, pre, grant, keys,
    signerRegistry, runtime, reservation, execution,
  };
}

function completionFixture(scenario) {
  const cloneAction = scenario.execution.capability_id === CLONE_CAPABILITY_ID;
  const postSlots = cloneAction ? occupiedSlots() : slots();
  const declared = createChameleonStateSnapshot(
    snapshotInput("declared", cloneAction ? 2 : 1, "unused-declared", {
      slotState: postSlots,
    }),
    scenario.clock.sample(3_500),
  );
  const observed = createChameleonStateSnapshot(
    snapshotInput("observed", cloneAction ? 2 : 1, "manual-post-state", {
      slotState: postSlots,
    }),
    scenario.clock.sample(4_000),
  );
  const operation = getChameleonOperation("instrument.manual_action");
  const transition = createChameleonStateTransition({
    version: 1,
    transition_ref: "state-transition:manual-action-1",
    operation_id: operation.operation_id,
    operation_contract_digest: operation.operation_contract_digest,
    attempt_ref: "attempt:manual-attempt-1",
    request_digest: scenario.grant.request.execution_request_digest,
    lease_id: LEASE_ID,
    fencing_generation: FENCING_GENERATION,
    authorized_effects_digest: scenario.plan.requested_effects_digest,
    recovery_policy: cloneAction ? "required" : "not_required",
    restore_plan_digest: cloneAction ? digest("manual-clone-restore-plan") : null,
    restore_effects_digest: cloneAction ? digest("manual-clone-restore-effects") : null,
    slot_mutations: cloneAction ? [{
      slot_index: 1,
      action: "stage",
      pre_slot_digest: scenario.pre.slots[0].slot_digest,
      post_slot_digest: declared.slots[0].slot_digest,
      authorization_plan_digest: digest("manual-clone-slot-stage-plan"),
      source_artifact_handle: declared.slots[0].content_artifact_handle,
      preimage_artifact_handle: null,
    }] : [],
    mode_change: null,
    settings_change_ids: [],
    settings_change_plan_digest: null,
    log_action: "preserve",
    effect_disposition: cloneAction ? "confirmed_effect" : "confirmed_no_effect",
    receipt_ref: "receipt:manual-state-transition-1",
  }, scenario.pre, declared, observed, scenario.clock.sample(4_200));
  let restoreResult = null;
  if (cloneAction) {
    const restored = createChameleonStateSnapshot(
      snapshotInput("observed", 3, "manual-restored-state", {
        operationId: "workspace.restore",
        attemptRef: "attempt:manual-restore-1",
      }),
      scenario.clock.sample(4_300),
    );
    const restoreOperation = getChameleonOperation("workspace.restore");
    restoreResult = createChameleonStateRestoreResult({
      version: 1,
      restore_ref: "restore:manual-action-1",
      restore_attempt_ref: "attempt:manual-restore-1",
      operation_id: restoreOperation.operation_id,
      operation_contract_digest: restoreOperation.operation_contract_digest,
      lease_id: LEASE_ID,
      fencing_generation: FENCING_GENERATION,
      snapshot_artifact_handle: scenario.pre.snapshot_artifact_handle,
      restore_plan_digest: transition.restore_plan_digest,
      restore_effects_digest: transition.restore_effects_digest,
      log_action: "preserve",
      disposition: "restored",
      receipt_ref: "receipt:manual-restore-1",
    }, transition, restored, scenario.clock.sample(4_400));
  }
  const context = createChameleonManualActionCompletionContext(scenario.execution, {
    version: 1,
    completed_at: at(4_500),
    manual_evidence_artifact_ref: artifact("manual-evidence-bundle"),
    rf_on_observed_at: at(3_100),
    rf_off_observed_at: at(4_000),
    external_rf_state_digest: digest("external-rf-on-off-state"),
    rf_sensor_artifact_ref: artifact("external-rf-trace"),
  }, transition, restoreResult);
  const operatorPayload = createChameleonManualActionCompletionPayload(
    scenario.execution,
    context,
    "operator",
    "performed",
  );
  const witnessPayload = createChameleonManualActionCompletionPayload(
    scenario.execution,
    context,
    "witness",
    "performed",
  );
  const operatorReceipt = signManualPayload(
    operatorPayload,
    scenario.keys.operator,
    "signer-key:manual-operator",
    at(4_600),
  );
  const witnessReceipt = signManualPayload(
    witnessPayload,
    scenario.keys.witness,
    "signer-key:manual-witness",
    at(4_700),
  );
  return { declared, observed, transition, restoreResult, context, operatorPayload, witnessPayload,
    operatorReceipt, witnessReceipt };
}

function completeScenario(scenario, fixture, clockOffset = 5_000) {
  return completeChameleonManualAction(scenario.runtime, scenario.execution, fixture.context, {
    version: 1,
    operator_receipt: fixture.operatorReceipt,
    witness_receipt: fixture.witnessReceipt,
  }, scenario.clock.sample(clockOffset));
}

test("reviewed manual registry is exact, source-pinned, provider-private, and never production-ready", () => {
  const description = describeChameleonManualActions();
  assert.equal(description.manual_action_registry_digest,
    "fce6a16f56c002d9e6259762b7887461d1be145aa0c1cd059790f8955c2dd9c7");
  assert.deepEqual(description.actions.map((entry) => entry.capability_id), [
    "CU-ADMIN-BUTTON-CLONE-INVOKE",
    "CU-ADMIN-FIELD-GENERATOR-INVOKE",
  ]);
  assert.ok(description.actions.every((entry) => (
    entry.source_sha256 === "95a62be3fffe6b66b635216523d7beb5d74692db14747549da37b29aea8828bd"
    && entry.source_symbol === "run_button_function_by_settings"
    && /^[a-f0-9]{64}$/u.test(entry.procedure_binding_digest)
    && /^[a-f0-9]{64}$/u.test(entry.parameter_digest)
  )));
  const readiness = chameleonManualActionRuntimeReadiness();
  assert.equal(readiness.engineering_ready, true);
  assert.equal(readiness.production_ready, false);
  assert.equal(readiness.hil_ready, false);
  assert.ok(readiness.blockers.includes("owned_shielded_fixture_hil_evidence_not_completed"));
  assert.equal(Object.isFrozen(readiness), true);
});

test("manual action completes only from active grant, fresh challenge, distinct signatures, RF-off, and clean state", () => {
  const scenario = createScenario();
  const fixture = completionFixture(scenario);
  const terminal = completeScenario(scenario, fixture);
  assert.equal(terminal.disposition, "completed_clean");
  assert.equal(terminal.closable, true);
  assert.equal(terminal.cleanup_status, "succeeded");
  assert.equal(terminal.pre_mode, "rf_off");
  assert.equal(terminal.post_mode, "rf_off");
  assert.equal(terminal.pre_workspace_state_digest, terminal.post_workspace_state_digest);
  assert.equal(terminal.rf_off_observed_at, at(4_000));
  assert.equal(terminal.rf_off_deadline, at(10_000));
  assert.match(terminal.operator_receipt_digest, /^[a-f0-9]{64}$/u);
  assert.match(terminal.witness_receipt_digest, /^[a-f0-9]{64}$/u);

  const executionBinding = executionConsumptionBindingDigest(
    scenario.plan,
    scenario.plan.positive_cohort,
    scenario.plan.positive_cohort.grant_ref,
    scenario.plan.positive_cohort.execution_identity,
  );
  const executionConsumption = scenario.receipts.issuer.issueConsumption({
    version: 1,
    kind: "grant",
    binding_digest: executionBinding,
    subject_ref: scenario.plan.positive_cohort.grant_ref,
    consumption_ref: "consumption:manual-grant-1",
    plan_hash: scenario.plan.plan_hash,
    attempt_id: scenario.plan.attempt_id,
    sequence: 1,
    consumed_at: scenario.execution.started_at,
  });
  const executionPayload = projectChameleonManualActionExecutionPayload(terminal, {
    version: 1,
    instrument_trust_domain_ref: "trust-domain:manual-instrument",
    consumption_attestation: executionConsumption,
  });
  const normalizedExecution = normalizePhysicalExperimentRowPayload(
    "execution_receipt",
    executionPayload,
    scenario.plan,
  );
  assert.equal(normalizedExecution.status, "executed");
  assert.equal(normalizedExecution.stimulus_artifact_ref, terminal.manual_evidence_artifact_ref);

  const observationSeed = projectChameleonManualActionObservationPayload(terminal, {
    version: 1,
    execution_receipt_ref: `physical-execution-receipt:v1:${"a".repeat(64)}`,
    consumption_attestation: {},
    clock_offset_ms: 0,
    clock_uncertainty_ms: 0,
  });
  const observer = scenario.plan.positive_cohort.observer_plan[0];
  const replayGuard = { kind: "one_time_challenge", value: observer.challenge_nonce };
  const observationBinding = observationConsumptionBindingDigest(
    scenario.plan,
    observer,
    observationSeed,
    replayGuard,
  );
  const observationConsumption = scenario.receipts.issuer.issueConsumption({
    version: 1,
    kind: "one_time_challenge",
    binding_digest: observationBinding,
    subject_ref: `challenge:${observer.challenge_nonce}`,
    consumption_ref: "consumption:manual-witness-challenge-1",
    plan_hash: scenario.plan.plan_hash,
    attempt_id: scenario.plan.attempt_id,
    sequence: 2,
    consumed_at: terminal.rf_off_observed_at,
  });
  const observationPayload = projectChameleonManualActionObservationPayload(terminal, {
    version: 1,
    execution_receipt_ref: observationSeed.execution_receipt_ref,
    consumption_attestation: observationConsumption,
    clock_offset_ms: 0,
    clock_uncertainty_ms: 0,
  });
  const normalizedObservation = normalizePhysicalExperimentRowPayload(
    "observation",
    observationPayload,
    scenario.plan,
  );
  assert.equal(normalizedObservation.source_kind, "sensor");
  assert.equal(normalizedObservation.observed_state_digest, terminal.external_rf_state_digest);
  assert.equal(normalizedObservation.artifact_ref, terminal.rf_sensor_artifact_ref);

  const cleanupPayload = projectChameleonManualActionCleanupPayload(terminal, {
    version: 1,
    execution_receipt_ref: observationSeed.execution_receipt_ref,
  });
  assert.equal(normalizePhysicalExperimentRowPayload(
    "cleanup_verdict",
    cleanupPayload,
    scenario.plan,
  ).outcome, "succeeded");
});

test("clone procedure binds both reviewed effects and closes only after exact workspace restoration", () => {
  const scenario = createScenario({ capabilityId: CLONE_CAPABILITY_ID });
  assert.deepEqual(scenario.reservation.effect_profile_refs, [
    "EP-TARGET-TRANSMIT-RF-MANUAL",
    "EP-INSTRUMENT-CONFIGURE-MANUAL",
  ]);
  const fixture = completionFixture(scenario);
  assert.equal(fixture.transition.transition_state, "restore_required");
  assert.equal(fixture.restoreResult.disposition, "restored");
  const terminal = completeScenario(scenario, fixture);
  assert.equal(terminal.disposition, "completed_clean");
  assert.equal(terminal.cleanup_disposition, "restored");
  assert.equal(terminal.pre_workspace_state_digest, terminal.post_workspace_state_digest);
  assert.equal(terminal.post_state_epoch, 3);
  assert.equal(terminal.post_mode, "rf_off");
});

test("reservation, challenge, and execution permits are one-use and replay-safe", () => {
  const scenario = createScenario();
  const operatorPayload = createChameleonManualActionAcknowledgementPayload(
    scenario.reservation,
    "operator",
    at(3_100),
  );
  const witnessPayload = createChameleonManualActionAcknowledgementPayload(
    scenario.reservation,
    "witness",
    at(3_100),
  );
  assert.throws(() => beginChameleonManualAction(scenario.runtime, scenario.reservation, {
    version: 1,
    operator_acknowledgement: signManualPayload(
      operatorPayload,
      scenario.keys.operator,
      "signer-key:manual-operator",
      at(3_200),
    ),
    witness_acknowledgement: signManualPayload(
      witnessPayload,
      scenario.keys.witness,
      "signer-key:manual-witness",
      at(3_200),
    ),
  }, scenario.clock.sample(3_300)), /already consumed/u);
  const fixture = completionFixture(scenario);
  assert.equal(completeScenario(scenario, fixture).closable, true);
  assert.throws(() => completeScenario(scenario, fixture, 5_100), /already consumed/u);
});

test("late completion consumes the attempt into inconclusive quarantine and cannot project", () => {
  const scenario = createScenario();
  const fixture = completionFixture(scenario);
  const terminal = completeScenario(scenario, fixture, 61_000);
  assert.equal(terminal.disposition, "inconclusive");
  assert.equal(terminal.reason_code, "late_evidence");
  assert.equal(terminal.cleanup_status, "quarantine_required");
  assert.equal(terminal.closable, false);
  assert.throws(() => projectChameleonManualActionExecutionPayload(terminal, {
    version: 1,
    instrument_trust_domain_ref: "trust-domain:manual-instrument",
    consumption_attestation: {},
  }), /cannot enter the ordinary verifier path/u);
});

test("validly signed cross-attempt receipt is inconclusive, quarantined, and non-retryable", () => {
  const scenario = createScenario();
  const fixture = completionFixture(scenario);
  const crossedPayload = { ...fixture.operatorPayload, attempt_id: "another-attempt" };
  fixture.operatorReceipt = signManualPayload(
    crossedPayload,
    scenario.keys.operator,
    "signer-key:manual-operator",
    at(4_600),
  );
  const terminal = completeScenario(scenario, fixture);
  assert.equal(terminal.disposition, "inconclusive");
  assert.equal(terminal.reason_code, "cross_attempt_evidence");
  assert.equal(terminal.cleanup_status, "quarantine_required");
  assert.throws(() => completeScenario(scenario, fixture, 5_100), /already consumed/u);
});

test("procedure and capability substitution remains inconclusive even when an enrolled operator signs it", () => {
  const scenario = createScenario();
  const fixture = completionFixture(scenario);
  const substituted = {
    ...fixture.operatorPayload,
    capability_id: "CU-ADMIN-BUTTON-CLONE-INVOKE",
  };
  fixture.operatorReceipt = signManualPayload(
    substituted,
    scenario.keys.operator,
    "signer-key:manual-operator",
    at(4_600),
  );
  const terminal = completeScenario(scenario, fixture);
  assert.equal(terminal.disposition, "inconclusive");
  assert.equal(terminal.reason_code, "receipt_substitution");
  assert.equal(terminal.closable, false);
});

test("invalid completion signature consumes the execution into inconclusive quarantine", () => {
  const scenario = createScenario();
  const fixture = completionFixture(scenario);
  fixture.witnessReceipt = {
    ...fixture.witnessReceipt,
    signature: `${fixture.witnessReceipt.signature.slice(0, -1)}${
      fixture.witnessReceipt.signature.endsWith("A") ? "B" : "A"
    }`,
  };
  const terminal = completeScenario(scenario, fixture);
  assert.equal(terminal.disposition, "inconclusive");
  assert.equal(terminal.reason_code, "signature_invalid");
  assert.equal(terminal.cleanup_status, "quarantine_required");
});

test("self-witness, shared key material, revoked signers, and non-sensor enrollment fail closed", () => {
  const registry = observerRegistry();
  const shared = pemPair();
  assert.throws(() => manualSignerRegistry({ operator: shared, witness: shared }, registry),
    /public key material cannot be shared|self-witness/u);
  const distinct = { operator: pemPair(), witness: pemPair() };
  assert.throws(() => manualSignerRegistry(distinct, registry, {
    witness: {
      signer_principal_ref: "principal:manual-operator",
      trust_domain_ref: "trust-domain:manual-operator",
      independence_domain_ref: "independence-domain:manual-operator",
    },
  }), /self-witnessing/u);
  assert.throws(() => createScenario({
    begin: false,
    signerOverrides: {
      witness: { revoked: true, revoked_at: at(1_000) },
    },
  }), /not currently trusted and active/u);
  assert.throws(() => createScenario({
    begin: false,
    observerSourceKind: "operator",
  }), /source_kind enrollment drift/u);
  assert.throws(() => createScenario({ begin: false }).signerRegistry.describe().push({}), /not extensible|read only|object is not extensible/ui);
});

test("unknown fields, callbacks, raw bytes, accessors, and arbitrary capability IDs never reach reservation", () => {
  const scenario = createScenario({ begin: false });
  const base = {
    version: 1,
    capability_id: CAPABILITY_ID,
    cohort_kind: "positive",
    operator_signer_key_id: "signer-key:manual-operator",
    witness_signer_key_id: "signer-key:manual-witness",
    witness_observer_id: "manual-witness",
    rf_off_deadline: at(10_000),
  };
  const fresh = () => createScenario({ begin: false });
  {
    const s = fresh();
    assert.throws(() => reserveChameleonManualAction(s.runtime, {
      ...base,
      capability_id: "CU-ADMIN-ARBITRARY-BUTTON",
    }, s.plan, s.grant.projection, s.pre, s.clock.sample(2_100)), /outside the reviewed closed registry/u);
  }
  {
    const s = fresh();
    assert.throws(() => reserveChameleonManualAction(s.runtime, {
      ...base,
      callback: () => true,
    }, s.plan, s.grant.projection, s.pre, s.clock.sample(2_100)), /callbacks|unknown fields/u);
  }
  {
    const s = fresh();
    assert.throws(() => reserveChameleonManualAction(s.runtime, {
      ...base,
      raw: Buffer.from("press"),
    }, s.plan, s.grant.projection, s.pre, s.clock.sample(2_100)), /raw byte material/u);
  }
  {
    const input = { ...base };
    Object.defineProperty(input, "rf_off_deadline", { enumerable: true, get() { return at(10_000); } });
    const s = fresh();
    assert.throws(() => reserveChameleonManualAction(s.runtime, input,
      s.plan, s.grant.projection, s.pre, s.clock.sample(2_100)), /enumerable data field/u);
  }
  {
    const s = fresh();
    const proxy = new Proxy({ ...base }, {});
    assert.throws(() => reserveChameleonManualAction(s.runtime, proxy,
      s.plan, s.grant.projection, s.pre, s.clock.sample(2_100)), /proxy/u);
  }
  {
    const s = fresh();
    const operatorPayload = createChameleonManualActionAcknowledgementPayload(
      s.reservation,
      "operator",
      at(2_200),
    );
    const witnessPayload = createChameleonManualActionAcknowledgementPayload(
      s.reservation,
      "witness",
      at(2_200),
    );
    const operatorReceipt = signManualPayload(
      operatorPayload,
      s.keys.operator,
      "signer-key:manual-operator",
      at(2_300),
    );
    const witnessReceipt = signManualPayload(
      witnessPayload,
      s.keys.witness,
      "signer-key:manual-witness",
      at(2_300),
    );
    assert.throws(() => beginChameleonManualAction(s.runtime, s.reservation, {
      version: 1,
      operator_acknowledgement: new Proxy(operatorReceipt, {}),
      witness_acknowledgement: witnessReceipt,
    }, s.clock.sample(2_500)), /proxy/u);
  }
  assert.equal(scenario.runtime.production_ready, false);
  assert.equal(scenario.runtime.hil_ready, false);
});

test("cloning or serializing runtime, reservation, execution, or terminal state loses authority", () => {
  const reserved = createScenario({ begin: false });
  const runtimeClone = structuredClone(reserved.runtime);
  assert.throws(() => reserveChameleonManualAction(runtimeClone, {
    version: 1,
    capability_id: CAPABILITY_ID,
    cohort_kind: "positive",
    operator_signer_key_id: "signer-key:manual-operator",
    witness_signer_key_id: "signer-key:manual-witness",
    witness_observer_id: "manual-witness",
    rf_off_deadline: at(10_000),
  }, reserved.plan, reserved.grant.projection, reserved.pre, reserved.clock.sample(2_100)),
  /privately branded/u);
  const reservationClone = structuredClone(reserved.reservation);
  const reservationJsonClone = JSON.parse(JSON.stringify(reserved.reservation));
  for (const clone of [reservationClone, reservationJsonClone]) {
    assert.throws(() => beginChameleonManualAction(reserved.runtime, clone, {
      version: 1,
      operator_acknowledgement: {},
      witness_acknowledgement: {},
    }, reserved.clock.sample(2_200)), /privately branded/u);
  }

  const scenario = createScenario();
  const fixture = completionFixture(scenario);
  const executionClone = structuredClone(scenario.execution);
  assert.throws(() => completeChameleonManualAction(
    scenario.runtime,
    executionClone,
    fixture.context,
    { version: 1, operator_receipt: fixture.operatorReceipt, witness_receipt: fixture.witnessReceipt },
    scenario.clock.sample(5_000),
  ), /privately branded/u);
  const terminal = completeScenario(scenario, fixture, 5_100);
  const terminalClone = JSON.parse(JSON.stringify(terminal));
  assert.throws(() => projectChameleonManualActionCleanupPayload(terminalClone, {
    version: 1,
    execution_receipt_ref: `physical-execution-receipt:v1:${"b".repeat(64)}`,
  }), /privately branded/u);
});

test("no agent-facing tool or generic physical-button surface is introduced", () => {
  const toolRegistry = require("../../../mcp/core/dispatch/tool-registry.js");
  const serializedTools = JSON.stringify(toolRegistry.TOOL_MANIFEST || toolRegistry);
  assert.equal(/manual[_-]?action|arbitrary[_-]?button|press[_-]?button/ui.test(serializedTools), false);
  const exported = Object.keys(manual).join("\n");
  assert.equal(/raw|path|pressButton|arbitraryButton|transport|sendCommand/u.test(exported), false);
});

test("PH-P9 HIL plan is exhaustive for the closed registry and has no execution mode", () => {
  const hil = require("../../../test/manual/chameleon-manual-actions.js");
  const plan = hil.buildPlan();
  assert.equal(plan.node_id, "PH-P9");
  assert.equal(plan.execution_policy.import_is_inert, true);
  assert.equal(plan.execution_policy.hardware_access_authorized, false);
  assert.equal(plan.execution_policy.production_ready, false);
  assert.equal(plan.execution_policy.hil_ready, false);
  assert.equal(plan.plan_digest, CHAMELEON_MANUAL_ACTION_HIL_PLAN_DIGEST);
  assert.equal(
    chameleonManualActionRuntimeReadiness().hil_plan_digest,
    CHAMELEON_MANUAL_ACTION_HIL_PLAN_DIGEST,
  );
  assert.ok(chameleonManualActionRuntimeReadiness().blockers.includes(
    "provider_private_production_composition_owner_not_installed",
  ));
  assert.ok(chameleonManualActionRuntimeReadiness().blockers.includes(
    "signed_hil_gate_evidence_not_ingested",
  ));
  assert.deepEqual(plan.scenarios.map((entry) => entry.capability_id).sort(),
    describeChameleonManualActions().actions.map((entry) => entry.capability_id).sort());
  assert.ok(plan.scenarios.every((entry) => (
    entry.required_evidence.includes("external_rf_off_before_deadline")
    && entry.required_evidence.includes("ordinary_ph_s6_execution_observation_cleanup_rows")
    && entry.evidence_state === "pending_real_hil"
  )));
  let stdout = "";
  let stderr = "";
  assert.equal(hil.runCli([], { write: (value) => { stdout += value; } }, {
    write: (value) => { stderr += value; },
  }), 0);
  assert.equal(stdout, "");
  assert.match(stderr, /inert/u);
  assert.equal(hil.runCli(["--execute"], { write() {} }, { write() {} }), 2);
  assert.equal(Object.isFrozen(plan), true);
});
