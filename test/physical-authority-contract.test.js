"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN,
  PHYSICAL_BOOTSTRAP_GRANT_DOMAIN,
  PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE,
  activePhysicalExecutionGrantSignatureInputDigest,
  assertVerifiedActivePhysicalExecutionGrant,
  assertVerifiedPhysicalBootstrapGrant,
  buildPhysicalEffectAuthorityTuples,
  createActivePhysicalExecutionGrantVerifier,
  createPhysicalBootstrapGrantVerifier,
  normalizeCleanupCapability,
  normalizeCleanupInvocation,
  normalizeMcpPhysicalExecutionRequest,
  normalizeOperatorMaintenanceRequest,
  normalizePhysicalEffectAuthorityRule,
  normalizePhysicalEffectAuthorityRules,
  physicalExecutionRequestDigest,
  physicalBootstrapGrantSignatureInputDigest,
  projectVerifiedActivePhysicalExecutionGrant,
  projectVerifiedPhysicalBootstrapGrant,
  resolvePhysicalEffectAuthority,
  resolvePhysicalRequestAuthority,
} = require("../mcp/domains/physical/physical-authority.js");
const {
  normalizePhysicalScopeNucleusAxis,
} = require("../mcp/core/governance/governance-contracts.js");
const {
  buildEffectTemplateRegistry,
} = require("../mcp/core/requested-effects.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");
const {
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
} = require("../mcp/domains/physical/physical-trusted-clock.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function signedTrustedClockFixture(options = {}) {
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const control = {
    monotonic_ms: options.monotonicMs == null ? 1_000 : options.monotonicMs,
    mapping: null,
    trust: null,
  };
  const payload = {
    version: 1,
    clock_id: options.clockId || "physical-clock:grant-verifier-test-1",
    monotonic_epoch_id: digest(options.monotonicEpoch || "grant-verifier-monotonic-epoch-1"),
    mapping_generation: 1,
    reference_monotonic_ms: control.monotonic_ms,
    reference_utc: options.now || "2026-07-18T00:00:10.000Z",
    max_uncertainty_ms: options.uncertaintyMs == null ? 1_000 : options.uncertaintyMs,
    not_before: "2026-07-17T23:00:00.000Z",
    expires_at: "2026-07-18T01:00:00.000Z",
    trust_root_epoch: 4,
    authority_epoch: 7,
    revocation_generation: 2,
    signer_key_id: "clock-key:grant-verifier-test-1",
    signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
  };
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockMappingSigningMessage(payloadDigest),
    keyPair.privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: TRUSTED_CLOCK_MAPPING_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  control.mapping = {
    ...basis,
    signed_mapping_digest: hashCanonicalJson(basis),
  };
  control.trust = {
    version: 1,
    trusted: true,
    revoked: false,
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    current_mapping_generation: payload.mapping_generation,
    current_signed_mapping_digest: control.mapping.signed_mapping_digest,
    trust_root_epoch: payload.trust_root_epoch,
    authority_epoch: payload.authority_epoch,
    revocation_generation: payload.revocation_generation,
    signer_key_id: payload.signer_key_id,
    signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
    public_key: keyPair.publicKey,
  };
  const port = createPhysicalTrustedClockPort({
    port_id: options.portId || "grant_verifier_clock_port",
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: options.uncertaintyCeilingMs == null
      ? 60_000
      : options.uncertaintyCeilingMs,
    read_monotonic_ms: () => control.monotonic_ms,
    read_signed_mapping: () => control.mapping,
    resolve_current_trust: () => control.trust,
  });
  return { control, keyPair, port };
}

function template(templateId, subjectKind, action, channel, persistence) {
  return {
    version: 1,
    template_id: templateId,
    subject_kind: subjectKind,
    action,
    channel,
    persistence,
    bounds: {},
  };
}

function fixtureRegistry() {
  return buildEffectTemplateRegistry([
    template("instrument.observe.usb.v1", "instrument", "observe", "usb", "none"),
    template("instrument.configure.usb.v1", "instrument", "configure", "usb", "persistent"),
    template("instrument.transmit.rf.v1", "instrument", "transmit", "rf", "ephemeral"),
    template("instrument.administer.usb.v1", "instrument", "administer", "usb", "persistent"),
    template("instrument.destroy.usb.v1", "instrument", "destroy", "usb", "irreversible"),
    template("target.transmit.rf.v1", "target", "transmit", "rf", "ephemeral"),
    template("target.mutate.contact.v1", "target", "mutate", "contact", "persistent"),
    template("environment.actuate.gpio.v1", "environment", "actuate", "gpio", "ephemeral"),
  ]);
}

function requestedEffect(registry, templateId, subjectRef) {
  const effectTemplate = registry.get(templateId);
  return {
    version: 1,
    template_id: effectTemplate.template_id,
    template_digest: effectTemplate.template_digest,
    subject_ref: subjectRef,
    subject_kind: effectTemplate.subject_kind,
    action: effectTemplate.action,
    channel: effectTemplate.channel,
    persistence: effectTemplate.persistence,
    bounds: {},
  };
}

function commonRequest(grantKind, effects) {
  return {
    version: 1,
    grant_kind: grantKind,
    session_id: "session-physical-1",
    session_nucleus_hash: digest("session-nucleus"),
    caller_role_id: grantKind === "maintenance" ? "operator" : "orchestrator",
    requester_principal_id: grantKind === "maintenance" ? "principal:operator-1" : "principal:agent-1",
    ipc_peer_principal_id: grantKind === "maintenance" ? "principal:operator-peer-1" : "principal:mcp-peer-1",
    execution_principal_id: "principal:physical-worker-1",
    instrument_ref: "instrument:owned-reader-1",
    operation_id: `${grantKind}.operation.v1`,
    parameter_digest: digest(`${grantKind}-parameters`),
    authority_epoch: 7,
    revocation_generation: 2,
    nonce: `${grantKind}-nonce-1`,
    sequence: 11,
    not_before: "2026-07-18T00:00:00.000Z",
    expires_at: "2026-07-18T00:01:00.000Z",
    requested_effects: effects,
  };
}

function bootstrapRequest(registry) {
  return {
    ...commonRequest("bootstrap", [
      requestedEffect(registry, "instrument.observe.usb.v1", "instrument:owned-reader-1"),
    ]),
    enrollment_candidate_ref: "enrollment-candidate:reader-1",
    bootstrap_manifest_digest: digest("bootstrap-manifest"),
    provider_binary_digest: digest("provider-binary"),
    transport_digest: digest("transport"),
    rf_state: "off",
  };
}

function preparationRequest(registry) {
  return {
    ...commonRequest("preparation", [
      requestedEffect(registry, "instrument.configure.usb.v1", "instrument:owned-reader-1"),
    ]),
    bootstrap_receipt_ref: "bootstrap-receipt:reader-1",
    bootstrap_execution_request_digest: digest("bootstrap-request"),
    bootstrap_inventory_observation_ref: "inventory-observation:reader-bootstrap-1",
    bootstrap_inventory_digest: digest("bootstrap-inventory"),
    assurance_profile_id: "physical-assurance-v1",
    assurance_claims_digest: digest("assurance-claims"),
    provider_manifest_digest: digest("provider-manifest"),
    preparation_plan_digest: digest("preparation-plan"),
    snapshot_plan_digest: digest("snapshot-plan"),
    rf_state: "off",
  };
}

function activeExecutionLineage(overrides = {}) {
  const compiledCommandDigest = digest("compiled-command-capability");
  return {
    version: 1,
    compiler_id: "closed_physical_compiler_v1",
    compiler_manifest_digest: digest("compiler-manifest"),
    compiler_registry_digest: digest("compiler-registry"),
    compiled_command_id: "compiled-command:active-test-1",
    compiled_command_capability_digest: compiledCommandDigest,
    compiled_operation_digest: digest("compiled-operation"),
    provider_command_ref: "command:active-test-1",
    command_input_ref: "command-input:active-test-1",
    command_input_digest: compiledCommandDigest,
    maximum_response_bytes: 64,
    vault_reservation_handle: `vault-reservation:v1:${"A".repeat(43)}`,
    vault_reservation_digest: digest("vault-reservation"),
    vault_ingest_capability_digest: digest("vault-ingest-capability"),
    vault_byte_limit: 64,
    worker_bundle_digest: digest("worker-bundle"),
    worker_launch_profile_digest: digest("worker-launch-profile"),
    worker_fence_plan_digest: digest("worker-fence-plan"),
    transport_profile_digest: digest("transport-profile"),
    durable_exchange_plan_digest: digest("durable-exchange-plan"),
    terminal_receipt_recipient_digest: digest("terminal-receipt-recipient"),
    safety_supervisor_plan_digest: digest("safety-supervisor-plan"),
    ...overrides,
  };
}

function activeRequest(registry, effects = null) {
  return {
    ...commonRequest("active", effects || [
      requestedEffect(registry, "target.transmit.rf.v1", "target:owned-card-1"),
    ]),
    node_id: "PH-C1-cell-1",
    contract_hash: digest("node-contract"),
    prep_token_hash: digest("prep-token"),
    dispatch_event_id: "dispatch-event-1",
    graph_context_hash: digest("graph-context"),
    capability_pack_id: "physical.rfid.v1",
    capability_pack_version: "1.0.0",
    capability_pack_digest: digest("capability-pack"),
    technique_cell_id: "rfid.replay.cell-1",
    attempt_id: "physical-attempt-1",
    experiment_plan_hash: digest("experiment-plan"),
    inventory_observation_ref: "inventory-observation:reader-active-1",
    inventory_observation_digest: digest("inventory-observation"),
    assurance_profile_id: "physical-assurance-v1",
    assurance_claims_digest: digest("assurance-claims"),
    provider_manifest_digest: digest("provider-manifest"),
    availability_variant_id: "target-transmit-rf-v1",
    availability_variant_digest: digest("availability-variant"),
    authorized_transition_set_digest: digest("authorized-transition-set"),
    resource_bundle_digest: digest("resource-bundle"),
    fencing_token: "fence-token-1",
    lease_id: "instrument-lease-1",
    workspace_snapshot_ref: "workspace-snapshot:reader-1",
    workspace_snapshot_digest: digest("workspace-snapshot"),
    observer_plan_digest: digest("observer-plan"),
    control_plan_digest: digest("control-plan"),
    cleanup_plan_digest: digest("cleanup-plan"),
    execution_lineage: activeExecutionLineage(),
  };
}

function maintenanceRequest(registry, effectTemplate = "instrument.administer.usb.v1") {
  return {
    ...commonRequest("maintenance", [
      requestedEffect(registry, effectTemplate, "instrument:owned-reader-1"),
    ]),
    owned_fixture_ref: "instrument:owned-reader-1",
    ownership_attestation_digest: digest("fixture-ownership"),
    pre_state_ref: "pre-state:reader-1",
    pre_state_digest: digest("pre-state"),
    backup_ref: "backup:reader-1",
    backup_digest: digest("backup"),
    exact_state_delta_digest: digest("exact-state-delta"),
    expected_terminal_state_digest: digest("expected-terminal-state"),
    post_operation_inventory_plan_digest: digest("post-inventory-plan"),
    assurance_invalidation_plan_digest: digest("assurance-invalidation-plan"),
    recovery_or_quarantine_plan_digest: digest("recovery-or-quarantine-plan"),
    hil_plan_digest: digest("maintenance-hil-plan"),
    terminal_custody: effectTemplate.includes("destroy") ? "disposal" : "operator",
  };
}

function cleanupCapability(registry, effectTemplate = "instrument.configure.usb.v1") {
  return {
    version: 1,
    capability_kind: "cleanup",
    root_kind: "cleanup_safety",
    nondelegable: true,
    agent_requestable: false,
    safety_root_ref: "safety-root:physical-1",
    source_execution_request_digest: digest("active-request"),
    session_id: "session-physical-1",
    instrument_ref: "instrument:owned-reader-1",
    recovery_principal_id: "principal:cleanup-worker-1",
    lease_id: "instrument-lease-1",
    fencing_token: "fence-token-1",
    workspace_snapshot_ref: "workspace-snapshot:reader-1",
    workspace_snapshot_digest: digest("workspace-snapshot"),
    restore_operation_id: "instrument.restore.v1",
    restore_operation_digest: digest("restore-operation"),
    cleanup_plan_digest: digest("cleanup-plan"),
    terminal_emission_state: "inhibited",
    allowed_terminal_states: ["quarantined", "restored"],
    capability_nonce: "cleanup-capability-nonce-1",
    requested_effects: [
      requestedEffect(registry, effectTemplate, "instrument:owned-reader-1"),
    ],
  };
}

function cleanupInvocation(capability) {
  return {
    version: 1,
    capability_digest: capability.capability_digest,
    safety_root_ref: capability.safety_root_ref,
    recovery_principal_id: capability.recovery_principal_id,
    source_execution_request_digest: capability.source_execution_request_digest,
    instrument_ref: capability.instrument_ref,
    lease_id: capability.lease_id,
    fencing_token: capability.fencing_token,
    workspace_snapshot_ref: capability.workspace_snapshot_ref,
    workspace_snapshot_digest: capability.workspace_snapshot_digest,
    restore_operation_id: capability.restore_operation_id,
    restore_operation_digest: capability.restore_operation_digest,
    cleanup_plan_digest: capability.cleanup_plan_digest,
    terminal_emission_state: capability.terminal_emission_state,
    requested_effects: capability.requested_effects,
  };
}

function authorityRule(ruleId, decision, tuple) {
  return {
    version: 1,
    rule_id: ruleId,
    decision,
    tuple,
  };
}

function activeGrantAxis(overrides = {}) {
  return normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "physical-authority-test-v1",
    policy_digest: digest("active-grant-policy"),
    projection_version: 1,
    projection_digest: digest("active-grant-scope-projection"),
    provenance_digest: digest("active-grant-scope-provenance"),
    compatibility_digest: digest("active-grant-scope-compatibility"),
    transition_receipt_registry_digest: digest("active-grant-transition-registry"),
    authority_epoch: 7,
    revocation_generation: 2,
    ...overrides,
  });
}

function replayReservationResult(claim, options = {}) {
  const generation = options.generation || 1;
  const receiptBasis = {
    version: 1,
    reservation_ref: options.reservationRef
      || `grant-replay-reservation:${hashCanonicalJson(claim).slice(0, 40)}`,
    replay_claim: claim,
    replay_claim_digest: hashCanonicalJson(claim),
    generation,
    previous_receipt_digest: generation === 1
      ? null
      : options.previousReceiptDigest || digest(`replay-receipt-${generation - 1}`),
    reserved_at: options.reservedAt || "2026-07-18T00:00:10.000Z",
    fsynced_at: options.fsyncedAt || "2026-07-18T00:00:10.000Z",
    ...(options.receipt || {}),
  };
  return {
    version: 1,
    disposition: options.disposition || "created",
    reservation_receipt: {
      ...receiptBasis,
      receipt_digest: hashCanonicalJson(receiptBasis),
      ...(options.receiptEnvelope || {}),
    },
  };
}

function activeGrantFixture(options = {}) {
  const registry = fixtureRegistry();
  const request = normalizeMcpPhysicalExecutionRequest(activeRequest(registry), registry);
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const issuerPublicKeyDigest = crypto.createHash("sha256").update(
    keyPair.publicKey.export({ type: "spki", format: "der" }),
  ).digest("hex");
  const authority = {
    version: 1,
    session_id: request.session_id,
    session_nucleus_hash: request.session_nucleus_hash,
    execution_request_digest: request.execution_request_digest,
    physical_scope_axis: activeGrantAxis(),
    authority_decision: "allow",
    authority_reason: "exact_allow",
    authority_resolution_digest: digest("active-grant-exact-authority-resolution"),
    trust_root_id: "trust-root:physical-authority-test",
    trust_root_epoch: 4,
    trust_registry_digest: digest("active-grant-trust-registry"),
    trust_root_trusted: true,
    trust_root_revoked: false,
    issuer_principal_id: "principal:physical-authority-issuer",
    issuer_key_id: "signer-key:physical-authority-test",
    issuer_epoch: 3,
    issuer_public_key_digest: issuerPublicKeyDigest,
    key_usage: "physical_active_grant_signing",
    issuer_trusted: true,
    issuer_revoked: false,
    ...(options.authority || {}),
  };
  let now = options.now || "2026-07-18T00:00:10.000Z";
  const reservationNow = options.reservationNow || now;
  const replayClaims = options.replayClaims || new Map();
  let reserveReplayCallCount = 0;
  let verifyEd25519CallCount = 0;
  const verifyEd25519 = options.verifyEd25519 || ((verification) => crypto.verify(
    null,
    Buffer.from(verification.signature_input_digest, "hex"),
    keyPair.publicKey,
    Buffer.from(verification.signature, "base64url"),
  ));
  const reserveReplay = options.reserveReplay || ((claim) => {
    const existing = [...replayClaims.values()].find((prior) => {
      const priorClaim = prior.reservation_receipt.replay_claim;
      return priorClaim.grant_ref === claim.grant_ref
        || priorClaim.execution_request_digest === claim.execution_request_digest;
    });
    if (existing) {
      if (hashCanonicalJson(existing.reservation_receipt.replay_claim) !== hashCanonicalJson(claim)) {
        throw new Error("replay reservation uniqueness conflict");
      }
      return { ...existing, disposition: "existing_same" };
    }
    const previous = [...replayClaims.values()].at(-1);
    const result = replayReservationResult(claim, {
      generation: replayClaims.size + 1,
      previousReceiptDigest: previous == null ? null : previous.reservation_receipt.receipt_digest,
      reservedAt: reservationNow,
      fsyncedAt: reservationNow,
    });
    replayClaims.set(claim.grant_ref, result);
    return result;
  });
  const verifierInput = {
    verifier_id: options.verifierId || "physical-active-grant-verifier-v1",
    resolve_current_authority: () => authority,
    verify_ed25519: (verification) => {
      verifyEd25519CallCount += 1;
      return verifyEd25519(verification);
    },
    reserve_replay: (claim) => {
      reserveReplayCallCount += 1;
      return reserveReplay(claim);
    },
  };
  if (options.trustedClockPort) {
    verifierInput.trusted_clock_port = options.trustedClockPort;
  } else {
    verifierInput.trusted_now = () => now;
  }
  const verifier = createActivePhysicalExecutionGrantVerifier(verifierInput);
  const bindings = {
    execution_request: request,
    effect_registry: registry,
    provider_id: "deterministic.physical.v1",
    provider_descriptor_digest: digest("active-grant-provider-descriptor"),
    operation_digest: digest("active-grant-operation"),
    fencing_generation: 1,
  };
  return {
    registry,
    request,
    keyPair,
    authority,
    verifier,
    bindings,
    replayClaims,
    getReserveReplayCallCount() {
      return reserveReplayCallCount;
    },
    getVerifyEd25519CallCount() {
      return verifyEd25519CallCount;
    },
    setNow(value) {
      now = value;
    },
  };
}

function signedActiveGrant(fixture, options = {}) {
  const { request, authority, bindings } = fixture;
  const axis = authority.physical_scope_axis;
  const payload = {
    version: 1,
    grant_kind: "active",
    grant_ref: options.grantRef || "physical-grant:active-authority-test-1",
    session_id: request.session_id,
    session_nucleus_hash: request.session_nucleus_hash,
    physical_scope_axis_digest: axis.axis_digest,
    physical_scope_policy_id: axis.policy_id,
    physical_scope_policy_digest: axis.policy_digest,
    physical_scope_projection_digest: axis.projection_digest,
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
    authority_decision: authority.authority_decision,
    authority_reason: authority.authority_reason,
    authority_resolution_digest: authority.authority_resolution_digest,
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
    ...(options.payload || {}),
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
    signed_at: options.signedAt || "2026-07-18T00:00:05.000Z",
    signed_payload_digest: hashCanonicalJson(payload),
    ...(options.authentication || {}),
  };
  const signatureInputDigest = activePhysicalExecutionGrantSignatureInputDigest(payload, authentication);
  const signature = crypto.sign(
    null,
    Buffer.from(signatureInputDigest, "hex"),
    fixture.keyPair.privateKey,
  ).toString("base64url");
  return {
    version: 1,
    kind: "active_physical_execution_grant",
    domain: ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN,
    payload,
    authentication: { ...authentication, signature },
    ...(options.envelope || {}),
  };
}

function brokerExpectedBindings(fixture) {
  return {
    execution_request_digest: fixture.request.execution_request_digest,
    authority_resolution_digest: fixture.authority.authority_resolution_digest,
    execution_principal_id: fixture.request.execution_principal_id,
    provider_id: fixture.bindings.provider_id,
    provider_descriptor_digest: fixture.bindings.provider_descriptor_digest,
    instrument_ref: fixture.request.instrument_ref,
    operation_id: fixture.request.operation_id,
    operation_digest: fixture.bindings.operation_digest,
    attempt_id: fixture.request.attempt_id,
    experiment_plan_hash: fixture.request.experiment_plan_hash,
    execution_lineage_digest: fixture.request.execution_lineage.execution_lineage_digest,
    lease_id: fixture.request.lease_id,
    fencing_token: fixture.request.fencing_token,
    fencing_generation: fixture.bindings.fencing_generation,
    resource_bundle_digest: fixture.request.resource_bundle_digest,
  };
}

function bootstrapGrantFixture(options = {}) {
  const registry = fixtureRegistry();
  const request = normalizeMcpPhysicalExecutionRequest(bootstrapRequest(registry), registry);
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const issuerPublicKeyDigest = crypto.createHash("sha256").update(
    keyPair.publicKey.export({ type: "spki", format: "der" }),
  ).digest("hex");
  const bindings = {
    execution_request: request,
    effect_registry: registry,
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: digest("bootstrap-provider-descriptor"),
    operation_digest: digest("bootstrap-operation"),
    bootstrap_invariants_digest: digest("bootstrap-invariants"),
  };
  const axis = activeGrantAxis();
  const authority = {
    version: 1,
    session_id: request.session_id,
    session_nucleus_hash: request.session_nucleus_hash,
    execution_request_digest: request.execution_request_digest,
    physical_scope_axis: axis,
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
    authority_decision: "allow",
    authority_reason: "exact_allow",
    authority_resolution_digest: digest("bootstrap-exact-authority-resolution"),
    trust_root_id: "trust-root:physical-bootstrap-test",
    trust_root_epoch: 5,
    trust_registry_digest: digest("bootstrap-trust-registry"),
    trust_root_trusted: true,
    trust_root_revoked: false,
    issuer_principal_id: "principal:physical-bootstrap-issuer",
    issuer_key_id: "signer-key:physical-bootstrap-test",
    issuer_epoch: 4,
    issuer_public_key_digest: issuerPublicKeyDigest,
    key_usage: PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE,
    issuer_trusted: true,
    issuer_revoked: false,
    ...(options.authority || {}),
  };
  let now = options.now || "2026-07-18T00:00:10.000Z";
  const reservationNow = options.reservationNow || now;
  const replayClaims = options.replayClaims || new Map();
  let verifyCount = 0;
  let reserveCount = 0;
  const verifyEd25519 = options.verifyEd25519 || ((verification) => crypto.verify(
    null,
    Buffer.from(verification.signature_input_digest, "hex"),
    keyPair.publicKey,
    Buffer.from(verification.signature, "base64url"),
  ));
  const reserveReplay = options.reserveReplay || ((claim) => {
    const existing = [...replayClaims.values()].find((prior) => {
      const priorClaim = prior.reservation_receipt.replay_claim;
      return priorClaim.grant_ref === claim.grant_ref
        || priorClaim.execution_request_digest === claim.execution_request_digest;
    });
    if (existing) return { ...existing, disposition: "existing_same" };
    const previous = [...replayClaims.values()].at(-1);
    const reservation = replayReservationResult(claim, {
      generation: replayClaims.size + 1,
      reservationRef: `bootstrap-grant-replay-reservation:${hashCanonicalJson(claim).slice(0, 40)}`,
      previousReceiptDigest: previous == null ? null : previous.reservation_receipt.receipt_digest,
      reservedAt: reservationNow,
      fsyncedAt: reservationNow,
    });
    replayClaims.set(claim.grant_ref, reservation);
    return reservation;
  });
  const verifierInput = {
    verifier_id: options.verifierId || "physical-bootstrap-grant-verifier-v1",
    resolve_current_authority: () => authority,
    verify_ed25519: (verification) => {
      verifyCount += 1;
      return verifyEd25519(verification);
    },
    reserve_replay: (claim) => {
      reserveCount += 1;
      return reserveReplay(claim);
    },
  };
  if (options.trustedClockPort) {
    verifierInput.trusted_clock_port = options.trustedClockPort;
  } else {
    verifierInput.trusted_now = () => now;
  }
  const verifier = createPhysicalBootstrapGrantVerifier(verifierInput);
  return {
    registry,
    request,
    keyPair,
    bindings,
    authority,
    verifier,
    replayClaims,
    setNow(value) {
      now = value;
    },
    getVerifyCount() {
      return verifyCount;
    },
    getReserveCount() {
      return reserveCount;
    },
  };
}

function signedBootstrapGrant(fixture, options = {}) {
  const { request, authority, bindings } = fixture;
  const axis = authority.physical_scope_axis;
  const payload = {
    version: 1,
    grant_kind: "bootstrap",
    grant_ref: options.grantRef || "physical-grant:bootstrap-authority-test-1",
    session_id: request.session_id,
    session_nucleus_hash: request.session_nucleus_hash,
    physical_scope_axis_digest: axis.axis_digest,
    physical_scope_policy_id: axis.policy_id,
    physical_scope_policy_digest: axis.policy_digest,
    physical_scope_projection_digest: axis.projection_digest,
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
    authority_decision: authority.authority_decision,
    authority_reason: authority.authority_reason,
    authority_resolution_digest: authority.authority_resolution_digest,
    not_before: request.not_before,
    expires_at: request.expires_at,
    ...(options.payload || {}),
  };
  const authentication = {
    version: 1,
    method: "ed25519",
    key_usage: PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE,
    trust_root_id: authority.trust_root_id,
    trust_root_epoch: authority.trust_root_epoch,
    trust_registry_digest: authority.trust_registry_digest,
    issuer_principal_id: authority.issuer_principal_id,
    issuer_key_id: authority.issuer_key_id,
    issuer_epoch: authority.issuer_epoch,
    issuer_public_key_digest: authority.issuer_public_key_digest,
    signed_at: options.signedAt || "2026-07-18T00:00:05.000Z",
    signed_payload_digest: hashCanonicalJson(payload),
    ...(options.authentication || {}),
  };
  const signatureInputDigest = physicalBootstrapGrantSignatureInputDigest(payload, authentication);
  const signature = crypto.sign(
    null,
    Buffer.from(signatureInputDigest, "hex"),
    fixture.keyPair.privateKey,
  ).toString("base64url");
  return {
    version: 1,
    kind: "physical_bootstrap_grant",
    domain: PHYSICAL_BOOTSTRAP_GRANT_DOMAIN,
    payload,
    authentication: { ...authentication, signature },
    ...(options.envelope || {}),
  };
}

function bootstrapExpectedBindings(fixture) {
  return {
    execution_request_digest: fixture.request.execution_request_digest,
    provider_id: fixture.bindings.provider_id,
    provider_descriptor_digest: fixture.bindings.provider_descriptor_digest,
    bootstrap_manifest_digest: fixture.request.bootstrap_manifest_digest,
    provider_binary_digest: fixture.request.provider_binary_digest,
    transport_digest: fixture.request.transport_digest,
    operation_id: fixture.request.operation_id,
    operation_digest: fixture.bindings.operation_digest,
    bootstrap_invariants_digest: fixture.bindings.bootstrap_invariants_digest,
  };
}

test("bootstrap request input is closed, unsigned, stable, read-only, and has no circular prior state", () => {
  const registry = fixtureRegistry();
  const input = bootstrapRequest(registry);
  const normalized = normalizeMcpPhysicalExecutionRequest(input, registry);

  assert.equal(normalized.grant_kind, "bootstrap");
  assert.equal(normalized.request_path, "mcp");
  assert.equal(normalized.execution_request_digest, physicalExecutionRequestDigest(input, registry));
  assert.equal(normalized.execution_request_digest, normalizeMcpPhysicalExecutionRequest({
    ...Object.fromEntries(Object.entries(input).reverse()),
  }, registry).execution_request_digest);
  assert.equal(normalizeMcpPhysicalExecutionRequest(normalized, registry).execution_request_digest,
    normalized.execution_request_digest, "normalized requests round-trip without digest drift");
  assert.equal(Object.isFrozen(normalized), true);
  assert.equal(Object.isFrozen(normalized.requested_effects[0]), true);
  assert.equal("signature" in normalized, false);

  assert.throws(
    () => normalizeMcpPhysicalExecutionRequest({
      ...input,
      inventory_observation_ref: "inventory-observation:impossible-prior-state",
    }, registry),
    /unknown fields: inventory_observation_ref/,
  );
  assert.throws(
    () => normalizeMcpPhysicalExecutionRequest({ ...input, signature: "agent-forged" }, registry),
    /unknown fields: signature/,
  );
  assert.throws(
    () => normalizeMcpPhysicalExecutionRequest({
      ...input,
      requested_effects: [requestedEffect(registry, "target.transmit.rf.v1", "target:owned-card-1")],
    }, registry),
    /must bind exactly to instrument/,
  );
  assert.throws(
    () => normalizeMcpPhysicalExecutionRequest({
      ...input,
      requested_effects: [requestedEffect(registry, "environment.actuate.gpio.v1", "environment:lab-zone-1")],
    }, registry),
    /must bind exactly to instrument/,
  );
  assert.throws(
    () => normalizeMcpPhysicalExecutionRequest({ ...input, rf_state: "on" }, registry),
    /rf_state must be off/,
  );
});

test("a signed bootstrap grant projects one signature-free branded authority with exact bindings", () => {
  const fixture = bootstrapGrantFixture();
  const signed = signedBootstrapGrant(fixture);
  const projection = projectVerifiedPhysicalBootstrapGrant(
    signed,
    fixture.verifier,
    fixture.bindings,
  );
  assert.equal(projection.grant_kind, "bootstrap");
  assert.equal(projection.provider_id, "chameleon_ultra");
  assert.equal(projection.execution_request_digest, fixture.request.execution_request_digest);
  assert.equal(projection.request_path, "mcp");
  assert.deepEqual(projection.requested_effects, fixture.request.requested_effects);
  assert.equal(projection.bootstrap_invariants_digest, fixture.bindings.bootstrap_invariants_digest);
  assert.equal(Object.isFrozen(projection), true);
  assert.match(projection.replay_reservation_receipt_digest, /^[a-f0-9]{64}$/);
  assert.equal(Object.prototype.hasOwnProperty.call(projection, "authentication"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(projection, "signature"), false);
  assert.equal(JSON.stringify(projection).includes(signed.authentication.signature), false);
  assert.equal(
    assertVerifiedPhysicalBootstrapGrant(
      projection,
      fixture.verifier,
      bootstrapExpectedBindings(fixture),
    ),
    projection,
  );
  assert.equal(fixture.getVerifyCount(), 1);
  assert.equal(fixture.getReserveCount(), 1);
  assert.equal(fixture.replayClaims.size, 1);
  assert.throws(
    () => assertVerifiedPhysicalBootstrapGrant(
      { ...projection },
      fixture.verifier,
      bootstrapExpectedBindings(fixture),
    ),
    /was not issued by the configured verifier/,
  );
  const other = bootstrapGrantFixture({ verifierId: "other-bootstrap-grant-verifier-v1" });
  assert.throws(
    () => assertVerifiedPhysicalBootstrapGrant(
      projection,
      other.verifier,
      bootstrapExpectedBindings(fixture),
    ),
    /was not issued by the configured verifier/,
  );
});

test("bootstrap signature, scope, authority, trust, time, and provider bindings fail closed", () => {
  {
    const fixture = bootstrapGrantFixture();
    const signed = signedBootstrapGrant(fixture);
    signed.payload = { ...signed.payload, transport_digest: digest("tampered-transport") };
    fixture.authority.transport_digest = signed.payload.transport_digest;
    signed.authentication = {
      ...signed.authentication,
      signed_payload_digest: hashCanonicalJson(signed.payload),
    };
    assert.throws(
      () => projectVerifiedPhysicalBootstrapGrant(signed, fixture.verifier, fixture.bindings),
      /Ed25519 signature verification failed/,
    );
  }
  {
    const fixture = bootstrapGrantFixture();
    assert.throws(
      () => projectVerifiedPhysicalBootstrapGrant(
        signedBootstrapGrant(fixture, {
          envelope: { domain: ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN },
        }),
        fixture.verifier,
        fixture.bindings,
      ),
      /signature domain/,
    );
  }
  for (const [name, mutate, pattern] of [
    ["scope epoch", (fixture) => {
      fixture.authority.physical_scope_axis = activeGrantAxis({ authority_epoch: 8 });
    }, /physical_scope_axis_digest does not match|authority_epoch does not match/],
    ["revocation generation", (fixture) => {
      fixture.authority.physical_scope_axis = activeGrantAxis({ revocation_generation: 3 });
    }, /physical_scope_axis_digest does not match|revocation_generation does not match/],
    ["authority withdrawn", (fixture) => {
      fixture.authority.authority_decision = "deny";
    }, /authority_decision must be one of allow/],
    ["trust root revoked", (fixture) => {
      fixture.authority.trust_root_revoked = true;
    }, /trust root is not currently usable/],
    ["issuer revoked", (fixture) => {
      fixture.authority.issuer_revoked = true;
    }, /issuer is not currently usable/],
    ["key usage substitution", (fixture) => {
      fixture.authority.key_usage = "physical_active_grant_signing";
    }, /key_usage must be one of physical_bootstrap_grant_signing/],
    ["provider descriptor drift", (fixture) => {
      fixture.authority.provider_descriptor_digest = digest("replacement-provider-descriptor");
    }, /provider_descriptor_digest does not match/],
    ["manifest drift", (fixture) => {
      fixture.authority.bootstrap_manifest_digest = digest("replacement-bootstrap-manifest");
    }, /bootstrap_manifest_digest does not match/],
    ["binary drift", (fixture) => {
      fixture.authority.provider_binary_digest = digest("replacement-provider-binary");
    }, /provider_binary_digest does not match/],
    ["transport drift", (fixture) => {
      fixture.authority.transport_digest = digest("replacement-transport");
    }, /transport_digest does not match/],
    ["operation drift", (fixture) => {
      fixture.authority.operation_digest = digest("replacement-operation");
    }, /operation_digest does not match/],
  ]) {
    const fixture = bootstrapGrantFixture();
    mutate(fixture);
    assert.throws(
      () => projectVerifiedPhysicalBootstrapGrant(
        signedBootstrapGrant(fixture),
        fixture.verifier,
        fixture.bindings,
      ),
      pattern,
      name,
    );
    assert.equal(fixture.replayClaims.size, 0, `${name} fails before replay reservation`);
  }
  {
    const fixture = bootstrapGrantFixture();
    assert.throws(
      () => projectVerifiedPhysicalBootstrapGrant(
        signedBootstrapGrant(fixture),
        fixture.verifier,
        { ...fixture.bindings, provider_id: "other_provider" },
      ),
      /provider_id does not match the trusted bootstrap binding/,
    );
  }
  {
    const fixture = bootstrapGrantFixture({ now: "2026-07-18T00:01:00.000Z" });
    assert.throws(
      () => projectVerifiedPhysicalBootstrapGrant(
        signedBootstrapGrant(fixture),
        fixture.verifier,
        fixture.bindings,
      ),
      /has expired/,
    );
  }
});

test("bootstrap grants are one-shot, receipt-bound, and live-revalidated without repeating admission", () => {
  const fixture = bootstrapGrantFixture();
  const signed = signedBootstrapGrant(fixture);
  const projection = projectVerifiedPhysicalBootstrapGrant(
    signed,
    fixture.verifier,
    fixture.bindings,
  );
  assert.throws(
    () => projectVerifiedPhysicalBootstrapGrant(signed, fixture.verifier, fixture.bindings),
    /replay was rejected/,
  );
  assert.throws(
    () => projectVerifiedPhysicalBootstrapGrant(
      signedBootstrapGrant(fixture, { grantRef: "physical-grant:bootstrap-authority-test-2" }),
      fixture.verifier,
      fixture.bindings,
    ),
    /replay was rejected/,
  );
  fixture.authority.physical_scope_axis = activeGrantAxis({ revocation_generation: 3 });
  assert.throws(
    () => assertVerifiedPhysicalBootstrapGrant(
      projection,
      fixture.verifier,
      bootstrapExpectedBindings(fixture),
    ),
    /physical_scope_axis_digest does not match|revocation_generation does not match/,
  );
  assert.equal(fixture.getVerifyCount(), 3, "replay attempts recheck signatures before local election");
  assert.equal(fixture.getReserveCount(), 1);

  {
    const existing = bootstrapGrantFixture({
      reserveReplay: (claim) => replayReservationResult(claim, {
        disposition: "existing_same",
        reservationRef: `bootstrap-grant-replay-reservation:${hashCanonicalJson(claim).slice(0, 40)}`,
      }),
    });
    assert.throws(
      () => projectVerifiedPhysicalBootstrapGrant(
        signedBootstrapGrant(existing),
        existing.verifier,
        existing.bindings,
      ),
      /existing replay reservation requires unavailable durable admission rehydration/,
    );
  }
  {
    const malformed = bootstrapGrantFixture({
      reserveReplay: (claim) => replayReservationResult(claim, {
        reservationRef: `bootstrap-grant-replay-reservation:${hashCanonicalJson(claim).slice(0, 40)}`,
        receipt: { replay_claim: { ...claim, request_sequence: claim.request_sequence + 1 } },
      }),
    });
    assert.throws(
      () => projectVerifiedPhysicalBootstrapGrant(
        signedBootstrapGrant(malformed),
        malformed.verifier,
        malformed.bindings,
      ),
      /replay reservation failed closed/,
    );
  }
  {
    const notFsynced = bootstrapGrantFixture({
      reserveReplay: (claim) => replayReservationResult(claim, {
        reservationRef: `bootstrap-grant-replay-reservation:${hashCanonicalJson(claim).slice(0, 40)}`,
        reservedAt: "2026-07-18T00:00:10.001Z",
        fsyncedAt: "2026-07-18T00:00:10.000Z",
      }),
    });
    assert.throws(
      () => projectVerifiedPhysicalBootstrapGrant(
        signedBootstrapGrant(notFsynced),
        notFsynced.verifier,
        notFsynced.bindings,
      ),
      /replay reservation failed closed/,
    );
  }
  {
    const late = bootstrapGrantFixture({
      now: "2026-07-18T00:00:59.999Z",
      reserveReplay: (claim) => replayReservationResult(claim, {
        reservationRef: `bootstrap-grant-replay-reservation:${hashCanonicalJson(claim).slice(0, 40)}`,
        reservedAt: "2026-07-18T00:00:59.999Z",
        fsyncedAt: "2026-07-18T00:01:00.000Z",
      }),
    });
    assert.throws(
      () => projectVerifiedPhysicalBootstrapGrant(
        signedBootstrapGrant(late),
        late.verifier,
        late.bindings,
      ),
      /outside its trusted effect window/,
    );
  }
  {
    const badDigest = bootstrapGrantFixture({
      reserveReplay: (claim) => {
        const reservation = replayReservationResult(claim, {
          reservationRef: `bootstrap-grant-replay-reservation:${hashCanonicalJson(claim).slice(0, 40)}`,
        });
        reservation.reservation_receipt.receipt_digest = digest("tampered-bootstrap-receipt");
        return reservation;
      },
    });
    assert.throws(
      () => projectVerifiedPhysicalBootstrapGrant(
        signedBootstrapGrant(badDigest),
        badDigest.verifier,
        badDigest.bindings,
      ),
      /replay reservation failed closed/,
    );
  }
  {
    const rollback = bootstrapGrantFixture();
    assert.throws(
      () => projectVerifiedPhysicalBootstrapGrant(
        signedBootstrapGrant(rollback, { signedAt: "2026-07-18T00:00:11.000Z" }),
        rollback.verifier,
        rollback.bindings,
      ),
      /signed in the future/,
    );
    rollback.setNow("2026-07-18T00:00:09.000Z");
    assert.throws(
      () => projectVerifiedPhysicalBootstrapGrant(
        signedBootstrapGrant(rollback),
        rollback.verifier,
        rollback.bindings,
      ),
      /trusted clock moved backwards/,
    );
  }
});

test("preparation consumes bootstrap inventory, cannot presuppose its snapshot, and stays RF-off/no-target", () => {
  const registry = fixtureRegistry();
  const input = preparationRequest(registry);
  const normalized = normalizeMcpPhysicalExecutionRequest(input, registry);

  assert.equal(normalized.bootstrap_inventory_observation_ref, "inventory-observation:reader-bootstrap-1");
  assert.equal(normalized.rf_state, "off");
  assert.equal(normalized.requested_effects[0].subject_kind, "instrument");

  for (const field of [
    "bootstrap_receipt_ref",
    "bootstrap_execution_request_digest",
    "bootstrap_inventory_observation_ref",
    "bootstrap_inventory_digest",
  ]) {
    const invalid = { ...input };
    delete invalid[field];
    assert.throws(
      () => normalizeMcpPhysicalExecutionRequest(invalid, registry),
      new RegExp(`missing fields: ${field}`),
    );
  }
  assert.throws(
    () => normalizeMcpPhysicalExecutionRequest({
      ...input,
      workspace_snapshot_ref: "workspace-snapshot:not-yet-created",
    }, registry),
    /unknown fields: workspace_snapshot_ref/,
  );
  assert.throws(
    () => normalizeMcpPhysicalExecutionRequest({
      ...input,
      requested_effects: [requestedEffect(registry, "target.mutate.contact.v1", "target:owned-card-1")],
    }, registry),
    /must bind exactly to instrument/,
  );
  assert.throws(
    () => normalizeMcpPhysicalExecutionRequest({
      ...input,
      requested_effects: [requestedEffect(registry, "instrument.transmit.rf.v1", "instrument:owned-reader-1")],
    }, registry),
    /must remain RF-off/,
  );
});

test("active requests require every task, plan, state, resource, fence, observer, control, and effect binding", () => {
  const registry = fixtureRegistry();
  const input = activeRequest(registry);
  const normalized = normalizeMcpPhysicalExecutionRequest(input, registry);
  assert.equal(normalized.grant_kind, "active");
  assert.equal(normalized.requested_effects[0].subject_kind, "target");

  for (const field of [
    "node_id",
    "contract_hash",
    "experiment_plan_hash",
    "inventory_observation_ref",
    "workspace_snapshot_ref",
    "resource_bundle_digest",
    "fencing_token",
    "lease_id",
    "observer_plan_digest",
    "control_plan_digest",
    "cleanup_plan_digest",
    "requested_effects",
  ]) {
    const invalid = { ...input };
    delete invalid[field];
    assert.throws(
      () => normalizeMcpPhysicalExecutionRequest(invalid, registry),
      new RegExp(`missing fields: ${field}`),
      `active request missing ${field} must fail closed`,
    );
  }

  for (const field of Object.keys(activeExecutionLineage())) {
    const executionLineage = { ...input.execution_lineage };
    delete executionLineage[field];
    assert.throws(
      () => normalizeMcpPhysicalExecutionRequest({
        ...input,
        execution_lineage: executionLineage,
      }, registry),
      new RegExp(`missing fields: ${field}`),
      `active execution lineage missing ${field} must fail closed`,
    );
  }
  assert.throws(
    () => normalizeMcpPhysicalExecutionRequest({
      ...input,
      execution_lineage: activeExecutionLineage({
        maximum_response_bytes: 65,
        vault_byte_limit: 64,
      }),
    }, registry),
    /vault_byte_limit cannot strand the maximum provider response/,
  );

  assert.throws(
    () => normalizeMcpPhysicalExecutionRequest(activeRequest(registry, [
      requestedEffect(registry, "instrument.administer.usb.v1", "instrument:owned-reader-1"),
    ]), registry),
    /requires a separate operator maintenance request/,
  );
});

test("maintenance is operator-path-only, owned-fixture-bound, and carries terminal custody", () => {
  const registry = fixtureRegistry();
  const input = maintenanceRequest(registry);

  assert.throws(
    () => normalizeMcpPhysicalExecutionRequest(input, registry),
    /maintenance is operator-only and unavailable on the MCP request path/,
  );
  const normalized = normalizeOperatorMaintenanceRequest(input, registry);
  assert.equal(normalized.request_path, "operator_control");
  assert.equal(normalized.owned_fixture_ref, normalized.instrument_ref);
  assert.equal(normalized.terminal_custody, "operator");

  assert.throws(
    () => normalizeOperatorMaintenanceRequest({ ...input, caller_role_id: "orchestrator" }, registry),
    /caller_role_id must be operator/,
  );
  assert.throws(
    () => normalizeOperatorMaintenanceRequest({ ...input, owned_fixture_ref: "instrument:other-reader" }, registry),
    /owned_fixture_ref must match/,
  );
  assert.throws(
    () => normalizeOperatorMaintenanceRequest({
      ...input,
      requested_effects: [requestedEffect(registry, "target.mutate.contact.v1", "target:owned-card-1")],
    }, registry),
    /must bind exactly to instrument/,
  );

  const destroy = maintenanceRequest(registry, "instrument.destroy.usb.v1");
  assert.equal(normalizeOperatorMaintenanceRequest(destroy, registry).terminal_custody, "disposal");
  assert.throws(
    () => normalizeOperatorMaintenanceRequest({ ...destroy, terminal_custody: "operator" }, registry),
    /terminal_custody must be quarantine or disposal after destroy/,
  );
});

test("cleanup is a separately rooted, nondelegable exact snapshot/restore capability", () => {
  const registry = fixtureRegistry();
  assert.throws(
    () => normalizeMcpPhysicalExecutionRequest({ ...bootstrapRequest(registry), grant_kind: "cleanup" }, registry),
    /not an agent-requestable grant/,
  );

  const normalized = normalizeCleanupCapability(cleanupCapability(registry), registry);
  assert.equal(normalized.root_kind, "cleanup_safety");
  assert.equal(normalized.nondelegable, true);
  assert.equal(normalized.agent_requestable, false);
  assert.equal(normalized.terminal_emission_state, "inhibited");
  assert.equal(normalizeCleanupCapability(normalized, registry).capability_digest, normalized.capability_digest);

  const invocation = normalizeCleanupInvocation(cleanupInvocation(normalized), normalized, registry);
  assert.equal(invocation.capability_digest, normalized.capability_digest);
  assert.equal(Object.isFrozen(invocation), true);

  for (const [field, value] of [
    ["workspace_snapshot_ref", "workspace-snapshot:other"],
    ["workspace_snapshot_digest", digest("other-snapshot")],
    ["restore_operation_id", "instrument.restore.other.v1"],
    ["restore_operation_digest", digest("other-restore-operation")],
  ]) {
    assert.throws(
      () => normalizeCleanupInvocation({ ...cleanupInvocation(normalized), [field]: value }, normalized, registry),
      new RegExp(`${field} widens or redirects`),
    );
  }

  assert.throws(
    () => normalizeCleanupCapability(cleanupCapability(registry, "instrument.administer.usb.v1"), registry),
    /exceeds the precommitted local snapshot\/restore surface/,
  );
  assert.throws(
    () => normalizeCleanupCapability(cleanupCapability(registry, "instrument.destroy.usb.v1"), registry),
    /exceeds the precommitted local snapshot\/restore surface/,
  );
});

test("exact effect authority is fail-closed and an exact deny overrides an exact allow", () => {
  const registry = fixtureRegistry();
  const request = activeRequest(registry);
  const [tuple] = buildPhysicalEffectAuthorityTuples(request, registry);
  const allow = authorityRule("allow-exact", "allow", tuple);
  const deny = authorityRule("deny-exact", "deny", tuple);

  const allowed = resolvePhysicalEffectAuthority(tuple, [allow]);
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.reason, "exact_allow");

  const denied = resolvePhysicalEffectAuthority(tuple, [allow, deny]);
  assert.equal(denied.decision, "deny");
  assert.equal(denied.reason, "explicit_deny");
  assert.deepEqual(denied.matched_rule_ids, ["allow-exact", "deny-exact"]);

  const { tuple_digest: ignoredDigest, ...nearTuple } = tuple;
  void ignoredDigest;
  nearTuple.parameter_digest = digest("different-parameters");
  const irrelevantDeny = authorityRule("deny-near-miss", "deny", nearTuple);
  assert.equal(
    resolvePhysicalEffectAuthority(tuple, [allow, irrelevantDeny]).decision,
    "allow",
    "a deny is not wildcarded beyond its exact tuple",
  );

  const changedRequest = { ...request, parameter_digest: digest("different-parameters") };
  const noExactAllow = resolvePhysicalRequestAuthority(changedRequest, registry, [allow]);
  assert.equal(noExactAllow.decision, "deny");
  assert.equal(noExactAllow.reason, "no_exact_allow");
  assert.equal(resolvePhysicalRequestAuthority({
    ...request,
    ipc_peer_principal_id: "principal:different-peer",
  }, registry, [allow]).reason, "no_exact_allow", "IPC principal drift changes the exact tuple");

  assert.throws(
    () => normalizePhysicalEffectAuthorityRules([
      allow,
      authorityRule("allow-exact", "deny", nearTuple),
    ]),
    /duplicate rule IDs/,
  );
  assert.equal(normalizePhysicalEffectAuthorityRule(allow).tuple.tuple_digest, tuple.tuple_digest);
});

test("request authority requires an exact allow for every requested effect", () => {
  const registry = fixtureRegistry();
  const request = activeRequest(registry, [
    requestedEffect(registry, "target.transmit.rf.v1", "target:owned-card-1"),
    requestedEffect(registry, "target.mutate.contact.v1", "target:owned-card-1"),
  ]);
  const tuples = buildPhysicalEffectAuthorityTuples(request, registry);
  const firstOnly = [authorityRule("allow-first", "allow", tuples[0])];

  const incomplete = resolvePhysicalRequestAuthority(request, registry, firstOnly);
  assert.equal(incomplete.decision, "deny");
  assert.equal(incomplete.reason, "no_exact_allow");
  assert.deepEqual(incomplete.effect_results.map((result) => result.reason), ["exact_allow", "no_exact_allow"]);

  const complete = resolvePhysicalRequestAuthority(request, registry, [
    ...firstOnly,
    authorityRule("allow-second", "allow", tuples[1]),
  ]);
  assert.equal(complete.decision, "allow");
  assert.equal(complete.reason, "exact_allow");
});

test("a configured verifier projects one signature-free, branded active grant for exact broker bindings", () => {
  const fixture = activeGrantFixture();
  const signed = signedActiveGrant(fixture);
  const projection = projectVerifiedActivePhysicalExecutionGrant(
    signed,
    fixture.verifier,
    fixture.bindings,
  );

  assert.equal(projection.execution_request_digest, fixture.request.execution_request_digest);
  assert.equal(projection.physical_scope_axis_digest, fixture.authority.physical_scope_axis.axis_digest);
  assert.equal(projection.physical_scope_policy_digest, fixture.authority.physical_scope_axis.policy_digest);
  assert.equal(projection.provider_id, fixture.bindings.provider_id);
  assert.equal(projection.provider_descriptor_digest, fixture.bindings.provider_descriptor_digest);
  assert.equal(projection.fencing_generation, 1);
  assert.match(projection.replay_reservation_ref, /^grant-replay-reservation:/);
  assert.equal(projection.replay_reservation_generation, 1);
  assert.match(projection.replay_reservation_receipt_digest, /^[a-f0-9]{64}$/);
  assert.equal(projection.signature_verifier_id, fixture.verifier.verifier_id);
  assert.equal(Object.isFrozen(projection), true);
  assert.equal("requested_effects" in projection, false, "the broker projection remains digest-compact");
  assert.equal("signature" in projection, false);
  assert.equal("authentication" in projection, false);
  assert.equal("public_key_pem" in projection, false);
  assert.equal(JSON.stringify(projection).includes(signed.authentication.signature), false);
  assert.equal(
    assertVerifiedActivePhysicalExecutionGrant(
      projection,
      fixture.verifier,
      brokerExpectedBindings(fixture),
    ),
    projection,
  );
  assert.equal(fixture.replayClaims.size, 1);
  const replayReceipt = fixture.replayClaims.get(signed.payload.grant_ref).reservation_receipt;
  assert.equal(projection.replay_claim_digest, replayReceipt.replay_claim_digest);
  assert.equal(projection.replay_reservation_ref, replayReceipt.reservation_ref);
  assert.equal(projection.replay_reservation_generation, replayReceipt.generation);
  assert.equal(projection.replay_reservation_receipt_digest, replayReceipt.receipt_digest);
  assert.equal(fixture.getVerifyEd25519CallCount(), 1);
  assert.equal(fixture.getReserveReplayCallCount(), 1);

  assert.throws(
    () => assertVerifiedActivePhysicalExecutionGrant(
      { ...projection },
      fixture.verifier,
      brokerExpectedBindings(fixture),
    ),
    /was not issued by the configured verifier/,
    "a digest-correct JSON clone is not an authority projection",
  );
  const other = activeGrantFixture({ verifierId: "other-active-grant-verifier-v1" });
  assert.throws(
    () => assertVerifiedActivePhysicalExecutionGrant(
      projection,
      other.verifier,
      brokerExpectedBindings(fixture),
    ),
    /was not issued by the configured verifier/,
    "a projection is scoped to its configured trust verifier",
  );
  assert.throws(
    () => assertVerifiedActivePhysicalExecutionGrant(
      projection,
      fixture.verifier,
      { ...brokerExpectedBindings(fixture), provider_id: "other.provider.v1" },
    ),
    /provider_id does not match the trusted execution binding/,
  );
});

test("active grant verification rejects tamper, domain substitution, cross-target, and cross-provider reuse", () => {
  {
    const fixture = activeGrantFixture();
    const signed = signedActiveGrant(fixture);
    signed.payload = { ...signed.payload, resource_bundle_digest: digest("tampered-resource-bundle") };
    signed.authentication = {
      ...signed.authentication,
      signed_payload_digest: hashCanonicalJson(signed.payload),
    };
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(signed, fixture.verifier, fixture.bindings),
      /Ed25519 signature verification failed/,
    );
    assert.equal(fixture.replayClaims.size, 0);
  }
  {
    const fixture = activeGrantFixture();
    const signed = signedActiveGrant(fixture, {
      envelope: { domain: "hacker-bob/physical-stop-request/v1" },
    });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(signed, fixture.verifier, fixture.bindings),
      /signature domain/,
    );
  }
  {
    const fixture = activeGrantFixture();
    const signed = signedActiveGrant(fixture);
    fixture.authority.session_nucleus_hash = digest("different-target-session-nucleus");
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(signed, fixture.verifier, fixture.bindings),
      /session_nucleus_hash does not match the trusted execution binding/,
    );
  }
  {
    const fixture = activeGrantFixture();
    const signed = signedActiveGrant(fixture);
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(signed, fixture.verifier, {
        ...fixture.bindings,
        provider_id: "other.physical.provider",
      }),
      /provider_id does not match the trusted execution binding/,
    );
  }
  {
    const fixture = activeGrantFixture();
    const signed = signedActiveGrant(fixture, {
      payload: { experiment_plan_hash: digest("redirected-experiment-plan") },
    });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(signed, fixture.verifier, fixture.bindings),
      /experiment_plan_hash does not match the trusted execution binding/,
    );
  }
  {
    const fixture = activeGrantFixture();
    const signed = signedActiveGrant(fixture, {
      payload: { execution_lineage_digest: digest("redirected-execution-lineage") },
    });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(signed, fixture.verifier, fixture.bindings),
      /execution_lineage_digest does not match the trusted execution binding/,
    );
  }
  {
    const fixture = activeGrantFixture();
    const signed = signedActiveGrant(fixture);
    const otherRegistry = fixtureRegistry();
    const otherRequest = activeRequest(otherRegistry);
    otherRequest.session_nucleus_hash = digest("other-target-nucleus");
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(signed, fixture.verifier, {
        ...fixture.bindings,
        execution_request: otherRequest,
        effect_registry: otherRegistry,
      }),
      /session_nucleus_hash does not match the trusted execution binding/,
    );
  }
});

test("active grant verification revalidates time, scope epoch, revocation, issuer, and trust root", () => {
  for (const [name, mutate, pattern] of [
    ["trust root epoch drift", (fixture) => {
      fixture.authority.trust_root_epoch += 1;
    }, /trust_root_epoch does not match/],
    ["trust registry drift", (fixture) => {
      fixture.authority.trust_registry_digest = digest("rotated-trust-registry");
    }, /trust_registry_digest does not match/],
    ["trust root revoked", (fixture) => {
      fixture.authority.trust_root_revoked = true;
    }, /trust root is not currently usable/],
    ["issuer revoked", (fixture) => {
      fixture.authority.issuer_revoked = true;
    }, /issuer is not currently usable/],
    ["issuer epoch drift", (fixture) => {
      fixture.authority.issuer_epoch += 1;
    }, /issuer_epoch does not match/],
    ["issuer key drift", (fixture) => {
      fixture.authority.issuer_public_key_digest = digest("rotated-issuer-key");
    }, /issuer_public_key_digest does not match/],
    ["authority decision withdrawn", (fixture) => {
      fixture.authority.authority_decision = "deny";
    }, /authority_decision must be one of allow/],
    ["authority epoch advanced", (fixture) => {
      fixture.authority.physical_scope_axis = activeGrantAxis({ authority_epoch: 8 });
    }, /physical_scope_axis_digest does not match|authority_epoch does not match/],
    ["revocation generation advanced", (fixture) => {
      fixture.authority.physical_scope_axis = activeGrantAxis({ revocation_generation: 3 });
    }, /physical_scope_axis_digest does not match|revocation_generation does not match/],
  ]) {
    const fixture = activeGrantFixture();
    const signed = signedActiveGrant(fixture);
    mutate(fixture);
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(signed, fixture.verifier, fixture.bindings),
      pattern,
      name,
    );
    assert.equal(fixture.replayClaims.size, 0, `${name} must fail before replay reservation`);
  }

  {
    const fixture = activeGrantFixture({ now: "2026-07-17T23:59:59.999Z" });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture, { signedAt: "2026-07-17T23:59:59.000Z" }),
        fixture.verifier,
        fixture.bindings,
      ),
      /not yet valid/,
    );
  }
  {
    const fixture = activeGrantFixture({ now: "2026-07-18T00:01:00.000Z" });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture),
        fixture.verifier,
        fixture.bindings,
      ),
      /has expired/,
    );
  }
  {
    const fixture = activeGrantFixture();
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture, { signedAt: "2026-07-18T00:00:11.000Z" }),
        fixture.verifier,
        fixture.bindings,
      ),
      /signed in the future/,
    );
  }
  {
    const fixture = activeGrantFixture({ verifyEd25519: () => Promise.resolve(true) });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture),
        fixture.verifier,
        fixture.bindings,
      ),
      /signature verification failed/,
      "an asynchronous or self-asserted verifier result is not silently accepted",
    );
  }
  {
    const fixture = activeGrantFixture();
    const future = signedActiveGrant(fixture, { signedAt: "2026-07-18T00:00:11.000Z" });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(future, fixture.verifier, fixture.bindings),
      /signed in the future/,
    );
    fixture.setNow("2026-07-18T00:00:09.000Z");
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture),
        fixture.verifier,
        fixture.bindings,
      ),
      /trusted clock moved backwards/,
    );
  }
});

test("a branded projection live-revalidates current authority, trust, and time without repeating signature or replay", () => {
  for (const [name, mutate, pattern] of [
    ["execution request drift", (fixture) => {
      fixture.authority.execution_request_digest = digest("different-current-execution-request");
    }, /execution_request_digest does not match/],
    ["session nucleus drift", (fixture) => {
      fixture.authority.session_nucleus_hash = digest("different-current-session-nucleus");
    }, /session_nucleus_hash does not match/],
    ["authority resolution drift", (fixture) => {
      fixture.authority.authority_resolution_digest = digest("withdrawn-authority-resolution");
    }, /authority_resolution_digest does not match/],
    ["authority epoch advanced", (fixture) => {
      fixture.authority.physical_scope_axis = activeGrantAxis({ authority_epoch: 8 });
    }, /physical_scope_axis_digest does not match|authority_epoch does not match/],
    ["revocation generation advanced", (fixture) => {
      fixture.authority.physical_scope_axis = activeGrantAxis({ revocation_generation: 3 });
    }, /physical_scope_axis_digest does not match|revocation_generation does not match/],
    ["trust registry rotated", (fixture) => {
      fixture.authority.trust_registry_digest = digest("current-trust-registry-rotated");
    }, /trust_registry_digest does not match/],
    ["issuer revoked", (fixture) => {
      fixture.authority.issuer_revoked = true;
    }, /issuer is not currently usable/],
    ["key usage removed", (fixture) => {
      fixture.authority.key_usage = "physical_observation_signing";
    }, /key_usage must be one of physical_active_grant_signing/],
    ["grant expired", (fixture) => {
      fixture.setNow("2026-07-18T00:01:00.000Z");
    }, /has expired/],
  ]) {
    const fixture = activeGrantFixture();
    const projection = projectVerifiedActivePhysicalExecutionGrant(
      signedActiveGrant(fixture),
      fixture.verifier,
      fixture.bindings,
    );
    const expectedBindings = brokerExpectedBindings(fixture);
    mutate(fixture);
    assert.throws(
      () => assertVerifiedActivePhysicalExecutionGrant(
        projection,
        fixture.verifier,
        expectedBindings,
      ),
      pattern,
      name,
    );
    assert.equal(fixture.getVerifyEd25519CallCount(), 1, `${name} must not reverify the signature`);
    assert.equal(fixture.getReserveReplayCallCount(), 1, `${name} must not reserve replay twice`);
    assert.equal(fixture.replayClaims.size, 1, `${name} must retain exactly one durable reservation`);
  }
});

test("active grants are one-shot and require an external atomic durable replay reservation", () => {
  const fixture = activeGrantFixture();
  const signed = signedActiveGrant(fixture);
  projectVerifiedActivePhysicalExecutionGrant(signed, fixture.verifier, fixture.bindings);
  assert.throws(
    () => projectVerifiedActivePhysicalExecutionGrant(signed, fixture.verifier, fixture.bindings),
    /replay was rejected/,
  );
  const secondEnvelope = signedActiveGrant(fixture, {
    grantRef: "physical-grant:active-authority-test-2",
  });
  assert.throws(
    () => projectVerifiedActivePhysicalExecutionGrant(
      secondEnvelope,
      fixture.verifier,
      fixture.bindings,
    ),
    /replay was rejected/,
    "the same execution request cannot be reissued under another grant reference",
  );
  assert.equal(fixture.replayClaims.size, 1);
  assert.equal(fixture.getReserveReplayCallCount(), 1, "process-local replay rejection avoids a second reservation");

  const unavailableLedger = activeGrantFixture({ reserveReplay: () => false });
  assert.throws(
    () => projectVerifiedActivePhysicalExecutionGrant(
      signedActiveGrant(unavailableLedger),
      unavailableLedger.verifier,
      unavailableLedger.bindings,
    ),
    /replay reservation failed closed/,
  );
});

test("active grant replay receipts are closed, claim-bound, fsynced, and cannot rehydrate without admission", () => {
  {
    const fixture = activeGrantFixture({
      reserveReplay: (claim) => replayReservationResult(claim, { disposition: "existing_same" }),
    });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture),
        fixture.verifier,
        fixture.bindings,
      ),
      /existing replay reservation requires unavailable durable admission rehydration/,
      "an existing reservation cannot mint a process-local projection without a trusted durable precommit",
    );
    assert.equal(fixture.getReserveReplayCallCount(), 1);
  }
  {
    const fixture = activeGrantFixture({
      reserveReplay: (claim) => replayReservationResult(claim, {
        receipt: { replay_claim: { ...claim, attempt_id: "other-attempt" } },
      }),
    });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture),
        fixture.verifier,
        fixture.bindings,
      ),
      /replay reservation failed closed/,
    );
  }
  {
    const fixture = activeGrantFixture({
      reserveReplay: (claim) => replayReservationResult(claim, {
        reservedAt: "2026-07-18T00:00:10.001Z",
        fsyncedAt: "2026-07-18T00:00:10.000Z",
      }),
    });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture),
        fixture.verifier,
        fixture.bindings,
      ),
      /replay reservation failed closed/,
    );
  }
  {
    const fixture = activeGrantFixture({
      reserveReplay: (claim) => replayReservationResult(claim, {
        receiptEnvelope: { receipt_digest: digest("tampered-replay-reservation-receipt") },
      }),
    });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture),
        fixture.verifier,
        fixture.bindings,
      ),
      /replay reservation failed closed/,
    );
  }
  {
    const fixture = activeGrantFixture({
      reserveReplay: (claim) => {
        const result = replayReservationResult(claim);
        result.reservation_receipt.ledger_secret = "must-not-cross-contract";
        return result;
      },
    });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture),
        fixture.verifier,
        fixture.bindings,
      ),
      /replay reservation failed closed/,
    );
  }
});

test("active grant envelopes and verifier dependencies are closed and canonical", () => {
  const fixture = activeGrantFixture();
  const signed = signedActiveGrant(fixture);
  assert.throws(
    () => projectVerifiedActivePhysicalExecutionGrant({
      ...signed,
      authorization_document: "raw operator authorization must not cross this boundary",
    }, fixture.verifier, fixture.bindings),
    /unknown fields: authorization_document/,
  );
  assert.throws(
    () => projectVerifiedActivePhysicalExecutionGrant({
      ...signed,
      authentication: { ...signed.authentication, signature: `${"A".repeat(85)}!` },
    }, fixture.verifier, fixture.bindings),
    /canonical 86-character Ed25519 base64url/,
  );
  const { signature: ignoredSignature, ...authenticationBasis } = signed.authentication;
  void ignoredSignature;
  assert.throws(
    () => activePhysicalExecutionGrantSignatureInputDigest(signed.payload, {
      ...authenticationBasis,
      signed_payload_digest: digest("detached-payload"),
    }),
    /does not bind/,
  );
  assert.throws(
    () => createActivePhysicalExecutionGrantVerifier({
      verifier_id: "physical-active-grant-verifier-v1",
      trusted_now: () => "2026-07-18T00:00:10.000Z",
      resolve_current_authority: () => fixture.authority,
      verify_ed25519: () => true,
    }),
    /missing fields: reserve_replay/,
  );
});

test("grant verifier clock modes are explicit and cloned or ambiguous production clocks fail closed", () => {
  const deterministicActive = activeGrantFixture();
  const deterministicProjection = projectVerifiedActivePhysicalExecutionGrant(
    signedActiveGrant(deterministicActive),
    deterministicActive.verifier,
    deterministicActive.bindings,
  );
  assert.equal(deterministicActive.verifier.trusted_clock_mode, "deterministic_test_clock");
  assert.equal(deterministicActive.verifier.trusted_clock_port_id, null);
  assert.equal(deterministicProjection.trusted_clock_mode, "deterministic_test_clock");
  assert.equal(deterministicProjection.verified_clock_uncertainty_ms, 0);
  assert.equal(deterministicProjection.verified_at_earliest, deterministicProjection.verified_at);
  assert.equal(deterministicProjection.verified_at_latest, deterministicProjection.verified_at);

  const clock = signedTrustedClockFixture();
  const productionActive = activeGrantFixture({
    trustedClockPort: clock.port,
    reservationNow: "2026-07-18T00:00:09.000Z",
  });
  assert.equal(productionActive.verifier.trusted_clock_mode, "signed_monotonic_wall_mapping");
  assert.equal(productionActive.verifier.trusted_clock_port_id, clock.port.port_id);
  assert.equal("trusted_clock_port" in productionActive.verifier, false);

  const common = {
    verifier_id: "ambiguous-active-clock-verifier-v1",
    resolve_current_authority: () => productionActive.authority,
    verify_ed25519: () => true,
    reserve_replay: () => ({}),
  };
  assert.throws(
    () => createActivePhysicalExecutionGrantVerifier({
      ...common,
      trusted_clock_port: clock.port,
      trusted_now: () => "2026-07-18T00:00:10.000Z",
    }),
    /requires exactly one/,
  );
  assert.throws(
    () => createActivePhysicalExecutionGrantVerifier(common),
    /requires exactly one/,
  );
  assert.throws(
    () => createPhysicalBootstrapGrantVerifier({
      ...common,
      verifier_id: "cloned-bootstrap-clock-verifier-v1",
      trusted_clock_port: structuredClone(clock.port),
    }),
    /privately branded live port/,
  );
});

test("active grant production verification preserves uncertainty and live clock provenance", () => {
  const clock = signedTrustedClockFixture();
  const fixture = activeGrantFixture({
    trustedClockPort: clock.port,
    reservationNow: "2026-07-18T00:00:09.000Z",
  });
  const signed = signedActiveGrant(fixture);
  const projection = projectVerifiedActivePhysicalExecutionGrant(
    signed,
    fixture.verifier,
    fixture.bindings,
  );

  assert.equal(projection.trusted_clock_mode, "signed_monotonic_wall_mapping");
  assert.equal(projection.verified_at, "2026-07-18T00:00:09.000Z");
  assert.equal(projection.verified_clock_center, "2026-07-18T00:00:10.000Z");
  assert.equal(projection.verified_at_earliest, "2026-07-18T00:00:09.000Z");
  assert.equal(projection.verified_at_latest, "2026-07-18T00:00:11.000Z");
  assert.equal(projection.verified_clock_uncertainty_ms, 1_000);
  assert.equal(
    projection.verified_clock_mapping_digest,
    clock.control.mapping.signed_mapping_digest,
  );
  assert.equal(projection.verified_clock_mapping_generation, 1);
  assert.equal(projection.verified_clock_port_id, clock.port.port_id);
  assert.equal(projection.verified_clock_id, clock.port.clock_id);
  const serialized = JSON.stringify(projection);
  assert.equal(serialized.includes(clock.control.mapping.signature), false);
  assert.equal(serialized.includes(clock.keyPair.publicKey.export({
    type: "spki",
    format: "pem",
  })), false);
  assert.equal("public_key" in projection, false);
  assert.equal(
    assertVerifiedActivePhysicalExecutionGrant(
      projection,
      fixture.verifier,
      brokerExpectedBindings(fixture),
    ),
    projection,
  );

  clock.control.trust = { ...clock.control.trust, revoked: true };
  assert.throws(
    () => assertVerifiedActivePhysicalExecutionGrant(
      projection,
      fixture.verifier,
      brokerExpectedBindings(fixture),
    ),
    /no longer trusted or current/,
  );

  const rollbackClock = signedTrustedClockFixture();
  const rollbackFixture = activeGrantFixture({
    trustedClockPort: rollbackClock.port,
    reservationNow: "2026-07-18T00:00:09.000Z",
  });
  const rollbackProjection = projectVerifiedActivePhysicalExecutionGrant(
    signedActiveGrant(rollbackFixture),
    rollbackFixture.verifier,
    rollbackFixture.bindings,
  );
  rollbackClock.control.monotonic_ms -= 1;
  assert.throws(
    () => assertVerifiedActivePhysicalExecutionGrant(
      rollbackProjection,
      rollbackFixture.verifier,
      brokerExpectedBindings(rollbackFixture),
    ),
    /monotonic clock moved backwards/,
  );
});

test("active production grant boundaries use earliest for admission and latest for expiry", () => {
  {
    const clock = signedTrustedClockFixture({
      now: "2026-07-18T00:00:00.100Z",
      uncertaintyMs: 100,
    });
    const fixture = activeGrantFixture({
      now: "2026-07-18T00:00:00.100Z",
      trustedClockPort: clock.port,
      reservationNow: "2026-07-18T00:00:00.000Z",
    });
    assert.ok(projectVerifiedActivePhysicalExecutionGrant(
      signedActiveGrant(fixture, { signedAt: "2026-07-18T00:00:00.000Z" }),
      fixture.verifier,
      fixture.bindings,
    ));
  }
  {
    const clock = signedTrustedClockFixture({
      now: "2026-07-18T00:00:00.099Z",
      uncertaintyMs: 100,
    });
    const fixture = activeGrantFixture({
      now: "2026-07-18T00:00:00.099Z",
      trustedClockPort: clock.port,
      reservationNow: "2026-07-17T23:59:59.999Z",
    });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture, { signedAt: "2026-07-17T23:59:59.900Z" }),
        fixture.verifier,
        fixture.bindings,
      ),
      /not yet valid/,
    );
  }
  {
    const clock = signedTrustedClockFixture({
      now: "2026-07-18T00:00:59.900Z",
      uncertaintyMs: 100,
    });
    const fixture = activeGrantFixture({
      now: "2026-07-18T00:00:59.900Z",
      trustedClockPort: clock.port,
      reservationNow: "2026-07-18T00:00:59.800Z",
    });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture),
        fixture.verifier,
        fixture.bindings,
      ),
      /has expired/,
    );
  }
  {
    const clock = signedTrustedClockFixture({
      now: "2026-07-18T00:00:59.899Z",
      uncertaintyMs: 100,
    });
    const fixture = activeGrantFixture({
      now: "2026-07-18T00:00:59.899Z",
      trustedClockPort: clock.port,
      reservationNow: "2026-07-18T00:00:59.799Z",
    });
    assert.ok(projectVerifiedActivePhysicalExecutionGrant(
      signedActiveGrant(fixture),
      fixture.verifier,
      fixture.bindings,
    ));
  }
  {
    const clock = signedTrustedClockFixture();
    const fixture = activeGrantFixture({
      trustedClockPort: clock.port,
      reservationNow: "2026-07-18T00:00:09.000Z",
    });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture, { signedAt: "2026-07-18T00:00:09.001Z" }),
        fixture.verifier,
        fixture.bindings,
      ),
      /signed in the future/,
    );
  }
});

test("bootstrap production verification uses the same conservative clock boundaries", () => {
  const clock = signedTrustedClockFixture();
  const fixture = bootstrapGrantFixture({
    trustedClockPort: clock.port,
    reservationNow: "2026-07-18T00:00:09.000Z",
  });
  const projection = projectVerifiedPhysicalBootstrapGrant(
    signedBootstrapGrant(fixture),
    fixture.verifier,
    fixture.bindings,
  );
  assert.equal(fixture.verifier.trusted_clock_mode, "signed_monotonic_wall_mapping");
  assert.equal(projection.trusted_clock_mode, "signed_monotonic_wall_mapping");
  assert.equal(projection.verified_at_earliest, "2026-07-18T00:00:09.000Z");
  assert.equal(projection.verified_at_latest, "2026-07-18T00:00:11.000Z");
  assert.equal(projection.verified_clock_uncertainty_ms, 1_000);
  assert.equal(JSON.stringify(projection).includes(clock.control.mapping.signature), false);
  assert.equal(
    assertVerifiedPhysicalBootstrapGrant(
      projection,
      fixture.verifier,
      bootstrapExpectedBindings(fixture),
    ),
    projection,
  );
  clock.control.trust = { ...clock.control.trust, revoked: true };
  assert.throws(
    () => assertVerifiedPhysicalBootstrapGrant(
      projection,
      fixture.verifier,
      bootstrapExpectedBindings(fixture),
    ),
    /no longer trusted or current/,
  );

  const expiryClock = signedTrustedClockFixture({
    now: "2026-07-18T00:00:59.900Z",
    uncertaintyMs: 100,
  });
  const expiryFixture = bootstrapGrantFixture({
    now: "2026-07-18T00:00:59.900Z",
    trustedClockPort: expiryClock.port,
    reservationNow: "2026-07-18T00:00:59.800Z",
  });
  assert.throws(
    () => projectVerifiedPhysicalBootstrapGrant(
      signedBootstrapGrant(expiryFixture),
      expiryFixture.verifier,
      expiryFixture.bindings,
    ),
    /has expired/,
  );

  const futureClock = signedTrustedClockFixture();
  const futureFixture = bootstrapGrantFixture({
    trustedClockPort: futureClock.port,
    reservationNow: "2026-07-18T00:00:09.000Z",
  });
  assert.throws(
    () => projectVerifiedPhysicalBootstrapGrant(
      signedBootstrapGrant(futureFixture, { signedAt: "2026-07-18T00:00:09.001Z" }),
      futureFixture.verifier,
      futureFixture.bindings,
    ),
    /signed in the future/,
  );

  const exactStartClock = signedTrustedClockFixture({
    now: "2026-07-18T00:00:00.100Z",
    uncertaintyMs: 100,
  });
  const exactStartFixture = bootstrapGrantFixture({
    now: "2026-07-18T00:00:00.100Z",
    trustedClockPort: exactStartClock.port,
    reservationNow: "2026-07-18T00:00:00.000Z",
  });
  assert.ok(projectVerifiedPhysicalBootstrapGrant(
    signedBootstrapGrant(exactStartFixture, { signedAt: "2026-07-18T00:00:00.000Z" }),
    exactStartFixture.verifier,
    exactStartFixture.bindings,
  ));

  const tooEarlyClock = signedTrustedClockFixture({
    now: "2026-07-18T00:00:00.099Z",
    uncertaintyMs: 100,
  });
  const tooEarlyFixture = bootstrapGrantFixture({
    now: "2026-07-18T00:00:00.099Z",
    trustedClockPort: tooEarlyClock.port,
    reservationNow: "2026-07-17T23:59:59.999Z",
  });
  assert.throws(
    () => projectVerifiedPhysicalBootstrapGrant(
      signedBootstrapGrant(tooEarlyFixture, { signedAt: "2026-07-17T23:59:59.900Z" }),
      tooEarlyFixture.verifier,
      tooEarlyFixture.bindings,
    ),
    /not yet valid/,
  );
});

test("durable replay reservation is followed by a fresh production clock check", async (t) => {
  await t.test("active grant", () => {
    const clock = signedTrustedClockFixture({ uncertaintyMs: 0 });
    const fixture = activeGrantFixture({
      trustedClockPort: clock.port,
      reserveReplay: (claim) => {
        clock.control.monotonic_ms = 52_000;
        return replayReservationResult(claim, {
          reservedAt: "2026-07-18T00:00:10.000Z",
          fsyncedAt: "2026-07-18T00:00:10.000Z",
        });
      },
    });
    assert.throws(
      () => projectVerifiedActivePhysicalExecutionGrant(
        signedActiveGrant(fixture),
        fixture.verifier,
        fixture.bindings,
      ),
      /has expired/,
    );
    assert.equal(fixture.getReserveReplayCallCount(), 1);
  });

  await t.test("bootstrap grant", () => {
    const clock = signedTrustedClockFixture({ uncertaintyMs: 0 });
    const fixture = bootstrapGrantFixture({
      trustedClockPort: clock.port,
      reserveReplay: (claim) => {
        clock.control.monotonic_ms = 52_000;
        return replayReservationResult(claim, {
          reservationRef:
            `bootstrap-grant-replay-reservation:${hashCanonicalJson(claim).slice(0, 40)}`,
          reservedAt: "2026-07-18T00:00:10.000Z",
          fsyncedAt: "2026-07-18T00:00:10.000Z",
        });
      },
    });
    assert.throws(
      () => projectVerifiedPhysicalBootstrapGrant(
        signedBootstrapGrant(fixture),
        fixture.verifier,
        fixture.bindings,
      ),
      /has expired/,
    );
    assert.equal(fixture.getReserveCount(), 1);
  });
});
