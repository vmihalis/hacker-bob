"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN,
  activePhysicalExecutionGrantSignatureInputDigest,
  createActivePhysicalExecutionGrantVerifier,
  normalizeMcpPhysicalExecutionRequest,
  projectVerifiedActivePhysicalExecutionGrant,
} = require("../mcp/domains/physical/physical-authority.js");
const {
  assertCurrentPhysicalDispatchAuthority,
  assertCurrentPhysicalDispatchExecutionAuthorityClaim,
  assertPhysicalDispatchAuthorityPort,
  claimPhysicalDispatchExecutionAuthority,
  createActivePhysicalDispatchAuthorityPort,
  createDeterministicMockDispatchAuthorityPort,
  takePhysicalDispatchExecutionAuthorityClaimOwnership,
} = require("../mcp/domains/physical/physical-dispatch-authority.js");
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
} = require("../mcp/domains/physical/physical-trusted-clock.js");
const {
  assertAttemptJournalAppend,
  normalizeAttemptJournalEntry,
  normalizeEffectDispatchRecord,
} = require("../mcp/domains/physical/instrument-lease-contract.js");
const {
  createDurableInstrumentLeaseStore,
  createDurableInstrumentProviderDispatchPort,
} = require("../mcp/domains/physical/instrument-lease-store.js");
const {
  createPhysicalProviderCommandAuthorizationPort,
  createPhysicalProviderCommandRegistry,
  createPhysicalProviderCommandRequest,
  createPhysicalProviderCompletionVerificationPort,
  createPhysicalProviderDispatchBridge,
  createPhysicalProviderDispatchHeadFence,
  normalizePhysicalProviderBinding,
  resolvePhysicalProviderCommand,
  resolvePhysicalProviderCommandAuthorization,
} = require("../packages/bob-instrument-broker/lib/physical-provider-dispatch.js");
const {
  createPhysicalReservationFixture,
} = require("../packages/bob-instrument-broker/test/helpers/physical-reservation-fixture.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function createTestCompletionVerificationPort(label) {
  const records = new Map();
  return createPhysicalProviderCompletionVerificationPort({
    port_id: `test_completion_${label}`,
    evidence_domain_digest: digest(`completion-domain-${label}`),
    read_committed({ completion_binding: binding }) {
      return structuredClone(records.get(binding.completion_binding_digest) || null);
    },
    verify_and_commit({ completion_binding: binding, provider_claim: claim }) {
      const record = {
        version: 1,
        completion_binding_digest: binding.completion_binding_digest,
        completion: claim.completion,
        effect_disposition: claim.completion === "confirmed"
          ? "requested_effect_committed"
          : "requested_effect_not_applied",
        provider_result_digest: claim.provider_result_digest,
        provider_receipt_ref: claim.provider_receipt_ref,
        committed_receipt_ref:
          `completion-receipt:${binding.completion_binding_digest.slice(0, 32)}`,
      };
      record.committed_receipt_digest = hashCanonicalJson({
        domain: "hacker-bob/physical-provider-completion-receipt/v1",
        ...record,
      });
      record.completion_evidence_digest = hashCanonicalJson({
        ...record,
        domain: "hacker-bob/physical-provider-completion-evidence/v1",
        committed_receipt_digest: record.committed_receipt_digest,
      });
      if (!records.has(binding.completion_binding_digest)) {
        records.set(binding.completion_binding_digest, structuredClone(record));
      }
      return structuredClone(records.get(binding.completion_binding_digest));
    },
  });
}

function publicKeyDigest(publicKey) {
  return crypto.createHash("sha256").update(
    publicKey.export({ type: "spki", format: "der" }),
  ).digest("hex");
}

function signedZeroUncertaintyClockPort() {
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const payload = {
    version: 1,
    clock_id: "physical-clock:dispatch-authority-test-1",
    monotonic_epoch_id: digest("dispatch-authority-monotonic-epoch-1"),
    mapping_generation: 1,
    reference_monotonic_ms: 1_000,
    reference_utc: "2026-07-18T00:00:02.000Z",
    max_uncertainty_ms: 0,
    not_before: "2026-07-17T23:00:00.000Z",
    expires_at: "2026-07-18T01:00:00.000Z",
    trust_root_epoch: 4,
    authority_epoch: 7,
    revocation_generation: 2,
    signer_key_id: "clock-key:dispatch-authority-test-1",
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
  const mapping = {
    ...basis,
    signed_mapping_digest: hashCanonicalJson(basis),
  };
  const trust = {
    version: 1,
    trusted: true,
    revoked: false,
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    current_mapping_generation: payload.mapping_generation,
    current_signed_mapping_digest: mapping.signed_mapping_digest,
    trust_root_epoch: payload.trust_root_epoch,
    authority_epoch: payload.authority_epoch,
    revocation_generation: payload.revocation_generation,
    signer_key_id: payload.signer_key_id,
    signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
    public_key: keyPair.publicKey,
  };
  return createPhysicalTrustedClockPort({
    port_id: "dispatch_authority_clock_port",
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: 0,
    read_monotonic_ms: () => 1_000,
    read_signed_mapping: () => mapping,
    resolve_current_trust: () => trust,
  });
}

function activeGrantFixture(options = {}) {
  const effectRegistry = buildEffectTemplateRegistry([{
    version: 1,
    template_id: "target.transmit.rf.v1",
    subject_kind: "target",
    action: "transmit",
    channel: "rf",
    persistence: "ephemeral",
    bounds: {},
  }]);
  const effect = effectRegistry.get("target.transmit.rf.v1");
  const compiledCommandDigest = digest("dispatch-authority-compiled-command");
  const request = normalizeMcpPhysicalExecutionRequest({
    version: 1,
    grant_kind: "active",
    session_id: "dispatch-authority-session-1",
    session_nucleus_hash: digest("dispatch-authority-session-nucleus"),
    caller_role_id: "orchestrator",
    requester_principal_id: "principal:dispatch-authority-requester-1",
    ipc_peer_principal_id: "principal:dispatch-authority-peer-1",
    execution_principal_id: "principal:dispatch-authority-worker-1",
    instrument_ref: "instrument:dispatch-authority-reader-1",
    operation_id: "target.transmit.rf.v1",
    parameter_digest: digest("dispatch-authority-parameters"),
    authority_epoch: 7,
    revocation_generation: 2,
    nonce: "dispatch-authority-nonce-1",
    sequence: 1,
    not_before: "2026-07-18T00:00:00.000Z",
    expires_at: "2026-07-18T00:01:00.000Z",
    requested_effects: [{
      version: 1,
      template_id: effect.template_id,
      template_digest: effect.template_digest,
      subject_ref: "target:owned-card-1",
      subject_kind: effect.subject_kind,
      action: effect.action,
      channel: effect.channel,
      persistence: effect.persistence,
      bounds: {},
    }],
    node_id: "PH-S7",
    contract_hash: digest("dispatch-authority-node-contract"),
    prep_token_hash: digest("dispatch-authority-prep-token"),
    dispatch_event_id: "dispatch-authority-event-1",
    graph_context_hash: digest("dispatch-authority-graph-context"),
    capability_pack_id: "physical.rfid.v1",
    capability_pack_version: "1.0.0",
    capability_pack_digest: digest("dispatch-authority-capability-pack"),
    technique_cell_id: "rfid.authorized-transmit",
    attempt_id: "dispatch-authority-attempt-1",
    experiment_plan_hash: digest("dispatch-authority-experiment-plan"),
    inventory_observation_ref: "inventory-observation:dispatch-authority-1",
    inventory_observation_digest: digest("dispatch-authority-inventory"),
    assurance_profile_id: "physical-assurance-v1",
    assurance_claims_digest: digest("dispatch-authority-assurance-claims"),
    provider_manifest_digest: digest("dispatch-authority-provider-manifest"),
    availability_variant_id: "authorized-rf-transmit-v1",
    availability_variant_digest: digest("dispatch-authority-availability-variant"),
    authorized_transition_set_digest: digest("dispatch-authority-transition-set"),
    resource_bundle_digest: digest("dispatch-authority-resource-bundle"),
    fencing_token: "dispatch-authority-fence-1",
    lease_id: "dispatch-authority-lease-1",
    workspace_snapshot_ref: "workspace-snapshot:dispatch-authority-1",
    workspace_snapshot_digest: digest("dispatch-authority-workspace-snapshot"),
    observer_plan_digest: digest("dispatch-authority-observer-plan"),
    control_plan_digest: digest("dispatch-authority-control-plan"),
    cleanup_plan_digest: digest("dispatch-authority-cleanup-plan"),
    execution_lineage: {
      version: 1,
      compiler_id: "closed_dispatch_compiler_v1",
      compiler_manifest_digest: digest("dispatch-authority-compiler-manifest"),
      compiler_registry_digest: digest("dispatch-authority-compiler-registry"),
      compiled_command_id: "compiled-command:dispatch-authority-1",
      compiled_command_capability_digest: compiledCommandDigest,
      compiled_operation_digest: digest("dispatch-authority-compiled-operation"),
      provider_command_ref: "command:active-first",
      command_input_ref: "command-input:active-first",
      command_input_digest: compiledCommandDigest,
      maximum_response_bytes: 64,
      vault_reservation_handle: `vault-reservation:v1:${"A".repeat(43)}`,
      vault_reservation_digest: digest("dispatch-authority-vault-reservation"),
      vault_ingest_capability_digest: digest("dispatch-authority-vault-ingest"),
      vault_byte_limit: 64,
      worker_bundle_digest: digest("dispatch-authority-worker-bundle"),
      worker_launch_profile_digest: digest("dispatch-authority-launch-profile"),
      worker_fence_plan_digest: digest("dispatch-authority-worker-fence"),
      transport_profile_digest: digest("dispatch-authority-transport-profile"),
      durable_exchange_plan_digest: digest("dispatch-authority-exchange-plan"),
      terminal_receipt_recipient_digest: digest("dispatch-authority-terminal-recipient"),
      safety_supervisor_plan_digest: digest("dispatch-authority-safety-plan"),
    },
    ...options.requestOverrides,
  }, effectRegistry);
  const scopeAxis = normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "dispatch-authority-policy-v1",
    policy_digest: digest("dispatch-authority-scope-policy"),
    projection_version: 1,
    projection_digest: digest("dispatch-authority-scope-projection"),
    provenance_digest: digest("dispatch-authority-scope-provenance"),
    compatibility_digest: digest("dispatch-authority-scope-compatibility"),
    transition_receipt_registry_digest: digest("dispatch-authority-transition-receipts"),
    authority_epoch: request.authority_epoch,
    revocation_generation: request.revocation_generation,
  });
  const providerId = options.providerId || "deterministic_mock";
  const providerDescriptorDigest = options.providerDescriptorDigest
    || digest("dispatch-authority-provider-descriptor");
  const operationDigest = options.operationDigest || digest("dispatch-authority-operation");
  const fencingGeneration = 1;
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const authority = {
    version: 1,
    session_id: request.session_id,
    session_nucleus_hash: request.session_nucleus_hash,
    execution_request_digest: request.execution_request_digest,
    physical_scope_axis: scopeAxis,
    authority_decision: "allow",
    authority_reason: "exact_allow",
    authority_resolution_digest: digest("dispatch-authority-resolution"),
    trust_root_id: "trust-root:dispatch-authority-test",
    trust_root_epoch: 4,
    trust_registry_digest: digest("dispatch-authority-trust-registry"),
    trust_root_trusted: true,
    trust_root_revoked: false,
    issuer_principal_id: "principal:dispatch-authority-issuer",
    issuer_key_id: "signer-key:dispatch-authority-test",
    issuer_epoch: 3,
    issuer_public_key_digest: publicKeyDigest(keyPair.publicKey),
    key_usage: "physical_active_grant_signing",
    issuer_trusted: true,
    issuer_revoked: false,
  };
  let now = "2026-07-18T00:00:02.000Z";
  let verifyCount = 0;
  let replayCount = 0;
  const verifierInput = {
    verifier_id: "dispatch-authority-verifier-v1",
    resolve_current_authority: () => authority,
    verify_ed25519: (verification) => {
      verifyCount += 1;
      return crypto.verify(
        null,
        Buffer.from(verification.signature_input_digest, "hex"),
        keyPair.publicKey,
        Buffer.from(verification.signature, "base64url"),
      );
    },
    reserve_replay: (claim) => {
      replayCount += 1;
      const receipt = {
        version: 1,
        reservation_ref: "grant-replay-reservation:dispatch-authority-1",
        replay_claim: claim,
        replay_claim_digest: hashCanonicalJson(claim),
        generation: 1,
        previous_receipt_digest: null,
        reserved_at: "2026-07-18T00:00:01.000Z",
        fsynced_at: "2026-07-18T00:00:01.000Z",
      };
      return {
        version: 1,
        disposition: "created",
        reservation_receipt: {
          ...receipt,
          receipt_digest: hashCanonicalJson(receipt),
        },
      };
    },
  };
  if (options.trustedClockPort) {
    verifierInput.trusted_clock_port = options.trustedClockPort;
  } else {
    verifierInput.trusted_now = () => now;
  }
  const verifier = createActivePhysicalExecutionGrantVerifier(verifierInput);
  const payload = {
    version: 1,
    grant_kind: "active",
    grant_ref: "physical-grant:dispatch-authority-test-1",
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
    provider_id: providerId,
    provider_descriptor_digest: providerDescriptorDigest,
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
    fencing_generation: fencingGeneration,
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
    signed_at: "2026-07-18T00:00:00.500Z",
    signed_payload_digest: hashCanonicalJson(payload),
  };
  const signatureInputDigest = activePhysicalExecutionGrantSignatureInputDigest(
    payload,
    authentication,
  );
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
        keyPair.privateKey,
      ).toString("base64url"),
    },
  };
  const projectionBindings = {
    execution_request: request,
    effect_registry: effectRegistry,
    provider_id: providerId,
    provider_descriptor_digest: providerDescriptorDigest,
    operation_digest: operationDigest,
    fencing_generation: fencingGeneration,
  };
  const grantProjection = projectVerifiedActivePhysicalExecutionGrant(
    signedGrant,
    verifier,
    projectionBindings,
  );
  const expectedGrantBindings = Object.freeze({
    execution_request_digest: request.execution_request_digest,
    authority_resolution_digest: authority.authority_resolution_digest,
    execution_principal_id: request.execution_principal_id,
    provider_id: providerId,
    provider_descriptor_digest: providerDescriptorDigest,
    instrument_ref: request.instrument_ref,
    operation_id: request.operation_id,
    operation_digest: operationDigest,
    attempt_id: request.attempt_id,
    experiment_plan_hash: request.experiment_plan_hash,
    execution_lineage_digest: request.execution_lineage.execution_lineage_digest,
    lease_id: request.lease_id,
    fencing_token: request.fencing_token,
    fencing_generation: fencingGeneration,
    resource_bundle_digest: request.resource_bundle_digest,
  });
  const assertion = Object.freeze({
    session_nucleus_hash: request.session_nucleus_hash,
    signed_grant_digest: grantProjection.signed_grant_digest,
    execution_request_digest: request.execution_request_digest,
    experiment_plan_hash: request.experiment_plan_hash,
    execution_lineage_digest: request.execution_lineage.execution_lineage_digest,
    execution_principal_id: request.execution_principal_id,
    attempt_ref: `attempt:${request.attempt_id}`,
    instrument_ref: request.instrument_ref,
    lease_id: request.lease_id,
    fencing_token: request.fencing_token,
    fencing_generation: fencingGeneration,
    operation_id: request.operation_id,
    provider_id: providerId,
    provider_descriptor_digest: providerDescriptorDigest,
    effect_not_before: "2026-07-18T00:00:03.000Z",
    effect_deadline: "2026-07-18T00:00:50.000Z",
  });
  const {
    version: _lineageVersion,
    execution_lineage_digest: _lineageDigest,
    ...executionLineageAssertion
  } = request.execution_lineage;
  const executionAssertion = Object.freeze({
    ...assertion,
    effect_not_before: request.not_before,
    effect_deadline: request.expires_at,
    session_id: request.session_id,
    node_id: request.node_id,
    contract_hash: request.contract_hash,
    prep_token_hash: request.prep_token_hash,
    dispatch_event_id: request.dispatch_event_id,
    graph_context_hash: request.graph_context_hash,
    resource_bundle_digest: request.resource_bundle_digest,
    operation_digest: operationDigest,
    parameter_digest: request.parameter_digest,
    requested_effects_digest: request.requested_effects_digest,
    ...executionLineageAssertion,
  });
  const port = createActivePhysicalDispatchAuthorityPort({
    port_id: "dispatch-authority-active-port-v1",
    grant_projection: grantProjection,
    grant_verifier: verifier,
    expected_grant_bindings: expectedGrantBindings,
    execution_request: request,
    effect_registry: effectRegistry,
  });
  return {
    assertion,
    authority,
    effectRegistry,
    executionAssertion,
    expectedGrantBindings,
    grantProjection,
    keyPair,
    port,
    request,
    signedGrant,
    verifier,
    getReplayCount: () => replayCount,
    getVerifyCount: () => verifyCount,
    setNow: (value) => { now = value; },
  };
}

function mockAssertion(overrides = {}) {
  return {
    session_nucleus_hash: digest("mock-session-nucleus"),
    signed_grant_digest: digest("mock-signed-grant"),
    execution_request_digest: digest("mock-execution-request"),
    experiment_plan_hash: digest("mock-experiment-plan"),
    execution_lineage_digest: hashCanonicalJson({
      version: 1,
      ...mockExecutionLineage(),
    }),
    execution_principal_id: "principal:mock-worker-1",
    attempt_ref: "attempt:mock-attempt-1",
    instrument_ref: "instrument:mock-reader-1",
    lease_id: "mock-lease-1",
    fencing_token: "mock-fence-1",
    fencing_generation: 1,
    operation_id: "mock.observe.v1",
    provider_id: "deterministic_dispatch_fixture",
    provider_descriptor_digest: digest("mock-provider-descriptor"),
    effect_not_before: "2026-07-18T00:00:00.000Z",
    effect_deadline: "2026-07-18T00:01:00.000Z",
    ...overrides,
  };
}

function mockExecutionLineage(overrides = {}) {
  const compiledCommandDigest = digest("mock-compiled-command");
  return {
    compiler_id: "closed_mock_compiler_v1",
    compiler_manifest_digest: digest("mock-compiler-manifest"),
    compiler_registry_digest: digest("mock-compiler-registry"),
    compiled_command_id: "compiled-command:mock-1",
    compiled_command_capability_digest: compiledCommandDigest,
    compiled_operation_digest: digest("mock-compiled-operation"),
    provider_command_ref: "command:mock-1",
    command_input_ref: "command-input:mock-1",
    command_input_digest: compiledCommandDigest,
    maximum_response_bytes: 64,
    vault_reservation_handle: `vault-reservation:v1:${"B".repeat(43)}`,
    vault_reservation_digest: digest("mock-vault-reservation"),
    vault_ingest_capability_digest: digest("mock-vault-ingest"),
    vault_byte_limit: 64,
    worker_bundle_digest: digest("mock-worker-bundle"),
    worker_launch_profile_digest: digest("mock-worker-launch-profile"),
    worker_fence_plan_digest: digest("mock-worker-fence"),
    transport_profile_digest: digest("mock-transport-profile"),
    durable_exchange_plan_digest: digest("mock-durable-exchange-plan"),
    terminal_receipt_recipient_digest: digest("mock-terminal-recipient"),
    safety_supervisor_plan_digest: digest("mock-safety-plan"),
    ...overrides,
  };
}

function mockActiveAdmissionAssertion(overrides = {}) {
  return {
    physical_scope_axis_digest: digest("mock-physical-scope-axis"),
    physical_scope_policy_id: "mock_physical_scope_policy",
    physical_scope_policy_digest: digest("mock-physical-scope-policy"),
    physical_scope_projection_digest: digest("mock-physical-scope-projection"),
    authority_epoch: 1,
    revocation_generation: 0,
    authority_resolution_digest: digest("mock-authority-resolution"),
    caller_role_id: "evaluator-physical-agent",
    requester_principal_id: "principal:mock-requester-1",
    ipc_peer_principal_id: "principal:mock-ipc-peer-1",
    capability_pack_id: "physical",
    capability_pack_version: "1",
    capability_pack_digest: digest("mock-capability-pack"),
    technique_cell_id: "physical-cell:mock-cell-1",
    inventory_observation_ref: "inventory-observation:mock-inventory-1",
    inventory_observation_digest: digest("mock-inventory-observation"),
    assurance_profile_id: "mock_assurance_profile",
    assurance_claims_digest: digest("mock-assurance-claims"),
    provider_manifest_digest: digest("mock-provider-manifest"),
    availability_variant_id: "mock-availability-variant",
    availability_variant_digest: digest("mock-availability-variant"),
    authorized_transition_set_digest: digest("mock-authorized-transition-set"),
    workspace_snapshot_ref: "workspace-snapshot:mock-workspace-1",
    workspace_snapshot_digest: digest("mock-workspace-snapshot"),
    observer_plan_digest: digest("mock-observer-plan"),
    control_plan_digest: digest("mock-control-plan"),
    cleanup_plan_digest: digest("mock-cleanup-plan"),
    ...overrides,
  };
}

function mockPort(overrides = {}) {
  const assertion = {
    ...mockAssertion(),
    ...mockExecutionLineage(),
    ...mockActiveAdmissionAssertion(),
    session_id: "mock-session-1",
    node_id: "mock-node-1",
    contract_hash: digest("mock-contract"),
    prep_token_hash: digest("mock-prep-token"),
    dispatch_event_id: "mock-dispatch-event-1",
    graph_context_hash: digest("mock-graph-context"),
    resource_bundle_digest: digest("mock-resource-bundle"),
    operation_digest: digest("mock-operation"),
    parameter_digest: digest("mock-parameter"),
    requested_effects_digest: digest("mock-requested-effects"),
  };
  return createDeterministicMockDispatchAuthorityPort({
    port_id: "dispatch-authority-mock-port-v1",
    session_nucleus_hash: assertion.session_nucleus_hash,
    provider_id: assertion.provider_id,
    provider_descriptor_digest: assertion.provider_descriptor_digest,
    execution_principal_id: assertion.execution_principal_id,
    test_only_execution_assertion: assertion,
    ...overrides,
  });
}

function activeProviderBridgeFixture() {
  const reservation = createPhysicalReservationFixture();
  const providerDescriptorDigest = digest("active-bridge-provider-descriptor");
  const operationDigest = digest("active-bridge-operation");
  const active = activeGrantFixture({
    providerId: "deterministic_mock",
    providerDescriptorDigest,
    operationDigest,
    requestOverrides: {
      session_id: reservation.reservationBinding.session_id,
      session_nucleus_hash: reservation.request.session_nucleus_hash,
      execution_principal_id: reservation.request.execution_principal_ref,
      instrument_ref: reservation.held.receipt.allocations[0].resource_ref,
      node_id: reservation.request.node_id,
      contract_hash: reservation.request.contract_hash,
      prep_token_hash: reservation.reservationBinding.prep_token_hash,
      dispatch_event_id: reservation.reservationBinding.dispatch_event_id,
      graph_context_hash: reservation.reservationBinding.graph_context_hash,
      attempt_id: reservation.request.attempt_ref.slice("attempt:".length),
      resource_bundle_digest: reservation.request.resource_bundle_digest,
      not_before: reservation.request.effect_not_before,
      expires_at: reservation.request.effect_deadline,
    },
  });
  const providerInput = {
    version: 1,
    provider_id: "deterministic_mock",
    provider_descriptor_digest: providerDescriptorDigest,
    semantic_manifest_digest: digest("active-bridge-provider-manifest"),
    device_ref: "device:active-bridge-reader",
    device_identity_digest: digest("active-bridge-device"),
    custody_ref: "custody:active-bridge-worker",
    custody_identity_digest: digest("active-bridge-custody"),
    custody_epoch: 1,
  };
  const provider = normalizePhysicalProviderBinding(providerInput);
  const allocation = reservation.held.receipt.allocations[0];
  const requirement = reservation.bundle.requirements[0];
  const authorizationPort = createPhysicalProviderCommandAuthorizationPort({
    port_id: "active_bridge_command_authority",
    semantic_authority_digest: active.request.execution_request_digest,
    authorization_epoch: 1,
    provider_binding_digest: provider.provider_binding_digest,
    reservation_binding: {
      reservation_request_digest: reservation.request.reservation_request_digest,
      node_id: reservation.request.node_id,
      contract_hash: reservation.request.contract_hash,
      source_graph_hash: reservation.request.source_graph_hash,
      session_nucleus_hash: reservation.request.session_nucleus_hash,
      resource_bundle_digest: reservation.request.resource_bundle_digest,
      allocation_digest: reservation.reservationBinding.allocation_digest,
    },
    resource_bundle: reservation.bundle,
    receipt_allocations: reservation.held.receipt.allocations,
    authorizations: [
      ["command", "command:active-first"],
      ["command", "command:active-later"],
      ["cleanup", "command:active-cleanup"],
      ["fence", "command:active-fence"],
      ["quarantine", "command:active-quarantine"],
    ].map(([command_kind, command_ref]) => ({
      command_kind,
      command_ref,
      operation_id: active.request.operation_id,
      operation_digest: operationDigest,
      semantic_owner_ref: `semantic-owner:active-${command_kind}-${command_ref.split(":").at(-1)}`,
      semantic_owner_digest: digest(`active-${command_ref}`),
      requested_effect_digest: requirement.requested_effect_digests[0],
      requested_effects_digest: active.request.requested_effects_digest,
      resource_alias: allocation.alias,
      resource_ref: allocation.resource_ref,
      resource_requirement_digest: hashCanonicalJson(requirement),
    })),
  });
  const calls = [];
  let observeHook = null;
  const definition = (ref) => ({
    command_authorization: resolvePhysicalProviderCommandAuthorization(authorizationPort, ref),
    execute: async () => {
      calls.push(ref);
      return { version: 1, completion: "confirmed", provider_result_digest: digest(ref) };
    },
  });
  const registry = createPhysicalProviderCommandRegistry({
    provider_binding: providerInput,
    command_authorization_port: authorizationPort,
    completion_verification_port: createTestCompletionVerificationPort("dispatch_authority"),
    observe_binding: () => {
      if (observeHook) observeHook();
      return structuredClone(providerInput);
    },
    commands: [definition("command:active-first"), definition("command:active-later")],
    compensation: {
      cleanup: definition("command:active-cleanup"),
      fence: definition("command:active-fence"),
      quarantine: definition("command:active-quarantine"),
    },
  });
  const bridge = createPhysicalProviderDispatchBridge({
    reservation_authority: reservation.authority,
    reservation_credential: reservation.held.credential,
    reservation_binding: reservation.reservationBinding,
    dispatch_head_fence: createPhysicalProviderDispatchHeadFence({
      reservation_binding: reservation.reservationBinding,
      run_while_current: (invoke) => invoke(),
    }),
    command_registry: registry,
    dispatch_authority_port: active.port,
  });
  const invoke = (method, ref) => {
    const command = resolvePhysicalProviderCommand(registry, ref);
    const capability = bridge.createDispatchCapability(command);
    const ordinary = method === "dispatch";
    return bridge[method](capability, createPhysicalProviderCommandRequest(capability, {
      command_input_ref: ordinary
        ? active.request.execution_lineage.command_input_ref
        : `command-input:${ref.split(":").at(-1)}`,
      command_input_digest: ordinary
        ? active.request.execution_lineage.command_input_digest
        : active.request.parameter_digest,
    }));
  };
  return {
    active,
    bridge,
    calls,
    cleanup: () => invoke("cleanup", "command:active-cleanup"),
    dispatch: (ref) => invoke("dispatch", ref),
    setObserveHook(callback) { observeHook = callback; },
  };
}

class MemoryStateAnchor {
  constructor() {
    this.state = null;
  }

  readState() {
    return this.state == null ? null : structuredClone(this.state);
  }

  compareAndSet(request) {
    const generation = this.state == null ? null : this.state.generation;
    const head = this.state == null ? null : this.state.head_event_digest;
    if (request.expected_generation !== generation
        || request.expected_head_event_digest !== head) return false;
    this.state = structuredClone(request.next_state);
    return true;
  }
}

function nextJournal(previous, state, providerState, millis) {
  const candidate = {
    ...previous,
    journal_entry_ref: `journal-entry:dispatch-authority-${previous.sequence + 1}`,
    state,
    provider_state: providerState,
    provider_sequence: providerState === previous.provider_state
      ? previous.provider_sequence
      : previous.provider_sequence + 1,
    effect_disposition: "not_dispatched",
    sequence: previous.sequence + 1,
    previous_entry_digest: previous.journal_entry_digest,
    recorded_at: `2026-07-18T00:00:00.${String(millis).padStart(3, "0")}Z`,
    fsynced_at: `2026-07-18T00:00:00.${String(millis + 1).padStart(3, "0")}Z`,
  };
  delete candidate.journal_entry_digest;
  return assertAttemptJournalAppend(previous, candidate);
}

test("dispatch authority ports are private branded capabilities and expose only safe digests", () => {
  const fixture = activeGrantFixture();
  const port = fixture.port;
  assert.equal(assertPhysicalDispatchAuthorityPort(port), port);
  assert.equal(Object.isFrozen(port), true);
  assert.deepEqual(Reflect.ownKeys(port).sort(), [
    "authority_binding_digest",
    "authority_mode",
    "port_id",
    "trusted_clock_mode",
    "version",
  ]);
  assert.equal(port.trusted_clock_mode, "deterministic_test_clock");

  const serialized = JSON.stringify(port);
  for (const secret of [
    fixture.signedGrant.authentication.signature,
    fixture.signedGrant.payload.grant_ref,
    fixture.request.fencing_token,
    fixture.verifier.verifier_id,
    fixture.authority.issuer_key_id,
    fixture.authority.issuer_public_key_digest,
    fixture.keyPair.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
  ]) {
    assert.equal(serialized.includes(secret), false);
  }
  for (const forbiddenField of [
    "grant_projection",
    "grant_verifier",
    "expected_grant_bindings",
    "signature",
    "authentication",
    "private_key",
    "public_key",
  ]) {
    assert.equal(forbiddenField in port, false);
  }

  const clone = structuredClone(port);
  assert.throws(
    () => assertPhysicalDispatchAuthorityPort(clone),
    /must be created by Bob's authority factory/,
  );
  assert.throws(
    () => assertCurrentPhysicalDispatchAuthority(clone, fixture.assertion),
    /must be created by Bob's authority factory/,
  );
  assert.throws(
    () => createActivePhysicalDispatchAuthorityPort({
      port_id: "dispatch-authority-leaky-port-v1",
      grant_projection: fixture.grantProjection,
      grant_verifier: fixture.verifier,
      expected_grant_bindings: fixture.expectedGrantBindings,
      private_key: "must-not-cross",
    }),
    /unknown fields: private_key/,
  );
});

test("active dispatch ports publicly preserve the signed production clock mode", () => {
  const clockPort = signedZeroUncertaintyClockPort();
  const fixture = activeGrantFixture({
    providerId: "chameleon_ultra",
    trustedClockPort: clockPort,
  });
  assert.equal(fixture.verifier.trusted_clock_mode, "signed_monotonic_wall_mapping");
  assert.equal(fixture.grantProjection.trusted_clock_mode, "signed_monotonic_wall_mapping");
  assert.equal(fixture.port.trusted_clock_mode, "signed_monotonic_wall_mapping");
  assert.equal("trusted_clock_port" in fixture.port, false);
  assert.deepEqual(
    assertCurrentPhysicalDispatchAuthority(fixture.port, fixture.assertion),
    fixture.assertion,
  );
});

test("active dispatch rejects deterministic time for every non-registry provider identity", () => {
  for (const providerId of [
    "chameleon_ultra",
    "deterministic_mock_redirected",
    "deterministic_dispatch_fixture",
  ]) {
    assert.throws(
      () => activeGrantFixture({ providerId }),
      /non-deterministic provider requires a signed trusted clock/,
      providerId,
    );
  }
  assert.equal(activeGrantFixture().port.trusted_clock_mode, "deterministic_test_clock");
});

test("deterministic mock authority is restricted and rejects every bound identity drift", () => {
  assert.throws(
    () => mockPort({ provider_id: "chameleon_ultra" }),
    /restricted to deterministic_\* provider IDs/,
  );
  const port = mockPort();
  const assertion = mockAssertion();
  assert.equal(port.authority_mode, "deterministic_mock");
  assert.equal(port.trusted_clock_mode, "deterministic_test_clock");
  assert.deepEqual(assertCurrentPhysicalDispatchAuthority(port, assertion), assertion);

  for (const [field, replacement] of Object.entries({
    session_nucleus_hash: digest("other-mock-session-nucleus"),
    provider_id: "deterministic_other_fixture",
    provider_descriptor_digest: digest("other-mock-provider-descriptor"),
    execution_principal_id: "principal:other-mock-worker-1",
  })) {
    assert.throws(
      () => assertCurrentPhysicalDispatchAuthority(port, mockAssertion({ [field]: replacement })),
      new RegExp(`${field} binding drift`),
      field,
    );
  }
  assert.throws(
    () => assertPhysicalDispatchAuthorityPort(structuredClone(port)),
    /must be created by Bob's authority factory/,
  );
});

test("dispatch authority factories and assertions reject accessors without invoking them", () => {
  let reads = 0;
  const factoryInput = {
    port_id: "dispatch-authority-hostile-port-v1",
    session_nucleus_hash: digest("hostile-session-nucleus"),
    provider_descriptor_digest: digest("hostile-provider-descriptor"),
    execution_principal_id: "principal:hostile-worker-1",
  };
  Object.defineProperty(factoryInput, "provider_id", {
    enumerable: true,
    get() { reads += 1; return "deterministic_hostile"; },
  });
  assert.throws(
    () => createDeterministicMockDispatchAuthorityPort(factoryInput),
    /provider_id must be an enumerable data field/,
  );
  const port = mockPort();
  const assertion = mockAssertion();
  Object.defineProperty(assertion, "provider_id", {
    enumerable: true,
    get() { reads += 1; return "deterministic_dispatch_fixture"; },
  });
  assert.throws(
    () => assertCurrentPhysicalDispatchAuthority(port, assertion),
    /provider_id must be an enumerable data field/,
  );
  assert.equal(reads, 0);
});

test("active authority accepts only the exact dispatch identity and a contained effect window", () => {
  const fixture = activeGrantFixture();
  const accepted = assertCurrentPhysicalDispatchAuthority(fixture.port, fixture.assertion);
  assert.equal(Object.isFrozen(accepted), true);
  assert.deepEqual(accepted, fixture.assertion);

  const mutableBindings = { ...fixture.expectedGrantBindings };
  const snapshottedPort = createActivePhysicalDispatchAuthorityPort({
    port_id: "dispatch-authority-snapshotted-port-v1",
    grant_projection: fixture.grantProjection,
    grant_verifier: fixture.verifier,
    expected_grant_bindings: mutableBindings,
    execution_request: fixture.request,
    effect_registry: fixture.effectRegistry,
  });
  mutableBindings.provider_id = "other_dispatch_provider";
  assert.doesNotThrow(
    () => assertCurrentPhysicalDispatchAuthority(snapshottedPort, fixture.assertion),
    "caller mutation cannot alter the port's private grant bindings",
  );

  const replacements = {
    session_nucleus_hash: digest("other-session-nucleus"),
    signed_grant_digest: digest("other-signed-grant"),
    execution_request_digest: digest("other-execution-request"),
    execution_principal_id: "principal:other-dispatch-worker-1",
    attempt_ref: "attempt:other-dispatch-attempt-1",
    instrument_ref: "instrument:other-dispatch-reader-1",
    lease_id: "other-dispatch-lease-1",
    fencing_token: "other-dispatch-fence-1",
    fencing_generation: 2,
    operation_id: "other.operation.v1",
    provider_id: "other_dispatch_provider",
    provider_descriptor_digest: digest("other-provider-descriptor"),
  };
  for (const [field, replacement] of Object.entries(replacements)) {
    assert.throws(
      () => assertCurrentPhysicalDispatchAuthority(
        fixture.port,
        { ...fixture.assertion, [field]: replacement },
      ),
      new RegExp(`${field} binding drift`),
      field,
    );
  }
  assert.throws(
    () => assertCurrentPhysicalDispatchAuthority(fixture.port, {
      ...fixture.assertion,
      effect_not_before: "2026-07-17T23:59:59.999Z",
    }),
    /effect window exceeds the signed grant/,
  );
  assert.throws(
    () => assertCurrentPhysicalDispatchAuthority(fixture.port, {
      ...fixture.assertion,
      effect_deadline: "2026-07-18T00:01:00.001Z",
    }),
    /effect window exceeds the signed grant/,
  );
  assert.throws(
    () => assertCurrentPhysicalDispatchAuthority(fixture.port, {
      ...fixture.assertion,
      unexpected_authority: "allow",
    }),
    /unknown fields: unexpected_authority/,
  );
  const { operation_id: ignoredOperation, ...missingOperation } = fixture.assertion;
  void ignoredOperation;
  assert.throws(
    () => assertCurrentPhysicalDispatchAuthority(fixture.port, missingOperation),
    /is missing fields: operation_id/,
  );
});

test("active authority revalidates issuer and trust-root revocation at every use", () => {
  for (const [name, mutate, pattern] of [
    ["issuer revocation", (fixture) => { fixture.authority.issuer_revoked = true; }, /issuer is not currently usable/],
    ["trust-root revocation", (fixture) => { fixture.authority.trust_root_revoked = true; }, /trust root is not currently usable/],
  ]) {
    const fixture = activeGrantFixture();
    assert.doesNotThrow(
      () => assertCurrentPhysicalDispatchAuthority(fixture.port, fixture.assertion),
      name,
    );
    mutate(fixture);
    assert.throws(
      () => assertCurrentPhysicalDispatchAuthority(fixture.port, fixture.assertion),
      pattern,
      name,
    );
    assert.equal(fixture.getVerifyCount(), 1, `${name} must not repeat signature verification`);
    assert.equal(fixture.getReplayCount(), 1, `${name} must not repeat replay reservation`);
  }
});

test("active authority uses trusted time and fails closed at the signed expiry instant", () => {
  const fixture = activeGrantFixture();
  assertCurrentPhysicalDispatchAuthority(fixture.port, fixture.assertion);
  fixture.setNow(fixture.request.expires_at);
  assert.throws(
    () => assertCurrentPhysicalDispatchAuthority(fixture.port, fixture.assertion),
    /active physical execution grant has expired/,
  );
  assert.equal(fixture.getVerifyCount(), 1);
  assert.equal(fixture.getReplayCount(), 1);
});

test("active execution authority claims the exact signed graph request once and revalidates live trust", () => {
  const fixture = activeGrantFixture();
  const claim = claimPhysicalDispatchExecutionAuthority(fixture.port);
  const owner = Object.freeze({});
  assert.equal(claim.execution_request_digest, fixture.request.execution_request_digest);
  assert.equal(claim.node_id, fixture.request.node_id);
  assert.equal(claim.physical_scope_axis_digest, fixture.grantProjection.physical_scope_axis_digest);
  assert.equal(claim.capability_pack_id, fixture.request.capability_pack_id);
  assert.equal(claim.capability_pack_version, fixture.request.capability_pack_version);
  assert.equal(claim.capability_pack_digest, fixture.request.capability_pack_digest);
  assert.equal(claim.technique_cell_id, fixture.request.technique_cell_id);
  assert.equal(claim.availability_variant_id, fixture.request.availability_variant_id);
  assert.equal(claim.availability_variant_digest, fixture.request.availability_variant_digest);
  assert.equal(claim.inventory_observation_ref, fixture.request.inventory_observation_ref);
  assert.equal(claim.assurance_claims_digest, fixture.request.assurance_claims_digest);
  assert.equal(claim.workspace_snapshot_digest, fixture.request.workspace_snapshot_digest);
  assert.equal(claim.observer_plan_digest, fixture.request.observer_plan_digest);
  assert.equal(claim.control_plan_digest, fixture.request.control_plan_digest);
  assert.equal(claim.cleanup_plan_digest, fixture.request.cleanup_plan_digest);
  assert.equal(claim.fencing_generation, 1);
  assert.equal(JSON.stringify(claim).includes(fixture.request.fencing_token), false);
  assert.match(claim.fencing_token_digest, /^[a-f0-9]{64}$/u);
  assert.throws(
    () => assertCurrentPhysicalDispatchExecutionAuthorityClaim(claim, owner),
    /not owned by this consumer/,
  );
  takePhysicalDispatchExecutionAuthorityClaimOwnership(claim, owner);
  assert.equal(assertCurrentPhysicalDispatchExecutionAuthorityClaim(claim, owner), claim);
  assert.throws(
    () => takePhysicalDispatchExecutionAuthorityClaimOwnership(claim, Object.freeze({})),
    /ownership was already transferred/,
  );
  assert.throws(
    () => claimPhysicalDispatchExecutionAuthority(fixture.port),
    /already claimed/,
  );
  fixture.authority.issuer_revoked = true;
  assert.throws(
    () => assertCurrentPhysicalDispatchExecutionAuthorityClaim(claim, owner),
    /issuer is not currently usable/,
  );
});

test("active grant revocation stops the ordinary command and later cleanup before provider invocation", async () => {
  const first = activeProviderBridgeFixture();
  first.active.authority.issuer_revoked = true;
  assert.equal((await first.dispatch("command:active-first")).kind, "fenced");
  assert.equal(first.calls.length, 0);

  const later = activeProviderBridgeFixture();
  assert.equal((await later.dispatch("command:active-first")).kind, "confirmed");
  later.active.authority.trust_root_revoked = true;
  assert.equal((await later.cleanup()).kind, "quarantined");
  assert.deepEqual(later.calls, ["command:active-first"]);
  assert.equal(
    later.bridge.readiness().active_dispatch_authority_assurance,
    "cryptographically_verified_one_use_active_dispatch_authority_live_revalidated",
  );

  const duringObservation = activeProviderBridgeFixture();
  duringObservation.setObserveHook(() => {
    duringObservation.active.authority.issuer_revoked = true;
  });
  assert.equal((await duringObservation.dispatch("command:active-first")).kind, "fenced");
  assert.equal(duringObservation.calls.length, 0);
});

test("the durable provider permit revalidates live grant revocation at the final effect seam", (t) => {
  const fixture = activeGrantFixture();
  fixture.setNow("2026-07-18T00:00:04.000Z");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-dispatch-authority-store-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  let storeNow = Date.parse("2026-07-18T00:00:04.000Z");
  const store = createDurableInstrumentLeaseStore({
    root,
    runtimeId: `physical-runtime:v1:${digest("dispatch-authority-runtime").slice(0, 32)}`,
    sessionNucleusHash: fixture.assertion.session_nucleus_hash,
    masterKey: crypto.createHash("sha256").update("dispatch-authority-store-key").digest(),
    stateAnchor: new MemoryStateAnchor(),
    checkpointMode: "legacy_full_audit",
    now: () => new Date(storeNow++),
  });
  t.after(() => {
    try { store.close(); } catch {}
  });

  const lease = {
    version: 1,
    lease_id: fixture.assertion.lease_id,
    instrument_ref: fixture.assertion.instrument_ref,
    owner_principal_id: "principal:dispatch-authority-broker-1",
    execution_principal_id: fixture.assertion.execution_principal_id,
    terminal_receipt_recipient_principal_id: "principal:dispatch-authority-broker-1",
    terminal_receipt_idempotency_domain_digest: digest("dispatch-authority-terminal-domain"),
    attempt_ref: fixture.assertion.attempt_ref,
    operation_id: fixture.assertion.operation_id,
    execution_request_digest: fixture.assertion.execution_request_digest,
    resource_bundle_digest: fixture.request.resource_bundle_digest,
    fencing_token: fixture.request.fencing_token,
    fencing_generation: fixture.assertion.fencing_generation,
    state: "held",
    sequence: 0,
    acquired_at: fixture.request.not_before,
    updated_at: fixture.request.not_before,
    effect_not_before: fixture.assertion.effect_not_before,
    effect_deadline: fixture.assertion.effect_deadline,
    heartbeat_deadline: "2026-07-18T00:00:40.000Z",
    expires_at: fixture.request.expires_at,
  };
  const providerRequestDigest = digest("dispatch-authority-provider-request");
  const journal0 = normalizeAttemptJournalEntry({
    version: 1,
    journal_entry_ref: "journal-entry:dispatch-authority-0",
    attempt_ref: lease.attempt_ref,
    instrument_ref: lease.instrument_ref,
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    fencing_generation: lease.fencing_generation,
    operation_id: lease.operation_id,
    execution_request_digest: lease.execution_request_digest,
    experiment_plan_hash: fixture.assertion.experiment_plan_hash,
    execution_lineage_digest: fixture.assertion.execution_lineage_digest,
    authority_resolution_digest: fixture.authority.authority_resolution_digest,
    signed_grant_digest: fixture.grantProjection.signed_grant_digest,
    replay_claim_digest: fixture.grantProjection.replay_claim_digest,
    replay_reservation_receipt_digest:
      fixture.grantProjection.replay_reservation_receipt_digest,
    provider_id: fixture.assertion.provider_id,
    provider_descriptor_digest: fixture.assertion.provider_descriptor_digest,
    provider_request_digest: providerRequestDigest,
    cleanup_capability_digest: digest("dispatch-authority-cleanup-capability"),
    cleanup_plan_digest: fixture.request.cleanup_plan_digest,
    workspace_snapshot_ref: fixture.request.workspace_snapshot_ref,
    workspace_snapshot_digest: fixture.request.workspace_snapshot_digest,
    stop_contract_digest: digest("dispatch-authority-stop-contract"),
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
  store.appendJournal(journal0);
  const admitted = nextJournal(journal0, "admitted", "prepared", 120);
  store.appendJournal(admitted);
  const starting = nextJournal(admitted, "effect_starting", "prepared", 130);
  store.appendJournal(starting);
  const dispatch = normalizeEffectDispatchRecord({
    version: 1,
    dispatch_event_ref: "dispatch-event:dispatch-authority-1",
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
  const credential = store.commitDispatch(dispatch).dispatch_credential;
  const providerPort = createDurableInstrumentProviderDispatchPort(store, {
    provider_id: fixture.assertion.provider_id,
    provider_descriptor_digest: fixture.assertion.provider_descriptor_digest,
    execution_principal_id: fixture.assertion.execution_principal_id,
    instrument_refs: [fixture.assertion.instrument_ref],
    authority_port: fixture.port,
  });
  const permit = providerPort.redeem(credential, {
    attempt_ref: starting.attempt_ref,
    instrument_ref: starting.instrument_ref,
    operation_id: starting.operation_id,
    provider_id: starting.provider_id,
    provider_descriptor_digest: starting.provider_descriptor_digest,
    dispatch_journal_ref: starting.journal_entry_ref,
    provider_request_digest: starting.provider_request_digest,
    expected_state: "prepared",
    expected_sequence: starting.provider_sequence,
  });
  assert.equal(store.snapshot().dispatch_redemptions.length, 1);

  fixture.authority.issuer_revoked = true;
  let effects = 0;
  assert.throws(
    () => providerPort.consumeEffect(permit, () => { effects += 1; }),
    /issuer is not currently usable/,
  );
  assert.equal(effects, 0);
  assert.equal(fixture.getVerifyCount(), 1, "effect-seam revalidation does not repeat signature work");
  assert.equal(fixture.getReplayCount(), 1, "effect-seam revalidation does not reserve replay again");
});
