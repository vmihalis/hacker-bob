"use strict";

const crypto = require("node:crypto");

const {
  createInitialPhysicalResourceReservationState,
  createPhysicalResourceBundleResolverPort,
  createPhysicalResourceReservationAuthority,
  createPhysicalResourceReservationStatePort,
  physicalResourceReservationReadiness,
  reservePhysicalResources,
} = require("../../lib/resource-reservations.js");
const {
  RESOURCE_INVENTORY_ATTESTATION_DOMAIN,
  RESOURCE_RESERVATION_ATTESTATION_VERSION,
  RESOURCE_RESERVATION_CHECKPOINT_DOMAIN,
  checkpointStateBindings,
  createPhysicalResourceInventoryTrustPort,
  createPhysicalResourceReservationCheckpointTrustPort,
  normalizeSignedPhysicalResourceInventoryAttestation,
  normalizeSignedPhysicalResourceReservationCheckpoint,
  physicalResourceAttestationPublicKeyDigest,
  physicalResourceClockBindingDigest,
  physicalResourceClockEpochTransitionDigest,
  physicalResourceInventoryAttestationSigningMessage,
  physicalResourceReservationAuthorityDigest,
  physicalResourceReservationCheckpointSigningMessage,
  physicalResourceSessionBindingDigest,
  physicalResourceWorkspaceStateDigest,
} = require("../../lib/resource-reservation-attestations.js");
const {
  normalizePhysicalReservationRequest,
  normalizePhysicalResourceBundle,
} = require("../../../../mcp/lib/physical-resource-contract.js");
const {
  normalizePhysicalResourceInventory,
} = require("../../../../mcp/lib/physical-resource-scheduler.js");
const {
  MAX_UNCERTAINTY_MS,
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
} = require("../../../../mcp/lib/physical-trusted-clock.js");
const {
  hashCanonicalJson,
} = require("../../../../mcp/lib/verification-contracts.js");

const clone = (value) => structuredClone(value);
const digest = (label) => hashCanonicalJson({ label });

function createClock(readMonotonicMs = null) {
  const keyPair = crypto.generateKeyPairSync("ed25519");
  let monotonicMs = 1_000;
  const payload = {
    version: 1,
    clock_id: "physical-clock:provider-dispatch-test",
    monotonic_epoch_id: digest("provider-dispatch-monotonic-epoch"),
    mapping_generation: 1,
    reference_monotonic_ms: 1_000,
    reference_utc: "2026-07-18T00:00:02.000Z",
    max_uncertainty_ms: 10,
    not_before: "2026-07-17T23:55:00.000Z",
    expires_at: "2026-07-18T00:10:00.000Z",
    trust_root_epoch: 2,
    authority_epoch: 3,
    revocation_generation: 0,
    signer_key_id: "clock-key:provider-dispatch-test",
    signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
  };
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockMappingSigningMessage(payloadDigest),
    keyPair.privateKey,
  ).toString("base64url");
  const envelope = {
    version: 1,
    domain: TRUSTED_CLOCK_MAPPING_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  const mapping = { ...envelope, signed_mapping_digest: hashCanonicalJson(envelope) };
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
    signer_public_key_digest: payload.signer_public_key_digest,
    public_key: keyPair.publicKey,
  };
  return {
    port: createPhysicalTrustedClockPort({
      port_id: "provider_dispatch_test_clock",
      clock_id: payload.clock_id,
      monotonic_epoch_id: payload.monotonic_epoch_id,
      uncertainty_ceiling_ms: MAX_UNCERTAINTY_MS,
      read_monotonic_ms: readMonotonicMs || (() => monotonicMs),
      read_signed_mapping: () => mapping,
      resolve_current_trust: () => trust,
    }),
    set(timestamp) {
      monotonicMs = 1_000 + Date.parse(timestamp) - Date.parse(payload.reference_utc);
    },
    binding() {
      return {
        clock_id: payload.clock_id,
        monotonic_epoch_id: payload.monotonic_epoch_id,
        clock_mapping_generation: payload.mapping_generation,
        signed_clock_mapping_digest: mapping.signed_mapping_digest,
        clock_trust_root_epoch: payload.trust_root_epoch,
        clock_authority_epoch: payload.authority_epoch,
        clock_revocation_generation: payload.revocation_generation,
      };
    },
  };
}

function signEnvelope(domain, payload, privateKey, signingMessage, normalize) {
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(null, signingMessage(payloadDigest), privateKey).toString("base64url");
  const basis = {
    version: RESOURCE_RESERVATION_ATTESTATION_VERSION,
    domain,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  return normalize({ ...basis, signed_document_digest: hashCanonicalJson(basis) });
}

class MemoryState {
  constructor(state) {
    this.state = clone(state);
    this.casCalls = 0;
    this.throwBeforeNext = false;
    this.throwOnCasNumber = null;
  }

  read() {
    return clone(this.state);
  }

  cas(command) {
    this.casCalls += 1;
    if (this.throwBeforeNext || this.throwOnCasNumber === this.casCalls) {
      this.throwBeforeNext = false;
      throw new Error("provider dispatch test durable CAS acknowledgement unavailable");
    }
    if (this.state.revision !== command.expected_revision
        || this.state.state_digest !== command.expected_state_digest) return false;
    this.state = clone(command.next_state);
    return true;
  }
}

function createTrust({ clock, statePort, resolver, state }) {
  const inventoryKeys = crypto.generateKeyPairSync("ed25519");
  const checkpointKeys = crypto.generateKeyPairSync("ed25519");
  const inventorySigner = {
    inventory_authority_id: "inventory-authority:provider-dispatch-test",
    trust_root_epoch: 11,
    authority_epoch: 12,
    revocation_generation: 1,
    signer_key_id: "inventory-key:provider-dispatch-test",
    signer_public_key_digest: physicalResourceAttestationPublicKeyDigest(inventoryKeys.publicKey),
  };
  const checkpointSigner = {
    checkpoint_authority_id: "checkpoint-authority:provider-dispatch-test",
    trust_root_epoch: 21,
    authority_epoch: 22,
    revocation_generation: 2,
    signer_key_id: "checkpoint-key:provider-dispatch-test",
    signer_public_key_digest: physicalResourceAttestationPublicKeyDigest(checkpointKeys.publicKey),
  };
  let checkpointChain = null;
  let inventoryDocument = null;
  const inventoryTrustPort = createPhysicalResourceInventoryTrustPort({
    port_id: "provider_dispatch_test_inventory_trust",
    inventory_authority_id: inventorySigner.inventory_authority_id,
    resolve_current_trust: () => {
      const anchoredClockBindingDigest = physicalResourceClockBindingDigest(
        inventoryDocument.payload,
      );
      const currentClockBindingDigest = physicalResourceClockBindingDigest(clock.binding());
      const clockEpochTransitionGeneration =
        inventoryDocument.payload.clock_id === clock.binding().clock_id
          && inventoryDocument.payload.monotonic_epoch_id === clock.binding().monotonic_epoch_id
          ? 0
          : 1;
      return {
        version: 1,
        trusted: true,
        revoked: false,
        inventory_authority_id: inventorySigner.inventory_authority_id,
        current_attestation_generation: inventoryDocument.payload.attestation_generation,
        current_signed_attestation_digest: inventoryDocument.signed_document_digest,
        anchored_clock_binding_digest: anchoredClockBindingDigest,
        current_clock_binding_digest: currentClockBindingDigest,
        clock_epoch_transition_generation: clockEpochTransitionGeneration,
        clock_epoch_transition_digest: physicalResourceClockEpochTransitionDigest({
          anchored_clock_binding_digest: anchoredClockBindingDigest,
          current_clock_binding_digest: currentClockBindingDigest,
          clock_epoch_transition_generation: clockEpochTransitionGeneration,
        }),
        ...inventorySigner,
        public_key: inventoryKeys.publicKey,
      };
    },
  });
  const checkpointTrustPort = createPhysicalResourceReservationCheckpointTrustPort({
    port_id: "provider_dispatch_test_checkpoint_trust",
    checkpoint_authority_id: checkpointSigner.checkpoint_authority_id,
    resolve_current_trust: () => {
      const first = checkpointChain[0];
      const last = checkpointChain.at(-1);
      const anchoredClockBindingDigest = physicalResourceClockBindingDigest(last.payload);
      const currentClockBindingDigest = physicalResourceClockBindingDigest(clock.binding());
      const clockEpochTransitionGeneration = last.payload.clock_id === clock.binding().clock_id
          && last.payload.monotonic_epoch_id === clock.binding().monotonic_epoch_id
        ? 0
        : 1;
      return {
        version: 1,
        trusted: true,
        revoked: false,
        checkpoint_authority_id: checkpointSigner.checkpoint_authority_id,
        anchor_checkpoint_generation: first.payload.checkpoint_generation,
        anchor_signed_checkpoint_digest: first.signed_document_digest,
        current_checkpoint_generation: last.payload.checkpoint_generation,
        current_signed_checkpoint_digest: last.signed_document_digest,
        anchored_clock_binding_digest: anchoredClockBindingDigest,
        current_clock_binding_digest: currentClockBindingDigest,
        clock_epoch_transition_generation: clockEpochTransitionGeneration,
        clock_epoch_transition_digest: physicalResourceClockEpochTransitionDigest({
          anchored_clock_binding_digest: anchoredClockBindingDigest,
          current_clock_binding_digest: currentClockBindingDigest,
          clock_epoch_transition_generation: clockEpochTransitionGeneration,
        }),
        ...checkpointSigner,
        public_key: checkpointKeys.publicKey,
      };
    },
  });
  const authorityDigest = physicalResourceReservationAuthorityDigest({
    state_domain_digest: statePort.state_domain_digest,
    broker_ref: state.broker_ref,
    broker_epoch: state.broker_epoch,
    session_nucleus_hash: state.inventory.session_nucleus_hash,
    source_graph_hash: state.inventory.source_graph_hash,
    state_port_id: statePort.port_id,
    trusted_clock_port_id: clock.port.port_id,
    bundle_resolver_port_id: resolver.port_id,
    inventory_trust_port_id: inventoryTrustPort.port_id,
    checkpoint_trust_port_id: checkpointTrustPort.port_id,
  });
  const sessionBindingDigest = physicalResourceSessionBindingDigest({
    broker_ref: state.broker_ref,
    broker_epoch: state.broker_epoch,
    session_nucleus_hash: state.inventory.session_nucleus_hash,
    source_graph_hash: state.inventory.source_graph_hash,
  });

  function checkpoint(checkpointState) {
    const bindings = checkpointStateBindings(checkpointState);
    return signEnvelope(
      RESOURCE_RESERVATION_CHECKPOINT_DOMAIN,
      {
        version: 1,
        checkpoint_authority_id: checkpointSigner.checkpoint_authority_id,
        checkpoint_generation: checkpointState.revision + 1,
        prior_checkpoint_digest: checkpointState.revision === 0
          ? null
          : digest(`provider-dispatch-checkpoint:${checkpointState.revision}`),
        reservation_authority_digest: authorityDigest,
        state_domain_digest: checkpointState.state_domain_digest,
        broker_ref: checkpointState.broker_ref,
        broker_epoch: checkpointState.broker_epoch,
        workspace_state_digest: bindings.workspace_state_digest,
        session_binding_digest: sessionBindingDigest,
        session_nucleus_hash: checkpointState.inventory.session_nucleus_hash,
        source_graph_hash: checkpointState.inventory.source_graph_hash,
        state_revision: bindings.state_revision,
        state_digest: bindings.state_digest,
        prior_state_revision: bindings.prior_state_revision,
        prior_state_digest: bindings.prior_state_digest,
        inventory_generation: bindings.inventory_generation,
        inventory_digest: bindings.inventory_digest,
        inventory_attestation_generation: bindings.inventory_attestation_generation,
        inventory_attestation_digest: bindings.inventory_attestation_digest,
        inventory_attestation_prior_digest: bindings.inventory_attestation_prior_digest,
        inventory_attestation_state_revision: bindings.inventory_attestation_state_revision,
        inventory_attestation_state_digest: bindings.inventory_attestation_state_digest,
        inventory_attestation_prior_inventory_digest:
          bindings.inventory_attestation_prior_inventory_digest,
        attested_inventory_digest: bindings.attested_inventory_digest,
        compaction_generation: bindings.compaction_generation,
        compaction_history_accumulator: bindings.compaction_history_accumulator,
        compaction_prior_accumulator: bindings.compaction_prior_accumulator,
        compaction_source_checkpoint_generation:
          bindings.compaction_source_checkpoint_generation,
        compaction_source_checkpoint_digest: bindings.compaction_source_checkpoint_digest,
        compaction_source_state_revision: bindings.compaction_source_state_revision,
        compaction_source_state_digest: bindings.compaction_source_state_digest,
        compaction_batch_record_digests: bindings.compaction_batch_record_digests,
        compaction_tombstone_set_digest: bindings.compaction_tombstone_set_digest,
        compacted_record_count: bindings.compacted_record_count,
        reservation_tombstone_count: bindings.reservation_tombstone_count,
        reservation_tombstone_digests: bindings.reservation_tombstone_digests,
        compacted_source_record_digests: bindings.compacted_source_record_digests,
        reservation_history_digest: bindings.reservation_history_digest,
        terminal_history_digest: bindings.terminal_history_digest,
        reservation_request_digests: bindings.reservation_request_digests,
        terminal_receipt_digests: bindings.terminal_receipt_digests,
        terminal_record_digests: bindings.terminal_record_digests,
        issued_at: "2026-07-18T00:00:01.000Z",
        not_before: "2026-07-18T00:00:00.000Z",
        expires_at: "2026-07-18T00:09:00.000Z",
        ...clock.binding(),
        ...checkpointSigner,
      },
      checkpointKeys.privateKey,
      physicalResourceReservationCheckpointSigningMessage,
      normalizeSignedPhysicalResourceReservationCheckpoint,
    );
  }

  function inventory(checkpointState, value) {
    inventoryDocument = signEnvelope(
      RESOURCE_INVENTORY_ATTESTATION_DOMAIN,
      {
        version: 1,
        inventory_authority_id: inventorySigner.inventory_authority_id,
        attestation_generation: checkpointState.inventory_attestation_generation + 1,
        prior_attestation_digest: checkpointState.inventory_attestation_digest,
        reservation_authority_digest: authorityDigest,
        state_domain_digest: checkpointState.state_domain_digest,
        broker_ref: checkpointState.broker_ref,
        broker_epoch: checkpointState.broker_epoch,
        workspace_state_digest: physicalResourceWorkspaceStateDigest(value),
        session_binding_digest: sessionBindingDigest,
        session_nucleus_hash: checkpointState.inventory.session_nucleus_hash,
        source_graph_hash: checkpointState.inventory.source_graph_hash,
        expected_state_revision: checkpointState.revision,
        expected_state_digest: checkpointState.state_digest,
        prior_inventory_digest: checkpointState.inventory.inventory_digest,
        inventory_digest: value.inventory_digest,
        inventory: value,
        issued_at: value.captured_at,
        not_before: value.valid_from,
        expires_at: value.expires_at,
        ...clock.binding(),
        ...inventorySigner,
      },
      inventoryKeys.privateKey,
      physicalResourceInventoryAttestationSigningMessage,
      normalizeSignedPhysicalResourceInventoryAttestation,
    );
    return inventoryDocument;
  }

  checkpointChain = Object.freeze([checkpoint(state)]);
  inventory(state, state.inventory);
  return {
    get checkpointChain() { return checkpointChain; },
    checkpointTrustPort,
    checkpoint,
    inventory,
    inventoryTrustPort,
    restartInventoryAttestation: inventoryDocument,
    setCheckpointChain(chain) { checkpointChain = chain; },
  };
}

function createPhysicalReservationFixture(options = {}) {
  const effectDeadline = options.effect_deadline || "2026-07-18T00:00:45.000Z";
  const inventoryExpiresAt = options.inventory_expires_at || "2026-07-18T00:00:40.000Z";
  const cooldownMs = options.cooldown_ms == null ? 0 : options.cooldown_ms;
  const requirement = {
    alias: "instrument",
    resource_kind: "instrument",
    candidate_resource_refs: ["instrument:provider-dispatch-device"],
    ownership: "exclusive",
    capacity_units: 1,
    capability_refs: ["capability:provider.command"],
    requested_effect_digests: [digest("provider-command-effect")],
    constraints: [],
    required_state_epoch_digest: digest("provider-dispatch-device-state"),
    mode_ref: "mode:provider-dispatch",
    workspace_ref: "workspace:provider-dispatch",
  };
  const bundle = options.resource_bundle || normalizePhysicalResourceBundle({
    version: 1,
    bundle_id: "provider-dispatch-test",
    requirements: [requirement],
    attempt_budget: 2,
    duration_ms: 45_000,
    reservation_ttl_ms: 55_000,
    cooldown_ms: cooldownMs,
    preemption_policy: "before_effect_only",
    fairness_class: "physical-test",
    batch_key: "physical:provider-dispatch-test",
    setup_cost_units: 1,
  });
  const request = options.reservation_request || normalizePhysicalReservationRequest({
    version: 1,
    reservation_request_id: "reservation-request:provider-dispatch-test",
    node_id: "TG-provider-dispatch-test",
    contract_hash: digest("provider-dispatch-contract"),
    source_graph_hash: digest("provider-dispatch-graph"),
    session_nucleus_hash: digest("provider-dispatch-nucleus"),
    experiment_ref: "experiment:provider-dispatch-test",
    attempt_ref: "attempt:provider-dispatch-test",
    owner_principal_ref: "principal:broker",
    execution_principal_ref: "principal:provider-worker",
    resource_bundle_digest: bundle.resource_bundle_digest,
    requested_at: "2026-07-18T00:00:00.000Z",
    effect_not_before: "2026-07-18T00:00:01.000Z",
    effect_deadline: effectDeadline,
  });
  const inventory = options.resource_inventory || normalizePhysicalResourceInventory({
    version: 1,
    broker_ref: "broker:provider-dispatch-test",
    broker_epoch: 8,
    inventory_generation: 3,
    captured_at: "2026-07-18T00:00:01.000Z",
    valid_from: "2026-07-18T00:00:00.000Z",
    expires_at: inventoryExpiresAt,
    session_nucleus_hash: request.session_nucleus_hash,
    source_graph_hash: request.source_graph_hash,
    resources: [{
      resource_kind: "instrument",
      resource_ref: "instrument:provider-dispatch-device",
      state_epoch_digest: requirement.required_state_epoch_digest,
      availability: "available",
      total_capacity_units: 1,
      available_capacity_units: 1,
      exclusive_available: true,
      fencing_generation: 5,
      setup_cost_units: 1,
      eligible_requirement_digests: [hashCanonicalJson(bundle.requirements[0])],
      switchable_mode_refs: [requirement.mode_ref],
      switchable_workspace_refs: [requirement.workspace_ref],
      current_mode_ref: requirement.mode_ref,
      current_workspace_ref: requirement.workspace_ref,
    }],
  });
  const initial = createInitialPhysicalResourceReservationState({
    state_domain_digest: options.state_domain_digest || digest("provider-dispatch-state-domain"),
    inventory,
  });
  const memory = options.memory || new MemoryState(initial);
  const statePort = createPhysicalResourceReservationStatePort({
    port_id: "provider_dispatch_test_state",
    state_domain_digest: initial.state_domain_digest,
    read_state: memory.read.bind(memory),
    compare_and_set: memory.cas.bind(memory),
  });
  const resolver = createPhysicalResourceBundleResolverPort({
    port_id: "provider_dispatch_test_bundles",
    resolve_bundle: ({ resource_bundle_digest: requested }) => {
      if (requested !== bundle.resource_bundle_digest) throw new Error("unknown resource bundle");
      return bundle;
    },
  });
  const clock = createClock(options.read_monotonic_ms || null);
  const trust = createTrust({ clock, statePort, resolver, state: memory.read() });
  const authorityInput = {
    state_port: statePort,
    trusted_clock_port: clock.port,
    bundle_resolver_port: resolver,
    inventory_trust_port: trust.inventoryTrustPort,
    checkpoint_trust_port: trust.checkpointTrustPort,
    restart_checkpoint_chain: trust.checkpointChain,
    restart_inventory_attestation: trust.restartInventoryAttestation,
    broker_ref: initial.broker_ref,
    broker_epoch: initial.broker_epoch,
    source_graph_hash: request.source_graph_hash,
    session_nucleus_hash: request.session_nucleus_hash,
  };
  let authority = createPhysicalResourceReservationAuthority(authorityInput);
  if (physicalResourceReservationReadiness(authority).mutation_state
      === "checkpoint_refresh_required") {
    const provisionedCheckpoint = trust.checkpoint(memory.read());
    trust.setCheckpointChain(Object.freeze([provisionedCheckpoint]));
    authority = createPhysicalResourceReservationAuthority({
      ...authorityInput,
      restart_checkpoint_chain: trust.checkpointChain,
      restart_inventory_attestation: trust.restartInventoryAttestation,
    });
    if (physicalResourceReservationReadiness(authority).mutation_state !== "available") {
      throw new Error("provider dispatch fixture failed to externally anchor inventory bootstrap");
    }
    memory.casCalls = 0;
  }
  if (typeof options.before_reserve === "function") options.before_reserve(memory);
  const held = options.reserve === false ? null : reservePhysicalResources(authority, request);
  const reservationBinding = held == null ? null : {
    reservation_ref: held.receipt.reservation_ref,
    receipt_digest: held.receipt.receipt_digest,
    reservation_request_digest: request.reservation_request_digest,
    node_id: request.node_id,
    contract_hash: request.contract_hash,
    source_graph_hash: request.source_graph_hash,
    session_nucleus_hash: request.session_nucleus_hash,
    resource_bundle_digest: request.resource_bundle_digest,
    allocation_plan_digest: held.allocation_plan_digest,
    allocation_digest: hashCanonicalJson(held.receipt.allocations),
    attempt_ref: request.attempt_ref,
    execution_principal_ref: request.execution_principal_ref,
    effect_not_before: request.effect_not_before,
    effect_deadline: request.effect_deadline,
    session_id: "provider-dispatch-session-1",
    prep_token_hash: digest("provider-dispatch-prep-token"),
    dispatch_event_id: "provider-dispatch-event-1",
    graph_context_hash: request.source_graph_hash,
  };
  return {
    authority,
    bundle,
    clock,
    digest,
    held,
    memory,
    request,
    reservationBinding,
    storedRawFence: held == null ? null : memory.state.reservations[0].resource_fences[0].raw_fence,
  };
}

module.exports = {
  clone,
  createPhysicalReservationFixture,
  digest,
};
