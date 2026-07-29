"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const {
  MAX_GENERAL_RESERVATION_TOMBSTONES,
  MAX_RESERVATION_TOMBSTONES,
  RESERVATION_TOMBSTONE_SAFETY_RESERVE,
  assertCurrentPhysicalResourceReservationCredential,
  assertPhysicalResourceEffectAuthorizedNow,
  beginPhysicalResourceCleanup,
  cancelPhysicalResourceReservation,
  compactPhysicalResourceReservationHistory,
  completePhysicalResourceCleanup,
  createInitialPhysicalResourceReservationState,
  createPhysicalResourceBundleResolverPort,
  createPhysicalResourceReservationAuthority,
  createPhysicalResourceReservationEligibilityPort,
  createPhysicalResourceReservationStatePort,
  expirePhysicalResourceReservation,
  fencePhysicalResourceReservation,
  markPhysicalResourceEffectStarted,
  normalizePhysicalResourceReservationState,
  physicalResourceReservationReadiness,
  preemptPhysicalResourceReservation,
  projectPhysicalResourceReservationInventory,
  refreshPhysicalResourceInventory,
  readPhysicalResourceReservationProjection,
  rehydratePhysicalResourceReservationCredential,
  reservePhysicalResources,
  resolveHeldPhysicalResourceForNode,
} = require("../lib/resource-reservations.js");
const {
  MAX_CANONICAL_TREE_NODES,
  MAX_RESERVATION_CHECKPOINT_HISTORY_DIGESTS,
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
  physicalResourceReservationCompactionAccumulatorDigest,
  physicalResourceSessionBindingDigest,
  physicalResourceWorkspaceStateDigest,
} = require("../lib/resource-reservation-attestations.js");
const {
  normalizePhysicalReservationRequest,
  normalizePhysicalResourceBundle,
} = require("../../../mcp/lib/physical-resource-contract.js");
const {
  normalizePhysicalResourceInventory,
} = require("../../../mcp/lib/physical-resource-scheduler.js");
const {
  MAX_UNCERTAINTY_MS,
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
} = require("../../../mcp/lib/physical-trusted-clock.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/lib/verification-contracts.js");

const digest = (label) => hashCanonicalJson({ label });
const clone = (value) => structuredClone(value);

function createTrustedClockFixture(overrides = {}, priorMaterial = null) {
  const binding = {
    clock_id: overrides.clock_id || "physical-clock:resource-reservation-test",
    monotonic_epoch_id: overrides.monotonic_epoch_id
      || digest("resource-reservation-monotonic-epoch"),
    mapping_generation: overrides.mapping_generation || 1,
    trust_root_epoch: overrides.trust_root_epoch || 2,
    authority_epoch: overrides.authority_epoch || 3,
    revocation_generation: overrides.revocation_generation == null
      ? 0
      : overrides.revocation_generation,
  };
  const reusePrior = priorMaterial != null
    && hashCanonicalJson(priorMaterial.binding) === hashCanonicalJson(binding);
  const keyPair = reusePrior
    ? priorMaterial.keyPair
    : crypto.generateKeyPairSync("ed25519");
  const trustMaterial = {
    binding,
    keyPair,
    monotonicMs: reusePrior && Number.isSafeInteger(priorMaterial.monotonicMs)
      ? priorMaterial.monotonicMs
      : 1_000,
  };
  const payload = {
    version: 1,
    clock_id: binding.clock_id,
    monotonic_epoch_id: binding.monotonic_epoch_id,
    mapping_generation: binding.mapping_generation,
    reference_monotonic_ms: 1_000,
    reference_utc: "2026-07-18T00:00:02.000Z",
    max_uncertainty_ms: 10,
    not_before: "2026-07-17T23:55:00.000Z",
    expires_at: "2026-07-18T00:10:00.000Z",
    trust_root_epoch: binding.trust_root_epoch,
    authority_epoch: binding.authority_epoch,
    revocation_generation: binding.revocation_generation,
    signer_key_id: "clock-key:resource-reservation-test",
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
  const mapping = { ...basis, signed_mapping_digest: hashCanonicalJson(basis) };
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
    trustMaterial,
    port: createPhysicalTrustedClockPort({
      port_id: "resource_reservation_test_clock",
      clock_id: payload.clock_id,
      monotonic_epoch_id: payload.monotonic_epoch_id,
      uncertainty_ceiling_ms: MAX_UNCERTAINTY_MS,
      read_monotonic_ms: () => trustMaterial.monotonicMs,
      read_signed_mapping: () => mapping,
      resolve_current_trust: () => trust,
    }),
    set(timestamp) {
      trustMaterial.monotonicMs = 1_000
        + Date.parse(timestamp) - Date.parse(payload.reference_utc);
    },
    attestationClockBinding() {
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

function requirement(overrides = {}) {
  return {
    alias: "reader",
    resource_kind: "instrument",
    candidate_resource_refs: ["instrument:ultra-a"],
    ownership: "exclusive",
    capacity_units: 1,
    capability_refs: ["capability:hf.inventory"],
    requested_effect_digests: [digest("observe-only")],
    constraints: [],
    required_state_epoch_digest: digest("ultra-state"),
    mode_ref: "mode:reader",
    workspace_ref: "workspace:slot-a",
    ...overrides,
  };
}

function makeBundle(overrides = {}) {
  return normalizePhysicalResourceBundle({
    version: 1,
    bundle_id: "resource-reservation-test",
    requirements: [requirement()],
    attempt_budget: 2,
    duration_ms: 30_000,
    reservation_ttl_ms: 45_000,
    cooldown_ms: 5_000,
    preemption_policy: "before_effect_only",
    fairness_class: "physical-test",
    batch_key: "physical:test",
    setup_cost_units: 2,
    ...overrides,
  });
}

function makeRequest(bundle, overrides = {}) {
  return normalizePhysicalReservationRequest({
    version: 1,
    reservation_request_id: "reservation-request:resource-test",
    node_id: "TG-cell-resource-reservation-test",
    contract_hash: digest("resource-contract"),
    source_graph_hash: digest("resource-graph"),
    session_nucleus_hash: digest("resource-nucleus"),
    experiment_ref: "experiment:resource-test",
    attempt_ref: "attempt:resource-test",
    owner_principal_ref: "principal:broker",
    execution_principal_ref: "principal:worker",
    resource_bundle_digest: bundle.resource_bundle_digest,
    requested_at: "2026-07-18T00:00:00.000Z",
    effect_not_before: "2026-07-18T00:00:01.000Z",
    effect_deadline: "2026-07-18T00:00:31.000Z",
    ...overrides,
  });
}

function makeInventory(bundle, overrides = {}) {
  return normalizePhysicalResourceInventory({
    version: 1,
    broker_ref: "broker:physical-test",
    broker_epoch: 4,
    inventory_generation: 7,
    captured_at: "2026-07-18T00:00:01.000Z",
    valid_from: "2026-07-18T00:00:00.000Z",
    expires_at: "2026-07-18T00:00:50.000Z",
    session_nucleus_hash: digest("resource-nucleus"),
    source_graph_hash: digest("resource-graph"),
    resources: [{
      resource_kind: "instrument",
      resource_ref: "instrument:ultra-a",
      state_epoch_digest: digest("ultra-state"),
      availability: "available",
      total_capacity_units: 1,
      available_capacity_units: 1,
      exclusive_available: true,
      fencing_generation: 11,
      setup_cost_units: 2,
      eligible_requirement_digests: [hashCanonicalJson(bundle.requirements[0])],
      switchable_mode_refs: ["mode:reader"],
      switchable_workspace_refs: ["workspace:slot-a"],
      current_mode_ref: "mode:reader",
      current_workspace_ref: "workspace:slot-a",
    }],
    ...overrides,
  });
}

class MemoryCasState {
  constructor(initial) {
    this.state = clone(initial);
    this.calls = { read: 0, cas: 0 };
    this.failNext = false;
    this.throwBeforeNext = false;
    this.throwAfterNext = false;
    this.returnRaw = false;
    this.onRead = null;
    this.onCas = null;
    this.inventoryTrustMaterial = null;
    this.clockTrustMaterial = null;
  }

  read() {
    this.calls.read += 1;
    if (this.onRead) this.onRead();
    return this.returnRaw ? this.state : clone(this.state);
  }

  cas(command) {
    this.calls.cas += 1;
    if (this.onCas) this.onCas();
    if (this.throwBeforeNext) {
      this.throwBeforeNext = false;
      throw new Error("anchor acknowledgement lost before commit");
    }
    if (this.failNext) {
      this.failNext = false;
      return false;
    }
    if (this.state.revision !== command.expected_revision
        || this.state.state_digest !== command.expected_state_digest) return false;
    this.state = clone(command.next_state);
    if (this.throwAfterNext) {
      this.throwAfterNext = false;
      throw new Error("anchor acknowledgement lost after commit");
    }
    return true;
  }
}

function signEnvelope(domain, payload, privateKey, signingMessageFactory, normalize) {
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    signingMessageFactory(payloadDigest),
    privateKey,
  ).toString("base64url");
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

function createReservationTrustFixture({
  clock,
  statePort,
  bundleResolverPort,
  state,
  inventoryTrustMaterial = null,
}) {
  const material = inventoryTrustMaterial || {
    inventoryKeys: crypto.generateKeyPairSync("ed25519"),
    checkpointKeys: crypto.generateKeyPairSync("ed25519"),
    currentInventoryDocument: null,
  };
  const inventoryKeys = material.inventoryKeys;
  const checkpointKeys = material.checkpointKeys
    || crypto.generateKeyPairSync("ed25519");
  material.checkpointKeys = checkpointKeys;
  const inventorySigner = {
    inventory_authority_id: "inventory-authority:resource-reservation-test",
    trust_root_epoch: 11,
    authority_epoch: 12,
    revocation_generation: 1,
    signer_key_id: "inventory-key:resource-reservation-test",
    signer_public_key_digest: physicalResourceAttestationPublicKeyDigest(inventoryKeys.publicKey),
  };
  const checkpointSigner = {
    checkpoint_authority_id: "checkpoint-authority:resource-reservation-test",
    trust_root_epoch: 21,
    authority_epoch: 22,
    revocation_generation: 2,
    signer_key_id: "checkpoint-key:resource-reservation-test",
    signer_public_key_digest: physicalResourceAttestationPublicKeyDigest(checkpointKeys.publicKey),
  };
  let currentInventoryDocument = material.currentInventoryDocument;
  let currentCheckpointChain = null;
  let onInventoryTrust = null;
  let onCheckpointTrust = null;
  let checkpointTrustResponseTransform = null;
  const inventoryTrustPort = createPhysicalResourceInventoryTrustPort({
    port_id: "resource_reservation_test_inventory_trust",
    inventory_authority_id: inventorySigner.inventory_authority_id,
    resolve_current_trust: (query) => {
      if (onInventoryTrust) onInventoryTrust(query);
      if (currentInventoryDocument == null) throw new Error("no current inventory attestation");
      const anchoredClockBindingDigest = physicalResourceClockBindingDigest(
        currentInventoryDocument.payload,
      );
      const currentClockBindingDigest = physicalResourceClockBindingDigest(
        clock.attestationClockBinding(),
      );
      const clockEpochTransitionGeneration =
        currentInventoryDocument.payload.clock_id === clock.attestationClockBinding().clock_id
          && currentInventoryDocument.payload.monotonic_epoch_id
            === clock.attestationClockBinding().monotonic_epoch_id
          ? 0
          : 1;
      const response = {
        version: 1,
        trusted: true,
        revoked: false,
        inventory_authority_id: inventorySigner.inventory_authority_id,
        current_attestation_generation: currentInventoryDocument.payload.attestation_generation,
        current_signed_attestation_digest: currentInventoryDocument.signed_document_digest,
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
      return response;
    },
  });
  const checkpointTrustPort = createPhysicalResourceReservationCheckpointTrustPort({
    port_id: "resource_reservation_test_checkpoint_trust",
    checkpoint_authority_id: checkpointSigner.checkpoint_authority_id,
    resolve_current_trust: (query) => {
      if (onCheckpointTrust) onCheckpointTrust(query);
      if (currentCheckpointChain == null) throw new Error("no current checkpoint chain");
      const first = currentCheckpointChain[0];
      const last = currentCheckpointChain[currentCheckpointChain.length - 1];
      const anchoredClockBindingDigest = physicalResourceClockBindingDigest(last.payload);
      const currentClockBindingDigest = physicalResourceClockBindingDigest(
        clock.attestationClockBinding(),
      );
      const clockEpochTransitionGeneration =
        last.payload.clock_id === clock.attestationClockBinding().clock_id
          && last.payload.monotonic_epoch_id === clock.attestationClockBinding().monotonic_epoch_id
          ? 0
          : 1;
      const response = {
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
      return checkpointTrustResponseTransform
        ? checkpointTrustResponseTransform(response)
        : response;
    },
  });
  const authorityBinding = {
    state_domain_digest: statePort.state_domain_digest,
    broker_ref: state.broker_ref,
    broker_epoch: state.broker_epoch,
    session_nucleus_hash: state.inventory.session_nucleus_hash,
    source_graph_hash: state.inventory.source_graph_hash,
    state_port_id: statePort.port_id,
    trusted_clock_port_id: clock.port.port_id,
    bundle_resolver_port_id: bundleResolverPort.port_id,
    inventory_trust_port_id: inventoryTrustPort.port_id,
    checkpoint_trust_port_id: checkpointTrustPort.port_id,
  };
  const reservationAuthorityDigest = physicalResourceReservationAuthorityDigest(authorityBinding);
  const sessionBindingDigest = physicalResourceSessionBindingDigest({
    broker_ref: state.broker_ref,
    broker_epoch: state.broker_epoch,
    session_nucleus_hash: state.inventory.session_nucleus_hash,
    source_graph_hash: state.inventory.source_graph_hash,
  });

  function signCheckpoint(checkpointState, overrides = {}) {
    const bindings = checkpointStateBindings(checkpointState);
    return signEnvelope(
      RESOURCE_RESERVATION_CHECKPOINT_DOMAIN,
      {
        version: 1,
        checkpoint_authority_id: checkpointSigner.checkpoint_authority_id,
        checkpoint_generation: checkpointState.revision + 1,
        prior_checkpoint_digest: checkpointState.revision === 0
          ? null
          : digest(`externally-anchored-checkpoint:${checkpointState.revision}`),
        reservation_authority_digest: reservationAuthorityDigest,
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
        ...clock.attestationClockBinding(),
        ...checkpointSigner,
        ...overrides,
      },
      checkpointKeys.privateKey,
      physicalResourceReservationCheckpointSigningMessage,
      normalizeSignedPhysicalResourceReservationCheckpoint,
    );
  }

  function signInventory(checkpointState, inventory, overrides = {}) {
    const document = signEnvelope(
      RESOURCE_INVENTORY_ATTESTATION_DOMAIN,
      {
        version: 1,
        inventory_authority_id: inventorySigner.inventory_authority_id,
        attestation_generation: checkpointState.inventory_attestation_generation + 1,
        prior_attestation_digest: checkpointState.inventory_attestation_digest,
        reservation_authority_digest: reservationAuthorityDigest,
        state_domain_digest: checkpointState.state_domain_digest,
        broker_ref: checkpointState.broker_ref,
        broker_epoch: checkpointState.broker_epoch,
        workspace_state_digest: physicalResourceWorkspaceStateDigest(inventory),
        session_binding_digest: sessionBindingDigest,
        session_nucleus_hash: checkpointState.inventory.session_nucleus_hash,
        source_graph_hash: checkpointState.inventory.source_graph_hash,
        expected_state_revision: checkpointState.revision,
        expected_state_digest: checkpointState.state_digest,
        prior_inventory_digest: checkpointState.inventory.inventory_digest,
        inventory_digest: inventory.inventory_digest,
        inventory,
        issued_at: inventory.captured_at,
        not_before: inventory.valid_from,
        expires_at: inventory.expires_at,
        ...clock.attestationClockBinding(),
        ...inventorySigner,
        ...overrides,
      },
      inventoryKeys.privateKey,
      physicalResourceInventoryAttestationSigningMessage,
      normalizeSignedPhysicalResourceInventoryAttestation,
    );
    currentInventoryDocument = document;
    material.currentInventoryDocument = document;
    return document;
  }

  currentCheckpointChain = Object.freeze([signCheckpoint(state)]);
  if (currentInventoryDocument == null) signInventory(state, state.inventory);
  return {
    authorityBinding,
    checkpointTrustPort,
    inventoryTrustPort,
    get restartCheckpointChain() { return currentCheckpointChain; },
    inventoryKeys,
    checkpointKeys,
    inventoryTrustMaterial: material,
    signCheckpoint,
    signInventory,
    setCurrentInventoryDocument(document) {
      currentInventoryDocument = document;
      material.currentInventoryDocument = document;
    },
    setCurrentCheckpointChain(chain) { currentCheckpointChain = chain; },
    setInventoryTrustHook(callback) { onInventoryTrust = callback; },
    setCheckpointTrustHook(callback) { onCheckpointTrust = callback; },
    setCheckpointTrustResponseTransform(callback) {
      checkpointTrustResponseTransform = callback;
    },
  };
}

function fixture({
  bundle = makeBundle(),
  inventory = null,
  memory = null,
  resolveHook = null,
  prepareTrust = null,
  authorityOverrides = {},
  clockOptions = {},
  autoAnchorInventory = true,
} = {}) {
  const resourceInventory = inventory || makeInventory(bundle);
  const initial = createInitialPhysicalResourceReservationState({
    state_domain_digest: digest("resource-state-domain"),
    inventory: resourceInventory,
  });
  const durable = memory || new MemoryCasState(initial);
  const clock = createTrustedClockFixture(clockOptions, durable.clockTrustMaterial);
  durable.clockTrustMaterial = clock.trustMaterial;
  const statePort = createPhysicalResourceReservationStatePort({
    port_id: "resource_reservation_test_state",
    state_domain_digest: digest("resource-state-domain"),
    read_state: durable.read.bind(durable),
    compare_and_set: durable.cas.bind(durable),
  });
  const resolver = createPhysicalResourceBundleResolverPort({
    port_id: "resource_reservation_test_bundles",
    resolve_bundle: ({ resource_bundle_digest: requestedDigest }) => {
      if (resolveHook) resolveHook();
      if (requestedDigest !== bundle.resource_bundle_digest) throw new Error("unknown bundle");
      return bundle;
    },
  });
  const trust = createReservationTrustFixture({
    clock,
    statePort,
    bundleResolverPort: resolver,
    state: durable.read(),
    inventoryTrustMaterial: durable.inventoryTrustMaterial,
  });
  durable.inventoryTrustMaterial = trust.inventoryTrustMaterial;
  const preparedAuthorityOverrides = prepareTrust
    ? (prepareTrust(trust, durable, clock) || {})
    : {};
  const baseAuthorityInput = {
    state_port: statePort,
    trusted_clock_port: clock.port,
    bundle_resolver_port: resolver,
    inventory_trust_port: trust.inventoryTrustPort,
    checkpoint_trust_port: trust.checkpointTrustPort,
    restart_checkpoint_chain: trust.restartCheckpointChain,
    restart_inventory_attestation: trust.inventoryTrustMaterial.currentInventoryDocument,
    broker_ref: "broker:physical-test",
    broker_epoch: 4,
    source_graph_hash: digest("resource-graph"),
    session_nucleus_hash: digest("resource-nucleus"),
    ...authorityOverrides,
    ...preparedAuthorityOverrides,
  };
  let authority = createPhysicalResourceReservationAuthority(baseAuthorityInput);
  if (autoAnchorInventory
      && physicalResourceReservationReadiness(authority).mutation_state
        === "checkpoint_refresh_required") {
    const provisionedHead = durable.read();
    const provisionedCheckpoint = trust.signCheckpoint(provisionedHead);
    trust.setCurrentCheckpointChain(Object.freeze([provisionedCheckpoint]));
    authority = createPhysicalResourceReservationAuthority({
      ...baseAuthorityInput,
      restart_checkpoint_chain: trust.restartCheckpointChain,
      restart_inventory_attestation: trust.inventoryTrustMaterial.currentInventoryDocument,
    });
    assert.equal(
      physicalResourceReservationReadiness(authority).mutation_state,
      "available",
    );
    // Most tests count operation CAS calls, not the explicit trust bootstrap.
    // The dedicated bootstrap test below asserts that provisioning transaction.
    durable.calls = { read: 0, cas: 0 };
  }
  return { authority, bundle, clock, durable, request: makeRequest(bundle), trust };
}

function nodeBinding(request, overrides = {}) {
  return {
    node_id: request.node_id,
    contract_hash: request.contract_hash,
    source_graph_hash: request.source_graph_hash,
    session_nucleus_hash: request.session_nucleus_hash,
    resource_bundle_digest: request.resource_bundle_digest,
    ...overrides,
  };
}

function makeRefreshInventory(state, overrides = {}) {
  const value = clone(state.inventory);
  delete value.inventory_digest;
  value.inventory_generation = state.inventory.inventory_generation + 1;
  value.captured_at = "2026-07-18T00:00:03.000Z";
  value.valid_from = "2026-07-18T00:00:02.000Z";
  value.expires_at = "2026-07-18T00:00:53.000Z";
  Object.assign(value, overrides);
  return normalizePhysicalResourceInventory(value);
}

function anchorReservationHead(fx, state = clone(fx.durable.state)) {
  const checkpoint = fx.trust.signCheckpoint(state);
  const chain = Object.freeze([checkpoint]);
  fx.trust.setCurrentCheckpointChain(chain);
  return chain;
}

function rebindForgedCompactionState(state, mutate) {
  const input = clone(state);
  mutate(input);
  for (const tombstone of input.reservation_tombstones) {
    delete tombstone.tombstone_digest;
    tombstone.tombstone_digest = hashCanonicalJson(tombstone);
  }
  input.compaction_tombstone_set_digest = hashCanonicalJson(input.reservation_tombstones);
  input.compaction_history_accumulator =
    physicalResourceReservationCompactionAccumulatorDigest({
      compaction_generation: input.compaction_generation,
      prior_accumulator: input.compaction_prior_accumulator,
      compacted_record_digests: input.compaction_batch_record_digests,
      source_checkpoint_generation: input.compaction_source_checkpoint_generation,
      source_checkpoint_digest: input.compaction_source_checkpoint_digest,
      source_state_revision: input.compaction_source_state_revision,
      source_state_digest: input.compaction_source_state_digest,
      tombstone_set_digest: input.compaction_tombstone_set_digest,
      tombstone_count: input.reservation_tombstones.length,
      compacted_record_count: input.compacted_record_count,
    });
  delete input.state_digest;
  return normalizePhysicalResourceReservationState(input);
}

function assertNoRawFence(value, rawFence = null) {
  const encoded = JSON.stringify(value);
  assert.doesNotMatch(encoded, /raw_fence|rawFence/u);
  if (rawFence != null) assert.equal(encoded.includes(rawFence), false);
}

test("atomic reservation replans private inventory and exposes only receipt hashes plus opaque credential", () => {
  const fx = fixture();
  const result = reservePhysicalResources(fx.authority, fx.request);
  assert.equal(result.receipt.state, "held");
  assert.equal(result.receipt.allocations[0].fencing_generation, 12);
  assert.match(result.receipt.allocations[0].fencing_token_hash, /^[a-f0-9]{64}$/u);
  assert.equal(result.credential.resource_fence_count, 1);
  assert.equal(result.idempotent, false);
  const storedFence = fx.durable.state.reservations[0].resource_fences[0];
  assertNoRawFence(result, storedFence.raw_fence);
  assert.match(storedFence.raw_fence, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(storedFence.fencing_token_hash, result.receipt.allocations[0].fencing_token_hash);
  const inventory = projectPhysicalResourceReservationInventory(fx.authority);
  assert.equal(inventory.inventory_generation, 8);
  assert.equal(inventory.resources[0].available_capacity_units, 0);
  assert.equal(inventory.resources[0].exclusive_available, false);
  assert.equal(inventory.resources[0].current_mode_ref, "mode:reader");
  assert.equal(inventory.resources[0].current_workspace_ref, "workspace:slot-a");
  const projection = readPhysicalResourceReservationProjection(
    fx.authority,
    result.receipt.reservation_ref,
  );
  assert.equal(projection.allocation_plan_digest, result.allocation_plan_digest);
  assert.equal(projection.broker_reservation_digest, result.reservation_projection.broker_reservation_digest);
  assertNoRawFence(projection, storedFence.raw_fence);
});

test("one CAS holds a complete multi-resource plan with distinct random per-resource fences", () => {
  const secondRequirement = requirement({
    alias: "reader_b",
    candidate_resource_refs: ["instrument:ultra-b"],
    required_state_epoch_digest: digest("ultra-b-state"),
  });
  const bundle = makeBundle({ requirements: [requirement(), secondRequirement] });
  const resourceFor = (requirementInput, resourceRef, stateDigest) => ({
    resource_kind: "instrument",
    resource_ref: resourceRef,
    state_epoch_digest: stateDigest,
    availability: "available",
    total_capacity_units: 1,
    available_capacity_units: 1,
    exclusive_available: true,
    fencing_generation: 11,
    setup_cost_units: 2,
    eligible_requirement_digests: [hashCanonicalJson(requirementInput)],
    switchable_mode_refs: ["mode:reader"],
    switchable_workspace_refs: ["workspace:slot-a"],
    current_mode_ref: "mode:reader",
    current_workspace_ref: "workspace:slot-a",
  });
  const inventory = makeInventory(bundle, {
    resources: [
      resourceFor(bundle.requirements.find((entry) => entry.alias === "reader"), "instrument:ultra-a", digest("ultra-state")),
      resourceFor(bundle.requirements.find((entry) => entry.alias === "reader_b"), "instrument:ultra-b", digest("ultra-b-state")),
    ],
  });
  const fx = fixture({ bundle, inventory });
  const result = reservePhysicalResources(fx.authority, fx.request);
  assert.equal(result.receipt.allocations.length, 2);
  assert.equal(fx.durable.calls.cas, 1);
  assert.deepEqual(fx.durable.state.reservations[0].lock_order, [
    "instrument:ultra-a",
    "instrument:ultra-b",
  ]);
  const rawFences = fx.durable.state.reservations[0].resource_fences.map((entry) => entry.raw_fence);
  const publicHashes = result.receipt.allocations.map((entry) => entry.fencing_token_hash);
  assert.equal(new Set(rawFences).size, 2);
  assert.equal(new Set(publicHashes).size, 2);
  assert.equal(projectPhysicalResourceReservationInventory(fx.authority).resources.every(
    (resource) => resource.available_capacity_units === 0,
  ), true);
  for (const rawFence of rawFences) assertNoRawFence(result, rawFence);
});

test("exact request is idempotent while a conflicting duplicate request ID is refused", () => {
  const fx = fixture();
  const first = reservePhysicalResources(fx.authority, fx.request);
  const count = fx.durable.calls.cas;
  const second = reservePhysicalResources(fx.authority, clone(fx.request));
  assert.equal(second.idempotent, true);
  assert.equal(second.receipt.receipt_digest, first.receipt.receipt_digest);
  assert.equal(fx.durable.calls.cas, count);

  const conflict = makeRequest(fx.bundle, { contract_hash: digest("different-contract") });
  assert.throws(
    () => reservePhysicalResources(fx.authority, conflict),
    (error) => error.code === "reservation_request_identity_conflict",
  );
});

test("held eligibility is privately resolved from exact node bindings and trusted time", () => {
  const fx = fixture();
  const result = reservePhysicalResources(fx.authority, fx.request);
  const port = createPhysicalResourceReservationEligibilityPort(fx.authority);
  const held = resolveHeldPhysicalResourceForNode(port, nodeBinding(fx.request));
  assert.equal(held.held, true);
  assert.equal(held.receipt_digest, result.receipt.receipt_digest);
  assert.equal(held.resource_bundle_digest, fx.bundle.resource_bundle_digest);
  assertNoRawFence(held, fx.durable.state.reservations[0].resource_fences[0].raw_fence);
  assert.equal(resolveHeldPhysicalResourceForNode(
    port,
    nodeBinding(fx.request, { contract_hash: digest("drift") }),
  ), null);

  const started = markPhysicalResourceEffectStarted(fx.authority, result.credential);
  assert.equal(started.receipt.state, "held");
  assert.equal(resolveHeldPhysicalResourceForNode(port, nodeBinding(fx.request)), null);
  assert.throws(
    () => assertCurrentPhysicalResourceReservationCredential(fx.authority, result.credential),
    (error) => error.code === "resource_reservation_credential_stale",
  );
});

test("credential can be rehydrated exactly and cleanup holds capacity through cooldown", () => {
  const fx = fixture();
  const held = reservePhysicalResources(fx.authority, fx.request);
  const restored = rehydratePhysicalResourceReservationCredential(fx.authority, {
    reservation_ref: held.receipt.reservation_ref,
    receipt_digest: held.receipt.receipt_digest,
  });
  assert.equal(restored.credential_binding_digest, held.credential.credential_binding_digest);
  const started = markPhysicalResourceEffectStarted(fx.authority, restored);
  const cleanup = beginPhysicalResourceCleanup(
    fx.authority,
    started.credential,
    "cleanup-handoff:resource-test",
  );
  assert.equal(cleanup.receipt.state, "cleanup_pending");
  assert.equal(projectPhysicalResourceReservationInventory(fx.authority).resources[0].available_capacity_units, 0);
  assert.throws(
    () => completePhysicalResourceCleanup(fx.authority, cleanup.credential),
    (error) => error.code === "reservation_cooldown_pending",
  );

  fx.clock.set("2026-07-18T00:00:08.000Z");
  const released = completePhysicalResourceCleanup(fx.authority, cleanup.credential);
  assert.equal(released.receipt.state, "released");
  assert.equal(released.receipt.terminal_disposition, "cleanup_confirmed");
  assert.equal(released.credential, null);
  const projected = projectPhysicalResourceReservationInventory(fx.authority);
  assert.equal(projected.resources[0].available_capacity_units, 1);
  assert.equal(projected.resources[0].exclusive_available, true);
  assert.equal(projected.resources[0].fencing_generation, 13);
  assert.throws(
    () => rehydratePhysicalResourceReservationCredential(fx.authority, {
      reservation_ref: released.receipt.reservation_ref,
      receipt_digest: released.receipt.receipt_digest,
    }),
    (error) => error.code === "resource_reservation_credential_stale",
  );
});

test("cancel and preempt are strictly before-effect and release/fence transitions rotate authority", () => {
  {
    const fx = fixture();
    const held = reservePhysicalResources(fx.authority, fx.request);
    const cancelled = cancelPhysicalResourceReservation(fx.authority, held.credential);
    assert.equal(cancelled.receipt.terminal_disposition, "cancelled_before_effect");
    assert.equal(projectPhysicalResourceReservationInventory(fx.authority).resources[0].fencing_generation, 13);
  }
  {
    const fx = fixture();
    const held = reservePhysicalResources(fx.authority, fx.request);
    const preempted = preemptPhysicalResourceReservation(fx.authority, held.credential);
    assert.equal(preempted.receipt.terminal_disposition, "preempted_before_effect");
  }
  {
    const fx = fixture();
    const held = reservePhysicalResources(fx.authority, fx.request);
    const started = markPhysicalResourceEffectStarted(fx.authority, held.credential);
    assert.throws(
      () => cancelPhysicalResourceReservation(fx.authority, started.credential),
      (error) => error.code === "reservation_effect_already_started",
    );
    const fenced = fencePhysicalResourceReservation(fx.authority, started.credential);
    assert.equal(fenced.receipt.state, "fenced");
    assert.equal(projectPhysicalResourceReservationInventory(fx.authority).resources[0].availability, "unavailable");
  }
});

test("definitive CAS conflicts replan all-or-none while ambiguous CAS fails closed", () => {
  {
    const fx = fixture();
    fx.durable.failNext = true;
    const result = reservePhysicalResources(fx.authority, fx.request);
    assert.equal(result.receipt.state, "held");
    assert.equal(fx.durable.calls.cas, 2);
    assert.equal(fx.durable.state.reservations.length, 1);
    assert.equal(fx.durable.state.inventory.resources[0].available_capacity_units, 0);
  }
  {
    const fx = fixture();
    fx.durable.throwBeforeNext = true;
    assert.throws(
      () => reservePhysicalResources(fx.authority, fx.request),
      (error) => error.code === "reservation_state_ambiguous",
    );
    const readiness = physicalResourceReservationReadiness(fx.authority);
    assert.equal(readiness.production_ready, false);
    assert.equal(readiness.mutation_state, "ambiguous_fail_closed");
    assert.throws(
      () => reservePhysicalResources(fx.authority, fx.request),
      (error) => error.code === "reservation_state_ambiguous",
    );
  }
  {
    const fx = fixture();
    const held = reservePhysicalResources(fx.authority, fx.request);
    const eligibility = createPhysicalResourceReservationEligibilityPort(fx.authority);
    fx.durable.throwBeforeNext = true;
    assert.throws(
      () => markPhysicalResourceEffectStarted(fx.authority, held.credential),
      (error) => error.code === "reservation_state_ambiguous",
    );
    assert.throws(
      () => resolveHeldPhysicalResourceForNode(eligibility, nodeBinding(fx.request)),
      (error) => error.code === "reservation_state_ambiguous",
    );
    assert.throws(
      () => assertCurrentPhysicalResourceReservationCredential(fx.authority, held.credential),
      (error) => error.code === "reservation_state_ambiguous",
    );
    assert.throws(
      () => rehydratePhysicalResourceReservationCredential(fx.authority, {
        reservation_ref: held.receipt.reservation_ref,
        receipt_digest: held.receipt.receipt_digest,
      }),
      (error) => error.code === "reservation_state_ambiguous",
    );
  }
});

test("unattested genesis provisions once but cannot authorize until its successor is checkpointed", () => {
  const bootstrap = fixture({ autoAnchorInventory: false });
  const readiness = physicalResourceReservationReadiness(bootstrap.authority);
  assert.equal(bootstrap.durable.calls.cas, 1);
  assert.equal(bootstrap.durable.state.revision, 1);
  assert.equal(bootstrap.durable.state.inventory_attestation_generation, 1);
  assert.equal(readiness.restart_checkpoint_state, "inventory_successor_unanchored");
  assert.equal(readiness.checkpoint_verified_revision, 0);
  assert.equal(readiness.live_observed_revision, 1);
  assert.equal(readiness.checkpoint_matches_live_head, false);
  assert.equal(readiness.mutation_state, "checkpoint_refresh_required");
  assert.throws(
    () => reservePhysicalResources(bootstrap.authority, bootstrap.request),
    (error) => error.code === "reservation_checkpoint_refresh_required",
  );
  assert.throws(
    () => createPhysicalResourceReservationEligibilityPort(bootstrap.authority),
    (error) => error.code === "reservation_checkpoint_refresh_required",
  );

  const admitted = fixture({ bundle: bootstrap.bundle, memory: bootstrap.durable });
  const admittedReadiness = physicalResourceReservationReadiness(admitted.authority);
  assert.equal(admittedReadiness.restart_checkpoint_state, "verified_exact_head_at_authority_start");
  assert.equal(admittedReadiness.checkpoint_matches_live_head, true);
  assert.equal(reservePhysicalResources(admitted.authority, admitted.request).receipt.state, "held");

  assert.throws(
    () => fixture({
      autoAnchorInventory: false,
      authorityOverrides: { restart_inventory_attestation: null },
    }),
    (error) => error.code === "reservation_restart_inventory_attestation_invalid",
  );
  assert.throws(
    () => fixture({
      autoAnchorInventory: false,
      prepareTrust: (trust) => ({
        restart_inventory_attestation: trust.restartCheckpointChain[0],
      }),
    }),
    (error) => error.code === "reservation_restart_inventory_attestation_invalid",
  );
});

test("readiness is honest and never invokes arbitrary state, resolver, or clock callbacks", () => {
  const fx = fixture();
  const reads = fx.durable.calls.read;
  const readiness = physicalResourceReservationReadiness(fx.authority);
  assert.equal(readiness.production_ready, false);
  assert.equal(readiness.durability_assurance, "caller_asserted_callback_unattested");
  assert.equal(readiness.restart_checkpoint_state, "verified_exact_head_at_authority_start");
  assert.equal(readiness.checkpoint_matches_live_head, true);
  assert.equal(readiness.checkpoint_verified_revision, readiness.live_observed_revision);
  assert.equal(fx.durable.calls.read, reads);

  reservePhysicalResources(fx.authority, fx.request);
  const stale = physicalResourceReservationReadiness(fx.authority);
  assert.equal(stale.restart_checkpoint_state, "stale_after_live_mutation");
  assert.equal(stale.checkpoint_matches_live_head, false);
  assert.equal(stale.checkpoint_verified_revision + 1, stale.live_observed_revision);
  assert.equal(stale.mutation_state, "available");
});

test("compatible shared reservations consume capacity independently and retain current credentials", () => {
  const bundle = makeBundle({
    requirements: [requirement({
      ownership: "shared",
      compatibility_ref: "compatibility:hf-observe-v1",
    })],
  });
  const inventory = makeInventory(bundle, {
    resources: [{
      resource_kind: "instrument",
      resource_ref: "instrument:ultra-a",
      state_epoch_digest: digest("ultra-state"),
      availability: "available",
      total_capacity_units: 2,
      available_capacity_units: 2,
      exclusive_available: true,
      fencing_generation: 11,
      setup_cost_units: 2,
      eligible_requirement_digests: [hashCanonicalJson(bundle.requirements[0])],
      switchable_mode_refs: ["mode:reader"],
      switchable_workspace_refs: ["workspace:slot-a"],
      current_mode_ref: "mode:reader",
      current_workspace_ref: "workspace:slot-a",
    }],
  });
  const fx = fixture({ bundle, inventory });
  const firstRequest = makeRequest(bundle);
  const secondRequest = makeRequest(bundle, {
    reservation_request_id: "reservation-request:resource-test-two",
    node_id: "TG-cell-resource-reservation-test-two",
    attempt_ref: "attempt:resource-test-two",
  });
  const first = reservePhysicalResources(fx.authority, firstRequest);
  const second = reservePhysicalResources(fx.authority, secondRequest);
  const eligibility = createPhysicalResourceReservationEligibilityPort(fx.authority);
  assert.equal(resolveHeldPhysicalResourceForNode(eligibility, nodeBinding(firstRequest)).held, true);
  assert.equal(resolveHeldPhysicalResourceForNode(eligibility, nodeBinding(secondRequest)).held, true);
  let projected = projectPhysicalResourceReservationInventory(fx.authority);
  assert.equal(projected.resources[0].available_capacity_units, 0);
  assert.equal(projected.resources[0].active_shared_compatibility_ref, "compatibility:hf-observe-v1");
  assert.equal(first.receipt.allocations[0].fencing_generation, 12);
  assert.equal(second.receipt.allocations[0].fencing_generation, 13);

  cancelPhysicalResourceReservation(fx.authority, first.credential);
  assert.doesNotThrow(() => (
    assertCurrentPhysicalResourceReservationCredential(fx.authority, second.credential)
  ));
  projected = projectPhysicalResourceReservationInventory(fx.authority);
  assert.equal(projected.resources[0].available_capacity_units, 1);
  assert.equal(projected.resources[0].exclusive_available, false);
  assert.equal(resolveHeldPhysicalResourceForNode(eligibility, nodeBinding(secondRequest)).held, true);
  cancelPhysicalResourceReservation(fx.authority, second.credential);
  projected = projectPhysicalResourceReservationInventory(fx.authority);
  assert.equal(projected.resources[0].available_capacity_units, 2);
  assert.equal(projected.resources[0].exclusive_available, true);
});

test("fencing one shared holder cascades across the active resource component", () => {
  const bundle = makeBundle({
    requirements: [requirement({
      ownership: "shared",
      compatibility_ref: "compatibility:hf-observe-v1",
    })],
  });
  const inventory = makeInventory(bundle, {
    resources: [{
      resource_kind: "instrument",
      resource_ref: "instrument:ultra-a",
      state_epoch_digest: digest("ultra-state"),
      availability: "available",
      total_capacity_units: 2,
      available_capacity_units: 2,
      exclusive_available: true,
      fencing_generation: 11,
      setup_cost_units: 2,
      eligible_requirement_digests: [hashCanonicalJson(bundle.requirements[0])],
      switchable_mode_refs: ["mode:reader"],
      switchable_workspace_refs: ["workspace:slot-a"],
      current_mode_ref: "mode:reader",
      current_workspace_ref: "workspace:slot-a",
    }],
  });
  const fx = fixture({ bundle, inventory });
  const firstRequest = makeRequest(bundle);
  const secondRequest = makeRequest(bundle, {
    reservation_request_id: "reservation-request:resource-test-two",
    node_id: "TG-cell-resource-reservation-test-two",
    attempt_ref: "attempt:resource-test-two",
  });
  const first = reservePhysicalResources(fx.authority, firstRequest);
  const second = reservePhysicalResources(fx.authority, secondRequest);
  const eligibility = createPhysicalResourceReservationEligibilityPort(fx.authority);
  fencePhysicalResourceReservation(fx.authority, first.credential);
  assert.equal(resolveHeldPhysicalResourceForNode(eligibility, nodeBinding(firstRequest)), null);
  assert.equal(resolveHeldPhysicalResourceForNode(eligibility, nodeBinding(secondRequest)), null);
  assert.throws(
    () => assertCurrentPhysicalResourceReservationCredential(fx.authority, second.credential),
    (error) => error.code === "resource_reservation_credential_stale",
  );
  const projected = projectPhysicalResourceReservationInventory(fx.authority);
  assert.equal(projected.resources[0].availability, "unavailable");
  assert.equal(projected.resources[0].available_capacity_units, 0);
  assert.equal(fx.durable.state.reservations.every((record) => record.receipt.state === "fenced"), true);
});

test("reservation refuses to manufacture planned mode/workspace state", () => {
  const bundle = makeBundle({
    requirements: [requirement({ required_state_epoch_digest: undefined })],
  });
  const inventory = makeInventory(bundle, {
    resources: [{
      resource_kind: "instrument",
      resource_ref: "instrument:ultra-a",
      state_epoch_digest: digest("ultra-state"),
      availability: "available",
      total_capacity_units: 1,
      available_capacity_units: 1,
      exclusive_available: true,
      fencing_generation: 11,
      setup_cost_units: 2,
      eligible_requirement_digests: [hashCanonicalJson(bundle.requirements[0])],
      switchable_mode_refs: ["mode:reader"],
      switchable_workspace_refs: ["workspace:slot-a"],
      current_mode_ref: "mode:idle",
      current_workspace_ref: "workspace:storage",
    }],
  });
  const fx = fixture({ bundle, inventory });
  assert.throws(
    () => reservePhysicalResources(fx.authority, fx.request),
    (error) => error.code === "resource_setup_transition_required",
  );
  assert.equal(fx.durable.state.revision, 1);
  assert.equal(fx.durable.state.inventory.resources[0].current_mode_ref, "mode:idle");
  assert.equal(fx.durable.state.inventory.resources[0].current_workspace_ref, "workspace:storage");
});

test("held eligibility and effect start fail closed when external inventory freshness expires", () => {
  const bundle = makeBundle({
    duration_ms: 55_000,
    reservation_ttl_ms: 65_000,
    cooldown_ms: 5_000,
  });
  const inventory = makeInventory(bundle);
  const fx = fixture({ bundle, inventory });
  const request = makeRequest(bundle, { effect_deadline: "2026-07-18T00:00:55.000Z" });
  const held = reservePhysicalResources(fx.authority, request);
  fx.clock.set("2026-07-18T00:00:51.000Z");
  const eligibility = createPhysicalResourceReservationEligibilityPort(fx.authority);
  assert.equal(resolveHeldPhysicalResourceForNode(eligibility, nodeBinding(request)), null);
  assert.throws(
    () => markPhysicalResourceEffectStarted(fx.authority, held.credential),
    (error) => error.code === "resource_inventory_expired",
  );
});

test("current credential assertion rejects post-start resource health loss", () => {
  const fx = fixture();
  const held = reservePhysicalResources(fx.authority, fx.request);
  const started = markPhysicalResourceEffectStarted(fx.authority, held.credential);
  const changed = clone(fx.durable.state);
  changed.prior_state_digest = fx.durable.state.state_digest;
  changed.revision += 1;
  changed.inventory.inventory_generation += 1;
  changed.inventory.resources[0].availability = "unavailable";
  changed.inventory.resources[0].available_capacity_units = 0;
  changed.inventory.resources[0].exclusive_available = false;
  delete changed.inventory.inventory_digest;
  changed.inventory = normalizePhysicalResourceInventory(changed.inventory);
  delete changed.state_digest;
  changed.state_digest = hashCanonicalJson(changed);
  fx.durable.state = changed;

  const restarted = fixture({ bundle: fx.bundle, memory: fx.durable });
  const credential = rehydratePhysicalResourceReservationCredential(restarted.authority, {
    reservation_ref: started.receipt.reservation_ref,
    receipt_digest: started.receipt.receipt_digest,
  });
  assert.throws(
    () => assertCurrentPhysicalResourceReservationCredential(restarted.authority, credential),
    (error) => error.code === "resource_inventory_binding_drift",
  );
  assert.throws(
    () => assertPhysicalResourceEffectAuthorizedNow(restarted.authority, credential),
    (error) => error.code === "resource_inventory_binding_drift",
  );
});

test("per-command effect authority requires started state and the exact request deadline", () => {
  const fx = fixture();
  const held = reservePhysicalResources(fx.authority, fx.request);
  assert.throws(
    () => assertPhysicalResourceEffectAuthorizedNow(fx.authority, held.credential),
    (error) => error.code === "reservation_effect_not_started",
  );
  const started = markPhysicalResourceEffectStarted(fx.authority, held.credential);
  const authorized = assertPhysicalResourceEffectAuthorizedNow(fx.authority, started.credential);
  assert.equal(authorized.reservation_ref, held.receipt.reservation_ref);
  assert.equal(authorized.attempt_ref, fx.request.attempt_ref);
  assert.match(authorized.effect_authorization_digest, /^[a-f0-9]{64}$/u);
  assertNoRawFence(authorized);

  fx.clock.set("2026-07-18T00:00:32.000Z");
  assert.throws(
    () => assertPhysicalResourceEffectAuthorizedNow(fx.authority, started.credential),
    (error) => error.code === "reservation_effect_window_expired",
  );
});

test("inventory staleness never blocks cancel, explicit expiry, or safety fencing", () => {
  function staleFixture() {
    const bundle = makeBundle({
      duration_ms: 55_000,
      reservation_ttl_ms: 65_000,
      cooldown_ms: 5_000,
    });
    const fx = fixture({ bundle, inventory: makeInventory(bundle) });
    const request = makeRequest(bundle, { effect_deadline: "2026-07-18T00:00:55.000Z" });
    const held = reservePhysicalResources(fx.authority, request);
    return { ...fx, held, request };
  }
  {
    const fx = staleFixture();
    fx.clock.set("2026-07-18T00:00:51.000Z");
    const cancelled = cancelPhysicalResourceReservation(fx.authority, fx.held.credential);
    assert.equal(cancelled.receipt.terminal_disposition, "cancelled_before_effect");
    assert.equal(Date.parse(projectPhysicalResourceReservationInventory(fx.authority).expires_at)
      < Date.parse("2026-07-18T00:00:51.000Z"), true);
  }
  {
    const fx = staleFixture();
    fx.clock.set("2026-07-18T00:00:56.000Z");
    const expired = expirePhysicalResourceReservation(fx.authority, fx.held.credential);
    assert.equal(expired.receipt.terminal_disposition, "expired_before_effect");
  }
  {
    const fx = staleFixture();
    fx.clock.set("2026-07-18T00:00:51.000Z");
    const fenced = fencePhysicalResourceReservation(fx.authority, fx.held.credential);
    assert.equal(fenced.receipt.state, "fenced");
    assert.equal(projectPhysicalResourceReservationInventory(fx.authority).resources[0].availability, "unavailable");
  }
});

test("release never resurrects an externally unavailable exclusive resource", () => {
  const fx = fixture();
  const held = reservePhysicalResources(fx.authority, fx.request);
  const changed = clone(fx.durable.state);
  changed.prior_state_digest = fx.durable.state.state_digest;
  changed.revision += 1;
  changed.inventory.inventory_generation += 1;
  changed.inventory.resources[0].availability = "unavailable";
  changed.inventory.resources[0].available_capacity_units = 0;
  changed.inventory.resources[0].exclusive_available = false;
  delete changed.inventory.inventory_digest;
  changed.inventory = normalizePhysicalResourceInventory(changed.inventory);
  delete changed.state_digest;
  changed.state_digest = hashCanonicalJson(changed);
  fx.durable.state = changed;

  // A fresh authority models restart/reconciliation onto an externally
  // observed health state. The original live authority correctly refuses an
  // unverified higher-revision successor in a separate test below.
  const restarted = fixture({ bundle: fx.bundle, memory: fx.durable });
  const credential = rehydratePhysicalResourceReservationCredential(restarted.authority, {
    reservation_ref: held.receipt.reservation_ref,
    receipt_digest: held.receipt.receipt_digest,
  });
  const cancelled = cancelPhysicalResourceReservation(restarted.authority, credential);
  assert.equal(cancelled.receipt.terminal_disposition, "cancelled_before_effect");
  const projected = projectPhysicalResourceReservationInventory(restarted.authority).resources[0];
  assert.equal(restarted.durable.state.attested_inventory.resources[0].availability, "available");
  assert.equal(projected.availability, "unavailable");
  assert.equal(projected.available_capacity_units, 0);
  assert.equal(projected.exclusive_available, false);
});

test("attempt budget counts active slots and executed history but not cancelled-before-effect tombstones", () => {
  const bundle = makeBundle({
    attempt_budget: 2,
    requirements: [requirement({
      ownership: "shared",
      compatibility_ref: "compatibility:hf-observe-v1",
    })],
  });
  const inventory = makeInventory(bundle, {
    resources: [{
      resource_kind: "instrument",
      resource_ref: "instrument:ultra-a",
      state_epoch_digest: digest("ultra-state"),
      availability: "available",
      total_capacity_units: 3,
      available_capacity_units: 3,
      exclusive_available: true,
      fencing_generation: 11,
      setup_cost_units: 2,
      eligible_requirement_digests: [hashCanonicalJson(bundle.requirements[0])],
      switchable_mode_refs: ["mode:reader"],
      switchable_workspace_refs: ["workspace:slot-a"],
      current_mode_ref: "mode:reader",
      current_workspace_ref: "workspace:slot-a",
    }],
  });
  const fx = fixture({ bundle, inventory });
  const firstRequest = makeRequest(bundle);
  const secondRequest = makeRequest(bundle, {
    reservation_request_id: "reservation-request:budget-two",
    attempt_ref: "attempt:budget-two",
  });
  const thirdRequest = makeRequest(bundle, {
    reservation_request_id: "reservation-request:budget-three",
    attempt_ref: "attempt:budget-three",
  });
  const first = reservePhysicalResources(fx.authority, firstRequest);
  reservePhysicalResources(fx.authority, secondRequest);
  assert.throws(
    () => reservePhysicalResources(fx.authority, thirdRequest),
    (error) => error.code === "resource_attempt_budget_exhausted",
  );
  cancelPhysicalResourceReservation(fx.authority, first.credential);
  assert.equal(reservePhysicalResources(fx.authority, thirdRequest).receipt.state, "held");
});

test("unknown-effect fencing consumes the attempt budget after inventory recovery", () => {
  const bundle = makeBundle({ attempt_budget: 1 });
  const fx = fixture({ bundle, inventory: makeInventory(bundle) });
  const held = reservePhysicalResources(fx.authority, fx.request);
  const fenced = fencePhysicalResourceReservation(fx.authority, held.credential);
  assert.equal(fenced.receipt.terminal_disposition, "unknown_effect");
  assert.equal(fx.durable.state.reservations[0].effect_state, "not_started");

  const fencedState = clone(fx.durable.state);
  const recoveryInput = clone(makeRefreshInventory(fencedState));
  delete recoveryInput.inventory_digest;
  recoveryInput.resources[0].availability = "available";
  recoveryInput.resources[0].available_capacity_units = 1;
  recoveryInput.resources[0].exclusive_available = true;
  const recoveredInventory = normalizePhysicalResourceInventory(recoveryInput);
  const recoveryDocument = fx.trust.signInventory(fencedState, recoveredInventory);
  fx.clock.set("2026-07-18T00:00:04.000Z");
  refreshPhysicalResourceInventory(fx.authority, recoveryDocument);

  const restarted = fixture({ bundle, memory: fx.durable });
  const nextRequest = makeRequest(bundle, {
    reservation_request_id: "reservation-request:after-unknown-effect",
    attempt_ref: "attempt:after-unknown-effect",
    experiment_ref: "experiment:rotated-cannot-reset-budget",
  });
  assert.throws(
    () => reservePhysicalResources(restarted.authority, nextRequest),
    (error) => error.code === "resource_attempt_budget_exhausted",
  );
});

test("checkpoint-bound compaction preserves terminal identity and projection across restart", () => {
  const fx = fixture();
  const held = reservePhysicalResources(fx.authority, fx.request);
  const cancelled = cancelPhysicalResourceReservation(fx.authority, held.credential);
  const terminalProjection = readPhysicalResourceReservationProjection(
    fx.authority,
    cancelled.receipt.reservation_ref,
  );
  const activeRequest = makeRequest(fx.bundle, {
    reservation_request_id: "reservation-request:active-during-compaction",
    attempt_ref: "attempt:active-during-compaction",
  });
  const active = reservePhysicalResources(fx.authority, activeRequest);
  const sourceState = clone(fx.durable.state);
  const sourceChain = anchorReservationHead(fx, sourceState);

  const compacted = compactPhysicalResourceReservationHistory(fx.authority, {
    checkpoint_chain: sourceChain,
  });
  assert.equal(compacted.idempotent, false);
  assert.equal(compacted.compacted_record_count, 1);
  assert.equal(compacted.retained_active_record_count, 1);
  assert.equal(compacted.retained_unresolved_safety_record_count, 0);
  assert.equal(fx.durable.state.reservations.length, 1);
  assert.equal(fx.durable.state.reservation_tombstones.length, 1);
  assert.equal(fx.durable.state.reservations[0].receipt.reservation_ref, active.receipt.reservation_ref);
  assert.equal(fx.durable.state.compaction_source_state_digest, sourceState.state_digest);
  assert.equal(
    fx.durable.state.compaction_source_checkpoint_digest,
    sourceChain[0].signed_document_digest,
  );
  assert.equal(Object.hasOwn(fx.durable.state.reservation_tombstones[0], "request"), false);
  assert.equal(Object.hasOwn(fx.durable.state.reservation_tombstones[0], "bundle"), false);
  assert.equal(Object.hasOwn(fx.durable.state.reservation_tombstones[0], "resource_fences"), false);
  assert.deepEqual(
    readPhysicalResourceReservationProjection(fx.authority, cancelled.receipt.reservation_ref),
    terminalProjection,
  );

  const casAfterCompaction = fx.durable.calls.cas;
  const duplicate = reservePhysicalResources(fx.authority, clone(fx.request));
  assert.equal(duplicate.idempotent, true);
  assert.equal(duplicate.credential, null);
  assert.equal(duplicate.receipt.receipt_digest, cancelled.receipt.receipt_digest);
  assert.deepEqual(duplicate.reservation_projection, terminalProjection);
  assert.equal(fx.durable.calls.cas, casAfterCompaction);
  assert.throws(
    () => reservePhysicalResources(fx.authority, makeRequest(fx.bundle, {
      contract_hash: digest("conflicting-compacted-request"),
    })),
    (error) => error.code === "reservation_request_identity_conflict",
  );
  assert.throws(
    () => compactPhysicalResourceReservationHistory(fx.authority, {
      checkpoint_chain: sourceChain,
    }),
    (error) => error.code === "reservation_history_compaction_checkpoint_invalid",
  );
  assert.equal(fx.durable.calls.cas, casAfterCompaction);

  const exactHeadChain = anchorReservationHead(fx);
  const repeated = compactPhysicalResourceReservationHistory(fx.authority, {
    checkpoint_chain: exactHeadChain,
  });
  assert.equal(repeated.idempotent, true);
  assert.equal(repeated.compacted_record_count, 0);
  assert.equal(fx.durable.calls.cas, casAfterCompaction);

  const restarted = fixture({ bundle: fx.bundle, memory: fx.durable });
  const afterRestart = reservePhysicalResources(restarted.authority, clone(fx.request));
  assert.equal(afterRestart.idempotent, true);
  assert.deepEqual(afterRestart.reservation_projection, terminalProjection);
  assert.deepEqual(
    readPhysicalResourceReservationProjection(
      restarted.authority,
      cancelled.receipt.reservation_ref,
    ),
    terminalProjection,
  );
});

test("compacted tombstones retain attempt uniqueness and consumed budget", () => {
  const bundle = makeBundle({ attempt_budget: 1 });
  const fx = fixture({ bundle, inventory: makeInventory(bundle) });
  const held = reservePhysicalResources(fx.authority, fx.request);
  const started = markPhysicalResourceEffectStarted(fx.authority, held.credential);
  const cleanup = beginPhysicalResourceCleanup(
    fx.authority,
    started.credential,
    "cleanup-handoff:compaction-budget",
  );
  fx.clock.set("2026-07-18T00:00:08.000Z");
  completePhysicalResourceCleanup(fx.authority, cleanup.credential);
  compactPhysicalResourceReservationHistory(fx.authority, {
    checkpoint_chain: anchorReservationHead(fx),
  });
  assert.equal(fx.durable.state.reservation_tombstones[0].attempt_budget_consumed, true);

  assert.throws(
    () => reservePhysicalResources(fx.authority, makeRequest(bundle, {
      reservation_request_id: "reservation-request:same-compacted-attempt",
    })),
    (error) => error.code === "reservation_attempt_identity_conflict",
  );
  assert.throws(
    () => reservePhysicalResources(fx.authority, makeRequest(bundle, {
      reservation_request_id: "reservation-request:budget-after-compaction",
      attempt_ref: "attempt:budget-after-compaction",
    })),
    (error) => error.code === "resource_attempt_budget_exhausted",
  );

  const forged = clone(fx.durable.state);
  forged.reservation_tombstones[0].attempt_budget_consumed = false;
  delete forged.reservation_tombstones[0].tombstone_digest;
  delete forged.state_digest;
  assert.throws(
    () => normalizePhysicalResourceReservationState(forged),
    /attempt_budget_consumed is inconsistent/u,
  );
});

test("compaction retains unresolved safety history until signed inventory crosses its fence", () => {
  const bundle = makeBundle({ attempt_budget: 1 });
  const fx = fixture({ bundle, inventory: makeInventory(bundle) });
  const held = reservePhysicalResources(fx.authority, fx.request);
  const fenced = fencePhysicalResourceReservation(fx.authority, held.credential);
  const unresolvedCasCount = fx.durable.calls.cas;
  const unresolved = compactPhysicalResourceReservationHistory(fx.authority, {
    checkpoint_chain: anchorReservationHead(fx),
  });
  assert.equal(unresolved.idempotent, true);
  assert.equal(unresolved.compacted_record_count, 0);
  assert.equal(unresolved.retained_unresolved_safety_record_count, 1);
  assert.equal(fx.durable.calls.cas, unresolvedCasCount);
  assert.equal(fx.durable.state.reservations.length, 1);
  assert.equal(fx.durable.state.reservation_tombstones.length, 0);

  const fencedState = clone(fx.durable.state);
  const recoveryInput = clone(makeRefreshInventory(fencedState));
  delete recoveryInput.inventory_digest;
  recoveryInput.resources[0].availability = "available";
  recoveryInput.resources[0].available_capacity_units = 1;
  recoveryInput.resources[0].exclusive_available = true;
  recoveryInput.resources[0].fencing_generation =
    fenced.receipt.allocations[0].fencing_generation + 1;
  const recoveredInventory = normalizePhysicalResourceInventory(recoveryInput);
  const recoveryDocument = fx.trust.signInventory(fencedState, recoveredInventory);
  fx.clock.set("2026-07-18T00:00:04.000Z");
  refreshPhysicalResourceInventory(fx.authority, recoveryDocument);

  const compacted = compactPhysicalResourceReservationHistory(fx.authority, {
    checkpoint_chain: anchorReservationHead(fx),
  });
  assert.equal(compacted.compacted_record_count, 1);
  assert.equal(fx.durable.state.reservations.length, 0);
  assert.equal(fx.durable.state.reservation_tombstones.length, 1);

  const resurrected = clone(fx.durable.state);
  for (const field of ["inventory", "attested_inventory"]) {
    delete resurrected[field].inventory_digest;
    resurrected[field].resources[0].availability = "available";
    resurrected[field].resources[0].available_capacity_units = 1;
    resurrected[field].resources[0].exclusive_available = true;
    resurrected[field].resources[0].fencing_generation =
      fenced.receipt.allocations[0].fencing_generation;
    resurrected[field] = normalizePhysicalResourceInventory(resurrected[field]);
  }
  delete resurrected.state_digest;
  assert.throws(
    () => normalizePhysicalResourceReservationState(resurrected),
    /resurrected a safety-fenced resource/u,
  );
});

test("compaction verifies the exact external head twice and reconciles only an exact lost CAS", () => {
  {
    const fx = fixture();
    const held = reservePhysicalResources(fx.authority, fx.request);
    cancelPhysicalResourceReservation(fx.authority, held.credential);
    let trustCalls = 0;
    fx.trust.setCheckpointTrustHook(() => { trustCalls += 1; });
    const result = compactPhysicalResourceReservationHistory(fx.authority, {
      checkpoint_chain: anchorReservationHead(fx),
    });
    assert.equal(result.compacted_record_count, 1);
    assert.equal(trustCalls, 2);
  }
  {
    const fx = fixture();
    const held = reservePhysicalResources(fx.authority, fx.request);
    cancelPhysicalResourceReservation(fx.authority, held.credential);
    const chain = anchorReservationHead(fx);
    const sourceDigest = fx.durable.state.state_digest;
    const casCount = fx.durable.calls.cas;
    let trustCalls = 0;
    fx.trust.setCheckpointTrustHook(() => {
      trustCalls += 1;
      if (trustCalls === 2) throw new Error("checkpoint trust response lost");
    });
    assert.throws(
      () => compactPhysicalResourceReservationHistory(fx.authority, {
        checkpoint_chain: chain,
      }),
      (error) => error.code === "reservation_history_compaction_checkpoint_invalid",
    );
    assert.equal(trustCalls, 2);
    assert.equal(fx.durable.calls.cas, casCount);
    assert.equal(fx.durable.state.state_digest, sourceDigest);
    assert.equal(fx.durable.state.reservation_tombstones.length, 0);
  }
  {
    const fx = fixture();
    const held = reservePhysicalResources(fx.authority, fx.request);
    cancelPhysicalResourceReservation(fx.authority, held.credential);
    const chain = anchorReservationHead(fx);
    const casCount = fx.durable.calls.cas;
    let changed = false;
    fx.trust.setCheckpointTrustHook(() => {
      if (changed) return;
      changed = true;
      const forkInput = clone(fx.durable.state);
      forkInput.inventory.inventory_generation += 1;
      delete forkInput.inventory.inventory_digest;
      forkInput.inventory = normalizePhysicalResourceInventory(forkInput.inventory);
      delete forkInput.state_digest;
      fx.durable.state = normalizePhysicalResourceReservationState(forkInput);
    });
    assert.throws(
      () => compactPhysicalResourceReservationHistory(fx.authority, {
        checkpoint_chain: chain,
      }),
      (error) => error.code === "reservation_state_fork",
    );
    assert.equal(fx.durable.calls.cas, casCount);
  }
  {
    const fx = fixture();
    const held = reservePhysicalResources(fx.authority, fx.request);
    cancelPhysicalResourceReservation(fx.authority, held.credential);
    const source = clone(fx.durable.state);
    fx.durable.failNext = true;
    assert.throws(
      () => compactPhysicalResourceReservationHistory(fx.authority, {
        checkpoint_chain: anchorReservationHead(fx),
      }),
      (error) => error.code === "reservation_history_compaction_conflict",
    );
    assert.equal(fx.durable.state.state_digest, source.state_digest);
    assert.equal(fx.durable.state.reservations.length, 1);
    assert.equal(fx.durable.state.reservation_tombstones.length, 0);
  }
  {
    const fx = fixture();
    const held = reservePhysicalResources(fx.authority, fx.request);
    cancelPhysicalResourceReservation(fx.authority, held.credential);
    fx.durable.throwAfterNext = true;
    const result = compactPhysicalResourceReservationHistory(fx.authority, {
      checkpoint_chain: anchorReservationHead(fx),
    });
    assert.equal(result.compacted_record_count, 1);
    assert.equal(fx.durable.state.reservations.length, 0);
    assert.equal(fx.durable.state.reservation_tombstones.length, 1);
    assert.equal(physicalResourceReservationReadiness(fx.authority).mutation_state, "available");
  }
});

test("compaction rejects malformed proof shapes and checkpoint callback reentrancy", () => {
  {
    const fx = fixture();
    const held = reservePhysicalResources(fx.authority, fx.request);
    cancelPhysicalResourceReservation(fx.authority, held.credential);
    const casCount = fx.durable.calls.cas;
    assert.throws(
      () => compactPhysicalResourceReservationHistory(fx.authority, {
        checkpoint_chain: new Array(1),
      }),
      (error) => error.code === "reservation_history_compaction_checkpoint_invalid",
    );
    let getterCalled = false;
    const accessorChain = [];
    Object.defineProperty(accessorChain, "0", {
      enumerable: true,
      configurable: true,
      get() {
        getterCalled = true;
        return anchorReservationHead(fx)[0];
      },
    });
    accessorChain.length = 1;
    assert.throws(
      () => compactPhysicalResourceReservationHistory(fx.authority, {
        checkpoint_chain: accessorChain,
      }),
      (error) => error.code === "reservation_history_compaction_checkpoint_invalid",
    );
    assert.equal(getterCalled, false);
    assert.equal(fx.durable.calls.cas, casCount);
  }
  {
    const fx = fixture();
    const held = reservePhysicalResources(fx.authority, fx.request);
    cancelPhysicalResourceReservation(fx.authority, held.credential);
    const chain = anchorReservationHead(fx);
    let trustCalls = 0;
    fx.trust.setCheckpointTrustHook(() => {
      trustCalls += 1;
      assert.throws(
        () => compactPhysicalResourceReservationHistory(fx.authority, {
          checkpoint_chain: chain,
        }),
        (error) => error.code === "reservation_history_compaction_reentrant",
      );
      assert.throws(
        () => reservePhysicalResources(fx.authority, clone(fx.request)),
        (error) => error.code === "reservation_history_compaction_reentrant_mutation",
      );
    });
    const casCount = fx.durable.calls.cas;
    const result = compactPhysicalResourceReservationHistory(fx.authority, {
      checkpoint_chain: chain,
    });
    assert.equal(result.compacted_record_count, 1);
    assert.equal(trustCalls, 2);
    assert.equal(fx.durable.calls.cas, casCount + 1);
  }
});

test("checkpoint ancestry binds compaction lineage and refuses tombstone rollback or forks", () => {
  const fx = fixture();
  const held = reservePhysicalResources(fx.authority, fx.request);
  cancelPhysicalResourceReservation(fx.authority, held.credential);
  const sourceState = clone(fx.durable.state);
  const sourceCheckpoint = fx.trust.signCheckpoint(sourceState);
  fx.trust.setCurrentCheckpointChain(Object.freeze([sourceCheckpoint]));
  const first = compactPhysicalResourceReservationHistory(fx.authority, {
    checkpoint_chain: Object.freeze([sourceCheckpoint]),
  });
  const compactedState = clone(fx.durable.state);
  assert.equal(first.compaction_generation, 1);
  assert.equal(compactedState.compaction_prior_accumulator, null);

  const restarted = fixture({
    bundle: fx.bundle,
    memory: fx.durable,
    prepareTrust: (trust, durable) => {
      const current = trust.signCheckpoint(durable.state, {
        prior_checkpoint_digest: sourceCheckpoint.signed_document_digest,
      });
      const chain = Object.freeze([sourceCheckpoint, current]);
      trust.setCurrentCheckpointChain(chain);
      return { restart_checkpoint_chain: chain };
    },
  });
  assert.equal(
    physicalResourceReservationReadiness(restarted.authority).checkpoint_matches_live_head,
    true,
  );
  const secondHeld = reservePhysicalResources(restarted.authority, makeRequest(fx.bundle, {
    reservation_request_id: "reservation-request:second-compaction-generation",
    attempt_ref: "attempt:second-compaction-generation",
  }));
  cancelPhysicalResourceReservation(restarted.authority, secondHeld.credential);
  const secondSourceState = clone(fx.durable.state);
  const secondSourceCheckpoint = restarted.trust.signCheckpoint(secondSourceState);
  restarted.trust.setCurrentCheckpointChain(Object.freeze([secondSourceCheckpoint]));
  const second = compactPhysicalResourceReservationHistory(restarted.authority, {
    checkpoint_chain: Object.freeze([secondSourceCheckpoint]),
  });
  assert.equal(second.compaction_generation, 2);
  assert.equal(fx.durable.state.compaction_prior_accumulator, first.compaction_history_accumulator);
  assert.equal(fx.durable.state.compacted_record_count, 2);
  assert.equal(fx.durable.state.compaction_batch_record_digests.length, 1);
  assert.equal(fx.durable.state.reservation_tombstones.length, 2);

  const secondRestart = fixture({
    bundle: fx.bundle,
    memory: fx.durable,
    prepareTrust: (trust, durable) => {
      const current = trust.signCheckpoint(durable.state, {
        prior_checkpoint_digest: secondSourceCheckpoint.signed_document_digest,
      });
      const chain = Object.freeze([secondSourceCheckpoint, current]);
      trust.setCurrentCheckpointChain(chain);
      return { restart_checkpoint_chain: chain };
    },
  });
  assert.equal(
    physicalResourceReservationReadiness(secondRestart.authority).checkpoint_matches_live_head,
    true,
  );

  const truncated = clone(compactedState);
  truncated.reservation_tombstones = [];
  delete truncated.state_digest;
  assert.throws(
    () => normalizePhysicalResourceReservationState(truncated),
    /compaction lineage is incomplete/u,
  );
  const accumulatorFork = clone(compactedState);
  accumulatorFork.compaction_history_accumulator = digest("compaction-accumulator-fork");
  delete accumulatorFork.state_digest;
  assert.throws(
    () => normalizePhysicalResourceReservationState(accumulatorFork),
    /compaction accumulator is invalid/u,
  );

  const forgedInput = clone(compactedState);
  forgedInput.compaction_source_checkpoint_digest = digest("unrelated-source-checkpoint");
  forgedInput.compaction_history_accumulator =
    physicalResourceReservationCompactionAccumulatorDigest({
      compaction_generation: forgedInput.compaction_generation,
      prior_accumulator: forgedInput.compaction_prior_accumulator,
      compacted_record_digests: forgedInput.compaction_batch_record_digests,
      source_checkpoint_generation: forgedInput.compaction_source_checkpoint_generation,
      source_checkpoint_digest: forgedInput.compaction_source_checkpoint_digest,
      source_state_revision: forgedInput.compaction_source_state_revision,
      source_state_digest: forgedInput.compaction_source_state_digest,
      tombstone_set_digest: forgedInput.compaction_tombstone_set_digest,
      tombstone_count: forgedInput.reservation_tombstones.length,
      compacted_record_count: forgedInput.compacted_record_count,
    });
  delete forgedInput.state_digest;
  const forgedState = normalizePhysicalResourceReservationState(forgedInput);
  const forgedMemory = new MemoryCasState(forgedState);
  forgedMemory.inventoryTrustMaterial = fx.durable.inventoryTrustMaterial;
  forgedMemory.clockTrustMaterial = fx.durable.clockTrustMaterial;
  assert.throws(
    () => fixture({
      bundle: fx.bundle,
      memory: forgedMemory,
      prepareTrust: (trust, durable) => {
        const prior = trust.signCheckpoint(sourceState);
        const current = trust.signCheckpoint(durable.state, {
          prior_checkpoint_digest: prior.signed_document_digest,
        });
        const chain = Object.freeze([prior, current]);
        trust.setCurrentCheckpointChain(chain);
        return { restart_checkpoint_chain: chain };
      },
    }),
    /compaction advance is invalid/u,
  );

  fx.durable.state = sourceState;
  assert.throws(
    () => projectPhysicalResourceReservationInventory(restarted.authority),
    (error) => error.code === "reservation_state_rollback",
  );
});

test("checkpoint ancestry preserves exact tombstones and binds each new compaction batch", () => {
  const fx = fixture();
  const firstHeld = reservePhysicalResources(fx.authority, fx.request);
  cancelPhysicalResourceReservation(fx.authority, firstHeld.credential);
  compactPhysicalResourceReservationHistory(fx.authority, {
    checkpoint_chain: anchorReservationHead(fx),
  });

  const secondHeld = reservePhysicalResources(fx.authority, makeRequest(fx.bundle, {
    reservation_request_id: "reservation-request:checkpoint-member-second",
    attempt_ref: "attempt:checkpoint-member-second",
  }));
  cancelPhysicalResourceReservation(fx.authority, secondHeld.credential);
  const secondSourceState = clone(fx.durable.state);
  const secondSourceCheckpoint = fx.trust.signCheckpoint(secondSourceState);
  fx.trust.setCurrentCheckpointChain(Object.freeze([secondSourceCheckpoint]));
  compactPhysicalResourceReservationHistory(fx.authority, {
    checkpoint_chain: Object.freeze([secondSourceCheckpoint]),
  });
  const legitimateSuccessor = clone(fx.durable.state);
  const priorTombstone = secondSourceState.reservation_tombstones[0];

  function assertForgedRestartRejected(forgedState, pattern) {
    const forgedMemory = new MemoryCasState(forgedState);
    forgedMemory.inventoryTrustMaterial = fx.durable.inventoryTrustMaterial;
    forgedMemory.clockTrustMaterial = fx.durable.clockTrustMaterial;
    assert.throws(
      () => fixture({
        bundle: fx.bundle,
        memory: forgedMemory,
        prepareTrust: (trust, durable) => {
          const forgedCheckpoint = trust.signCheckpoint(durable.state, {
            prior_checkpoint_digest: secondSourceCheckpoint.signed_document_digest,
          });
          const chain = Object.freeze([secondSourceCheckpoint, forgedCheckpoint]);
          trust.setCurrentCheckpointChain(chain);
          return { restart_checkpoint_chain: chain };
        },
      }),
      pattern,
    );
  }

  const rewrittenPriorTombstone = rebindForgedCompactionState(
    legitimateSuccessor,
    (state) => {
      const tombstone = state.reservation_tombstones.find((entry) => (
        entry.receipt.reservation_ref === priorTombstone.receipt.reservation_ref
      ));
      tombstone.allocation_plan_digest = digest("rewritten-prior-tombstone-projection");
    },
  );
  assertForgedRestartRejected(
    rewrittenPriorTombstone,
    /compaction advance is invalid|deleted or rewrote compacted tombstone proof history/u,
  );

  const detachedBatch = rebindForgedCompactionState(
    legitimateSuccessor,
    (state) => {
      state.compaction_batch_record_digests = [priorTombstone.source_record_digest];
    },
  );
  assertForgedRestartRejected(detachedBatch, /compaction advance is invalid/u);

  const inventedSourceRecord = digest("invented-compaction-source-record");
  const unprovenBatch = rebindForgedCompactionState(
    legitimateSuccessor,
    (state) => {
      const newTombstone = state.reservation_tombstones.find((entry) => (
        entry.receipt.reservation_ref !== priorTombstone.receipt.reservation_ref
      ));
      newTombstone.source_record_digest = inventedSourceRecord;
      state.compaction_batch_record_digests = [inventedSourceRecord];
    },
  );
  assertForgedRestartRejected(unprovenBatch, /compaction advance is invalid/u);
});

test("readiness publishes bounded tombstone capacity and preserves a safety reserve", () => {
  const fx = fixture();
  const readiness = physicalResourceReservationReadiness(fx.authority);
  assert.equal(readiness.production_ready, false);
  assert.equal(
    readiness.reservation_history_capacity.tombstone_limit,
    MAX_RESERVATION_TOMBSTONES,
  );
  assert.equal(
    readiness.reservation_history_capacity.general_tombstone_limit,
    MAX_GENERAL_RESERVATION_TOMBSTONES,
  );
  assert.equal(
    readiness.reservation_history_capacity.safety_tombstone_reserve,
    RESERVATION_TOMBSTONE_SAFETY_RESERVE,
  );
  assert.equal(
    MAX_GENERAL_RESERVATION_TOMBSTONES + RESERVATION_TOMBSTONE_SAFETY_RESERVE,
    MAX_RESERVATION_TOMBSTONES,
  );
  assert.equal(
    MAX_RESERVATION_CHECKPOINT_HISTORY_DIGESTS,
    readiness.reservation_history_capacity.full_record_limit
      + readiness.reservation_history_capacity.tombstone_limit,
  );
  const beyondLegacyFullRecordLimit = Array.from(
    { length: 4_097 },
    (_, index) => digest(`checkpoint-history-member:${index}`),
  ).sort();
  assert.equal(
    fx.trust.signCheckpoint(fx.durable.state, {
      reservation_request_digests: beyondLegacyFullRecordLimit,
    }).payload.reservation_request_digests.length,
    4_097,
  );
  assert.throws(
    () => fx.trust.signCheckpoint(fx.durable.state, {
      reservation_request_digests: new Array(
        MAX_RESERVATION_CHECKPOINT_HISTORY_DIGESTS + 1,
      ).fill(digest("checkpoint-history-overflow")),
    }),
    /0-20480 entries/u,
  );
  const overCeiling = clone(fx.durable.state);
  overCeiling.reservation_tombstones = new Array(MAX_RESERVATION_TOMBSTONES + 1);
  delete overCeiling.state_digest;
  assert.throws(
    () => normalizePhysicalResourceReservationState(overCeiling),
    /0-16384 entries/u,
  );
});

test("terminal receipt state, disposition, and effect lifecycle form a closed matrix", () => {
  const fx = fixture();
  const held = reservePhysicalResources(fx.authority, fx.request);
  cancelPhysicalResourceReservation(fx.authority, held.credential);
  const corrupt = clone(fx.durable.state);
  corrupt.reservations[0].effect_state = "started";
  corrupt.reservations[0].effect_started_at = corrupt.reservations[0].receipt.closed_at;
  delete corrupt.state_digest;
  assert.throws(
    () => normalizePhysicalResourceReservationState(corrupt),
    /impossible terminal\/effect disposition/,
  );
});

test("live authority detects rollback and same-revision forks", () => {
  {
    const fx = fixture();
    const older = clone(fx.durable.state);
    reservePhysicalResources(fx.authority, fx.request);
    fx.durable.state = older;
    assert.throws(
      () => projectPhysicalResourceReservationInventory(fx.authority),
      (error) => error.code === "reservation_state_rollback",
    );
    assert.equal(physicalResourceReservationReadiness(fx.authority).mutation_state, "ambiguous_fail_closed");
  }
  {
    const fx = fixture();
    const fork = clone(fx.durable.state);
    fork.inventory.resources[0].fencing_generation += 1;
    delete fork.inventory.inventory_digest;
    fork.inventory = normalizePhysicalResourceInventory(fork.inventory);
    delete fork.state_digest;
    fork.state_digest = hashCanonicalJson(fork);
    fx.durable.state = fork;
    assert.throws(
      () => projectPhysicalResourceReservationInventory(fx.authority),
      (error) => error.code === "reservation_state_fork",
    );
  }
});

test("live authority refuses higher-revision history deletion and cannot replay its tombstone", () => {
  const fx = fixture();
  const held = reservePhysicalResources(fx.authority, fx.request);
  cancelPhysicalResourceReservation(fx.authority, held.credential);

  const rewritten = clone(fx.durable.state);
  rewritten.revision += 1;
  rewritten.inventory.inventory_generation += 1;
  delete rewritten.inventory.inventory_digest;
  rewritten.inventory = normalizePhysicalResourceInventory(rewritten.inventory);
  rewritten.reservations = [];
  delete rewritten.state_digest;
  rewritten.state_digest = hashCanonicalJson(rewritten);
  fx.durable.state = rewritten;

  assert.throws(
    () => projectPhysicalResourceReservationInventory(fx.authority),
    (error) => error.code === "reservation_state_history_unverified",
  );
  assert.throws(
    () => reservePhysicalResources(fx.authority, fx.request),
    (error) => error.code === "reservation_state_ambiguous",
  );
  assert.equal(fx.durable.state.reservations.length, 0);
});

test("durable local arrays reject sparse, adorned, symbol, and accessor shapes", () => {
  {
    const fx = fixture();
    const sparse = clone(fx.durable.state);
    sparse.reservations = new Array(1);
    fx.durable.state = sparse;
    fx.durable.returnRaw = true;
    assert.throws(() => projectPhysicalResourceReservationInventory(fx.authority), /sparse\/accessor/u);
  }
  {
    const fx = fixture();
    reservePhysicalResources(fx.authority, fx.request);
    const adorned = clone(fx.durable.state);
    adorned.reservations[0].lock_order.extra = true;
    fx.durable.state = adorned;
    fx.durable.returnRaw = true;
    assert.throws(() => projectPhysicalResourceReservationInventory(fx.authority), /adorned fields/u);
  }
  {
    const fx = fixture();
    reservePhysicalResources(fx.authority, fx.request);
    const symbolic = clone(fx.durable.state);
    symbolic.reservations[0].resource_fences[Symbol("hidden")] = true;
    fx.durable.state = symbolic;
    fx.durable.returnRaw = true;
    assert.throws(() => projectPhysicalResourceReservationInventory(fx.authority), /symbol fields/u);
  }
  {
    const fx = fixture();
    const accessor = clone(fx.durable.state);
    accessor.reservations = [];
    Object.defineProperty(accessor.reservations, "0", {
      enumerable: true,
      configurable: true,
      get() { throw new Error("must not execute"); },
    });
    accessor.reservations.length = 1;
    fx.durable.state = accessor;
    fx.durable.returnRaw = true;
    assert.throws(() => projectPhysicalResourceReservationInventory(fx.authority), /sparse\/accessor/u);
  }
});

test("state and bundle callbacks cannot recursively re-enter authority", () => {
  {
    const fx = fixture();
    fx.durable.onRead = () => projectPhysicalResourceReservationInventory(fx.authority);
    assert.throws(
      () => projectPhysicalResourceReservationInventory(fx.authority),
      (error) => error.code === "reservation_state_unavailable"
        && error.cause?.code === "reservation_state_reentrant_callback",
    );
  }
  {
    const fx = fixture();
    fx.durable.onCas = () => {
      assert.throws(
        () => projectPhysicalResourceReservationInventory(fx.authority),
        (error) => error.code === "reservation_state_reentrant_callback",
      );
    };
    const held = reservePhysicalResources(fx.authority, fx.request);
    assert.equal(held.receipt.state, "held");
    assert.equal(fx.durable.state.revision, 2);
  }
  {
    let fx;
    fx = fixture({
      resolveHook: () => reservePhysicalResources(fx.authority, fx.request),
    });
    assert.throws(
      () => reservePhysicalResources(fx.authority, fx.request),
      (error) => error.code === "resource_bundle_resolver_reentrant",
    );
  }
});

test("preemption policy never is enforced and inventory cannot erase an active hold", () => {
  const bundle = makeBundle({ preemption_policy: "never" });
  const fx = fixture({ bundle });
  const held = reservePhysicalResources(fx.authority, fx.request);
  assert.throws(
    () => preemptPhysicalResourceReservation(fx.authority, held.credential),
    (error) => error.code === "reservation_preemption_forbidden",
  );
  fx.durable.state.inventory.resources[0].available_capacity_units = 1;
  fx.durable.state.inventory.resources[0].exclusive_available = true;
  delete fx.durable.state.inventory.inventory_digest;
  fx.durable.state.inventory = normalizePhysicalResourceInventory(fx.durable.state.inventory);
  delete fx.durable.state.state_digest;
  fx.durable.state.state_digest = hashCanonicalJson(fx.durable.state);
  assert.throws(
    () => projectPhysicalResourceReservationInventory(fx.authority),
    /does not reflect held capacity/u,
  );
});

test("authority rejects public lookalike ports and graph/nucleus or state-digest drift", () => {
  const fx = fixture();
  const fake = { ...createPhysicalResourceReservationEligibilityPort(fx.authority) };
  assert.throws(
    () => resolveHeldPhysicalResourceForNode(fake, nodeBinding(fx.request)),
    /private factory/u,
  );
  fx.durable.state.state_digest = digest("tampered-state");
  assert.throws(
    () => projectPhysicalResourceReservationInventory(fx.authority),
    /state_digest does not match/u,
  );
});

test("signed aggregate inventory refresh is an authority-owned exact CAS and reconciles lost responses", () => {
  const fx = fixture();
  const held = reservePhysicalResources(fx.authority, fx.request);
  const before = clone(fx.durable.state);
  fx.clock.set("2026-07-18T00:00:04.000Z");
  const inventoryInput = clone(makeRefreshInventory(before));
  delete inventoryInput.inventory_digest;
  inventoryInput.resources[0].available_capacity_units = 1;
  inventoryInput.resources[0].exclusive_available = true;
  const inventory = normalizePhysicalResourceInventory(inventoryInput);
  const document = fx.trust.signInventory(before, inventory);
  fx.durable.throwAfterNext = true;
  const result = refreshPhysicalResourceInventory(fx.authority, document);
  assert.equal(result.state_revision, before.revision + 1);
  assert.equal(result.inventory_generation, before.inventory.inventory_generation + 1);
  assert.equal(result.inventory_attestation_generation, 2);
  assert.equal(result.inventory_attestation_digest, document.signed_document_digest);
  assert.equal(fx.durable.state.reservations.length, before.reservations.length);
  assert.equal(
    hashCanonicalJson(fx.durable.state.reservations),
    hashCanonicalJson(before.reservations),
  );
  assert.equal(fx.durable.state.attested_inventory.resources[0].available_capacity_units, 1);
  assert.equal(fx.durable.state.inventory.resources[0].available_capacity_units, 0);
  assert.equal(
    assertCurrentPhysicalResourceReservationCredential(fx.authority, held.credential).state,
    "held",
  );
  assertNoRawFence(result, before.reservations[0].resource_fences[0].raw_fence);

  const casCalls = fx.durable.calls.cas;
  assert.throws(
    () => refreshPhysicalResourceInventory(fx.authority, document),
    (error) => error.code === "resource_inventory_attestation_invalid",
  );
  assert.equal(fx.durable.calls.cas, casCalls);
});

test("inventory trust callbacks cannot re-enter reservation mutation authority", () => {
  const fx = fixture();
  const state = clone(fx.durable.state);
  fx.clock.set("2026-07-18T00:00:04.000Z");
  const document = fx.trust.signInventory(state, makeRefreshInventory(state));
  let nestedError = null;
  fx.trust.setInventoryTrustHook(() => {
    try {
      reservePhysicalResources(fx.authority, fx.request);
    } catch (error) {
      nestedError = error;
    }
  });
  const refreshed = refreshPhysicalResourceInventory(fx.authority, document);
  assert.equal(refreshed.inventory_attestation_generation, 2);
  assert.equal(nestedError && nestedError.code, "resource_inventory_refresh_reentrant_mutation");
  assert.equal(fx.durable.state.reservations.length, 0);
});

test("inventory refresh rejects expiry, wrong signatures, fencing rollback, and state-binding replay", () => {
  {
    const fx = fixture();
    const state = clone(fx.durable.state);
    const document = fx.trust.signInventory(state, makeRefreshInventory(state));
    fx.clock.set("2026-07-18T00:00:54.000Z");
    assert.throws(
      () => refreshPhysicalResourceInventory(fx.authority, document),
      (error) => error.code === "resource_inventory_attestation_invalid",
    );
    assert.equal(fx.durable.state.revision, 1);
  }
  {
    const fx = fixture();
    const state = clone(fx.durable.state);
    fx.clock.set("2026-07-18T00:00:04.000Z");
    const document = clone(fx.trust.signInventory(state, makeRefreshInventory(state)));
    document.signature = `${document.signature[0] === "A" ? "B" : "A"}${document.signature.slice(1)}`;
    delete document.signed_document_digest;
    document.signed_document_digest = hashCanonicalJson(Object.fromEntries(
      Object.entries(document).filter(([field]) => field !== "signed_document_digest"),
    ));
    fx.trust.setCurrentInventoryDocument(document);
    assert.throws(
      () => refreshPhysicalResourceInventory(fx.authority, document),
      (error) => error.code === "resource_inventory_attestation_invalid"
        && /signature is invalid/u.test(String(error.cause)),
    );
  }
  {
    const fx = fixture();
    const state = clone(fx.durable.state);
    fx.clock.set("2026-07-18T00:00:04.000Z");
    const inventoryInput = clone(makeRefreshInventory(state));
    delete inventoryInput.inventory_digest;
    inventoryInput.resources[0].fencing_generation -= 1;
    const document = fx.trust.signInventory(
      state,
      normalizePhysicalResourceInventory(inventoryInput),
    );
    assert.throws(
      () => refreshPhysicalResourceInventory(fx.authority, document),
      (error) => error.code === "resource_inventory_fencing_rollback",
    );
  }
  {
    const fx = fixture();
    const state = clone(fx.durable.state);
    fx.clock.set("2026-07-18T00:00:04.000Z");
    const first = fx.trust.signInventory(state, makeRefreshInventory(state));
    refreshPhysicalResourceInventory(fx.authority, first);
    const replay = fx.trust.signInventory(state, makeRefreshInventory(state, {
      captured_at: "2026-07-18T00:00:04.000Z",
      valid_from: "2026-07-18T00:00:03.000Z",
      expires_at: "2026-07-18T00:00:54.000Z",
    }));
    assert.throws(
      () => refreshPhysicalResourceInventory(fx.authority, replay),
      (error) => error.code === "resource_inventory_attestation_invalid",
    );
  }
});

test("signed inventory envelopes reject aliases, accessors, sparse arrays, symbols, and prototypes", () => {
  const variants = [
    (document) => {
      document.payload.inventory.resources[0].switchable_workspace_refs =
        document.payload.inventory.resources[0].switchable_mode_refs;
    },
    (document) => {
      Object.defineProperty(document.payload, "issued_at", {
        enumerable: true,
        get() { return "2026-07-18T00:00:03.000Z"; },
      });
    },
    (document) => { delete document.payload.inventory.resources[0]; },
    (document) => { document.payload[Symbol("drift")] = true; },
    (document) => { Object.setPrototypeOf(document.payload.inventory, { polluted: true }); },
  ];
  for (const mutate of variants) {
    const fx = fixture();
    const state = clone(fx.durable.state);
    fx.clock.set("2026-07-18T00:00:04.000Z");
    const document = clone(fx.trust.signInventory(state, makeRefreshInventory(state)));
    mutate(document);
    assert.throws(
      () => refreshPhysicalResourceInventory(fx.authority, document),
      (error) => error.code === "resource_inventory_attestation_invalid",
    );
    assert.equal(fx.durable.state.revision, 1);
  }
});

test("restart admission requires an independently anchored exact checkpoint", () => {
  assert.throws(
    () => fixture({ authorityOverrides: { restart_checkpoint_chain: [] } }),
    /must contain 1-/u,
  );

  const original = fixture();
  const prior = clone(original.durable.state);
  reservePhysicalResources(original.authority, original.request);
  assert.throws(
    () => fixture({
      bundle: original.bundle,
      memory: original.durable,
      prepareTrust: (trust) => {
        const stale = trust.signCheckpoint(prior);
        trust.setCurrentCheckpointChain(Object.freeze([stale]));
      },
    }),
    /does not bind the durable state head/u,
  );

  const forkedHead = clone(original.durable.state);
  const exactHead = clone(original.durable.state);
  forkedHead.inventory.resources[0].fencing_generation += 1;
  delete forkedHead.inventory.inventory_digest;
  forkedHead.inventory = normalizePhysicalResourceInventory(forkedHead.inventory);
  delete forkedHead.state_digest;
  forkedHead.state_digest = hashCanonicalJson(forkedHead);
  original.durable.state = forkedHead;
  assert.throws(
    () => fixture({
      bundle: original.bundle,
      memory: original.durable,
      prepareTrust: (trust) => {
        const checkpoint = trust.signCheckpoint(exactHead);
        trust.setCurrentCheckpointChain(Object.freeze([checkpoint]));
      },
    }),
    /does not bind the durable state head/u,
  );
});

test("checkpoint trust does not receive attacker-selected anchor or current head claims", () => {
  let query = null;
  fixture({
    prepareTrust: (trust) => {
      trust.setCheckpointTrustHook((value) => { query = value; });
    },
  });
  assert.deepEqual(Object.keys(query).sort(), [
    "checkpoint_authority_id",
    "reservation_authority_digest",
    "state_domain_digest",
    "version",
  ]);
  assert.equal("anchor_checkpoint_generation" in query, false);
  assert.equal("current_signed_checkpoint_digest" in query, false);
});

test("checkpoint restart rejects response loss, future issue time, and wrong signer while allowing an anchored historical expiry", () => {
  assert.throws(
    () => fixture({
      prepareTrust: (trust) => {
        trust.setCheckpointTrustHook(() => { throw new Error("external anchor unavailable"); });
      },
    }),
    /external anchor unavailable/u,
  );
  const historicallyExpired = fixture({
    prepareTrust: (trust, durable, clock) => {
      const expired = trust.signCheckpoint(durable.state, {
        expires_at: "2026-07-18T00:00:01.500Z",
      });
      trust.setCurrentCheckpointChain(Object.freeze([expired]));
      clock.set("2026-07-18T00:00:02.000Z");
    },
  });
  assert.equal(
    physicalResourceReservationReadiness(historicallyExpired.authority).restart_checkpoint_state,
    "verified_exact_head_at_authority_start",
  );
  assert.throws(
    () => fixture({
      prepareTrust: (trust, durable) => {
        const future = trust.signCheckpoint(durable.state, {
          issued_at: "2026-07-18T00:00:03.000Z",
          expires_at: "2026-07-18T00:09:00.000Z",
        });
        trust.setCurrentCheckpointChain(Object.freeze([future]));
      },
    }),
    /in the future/u,
  );
  assert.throws(
    () => fixture({
      prepareTrust: (trust) => {
        const invalid = clone(trust.restartCheckpointChain[0]);
        invalid.signature = `${invalid.signature[0] === "A" ? "B" : "A"}${invalid.signature.slice(1)}`;
        delete invalid.signed_document_digest;
        invalid.signed_document_digest = hashCanonicalJson(Object.fromEntries(
          Object.entries(invalid).filter(([field]) => field !== "signed_document_digest"),
        ));
        trust.setCurrentCheckpointChain(Object.freeze([invalid]));
      },
    }),
    /signature is invalid/u,
  );
});

test("checkpoint ancestry survives clock mapping and signer rotation", () => {
  const clockOptions = {
    mapping_generation: 2,
    trust_root_epoch: 3,
    authority_epoch: 4,
    revocation_generation: 1,
  };
  const original = fixture({ clockOptions });
  const genesis = clone(original.durable.state);
  reservePhysicalResources(original.authority, original.request);
  const restarted = fixture({
    bundle: original.bundle,
    memory: original.durable,
    clockOptions,
    prepareTrust: (trust, durable) => {
      const historical = trust.signCheckpoint(genesis, {
        clock_mapping_generation: 1,
        signed_clock_mapping_digest: digest("historical-clock-mapping"),
        clock_trust_root_epoch: 2,
        clock_authority_epoch: 3,
        clock_revocation_generation: 0,
        trust_root_epoch: 20,
        authority_epoch: 21,
        revocation_generation: 1,
        signer_key_id: "checkpoint-key:historical-resource-test",
        signer_public_key_digest: digest("historical-checkpoint-public-key"),
      });
      const current = trust.signCheckpoint(durable.state, {
        prior_checkpoint_digest: historical.signed_document_digest,
      });
      const chain = Object.freeze([historical, current]);
      trust.setCurrentCheckpointChain(chain);
      return { restart_checkpoint_chain: chain };
    },
  });
  assert.equal(
    physicalResourceReservationReadiness(restarted.authority).restart_checkpoint_generation,
    3,
  );
});

test("cold restart accepts an exact external checkpoint across a monotonic clock epoch transition", () => {
  const original = fixture({ clockOptions: { mapping_generation: 7 } });
  reservePhysicalResources(original.authority, original.request);
  const oldClockBinding = original.clock.attestationClockBinding();
  const newClockOptions = {
    mapping_generation: 1,
    monotonic_epoch_id: digest("resource-reservation-monotonic-epoch-after-restart"),
    trust_root_epoch: 3,
    authority_epoch: 4,
    revocation_generation: 1,
  };
  const restarted = fixture({
    bundle: original.bundle,
    memory: original.durable,
    clockOptions: newClockOptions,
    prepareTrust: (trust, durable) => {
      const historicalHead = trust.signCheckpoint(durable.state, oldClockBinding);
      trust.setCurrentCheckpointChain(Object.freeze([historicalHead]));
    },
  });
  assert.equal(
    readPhysicalResourceReservationProjection(
      restarted.authority,
      original.durable.state.reservations[0].receipt.reservation_ref,
    ).state,
    "held",
  );

  assert.throws(
    () => fixture({
      bundle: original.bundle,
      memory: original.durable,
      clockOptions: newClockOptions,
      prepareTrust: (trust, durable) => {
        const historicalHead = trust.signCheckpoint(durable.state, oldClockBinding);
        trust.setCurrentCheckpointChain(Object.freeze([historicalHead]));
        trust.setCheckpointTrustResponseTransform((response) => {
          const changed = { ...response, clock_epoch_transition_generation: 0 };
          changed.clock_epoch_transition_digest = physicalResourceClockEpochTransitionDigest({
            anchored_clock_binding_digest: changed.anchored_clock_binding_digest,
            current_clock_binding_digest: changed.current_clock_binding_digest,
            clock_epoch_transition_generation: 0,
          });
          return changed;
        });
      },
    }),
    /clock epoch transition is not externally anchored/u,
  );

  assert.throws(
    () => fixture({
      bundle: original.bundle,
      memory: original.durable,
      clockOptions: newClockOptions,
      prepareTrust: (trust, durable) => {
        const futureEpochHead = trust.signCheckpoint(durable.state, {
          ...oldClockBinding,
          clock_trust_root_epoch: 4,
          clock_authority_epoch: 5,
          clock_revocation_generation: 2,
        });
        trust.setCurrentCheckpointChain(Object.freeze([futureEpochHead]));
      },
    }),
    /ahead of current trusted clock state/u,
  );
});

test("checkpoint links reject coordinate rollback, inventory forks, and history truncation", () => {
  {
    const original = fixture();
    const genesis = clone(original.durable.state);
    reservePhysicalResources(original.authority, original.request);
    assert.throws(
      () => fixture({
        bundle: original.bundle,
        memory: original.durable,
        prepareTrust: (trust, durable) => {
          const prior = trust.signCheckpoint(genesis, { authority_epoch: 23 });
          const current = trust.signCheckpoint(durable.state, {
            prior_checkpoint_digest: prior.signed_document_digest,
          });
          const chain = Object.freeze([prior, current]);
          trust.setCurrentCheckpointChain(chain);
          return { restart_checkpoint_chain: chain };
        },
      }),
      /authority_epoch moved backwards/u,
    );
  }
  {
    const original = fixture();
    const genesis = clone(original.durable.state);
    reservePhysicalResources(original.authority, original.request);
    assert.throws(
      () => fixture({
        bundle: original.bundle,
        memory: original.durable,
        prepareTrust: (trust, durable) => {
          const prior = trust.signCheckpoint(genesis, {
            inventory_generation: durable.state.inventory.inventory_generation,
            inventory_digest: digest("forked-inventory-at-prior-generation"),
          });
          const current = trust.signCheckpoint(durable.state, {
            prior_checkpoint_digest: prior.signed_document_digest,
          });
          const chain = Object.freeze([prior, current]);
          trust.setCurrentCheckpointChain(chain);
          return { restart_checkpoint_chain: chain };
        },
      }),
      /inventory forked at one generation/u,
    );
  }
  {
    const original = fixture();
    const held = reservePhysicalResources(original.authority, original.request);
    cancelPhysicalResourceReservation(original.authority, held.credential);
    const terminalHead = clone(original.durable.state);
    const truncatedInput = clone(terminalHead);
    truncatedInput.revision += 1;
    truncatedInput.prior_state_digest = terminalHead.state_digest;
    truncatedInput.reservations = [];
    delete truncatedInput.state_digest;
    const truncated = normalizePhysicalResourceReservationState(truncatedInput);
    original.durable.state = clone(truncated);
    assert.throws(
      () => fixture({
        bundle: original.bundle,
        memory: original.durable,
        prepareTrust: (trust) => {
          const prior = trust.signCheckpoint(terminalHead);
          const current = trust.signCheckpoint(truncated, {
            prior_checkpoint_digest: prior.signed_document_digest,
          });
          const chain = Object.freeze([prior, current]);
          trust.setCurrentCheckpointChain(chain);
          return { restart_checkpoint_chain: chain };
        },
      }),
      /deleted reservation or terminal proof history/u,
    );
  }
});

test("canonical signed-document traversal is globally budgeted before schema normalization", () => {
  const fx = fixture();
  const state = clone(fx.durable.state);
  fx.clock.set("2026-07-18T00:00:04.000Z");
  const document = clone(fx.trust.signInventory(state, makeRefreshInventory(state)));
  document.adornment = Array.from({ length: MAX_CANONICAL_TREE_NODES + 1 }, () => 0);
  assert.throws(
    () => refreshPhysicalResourceInventory(fx.authority, document),
    (error) => error.code === "resource_inventory_attestation_invalid"
      && /canonical (?:node|key) budget/u.test(String(error.cause)),
  );
});
