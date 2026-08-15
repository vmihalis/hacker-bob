"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  createArtifactVault,
} = require("../packages/bob-artifact-vault/index.js");
const {
  createInstrumentBroker,
} = require("../packages/bob-instrument-broker/lib/broker.js");
const {
  DeterministicInstrumentProvider,
} = require("../packages/bob-instrument-deterministic/lib/provider.js");
const {
  createDurableInstrumentLeaseBrokerPort,
  createDurableInstrumentLeaseStore,
  createDurableInstrumentProviderDispatchPort,
} = require("../mcp/domains/physical/instrument-lease-store.js");
const {
  acquireInstrumentLease,
  beginInstrumentRestoration,
  normalizeAttemptJournalEntry,
  normalizeSignedStopRequest,
  requestInstrumentLeaseStop,
} = require("../mcp/domains/physical/instrument-lease-contract.js");
const {
  PROVIDER_METHODS,
  buildNormalizedOperationRegistry,
  defineProviderDescriptor,
  normalizePrepareRequest,
  normalizePublicResult,
} = require("../mcp/domains/physical/instrument-provider-contract.js");
const {
  buildDurableReceiptTrustRegistry,
  buildExecutedEvidenceRegistry,
  verifyRegisteredEvidence,
} = require("../mcp/core/executed-evidence-registry.js");
const {
  assertVerifiedPhysicalClaimProjection,
  buildPhysicalObserverEnrollmentRegistry,
  buildPhysicalReceiptTrustRegistry,
  normalizePhysicalExperimentPlan,
  observerAttemptBindingDigest,
} = require("../mcp/domains/physical/physical-experiment-contract.js");
const {
  ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN,
  activePhysicalExecutionGrantSignatureInputDigest,
  createActivePhysicalExecutionGrantVerifier,
  normalizeCleanupCapability,
  normalizeCleanupInvocation,
  normalizeMcpPhysicalExecutionRequest,
  projectVerifiedActivePhysicalExecutionGrant,
} = require("../mcp/domains/physical/physical-authority.js");
const {
  createActivePhysicalDispatchAuthorityPort,
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
  createInProcessBackupKeyCustodyFixture,
} = require("./helpers/artifact-vault-backup-key-custody.js");

const FIXED_NOW = "2026-07-18T00:00:00.200Z";

function digest(label) {
  return hashCanonicalJson({ label });
}

function clone(value) {
  return structuredClone(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function deferred() {
  let resolve;
  const promise = new Promise((settle) => { resolve = settle; });
  return { promise, resolve };
}

function makeClock() {
  let current = Date.parse(FIXED_NOW);
  return () => {
    const value = new Date(current);
    current += 1;
    return value;
  };
}

class MemoryStateAnchor {
  constructor() {
    this.state = null;
  }

  readState() {
    return clone(this.state);
  }

  compareAndSet(request) {
    const generation = this.state == null ? null : this.state.generation;
    const head = this.state == null ? null : this.state.head_event_digest;
    if (request.expected_generation !== generation
        || request.expected_head_event_digest !== head) return false;
    this.state = clone(request.next_state);
    return true;
  }
}

function effectInput(template, subjectRef) {
  return {
    version: 1,
    template_id: template.template_id,
    template_digest: template.template_digest,
    subject_ref: subjectRef,
    subject_kind: template.subject_kind,
    action: template.action,
    channel: template.channel,
    persistence: template.persistence,
    bounds: template.template_id === "instrument.observe.usb.v1"
      ? { attempt_limit: 1 }
      : {},
  };
}

function worstCaseEffect(template) {
  return {
    template_id: template.template_id,
    template_digest: template.template_digest,
    subject_kind: template.subject_kind,
    action: template.action,
    channel: template.channel,
    persistence: template.persistence,
  };
}

function issuerPublicKeyDigest(publicKey) {
  return crypto.createHash("sha256").update(
    publicKey.export({ type: "spki", format: "der" }),
  ).digest("hex");
}

function activeScopeAxis() {
  return normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "ph0-acceptance-policy",
    policy_digest: digest("ph0-scope-policy"),
    projection_version: 1,
    projection_digest: digest("ph0-scope-projection"),
    provenance_digest: digest("ph0-scope-provenance"),
    compatibility_digest: digest("ph0-scope-compatibility"),
    transition_receipt_registry_digest: digest("ph0-transition-receipts"),
    authority_epoch: 7,
    revocation_generation: 2,
  });
}

function makeBrokerFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-ph0-broker-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const effectRegistry = buildEffectTemplateRegistry([
    {
      version: 1,
      template_id: "instrument.observe.usb.v1",
      subject_kind: "instrument",
      action: "observe",
      channel: "usb",
      persistence: "none",
      bounds: {
        attempt_limit: { kind: "integer", required: true, min: 1, max: 2 },
      },
    },
    {
      version: 1,
      template_id: "instrument.configure.usb.v1",
      subject_kind: "instrument",
      action: "configure",
      channel: "usb",
      persistence: "persistent",
      bounds: {},
    },
    {
      version: 1,
      template_id: "target.transmit.rf.v1",
      subject_kind: "target",
      action: "transmit",
      channel: "rf",
      persistence: "ephemeral",
      bounds: {},
    },
  ]);
  const operationRegistry = buildNormalizedOperationRegistry([{
    version: 1,
    operation_id: "instrument.inventory",
    semantic_version: 1,
    parameters: {},
    public_summary_codes: [
      "operation_failed",
      "operation_inconclusive",
      "operation_refused",
      "operation_stopped",
      "operation_succeeded",
    ],
  }]);
  const observeTemplate = effectRegistry.get("instrument.observe.usb.v1");
  const operation = operationRegistry.get("instrument.inventory");
  const instrumentRef = "instrument:ph0-reader-0001";
  const requestedEffect = effectInput(observeTemplate, instrumentRef);
  const descriptor = defineProviderDescriptor({
    version: 1,
    abi_version: 2,
    provider_id: "deterministic_mock",
    provider_version: "1.0.0",
    implementation_digest: digest("ph0-provider-implementation"),
    operation_registry_digest: operationRegistry.registry_digest,
    capabilities: [{
      capability_id: "ph0.inventory",
      operation_id: operation.operation_id,
      operation_digest: operation.operation_digest,
      worst_case_effects: [worstCaseEffect(observeTemplate)],
      idempotency: "read_only_idempotent",
      retry_policy: "new_attempt_after_confirmed_no_effect",
      stop_semantics: "not_applicable",
      restore_policy: "not_required",
    }],
  }, operationRegistry, effectRegistry);
  const prepareRequest = {
    version: 1,
    attempt_ref: "attempt:ph0-acceptance-0001",
    instrument_ref: instrumentRef,
    capability_id: "ph0.inventory",
    operation_id: operation.operation_id,
    operation_digest: operation.operation_digest,
    parameters: {},
    requested_effects: [requestedEffect],
    execution_deadline: "2026-07-18T00:04:00.000Z",
    journal_entry_ref: "journal-entry:ph0-precommit-0001",
  };
  const normalizedPrepare = normalizePrepareRequest(prepareRequest, {
    descriptor,
    operation_registry: operationRegistry,
    effect_registry: effectRegistry,
  });

  const sessionNucleusHash = digest("ph0-session-nucleus");
  const executionPrincipalId = "principal:ph0-worker-0001";
  const clock = makeClock();
  const store = createDurableInstrumentLeaseStore({
    root,
    runtimeId: `physical-runtime:v1:${digest("ph0-runtime").slice(0, 32)}`,
    sessionNucleusHash,
    masterKey: crypto.createHash("sha256").update("ph0-store-key").digest(),
    stateAnchor: new MemoryStateAnchor(),
    checkpointMode: "legacy_full_audit",
    now: clock,
  });
  t.after(() => store.close());

  const resourceBundleDigest = digest("ph0-resource-bundle");
  const workspaceSnapshotRef = "workspace-snapshot:ph0-reader-0001";
  const workspaceSnapshotDigest = digest("ph0-workspace-snapshot");
  const cleanupPlanDigest = digest("ph0-cleanup-plan");
  const authorityResolutionDigest = digest("ph0-authority-resolution");
  const compiledCommandDigest = digest("ph0-compiled-command");
  const physicalRequest = normalizeMcpPhysicalExecutionRequest({
    version: 1,
    grant_kind: "active",
    session_id: "ph0-acceptance-session",
    session_nucleus_hash: sessionNucleusHash,
    caller_role_id: "evaluator-physical",
    requester_principal_id: "principal:ph0-requester",
    ipc_peer_principal_id: "principal:ph0-ipc-peer",
    execution_principal_id: executionPrincipalId,
    instrument_ref: instrumentRef,
    operation_id: operation.operation_id,
    parameter_digest: hashCanonicalJson(normalizedPrepare.parameters),
    authority_epoch: 7,
    revocation_generation: 2,
    nonce: "ph0-request-nonce-0001",
    sequence: 1,
    not_before: "2026-07-18T00:00:00.000Z",
    expires_at: "2026-07-18T00:04:30.000Z",
    requested_effects: normalizedPrepare.requested_effects,
    node_id: "PH0-acceptance",
    contract_hash: digest("ph0-node-contract"),
    prep_token_hash: digest("ph0-prep-token"),
    dispatch_event_id: "ph0-dispatch-event-0001",
    graph_context_hash: digest("ph0-graph-context"),
    capability_pack_id: "physical-ph0-fixture",
    capability_pack_version: "1.0.0",
    capability_pack_digest: digest("ph0-capability-pack"),
    technique_cell_id: "physical.ph0.acceptance",
    attempt_id: "ph0-acceptance-0001",
    experiment_plan_hash: digest("ph0-experiment-plan"),
    inventory_observation_ref: "inventory-observation:ph0-0001",
    inventory_observation_digest: digest("ph0-inventory-observation"),
    assurance_profile_id: "ph0-assurance-v1",
    assurance_claims_digest: digest("ph0-assurance-claims"),
    provider_manifest_digest: descriptor.descriptor_digest,
    availability_variant_id: "ph0-inventory-v1",
    availability_variant_digest: digest("ph0-availability-variant"),
    authorized_transition_set_digest: digest("ph0-transition-set"),
    resource_bundle_digest: resourceBundleDigest,
    fencing_token: "fence-ph0-0001",
    lease_id: "lease-ph0-0001",
    workspace_snapshot_ref: workspaceSnapshotRef,
    workspace_snapshot_digest: workspaceSnapshotDigest,
    observer_plan_digest: digest("ph0-observer-plan"),
    control_plan_digest: digest("ph0-control-plan"),
    cleanup_plan_digest: cleanupPlanDigest,
    execution_lineage: {
      version: 1,
      compiler_id: "closed_ph0_compiler_v1",
      compiler_manifest_digest: digest("ph0-compiler-manifest"),
      compiler_registry_digest: digest("ph0-compiler-registry"),
      compiled_command_id: "compiled-command:ph0-1",
      compiled_command_capability_digest: compiledCommandDigest,
      compiled_operation_digest: digest("ph0-compiled-operation"),
      provider_command_ref: "command:ph0-1",
      command_input_ref: "command-input:ph0-1",
      command_input_digest: compiledCommandDigest,
      maximum_response_bytes: 512,
      vault_reservation_handle: `vault-reservation:v1:${"E".repeat(43)}`,
      vault_reservation_digest: digest("ph0-vault-reservation"),
      vault_ingest_capability_digest: digest("ph0-vault-ingest"),
      vault_byte_limit: 512,
      worker_bundle_digest: digest("ph0-worker-bundle"),
      worker_launch_profile_digest: digest("ph0-worker-launch-profile"),
      worker_fence_plan_digest: digest("ph0-worker-fence"),
      transport_profile_digest: digest("ph0-transport-profile"),
      durable_exchange_plan_digest: digest("ph0-durable-exchange-plan"),
      terminal_receipt_recipient_digest: digest("ph0-terminal-recipient-plan"),
      safety_supervisor_plan_digest: digest("ph0-safety-supervisor-plan"),
    },
  }, effectRegistry);
  const lease = {
    version: 1,
    lease_id: physicalRequest.lease_id,
    instrument_ref: instrumentRef,
    owner_principal_id: "principal:ph0-runtime-0001",
    execution_principal_id: executionPrincipalId,
    terminal_receipt_recipient_principal_id: "principal:ph0-runtime-0001",
    terminal_receipt_idempotency_domain_digest: digest("ph0-terminal-recipient"),
    attempt_ref: prepareRequest.attempt_ref,
    operation_id: prepareRequest.operation_id,
    execution_request_digest: physicalRequest.execution_request_digest,
    resource_bundle_digest: resourceBundleDigest,
    fencing_token: physicalRequest.fencing_token,
    fencing_generation: 1,
    state: "held",
    sequence: 0,
    acquired_at: "2026-07-18T00:00:00.000Z",
    updated_at: "2026-07-18T00:00:00.000Z",
    effect_not_before: "2026-07-18T00:00:00.000Z",
    effect_deadline: "2026-07-18T00:04:00.000Z",
    heartbeat_deadline: "2026-07-18T00:05:00.000Z",
    expires_at: "2026-07-18T00:10:00.000Z",
  };

  const scopeAxis = activeScopeAxis();
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const authority = {
    version: 1,
    session_id: physicalRequest.session_id,
    session_nucleus_hash: sessionNucleusHash,
    physical_scope_axis: scopeAxis,
    execution_request_digest: physicalRequest.execution_request_digest,
    authority_decision: "allow",
    authority_reason: "exact_allow",
    authority_resolution_digest: authorityResolutionDigest,
    trust_root_id: "trust-root:ph0",
    trust_root_epoch: 4,
    trust_registry_digest: digest("ph0-trust-registry"),
    trust_root_trusted: true,
    trust_root_revoked: false,
    issuer_principal_id: "principal:ph0-grant-issuer",
    issuer_key_id: "signer-key:ph0-grant-issuer",
    issuer_epoch: 3,
    issuer_public_key_digest: issuerPublicKeyDigest(keyPair.publicKey),
    key_usage: "physical_active_grant_signing",
    issuer_trusted: true,
    issuer_revoked: false,
  };
  const replayClaims = new Map();
  const grantVerifier = createActivePhysicalExecutionGrantVerifier({
    verifier_id: "ph0-active-grant-verifier-v1",
    trusted_now: () => "2026-07-18T00:00:00.150Z",
    resolve_current_authority: () => authority,
    verify_ed25519: (verification) => crypto.verify(
      null,
      Buffer.from(verification.signature_input_digest, "hex"),
      keyPair.publicKey,
      Buffer.from(verification.signature, "base64url"),
    ),
    reserve_replay: (claim) => {
      const existing = replayClaims.get(claim.grant_ref);
      if (existing) return {
        version: 1,
        disposition: "existing_same",
        reservation_receipt: existing,
      };
      const receiptBasis = {
        version: 1,
        reservation_ref: "grant-replay-reservation:ph0-0001",
        replay_claim: claim,
        replay_claim_digest: hashCanonicalJson(claim),
        generation: 1,
        previous_receipt_digest: null,
        reserved_at: "2026-07-18T00:00:00.120Z",
        fsynced_at: "2026-07-18T00:00:00.130Z",
      };
      const receipt = deepFreeze({
        ...receiptBasis,
        receipt_digest: hashCanonicalJson(receiptBasis),
      });
      replayClaims.set(claim.grant_ref, receipt);
      return { version: 1, disposition: "created", reservation_receipt: receipt };
    },
  });
  const grantPayload = {
    version: 1,
    grant_kind: "active",
    grant_ref: "physical-grant:ph0-0001",
    session_id: physicalRequest.session_id,
    session_nucleus_hash: physicalRequest.session_nucleus_hash,
    physical_scope_axis_digest: scopeAxis.axis_digest,
    physical_scope_policy_id: scopeAxis.policy_id,
    physical_scope_policy_digest: scopeAxis.policy_digest,
    physical_scope_projection_digest: scopeAxis.projection_digest,
    authority_epoch: physicalRequest.authority_epoch,
    revocation_generation: physicalRequest.revocation_generation,
    execution_request_digest: physicalRequest.execution_request_digest,
    request_nonce: physicalRequest.nonce,
    request_sequence: physicalRequest.sequence,
    execution_principal_id: physicalRequest.execution_principal_id,
    provider_id: descriptor.provider_id,
    provider_descriptor_digest: descriptor.descriptor_digest,
    instrument_ref: instrumentRef,
    operation_id: operation.operation_id,
    operation_digest: operation.operation_digest,
    parameter_digest: physicalRequest.parameter_digest,
    requested_effects_digest: physicalRequest.requested_effects_digest,
    authority_decision: authority.authority_decision,
    authority_reason: authority.authority_reason,
    authority_resolution_digest: authority.authority_resolution_digest,
    attempt_id: physicalRequest.attempt_id,
    experiment_plan_hash: physicalRequest.experiment_plan_hash,
    execution_lineage_digest: physicalRequest.execution_lineage.execution_lineage_digest,
    resource_bundle_digest: physicalRequest.resource_bundle_digest,
    lease_id: physicalRequest.lease_id,
    fencing_token: physicalRequest.fencing_token,
    fencing_generation: lease.fencing_generation,
    workspace_snapshot_digest: physicalRequest.workspace_snapshot_digest,
    cleanup_plan_digest: physicalRequest.cleanup_plan_digest,
    not_before: physicalRequest.not_before,
    expires_at: physicalRequest.expires_at,
  };
  const grantAuthentication = {
    version: 1,
    method: "ed25519",
    trust_root_id: authority.trust_root_id,
    trust_root_epoch: authority.trust_root_epoch,
    trust_registry_digest: authority.trust_registry_digest,
    issuer_principal_id: authority.issuer_principal_id,
    issuer_key_id: authority.issuer_key_id,
    issuer_epoch: authority.issuer_epoch,
    issuer_public_key_digest: authority.issuer_public_key_digest,
    signed_at: "2026-07-18T00:00:00.100Z",
    signed_payload_digest: hashCanonicalJson(grantPayload),
  };
  const signatureInputDigest = activePhysicalExecutionGrantSignatureInputDigest(
    grantPayload,
    grantAuthentication,
  );
  const signedGrant = deepFreeze({
    version: 1,
    kind: "active_physical_execution_grant",
    domain: ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN,
    payload: grantPayload,
    authentication: {
      ...grantAuthentication,
      signature: crypto.sign(
        null,
        Buffer.from(signatureInputDigest, "hex"),
        keyPair.privateKey,
      ).toString("base64url"),
    },
  });
  const grantProjection = projectVerifiedActivePhysicalExecutionGrant(
    signedGrant,
    grantVerifier,
    {
      execution_request: physicalRequest,
      effect_registry: effectRegistry,
      provider_id: descriptor.provider_id,
      provider_descriptor_digest: descriptor.descriptor_digest,
      operation_digest: operation.operation_digest,
      fencing_generation: lease.fencing_generation,
    },
  );
  const grantExpectedBindings = Object.freeze({
    execution_request_digest: grantProjection.execution_request_digest,
    authority_resolution_digest: grantProjection.authority_resolution_digest,
    execution_principal_id: grantProjection.execution_principal_id,
    provider_id: grantProjection.provider_id,
    provider_descriptor_digest: grantProjection.provider_descriptor_digest,
    instrument_ref: grantProjection.instrument_ref,
    operation_id: grantProjection.operation_id,
    operation_digest: grantProjection.operation_digest,
    attempt_id: grantProjection.attempt_id,
    experiment_plan_hash: grantProjection.experiment_plan_hash,
    execution_lineage_digest: grantProjection.execution_lineage_digest,
    lease_id: grantProjection.lease_id,
    fencing_token: grantProjection.fencing_token,
    fencing_generation: grantProjection.fencing_generation,
    resource_bundle_digest: grantProjection.resource_bundle_digest,
  });
  const dispatchAuthorityPort = createActivePhysicalDispatchAuthorityPort({
    port_id: "ph0-active-dispatch-authority-v1",
    grant_projection: grantProjection,
    grant_verifier: grantVerifier,
    expected_grant_bindings: grantExpectedBindings,
    execution_request: physicalRequest,
    effect_registry: effectRegistry,
  });

  const journal = normalizeAttemptJournalEntry({
    version: 1,
    journal_entry_ref: prepareRequest.journal_entry_ref,
    attempt_ref: lease.attempt_ref,
    instrument_ref: lease.instrument_ref,
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    fencing_generation: lease.fencing_generation,
    operation_id: lease.operation_id,
    execution_request_digest: lease.execution_request_digest,
    experiment_plan_hash: physicalRequest.experiment_plan_hash,
    execution_lineage_digest: physicalRequest.execution_lineage.execution_lineage_digest,
    authority_resolution_digest: authorityResolutionDigest,
    signed_grant_digest: grantProjection.signed_grant_digest,
    replay_claim_digest: grantProjection.replay_claim_digest,
    replay_reservation_receipt_digest: grantProjection.replay_reservation_receipt_digest,
    provider_id: descriptor.provider_id,
    provider_descriptor_digest: descriptor.descriptor_digest,
    provider_request_digest: normalizedPrepare.request_digest,
    cleanup_capability_digest: digest("ph0-cleanup-capability"),
    cleanup_plan_digest: cleanupPlanDigest,
    workspace_snapshot_ref: workspaceSnapshotRef,
    workspace_snapshot_digest: workspaceSnapshotDigest,
    stop_contract_digest: digest("ph0-stop-contract"),
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
  store.appendJournal(journal);

  const implementation = new DeterministicInstrumentProvider({
    descriptor,
    operationRegistry,
    effectRegistry,
    providerDispatchPort: createDurableInstrumentProviderDispatchPort(store, {
      provider_id: descriptor.provider_id,
      provider_descriptor_digest: descriptor.descriptor_digest,
      execution_principal_id: executionPrincipalId,
      instrument_refs: [instrumentRef],
      authority_port: dispatchAuthorityPort,
    }),
  });
  const providerMethods = PROVIDER_METHODS;
  const providerCounts = Object.fromEntries(providerMethods.map((method) => [method, 0]));
  const describeEntered = deferred();
  const releaseDescribe = deferred();
  const providerPort = {};
  for (const method of providerMethods) {
    providerPort[method] = async (...arguments_) => {
      providerCounts[method] += 1;
      if (method === "describe") {
        describeEntered.resolve();
        await releaseDescribe.promise;
      }
      return implementation[method](...arguments_);
    };
  }
  const broker = createInstrumentBroker({
    operation_registry: operationRegistry,
    effect_registry: effectRegistry,
    lease_store: createDurableInstrumentLeaseBrokerPort(store),
    grant_verifier: grantVerifier,
    execution_principal_id: executionPrincipalId,
    providers: [{
      provider_projection: descriptor,
      provider: providerPort,
      instrument_refs: [instrumentRef],
    }],
    admissions: [{
      grant_projection: grantProjection,
      provider_projection: descriptor,
      lease_id: lease.lease_id,
    }],
    now: clock,
    provider_call_timeout_ms: 5_000,
  });
  t.after(() => broker.close());

  return {
    broker,
    describeEntered,
    descriptor,
    effectRegistry,
    grantProjection,
    lease,
    operation,
    operationRegistry,
    prepareRequest,
    providerCounts,
    releaseDescribe,
    request: Object.freeze({
      grant_projection: grantProjection,
      provider_projection: descriptor,
      lease_id: lease.lease_id,
      prepare_request: prepareRequest,
    }),
    sessionNucleusHash,
  };
}

function makeDeletionLedgerAnchor() {
  const states = new Map();
  return Object.freeze({
    readState({ vault_slot: vaultSlot }) {
      const state = states.get(vaultSlot);
      return state == null ? null : clone(state);
    },
    compareAndSet(request) {
      const current = states.get(request.vault_slot) || null;
      const matches = current == null
        ? request.expected_generation == null && request.expected_ledger_digest == null
        : request.expected_generation === current.generation
          && request.expected_ledger_digest === current.ledger_digest;
      if (!matches) return false;
      states.set(request.vault_slot, clone(request.next_state));
      return true;
    },
  });
}

function makeIndexStateAnchor() {
  const states = new Map();
  return Object.freeze({
    readState({ vault_slot: vaultSlot }) {
      const state = states.get(vaultSlot);
      return state == null ? null : clone(state);
    },
    compareAndSet(request) {
      const current = states.get(request.vault_slot) || null;
      const matches = current == null
        ? request.expected_generation == null && request.expected_index_digest == null
        : request.expected_generation === current.generation
          && request.expected_index_digest === current.index_digest;
      if (!matches) return false;
      states.set(request.vault_slot, clone(request.next_state));
      return true;
    },
  });
}

function makeVault(t, sessionNucleusHash) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "bob-ph0-vault-"));
  const root = path.join(parent, "vault");
  const masterKey = crypto.randomBytes(32);
  const vaultId = `vault:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const vaultSlot = `vault-slot:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const backupKeyCustodyFixture = createInProcessBackupKeyCustodyFixture({
    vaultId,
    vaultSlot,
    sessionNucleusHash,
  });
  const vault = createArtifactVault({
    root,
    sessionNucleusHash,
    vaultId,
    vaultSlot,
    backupKeyCustody: backupKeyCustodyFixture.port,
    createNew: true,
    masterKey,
    deletionLedgerAnchor: makeDeletionLedgerAnchor(),
    indexStateAnchor: makeIndexStateAnchor(),
    quotaBytes: 1024 * 1024,
    minFreeBytes: 0,
  });
  masterKey.fill(0);
  t.after(() => {
    vault.destroy();
    backupKeyCustodyFixture.destroy();
    fs.rmSync(parent, { recursive: true, force: true });
  });
  return { root, vault };
}

function readFilesRecursively(root) {
  const files = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(entryPath);
      else files.push(fs.readFileSync(entryPath));
    }
  };
  visit(root);
  return files;
}

function signedStopRequest(lease, operationId = lease.operation_id) {
  const payload = {
    version: 1,
    stop_request_ref: `stop-request:${operationId.replaceAll(".", "-")}-0001`,
    attempt_ref: lease.attempt_ref,
    instrument_ref: lease.instrument_ref,
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    fencing_generation: lease.fencing_generation,
    operation_id: operationId,
    execution_request_digest: lease.execution_request_digest,
    authority_epoch: 7,
    revocation_generation: 3,
    issuer_principal_id: "principal:ph0-policy-issuer",
    reason: "revocation_generation_advanced",
    sequence: 9,
    nonce: "ph0-stop-nonce-0001",
    requested_at: "2026-07-18T00:00:10.000Z",
    ack_deadline: "2026-07-18T00:00:12.000Z",
  };
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const signedPayloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    Buffer.from(signedPayloadDigest, "hex"),
    keyPair.privateKey,
  );
  return Object.freeze({
    input: {
      ...payload,
      authentication: {
        version: 1,
        method: "ed25519",
        signer_key_id: "issuer-stop-key:ph0-0001",
        trust_root_epoch: 3,
        signed_payload_digest: signedPayloadDigest,
        proof_ref: "auth-proof:ph0-stop-0001",
        proof_digest: crypto.createHash("sha256").update(signature).digest("hex"),
      },
    },
    publicKey: keyPair.publicKey,
    signature,
  });
}

function verifySignedStopRequest(bundle, request, verifierId) {
  assert.equal(
    crypto.createHash("sha256").update(bundle.signature).digest("hex"),
    request.authentication.proof_digest,
  );
  assert.equal(crypto.verify(
    null,
    Buffer.from(request.authentication.signed_payload_digest, "hex"),
    bundle.publicKey,
    bundle.signature,
  ), true);
  return {
    version: 1,
    verified: true,
    method: request.authentication.method,
    signer_key_id: request.authentication.signer_key_id,
    trust_root_epoch: request.authentication.trust_root_epoch,
    verified_payload_digest: request.authentication.signed_payload_digest,
    verified_proof_digest: request.authentication.proof_digest,
    signature_verifier_id: verifierId,
    signature_verdict_digest: digest(`${verifierId}-verdict`),
  };
}

function cleanupCapability(effectRegistry, lease) {
  const template = effectRegistry.get("instrument.configure.usb.v1");
  return normalizeCleanupCapability({
    version: 1,
    capability_kind: "cleanup",
    root_kind: "cleanup_safety",
    nondelegable: true,
    agent_requestable: false,
    safety_root_ref: "safety-root:ph0-0001",
    source_execution_request_digest: lease.execution_request_digest,
    session_id: "ph0-acceptance-session",
    instrument_ref: lease.instrument_ref,
    recovery_principal_id: "principal:ph0-cleanup-worker",
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    workspace_snapshot_ref: "workspace-snapshot:ph0-reader-0001",
    workspace_snapshot_digest: digest("ph0-workspace-snapshot"),
    restore_operation_id: "instrument.restore.v1",
    restore_operation_digest: digest("ph0-restore-operation"),
    cleanup_plan_digest: digest("ph0-cleanup-plan"),
    terminal_emission_state: "inhibited",
    allowed_terminal_states: ["quarantined", "restored"],
    capability_nonce: "ph0-cleanup-capability-nonce-0001",
    requested_effects: [effectInput(template, lease.instrument_ref)],
  }, effectRegistry);
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

function leaseMutationBindings(lease) {
  return {
    version: 1,
    lease_id: lease.lease_id,
    instrument_ref: lease.instrument_ref,
    owner_principal_id: lease.owner_principal_id,
    execution_principal_id: lease.execution_principal_id,
    fencing_token: lease.fencing_token,
    fencing_generation: lease.fencing_generation,
    expected_sequence: lease.sequence,
  };
}

function evidenceComponent(name, implementationKind, verdictType) {
  return {
    version: 1,
    owner_principal: `principal:${name}`,
    [`${implementationKind}_digest`]: digest(`${name}-${implementationKind}`),
    signed_verdict_type: verdictType,
    trust_epoch: 1,
    trust_state: "trusted",
    attested_at: "2026-07-18T00:00:00.000Z",
    freshness_window_ms: 24 * 60 * 60 * 1000,
    revoked: false,
  };
}

function makeInstrumentEvidenceFixture() {
  const verdictType = "physical.transition.v1";
  const evidenceRef = "instrument-response:ph0-0001";
  const row = {
    evidence_ref: evidenceRef,
    payload_digest: digest("ph0-instrument-response-payload"),
    implementation_digest: digest("ph0-instrument-source-artifact"),
    content_hash_valid: true,
    owner_principal: "principal:ph0-instrument-worker",
    signer_key_id: "signer-key:ph0-instrument-worker",
    signed_verdict_type: verdictType,
    trust_epoch: 1,
    signature_valid: true,
    reverification_valid: true,
    trusted: true,
    revoked: false,
    execution_identity: "execution:ph0-instrument-only",
    node_contract_digest: digest("ph0-evidence-node-contract"),
    context_digest: digest("ph0-evidence-context"),
    surface_refs: ["asset:ph0-instrument"],
    disposition: "verified",
    verdict_hash: digest("ph0-instrument-verdict"),
    observed_at: "2026-07-18T00:30:00.000Z",
    cleanup_status: "succeeded",
  };
  const source = {
    ...evidenceComponent("ph0-instrument-source", "artifact", verdictType),
    owner_principal: row.owner_principal,
    artifact_digest: row.implementation_digest,
    source_id: "physical.instrument-response",
    ref_prefix: "instrument-response",
    resolve: async (ref) => ref === evidenceRef ? row : null,
    reverify: async (value) => ({
      version: 1,
      verified: value.reverification_valid === true,
      verification_digest: digest(`ph0-reverify-${value.payload_digest}`),
    }),
    project_integrity: (value) => ({
      payload_digest: value.payload_digest,
      implementation_digest: value.implementation_digest,
      content_hash_valid: value.content_hash_valid,
    }),
    project_signer_trust: (value) => ({
      owner_principal: value.owner_principal,
      signer_key_id: value.signer_key_id,
      signed_verdict_type: value.signed_verdict_type,
      trust_epoch: value.trust_epoch,
      signature_valid: value.signature_valid,
      trusted: value.trusted,
      revoked: value.revoked,
    }),
    project_execution_identity: (value) => value.execution_identity,
    project_node_contract_digest: (value) => value.node_contract_digest,
    project_context_digest: (value) => value.context_digest,
    project_surfaces: (value) => value.surface_refs,
    project_outcome: (value) => ({
      disposition: value.disposition,
      verdict_hash: value.verdict_hash,
      observed_at: value.observed_at,
    }),
    project_cleanup: (value) => ({
      status: value.cleanup_status,
      observed_at: value.observed_at,
    }),
  };
  const resolver = {
    ...evidenceComponent("ph0-context-resolver", "tool", verdictType),
    resolver_id: "physical.ph0-context",
    context_kind: "physical",
    resolve_context: async (request) => ({
      version: 1,
      ...request,
      resolved_at: "2026-07-18T00:30:00.000Z",
    }),
  };
  const executor = {
    ...evidenceComponent("ph0-bind-executor", "tool", verdictType),
    executor_id: "physical.ph0-bind",
    mode: "verified-verdict-bind",
    required_dependency_keys: [],
    execute: async ({ evidence, context }) => ({
      version: 1,
      disposition: evidence.outcome.disposition,
      signed_verdict_type: verdictType,
      verdict_hash: evidence.outcome.verdict_hash,
      consumed_evidence_digest: evidence.evidence_digest,
      execution_identity: context.execution_identity,
      node_contract_digest: context.node_contract_digest,
      context_digest: context.context_digest,
      executed_at: "2026-07-18T00:30:00.000Z",
      cleanup_status: evidence.cleanup.status,
    }),
  };
  const template = {
    ...evidenceComponent("ph0-verifier-template", "artifact", verdictType),
    template_id: "physical.ph0-instrument-bind",
    template_version: 1,
    mode: "verified-verdict-bind",
    source_ids: [source.source_id],
    context_resolver_id: resolver.resolver_id,
    replay_executor_id: executor.executor_id,
    dependency_provider_ids: [],
    decision_rule_digest: digest("ph0-instrument-only-decision-rule"),
    adjudicate: async ({ replay }) => ({
      version: 1,
      disposition: replay.disposition,
      signed_verdict_type: verdictType,
      verdict_hash: replay.verdict_hash,
      replay_digest: replay.replay_digest,
      execution_identity: replay.execution_identity,
      node_contract_digest: replay.node_contract_digest,
      context_digest: replay.context_digest,
      decided_at: "2026-07-18T00:30:00.000Z",
    }),
  };
  const registry = buildExecutedEvidenceRegistry({
    source_adapters: [source],
    context_resolvers: [resolver],
    replay_executors: [executor],
    verifier_templates: [template],
    dependency_proof_providers: [],
  });
  const normalizedSource = registry.get("source_adapters", source.source_id);
  const normalizedResolver = registry.get("context_resolvers", resolver.resolver_id);
  const normalizedExecutor = registry.get("replay_executors", executor.executor_id);
  const normalizedTemplate = registry.get("verifier_templates", template.template_id);
  const request = {
    version: 1,
    executed_evidence_ref: {
      version: 1,
      source_id: source.source_id,
      source_adapter_digest: normalizedSource.adapter_digest,
      evidence_ref: evidenceRef,
      expected_payload_digest: row.payload_digest,
      expected_verdict_hash: row.verdict_hash,
      execution_identity: row.execution_identity,
      node_contract_digest: row.node_contract_digest,
      context_digest: row.context_digest,
    },
    context_resolver_ref: {
      resolver_id: resolver.resolver_id,
      resolver_digest: normalizedResolver.resolver_digest,
    },
    context_request: {
      execution_identity: row.execution_identity,
      node_contract_digest: row.node_contract_digest,
      context_digest: row.context_digest,
      surface_refs: row.surface_refs,
    },
    replay_executor_ref: {
      executor_id: executor.executor_id,
      executor_digest: normalizedExecutor.executor_digest,
    },
    verifier_template_ref: {
      template_id: template.template_id,
      template_version: normalizedTemplate.template_version,
      template_digest: normalizedTemplate.template_digest,
    },
    dependency_proof_refs: [],
  };
  return { registry, request };
}

function assertExperimentControlIsMandatory(fixture, evidenceRegistry) {
  const receiptKeys = crypto.generateKeyPairSync("ed25519");
  const receiptPublicKeyPem = receiptKeys.publicKey.export({ type: "spki", format: "pem" });
  const physicalReceiptRegistry = buildPhysicalReceiptTrustRegistry({
    version: 1,
    registry_id: "ph0-physical-receipts",
    issuers: [{
      issuer_key_id: "signer-key:ph0-physical-ledger",
      issuer_epoch: 1,
      public_key_pem: receiptPublicKeyPem,
      valid_from: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-19T00:00:00.000Z",
      trusted: true,
      revoked: false,
    }],
  });
  const evidenceReceiptRegistry = buildDurableReceiptTrustRegistry({
    version: 1,
    registry_id: "ph0-evidence-receipts",
    issuers: [{
      issuer_key_id: "signer-key:ph0-evidence-receipts",
      issuer_epoch: 1,
      signature_scheme: "ed25519",
      public_key_pem: receiptPublicKeyPem,
      receipt_kinds: ["executed_evidence_verification", "physical_verifier_execution"],
      valid_from: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-19T00:00:00.000Z",
      trusted: true,
      revoked: false,
    }],
  });
  const observerEnrollmentRegistry = buildPhysicalObserverEnrollmentRegistry([
    {
      observer_enrollment_ref: "observer-enrollment:ph0-positive",
      observer_identity_ref: "observer:ph0-positive",
      signer_key_id: "signer-key:ph0-positive-observer",
      source_kind: "sensor",
      source_ref: "sensor:ph0-positive",
      source_assurance_scheme: "fixture_sensor_v1",
      trust_domain_ref: "trust-domain:ph0-positive",
      independence_domain_ref: "independence-domain:ph0-positive",
      external_outcome_allowed: true,
      valid_from: "2026-07-18T00:00:00.000Z",
      revoked: false,
    },
    {
      observer_enrollment_ref: "observer-enrollment:ph0-control",
      observer_identity_ref: "observer:ph0-control",
      signer_key_id: "signer-key:ph0-control-observer",
      source_kind: "sensor",
      source_ref: "sensor:ph0-control",
      source_assurance_scheme: "fixture_sensor_v1",
      trust_domain_ref: "trust-domain:ph0-control",
      independence_domain_ref: "independence-domain:ph0-control",
      external_outcome_allowed: true,
      valid_from: "2026-07-18T00:00:00.000Z",
      revoked: false,
    },
  ]);
  const experimentId = "ph0-control-required";
  const taskId = "ph0-task-0001";
  const attemptId = "ph0-acceptance-0001";
  const executionRequestDigest = fixture.lease.execution_request_digest;
  const cohort = (kind) => {
    const suffix = kind === "positive" ? "positive" : "control";
    const enrollment = observerEnrollmentRegistry.get(`observer-enrollment:ph0-${suffix}`);
    const stimulusPlanRef = `stimulus-plan:ph0-${suffix}`;
    const stimulusPlanDigest = digest(`ph0-${suffix}-stimulus`);
    const cohortExecutionRequestDigest = digest(`ph0-${suffix}-execution-request`);
    const observer = {
      observer_id: `ph0_${suffix}_observer`,
      observer_identity_ref: enrollment.observer_identity_ref,
      observer_enrollment_ref: enrollment.observer_enrollment_ref,
      source_kind: enrollment.source_kind,
      source_ref: enrollment.source_ref,
      source_assurance_scheme: enrollment.source_assurance_scheme,
      required_trust_domain_ref: enrollment.trust_domain_ref,
      required_independence_domain_ref: enrollment.independence_domain_ref,
      challenge_nonce: kind === "positive"
        ? "AAAAAAAAAAAAAAAAAAAAAA"
        : "BBBBBBBBBBBBBBBBBBBBBB",
      external_outcome: true,
    };
    observer.attempt_binding_digest = observerAttemptBindingDigest({
      session_nucleus_hash: fixture.sessionNucleusHash,
      experiment_id: experimentId,
      task_id: taskId,
      attempt_id: attemptId,
      cohort_kind: kind,
      execution_request_digest: executionRequestDigest,
      cohort_execution_request_digest: cohortExecutionRequestDigest,
      stimulus_plan_ref: stimulusPlanRef,
      stimulus_plan_digest: stimulusPlanDigest,
      observer_id: observer.observer_id,
      observer_identity_ref: observer.observer_identity_ref,
      observer_enrollment_ref: observer.observer_enrollment_ref,
      observer_enrollment_digest: enrollment.enrollment_digest,
      signer_key_id: enrollment.signer_key_id,
      source_kind: observer.source_kind,
      source_ref: observer.source_ref,
      required_trust_domain_ref: observer.required_trust_domain_ref,
      required_independence_domain_ref: observer.required_independence_domain_ref,
      challenge_nonce: observer.challenge_nonce,
    });
    return {
      kind,
      stimulus_plan_ref: stimulusPlanRef,
      stimulus_plan_digest: stimulusPlanDigest,
      cohort_execution_request_digest: cohortExecutionRequestDigest,
      grant_ref: `grant:ph0-${suffix}`,
      execution_identity: `execution:ph0-${suffix}`,
      expected_outcome_digest: digest(`ph0-${suffix}-outcome`),
      observer_plan: [observer],
    };
  };
  const positiveCohort = cohort("positive");
  const controlCohort = cohort("control");
  const assuranceClaims = {
    identity_enrollment: digest("ph0-identity-enrollment"),
    firmware_provenance: digest("ph0-firmware-provenance"),
    command_surface_conformance: digest("ph0-command-conformance"),
    transport_trust: digest("ph0-transport-trust"),
  };
  assuranceClaims.claims_digest = hashCanonicalJson(assuranceClaims);
  const targetEffect = effectInput(
    fixture.effectRegistry.get("target.transmit.rf.v1"),
    "target:ph0-card-0001",
  );
  const verifierTemplate = evidenceRegistry.get(
    "verifier_templates",
    "physical.ph0-instrument-bind",
  );
  const planWithoutControl = {
    version: 1,
    experiment_id: experimentId,
    task_id: taskId,
    attempt_id: attemptId,
    session_nucleus_hash: fixture.sessionNucleusHash,
    node_id: "PH0-acceptance",
    contract_hash: digest("ph0-node-contract"),
    execution_request_digest: executionRequestDigest,
    hypothesis_ref: "hypothesis:ph0-transition",
    claim_predicate_digest: digest("ph0-claim-predicate"),
    expected_positive_outcome_digest: positiveCohort.expected_outcome_digest,
    expected_control_outcome_digest: controlCohort.expected_outcome_digest,
    verifier_template_id: verifierTemplate.template_id,
    verifier_template_version: verifierTemplate.template_version,
    verifier_template_digest: verifierTemplate.template_digest,
    decision_rule_digest: verifierTemplate.decision_rule_digest,
    observation_window: {
      start_rule: "execution_ended",
      max_duration_ms: 5_000,
      max_clock_offset_abs_ms: 100,
      max_clock_uncertainty_ms: 100,
    },
    retry_policy: {
      fresh_attempt_and_challenge: true,
      max_attempts: 1,
      retry_on: ["inconclusive"],
    },
    trust_registry_digest: digest("ph0-plan-trust-registry"),
    executed_evidence_registry_digest: evidenceRegistry.registry_digest,
    evidence_receipt_registry_digest: evidenceReceiptRegistry.registry_digest,
    evidence_receipt_issuer_key_id: "signer-key:ph0-evidence-receipts",
    evidence_receipt_issuer_epoch: 1,
    observer_enrollment_registry_digest: observerEnrollmentRegistry.registry_digest,
    physical_receipt_registry_digest: physicalReceiptRegistry.registry_digest,
    allocation_issuer_key_id: "signer-key:ph0-physical-ledger",
    allocation_issuer_epoch: 1,
    append_issuer_key_id: "signer-key:ph0-physical-ledger",
    append_issuer_epoch: 1,
    attempt_allocation_receipt: {},
    ingestion_policy: { max_future_skew_ms: 0, max_ingestion_delay_ms: 5_000 },
    consumption_registry_digest: physicalReceiptRegistry.registry_digest,
    consumption_issuer_key_id: "signer-key:ph0-physical-ledger",
    consumption_issuer_epoch: 1,
    instrument_ref: fixture.lease.instrument_ref,
    instrument_identity_ref: "instrument-identity:ph0-reader",
    instrument_inventory_ref: "inventory:ph0-reader",
    assurance_profile_id: "ph0-assurance-v1",
    instrument_assurance_claims: assuranceClaims,
    provider_manifest_digest: fixture.descriptor.descriptor_digest,
    source_asset_ref: "source:ph0-credential",
    target_asset_ref: "target:ph0-card-0001",
    operation_id: fixture.operation.operation_id,
    parameter_digest: digest("ph0-plan-parameters"),
    requested_effects_registry_digest: fixture.effectRegistry.registry_digest,
    requested_effects: [targetEffect],
    requested_effects_digest: hashCanonicalJson([targetEffect]),
    positive_cohort: positiveCohort,
    control_cohort: controlCohort,
    controls: [],
    cleanup_plan_digest: digest("ph0-cleanup-plan"),
  };
  assert.throws(
    () => normalizePhysicalExperimentPlan(
      planWithoutControl,
      "ph0_plan_without_control",
      {
        observerEnrollmentRegistry,
        physicalReceiptRegistry,
        evidenceReceiptRegistry,
        trustedNow: "2026-07-18T01:00:00.000Z",
      },
    ),
    /controls must be a non-empty array/,
  );
}

test("PH0 fixture closes effect, custody, secret, stop/cleanup, and claim-minting boundaries", async (t) => {
  const fixture = makeBrokerFixture(t);

  // PH-S1/S2/S4: a syntactically valid but undeclared target/RF effect is
  // rejected by the enrolled broker before any provider ABI method is entered.
  const targetTemplate = fixture.effectRegistry.get("target.transmit.rf.v1");
  const outOfScopePrepare = clone(fixture.prepareRequest);
  outOfScopePrepare.requested_effects = [effectInput(targetTemplate, "target:ph0-card-0001")];
  await assert.rejects(
    fixture.broker.executeOnce({
      ...fixture.request,
      prepare_request: outOfScopePrepare,
    }),
    /requested_effects exceeds the capability worst-case declaration/,
  );
  assert.deepEqual(
    Object.values(fixture.providerCounts),
    Object.values(fixture.providerCounts).map(() => 0),
    "scope refusal must precede every provider call",
  );

  // PH-S7: one valid command holds the broker's instrument custody while its
  // provider entry is deliberately paused; the concurrent command is refused.
  const firstExecution = fixture.broker.executeOnce(fixture.request);
  await fixture.describeEntered.promise;
  assert.equal(fixture.broker.snapshot().busy_instrument_count, 1);
  const concurrent = await fixture.broker.executeOnce(fixture.request);
  assert.equal(concurrent.kind, "ambiguous");
  assert.equal(concurrent.reason_code, "dispatch_in_progress");
  assert.equal(fixture.providerCounts.describe, 1);
  assert.equal(fixture.providerCounts.prepare, 0);
  assert.equal(fixture.providerCounts.execute, 0);
  fixture.releaseDescribe.resolve();
  const first = await firstExecution;
  assert.equal(first.reason_code, "provider_dispatched");
  assert.equal(fixture.providerCounts.execute, 1);

  // The pure durable-lease contract independently proves that the same
  // instrument cannot be acquired by a second command/owner while held.
  const acquired = acquireInstrumentLease(fixture.lease, []);
  assert.throws(
    () => acquireInstrumentLease({
      ...fixture.lease,
      lease_id: "lease-ph0-0002",
      owner_principal_id: "principal:ph0-other-runtime",
      execution_principal_id: "principal:ph0-other-worker",
      terminal_receipt_recipient_principal_id: "principal:ph0-other-runtime",
      terminal_receipt_idempotency_domain_digest: digest("ph0-other-terminal-recipient"),
      attempt_ref: "attempt:ph0-acceptance-0002",
      fencing_token: "fence-ph0-0002",
      fencing_generation: 2,
    }, [acquired]),
    /instrument already bound by lease/,
  );

  // PH-S5/S4: raw credential bytes cross only the vault ingest boundary. The
  // provider/MCP-safe public contract accepts the random handle and rejects any
  // attempt to add byte material; durable vault files contain ciphertext only.
  const { root: vaultRoot, vault } = makeVault(t, fixture.sessionNucleusHash);
  const secretText = "PH0-CREDENTIAL-BYTES-NEVER-PUBLIC-7c37c2d4";
  const credentialBytes = Buffer.from(secretText, "utf8");
  const reservation = vault.reserve({
    version: 1,
    session_nucleus_hash: fixture.sessionNucleusHash,
    task_id: "ph0-task-0001",
    attempt_id: "ph0-acceptance-0001",
    reservation_ref: "reservation:ph0-credential-0001",
    purpose_ref: "purpose:credential-capture",
    byte_ceiling: credentialBytes.length,
    expires_at: "2099-01-01T00:00:00.000Z",
  });
  const artifact = vault.ingest({
    reservation_handle: reservation.reservation_handle,
    metadata: {
      version: 1,
      session_nucleus_hash: fixture.sessionNucleusHash,
      task_id: "ph0-task-0001",
      attempt_id: "ph0-acceptance-0001",
      data_class: "credential_secret",
      media_type: "application/octet-stream",
      source_ref: "provider:deterministic-ph0",
      retention_expires_at: "2099-01-02T00:00:00.000Z",
    },
    plaintext: credentialBytes,
  });
  const publicResult = normalizePublicResult({
    version: 1,
    outcome: "succeeded",
    summary_code: "operation_succeeded",
    artifact_refs: [artifact.artifact_handle],
    metric_counts: { observation_count: 1 },
  }, fixture.operation);
  const serializedPublic = JSON.stringify({ version: 1, public_result: publicResult });
  assert.equal(serializedPublic.includes(secretText), false);
  assert.equal(serializedPublic.includes("content_digest"), false);
  assert.equal(serializedPublic.includes("wrapped_data_key"), false);
  assert.deepEqual(publicResult.artifact_refs, [artifact.artifact_handle]);
  assert.throws(
    () => normalizePublicResult({
      ...clone(publicResult),
      raw_credential_bytes: Buffer.from(secretText),
    }, fixture.operation),
    /must not contain raw byte material/,
  );
  for (const durableBytes of readFilesRecursively(vaultRoot)) {
    assert.equal(durableBytes.includes(Buffer.from(secretText)), false);
  }
  credentialBytes.fill(0);

  // PH-S7: stop authority is signed and exact-operation-bound. Restoration is
  // admitted only from the separate, nondelegable, precommitted cleanup root.
  const signedStop = signedStopRequest(acquired);
  const stopRequest = normalizeSignedStopRequest(signedStop.input);
  const stopVerification = verifySignedStopRequest(
    signedStop,
    stopRequest,
    "ph0-stop-request-verifier-v1",
  );
  const stopRequested = requestInstrumentLeaseStop(acquired, stopRequest, stopVerification);
  assert.equal(stopRequested.state, "stop_requested");
  assert.equal(stopRequest.operation_id, acquired.operation_id);

  const cleanup = cleanupCapability(fixture.effectRegistry, acquired);
  const invocation = normalizeCleanupInvocation(
    cleanupInvocation(cleanup),
    cleanup,
    fixture.effectRegistry,
  );
  assert.equal(cleanup.agent_requestable, false);
  assert.equal(cleanup.nondelegable, true);
  assert.notEqual(stopRequest.stop_request_digest, cleanup.capability_digest);
  const restoring = beginInstrumentRestoration(stopRequested, {
    ...leaseMutationBindings(stopRequested),
    started_at: "2026-07-18T00:00:11.000Z",
    cleanup_capability_digest: invocation.capability_digest,
  });
  assert.equal(restoring.state, "restoring");

  const redirectedStopBundle = signedStopRequest(acquired, cleanup.restore_operation_id);
  const redirectedStop = normalizeSignedStopRequest(redirectedStopBundle.input);
  assert.throws(
    () => requestInstrumentLeaseStop(
      acquired,
      redirectedStop,
      verifySignedStopRequest(
        redirectedStopBundle,
        redirectedStop,
        "ph0-stop-request-verifier-v1",
      ),
    ),
    /operation_id binding drift/,
  );
  assert.throws(
    () => normalizeCleanupInvocation({
      ...cleanupInvocation(cleanup),
      capability_digest: stopRequest.stop_request_digest,
    }, cleanup, fixture.effectRegistry),
    /capability_digest widens or redirects the cleanup capability/,
  );
  assert.throws(
    () => normalizeCleanupCapability(stopRequest, fixture.effectRegistry),
    /unknown fields|missing fields/,
  );
  assert.throws(
    () => normalizeSignedStopRequest(cleanup),
    /unknown fields|missing fields/,
  );

  // PH-S6/S10: an instrument response must pass a registered evidence path,
  // but even a generic registered bind result is not a physical claim. Only a
  // live experiment ledger can mint that private claim brand after its
  // independent positive/control and verifier-receipt gates have succeeded.
  const evidence = makeInstrumentEvidenceFixture();
  const unregisteredVerifier = clone(evidence.request);
  unregisteredVerifier.verifier_template_ref = {
    template_id: "physical.ph0-unregistered-differential",
    template_version: 1,
    template_digest: digest("ph0-unregistered-verifier"),
  };
  await assert.rejects(
    verifyRegisteredEvidence(evidence.registry, unregisteredVerifier, {
      now: "2026-07-18T01:00:00.000Z",
    }),
    /verifier template is unregistered/,
  );
  const instrumentOnlyOutcome = await verifyRegisteredEvidence(
    evidence.registry,
    evidence.request,
    { now: "2026-07-18T01:00:00.000Z" },
  );
  assert.equal(instrumentOnlyOutcome.disposition, "verified");
  assert.equal(Object.hasOwn(instrumentOnlyOutcome, "control_evidence_refs"), false);
  assertExperimentControlIsMandatory(fixture, evidence.registry);
  assert.throws(
    () => assertVerifiedPhysicalClaimProjection({
      ...instrumentOnlyOutcome,
      outcome: "verified",
      reason_code: "differential_verified",
      control_evidence_refs: [],
    }),
    /production-qualified by a live Bob experiment ledger/,
  );
});
