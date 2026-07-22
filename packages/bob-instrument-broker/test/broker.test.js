"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  createInstrumentBroker,
} = require("../lib/broker.js");
const {
  PROVIDER_METHODS,
  buildNormalizedOperationRegistry,
  defineProviderDescriptor,
  normalizePrepareRequest,
} = require("../lib/provider-contract.js");
const {
  DeterministicInstrumentProvider,
} = require("../../bob-instrument-deterministic/lib/provider.js");
const {
  createDurableInstrumentLeaseBrokerPort,
  createDurableInstrumentLeaseStore,
  createDurableInstrumentProviderDispatchPort,
} = require("../lib/instrument-lease-store.js");
const {
  normalizeAttemptJournalEntry,
  normalizeEffectDispatchRecord,
} = require("../../../mcp/lib/instrument-lease-contract.js");
const {
  buildEffectTemplateRegistry,
} = require("../../../mcp/lib/requested-effects.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/lib/verification-contracts.js");
const {
  ACTIVE_PHYSICAL_EXECUTION_GRANT_DOMAIN,
  activePhysicalExecutionGrantSignatureInputDigest,
  createActivePhysicalExecutionGrantVerifier,
  normalizeMcpPhysicalExecutionRequest,
  projectVerifiedActivePhysicalExecutionGrant,
} = require("../../../mcp/lib/physical-authority.js");
const {
  normalizePhysicalScopeNucleusAxis,
} = require("../../../mcp/lib/governance-contracts.js");
const {
  createActivePhysicalDispatchAuthorityPort,
} = require("../../../mcp/lib/physical-dispatch-authority.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function clone(value) {
  return structuredClone(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object") return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function makeClock(start = "2026-07-18T00:00:00.200Z") {
  let current = Date.parse(start);
  const clock = () => {
    const value = new Date(current);
    current += 1;
    return value;
  };
  clock.set = (timestamp) => { current = Date.parse(timestamp); };
  return clock;
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
        || request.expected_head_event_digest !== head) {
      return false;
    }
    this.state = clone(request.next_state);
    return true;
  }
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

function activeGrantAxis() {
  return normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "broker-test-policy",
    policy_digest: digest("broker-scope-policy"),
    projection_version: 1,
    projection_digest: digest("broker-scope-projection"),
    provenance_digest: digest("broker-scope-provenance"),
    compatibility_digest: digest("broker-scope-compatibility"),
    transition_receipt_registry_digest: digest("broker-transition-receipts"),
    authority_epoch: 7,
    revocation_generation: 2,
  });
}

function issuerPublicKeyDigest(publicKey) {
  return crypto.createHash("sha256").update(
    publicKey.export({ type: "spki", format: "der" }),
  ).digest("hex");
}

function countedProvider(provider, beforeCall = null, callWrapper = null) {
  const counts = Object.fromEntries(PROVIDER_METHODS.map((method) => [method, 0]));
  const port = {};
  for (const method of PROVIDER_METHODS) {
    port[method] = (...arguments_) => {
      counts[method] += 1;
      if (beforeCall) beforeCall(method);
      const invoke = () => provider[method](...arguments_);
      return callWrapper ? callWrapper({ invoke, method }) : invoke();
    };
  }
  return { counts, port };
}

function fixture(t, {
  admissionGrantProjection = (projection) => projection,
  grantFencingToken = "fence-broker-test-0001",
  duplicateAdmission = false,
  providerCallHook = null,
  providerCallWrapper = null,
  script = [],
  storePortHooks = null,
} = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-instrument-broker-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const effectRegistry = buildEffectTemplateRegistry([{
    version: 1,
    template_id: "instrument.observe.usb.v1",
    subject_kind: "instrument",
    action: "observe",
    channel: "usb",
    persistence: "none",
    bounds: {
      attempt_limit: { kind: "integer", required: true, min: 1, max: 2 },
    },
  }]);
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
  const effect = effectRegistry.get("instrument.observe.usb.v1");
  const operation = operationRegistry.get("instrument.inventory");
  const requestedEffect = {
    version: 1,
    template_id: effect.template_id,
    template_digest: effect.template_digest,
    subject_ref: "instrument:broker-test-reader-0001",
    subject_kind: effect.subject_kind,
    action: effect.action,
    channel: effect.channel,
    persistence: effect.persistence,
    bounds: { attempt_limit: 1 },
  };
  const descriptor = defineProviderDescriptor({
    version: 1,
    abi_version: 2,
    provider_id: "deterministic_mock",
    provider_version: "1.0.0",
    implementation_digest: digest("broker-test-provider-implementation"),
    operation_registry_digest: operationRegistry.registry_digest,
    capabilities: [{
      capability_id: "broker_test.inventory",
      operation_id: operation.operation_id,
      operation_digest: operation.operation_digest,
      worst_case_effects: [worstCaseEffect(effect)],
      idempotency: "read_only_idempotent",
      retry_policy: "new_attempt_after_confirmed_no_effect",
      stop_semantics: "not_applicable",
      restore_policy: "not_required",
    }],
  }, operationRegistry, effectRegistry);
  const prepareRequest = {
    version: 1,
    attempt_ref: "attempt:broker-test-0001",
    instrument_ref: "instrument:broker-test-reader-0001",
    capability_id: "broker_test.inventory",
    operation_id: operation.operation_id,
    operation_digest: operation.operation_digest,
    parameters: {},
    requested_effects: [requestedEffect],
    execution_deadline: "2026-07-18T00:04:00.000Z",
    journal_entry_ref: "journal-entry:broker-test-precommit-0001",
  };
  const normalizedPrepare = normalizePrepareRequest(prepareRequest, {
    descriptor,
    operation_registry: operationRegistry,
    effect_registry: effectRegistry,
  });

  const clock = makeClock();
  const store = createDurableInstrumentLeaseStore({
    root,
    runtimeId: `physical-runtime:v1:${digest("broker-runtime").slice(0, 32)}`,
    sessionNucleusHash: digest("broker-session-nucleus"),
    masterKey: crypto.createHash("sha256").update("broker-test-key").digest(),
    stateAnchor: new MemoryStateAnchor(),
    checkpointMode: "legacy_full_audit",
    now: clock,
  });
  t.after(() => store.close());

  const resourceBundleDigest = digest("physical-resource-bundle");
  const executionPrincipalId = "principal:broker-test-worker-0001";
  const workspaceSnapshotRef = "workspace-snapshot:broker-test-0001";
  const workspaceSnapshotDigest = digest("broker-workspace-snapshot");
  const cleanupPlanDigest = digest("broker-cleanup-plan");
  const authorityResolutionDigest = digest("broker-exact-authority-resolution");
  const compiledCommandDigest = digest("broker-compiled-command");
  const physicalRequest = normalizeMcpPhysicalExecutionRequest({
    version: 1,
    grant_kind: "active",
    session_id: "broker-test-session",
    session_nucleus_hash: digest("broker-session-nucleus"),
    caller_role_id: "evaluator-physical",
    requester_principal_id: "principal:broker-test-requester",
    ipc_peer_principal_id: "principal:broker-test-ipc-peer",
    execution_principal_id: executionPrincipalId,
    instrument_ref: prepareRequest.instrument_ref,
    operation_id: operation.operation_id,
    parameter_digest: hashCanonicalJson(normalizedPrepare.parameters),
    authority_epoch: 7,
    revocation_generation: 2,
    nonce: "broker-test-request-nonce-0001",
    sequence: 1,
    not_before: "2026-07-18T00:00:00.000Z",
    expires_at: "2026-07-18T00:04:30.000Z",
    requested_effects: normalizedPrepare.requested_effects,
    node_id: "PH-P8",
    contract_hash: digest("broker-node-contract"),
    prep_token_hash: digest("broker-prep-token"),
    dispatch_event_id: "broker-dispatch-event-0001",
    graph_context_hash: digest("broker-graph-context"),
    capability_pack_id: "physical-bootstrap",
    capability_pack_version: "1.0.0",
    capability_pack_digest: digest("broker-capability-pack"),
    technique_cell_id: "physical.inventory.bootstrap",
    attempt_id: "broker-test-0001",
    experiment_plan_hash: digest("broker-experiment-plan"),
    inventory_observation_ref: "inventory-observation:broker-test-0001",
    inventory_observation_digest: digest("broker-inventory-observation"),
    assurance_profile_id: "broker-test-assurance-v1",
    assurance_claims_digest: digest("broker-assurance-claims"),
    provider_manifest_digest: descriptor.descriptor_digest,
    availability_variant_id: "broker-test-inventory-v1",
    availability_variant_digest: digest("broker-availability-variant"),
    authorized_transition_set_digest: digest("broker-transition-set"),
    resource_bundle_digest: resourceBundleDigest,
    fencing_token: grantFencingToken,
    lease_id: "lease-broker-test-0001",
    workspace_snapshot_ref: workspaceSnapshotRef,
    workspace_snapshot_digest: workspaceSnapshotDigest,
    observer_plan_digest: digest("broker-observer-plan"),
    control_plan_digest: digest("broker-control-plan"),
    cleanup_plan_digest: cleanupPlanDigest,
    execution_lineage: {
      version: 1,
      compiler_id: "closed_broker_compiler_v1",
      compiler_manifest_digest: digest("broker-compiler-manifest"),
      compiler_registry_digest: digest("broker-compiler-registry"),
      compiled_command_id: "compiled-command:broker-test-1",
      compiled_command_capability_digest: compiledCommandDigest,
      compiled_operation_digest: digest("broker-compiled-operation"),
      provider_command_ref: "command:broker-test-1",
      command_input_ref: "command-input:broker-test-1",
      command_input_digest: compiledCommandDigest,
      maximum_response_bytes: 512,
      vault_reservation_handle: `vault-reservation:v1:${"D".repeat(43)}`,
      vault_reservation_digest: digest("broker-vault-reservation"),
      vault_ingest_capability_digest: digest("broker-vault-ingest"),
      vault_byte_limit: 512,
      worker_bundle_digest: digest("broker-worker-bundle"),
      worker_launch_profile_digest: digest("broker-worker-launch-profile"),
      worker_fence_plan_digest: digest("broker-worker-fence"),
      transport_profile_digest: digest("broker-transport-profile"),
      durable_exchange_plan_digest: digest("broker-durable-exchange-plan"),
      terminal_receipt_recipient_digest: digest("broker-terminal-recipient-plan"),
      safety_supervisor_plan_digest: digest("broker-safety-supervisor-plan"),
    },
  }, effectRegistry);
  const executionRequestDigest = physicalRequest.execution_request_digest;
  const lease = {
    version: 1,
    lease_id: "lease-broker-test-0001",
    instrument_ref: prepareRequest.instrument_ref,
    owner_principal_id: "principal:broker-test-runtime-0001",
    execution_principal_id: executionPrincipalId,
    terminal_receipt_recipient_principal_id: "principal:broker-test-runtime-0001",
    terminal_receipt_idempotency_domain_digest: digest("broker-terminal-recipient"),
    attempt_ref: prepareRequest.attempt_ref,
    operation_id: prepareRequest.operation_id,
    execution_request_digest: executionRequestDigest,
    resource_bundle_digest: resourceBundleDigest,
    fencing_token: "fence-broker-test-0001",
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
  const scopeAxis = activeGrantAxis();
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const authority = {
    version: 1,
    session_id: physicalRequest.session_id,
    session_nucleus_hash: physicalRequest.session_nucleus_hash,
    physical_scope_axis: scopeAxis,
    execution_request_digest: physicalRequest.execution_request_digest,
    authority_decision: "allow",
    authority_reason: "exact_allow",
    authority_resolution_digest: authorityResolutionDigest,
    trust_root_id: "trust-root:broker-test",
    trust_root_epoch: 4,
    trust_registry_digest: digest("broker-trust-registry"),
    trust_root_trusted: true,
    trust_root_revoked: false,
    issuer_principal_id: "principal:broker-test-grant-issuer",
    issuer_key_id: "signer-key:broker-test-grant-issuer",
    issuer_epoch: 3,
    issuer_public_key_digest: issuerPublicKeyDigest(keyPair.publicKey),
    key_usage: "physical_active_grant_signing",
    issuer_trusted: true,
    issuer_revoked: false,
  };
  const replayClaims = new Map();
  const grantVerifier = createActivePhysicalExecutionGrantVerifier({
    verifier_id: "broker-active-grant-verifier-v1",
    trusted_now: () => "2026-07-18T00:00:00.150Z",
    resolve_current_authority: () => authority,
    verify_ed25519: (verification) => crypto.verify(
      null,
      Buffer.from(verification.signature_input_digest, "hex"),
      keyPair.publicKey,
      Buffer.from(verification.signature, "base64url"),
    ),
    reserve_replay: (claim) => {
      const replayClaimDigest = hashCanonicalJson(claim);
      const existing = replayClaims.get(claim.grant_ref);
      if (existing) {
        return {
          version: 1,
          disposition: "existing_same",
          reservation_receipt: existing,
        };
      }
      const receiptBasis = {
        version: 1,
        reservation_ref: "grant-replay-reservation:broker-test-0001",
        replay_claim: claim,
        replay_claim_digest: replayClaimDigest,
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
      return {
        version: 1,
        disposition: "created",
        reservation_receipt: receipt,
      };
    },
  });
  const grantPayload = {
    version: 1,
    grant_kind: "active",
    grant_ref: "physical-grant:broker-test-0001",
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
    instrument_ref: physicalRequest.instrument_ref,
    operation_id: physicalRequest.operation_id,
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
  const grantSignatureInputDigest = activePhysicalExecutionGrantSignatureInputDigest(
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
        Buffer.from(grantSignatureInputDigest, "hex"),
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
    port_id: "broker-active-dispatch-authority-v1",
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
    cleanup_capability_digest: digest("broker-cleanup-capability"),
    cleanup_plan_digest: cleanupPlanDigest,
    workspace_snapshot_ref: workspaceSnapshotRef,
    workspace_snapshot_digest: workspaceSnapshotDigest,
    stop_contract_digest: digest("broker-stop-contract"),
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
      instrument_refs: [prepareRequest.instrument_ref],
      authority_port: dispatchAuthorityPort,
    }),
    script,
  });
  const provider = countedProvider(
    implementation,
    (method) => {
      if (providerCallHook) providerCallHook({ clock, method });
    },
    providerCallWrapper,
  );
  const brokerStore = createDurableInstrumentLeaseBrokerPort(store, storePortHooks || {});
  const enrolledGrantProjection = admissionGrantProjection(grantProjection);
  const admissions = [{
    grant_projection: enrolledGrantProjection,
    provider_projection: descriptor,
    lease_id: lease.lease_id,
  }];
  if (duplicateAdmission) {
    admissions.push({
      grant_projection: grantProjection,
      provider_projection: descriptor,
      lease_id: lease.lease_id,
    });
  }
  const broker = createInstrumentBroker({
    operation_registry: operationRegistry,
    effect_registry: effectRegistry,
    lease_store: brokerStore,
    grant_verifier: grantVerifier,
    execution_principal_id: executionPrincipalId,
    providers: [{
      provider_projection: descriptor,
      provider: provider.port,
      instrument_refs: [prepareRequest.instrument_ref],
    }],
    admissions,
    now: clock,
    provider_call_timeout_ms: 250,
  });
  const request = Object.freeze({
    grant_projection: grantProjection,
    provider_projection: descriptor,
    lease_id: lease.lease_id,
    prepare_request: prepareRequest,
  });
  return {
    authority,
    broker,
    clock,
    descriptor,
    grantVerifier,
    grantProjection,
    lease,
    operationRegistry,
    prepareRequest,
    provider,
    request,
    store,
  };
}

test("the broker has a closed surface and rejects forged grant and provider projections", async (t) => {
  const f = fixture(t);
  assert.deepEqual(Object.keys(f.broker).sort(), ["close", "executeOnce", "reconcile", "snapshot"]);
  assert.equal(Object.isFrozen(f.broker), true);

  await assert.rejects(
    f.broker.executeOnce({ ...f.request, grant_projection: clone(f.grantProjection) }),
    /exact broker-enrolled grant, provider, and lease projections/,
  );
  await assert.rejects(
    f.broker.executeOnce({ ...f.request, authority_projection: clone(f.authority) }),
    /unknown fields: authority_projection/,
  );
  await assert.rejects(
    f.broker.executeOnce({ ...f.request, provider_projection: clone(f.descriptor) }),
    /exact broker-enrolled grant, provider, and lease projections/,
  );
  assert.equal(f.provider.counts.execute, 0);
  assert.equal(f.store.snapshot().dispatches.length, 0);
});

test("broker construction rejects a frozen self-hashed grant clone before admission", (t) => {
  assert.throws(
    () => fixture(t, { admissionGrantProjection: (projection) => deepFreeze(clone(projection)) }),
    /grant projection was not issued by the configured verifier/,
  );
});

test("broker construction rehydrates only a grant fence that matches durable record digests", (t) => {
  const mismatchedFence = "fence-broker-test-grant-fork";
  const durableFence = "fence-broker-test-0001";
  const originalCreateHash = crypto.createHash;
  let ambientCreateHashCalls = 0;
  let durableLeaseDigest = null;
  let durableJournalDigest = null;
  let forgedDigestReturnCount = 0;

  // Model hostile application code patching the shared crypto module after
  // all broker/contract modules have been imported. Before the canonical hash
  // contract captured its Hash intrinsics, this could make both redacted
  // durable records appear to bind a grant-controlled, incorrect fence.
  crypto.createHash = function poisonedCreateHash(...arguments_) {
    ambientCreateHashCalls += 1;
    const hash = Reflect.apply(originalCreateHash, crypto, arguments_);
    const originalUpdate = hash.update;
    const originalDigest = hash.digest;
    let stringMaterial = "";
    hash.update = function poisonedUpdate(value) {
      if (typeof value === "string") stringMaterial += value;
      Reflect.apply(originalUpdate, hash, arguments);
      return hash;
    };
    hash.digest = function poisonedDigest(encoding) {
      const genuineDigest = Reflect.apply(originalDigest, hash, arguments);
      if (encoding !== "hex") return genuineDigest;
      const isJournal = stringMaterial.includes("\"journal_entry_ref\"");
      const isLease = stringMaterial.includes("\"owner_principal_id\"");
      if (stringMaterial.includes(`"fencing_token":"${durableFence}"`)) {
        if (isJournal) durableJournalDigest = genuineDigest;
        if (isLease) durableLeaseDigest = genuineDigest;
      }
      if (stringMaterial.includes(`"fencing_token":"${mismatchedFence}"`)) {
        if (isJournal && durableJournalDigest != null) {
          forgedDigestReturnCount += 1;
          return durableJournalDigest;
        }
        if (isLease && durableLeaseDigest != null) {
          forgedDigestReturnCount += 1;
          return durableLeaseDigest;
        }
      }
      return genuineDigest;
    };
    return hash;
  };

  try {
    assert.throws(
      () => fixture(t, { grantFencingToken: mismatchedFence }),
      /lease_digest does not match normalized content/,
    );
  } finally {
    crypto.createHash = originalCreateHash;
  }
  assert.ok(ambientCreateHashCalls > 0, "the fixture must exercise the patched ambient crypto module");
  assert.equal(forgedDigestReturnCount, 0,
    "canonical record hashing must never use the post-import ambient crypto patch");

  const originalJsonStringify = JSON.stringify;
  JSON.stringify = function poisonedJsonStringify(...arguments_) {
    const serialized = Reflect.apply(originalJsonStringify, JSON, arguments_);
    if (typeof serialized === "string"
        && serialized.includes(`"fencing_token":"${mismatchedFence}"`)
        && (serialized.includes("\"journal_entry_ref\"")
          || serialized.includes("\"owner_principal_id\""))) {
      return serialized.replace(
        `"fencing_token":"${mismatchedFence}"`,
        `"fencing_token":"${durableFence}"`,
      );
    }
    return serialized;
  };
  try {
    assert.equal(
      JSON.stringify({ fencing_token: mismatchedFence, owner_principal_id: "principal:probe" })
        .includes(`"fencing_token":"${durableFence}"`),
      true,
      "the JSON poison probe must substitute the durable fence",
    );
    assert.throws(
      () => fixture(t, { grantFencingToken: mismatchedFence }),
      /lease_digest does not match normalized content/,
    );
  } finally {
    JSON.stringify = originalJsonStringify;
  }

  const originalArraySort = Array.prototype.sort;
  const originalArrayIndexOf = Array.prototype.indexOf;
  const originalArraySplice = Array.prototype.splice;
  Array.prototype.sort = function poisonedArraySort(...arguments_) {
    const result = Reflect.apply(originalArraySort, this, arguments_);
    const fenceIndex = Reflect.apply(originalArrayIndexOf, this, ["fencing_token"]);
    const hasLeaseMarker = Reflect.apply(originalArrayIndexOf, this, ["owner_principal_id"]) >= 0;
    const hasJournalMarker = Reflect.apply(originalArrayIndexOf, this, ["journal_entry_ref"]) >= 0;
    if (fenceIndex >= 0 && (hasLeaseMarker || hasJournalMarker)) {
      Reflect.apply(originalArraySplice, this, [fenceIndex, 1]);
    }
    return result;
  };
  try {
    const poisonProbe = ["owner_principal_id", "fencing_token"];
    poisonProbe.sort();
    assert.equal(poisonProbe.includes("fencing_token"), false,
      "the Array poison probe must remove the fence from canonical keys");
    assert.throws(
      () => fixture(t, { grantFencingToken: mismatchedFence }),
      /lease_digest does not match normalized content/,
    );
  } finally {
    Array.prototype.sort = originalArraySort;
  }
});

test("dispatch is durably elected once, duplicate execution is suppressed, and reconciliation confirms", async (t) => {
  const f = fixture(t);
  const first = await f.broker.executeOnce(f.request);
  assert.equal(first.reason_code, "provider_dispatched");
  assert.equal(first.kind, "ambiguous");
  assert.match(first.dispatch_record_digest, /^[a-f0-9]{64}$/);
  assert.equal(first.reconciliation_required, true);
  assert.equal(Object.hasOwn(first, "fencing_token"), false);
  const serializedFirst = JSON.stringify(first);
  assert.equal(serializedFirst.includes(f.lease.fencing_token), false);
  assert.doesNotMatch(serializedFirst, /dispatch_credential|credential_ref|fencing_token/);
  assert.equal(f.provider.counts.execute, 1);
  assert.equal(f.store.snapshot().dispatches.length, 1);
  const [dispatch] = f.store.snapshot().dispatches;
  assert.equal(dispatch.provider_id, f.descriptor.provider_id);
  assert.equal(dispatch.provider_descriptor_digest, f.descriptor.descriptor_digest);
  assert.equal(dispatch.provider_sequence, 1);

  const duplicate = await f.broker.executeOnce(f.request);
  assert.equal(duplicate.kind, "ambiguous");
  assert.equal(duplicate.reason_code, "dispatch_already_committed");
  assert.equal(duplicate.dispatch_record_digest, first.dispatch_record_digest);
  assert.equal(f.provider.counts.execute, 1, "a durable dispatch claim is never replayed");

  const reconciled = await f.broker.reconcile({
    ...f.request,
    observation_ref: "observation:broker-reconcile-0001",
  });
  assert.equal(reconciled.kind, "confirmed");
  assert.equal(reconciled.reason_code, "provider_acknowledged");
  assert.equal(reconciled.reconciliation_required, false);
  assert.equal(f.provider.counts.execute, 1);
  assert.equal(f.provider.counts.status, 1);
});

test("the broker clock is monotonic and rollback cannot reopen an admitted window", async (t) => {
  const f = fixture(t);
  const first = await f.broker.executeOnce(f.request);
  assert.equal(first.kind, "ambiguous");
  assert.equal(f.provider.counts.execute, 1);
  f.clock.set("2026-07-18T00:00:00.000Z");
  await assert.rejects(
    f.broker.executeOnce(f.request),
    /instrument broker clock moved backwards/,
  );
  assert.equal(f.provider.counts.execute, 1);
});

test("a lost durable-commit acknowledgement is ambiguous and never reaches the provider", async (t) => {
  let loseCommitAck = true;
  const f = fixture(t, {
    storePortHooks: {
      after_call({ method }) {
        if (method === "commitDispatch" && loseCommitAck) {
          loseCommitAck = false;
          throw new Error("injected broker/store response loss");
        }
      },
    },
  });
  const first = await f.broker.executeOnce(f.request);
  assert.equal(first.reason_code, "dispatch_commit_ack_lost");
  assert.equal(first.kind, "ambiguous");
  assert.equal(f.store.snapshot().dispatches.length, 1);
  assert.equal(f.provider.counts.execute, 0);

  const duplicate = await f.broker.executeOnce(f.request);
  assert.equal(duplicate.reason_code, "dispatch_already_committed");
  assert.equal(f.provider.counts.execute, 0);
});

test("a lost prepare acknowledgement recovers by exact status without replaying prepare", async (t) => {
  let losePrepareAck = true;
  const f = fixture(t, {
    async providerCallWrapper({ invoke, method }) {
      const response = await invoke();
      if (method === "prepare" && losePrepareAck) {
        losePrepareAck = false;
        const error = new Error("injected prepare response loss");
        error.code = "provider_disconnect";
        throw error;
      }
      return response;
    },
  });
  const result = await f.broker.executeOnce(f.request);
  assert.equal(result.kind, "ambiguous");
  assert.equal(result.reason_code, "provider_dispatched");
  assert.equal(f.provider.counts.prepare, 1);
  assert.equal(f.provider.counts.status, 1);
  assert.equal(f.provider.counts.execute, 1);
  assert.equal(f.store.snapshot().dispatches.length, 1);

  const duplicate = await f.broker.executeOnce(f.request);
  assert.equal(duplicate.reason_code, "dispatch_already_committed");
  assert.equal(f.provider.counts.prepare, 1);
  assert.equal(f.provider.counts.execute, 1);
});

test("durable prepare refusal remains stable when the broker response is lost", async (t) => {
  const f = fixture(t, {
    script: [{ method: "prepare", outcome: "refusal" }],
  });
  const first = await f.broker.executeOnce(f.request);
  assert.equal(first.kind, "rejected");
  assert.equal(first.reason_code, "provider_refused");
  assert.equal(f.provider.counts.prepare, 1);
  assert.equal(f.provider.counts.execute, 0);

  const retried = await f.broker.executeOnce(f.request);
  assert.equal(retried.kind, "rejected");
  assert.equal(retried.reason_code, "reconciled_no_effect");
  assert.equal(retried.journal_entry_digest, first.journal_entry_digest);
  assert.equal(f.provider.counts.prepare, 1);
  assert.equal(f.provider.counts.execute, 0);

  const reconciled = await f.broker.reconcile({
    ...f.request,
    observation_ref: "observation:broker-refusal-response-loss-0001",
  });
  assert.equal(reconciled.kind, "rejected");
  assert.equal(reconciled.reason_code, "reconciled_no_effect");
  assert.equal(reconciled.journal_entry_digest, first.journal_entry_digest);
});

test("a competing durable dispatch claimant is ambiguous and cannot trigger a loser replay", async (t) => {
  let electCompetitor = true;
  let storeForElection = null;
  const f = fixture(t, {
    storePortHooks: {
      before_call({ method }) {
        if (method === "commitDispatch" && electCompetitor) {
          electCompetitor = false;
          const snapshot = storeForElection.snapshot();
          const journal = snapshot.journal_heads.find(
            (entry) => entry.attempt_ref === f.lease.attempt_ref,
          );
          const competing = normalizeEffectDispatchRecord({
            version: 1,
            dispatch_event_ref: "dispatch-event:competing-broker-0001",
            journal_entry_ref: journal.journal_entry_ref,
            journal_entry_digest: journal.journal_entry_digest,
            attempt_ref: journal.attempt_ref,
            instrument_ref: journal.instrument_ref,
            lease_id: journal.lease_id,
            fencing_token: journal.fencing_token,
            fencing_generation: journal.fencing_generation,
            operation_id: journal.operation_id,
            execution_request_digest: journal.execution_request_digest,
            provider_id: journal.provider_id,
            provider_descriptor_digest: journal.provider_descriptor_digest,
            provider_request_digest: journal.provider_request_digest,
            provider_sequence: journal.provider_sequence,
            dispatched_at: new Date(Date.parse(journal.fsynced_at) + 1).toISOString(),
          }, journal);
          storeForElection.commitDispatch(competing);
          throw new Error("injected competing broker election loss");
        }
      },
    },
  });
  storeForElection = f.store;
  const result = await f.broker.executeOnce(f.request);
  assert.equal(result.kind, "ambiguous");
  assert.equal(result.reason_code, "dispatch_election_lost");
  assert.equal(result.dispatch_record_digest, f.store.snapshot().dispatches[0].dispatch_record_digest);
  assert.equal(f.provider.counts.execute, 0);

  const duplicate = await f.broker.executeOnce(f.request);
  assert.equal(duplicate.reason_code, "dispatch_already_committed");
  assert.equal(f.provider.counts.execute, 0);
});

test("throw-after-effect remains ambiguous, is never retried, and requires explicit reconciliation", async (t) => {
  const f = fixture(t, {
    script: [
      { method: "execute", outcome: "crash_after_dispatch" },
      { method: "reconcile", outcome: "confirmed_no_effect" },
    ],
  });
  const first = await f.broker.executeOnce(f.request);
  assert.equal(first.reason_code, "provider_crash");
  assert.equal(first.kind, "ambiguous");
  assert.equal(f.provider.counts.execute, 1);

  const duplicate = await f.broker.executeOnce(f.request);
  assert.equal(duplicate.reason_code, "dispatch_already_committed");
  assert.equal(f.provider.counts.execute, 1);

  const reconciled = await f.broker.reconcile({
    ...f.request,
    observation_ref: "observation:broker-reconcile-no-effect-0001",
  });
  assert.equal(reconciled.reason_code, "reconciled_no_effect");
  assert.equal(reconciled.kind, "rejected");
  assert.equal(reconciled.reconciliation_required, false);
  assert.equal(f.provider.counts.status, 1);
  assert.equal(f.provider.counts.reconcile, 1);
  assert.equal(f.provider.counts.execute, 1);

  const repeated = await f.broker.reconcile({
    ...f.request,
    observation_ref: "observation:broker-reconcile-no-effect-0002",
  });
  assert.equal(repeated.kind, "rejected");
  assert.equal(repeated.reason_code, "reconciled_no_effect");
  assert.equal(repeated.journal_entry_digest, reconciled.journal_entry_digest);
  assert.equal(f.provider.counts.execute, 1);
});

test("a stale per-instrument fence prevents claim and provider dispatch", async (t) => {
  const f = fixture(t);
  const held = f.store.snapshot().leases[0];
  const fencedAt = "2026-07-18T00:00:00.500Z";
  f.clock.set(fencedAt);
  f.store.fenceLease({
    version: 1,
    lease_id: held.lease_id,
    instrument_ref: held.instrument_ref,
    owner_principal_id: held.owner_principal_id,
    execution_principal_id: held.execution_principal_id,
    fencing_token: held.fencing_token,
    fencing_generation: held.fencing_generation,
    expected_sequence: held.sequence,
    fenced_at: fencedAt,
    reason: "revocation",
  });

  const result = await f.broker.executeOnce(f.request);
  assert.equal(result.kind, "unavailable");
  assert.equal(result.reason_code, "lease_not_executable");
  assert.equal(result.reconciliation_required, false);
  assert.equal(f.store.snapshot().dispatches.length, 0);
  assert.equal(f.provider.counts.prepare, 0);
  assert.equal(f.provider.counts.execute, 0);
});

test("one durable attempt/lease cannot be admitted under competing grant projections", (t) => {
  assert.throws(
    () => fixture(t, { duplicateAdmission: true }),
    /cannot duplicate an attempt, lease, or grant binding/,
  );
});

test("provider state/sequence skips after the durable claim are ambiguous and never replayed", async (t) => {
  const f = fixture(t, {
    script: [{ method: "execute", outcome: "stale_state" }],
  });
  const result = await f.broker.executeOnce(f.request);
  assert.equal(result.kind, "ambiguous");
  assert.equal(result.reason_code, "provider_invalid_transition");
  assert.equal(f.provider.counts.execute, 1);
  assert.equal(f.store.snapshot().dispatches.length, 1);

  const duplicate = await f.broker.executeOnce(f.request);
  assert.equal(duplicate.reason_code, "dispatch_already_committed");
  assert.equal(f.provider.counts.execute, 1);
});

test("restart status must match the exact durable provider state and sequence", async (t) => {
  const f = fixture(t, {
    script: [{ method: "status", outcome: "stale_state" }],
  });
  const dispatched = await f.broker.executeOnce(f.request);
  assert.equal(dispatched.reason_code, "provider_dispatched");

  const result = await f.broker.reconcile({
    ...f.request,
    observation_ref: "observation:broker-stale-provider-sequence-0001",
  });
  assert.equal(result.kind, "ambiguous");
  assert.equal(result.reason_code, "provider_invalid_transition");
  const head = f.store.snapshot().journal_heads[0];
  assert.equal(head.state, "running");
  assert.equal(head.provider_state, "dispatched");
  assert.equal(head.provider_sequence, 2);
  assert.equal(f.provider.counts.execute, 1);
});

test("unknown provider effect is durably projected before reconciliation returns", async (t) => {
  const f = fixture(t, {
    script: [
      { method: "status", outcome: "ambiguous" },
      { method: "reconcile", outcome: "timeout" },
    ],
  });
  const dispatched = await f.broker.executeOnce(f.request);
  assert.equal(dispatched.reason_code, "provider_dispatched");

  const uncertain = await f.broker.reconcile({
    ...f.request,
    observation_ref: "observation:broker-unknown-effect-0001",
  });
  assert.equal(uncertain.kind, "ambiguous");
  assert.equal(uncertain.reason_code, "provider_timeout");
  assert.equal(f.store.snapshot().journal_heads[0].state, "ambiguous_effect");

  const observed = await f.broker.reconcile({
    ...f.request,
    observation_ref: "observation:broker-unknown-effect-0002",
  });
  assert.equal(observed.kind, "ambiguous");
  assert.equal(observed.reason_code, "provider_unknown_effect");
  const head = f.store.snapshot().journal_heads[0];
  assert.equal(head.state, "unknown_effect");
  assert.equal(head.provider_state, "unknown_effect");
  assert.equal(head.provider_sequence, 4);
});

test("quarantined provider state is durably projected across skipped observations", async (t) => {
  const f = fixture(t, {
    async providerCallWrapper({ invoke, method }) {
      const response = await invoke();
      if (method !== "status") return response;
      return {
        ...response,
        state: "quarantined",
        sequence: response.sequence + 1,
        effect_disposition: "confirmed_effect",
      };
    },
  });
  const dispatched = await f.broker.executeOnce(f.request);
  assert.equal(dispatched.reason_code, "provider_dispatched");

  const observed = await f.broker.reconcile({
    ...f.request,
    observation_ref: "observation:broker-quarantined-0001",
  });
  assert.equal(observed.kind, "ambiguous");
  assert.equal(observed.reason_code, "provider_quarantined");
  const head = f.store.snapshot().journal_heads[0];
  assert.equal(head.state, "quarantined");
  assert.equal(head.provider_state, "quarantined");
  assert.equal(head.provider_sequence, 4);
});

test("a slow provider cannot carry an admitted attempt past its execution deadline", async (t) => {
  let advanced = false;
  const f = fixture(t, {
    providerCallHook({ clock, method }) {
      if (!advanced && method === "prepare") {
        advanced = true;
        clock.set("2026-07-18T00:04:01.000Z");
      }
    },
  });
  const result = await f.broker.executeOnce(f.request);
  assert.equal(result.kind, "unavailable");
  assert.equal(result.reason_code, "authorization_window_expired");
  assert.equal(f.store.snapshot().dispatches.length, 0);
  assert.equal(f.provider.counts.prepare, 1);
  assert.equal(f.provider.counts.execute, 0);
});

test("live authority revocation after prepare wins the final pre-dispatch fence", async (t) => {
  let f;
  f = fixture(t, {
    providerCallHook({ method }) {
      if (method === "prepare") f.authority.issuer_revoked = true;
    },
  });
  const result = await f.broker.executeOnce(f.request);
  assert.equal(result.kind, "unavailable");
  assert.equal(result.reason_code, "authorization_revalidation_failed");
  assert.equal(f.store.snapshot().dispatches.length, 0);
  assert.equal(f.provider.counts.prepare, 1);
  assert.equal(f.provider.counts.execute, 0);
});

test("the durable effect seam rejects delay past the signed grant and prepare deadline", async (t) => {
  const f = fixture(t, {
    providerCallHook({ clock, method }) {
      if (method === "execute") clock.set("2026-07-18T00:04:00.000Z");
    },
  });
  const result = await f.broker.executeOnce(f.request);
  assert.equal(result.kind, "ambiguous");
  assert.equal(result.reason_code, "provider_unavailable");
  const snapshot = f.store.snapshot();
  assert.equal(snapshot.dispatches.length, 1);
  assert.equal(snapshot.dispatch_redemptions.length, 0);
  assert.equal(f.provider.counts.execute, 1);
  assert.equal(snapshot.journal_heads[0].state, "effect_starting");
  assert.equal(snapshot.journal_heads[0].effect_disposition, "not_dispatched");
});

test("reconciliation without a durable dispatch is nonterminal and cannot masquerade as no-effect", async (t) => {
  const f = fixture(t);
  const result = await f.broker.reconcile({
    ...f.request,
    observation_ref: "observation:broker-no-dispatch-0001",
  });
  assert.equal(result.kind, "unavailable");
  assert.equal(result.reason_code, "dispatch_not_committed");
  assert.equal(f.store.snapshot().journal_heads[0].state, "precommitted");
  assert.equal(f.provider.counts.prepare, 0);
  assert.equal(f.provider.counts.execute, 0);
});

test("an expired action grant cannot strand reconciliation of a committed dispatch", async (t) => {
  const f = fixture(t);
  const dispatched = await f.broker.executeOnce(f.request);
  assert.equal(dispatched.kind, "ambiguous");
  f.clock.set("2026-07-18T00:04:31.000Z");

  const reconciled = await f.broker.reconcile({
    ...f.request,
    observation_ref: "observation:broker-expired-action-recovery-0001",
  });
  assert.equal(reconciled.kind, "confirmed");
  assert.equal(reconciled.reason_code, "provider_acknowledged");
  assert.equal(f.provider.counts.execute, 1);
});

test("normal dispatch ambiguity durably reconciles to confirmed no-effect", async (t) => {
  const f = fixture(t, {
    script: [
      { method: "status", outcome: "ambiguous" },
      { method: "reconcile", outcome: "confirmed_no_effect" },
    ],
  });
  const dispatched = await f.broker.executeOnce(f.request);
  assert.equal(dispatched.reason_code, "provider_dispatched");

  const reconciled = await f.broker.reconcile({
    ...f.request,
    observation_ref: "observation:broker-s7-gap-0001",
  });
  assert.equal(reconciled.reason_code, "reconciled_no_effect");
  assert.equal(reconciled.kind, "rejected");
  assert.equal(reconciled.reconciliation_required, false);
  assert.equal(f.store.snapshot().journal_heads[0].state, "reconciled_no_effect");
  assert.equal(f.provider.counts.execute, 1);
  assert.equal(f.provider.counts.reconcile, 1);
});
