"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  appendContract,
} = require("../mcp/core/contract/index.js");
const { TOOL_HANDLERS } = require("../mcp/tools/tool-registry.js");
const prepareNodeModule = require("../mcp/tools/prepare-node.js");
const {
  preparePhysicalResourceNode,
} = prepareNodeModule;
const {
  selectNextExecutableNodes,
} = require("../mcp/core/waves/graph-scheduler.js");
const {
  cancelPreparedPhysicalGraphReservation,
  createPhysicalResourceGraphCoordinator,
  projectPhysicalResourceGraphHandle,
  reserveAndPreparePhysicalGraphNode,
  transferPreparedPhysicalGraphReservationToProviderBridge,
} = require("../mcp/domains/physical/physical-resource-graph-coordinator.js");
const {
  createDeterministicMockDispatchAuthorityPort,
} = require("../mcp/domains/physical/physical-dispatch-authority.js");
const {
  bindPhysicalResourceBundle,
  normalizePhysicalReservationRequest,
  normalizePhysicalResourceBundle,
} = require("../mcp/core/physical-resource-contracts.js");
const {
  normalizePhysicalResourceInventory,
} = require("../mcp/domains/physical/physical-resource-scheduler.js");
const {
  MAX_UNCERTAINTY_MS,
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
} = require("../mcp/domains/physical/physical-trusted-clock.js");
const {
  readVerifiedSessionNucleus,
} = require("../mcp/core/governance/index.js");
const {
  sessionLockPath,
} = require("../mcp/core/io/paths.js");
const {
  initSession,
} = require("../mcp/core/session/session-state.js");
const {
  materializeTaskGraph,
} = require("../mcp/core/waves/task-graph-materializer.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
  appendHypothesisProposal,
  appendNodeTransition,
  expireStaleDispatchedNodes,
  readNodeTransitions,
} = require("../mcp/core/waves/task-graph-events.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");
const {
  cancelPhysicalResourceReservation,
  createInitialPhysicalResourceReservationState,
  createPhysicalResourceBundleResolverPort,
  createPhysicalResourceReservationAuthority,
  createPhysicalResourceReservationEligibilityPort,
  createPhysicalResourceReservationStatePort,
  projectPhysicalResourceReservationInventory,
  reservePhysicalResources,
  resolveHeldPhysicalResourceForNode,
} = require("../packages/bob-instrument-broker/lib/resource-reservations.js");
const {
  createPhysicalProviderCommandAuthorizationPort,
  createPhysicalProviderCommandRegistry,
  createPhysicalProviderCommandRequest,
  createPhysicalProviderCompletionVerificationPort,
  normalizePhysicalProviderBinding,
  resolvePhysicalProviderCommand,
  resolvePhysicalProviderCommandAuthorization,
} = require("../packages/bob-instrument-broker/lib/physical-provider-dispatch.js");
const {
  createPhysicalReservationFixture,
} = require("../packages/bob-instrument-broker/test/helpers/physical-reservation-fixture.js");

const digest = (label) => hashCanonicalJson({ label });

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

function dispatchBinding(eligibility) {
  return {
    source_graph_hash: eligibility.source_graph_hash,
    session_nucleus_hash: eligibility.session_nucleus_hash,
    resource_bundle_digest: eligibility.resource_bundle_digest,
    reservation_ref: eligibility.reservation_ref,
    receipt_digest: eligibility.receipt_digest,
    allocation_plan_digest: eligibility.allocation_plan_digest,
    eligibility_digest: eligibility.eligibility_digest,
  };
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-physical-resource-graph-"));
  process.env.HOME = home;
  try {
    const result = fn(home);
    if (result && typeof result.then === "function") {
      return result.finally(() => {
        process.env.HOME = previousHome;
        fs.rmSync(home, { recursive: true, force: true });
      });
    }
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
    return result;
  } catch (error) {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
    throw error;
  }
}

function createClock(readMonotonicMs = () => 1_000) {
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const payload = {
    version: 1,
    clock_id: "physical-clock:graph-coordinator-test",
    monotonic_epoch_id: digest("graph-coordinator-monotonic-epoch"),
    mapping_generation: 1,
    reference_monotonic_ms: 1_000,
    reference_utc: "2026-07-18T08:00:02.000Z",
    max_uncertainty_ms: 10,
    not_before: "2026-07-18T07:55:00.000Z",
    expires_at: "2026-07-18T08:10:00.000Z",
    trust_root_epoch: 2,
    authority_epoch: 3,
    revocation_generation: 0,
    signer_key_id: "clock-key:graph-coordinator-test",
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
  return createPhysicalTrustedClockPort({
    port_id: "graph_coordinator_test_clock",
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: MAX_UNCERTAINTY_MS,
    read_monotonic_ms: readMonotonicMs,
    read_signed_mapping: () => mapping,
    resolve_current_trust: () => trust,
  });
}

function makeBundle() {
  return normalizePhysicalResourceBundle({
    version: 1,
    bundle_id: "graph-coordinator-reader",
    requirements: [{
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
    }],
    attempt_budget: 2,
    duration_ms: 30_000,
    reservation_ttl_ms: 45_000,
    cooldown_ms: 5_000,
    preemption_policy: "before_effect_only",
    fairness_class: "physical-test",
    batch_key: "physical:reader",
    setup_cost_units: 2,
  });
}

function contractInput(binding) {
  return {
    contract_id: "physical-graph-reader-contract",
    severity_floor: "high",
    invariants: [{
      id: "enrolled_reader",
      statement: "The exact enrolled reader and resource reservation remain current.",
    }],
    witnesses: [{
      id: "reader_inventory",
      kind: "tool_output_match",
      predicate: { tool: "bob_http_scan", match: { path: "$.status", equals: 200 } },
    }],
    production_paths: [{
      description: "Exercise the registered observation producer under broker custody.",
      tool_call_pattern: [{ tool: "bob_http_scan" }],
    }],
    physical_resource_bundle: binding,
  };
}

class MemoryCas {
  constructor(initial) {
    this.state = structuredClone(initial);
    this.before_next_commit = null;
    this.after_next_commit = null;
    this.after_read_at_revision = null;
    this.reads_by_revision = new Map();
    this.cas_calls = 0;
  }

  read() {
    const revision = this.state.revision;
    const ordinal = (this.reads_by_revision.get(revision) || 0) + 1;
    this.reads_by_revision.set(revision, ordinal);
    const value = structuredClone(this.state);
    const hook = this.after_read_at_revision;
    if (hook && hook.revision === revision && hook.ordinal === ordinal) {
      this.after_read_at_revision = null;
      hook.callback();
    }
    return value;
  }

  cas(command) {
    this.cas_calls += 1;
    if (this.state.revision !== command.expected_revision
        || this.state.state_digest !== command.expected_state_digest) return false;
    const before = this.before_next_commit;
    this.before_next_commit = null;
    if (before) before(command);
    this.state = structuredClone(command.next_state);
    const callback = this.after_next_commit;
    this.after_next_commit = null;
    if (callback) callback();
    return true;
  }
}

function buildFixture({
  mutateAfterReservation = null,
  mutateDuringFinalEligibility = null,
  readMonotonicMs = () => 1_000,
  inventoryExpiresAt = "2026-07-18T00:00:50.000Z",
} = {}) {
  const domain = "physical-resource-graph.example";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  const bundle = makeBundle();
  const proposalId = "reserved-reader";
  const nodeId = `${TASK_GRAPH_NODE_ID_PREFIX}H-${proposalId}`;
  appendHypothesisProposal({
    target_domain: domain,
    ts: "2026-07-18T00:00:00.000Z",
    hypothesis_statement: "The authorized reader can inventory the enrolled fixture.",
    surface_refs: ["surface:physical-reader"],
    proposal_id: proposalId,
  });
  materializeTaskGraph(domain, { write: true });
  const attached = appendContract({
    target_domain: domain,
    node_id: nodeId,
    contract: contractInput(bindPhysicalResourceBundle(bundle, "resource-bundle:graph-reader")),
    ts: "2026-07-18T00:00:01.000Z",
  });
  const document = materializeTaskGraph(domain, { write: false }).document;
  const graphHash = document.hashes.graph_hash;
  const nucleusHash = readVerifiedSessionNucleus(domain).nucleus_hash;
  const request = (label) => normalizePhysicalReservationRequest({
    version: 1,
    reservation_request_id: `reservation-request:${label}`,
    node_id: nodeId,
    contract_hash: attached.contract.contract_hash,
    source_graph_hash: graphHash,
    session_nucleus_hash: nucleusHash,
    experiment_ref: "experiment:graph-reader",
    attempt_ref: `attempt:${label}`,
    owner_principal_ref: "principal:broker",
    execution_principal_ref: "principal:worker",
    resource_bundle_digest: bundle.resource_bundle_digest,
    requested_at: "2026-07-18T00:00:00.000Z",
    effect_not_before: "2026-07-18T00:00:01.000Z",
    effect_deadline: "2026-07-18T00:00:31.000Z",
  });
  const inventory = normalizePhysicalResourceInventory({
    version: 1,
    broker_ref: "broker:graph-test",
    broker_epoch: 1,
    inventory_generation: 1,
    captured_at: "2026-07-18T00:00:01.000Z",
    valid_from: "2026-07-18T00:00:00.000Z",
    expires_at: inventoryExpiresAt,
    session_nucleus_hash: nucleusHash,
    source_graph_hash: graphHash,
    resources: [{
      resource_kind: "instrument",
      resource_ref: "instrument:ultra-a",
      state_epoch_digest: digest("ultra-state"),
      availability: "available",
      total_capacity_units: 1,
      available_capacity_units: 1,
      exclusive_available: true,
      fencing_generation: 4,
      setup_cost_units: 2,
      eligible_requirement_digests: [hashCanonicalJson(bundle.requirements[0])],
      switchable_mode_refs: ["mode:reader"],
      switchable_workspace_refs: ["workspace:slot-a"],
      current_mode_ref: "mode:reader",
      current_workspace_ref: "workspace:slot-a",
    }],
  });
  const initial = createInitialPhysicalResourceReservationState({
    state_domain_digest: digest("graph-resource-state-domain"),
    inventory,
  });
  const memory = new MemoryCas(initial);
  const reservationFixture = createPhysicalReservationFixture({
    resource_bundle: bundle,
    reservation_request: request("bootstrap"),
    resource_inventory: inventory,
    state_domain_digest: digest("graph-resource-state-domain"),
    memory,
    read_monotonic_ms: readMonotonicMs,
    reserve: false,
  });
  if (mutateAfterReservation) memory.after_next_commit = mutateAfterReservation;
  if (mutateDuringFinalEligibility) {
    memory.after_read_at_revision = {
      revision: memory.state.revision + 1,
      ordinal: 3,
      callback: mutateDuringFinalEligibility,
    };
  }
  return {
    authority: reservationFixture.authority,
    bundle,
    document,
    domain,
    graphHash,
    memory,
    nodeId,
    nucleusHash,
    request,
  };
}

function buildProviderTransferFixture(fixture, request, prepared, options = {}) {
  const record = fixture.memory.state.reservations.find(
    (entry) => entry.receipt.reservation_ref === prepared.reservation.reservation_ref,
  );
  const allocation = record.receipt.allocations[0];
  const provider = normalizePhysicalProviderBinding({
    version: 1,
    provider_id: "deterministic_graph_provider",
    provider_descriptor_digest: digest("graph-provider-descriptor"),
    semantic_manifest_digest: digest("graph-provider-manifest"),
    device_ref: "device:graph-provider-reader",
    device_identity_digest: digest("graph-provider-device"),
    custody_ref: "custody:graph-provider-worker",
    custody_identity_digest: digest("graph-provider-custody"),
    custody_epoch: 1,
  });
  const { provider_binding_digest: ignoredProviderBindingDigest, ...providerInput } = provider;
  const compiledCommandCapabilityDigest = digest("graph-provider-parameters");
  const executionLineage = {
    version: 1,
    compiler_id: "closed_graph_provider_compiler_v1",
    compiler_manifest_digest: digest("graph-provider-compiler-manifest"),
    compiler_registry_digest: digest("graph-provider-compiler-registry"),
    compiled_command_id: "compiled-command:graph-observe-1",
    compiled_command_capability_digest: compiledCommandCapabilityDigest,
    compiled_operation_digest: digest("graph-provider-operation"),
    provider_command_ref: "command:graph-observe",
    command_input_ref: "command-input:graph-observe",
    command_input_digest: compiledCommandCapabilityDigest,
    maximum_response_bytes: 64,
    vault_reservation_handle: `vault-reservation:v1:${"G".repeat(43)}`,
    vault_reservation_digest: digest("graph-provider-vault-reservation"),
    vault_ingest_capability_digest: digest("graph-provider-vault-ingest"),
    vault_byte_limit: 64,
    worker_bundle_digest: digest("graph-provider-worker-bundle"),
    worker_launch_profile_digest: digest("graph-provider-worker-launch-profile"),
    worker_fence_plan_digest: digest("graph-provider-worker-fence"),
    transport_profile_digest: digest("graph-provider-transport-profile"),
    durable_exchange_plan_digest: digest("graph-provider-durable-exchange-plan"),
    terminal_receipt_recipient_digest: digest("graph-provider-terminal-recipient"),
    safety_supervisor_plan_digest: digest("graph-provider-safety-supervisor-plan"),
  };
  const authorityAssertion = {
    session_nucleus_hash: request.session_nucleus_hash,
    signed_grant_digest: digest("graph-provider-signed-grant"),
    execution_request_digest: digest("graph-provider-execution-request"),
    experiment_plan_hash: digest("graph-provider-experiment-plan"),
    execution_lineage_digest: hashCanonicalJson(executionLineage),
    execution_principal_id: request.execution_principal_ref,
    attempt_ref: request.attempt_ref,
    instrument_ref: allocation.resource_ref,
    lease_id: "graph-provider-lease-1",
    fencing_token: "graph-provider-static-grant-fence-1",
    fencing_generation: 1,
    operation_id: "graph.provider.observe.v1",
    provider_id: provider.provider_id,
    provider_descriptor_digest: provider.provider_descriptor_digest,
    effect_not_before: request.effect_not_before,
    effect_deadline: request.effect_deadline,
    session_id: "graph-provider-session-1",
    node_id: request.node_id,
    contract_hash: request.contract_hash,
    prep_token_hash: prepared.preparation.prep_token,
    dispatch_event_id: prepared.preparation.event_id,
    graph_context_hash: prepared.preparation.graph_context_hash,
    resource_bundle_digest: request.resource_bundle_digest,
    operation_digest: digest("graph-provider-operation"),
    parameter_digest: digest("graph-provider-parameters"),
    requested_effects_digest: digest("graph-provider-requested-effects"),
    physical_scope_axis_digest: digest("graph-provider-physical-scope-axis"),
    physical_scope_policy_id: "graph_provider_physical_scope_policy",
    physical_scope_policy_digest: digest("graph-provider-physical-scope-policy"),
    physical_scope_projection_digest: digest("graph-provider-physical-scope-projection"),
    authority_epoch: 1,
    revocation_generation: 0,
    authority_resolution_digest: digest("graph-provider-authority-resolution"),
    caller_role_id: "evaluator-physical-agent",
    requester_principal_id: "principal:graph-provider-requester-1",
    ipc_peer_principal_id: "principal:graph-provider-ipc-peer-1",
    capability_pack_id: "physical",
    capability_pack_version: "1",
    capability_pack_digest: digest("graph-provider-capability-pack"),
    technique_cell_id: "physical-cell:graph-provider-cell-1",
    inventory_observation_ref: "inventory-observation:graph-provider-inventory-1",
    inventory_observation_digest: digest("graph-provider-inventory-observation"),
    assurance_profile_id: "graph_provider_assurance_profile",
    assurance_claims_digest: digest("graph-provider-assurance-claims"),
    provider_manifest_digest: digest("graph-provider-manifest"),
    availability_variant_id: "graph-provider-availability-variant",
    availability_variant_digest: digest("graph-provider-availability-variant"),
    authorized_transition_set_digest: digest("graph-provider-authorized-transition-set"),
    workspace_snapshot_ref: "workspace-snapshot:graph-provider-workspace-1",
    workspace_snapshot_digest: digest("graph-provider-workspace-snapshot"),
    observer_plan_digest: digest("graph-provider-observer-plan"),
    control_plan_digest: digest("graph-provider-control-plan"),
    cleanup_plan_digest: digest("graph-provider-cleanup-plan"),
    ...Object.fromEntries(
      Object.entries(executionLineage).filter(([field]) => field !== "version"),
    ),
    ...options.authority_overrides,
  };
  const authorityPort = createDeterministicMockDispatchAuthorityPort({
    port_id: "deterministic_graph_provider_authority",
    session_nucleus_hash: authorityAssertion.session_nucleus_hash,
    provider_id: authorityAssertion.provider_id,
    provider_descriptor_digest: authorityAssertion.provider_descriptor_digest,
    execution_principal_id: authorityAssertion.execution_principal_id,
    test_only_execution_assertion: authorityAssertion,
  });
  const requirement = fixture.bundle.requirements.find((entry) => entry.alias === allocation.alias);
  const authorizationPort = createPhysicalProviderCommandAuthorizationPort({
    port_id: "graph_provider_command_authority",
    semantic_authority_digest: options.semantic_authority_digest
      || authorityAssertion.execution_request_digest,
    authorization_epoch: 1,
    provider_binding_digest: provider.provider_binding_digest,
    reservation_binding: {
      reservation_request_digest: request.reservation_request_digest,
      node_id: request.node_id,
      contract_hash: request.contract_hash,
      source_graph_hash: request.source_graph_hash,
      session_nucleus_hash: request.session_nucleus_hash,
      resource_bundle_digest: request.resource_bundle_digest,
      allocation_digest: hashCanonicalJson(record.receipt.allocations),
    },
    resource_bundle: fixture.bundle,
    receipt_allocations: record.receipt.allocations,
    authorizations: [
      ["command", "command:graph-observe"],
      ["cleanup", "command:graph-cleanup"],
      ["fence", "command:graph-fence"],
      ["quarantine", "command:graph-quarantine"],
    ].map(([command_kind, command_ref]) => ({
      command_kind,
      command_ref,
      operation_id: authorityAssertion.operation_id,
      operation_digest: authorityAssertion.operation_digest,
      semantic_owner_ref: `semantic-owner:graph-${command_kind}`,
      semantic_owner_digest: digest(`graph-${command_kind}-semantics`),
      requested_effect_digest: requirement.requested_effect_digests[0],
      requested_effects_digest: authorityAssertion.requested_effects_digest,
      resource_alias: allocation.alias,
      resource_ref: allocation.resource_ref,
      resource_requirement_digest: hashCanonicalJson(requirement),
    })),
  });
  const calls = [];
  const observationCalls = [];
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
    completion_verification_port: createTestCompletionVerificationPort("graph_coordinator"),
    observe_binding: () => {
      observationCalls.push("observe-binding");
      return structuredClone(providerInput);
    },
    commands: [definition("command:graph-observe")],
    compensation: {
      cleanup: definition("command:graph-cleanup"),
      fence: definition("command:graph-fence"),
      quarantine: definition("command:graph-quarantine"),
    },
  });
  return {
    authorityPort,
    calls,
    commandInput: Object.freeze({
      command_input_ref: executionLineage.command_input_ref,
      command_input_digest: executionLineage.command_input_digest,
    }),
    observationCalls,
    registry,
  };
}

function exactCancellationFailureReason(prepared) {
  const dispatch = prepared.preparation.physical_resource_dispatch;
  return {
    reason: "physical_reservation_cancelled",
    reservation_ref: dispatch.reservation_ref,
    receipt_digest: dispatch.receipt_digest,
    allocation_plan_digest: dispatch.allocation_plan_digest,
    eligibility_digest: dispatch.eligibility_digest,
    resource_bundle_digest: dispatch.resource_bundle_digest,
    source_graph_hash: dispatch.source_graph_hash,
    session_nucleus_hash: dispatch.session_nucleus_hash,
    prep_token_hash: prepared.preparation.prep_token,
  };
}

test("public prepare-node and JSON/lookalike capabilities cannot bypass physical reservation", () => {
  withTempHome(() => {
    const fixture = buildFixture();
    const transitionsBefore = readNodeTransitions(fixture.domain).length;
    const realPort = createPhysicalResourceReservationEligibilityPort(fixture.authority);
    const lookalike = Object.freeze({ ...realPort });
    assert.equal(Object.keys(prepareNodeModule).includes("preparePhysicalResourceNode"), false);

    for (const args of [
      { target_domain: fixture.domain, node_id: fixture.nodeId },
      {
        target_domain: fixture.domain,
        node_id: fixture.nodeId,
        physical_resource_eligibility_port: lookalike,
      },
    ]) {
      assert.throws(
        () => TOOL_HANDLERS.bob_prepare_node(args),
        (error) => error.code === "physical_resource_reservation_required",
      );
    }
    assert.throws(
      () => preparePhysicalResourceNode(
        { target_domain: fixture.domain, node_id: fixture.nodeId },
        lookalike,
        {
          source_graph_hash: fixture.graphHash,
          session_nucleus_hash: fixture.nucleusHash,
          resource_bundle_digest: fixture.bundle.resource_bundle_digest,
          reservation_ref: "reservation:v1:lookalike",
          receipt_digest: digest("lookalike-receipt"),
          allocation_plan_digest: digest("lookalike-plan"),
          eligibility_digest: digest("lookalike-eligibility"),
        },
      ),
      (error) => error.code === "physical_resource_eligibility_capability_untrusted",
    );
    assert.equal(readNodeTransitions(fixture.domain).length, transitionsBefore);
    assert.equal(
      materializeTaskGraph(fixture.domain, { write: false }).document.nodes
        .find((entry) => entry.node_id === fixture.nodeId).state,
      "contracted",
    );
  });
});

test("exact broker capability refuses eligibility-digest drift before either prepare transition", () => {
  withTempHome(() => {
    const fixture = buildFixture();
    const request = fixture.request("eligibility-binding-drift");
    const held = reservePhysicalResources(fixture.authority, request);
    const port = createPhysicalResourceReservationEligibilityPort(fixture.authority);
    const eligibility = resolveHeldPhysicalResourceForNode(port, {
      node_id: request.node_id,
      contract_hash: request.contract_hash,
      source_graph_hash: request.source_graph_hash,
      session_nucleus_hash: request.session_nucleus_hash,
      resource_bundle_digest: request.resource_bundle_digest,
    });
    const wrong = {
      ...dispatchBinding(eligibility),
      eligibility_digest: digest("substituted-eligibility"),
    };
    const transitionsBefore = readNodeTransitions(fixture.domain).length;
    assert.throws(
      () => preparePhysicalResourceNode(
        { target_domain: fixture.domain, node_id: fixture.nodeId },
        port,
        wrong,
      ),
      (error) => error.code === "physical_resource_reservation_drift",
    );
    assert.equal(readNodeTransitions(fixture.domain).length, transitionsBefore);
    assert.equal(
      materializeTaskGraph(fixture.domain, { write: false }).document.nodes
        .find((entry) => entry.node_id === fixture.nodeId).state,
      "contracted",
    );
    cancelPhysicalResourceReservation(fixture.authority, held.credential);
  });
});

test("physical TaskGraph selection requires the exact live broker-held reservation", () => {
  withTempHome(() => {
    const fixture = buildFixture();
    const before = selectNextExecutableNodes(fixture.domain, {}, 1, {
      document: fixture.document,
    });
    assert.equal(before.selected.length, 0);
    assert.equal(before.skipped[0].physical_reservation_state, "not_held");

    const request = fixture.request("selector");
    const held = reservePhysicalResources(fixture.authority, request);
    const port = createPhysicalResourceReservationEligibilityPort(fixture.authority);
    const selected = selectNextExecutableNodes(fixture.domain, {}, 1, {
      document: fixture.document,
      physicalResourceReservationEligibilityPort: port,
      sessionNucleusHash: fixture.nucleusHash,
    });
    assert.equal(selected.selected.length, 1);
    assert.equal(selected.selected[0].node_id, fixture.nodeId);
    assert.equal(selected.selected[0].contract_hash, request.contract_hash);
    assert.equal(selected.selected[0].physical_reservation_state, "held");
    assert.match(selected.selected[0].physical_reservation_eligibility_digest, /^[a-f0-9]{64}$/u);
    assert.equal(JSON.stringify(selected).includes("raw_fence"), false);
    cancelPhysicalResourceReservation(fixture.authority, held.credential);
  });
});

test("the private coordinator reserves, revalidates, prepares, and retains no public fence authority", () => {
  withTempHome(() => {
    const fixture = buildFixture();
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const request = fixture.request("prepare");
    const result = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: request,
      actor: "physical-graph-coordinator-test",
    });
    assert.equal(result.preparation.node_id, fixture.nodeId);
    assert.equal(result.preparation.contract_hash, request.contract_hash);
    assert.equal(result.reservation.lifecycle_state, "prepared");
    assert.equal(result.reservation_handle.node_id, fixture.nodeId);
    assert.doesNotMatch(JSON.stringify(result), /raw_fence|fencing_token|credential/u);
    assert.deepEqual(
      result.preparation.physical_resource_dispatch,
      result.preparation.brief.physical_resource_dispatch,
    );
    assert.deepEqual(result.preparation.physical_resource_dispatch, {
      source_graph_hash: request.source_graph_hash,
      session_nucleus_hash: request.session_nucleus_hash,
      resource_bundle_digest: request.resource_bundle_digest,
      reservation_ref: result.reservation.reservation_ref,
      receipt_digest: result.reservation.receipt_digest,
      allocation_plan_digest: result.reservation.allocation_plan_digest,
      eligibility_digest: result.reservation.eligibility_digest,
    });
    const expectedPrepToken = crypto.createHash("sha256").update([
      result.preparation.node_id,
      result.preparation.contract_hash,
      result.preparation.brief_hash,
      result.preparation.materialized_at,
      result.preparation.graph_context_hash,
      ...Object.values(result.preparation.physical_resource_dispatch),
    ].join("|")).digest("hex");
    assert.equal(result.preparation.prep_token, expectedPrepToken);
    const dispatchedEvent = readNodeTransitions(fixture.domain)
      .findLast((event) => event.payload.to_state === "dispatched");
    assert.deepEqual(
      dispatchedEvent.payload.physical_resource_dispatch,
      result.preparation.physical_resource_dispatch,
    );
    assert.equal(dispatchedEvent.payload.prep_token_hash, result.preparation.prep_token);
    const dispatchedNode = materializeTaskGraph(fixture.domain, { write: false }).document.nodes
      .find((entry) => entry.node_id === fixture.nodeId);
    assert.deepEqual(
      dispatchedNode.physical_resource_dispatch,
      result.preparation.physical_resource_dispatch,
    );
    assert.equal(
      dispatchedNode.state,
      "dispatched",
    );

    const cancelled = cancelPreparedPhysicalGraphReservation(
      coordinator,
      result.reservation_handle,
    );
    assert.equal(cancelled.lifecycle_state, "cancelled");
    assert.equal(projectPhysicalResourceGraphHandle(result.reservation_handle).lifecycle_state, "cancelled");
    const cancelledNode = materializeTaskGraph(fixture.domain, { write: false }).document.nodes
      .find((entry) => entry.node_id === fixture.nodeId);
    assert.equal(cancelledNode.state, "failed");
    const cancellationEvent = readNodeTransitions(fixture.domain)
      .findLast((event) => event.payload.to_state === "failed");
    assert.deepEqual(cancellationEvent.payload.failure_reason, {
      reason: "physical_reservation_cancelled",
      reservation_ref: result.preparation.physical_resource_dispatch.reservation_ref,
      receipt_digest: result.preparation.physical_resource_dispatch.receipt_digest,
      allocation_plan_digest: result.preparation.physical_resource_dispatch.allocation_plan_digest,
      eligibility_digest: result.preparation.physical_resource_dispatch.eligibility_digest,
      resource_bundle_digest: result.preparation.physical_resource_dispatch.resource_bundle_digest,
      source_graph_hash: result.preparation.physical_resource_dispatch.source_graph_hash,
      session_nucleus_hash: result.preparation.physical_resource_dispatch.session_nucleus_hash,
      prep_token_hash: result.preparation.prep_token,
    });
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 1);
    assert.throws(
      () => cancelPreparedPhysicalGraphReservation(coordinator, result.reservation_handle),
      /no longer cancellable/,
    );
  });
});

test("failed provider transfer retains the prepared credential for exact cancellation", () => {
  withTempHome(() => {
    const fixture = buildFixture();
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const request = fixture.request("failed-provider-transfer");
    const prepared = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: request,
    });
    const seam = buildProviderTransferFixture(fixture, request, prepared, {
      semantic_authority_digest: digest("wrong-signed-execution-request"),
    });
    assert.throws(
      () => transferPreparedPhysicalGraphReservationToProviderBridge(
        coordinator,
        prepared.reservation_handle,
        { dispatch_authority_port: seam.authorityPort, command_registry: seam.registry },
      ),
      (error) => error.code === "physical_dispatch_semantic_authority_drift",
    );
    assert.equal(projectPhysicalResourceGraphHandle(
      prepared.reservation_handle,
    ).lifecycle_state, "prepared");
    assert.equal(cancelPreparedPhysicalGraphReservation(
      coordinator,
      prepared.reservation_handle,
    ).lifecycle_state, "cancelled");
  });
});

test("successful provider transfer is one-shot and privately cancellable before effect", async () => {
  await withTempHome(async () => {
    const fixture = buildFixture();
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const request = fixture.request("successful-provider-transfer");
    const prepared = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: request,
    });
    const seam = buildProviderTransferFixture(fixture, request, prepared);
    const transferred = transferPreparedPhysicalGraphReservationToProviderBridge(
      coordinator,
      prepared.reservation_handle,
      { dispatch_authority_port: seam.authorityPort, command_registry: seam.registry },
    );
    assert.equal(transferred.reservation.lifecycle_state, "transferred");
    assert.doesNotMatch(
      JSON.stringify(transferred),
      /credential|fencing_token|graph-provider-static-grant-fence|cancellation_capability/u,
    );
    assert.throws(
      () => transferPreparedPhysicalGraphReservationToProviderBridge(
        coordinator,
        prepared.reservation_handle,
        { dispatch_authority_port: seam.authorityPort, command_registry: seam.registry },
      ),
      /no longer transferable/,
    );
    const command = resolvePhysicalProviderCommand(seam.registry, "command:graph-observe");
    const capability = transferred.dispatch_bridge.createDispatchCapability(command);
    const commandRequest = createPhysicalProviderCommandRequest(capability, seam.commandInput);
    let graphInvalidatedBeforeBrokerClose = false;
    fixture.memory.after_next_commit = () => {
      graphInvalidatedBeforeBrokerClose = materializeTaskGraph(
        fixture.domain,
        { write: false },
      ).document.nodes.find((entry) => entry.node_id === fixture.nodeId).state === "failed";
    };
    const cancelled = cancelPreparedPhysicalGraphReservation(
      coordinator,
      prepared.reservation_handle,
    );
    assert.equal(cancelled.lifecycle_state, "cancelled");
    assert.equal(graphInvalidatedBeforeBrokerClose, true);
    assert.equal(transferred.dispatch_bridge.snapshot().phase, "cancelled");
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 1);
    await assert.rejects(
      () => transferred.dispatch_bridge.dispatch(capability, commandRequest),
      (error) => error.code === "physical_dispatch_terminal",
    );
    assert.deepEqual(seam.calls, []);
    assert.throws(
      () => cancelPreparedPhysicalGraphReservation(coordinator, prepared.reservation_handle),
      /no longer cancellable/,
    );
    assert.equal(
      transferred.dispatch_bridge.readiness().durable_active_instrument_lease_fence_assurance,
      "durable_active_instrument_lease_fence_not_integrated",
    );
  });
});

test("transferred cancellation is forbidden after command permit consumption and effect start", async () => {
  await withTempHome(async () => {
    const fixture = buildFixture();
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const request = fixture.request("transferred-effect-started");
    const prepared = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: request,
    });
    const seam = buildProviderTransferFixture(fixture, request, prepared);
    const transferred = transferPreparedPhysicalGraphReservationToProviderBridge(
      coordinator,
      prepared.reservation_handle,
      { dispatch_authority_port: seam.authorityPort, command_registry: seam.registry },
    );
    const command = resolvePhysicalProviderCommand(seam.registry, "command:graph-observe");
    const capability = transferred.dispatch_bridge.createDispatchCapability(command);
    const commandRequest = createPhysicalProviderCommandRequest(capability, seam.commandInput);
    assert.equal((await transferred.dispatch_bridge.dispatch(capability, commandRequest)).kind, "confirmed");
    assert.throws(
      () => cancelPreparedPhysicalGraphReservation(coordinator, prepared.reservation_handle),
      (error) => error.code === "physical_dispatch_cancellation_after_effect",
    );
    assert.equal(
      materializeTaskGraph(fixture.domain, { write: false }).document.nodes
        .find((entry) => entry.node_id === fixture.nodeId).state,
      "dispatched",
    );
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 0);
    assert.deepEqual(seam.calls, ["command:graph-observe"]);
  });
});

test("transferred dispatch revalidates the live TaskGraph head on the happy provider path", async () => {
  await withTempHome(async () => {
    const fixture = buildFixture();
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const request = fixture.request("transferred-live-head-happy");
    const prepared = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: request,
    });
    const seam = buildProviderTransferFixture(fixture, request, prepared);
    const transferred = transferPreparedPhysicalGraphReservationToProviderBridge(
      coordinator,
      prepared.reservation_handle,
      { dispatch_authority_port: seam.authorityPort, command_registry: seam.registry },
    );
    const command = resolvePhysicalProviderCommand(seam.registry, "command:graph-observe");
    const capability = transferred.dispatch_bridge.createDispatchCapability(command);
    const commandRequest = createPhysicalProviderCommandRequest(capability, seam.commandInput);

    assert.equal((await transferred.dispatch_bridge.dispatch(
      capability,
      commandRequest,
    )).kind, "confirmed");
    assert.deepEqual(seam.observationCalls, ["observe-binding"]);
    assert.deepEqual(seam.calls, ["command:graph-observe"]);
    assert.equal(
      transferred.dispatch_bridge.readiness().task_graph_dispatch_head_assurance,
      "cooperative_same_process_session_lock_revalidated_before_provider_entry_v1",
    );
  });
});

test("transfer then generic reaper then dispatch fails before provider observation", async () => {
  await withTempHome(async () => {
    const fixture = buildFixture();
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const request = fixture.request("transferred-generic-reaper-race");
    const prepared = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: request,
    });
    const seam = buildProviderTransferFixture(fixture, request, prepared);
    const transferred = transferPreparedPhysicalGraphReservationToProviderBridge(
      coordinator,
      prepared.reservation_handle,
      { dispatch_authority_port: seam.authorityPort, command_registry: seam.registry },
    );
    const dispatched = readNodeTransitions(fixture.domain)
      .findLast((event) => event.payload.to_state === "dispatched");
    const expired = expireStaleDispatchedNodes(
      fixture.domain,
      materializeTaskGraph(fixture.domain, { write: false }).document,
      { now: new Date(Date.parse(dispatched.ts) + (31 * 60 * 1_000)) },
    );
    assert.equal(expired.length, 1);
    assert.equal(expired[0].payload.failure_reason.reason, "dispatch_timeout");

    const command = resolvePhysicalProviderCommand(seam.registry, "command:graph-observe");
    const capability = transferred.dispatch_bridge.createDispatchCapability(command);
    const commandRequest = createPhysicalProviderCommandRequest(capability, seam.commandInput);
    await assert.rejects(
      () => transferred.dispatch_bridge.dispatch(capability, commandRequest),
      (error) => error.code === "physical_task_graph_dispatch_head_stale",
    );
    assert.equal(transferred.dispatch_bridge.snapshot().phase, "held");
    assert.deepEqual(seam.observationCalls, []);
    assert.deepEqual(seam.calls, []);

    const closed = cancelPreparedPhysicalGraphReservation(
      coordinator,
      prepared.reservation_handle,
    );
    assert.equal(closed.lifecycle_state, "cancelled");
    assert.equal(transferred.dispatch_bridge.snapshot().phase, "cancelled");
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 1);
  });
});

test("transferred cancellation remains available after a definitive pre-start expiry", async () => {
  await withTempHome(async () => {
    let monotonicMs = 1_000;
    const fixture = buildFixture({ readMonotonicMs: () => monotonicMs });
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const request = fixture.request("transferred-start-expired");
    const prepared = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: request,
    });
    const seam = buildProviderTransferFixture(fixture, request, prepared);
    const transferred = transferPreparedPhysicalGraphReservationToProviderBridge(
      coordinator,
      prepared.reservation_handle,
      { dispatch_authority_port: seam.authorityPort, command_registry: seam.registry },
    );
    const command = resolvePhysicalProviderCommand(seam.registry, "command:graph-observe");
    const capability = transferred.dispatch_bridge.createDispatchCapability(command);
    const commandRequest = createPhysicalProviderCommandRequest(capability, seam.commandInput);
    monotonicMs = 40_000;

    await assert.rejects(
      () => transferred.dispatch_bridge.dispatch(capability, commandRequest),
      (error) => ["reservation_effect_window_expired", "resource_reservation_expired"].includes(
        error.code,
      ),
    );
    assert.equal(transferred.dispatch_bridge.snapshot().phase, "held");
    const closed = cancelPreparedPhysicalGraphReservation(
      coordinator,
      prepared.reservation_handle,
    );
    assert.equal(closed.lifecycle_state, "expired");
    assert.equal(transferred.dispatch_bridge.snapshot().phase, "expired");
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 1);
    assert.deepEqual(seam.calls, []);
  });
});

test("transferred cancellation resumes from one exact existing TaskGraph tombstone", () => {
  withTempHome(() => {
    const fixture = buildFixture();
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const request = fixture.request("transferred-existing-tombstone");
    const prepared = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: request,
    });
    const seam = buildProviderTransferFixture(fixture, request, prepared);
    transferPreparedPhysicalGraphReservationToProviderBridge(
      coordinator,
      prepared.reservation_handle,
      { dispatch_authority_port: seam.authorityPort, command_registry: seam.registry },
    );
    appendNodeTransition({
      target_domain: fixture.domain,
      node_id: fixture.nodeId,
      from_state: "dispatched",
      to_state: "failed",
      contract_hash: prepared.preparation.contract_hash,
      failure_reason: exactCancellationFailureReason(prepared),
      source: { tool: "test", reason: "simulate_exact_cancellation_retry" },
    });
    const failedCount = readNodeTransitions(fixture.domain)
      .filter((event) => event.payload.to_state === "failed").length;

    const closed = cancelPreparedPhysicalGraphReservation(
      coordinator,
      prepared.reservation_handle,
    );
    assert.equal(closed.lifecycle_state, "cancelled");
    assert.equal(readNodeTransitions(fixture.domain)
      .filter((event) => event.payload.to_state === "failed").length, failedCount);
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 1);
  });
});

test("transferred cancellation reconciles an exact lost broker acknowledgement", () => {
  withTempHome(() => {
    const fixture = buildFixture();
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const request = fixture.request("transferred-lost-close-response");
    const prepared = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: request,
    });
    const seam = buildProviderTransferFixture(fixture, request, prepared);
    transferPreparedPhysicalGraphReservationToProviderBridge(
      coordinator,
      prepared.reservation_handle,
      { dispatch_authority_port: seam.authorityPort, command_registry: seam.registry },
    );
    fixture.memory.after_next_commit = () => {
      throw new Error("simulated lost broker close acknowledgement");
    };

    const closed = cancelPreparedPhysicalGraphReservation(
      coordinator,
      prepared.reservation_handle,
    );
    assert.equal(closed.lifecycle_state, "cancelled");
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 1);
  });
});

test("ambiguous transferred cancellation fails closed and retry performs no second close", () => {
  withTempHome(() => {
    const fixture = buildFixture();
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const request = fixture.request("transferred-ambiguous-close");
    const prepared = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: request,
    });
    const seam = buildProviderTransferFixture(fixture, request, prepared);
    const transferred = transferPreparedPhysicalGraphReservationToProviderBridge(
      coordinator,
      prepared.reservation_handle,
      { dispatch_authority_port: seam.authorityPort, command_registry: seam.registry },
    );
    fixture.memory.before_next_commit = () => {
      throw new Error("simulated ambiguous broker close before commit");
    };
    const casBefore = fixture.memory.cas_calls;

    assert.throws(
      () => cancelPreparedPhysicalGraphReservation(coordinator, prepared.reservation_handle),
      (error) => error.code === "physical_resource_release_uncertain",
    );
    assert.equal(projectPhysicalResourceGraphHandle(
      prepared.reservation_handle,
    ).lifecycle_state, "transferred_release_uncertain");
    assert.equal(transferred.dispatch_bridge.snapshot().phase, "ambiguous");
    assert.equal(fixture.memory.state.inventory.resources[0].available_capacity_units, 0);
    assert.equal(
      materializeTaskGraph(fixture.domain, { write: false }).document.nodes
        .find((entry) => entry.node_id === fixture.nodeId).state,
      "failed",
    );
    const casAfterAmbiguity = fixture.memory.cas_calls;
    assert.equal(casAfterAmbiguity, casBefore + 1);
    assert.throws(
      () => cancelPreparedPhysicalGraphReservation(coordinator, prepared.reservation_handle),
      (error) => error.code === "physical_resource_release_uncertain",
    );
    assert.equal(fixture.memory.cas_calls, casAfterAmbiguity);
    assert.deepEqual(seam.calls, []);
  });
});

test("transferred cancellation explicitly expires a still-not-started reservation", () => {
  withTempHome(() => {
    let monotonicMs = 1_000;
    const fixture = buildFixture({ readMonotonicMs: () => monotonicMs });
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const request = fixture.request("transferred-expired-before-effect");
    const prepared = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: request,
    });
    const seam = buildProviderTransferFixture(fixture, request, prepared);
    const transferred = transferPreparedPhysicalGraphReservationToProviderBridge(
      coordinator,
      prepared.reservation_handle,
      { dispatch_authority_port: seam.authorityPort, command_registry: seam.registry },
    );
    monotonicMs = 40_000;

    const closed = cancelPreparedPhysicalGraphReservation(
      coordinator,
      prepared.reservation_handle,
    );
    assert.equal(closed.lifecycle_state, "expired");
    assert.equal(transferred.dispatch_bridge.snapshot().phase, "expired");
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 1);
    assert.deepEqual(seam.calls, []);
  });
});

test("cancellation after the effect deadline explicitly expires the reservation and tombstones dispatch", () => {
  withTempHome(() => {
    let monotonicMs = 1_000;
    const fixture = buildFixture({ readMonotonicMs: () => monotonicMs });
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const result = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: fixture.request("expire-after-prepare"),
    });
    monotonicMs = 40_000;
    const closed = cancelPreparedPhysicalGraphReservation(
      coordinator,
      result.reservation_handle,
    );
    assert.equal(closed.lifecycle_state, "expired");
    assert.equal(
      materializeTaskGraph(fixture.domain, { write: false }).document.nodes
        .find((entry) => entry.node_id === fixture.nodeId).state,
      "failed",
    );
    assert.equal(
      readNodeTransitions(fixture.domain)
        .findLast((event) => event.payload.to_state === "failed")
        .payload.failure_reason.reason,
      "physical_reservation_cancelled",
    );
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 1);
  });
});

test("expired inventory stops effects but cannot prevent before-effect cancellation", () => {
  withTempHome(() => {
    let monotonicMs = 1_000;
    const fixture = buildFixture({
      readMonotonicMs: () => monotonicMs,
      inventoryExpiresAt: "2026-07-18T00:00:10.000Z",
    });
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const result = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: fixture.request("cancel-after-inventory-expiry"),
    });

    monotonicMs = 10_000;
    const closed = cancelPreparedPhysicalGraphReservation(
      coordinator,
      result.reservation_handle,
    );
    assert.equal(closed.lifecycle_state, "cancelled");
    assert.equal(
      materializeTaskGraph(fixture.domain, { write: false }).document.nodes
        .find((entry) => entry.node_id === fixture.nodeId).state,
      "failed",
    );
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 1);
  });
});

test("generic dispatch timeout retains exact physical proof so broker capacity can close", () => {
  withTempHome(() => {
    const fixture = buildFixture();
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const result = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: fixture.request("cancel-after-dispatch-timeout"),
    });
    const dispatched = readNodeTransitions(fixture.domain)
      .findLast((event) => event.payload.to_state === "dispatched");
    const document = materializeTaskGraph(fixture.domain, { write: false }).document;
    const expired = expireStaleDispatchedNodes(fixture.domain, document, {
      now: new Date(Date.parse(dispatched.ts) + (31 * 60 * 1_000)),
    });
    assert.equal(expired.length, 1);
    assert.equal(expired[0].payload.failure_reason.reason, "dispatch_timeout");
    assert.equal(
      expired[0].payload.failure_reason.reservation_ref,
      result.reservation.reservation_ref,
    );
    assert.equal(
      expired[0].payload.failure_reason.prep_token_hash,
      result.preparation.prep_token,
    );

    const closed = cancelPreparedPhysicalGraphReservation(
      coordinator,
      result.reservation_handle,
    );
    assert.equal(closed.lifecycle_state, "cancelled");
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 1);
  });
});

test("an exact historical timeout tombstone still permits capacity close after re-contract", () => {
  withTempHome(() => {
    const fixture = buildFixture();
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const result = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: fixture.request("cancel-after-recontract"),
    });
    const dispatched = readNodeTransitions(fixture.domain)
      .findLast((event) => event.payload.to_state === "dispatched");
    expireStaleDispatchedNodes(
      fixture.domain,
      materializeTaskGraph(fixture.domain, { write: false }).document,
      { now: new Date(Date.parse(dispatched.ts) + (31 * 60 * 1_000)) },
    );
    appendNodeTransition({
      target_domain: fixture.domain,
      node_id: fixture.nodeId,
      from_state: "failed",
      to_state: "contracted",
      contract_hash: result.preparation.contract_hash,
      source: { tool: "test", reason: "operator_recontract" },
    });
    appendNodeTransition({
      target_domain: fixture.domain,
      node_id: fixture.nodeId,
      from_state: "contracted",
      to_state: "ready",
      contract_hash: result.preparation.contract_hash,
      source: { tool: "test", reason: "operator_recontract_ready" },
    });

    const closed = cancelPreparedPhysicalGraphReservation(
      coordinator,
      result.reservation_handle,
    );
    assert.equal(closed.lifecycle_state, "cancelled");
    assert.equal(
      materializeTaskGraph(fixture.domain, { write: false }).document.nodes
        .find((entry) => entry.node_id === fixture.nodeId).state,
      "ready",
    );
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 1);
  });
});

test("cancellation refuses a substituted durable successor proof and does not release capacity", () => {
  withTempHome(() => {
    const fixture = buildFixture();
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const result = reserveAndPreparePhysicalGraphNode(coordinator, {
      target_domain: fixture.domain,
      reservation_request: fixture.request("cancel-binding-drift"),
    });
    appendNodeTransition({
      target_domain: fixture.domain,
      node_id: fixture.nodeId,
      from_state: "dispatched",
      to_state: "failed",
      contract_hash: result.preparation.contract_hash,
      failure_reason: {
        reason: "dispatch_timeout",
        reservation_ref: result.preparation.physical_resource_dispatch.reservation_ref,
        receipt_digest: digest("substituted-receipt"),
        allocation_plan_digest:
          result.preparation.physical_resource_dispatch.allocation_plan_digest,
        eligibility_digest: result.preparation.physical_resource_dispatch.eligibility_digest,
        resource_bundle_digest:
          result.preparation.physical_resource_dispatch.resource_bundle_digest,
        source_graph_hash: result.preparation.physical_resource_dispatch.source_graph_hash,
        session_nucleus_hash:
          result.preparation.physical_resource_dispatch.session_nucleus_hash,
        prep_token_hash: result.preparation.prep_token,
      },
    });
    const transitionCountBeforeCancellation = readNodeTransitions(fixture.domain).length;
    assert.throws(
      () => cancelPreparedPhysicalGraphReservation(
        coordinator,
        result.reservation_handle,
      ),
      (error) => error.code === "physical_resource_graph_handle_stale",
    );
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 0);
    assert.equal(
      readNodeTransitions(fixture.domain).length,
      transitionCountBeforeCancellation,
    );
  });
});

test("post-reservation graph drift releases capacity and never calls prepare-node", () => {
  withTempHome(() => {
    let fixture;
    fixture = buildFixture({
      mutateAfterReservation: () => {
        appendHypothesisProposal({
          target_domain: fixture.domain,
          ts: "2026-07-18T00:00:02.000Z",
          hypothesis_statement: "Concurrent graph mutation changes the source hash.",
          surface_refs: ["surface:physical-reader"],
          proposal_id: "concurrent-graph-mutation",
        });
      },
    });
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const transitionsBefore = readNodeTransitions(fixture.domain).length;
    assert.throws(
      () => reserveAndPreparePhysicalGraphNode(coordinator, {
        target_domain: fixture.domain,
        reservation_request: fixture.request("graph-drift"),
      }),
      (error) => error.code === "physical_resource_graph_hash_drift",
    );
    assert.equal(readNodeTransitions(fixture.domain).length, transitionsBefore);
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 1);
    assert.equal(
      materializeTaskGraph(fixture.domain, { write: false }).document.nodes
        .find((entry) => entry.node_id === fixture.nodeId).state,
      "contracted",
    );
  });
});

test("the final eligibility callback is session-locked and graph drift after it cannot dispatch", () => {
  withTempHome(() => {
    let fixture;
    let observedSessionLock = false;
    fixture = buildFixture({
      mutateDuringFinalEligibility: () => {
        observedSessionLock = fs.existsSync(sessionLockPath(fixture.domain));
        appendHypothesisProposal({
          target_domain: fixture.domain,
          ts: "2026-07-18T00:00:03.000Z",
          hypothesis_statement: "A reentrant broker callback changes the source graph.",
          surface_refs: ["surface:physical-reader"],
          proposal_id: "eligibility-callback-mutation",
        });
      },
    });
    const coordinator = createPhysicalResourceGraphCoordinator({
      reservation_authority: fixture.authority,
    });
    const transitionsBefore = readNodeTransitions(fixture.domain).length;
    assert.throws(
      () => reserveAndPreparePhysicalGraphNode(coordinator, {
        target_domain: fixture.domain,
        reservation_request: fixture.request("eligibility-drift"),
      }),
      (error) => error.code === "physical_resource_graph_hash_drift",
    );
    assert.equal(observedSessionLock, true);
    assert.equal(readNodeTransitions(fixture.domain).length, transitionsBefore);
    assert.equal(projectPhysicalResourceReservationInventory(fixture.authority)
      .resources[0].available_capacity_units, 1);
    assert.equal(
      materializeTaskGraph(fixture.domain, { write: false }).document.nodes
        .find((entry) => entry.node_id === fixture.nodeId).state,
      "contracted",
    );
  });
});
