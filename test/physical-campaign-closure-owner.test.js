"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  buildPhysicalCampaignClosurePreflight,
} = require("../mcp/domains/physical/physical-campaign-closure.js");
const {
  assertDurablePhysicalCompletion,
  buildPhysicalFinding,
  derivePhysicalAssignmentContextDigest,
  deriveVerifiedPhysicalCoverageTerminalWitnessDigest,
  projectDurablePhysicalCampaignCompletion,
} = require("../mcp/domains/physical/physical-capability-consumers.js");
const {
  openProductionPhysicalCampaignClosureOwner,
  assertProductionPhysicalCampaignClosureOwner,
} = require("../mcp/domains/physical/physical-campaign-closure-owner.js");
const {
  installPhysicalCampaignAnchorResolver,
  physicalCampaignAnchorPortAssurance,
} = require("../mcp/domains/physical/physical-campaign-anchor.js");
const {
  initializePhysicalCampaignCoordinator,
  physicalCampaignClosureReadiness,
  readVerifiedPhysicalCampaignCompletionState,
  routePhysicalCampaignSegment,
} = require("../mcp/domains/physical/physical-campaign-coordinator.js");
const {
  createDurableInstrumentLeaseBrokerPort,
  createDurableInstrumentLeaseStore,
} = require("../mcp/domains/physical/instrument-lease-store.js");
const {
  sessionNucleusFromState,
} = require("../mcp/core/governance/governance-contracts.js");
const {
  buildInitialSessionState,
} = require("../mcp/core/session/session-state-contracts.js");
const {
  writeSessionStateDocument,
} = require("../mcp/core/session/session-state-store.js");
const {
  normalizePhysicalScopeNucleusAxis,
} = require("../mcp/lib/physical-scope-axis.js");
const {
  physicalCampaignDir,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const {
  SANDBOX_AGENT_UID_ENV,
  SANDBOX_ISOLATION_ACK_ENV,
  SANDBOX_ISOLATION_ACK_TOKEN,
  SANDBOX_SIGNER_UID_ENV,
} = require("../mcp/core/ledger-integrity/sandbox-isolation-attest.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");
const {
  createProductionPhysicalVerdictFixture,
} = require("./helpers/production-physical-verdict.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function installPhysicalSession(domain) {
  const physicalScope = normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "physical_campaign_closure_owner_fixture",
    policy_digest: digest(`policy:${domain}`),
    projection_version: 1,
    projection_digest: digest(`projection:${domain}`),
    provenance_digest: digest(`provenance:${domain}`),
    compatibility_digest: digest(`compatibility:${domain}`),
    transition_receipt_registry_digest: digest(`transition:${domain}`),
    authority_epoch: 1,
    revocation_generation: 0,
  });
  const directory = sessionDir(domain);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  const state = buildInitialSessionState(domain, `https://${domain}`, {
    physicalScope,
    egressProfile: {
      name: "default",
      region: null,
      proxy_configured: false,
      egress_profile_identity_hash: null,
      egress_profile_identity_version: null,
      egress_profile_identity_source: {
        proxy_url_source: "none",
        proxy_env_var: null,
        proxy_url_redacted: null,
        resolved_proxy: null,
      },
    },
  });
  writeSessionStateDocument(domain, {}, state);
  const nucleus = sessionNucleusFromState(state);
  fs.writeFileSync(
    path.join(directory, "session-nucleus.json"),
    `${JSON.stringify(nucleus, null, 2)}\n`,
    { mode: 0o600 },
  );
  return nucleus;
}

function createMemoryAnchor() {
  let state = null;
  return {
    readState() { return state == null ? null : structuredClone(state); },
    compareAndSet(request) {
      const generation = state == null ? null : state.generation;
      const head = state == null ? null : state.head_event_digest;
      if (request.expected_generation !== generation
          || request.expected_head_event_digest !== head) return false;
      state = structuredClone(request.next_state);
      return true;
    },
  };
}

function createLeaseBroker(root, nucleusHash) {
  const store = createDurableInstrumentLeaseStore({
    root,
    runtimeId: `physical-runtime:v1:${digest(`runtime:${nucleusHash}`).slice(0, 32)}`,
    sessionNucleusHash: nucleusHash,
    masterKey: crypto.createHash("sha256").update(`master:${nucleusHash}`).digest(),
    stateAnchor: createMemoryAnchor(),
    checkpointMode: "legacy_full_audit",
    now: () => new Date("2026-07-20T00:00:00.500Z"),
  });
  return { store, broker: createDurableInstrumentLeaseBrokerPort(store) };
}

function preflightInput(owner, authorityDigest = digest("assignment-authority")) {
  return {
    campaign_identity_version: 2,
    campaign_id: owner.campaign_id,
    session_nucleus_hash: owner.session_nucleus_hash,
    authority_binding_digest: authorityDigest,
    capability_pack_digest: digest("physical-capability-pack"),
    closure_signer_key_ref: owner.signer.signer_key_ref,
    closure_signer_public_key_digest: owner.signer.signer_public_key_digest,
    declared_dimensions: [{ dimension_id: "asset", values: ["door-reader-a"] }],
    events_per_cell: 1,
    segment_event_limit: 4,
  };
}

function routedTerminal(preflight, terminalState = "denied", witnessDigest = null) {
  const cellId = preflight.segments[0].cell_ids[0];
  return [{
    cell_id: cellId,
    event_ordinal: 1,
    terminal_state: terminalState,
    terminal_witness_digest: witnessDigest || digest(`terminal:${cellId}:${terminalState}`),
    frontier_event: {
      event_id: `FE-PC-${digest(`frontier:${cellId}`).slice(0, 24)}`,
      kind: "observation.recorded",
      ts: "2026-07-20T00:00:00.000Z",
      payload: {
        kind: "cell_proposed",
        surface_id: `physical:${cellId}`,
        cell_key: cellId,
        bug_class: "physical_fixture",
        auth_profile: "authorized_operator",
        technique_pack_ids: ["physical-fixture-technique"],
        capability_pack_ids: ["physical-fixture-capability"],
      },
    },
  }];
}

function mechanismAHarness(t, { enabled = true } = {}) {
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (uid == null || uid === 0) throw new Error("Mechanism-A fixture requires a non-root uid");
  const prior = Object.fromEntries([
    ["HOME", process.env.HOME],
    [SANDBOX_ISOLATION_ACK_ENV, process.env[SANDBOX_ISOLATION_ACK_ENV]],
    [SANDBOX_SIGNER_UID_ENV, process.env[SANDBOX_SIGNER_UID_ENV]],
    [SANDBOX_AGENT_UID_ENV, process.env[SANDBOX_AGENT_UID_ENV]],
  ]);
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-campaign-owner-home-"));
  fs.chmodSync(home, 0o700);
  process.env.HOME = home;
  if (enabled) {
    process.env[SANDBOX_ISOLATION_ACK_ENV] = SANDBOX_ISOLATION_ACK_TOKEN;
    process.env[SANDBOX_SIGNER_UID_ENV] = String(uid);
    process.env[SANDBOX_AGENT_UID_ENV] = String(uid + 1);
  } else {
    delete process.env[SANDBOX_ISOLATION_ACK_ENV];
    delete process.env[SANDBOX_SIGNER_UID_ENV];
    delete process.env[SANDBOX_AGENT_UID_ENV];
  }
  const externalRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-campaign-external-owner-"));
  const leaseRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-campaign-lease-owner-"));
  fs.chmodSync(externalRoot, 0o700);
  fs.chmodSync(leaseRoot, 0o700);
  t.after(() => {
    for (const [name, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(externalRoot, { recursive: true, force: true });
    fs.rmSync(leaseRoot, { recursive: true, force: true });
  });

  return { externalRoot, home, leaseRoot };
}

test("campaign identity v2 removes the assignment/campaign SHA-256 fixed point while v1 remains compatible", () => {
  const common = {
    session_nucleus_hash: digest("identity-session"),
    authority_binding_digest: digest("identity-assignment-a"),
    capability_pack_digest: digest("identity-pack"),
    closure_signer_key_ref: "campaign-signer:identity-fixture",
    closure_signer_public_key_digest: digest("identity-signer"),
    declared_dimensions: [{ dimension_id: "asset", values: ["reader-a"] }],
    events_per_cell: 1,
    segment_event_limit: 4,
  };
  const legacy = buildPhysicalCampaignClosurePreflight(common);
  assert.equal(legacy.campaign_identity_version, undefined);

  const issued = `physical-campaign:${digest("server-issued-id")}`;
  const first = buildPhysicalCampaignClosurePreflight({
    ...common,
    campaign_identity_version: 2,
    campaign_id: issued,
  });
  const second = buildPhysicalCampaignClosurePreflight({
    ...common,
    campaign_identity_version: 2,
    campaign_id: issued,
    authority_binding_digest: digest("identity-assignment-b"),
  });
  assert.equal(first.campaign_id, issued);
  assert.equal(second.campaign_id, issued);
  assert.notEqual(first.preflight_digest, second.preflight_digest);
  assert.notEqual(first.campaign_nucleus_digest, second.campaign_nucleus_digest);
});

test("the genuine owner remains non-authorizing without structural Mechanism-A", { concurrency: false }, (t) => {
  const harness = mechanismAHarness(t, { enabled: false });
  const domain = "campaign-owner-same-uid.example.com";
  const nucleus = installPhysicalSession(domain);
  const lease = createLeaseBroker(harness.leaseRoot, nucleus.nucleus_hash);
  t.after(() => lease.store.close());
  const owner = openProductionPhysicalCampaignClosureOwner({
    version: 1,
    target_domain: domain,
    session_nucleus_hash: nucleus.nucleus_hash,
    external_owner_root: harness.externalRoot,
    lease_broker_port: lease.broker,
  });
  assert.equal(owner.production_ready, false);
  assert.throws(() => assertProductionPhysicalCampaignClosureOwner(owner), /Mechanism-A/);
  const preflight = buildPhysicalCampaignClosurePreflight(preflightInput(owner));
  const assurance = physicalCampaignAnchorPortAssurance(owner.anchor_port, {
    target_domain: domain,
    session_nucleus_hash: nucleus.nucleus_hash,
    preflight,
  });
  assert.equal(assurance.production_ready, false);
  assert.equal(assurance.campaign_obligation_server_issued, false);
});

test("the genuine owner closes v2 only from its signed manifest and exact zero-effect lease readback",
  { concurrency: false }, (t) => {
    const harness = mechanismAHarness(t);
    const domain = "campaign-owner-production.example.com";
    const nucleus = installPhysicalSession(domain);
    const lease = createLeaseBroker(harness.leaseRoot, nucleus.nucleus_hash);
    t.after(() => lease.store.close());
    let owner = openProductionPhysicalCampaignClosureOwner({
      version: 1,
      target_domain: domain,
      session_nucleus_hash: nucleus.nucleus_hash,
      external_owner_root: harness.externalRoot,
      lease_broker_port: lease.broker,
    });
    assert.equal(assertProductionPhysicalCampaignClosureOwner(owner), owner);
    assert.match(owner.campaign_id, /^physical-campaign:[a-f0-9]{64}$/u);
    const input = preflightInput(owner);
    const preflight = buildPhysicalCampaignClosurePreflight(input);
    const legacyInput = { ...input };
    delete legacyInput.campaign_identity_version;
    delete legacyInput.campaign_id;
    const legacyPreflight = buildPhysicalCampaignClosurePreflight(legacyInput);
    assert.equal(physicalCampaignAnchorPortAssurance(owner.anchor_port, {
      target_domain: domain,
      session_nucleus_hash: nucleus.nucleus_hash,
      preflight: legacyPreflight,
    }).production_ready, false);

    let uninstall = installPhysicalCampaignAnchorResolver(() => owner.anchor_port);
    t.after(() => { if (uninstall) uninstall(); });
    initializePhysicalCampaignCoordinator({
      target_domain: domain,
      preflight_input: input,
      signer: owner.signer,
      verifier: owner.verifier,
    });
    routePhysicalCampaignSegment({
      target_domain: domain,
      segment_index: 0,
      routed_events: routedTerminal(preflight),
      signer: owner.signer,
    });
    const completion = readVerifiedPhysicalCampaignCompletionState(domain);
    assert.equal(completion.campaign_identity_version, 2);
    assert.equal(completion.production_ready, true);
    assert.equal(completion.active_effect_count, 0);
    assert.match(completion.campaign_obligation_digest, /^[a-f0-9]{64}$/u);
    assert.match(completion.terminal_witness_attestation_digest, /^[a-f0-9]{64}$/u);
    assert.match(completion.no_active_effects_attestation_digest, /^[a-f0-9]{64}$/u);
    assert.equal(physicalCampaignClosureReadiness(domain).satisfied, true);

    // Cold reopen uses the same genuine constructor and retains the server id,
    // signer enrollment, signed head, and closure attestation.
    uninstall();
    uninstall = null;
    owner = openProductionPhysicalCampaignClosureOwner({
      version: 1,
      target_domain: domain,
      session_nucleus_hash: nucleus.nucleus_hash,
      external_owner_root: harness.externalRoot,
      lease_broker_port: lease.broker,
    });
    assert.equal(owner.campaign_id, preflight.campaign_id);
    uninstall = installPhysicalCampaignAnchorResolver(() => owner.anchor_port);
    assert.equal(readVerifiedPhysicalCampaignCompletionState(domain).production_ready, true);

    // Assurance is revalidated from the live lease owner. A new held lease
    // after closure invalidates the signed zero-effect snapshot immediately;
    // the old attestation cannot be replayed as a boolean or digest shim.
    lease.store.acquireLease({
      version: 1,
      lease_id: "lease-campaign-owner-live-1",
      instrument_ref: "instrument:campaign-owner-reader-1",
      owner_principal_id: "principal:campaign-owner-broker",
      execution_principal_id: "principal:campaign-owner-worker",
      terminal_receipt_recipient_principal_id: "principal:campaign-owner-broker",
      terminal_receipt_idempotency_domain_digest: digest("campaign-owner-terminal-domain"),
      attempt_ref: "attempt:campaign-owner-live-1",
      operation_id: "representation.write",
      execution_request_digest: digest("campaign-owner-execution-request"),
      resource_bundle_digest: digest("campaign-owner-resource-bundle"),
      fencing_token: "fence-campaign-owner-live-1",
      fencing_generation: 1,
      state: "held",
      sequence: 0,
      acquired_at: "2026-07-20T00:00:00.000Z",
      updated_at: "2026-07-20T00:00:00.000Z",
      effect_not_before: "2026-07-20T00:00:00.000Z",
      effect_deadline: "2026-07-20T00:01:00.000Z",
      heartbeat_deadline: "2026-07-20T00:00:05.000Z",
      expires_at: "2026-07-20T00:01:00.000Z",
    });
    assert.throws(
      () => readVerifiedPhysicalCampaignCompletionState(domain),
      (error) => error.code === "physical_campaign_active_effects_remain",
    );

    // The external owner domain survives local campaign deletion and rejects a
    // cold-restart rebase rather than minting a new genesis.
    fs.rmSync(physicalCampaignDir(domain), { recursive: true, force: true });
    assert.throws(
      () => physicalCampaignClosureReadiness(domain),
      (error) => error.code === "physical_campaign_checkpoint_rollback",
    );

    // The same external reservation cannot be rebound across a domain/nucleus.
    const otherDomain = "campaign-owner-cross-session.example.com";
    const otherNucleus = installPhysicalSession(otherDomain);
    assert.throws(
      () => openProductionPhysicalCampaignClosureOwner({
        version: 1,
        target_domain: otherDomain,
        session_nucleus_hash: otherNucleus.nucleus_hash,
        external_owner_root: harness.externalRoot,
        lease_broker_port: lease.broker,
      }),
      /owner key binding drifted|authority drift/i,
    );
  });

test("the genuine experiment and campaign owners close the full production finding path",
  { concurrency: false }, async () => {
    const fixture = await createProductionPhysicalVerdictFixture({
      structural_mechanism_a: true,
      target_domain: "campaign-owner-full-positive.example.com",
    });
    const externalRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-campaign-positive-owner-"));
    const leaseRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-campaign-positive-lease-"));
    fs.chmodSync(externalRoot, 0o700);
    fs.chmodSync(leaseRoot, 0o700);
    const lease = createLeaseBroker(leaseRoot, fixture.verdict.session_nucleus_hash);
    let uninstall = null;
    try {
      const owner = openProductionPhysicalCampaignClosureOwner({
        version: 1,
        target_domain: fixture.target_domain,
        session_nucleus_hash: fixture.verdict.session_nucleus_hash,
        external_owner_root: externalRoot,
        lease_broker_port: lease.broker,
      });
      const assignmentBody = {
        version: 1,
        capability_pack: "physical",
        capability_pack_version: 1,
        evaluator_agent: "evaluator-physical-agent",
        brief_profile: "physical",
        surface_id: "surface:door-reader",
        surface_type: "control_point",
        surface_class: "physical",
        session_nucleus_hash: fixture.verdict.session_nucleus_hash,
        asset_locator: fixture.asset_locator,
        campaign_ref: owner.campaign_id,
        physical_resource_bundle_ref: "physical-resource-bundle:campaign-owner-positive",
        lifecycle_precondition: "no_active_effects",
        effect_authority: "broker_admission_required",
      };
      const assignment = {
        ...assignmentBody,
        assignment_context_digest: derivePhysicalAssignmentContextDigest(assignmentBody),
      };
      const finding = buildPhysicalFinding({
        title: "Credential presentation accepted by the access-control transition",
        severity: "high",
        description: "Independent control and positive observations verified the physical transition.",
        impact: "An authorized assessment demonstrated a security-relevant access-control transition.",
        verdict: fixture.verdict,
      });
      const input = preflightInput(owner, assignment.assignment_context_digest);
      const preflight = buildPhysicalCampaignClosurePreflight(input);
      const cellId = preflight.segments[0].cell_ids[0];
      const witnessDigest = deriveVerifiedPhysicalCoverageTerminalWitnessDigest({
        assignment_context_digest: assignment.assignment_context_digest,
        session_nucleus_hash: assignment.session_nucleus_hash,
        campaign_ref: assignment.campaign_ref,
        cell_ref: cellId,
        asset_locator: assignment.asset_locator,
        verified_verdict_ref: finding.verified_verdict_ref,
        verification_projection_digest: finding.verification_projection_digest,
      });

      uninstall = installPhysicalCampaignAnchorResolver(() => owner.anchor_port);
      initializePhysicalCampaignCoordinator({
        target_domain: fixture.target_domain,
        preflight_input: input,
        signer: owner.signer,
        verifier: owner.verifier,
      });
      routePhysicalCampaignSegment({
        target_domain: fixture.target_domain,
        segment_index: 0,
        routed_events: routedTerminal(preflight, "verified", witnessDigest),
        signer: owner.signer,
      });

      const completion = projectDurablePhysicalCampaignCompletion({
        target_domain: fixture.target_domain,
        assignment,
        finding,
      });
      assert.equal(assertDurablePhysicalCompletion(completion).completion_digest,
        completion.completion_digest);
      assert.equal(completion.production_ready, true);
      assert.equal(completion.campaign_identity_version, 2);
      assert.equal(completion.matched_verified_cell_count, 1);
      assert.equal(completion.verified_verdict_ref, fixture.verified_verdict_ref);
      assert.equal(completion.active_effect_count, 0);
      assert.equal(completion.residue_cell_count, 0);
    } finally {
      if (uninstall) uninstall();
      lease.store.close();
      fixture.cleanup();
      fs.rmSync(externalRoot, { recursive: true, force: true });
      fs.rmSync(leaseRoot, { recursive: true, force: true });
    }
  });
