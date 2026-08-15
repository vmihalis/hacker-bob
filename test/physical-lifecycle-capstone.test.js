"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  buildPhysicalCompositionProjection,
  createProductionPhysicalCompositionPort,
  installPhysicalCompositionPort,
} = require("../mcp/core/capability/capability-pack-composition-adapters.js");
const {
  buildClaimFreeze,
} = require("../mcp/core/claims/claim-freeze.js");
const {
  buildDurableReceiptTrustRegistry,
  createDurableEvidenceReceiptIssuer,
} = require("../mcp/core/executed-evidence-registry.js");
const {
  writeGradeVerdict,
} = require("../mcp/core/grade-verdict-store.js");
const {
  createDurableInstrumentLeaseBrokerPort,
  createDurableInstrumentLeaseStore,
} = require("../mcp/domains/physical/instrument-lease-store.js");
const {
  buildPhysicalCampaignClosurePreflight,
} = require("../mcp/domains/physical/physical-campaign-closure.js");
const {
  installPhysicalCampaignAnchorResolver,
} = require("../mcp/domains/physical/physical-campaign-anchor.js");
const {
  openProductionPhysicalCampaignClosureOwner,
} = require("../mcp/domains/physical/physical-campaign-closure-owner.js");
const {
  initializePhysicalCampaignCoordinator,
  routePhysicalCampaignSegment,
} = require("../mcp/domains/physical/physical-campaign-coordinator.js");
const {
  buildPhysicalFinding,
  derivePhysicalAssignmentContextDigest,
  deriveVerifiedPhysicalCoverageTerminalWitnessDigest,
} = require("../mcp/domains/physical/physical-capability-consumers.js");
const {
  assertPhysicalLifecycleEngineeringCapstone,
  auditPhysicalLifecycleEngineeringCapstone,
  buildPhysicalCapstoneCoverageDeclaration,
  buildPhysicalCapstoneVerificationResult,
} = require("../mcp/domains/physical/physical-lifecycle-capstone.js");
const {
  createPhysicalProviderAuthoringManifest,
} = require("../mcp/domains/physical/physical-provider-authoring.js");
const {
  physicalSurfaceTransitionClaimPredicateDigest,
} = require("../mcp/domains/physical/physical-surface-transition.js");
const {
  createProductionPhysicalVerdictResolverPort,
  installPhysicalVerdictResolver,
} = require("../mcp/domains/physical/physical-verdict-runtime.js");
const {
  proofBundlePaths,
  reportMarkdownPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const {
  writeProofBundles,
} = require("../mcp/core/proof-bundle.js");
const {
  appendReportSnapshot,
  readReportSnapshots,
} = require("../mcp/core/report-snapshots.js");
const {
  buildInitialSessionState,
} = require("../mcp/core/session/session-state-contracts.js");
const {
  writeSessionStateDocument,
} = require("../mcp/core/session/session-state-store.js");
const {
  appendEdges,
  createPhysicalSurfaceGraphServerService,
} = require("../mcp/core/frontier/surface-graph.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");
const {
  buildVerificationAdjudication,
  prepareVerificationEntry,
} = require("../mcp/core/verification/verification.js");
const {
  writeVerificationRound,
} = require("../mcp/core/verification/verification-round-store.js");
const {
  readCandidateClaims,
} = require("../mcp/core/claims/claims.js");
const {
  writeEvidencePacks,
} = require("../mcp/core/evidence.js");

const composeReportTool = require("../mcp/tools/compose-report.js");
const finalizeReportTool = require("../mcp/tools/finalize-report.js");
const recordPhysicalClaimTool = require("../mcp/tools/physical/record-physical-candidate-claim.js");
const {
  createProductionPhysicalVerdictFixture,
} = require("./helpers/production-physical-verdict.js");
const {
  createOrthogonalMultiInstrumentProviderFixture,
} = require("../packages/bob-instrument-deterministic/lib/orthogonal-fixture.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function uniqueDomain() {
  return `physical-capstone-${crypto.randomBytes(8).toString("hex")}.local`;
}

function orthogonalExperimentProfile(providerFixture, providerManifest) {
  return {
    effect_registry: providerFixture.effectRegistry,
    effect_template_id: "environment.actuate.gpio.v1",
    requested_effect: providerFixture.requestedEffects.actuate,
    surface_ref: "surface:orthogonal-optical-transition-0001",
    experiment_id: "orthogonal-gpio-optical-capstone",
    node_id: "PH-X4",
    instrument_ref: providerFixture.prepareRequests.actuate.instrument_ref,
    instrument_identity_ref: "instrument-identity:orthogonal-gpio-actuator-0001",
    instrument_inventory_ref: "inventory:orthogonal-gpio-actuator-0001",
    assurance_profile_id: "orthogonal-gpio-optical-v1",
    provider_manifest_digest: providerManifest.manifest_digest,
    source_asset_ref: "source:orthogonal-gpio-stimulus-0001",
    target_asset_ref: "target:orthogonal-owned-fixture-0001",
    operation_id: "environment.actuate",
    parameter_digest: hashCanonicalJson(providerFixture.prepareRequests.actuate.parameters),
  };
}

function topology(domain, assetLocator) {
  return {
    target_domain: domain,
    participants: [{
      participant_id: "subject",
      role: "subject",
      node: { type: "asset", id: assetLocator },
    }, {
      participant_id: "control",
      role: "outcome",
      node: { type: "control_point", id: "control-point:capstone-verified" },
    }],
    arcs: [{
      arc_id: "subject-to-control",
      source_participant_id: "subject",
      target_participant_id: "control",
      edge_type: "demonstrated_transition",
    }],
  };
}

function transitionAuthority() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const registry = buildDurableReceiptTrustRegistry({
    version: 1,
    registry_id: "physical-lifecycle-capstone",
    issuers: [{
      issuer_key_id: "signer-key:physical-capstone-transition",
      issuer_epoch: 1,
      signature_scheme: "ed25519",
      public_key_pem: keys.publicKey.export({ type: "spki", format: "pem" }),
      receipt_kinds: ["physical_surface_transition"],
      valid_from: "2020-01-01T00:00:00.000Z",
      expires_at: "2100-01-01T00:00:00.000Z",
      trusted: true,
      revoked: false,
    }],
  });
  const receiptsByRef = new Map();
  const receiptsBySemantic = new Map();
  const issuer = createDurableEvidenceReceiptIssuer({
    trust_registry: registry,
    issuer_key_id: "signer-key:physical-capstone-transition",
    issuer_epoch: 1,
    private_key_pem: keys.privateKey.export({ type: "pkcs8", format: "pem" }),
    now: () => new Date().toISOString(),
    commit_receipt(receipt, binding) {
      receiptsByRef.set(receipt.receipt_ref, receipt);
      receiptsBySemantic.set(binding.semantic_digest, receipt);
      return true;
    },
    resolve_committed_receipt({ semantic_digest: semanticDigest }) {
      return receiptsBySemantic.get(semanticDigest) || null;
    },
  });
  return { issuer, receiptsByRef, registry };
}

function createMemoryAnchor() {
  let state = null;
  return {
    readState() {
      return state == null ? null : structuredClone(state);
    },
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
    now: () => new Date(),
  });
  return { store, broker: createDurableInstrumentLeaseBrokerPort(store) };
}

function installMatchingVerificationState(domain, nucleus) {
  const state = buildInitialSessionState(domain, `https://${domain}`, {
    physicalScope: nucleus.physical_scope,
    egressProfile: {
      name: "default",
      region: null,
      proxy_configured: false,
      egress_profile_identity_hash: null,
      egress_profile_identity_version: null,
      egress_profile_identity_source: null,
    },
  });
  state.lifecycle_state = "VERIFY";
  state.phase = "VERIFY";
  writeSessionStateDocument(domain, {}, state);
  return state;
}

function routedTerminal(preflight, witnessDigest) {
  const cellId = preflight.segments[0].cell_ids[0];
  return [{
    cell_id: cellId,
    event_ordinal: 1,
    terminal_state: "verified",
    terminal_witness_digest: witnessDigest,
    frontier_event: {
      event_id: `FE-PC-${digest(`frontier:${cellId}`).slice(0, 24)}`,
      kind: "observation.recorded",
      ts: new Date().toISOString(),
      payload: {
        kind: "cell_proposed",
        surface_id: `physical:${cellId}`,
        cell_key: cellId,
        bug_class: "physical_verified_transition",
        auth_profile: "authorized_operator",
        technique_pack_ids: ["physical-control-testing"],
        capability_pack_ids: ["physical"],
      },
    },
  }];
}

function claimArgs(domain, assignment, verifiedVerdictRef) {
  return {
    target_domain: domain,
    assignment,
    verified_verdict_ref: verifiedVerdictRef,
    title: "Bounded actuation crosses the verified physical control",
    severity: "high",
    cwe: "CWE-284",
    description:
      "Independent positive and control observers verified the bounded physical state transition.",
    impact:
      "The authorized assessment demonstrated a security-relevant controlled-fixture transition.",
    created_at: new Date().toISOString(),
  };
}

function v2RoundArgs(domain, verificationEntry, round, result, adjudicationPlanHash = null) {
  const args = {
    target_domain: domain,
    round,
    notes: null,
    verification_attempt_id: verificationEntry.state_fields.verification_attempt_id,
    verification_snapshot_hash: verificationEntry.state_fields.verification_snapshot_hash,
    round_profile: round,
    results: [result],
  };
  if (adjudicationPlanHash != null) args.adjudication_plan_hash = adjudicationPlanHash;
  return args;
}

function fabricatedEvidencePack(findingId) {
  return {
    finding_id: findingId,
    sample_type: "caller_fabricated_physical_projection",
    sample_count: 1,
    aggregate_counts: { terminal_cells: 1 },
    representative_samples: [{ production_ready: true }],
    sensitive_clusters: [],
    replay_summary: "Caller asserts that a replay passed.",
    redaction_notes: "No raw bytes included.",
    report_snippet: "Caller-authored physical evidence must never win adapter dispatch.",
  };
}

test("PH-C10 drives a physical claim through the real audit-graded lifecycle adapters",
  { concurrency: false, timeout: 300_000 }, async () => {
    const domain = uniqueDomain();
    const authority = transitionAuthority();
    const providerFixture = createOrthogonalMultiInstrumentProviderFixture();
    const providerManifest = createPhysicalProviderAuthoringManifest({
      qualification_profile: "orthogonal_multi_instrument_v1",
      provider_descriptor: providerFixture.descriptor,
      operation_registry: providerFixture.operationRegistry,
      effect_registry: providerFixture.effectRegistry,
      resource_bundles: [providerFixture.resourceBundle],
    });
    const experimentProfile = orthogonalExperimentProfile(providerFixture, providerManifest);
    const graphTopology = topology(domain, experimentProfile.target_asset_ref);
    const fixture = await createProductionPhysicalVerdictFixture({
      structural_mechanism_a: true,
      target_domain: domain,
      transition_receipt_registry_digest: authority.registry.registry_digest,
      claim_predicate_digest: physicalSurfaceTransitionClaimPredicateDigest(graphTopology),
      experiment_profile: experimentProfile,
    });
    const externalRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-capstone-campaign-owner-"));
    const leaseRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-capstone-lease-owner-"));
    fs.chmodSync(externalRoot, 0o700);
    fs.chmodSync(leaseRoot, 0o700);
    const lease = createLeaseBroker(leaseRoot, fixture.verdict.session_nucleus_hash);
    const cleanup = [];
    try {
      assert.equal(fixture.ledger.plan.provider_manifest_digest, providerManifest.manifest_digest);
      assert.equal(fixture.ledger.plan.operation_id, "environment.actuate");
      const state = installMatchingVerificationState(domain, {
        physical_scope: JSON.parse(
          fs.readFileSync(path.join(sessionDir(domain), "session-nucleus.json"), "utf8"),
        ).physical_scope,
      });

      const receipt = await authority.issuer.issuePhysicalSurfaceTransition({
        verified_claim_projection: fixture.projection,
        target_domain: domain,
        participants: graphTopology.participants,
        arcs: graphTopology.arcs,
      });
      const service = createPhysicalSurfaceGraphServerService({
        target_domain: domain,
        resolve_receipt({ receipt_ref: receiptRef }) {
          return authority.receiptsByRef.get(receiptRef) || null;
        },
        resolve_trust_registry({ issuer_registry_digest: registryDigest }) {
          return registryDigest === authority.registry.registry_digest ? authority.registry : null;
        },
      });
      const compositionPort = createProductionPhysicalCompositionPort({
        version: 1,
        surface_graph_service: service,
        production_experiment_ledgers: [fixture.ledger],
      });
      cleanup.push(installPhysicalCompositionPort(compositionPort));
      cleanup.push(installPhysicalVerdictResolver(
        createProductionPhysicalVerdictResolverPort({
          version: 1,
          ledgers: [fixture.ledger],
        }),
      ));

      const finding = buildPhysicalFinding({
        title: claimArgs(domain, {}, fixture.verified_verdict_ref).title,
        severity: "high",
        cwe: "CWE-284",
        description: claimArgs(domain, {}, fixture.verified_verdict_ref).description,
        impact: claimArgs(domain, {}, fixture.verified_verdict_ref).impact,
        verdict: fixture.verdict,
      });

      // An ordinary SurfaceGraph edge remains adjacency only. It cannot satisfy
      // the pack grade adapter before a signed transition receipt is consumed.
      appendEdges({
        target_domain: domain,
        edges: [{
          source: { type: "asset", id: fixture.asset_locator },
          target: { type: "control_point", id: "control-point:adjacency-only" },
          edge_type: "controls",
          source_artifact: "capstone-adjacency-negative",
        }],
      });
      assert.throws(
        () => buildPhysicalCompositionProjection(domain, finding),
        /no exact verified SurfaceGraph transition receipt/u,
      );
      service.appendVerifiedTransition({
        receipt_ref: receipt.receipt_ref,
        receipt_digest: receipt.receipt_digest,
      });
      assert.doesNotThrow(() => buildPhysicalCompositionProjection(domain, finding));

      const owner = openProductionPhysicalCampaignClosureOwner({
        version: 1,
        target_domain: domain,
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
        surface_id: "surface:physical-capstone-control",
        surface_type: "control_point",
        surface_class: "physical",
        session_nucleus_hash: fixture.verdict.session_nucleus_hash,
        asset_locator: fixture.asset_locator,
        campaign_ref: owner.campaign_id,
        physical_resource_bundle_ref: "physical-resource-bundle:capstone-closed",
        lifecycle_precondition: "no_active_effects",
        effect_authority: "broker_admission_required",
      };
      const assignment = {
        ...assignmentBody,
        assignment_context_digest: derivePhysicalAssignmentContextDigest(assignmentBody),
      };
      const coverageDeclaration = buildPhysicalCapstoneCoverageDeclaration({
        assignment,
        technique_id: "environment.actuation",
        context_ref: "physical-context:owned-shielded-fixture",
        control_ref: "physical-control:known-denied-baseline",
      });
      const preflightInput = {
        campaign_identity_version: 2,
        campaign_id: owner.campaign_id,
        session_nucleus_hash: fixture.verdict.session_nucleus_hash,
        authority_binding_digest: assignment.assignment_context_digest,
        capability_pack_digest: coverageDeclaration.capability_pack_digest,
        closure_signer_key_ref: owner.signer.signer_key_ref,
        closure_signer_public_key_digest: owner.signer.signer_public_key_digest,
        declared_dimensions: coverageDeclaration.declared_dimensions,
        events_per_cell: 1,
        segment_event_limit: 4,
      };
      const preflight = buildPhysicalCampaignClosurePreflight(preflightInput);
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
      cleanup.push(installPhysicalCampaignAnchorResolver(() => owner.anchor_port));
      initializePhysicalCampaignCoordinator({
        target_domain: domain,
        preflight_input: preflightInput,
        signer: owner.signer,
        verifier: owner.verifier,
      });
      routePhysicalCampaignSegment({
        target_domain: domain,
        segment_index: 0,
        routed_events: routedTerminal(preflight, witnessDigest),
        signer: owner.signer,
      });

      const args = claimArgs(domain, assignment, fixture.verified_verdict_ref);
      const recorded = JSON.parse(recordPhysicalClaimTool.handler(args));
      assert.equal(recorded.recorded, true);
      assert.equal(recorded.finding_id, "F-1");
      const duplicate = JSON.parse(recordPhysicalClaimTool.handler(args));
      assert.equal(duplicate.recorded, false);
      assert.equal(duplicate.duplicate, true);
      assert.equal(duplicate.finding_id, "F-1");
      assert.equal(readCandidateClaims(domain).length, 1);

      const freeze = buildClaimFreeze(domain, { write: true });
      assert.equal(freeze.claim_count, 1);
      const verificationEntry = prepareVerificationEntry(domain, state);
      writeSessionStateDocument(domain, {}, {
        ...state,
        ...verificationEntry.state_fields,
      });
      const verificationResult = buildPhysicalCapstoneVerificationResult(domain, "F-1");
      for (const round of ["brutalist", "balanced"]) {
        const written = JSON.parse(writeVerificationRound(
          v2RoundArgs(domain, verificationEntry, round, verificationResult),
        ));
        assert.equal(written.schema_version, 2);
      }
      const adjudication = JSON.parse(buildVerificationAdjudication({ target_domain: domain }));
      const final = JSON.parse(writeVerificationRound(v2RoundArgs(
        domain,
        verificationEntry,
        "final",
        verificationResult,
        adjudication.adjudication_plan_hash,
      )));
      assert.match(final.final_verification_hash, /^[a-f0-9]{64}$/u);

      assert.throws(
        () => writeEvidencePacks({
          target_domain: domain,
          packs: [fabricatedEvidencePack("F-1")],
        }),
        /cannot override capability-pack findings/u,
      );
      const evidence = JSON.parse(writeEvidencePacks({ target_domain: domain, packs: [] }));
      assert.equal(evidence.capability_pack_generated_count, 1);
      const proof = JSON.parse(writeProofBundles({ target_domain: domain, packs: [] }));
      assert.equal(proof.capability_pack_generated_count, 1);
      assert.equal(fs.existsSync(proofBundlePaths(domain).json), true);

      const grade = JSON.parse(writeGradeVerdict({
        target_domain: domain,
        verdict: "SUBMIT",
        total_score: 75,
        findings: [{
          finding_id: "F-1",
          impact: 25,
          proof_quality: 20,
          severity_accuracy: 10,
          chain_potential: 10,
          report_quality: 10,
          total_score: 75,
          feedback: "Server-owned physical projection and closure are coherent.",
        }],
        feedback: "Engineering capstone only; production and HIL remain false.",
      }));
      assert.equal(grade.verdict, "SUBMIT");

      const rendered = JSON.parse(composeReportTool.handler({
        target_domain: domain,
        sections: [],
        severity_summary: "One high-severity controlled physical transition was verified in the engineering fixture.",
      }));
      assert.deepEqual(rendered.capability_pack_report.finding_ids, ["F-1"]);
      assert.equal(rendered.capability_pack_report.production_ready, true);
      assert.equal(fs.existsSync(reportMarkdownPath(domain)), true);
      const finalized = JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
      assert.equal(finalized.finalized, true);
      assert.match(finalized.snapshot_hash, /^[a-f0-9]{64}$/u);

      const capstone = auditPhysicalLifecycleEngineeringCapstone({
        target_domain: domain,
        finding_id: "F-1",
        coverage_declaration: coverageDeclaration,
      });
      assert.equal(assertPhysicalLifecycleEngineeringCapstone(capstone), capstone);
      assert.equal(capstone.capstone_path_verified, true);
      assert.equal(capstone.applicable_cell_count, 1);
      assert.equal(capstone.terminal_cell_count, 1);
      assert.equal(capstone.coverage_credited_cell_count, 1);
      assert.equal(capstone.active_effect_count, 0);
      assert.equal(capstone.residue_cell_count, 0);
      assert.equal(capstone.production_ready, false);
      assert.equal(capstone.hil_verified, false);
      assert.equal(capstone.full_provider_matrix, false);
      assert.equal(capstone.lifecycle_transition_path_verified, false);
      assert.equal(capstone.provider_lineage_binding, "via_verified_ledger_projection_digest");
      assert.equal(
        capstone.provider_lineage_projection_digest,
        fixture.projection.projection_digest,
      );
      assert.ok(capstone.residuals.includes("owned_hardware_hil_not_exercised"));

      // Persist a literal duplicate through the actual append-only snapshot
      // store. Re-finalization is generally valid, but an identical second row
      // is transcript replay for this one-shot engineering capstone.
      const snapshots = readReportSnapshots(domain);
      assert.equal(snapshots.length, 1);
      appendReportSnapshot(snapshots[0]);
      assert.throws(
        () => auditPhysicalLifecycleEngineeringCapstone({
          target_domain: domain,
          finding_id: "F-1",
          coverage_declaration: coverageDeclaration,
        }),
        /exactly one non-replayed report snapshot/u,
      );
    } finally {
      for (const uninstall of cleanup.reverse()) {
        try { uninstall(); } catch {}
      }
      lease.store.close();
      fixture.cleanup();
      fs.rmSync(externalRoot, { recursive: true, force: true });
      fs.rmSync(leaseRoot, { recursive: true, force: true });
    }
  });

test("PH-C10 coverage declarations and capstone projections cannot be caller fabricated", () => {
  assert.throws(
    () => assertPhysicalLifecycleEngineeringCapstone({
      capstone_path_verified: true,
      production_ready: false,
      hil_verified: false,
    }),
    /server-owned engineering auditor/u,
  );
  assert.throws(
    () => buildPhysicalCapstoneCoverageDeclaration({
      assignment: {},
      technique_id: "credential.discovery",
      context_ref: "physical-context:fixture",
      control_ref: "physical-control:baseline",
      production_ready: true,
    }),
    /must carry exactly/u,
  );
});
