"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  assertPhysicalBlastRadiusGradeBinding,
  assertPhysicalCompositionProjection,
  bindPhysicalSeverityToVerifiedBlastRadius,
  buildPhysicalCompositionProjection,
  createProductionPhysicalCompositionPort,
  installPhysicalCompositionPort,
  PHYSICAL_BLAST_RADIUS_NODE_POLICY,
  physicalCompositionRuntimeReadiness,
} = require("../mcp/core/capability/capability-pack-composition-adapters.js");
const {
  buildPhysicalGradeBinding,
  buildPhysicalFinding,
  closePhysicalCoverage,
  derivePhysicalAssignmentContextDigest,
  deriveVerifiedPhysicalCoverageTerminalWitnessDigest,
} = require("../mcp/domains/physical/physical-capability-consumers.js");
const {
  buildDurableReceiptTrustRegistry,
  createDurableEvidenceReceiptIssuer,
} = require("../mcp/core/executed-evidence-registry.js");
const {
  buildSessionNucleus,
  normalizePhysicalScopeNucleusAxis,
} = require("../mcp/core/governance/governance-contracts.js");
const {
  PHYSICAL_SURFACE_NODE_TYPES,
  normalizePhysicalSurfaceLiveRevalidationPayload,
  normalizePhysicalSurfaceTransitionPayload,
  physicalSurfaceTransitionClaimPredicateDigest,
} = require("../mcp/domains/physical/physical-surface-transition.js");
const {
  appendEdges,
  createPhysicalSurfaceGraphServerService,
} = require("../mcp/core/frontier/surface-graph.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");
const {
  createProductionPhysicalVerdictFixture,
} = require("./helpers/production-physical-verdict.js");

function digest(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function uniqueDomain() {
  return `physical-composition-${crypto.randomBytes(6).toString("hex")}.local`;
}

function sessionPath(domain, basename = "") {
  return path.join(os.homedir(), "hacker-bob-sessions", domain, basename);
}

test("composition authority inputs reject public flags, callbacks, getters, and unbranded projections", async () => {
  assert.deepEqual(
    Object.keys(PHYSICAL_BLAST_RADIUS_NODE_POLICY).sort(),
    [...PHYSICAL_SURFACE_NODE_TYPES].sort(),
  );
  assert.equal(physicalCompositionRuntimeReadiness().production_ready, false);
  assert.equal(physicalCompositionRuntimeReadiness().historical_projection_ready, false);
  assert.equal(physicalCompositionRuntimeReadiness().live_capability_ready, false);
  assert.equal(
    physicalCompositionRuntimeReadiness().live_capability_reason,
    "restart_durable_signed_trusted_time_not_installed",
  );
  assert.throws(
    () => createProductionPhysicalCompositionPort({
      version: 1,
      surface_graph_service: {},
      production_experiment_ledgers: [],
      trusted: true,
    }),
    /must carry exactly/u,
  );
  assert.throws(
    () => createProductionPhysicalCompositionPort({
      version: 1,
      surface_graph_service: {},
      production_experiment_ledgers: [],
      base_url: "https://not-a-physical-authority.invalid",
      httpScanFn() {},
    }),
    /must carry exactly/u,
  );
  assert.throws(
    () => createProductionPhysicalCompositionPort({
      version: 1,
      surface_graph_service: {
        queryVerifiedTransitionEdges() {
          return { edges: [], total_matched: 0, quarantined_count: 0 };
        },
      },
      production_experiment_ledgers: [],
    }),
    /Bob-owned server service/u,
  );
  const getterInput = { version: 1, production_experiment_ledgers: [] };
  Object.defineProperty(getterInput, "surface_graph_service", {
    enumerable: true,
    get() {
      throw new Error("composition input getter executed");
    },
  });
  assert.throws(
    () => createProductionPhysicalCompositionPort(getterInput),
    /must be an enumerable data property/u,
  );
  assert.throws(
    () => assertPhysicalCompositionProjection({
      production_ready: true,
      composition_projection_digest: digest("caller projection"),
    }),
    /production pack adapter/u,
  );
  assert.throws(
    () => assertPhysicalBlastRadiusGradeBinding({
      production_ready: true,
      blast_radius_grade_binding_digest: digest("caller grade"),
    }),
    /composition adapter/u,
  );
  const fixture = await createProductionPhysicalVerdictFixture({
      structural_mechanism_a: true,
      target_domain: uniqueDomain(),
  });
  try {
    const readiness = fixture.ledger.readiness();
    assert.equal(fixture.monotonic_head_owner.production_ready, true);
    assert.equal(readiness.production_ready, true);
    assert.equal(readiness.durability_trust_class, "independently_retained_monotonic_owner");
    assert.equal(readiness.external_monotonic_owner_bound, true);
    assert.equal(
      readiness.external_monotonic_owner_digest,
      fixture.monotonic_head_owner.slot_digest,
    );
    assert.equal(readiness.historical_event_ready, true);
    assert.equal(readiness.live_capability_ready, false);
    assert.equal(
      readiness.live_capability_reason,
      "restart_durable_signed_trusted_time_not_installed",
    );
  } finally {
    fixture.cleanup();
  }
});

function topology(domain, kind = "critical", assetId = "target:hotel-door-controller") {
  const participants = [{
    participant_id: "subject",
    role: "subject",
    node: { type: "asset", id: assetId },
  }, {
    participant_id: "control",
    role: "outcome",
    node: { type: kind === "medium" ? "interface" : "control_point", id: "control-point:verified" },
  }];
  const arcs = [{
    arc_id: "subject-to-control",
    source_participant_id: "subject",
    target_participant_id: "control",
    edge_type: "demonstrated_transition",
  }];
  if (kind === "critical") {
    participants.push({
      participant_id: "network",
      role: "context",
      node: { type: "network_attachment", id: "network-attachment:verified" },
    });
    arcs.push({
      arc_id: "control-to-network",
      source_participant_id: "control",
      target_participant_id: "network",
      edge_type: "demonstrated_transition",
    });
  } else if (kind === "disconnected-critical") {
    participants.push({
      participant_id: "network",
      role: "context",
      node: { type: "network_attachment", id: "network-attachment:disconnected" },
    }, {
      participant_id: "zone",
      role: "outcome",
      node: { type: "physical_zone", id: "physical-zone:disconnected" },
    });
    arcs.push({
      arc_id: "network-to-zone",
      source_participant_id: "network",
      target_participant_id: "zone",
      edge_type: "demonstrated_transition",
    });
  }
  return { target_domain: domain, participants, arcs };
}

function transitionAuthority() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const registry = buildDurableReceiptTrustRegistry({
    version: 1,
    registry_id: "physical-composition-test",
    issuers: [{
      issuer_key_id: "signer-key:physical-composition",
      issuer_epoch: 7,
      signature_scheme: "ed25519",
      public_key_pem: keys.publicKey.export({ type: "spki", format: "pem" }),
      receipt_kinds: [
        "physical_surface_transition",
        "physical_surface_live_revalidation",
      ],
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
    issuer_key_id: "signer-key:physical-composition",
    issuer_epoch: 7,
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

  function sign(receiptKind, payloadInput, signedAt = new Date().toISOString()) {
    const payload = receiptKind === "physical_surface_transition"
      ? normalizePhysicalSurfaceTransitionPayload(payloadInput)
      : normalizePhysicalSurfaceLiveRevalidationPayload(payloadInput);
    const envelopeBase = {
      issuer_registry_digest: registry.registry_digest,
      issuer_key_id: "signer-key:physical-composition",
      issuer_epoch: 7,
    };
    const semanticDigest = hashCanonicalJson({
      domain: "hacker-bob/durable-evidence-receipt-semantic/v1",
      version: 1,
      receipt_kind: receiptKind,
      payload,
      ...envelopeBase,
    });
    const envelope = {
      ...envelopeBase,
      semantic_digest: semanticDigest,
      signature_scheme: "ed25519",
      signed_at: signedAt,
    };
    const signatureInput = hashCanonicalJson({
      domain: "hacker-bob/durable-evidence-receipt/v1",
      version: 1,
      receipt_kind: receiptKind,
      payload,
      ...envelope,
    });
    const signed = {
      version: 1,
      receipt_kind: receiptKind,
      payload,
      ...envelope,
      signature: crypto.sign(
        null,
        Buffer.from(signatureInput, "hex"),
        keys.privateKey,
      ).toString("base64url"),
    };
    const receiptDigest = hashCanonicalJson(signed);
    const prefix = receiptKind === "physical_surface_transition"
      ? "surface-transition"
      : "surface-live-state";
    const receipt = Object.freeze({
      ...signed,
      receipt_digest: receiptDigest,
      receipt_ref: `${prefix}:v1:${receiptDigest}`,
    });
    receiptsByRef.set(receipt.receipt_ref, receipt);
    receiptsBySemantic.set(semanticDigest, receipt);
    return receipt;
  }

  return { issuer, registry, receiptsByRef, sign };
}

function liveRevalidationPayload(request, transition, overrides = {}) {
  const now = Date.now();
  return {
    version: 1,
    surface_graph_schema_version: 2,
    target_domain: transition.target_domain,
    session_nucleus_hash: transition.session_nucleus_hash,
    authority_context_digest: request.authority_context_digest,
    transition_receipt_ref: request.transition_receipt_ref,
    transition_receipt_digest: request.transition_receipt_digest,
    transition_payload_digest: request.transition_payload_digest,
    challenge_nonce: request.challenge_nonce,
    claim_verdict_ref: transition.claim_verdict_ref,
    claim_verdict_hash: transition.claim_verdict_hash,
    verified_claim_projection_digest: transition.verified_claim_projection_digest,
    claim_verdict_signer_key_id: transition.claim_verdict_signer_key_id,
    claim_verdict_trust_root_epoch: transition.claim_verdict_trust_root_epoch,
    verifier_template_id: transition.verifier_template_id,
    verifier_template_version: transition.verifier_template_version,
    verifier_template_digest: transition.verifier_template_digest,
    decision_rule_digest: transition.decision_rule_digest,
    upstream_execution_identities: transition.upstream_execution_identities,
    upstream_context_digest: transition.upstream_context_digest,
    physical_state_epoch: transition.physical_state_epoch,
    physical_state_digest: transition.physical_state_digest,
    validity_kind: "live_capability",
    valid_from: transition.valid_from,
    expires_at: transition.expires_at,
    capability_instance_ref: transition.capability_instance_ref,
    custody_state_digest: transition.custody_state_digest,
    status: "current",
    revalidated_at: new Date(now - 5).toISOString(),
    revalidation_expires_at: new Date(Math.min(
      now + 10_000,
      Date.parse(transition.expires_at) - 1,
    )).toISOString(),
    ...overrides,
  };
}

async function setupComposition({
  topologyKind = "critical",
  assetId = "target:hotel-door-controller",
  sharedObserverDomain = false,
  validityKind = "historical_event",
  appendTransition = true,
  liveResolver = false,
} = {}) {
  const domain = uniqueDomain();
  const graphTopology = topology(domain, topologyKind, assetId);
  const authority = transitionAuthority();
  const fixture = await createProductionPhysicalVerdictFixture({
    structural_mechanism_a: true,
    target_domain: domain,
    transition_receipt_registry_digest: authority.registry.registry_digest,
    claim_predicate_digest: physicalSurfaceTransitionClaimPredicateDigest(graphTopology),
    shared_observer_independence_domain: sharedObserverDomain,
    validity_kind: validityKind,
  });
  const finding = buildPhysicalFinding({
    title: "Candidate physical transition",
    severity: "critical",
    description: "Candidate narrative is not trusted for composition.",
    impact: "Candidate impact is not trusted for composition.",
    verdict: fixture.verdict,
  });
  const receipt = await authority.issuer.issuePhysicalSurfaceTransition({
    verified_claim_projection: fixture.projection,
    target_domain: domain,
    participants: graphTopology.participants,
    arcs: graphTopology.arcs,
  });
  const serviceInput = {
    target_domain: domain,
    resolve_receipt({ receipt_ref: receiptRef }) {
      return authority.receiptsByRef.get(receiptRef) || null;
    },
    resolve_trust_registry({ issuer_registry_digest: registryDigest }) {
      return registryDigest === authority.registry.registry_digest ? authority.registry : null;
    },
  };
  if (liveResolver) {
    serviceInput.resolve_live_revalidation_receipt = (request) => authority.sign(
      "physical_surface_live_revalidation",
      liveRevalidationPayload(request, receipt.payload),
    );
  }
  const service = createPhysicalSurfaceGraphServerService(serviceInput);
  if (appendTransition) {
    service.appendVerifiedTransition({
      receipt_ref: receipt.receipt_ref,
      receipt_digest: receipt.receipt_digest,
    });
  }
  const port = createProductionPhysicalCompositionPort({
    version: 1,
    surface_graph_service: service,
    production_experiment_ledgers: [fixture.ledger],
  });
  const uninstall = installPhysicalCompositionPort(port);
  return {
    authority,
    domain,
    finding,
    fixture,
    graphTopology,
    port,
    receipt,
    service,
    cleanup() {
      uninstall();
      fixture.cleanup();
    },
  };
}

test("historical physical composition derives only exact verified reachability and a bounded critical ceiling", async (t) => {
  const setup = await setupComposition();
  try {
    assert.equal(physicalCompositionRuntimeReadiness(setup.domain).production_ready, true);
    assert.equal(physicalCompositionRuntimeReadiness(setup.domain).live_capability_ready, false);
    assert.throws(
      () => setup.service.queryVerifiedTransitionEdges({
        verdict_ref: setup.finding.verified_verdict_ref,
      }),
      /must be supplied together/u,
    );
    assert.equal(setup.service.queryVerifiedTransitionEdges({
      verdict_ref: "physical-claim-verdict:not-the-finding",
      verified_claim_projection_digest: digest("not-the-finding"),
      limit: 1000,
    }).total_matched, 0);
    const projection = buildPhysicalCompositionProjection(setup.domain, setup.finding);
    assert.equal(assertPhysicalCompositionProjection(projection).transition_receipt_digest,
      setup.receipt.receipt_digest);
    assert.equal(projection.historical_fact_only, true);
    assert.equal(projection.live_capability_current, false);
    assert.equal(projection.plan_hash, setup.fixture.projection.plan_hash);
    assert.equal(
      projection.execution_request_digest,
      setup.fixture.projection.execution_request_digest,
    );
    assert.equal(projection.verifier_template_id, setup.fixture.projection.verifier_template_id);
    assert.equal(
      projection.verifier_template_digest,
      setup.fixture.projection.verifier_template_digest,
    );
    assert.equal(projection.transition_signer_key_id, "signer-key:physical-composition");
    assert.equal(projection.transition_trust_root_epoch, 7);
    assert.equal(projection.transition_edge_count, 2);
    assert.match(projection.transition_edge_set_digest, /^[a-f0-9]{64}$/u);
    assert.equal(projection.reachable_node_count, 2);
    assert.equal(projection.reachable_edge_count, 2);
    assert.deepEqual(projection.reachable_node_type_counts, {
      control_point: 1,
      network_attachment: 1,
    });
    assert.deepEqual(projection.blast_radius_categories, ["control", "network"]);
    assert.equal(projection.structural_severity_ceiling, "critical");
    assert.equal(projection.verified_severity_ceiling, "critical");
    assert.equal(projection.external_observer_independence_domain_count, 2);
    assert.equal(projection.high_impact_corroboration_satisfied, true);
    assert.equal(projection.observer_assurance_legacy_missing, false);
    assert.equal(projection.transition_leaves.length, 2);
    assert.ok(projection.transition_leaves.every((leaf) => (
      leaf.authority_inherited === false
      && leaf.downstream_authority_required === true
      && leaf.downstream_consumption_verified === false
      && leaf.prerequisite_eligible === false
    )));
    const grade = bindPhysicalSeverityToVerifiedBlastRadius(projection, "critical");
    assert.equal(grade.verified_severity, "critical");
    assert.equal(grade.blast_radius_class, "compound_control_plane");
    assert.equal(grade.composition_projection_digest, projection.composition_projection_digest);
    assert.equal(grade.transition_edge_set_digest, projection.transition_edge_set_digest);
    assert.equal(grade.downstream_consumption_verified, false);
    assert.match(grade.blast_radius_grade_binding_digest, /^[a-f0-9]{64}$/u);
    assert.equal(
      assertPhysicalBlastRadiusGradeBinding(grade).blast_radius_grade_binding_digest,
      grade.blast_radius_grade_binding_digest,
    );
  } finally {
    setup.cleanup();
  }
});

test("composition port refuses duck typing and cannot promote a caller-built service without production ledger trust", async (t) => {
  const setup = await setupComposition();
  try {
    assert.throws(
      () => createProductionPhysicalCompositionPort({
        version: 1,
        surface_graph_service: {
          ...setup.service,
          queryVerifiedTransitionEdges: () => ({ edges: [], total_matched: 0 }),
        },
        production_experiment_ledgers: [setup.fixture.ledger],
      }),
      /Bob-owned server service/u,
    );
    assert.throws(
      () => createProductionPhysicalCompositionPort({
        version: 1,
        surface_graph_service: setup.service,
        production_experiment_ledgers: [],
      }),
      /1\.\.1024 live ledgers/u,
    );
    assert.throws(
      () => createProductionPhysicalCompositionPort({
        version: 1,
        surface_graph_service: setup.service,
        production_experiment_ledgers: [setup.fixture.conformance_ledger],
      }),
      /live Bob-owned production composition/u,
    );
    assert.throws(
      () => createProductionPhysicalCompositionPort({
        version: 1,
        surface_graph_service: setup.service,
        production_experiment_ledgers: [{ ...setup.fixture.ledger }],
      }),
      /live Bob-owned production composition/u,
    );
    assert.throws(
      () => createProductionPhysicalCompositionPort({
        version: 1,
        surface_graph_service: setup.service,
        production_experiment_ledgers: [setup.fixture.ledger],
        trusted: true,
      }),
      /must carry exactly/u,
    );
  } finally {
    setup.cleanup();
  }
});

test("verified reachability still cannot bypass the independently durable campaign-closure gate", async (t) => {
  const setup = await setupComposition();
  try {
    const assignmentBody = {
      version: 1,
      capability_pack: "physical",
      capability_pack_version: 1,
      evaluator_agent: "evaluator-physical-agent",
      brief_profile: "physical",
      surface_id: "surface:composition-fixture",
      surface_type: "control_point",
      surface_class: "physical",
      session_nucleus_hash: setup.finding.session_nucleus_hash,
      asset_locator: setup.finding.asset_locator,
      campaign_ref: "physical-campaign:caller-projection",
      physical_resource_bundle_ref: "physical-resource-bundle:composition-fixture",
      lifecycle_precondition: "no_active_effects",
      effect_authority: "broker_admission_required",
    };
    const assignment = {
      ...assignmentBody,
      assignment_context_digest: derivePhysicalAssignmentContextDigest(assignmentBody),
    };
    const cellRef = "physical-cell:composition-fixture";
    const terminalWitnessDigest = deriveVerifiedPhysicalCoverageTerminalWitnessDigest({
      assignment_context_digest: assignment.assignment_context_digest,
      session_nucleus_hash: assignment.session_nucleus_hash,
      campaign_ref: assignment.campaign_ref,
      cell_ref: cellRef,
      asset_locator: assignment.asset_locator,
      verified_verdict_ref: setup.finding.verified_verdict_ref,
      verification_projection_digest: setup.finding.verification_projection_digest,
    });
    const callerCompletion = closePhysicalCoverage({
      version: 1,
      assignment,
      applicable_cell_refs: [cellRef],
      cells: [{
        version: 1,
        cell_ref: cellRef,
        assignment_context_digest: assignment.assignment_context_digest,
        asset_locator: assignment.asset_locator,
        technique_id: "fixture_technique",
        context_ref: "physical-context:composition-fixture",
        control_ref: "physical-control:composition-fixture",
        terminal_state: "verified",
        terminal_witness_digest: terminalWitnessDigest,
        verified_verdict_ref: setup.finding.verified_verdict_ref,
        verification_projection_digest: setup.finding.verification_projection_digest,
      }],
      active_effect_count: 0,
    });
    assert.equal(callerCompletion.production_ready, false);
    const composition = buildPhysicalCompositionProjection(setup.domain, setup.finding);
    const blastRadius = bindPhysicalSeverityToVerifiedBlastRadius(composition, "critical");
    assert.throws(
      () => buildPhysicalGradeBinding({
        finding: setup.finding,
        completion: callerCompletion,
        verified_severity: "critical",
        blast_radius_binding: blastRadius,
      }),
      /production-attested durable campaign/u,
    );
  } finally {
    setup.cleanup();
  }
});

test("ordinary or absent graph adjacency cannot become a verified physical transition", async (t) => {
  const setup = await setupComposition({ appendTransition: false });
  try {
    appendEdges({
      target_domain: setup.domain,
      edges: [{
        source: { type: "asset", id: setup.fixture.asset_locator },
        target: { type: "control_point", id: "control-point:caller-inferred" },
        edge_type: "controls",
        source_artifact: "caller-adjacency",
      }],
    });
    assert.throws(
      () => buildPhysicalCompositionProjection(setup.domain, setup.finding),
      /no exact verified SurfaceGraph transition receipt/u,
    );
  } finally {
    setup.cleanup();
  }
});

test("exact receipt selection rejects cross-asset and cross-session transition drift", async (t) => {
  const crossAsset = await setupComposition({ assetId: "asset:different-target" });
  try {
    assert.throws(
      () => buildPhysicalCompositionProjection(crossAsset.domain, crossAsset.finding),
      /does not bind the finding asset exactly once/u,
    );
  } finally {
    crossAsset.cleanup();
  }

  const crossSession = await setupComposition();
  try {
    const drifted = crossSession.authority.sign("physical_surface_transition", {
      ...crossSession.receipt.payload,
      session_nucleus_hash: digest("different-session-nucleus"),
    });
    assert.throws(
      () => crossSession.service.appendVerifiedTransition({
        receipt_ref: drifted.receipt_ref,
        receipt_digest: drifted.receipt_digest,
      }),
      /session nucleus drift/u,
    );
  } finally {
    crossSession.cleanup();
  }
});

test("authority-epoch or revocation-generation drift invalidates composition through the canonical nucleus", async (t) => {
  const setup = await setupComposition();
  try {
    const issuedProjection = buildPhysicalCompositionProjection(setup.domain, setup.finding);
    const issuedGrade = bindPhysicalSeverityToVerifiedBlastRadius(issuedProjection, "critical");
    const nucleusFile = sessionPath(setup.domain, "session-nucleus.json");
    const current = JSON.parse(fs.readFileSync(nucleusFile, "utf8"));
    const { axis_digest: _oldAxisDigest, ...axis } = current.physical_scope;
    const physicalScope = normalizePhysicalScopeNucleusAxis({
      ...axis,
      authority_epoch: axis.authority_epoch + 1,
      revocation_generation: axis.revocation_generation + 1,
    });
    const successor = buildSessionNucleus({
      ...current,
      physical_scope: physicalScope,
    });
    fs.writeFileSync(nucleusFile, `${JSON.stringify(successor, null, 2)}\n`, "utf8");
    assert.throws(
      () => buildPhysicalCompositionProjection(setup.domain, setup.finding),
      /session nucleus|drift|trust head/u,
    );
    assert.throws(
      () => assertPhysicalCompositionProjection(issuedProjection),
      /session nucleus|drift|trust head/u,
    );
    assert.throws(
      () => assertPhysicalBlastRadiusGradeBinding(issuedGrade),
      /session nucleus|drift|trust head/u,
    );
  } finally {
    setup.cleanup();
  }
});

test("tampered persisted arcs are rejected even when the local record digest is recomputed", async (t) => {
  const setup = await setupComposition();
  try {
    const graphFile = sessionPath(setup.domain, "surface-graph.jsonl");
    const records = fs.readFileSync(graphFile, "utf8").trim().split("\n").map(JSON.parse);
    const tampered = {
      ...records[0],
      target: { type: "control_point", id: "control-point:redirected" },
    };
    const { record_digest: _oldRecordDigest, ...body } = tampered;
    tampered.record_digest = hashCanonicalJson(body);
    fs.writeFileSync(
      graphFile,
      `${[tampered, ...records.slice(1)].map((row) => JSON.stringify(row)).join("\n")}\n`,
      "utf8",
    );
    assert.throws(
      () => buildPhysicalCompositionProjection(setup.domain, setup.finding),
      /arc drift/u,
    );
  } finally {
    setup.cleanup();
  }
});

test("high impact requires two observer domains and critical requires sufficient verified radius", async (t) => {
  const uncorroborated = await setupComposition({
    topologyKind: "high",
    sharedObserverDomain: true,
  });
  try {
    const projection = buildPhysicalCompositionProjection(
      uncorroborated.domain,
      uncorroborated.finding,
    );
    assert.equal(projection.external_observer_independence_domain_count, 1);
    assert.equal(projection.high_impact_corroboration_satisfied, false);
    assert.equal(projection.structural_severity_ceiling, "high");
    assert.equal(projection.verified_severity_ceiling, "medium");
    assert.throws(
      () => bindPhysicalSeverityToVerifiedBlastRadius(projection, "high"),
      /at least two independently enrolled external observer domains/u,
    );
  } finally {
    uncorroborated.cleanup();
  }

  const insufficientRadius = await setupComposition({ topologyKind: "high" });
  try {
    const projection = buildPhysicalCompositionProjection(
      insufficientRadius.domain,
      insufficientRadius.finding,
    );
    assert.equal(projection.verified_severity_ceiling, "high");
    assert.throws(
      () => bindPhysicalSeverityToVerifiedBlastRadius(projection, "critical"),
      /exceeds verified blast-radius ceiling high/u,
    );
  } finally {
    insufficientRadius.cleanup();
  }
});

test("disconnected verified arcs cannot inflate the finding's directed blast radius", async (t) => {
  const setup = await setupComposition({ topologyKind: "disconnected-critical" });
  try {
    const projection = buildPhysicalCompositionProjection(setup.domain, setup.finding);
    assert.equal(projection.transition_edge_count, 2);
    assert.equal(projection.reachable_edge_count, 1);
    assert.equal(projection.transition_leaves.length, 1);
    assert.deepEqual(projection.blast_radius_categories, ["control"]);
    assert.equal(projection.structural_severity_ceiling, "high");
    assert.equal(projection.verified_severity_ceiling, "high");
    assert.throws(
      () => bindPhysicalSeverityToVerifiedBlastRadius(projection, "critical"),
      /exceeds verified blast-radius ceiling high/u,
    );
  } finally {
    setup.cleanup();
  }
});

test("live-capability composition refuses projection before brand issuance without restart-durable trusted time", async () => {
  await assert.rejects(
    setupComposition({ validityKind: "live_capability" }),
    /restart-durable signed trusted-time validation/u,
  );
  await assert.rejects(
    setupComposition({ validityKind: "live_capability", liveResolver: true }),
    /restart-durable signed trusted-time validation/u,
  );
});
