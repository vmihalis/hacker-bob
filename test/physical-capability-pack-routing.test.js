"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  CAPABILITY_PACKS,
  PHYSICAL_CAPABILITY_PACK,
  PHYSICAL_CAPABILITY_PACK_UNAVAILABLE_REASON,
  PHYSICAL_SURFACE_TYPES,
  capabilityPackForLegacyFinding,
  classifySurfaceCapability,
  dispatchableCapabilityPacks,
  evaluatorAgentNamesForCapabilityPacks,
  getCapabilityPack,
  getCapabilityPackContextBudget,
  isCapabilityPackDispatchable,
  normalizeAssignmentRouteMetadata,
  techniqueCompatibilityPackId,
} = require("../mcp/core/capability/capability-packs.js");
const {
  EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK,
  derivePackForNode,
  routabilityForSurfaceMetadata,
} = require("../mcp/core/capability/capability-pack-derivation.js");
const {
  safeSurfaceRouteMap,
  surfaceMetadataFromRoute,
} = require("../mcp/core/dispatch/dispatch-node-pack.js");
const {
  buildSurfaceRoutesDocument,
  validateSurfaceRoute,
} = require("../mcp/core/frontier/surface-router.js");
const {
  getContextBudget,
} = require("../mcp/core/context-budget.js");
const {
  SURFACE_TYPE_VALUES,
} = require("../mcp/lib/constants.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
} = require("../mcp/core/waves/task-graph-events.js");
const {
  replayExecutionPolicy,
} = require("../mcp/core/verification/verification-replay-safety.js");
const {
  renderCapabilityPackVerifierTable,
} = require("../mcp/core/capability-packs-rendering.js");
const {
  appendFrontierEvent,
} = require("../mcp/core/frontier/frontier-events.js");
const {
  materializeFrontier,
} = require("../mcp/core/frontier/frontier-materializer.js");
const {
  currentSurfaces,
} = require("../mcp/core/frontier/frontier-projections.js");
const {
  buildWaveBriefDerivation,
} = require("../mcp/core/waves/wave-brief-derivation.js");
const {
  appendHypothesisProposal,
  readNodeTransitions,
} = require("../mcp/core/waves/task-graph-events.js");
const {
  materializeTaskGraph,
} = require("../mcp/core/waves/task-graph-materializer.js");
const {
  appendContract,
} = require("../mcp/core/contract/contracts.js");
const {
  sessionNucleusPath,
  surfaceRoutesPath,
} = require("../mcp/core/io/paths.js");
const {
  writeFileAtomic,
} = require("../mcp/core/io/storage.js");
const {
  TOOL_HANDLERS,
} = require("../mcp/core/dispatch/tool-registry.js");
const {
  buildSessionNucleus,
} = require("../mcp/core/governance/governance-contracts.js");
const {
  normalizePhysicalScopeNucleusAxis,
} = require("../mcp/lib/physical-scope-axis.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-physical-routing-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function physicalAttackSurface(surface) {
  return {
    source: "test_fixture",
    path: null,
    document: { surfaces: [surface] },
  };
}

function physicalSurfaceNode(surfaceId) {
  return {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}S-physical-routing`,
    kind: "surface",
    state: "proposed",
    surface_refs: [surfaceId],
    contract_hash: null,
    severity_floor: null,
    priority: "medium",
    ts_first: "2026-07-19T00:00:00.000Z",
    ts_last: "2026-07-19T00:00:00.000Z",
    source_events: ["FE-physical-routing-fixture"],
  };
}

test("physical is a provider-neutral registered capability family with dedicated staged consumers", () => {
  assert.equal(CAPABILITY_PACKS.physical, PHYSICAL_CAPABILITY_PACK);
  assert.equal(getCapabilityPack("physical"), PHYSICAL_CAPABILITY_PACK);
  assert.ok(Object.isFrozen(PHYSICAL_CAPABILITY_PACK));
  assert.ok(Object.isFrozen(PHYSICAL_CAPABILITY_PACK.role_bundles));
  assert.equal(PHYSICAL_CAPABILITY_PACK.surface_class, "physical");
  assert.equal(PHYSICAL_CAPABILITY_PACK.dispatchable, false);
  assert.equal(PHYSICAL_CAPABILITY_PACK.dispatch_block_reason, PHYSICAL_CAPABILITY_PACK_UNAVAILABLE_REASON);
  assert.deepEqual(PHYSICAL_CAPABILITY_PACK.role_bundles, ["evaluator-physical"]);
  assert.equal(PHYSICAL_CAPABILITY_PACK.evaluator_agent, "evaluator-physical-agent");
  assert.equal(PHYSICAL_CAPABILITY_PACK.brief_profile, "physical");
  assert.equal(PHYSICAL_CAPABILITY_PACK.completion_gate, "physical_campaign_terminal_cells_v1");
  for (const field of [
    "context_budget",
    "verifier",
    "evidence",
    "spawn",
    "assignment",
    "coverage",
    "finding",
    "verdict",
    "grade",
    "proof",
    "report",
    "composition",
  ]) {
    assert.ok(PHYSICAL_CAPABILITY_PACK[field], `${field} must have a dedicated physical consumer`);
  }
  assert.deepEqual(PHYSICAL_CAPABILITY_PACK.finding.forbidden_web_fields, [
    "base_url",
    "endpoint",
    "proof_of_concept",
  ]);
  assert.equal(PHYSICAL_CAPABILITY_PACK.verdict.production_backend_available, false);
  assert.equal(PHYSICAL_CAPABILITY_PACK.verdict.invokes_hardware, false);
  assert.equal(isCapabilityPackDispatchable("physical"), false);
  assert.ok(!dispatchableCapabilityPacks().includes(PHYSICAL_CAPABILITY_PACK));
  assert.equal(Object.hasOwn(EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK, "physical"), false);
  assert.equal(techniqueCompatibilityPackId("physical"), null);
  assert.equal(getCapabilityPackContextBudget("physical"), null);
  assert.ok(evaluatorAgentNamesForCapabilityPacks().every((name) => typeof name === "string" && name.length > 0));
  assert.equal(replayExecutionPolicy().some((entry) => entry.capability_pack === "physical"), false);
  assert.match(renderCapabilityPackVerifierTable(), /\| `physical` \| `bob_verify_physical_candidate_claim` \|/);

  const serialized = JSON.stringify(PHYSICAL_CAPABILITY_PACK);
  assert.doesNotMatch(serialized, /chameleon|hotel|keycard|rfid|unifi/i);
  assert.deepEqual(JSON.parse(serialized), PHYSICAL_CAPABILITY_PACK);
});

test("known, future, and explicit physical markers all classify fail-closed and never as web", () => {
  const physicalSignals = [
    { surface_type: "physical" },
    { surface_type: "asset" },
    { surface_type: "physical_future_medium" },
    { surface_type: "unknown", surface_class: "physical" },
    { surface_type: "api", capability_pack: "physical" },
    { surface_type: "api", required_capability_pack: "physical" },
    { surface_type: "physical_future_medium", capability_pack: "web" },
    { surface_type: "api", surface_class: "physical", capability_pack: "web" },
  ];

  assert.ok(PHYSICAL_SURFACE_TYPES.includes("asset"), "SurfaceGraph physical ontology must feed routing");
  for (const surface of physicalSignals) {
    const classified = classifySurfaceCapability(surface);
    assert.equal(classified.surface_class, "physical", JSON.stringify(surface));
    assert.equal(classified.routable, false, JSON.stringify(surface));
    assert.equal(classified.capability_pack, null, JSON.stringify(surface));
    assert.equal(classified.required_capability_pack, "physical", JSON.stringify(surface));
    assert.equal(
      classified.required_capability_pack_version,
      PHYSICAL_CAPABILITY_PACK.capability_pack_version,
      JSON.stringify(surface),
    );
    assert.equal(classified.evaluator_agent, null, JSON.stringify(surface));
    assert.equal(classified.brief_profile, null, JSON.stringify(surface));
    assert.equal(classified.context_budget, null, JSON.stringify(surface));
    assert.equal(classified.unroutable_reason, PHYSICAL_CAPABILITY_PACK_UNAVAILABLE_REASON);
    assert.equal(new Set(classified.reasons).size, classified.reasons.length, "classification reasons must be unique");

    const routing = routabilityForSurfaceMetadata(surface);
    assert.equal(routing.routable, false, JSON.stringify(surface));
    assert.equal(routing.pack_id, null, JSON.stringify(surface));
    assert.equal(routing.required_pack_id, "physical", JSON.stringify(surface));
  }

  const ordinaryUnknown = classifySurfaceCapability({ surface_type: "future_api_protocol" });
  assert.equal(ordinaryUnknown.routable, true);
  assert.equal(ordinaryUnknown.capability_pack, "web");
  assert.equal(new Set(ordinaryUnknown.reasons).size, ordinaryUnknown.reasons.length);
});

test("physical route serialization is disposition-only, stable, and validates its required pack marker", () => {
  const document = buildSurfaceRoutesDocument("physical-routing.example.test", {
    attackSurfaceInfo: physicalAttackSurface({
      id: "surface:physical:door",
      surface_type: "physical_future_access_medium",
    }),
  });
  assert.equal(document.routes.length, 1);
  const route = document.routes[0];
  assert.equal(route.disposition, "unroutable");
  assert.equal(route.surface_class, "physical");
  assert.equal(route.required_capability_pack, "physical");
  assert.equal(route.required_capability_pack_version, PHYSICAL_CAPABILITY_PACK.capability_pack_version);
  assert.equal(route.reason, PHYSICAL_CAPABILITY_PACK_UNAVAILABLE_REASON);
  for (const field of ["capability_pack", "evaluator_agent", "brief_profile", "context_budget"]) {
    assert.equal(Object.hasOwn(route, field), false, `${field} must not be serialized onto a physical disposition`);
  }
  assert.deepEqual(JSON.parse(JSON.stringify(document)), document);
  assert.deepEqual(validateSurfaceRoute(route, 0, "surface-routes.json"), route);

  assert.throws(
    () => validateSurfaceRoute({ ...route, required_capability_pack_version: 2 }, 0, "surface-routes.json"),
    /required_capability_pack_version 2 does not match pack physical/,
  );
  assert.throws(
    () => validateSurfaceRoute({ ...route, required_capability_pack: "web" }, 0, "surface-routes.json"),
    /required_capability_pack web is dispatchable/,
  );
  assert.throws(
    () => validateSurfaceRoute({ ...route, evaluator_agent: "evaluator-web-agent" }, 0, "surface-routes.json"),
    /evaluator_agent must be absent for required_capability_pack physical/,
  );
  assert.throws(
    () => validateSurfaceRoute({ ...route, required_capability_pack: undefined }, 0, "surface-routes.json"),
    /required_capability_pack and required_capability_pack_version must be provided together/,
  );
  assert.throws(
    () => validateSurfaceRoute({ ...route, required_capability_pack_version: undefined }, 0, "surface-routes.json"),
    /required_capability_pack and required_capability_pack_version must be provided together/,
  );
  assert.throws(
    () => validateSurfaceRoute({
      surface_id: route.surface_id,
      surface_type: route.surface_type,
      surface_class: "physical",
      disposition: "unroutable",
      reason: route.reason,
    }, 0, "surface-routes.json"),
    /surface_class physical requires required_capability_pack physical and its version/,
  );
  assert.throws(
    () => validateSurfaceRoute({ ...route, surface_class: "web" }, 0, "surface-routes.json"),
    /physical surface metadata requires surface_class physical/,
  );
  assert.throws(
    () => validateSurfaceRoute({ ...route, surface_class: undefined }, 0, "surface-routes.json"),
    /physical surface metadata requires surface_class physical/,
  );
  assert.throws(
    () => validateSurfaceRoute({
      surface_id: route.surface_id,
      surface_type: "physical_future_medium",
      disposition: "unroutable",
      reason: route.reason,
    }, 0, "surface-routes.json"),
    /physical surface metadata requires surface_class physical/,
  );
});

test("physical surfaces receive no TaskGraph evaluator tools while their required family remains auditable", () => {
  const surfaceId = "surface:physical:unknown-medium";
  const result = derivePackForNode(physicalSurfaceNode(surfaceId), {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      [surfaceId]: {
        id: surfaceId,
        surface_type: "physical_unknown_medium",
      },
    },
  }, [], null);

  assert.deepEqual(result.brief_emphasis.capability_pack_ids, []);
  assert.deepEqual(result.allowed_tools_for_node, []);
  assert.equal(result.brief_emphasis.capability_pack, null);
  assert.equal(result.brief_emphasis.required_capability_pack, "physical");
  assert.equal(
    result.brief_emphasis.required_capability_pack_version,
    PHYSICAL_CAPABILITY_PACK.capability_pack_version,
  );
  assert.equal(result.brief_emphasis.routable, false);

  for (const options of [
    { friction_history: [{ wanted_tool: "bob_http_scan" }] },
    { target_class: "phishing_fraud" },
    {
      friction_history: [{ wanted_tool: "bob_http_scan" }],
      target_class: "phishing_fraud",
    },
  ]) {
    const overlaid = derivePackForNode(physicalSurfaceNode(surfaceId), {
      adjacent_nodes: [],
      incident_edges: [],
      surface_metadata_by_id: {
        [surfaceId]: { id: surfaceId, surface_type: "physical_unknown_medium" },
      },
    }, [], null, options);
    assert.deepEqual(overlaid.allowed_tools_for_node, [], JSON.stringify(options));
    assert.deepEqual(overlaid.technique_packs, [], JSON.stringify(options));
    assert.equal(overlaid.brief_emphasis.physical_dispatch_blocked, true);
  }
});

test("dispatch metadata preserves physical deny markers and blocks every physical-connected node kind", () => {
  const physicalId = "surface:physical-marker-on-api";
  const webId = "surface:web-endpoint";
  const physicalMetadata = surfaceMetadataFromRoute({
    surface_id: physicalId,
    surface_type: "api",
    surface_class: "physical",
    disposition: "unroutable",
    reason: PHYSICAL_CAPABILITY_PACK_UNAVAILABLE_REASON,
    required_capability_pack: "physical",
    required_capability_pack_version: PHYSICAL_CAPABILITY_PACK.capability_pack_version,
  });
  assert.equal(physicalMetadata.surface_class, "physical");
  assert.equal(physicalMetadata.required_capability_pack, "physical");
  assert.equal(physicalMetadata.disposition, "unroutable");
  assert.equal(routabilityForSurfaceMetadata(physicalMetadata).routable, false);

  const graphContext = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      [physicalId]: physicalMetadata,
      [webId]: { id: webId, surface_type: "api", capability_pack: "web" },
    },
  };
  const nodes = [
    { node_id: "TG-S-physical-marker", kind: "surface", surface_refs: [physicalId] },
    { node_id: "TG-T-physical-marker", kind: "transition", surface_refs: [webId, physicalId] },
    { node_id: "TG-H-physical-marker", kind: "hypothesis", surface_refs: [physicalId] },
    { node_id: "TG-C-physical-marker", kind: "cell", surface_refs: [physicalId] },
    { node_id: "TG-C-physical-transition-marker", kind: "cell", surface_refs: [webId, physicalId] },
  ];
  for (const node of nodes) {
    const result = derivePackForNode(node, graphContext, [], null, {
      friction_history: [{ wanted_tool: "bob_http_scan" }],
      target_class: "phishing_fraud",
    });
    assert.deepEqual(result.allowed_tools_for_node, [], node.kind);
    assert.deepEqual(result.technique_packs, [], node.kind);
    assert.deepEqual(result.brief_emphasis.capability_pack_ids, [], node.kind);
    assert.deepEqual(result.brief_emphasis.endpoint_capability_packs || [], [], node.kind);
    assert.equal(result.brief_emphasis.required_capability_pack, "physical", node.kind);
    assert.equal(result.brief_emphasis.routable, false, node.kind);
    assert.equal(result.brief_emphasis.physical_dispatch_blocked, true, node.kind);
    assert.deepEqual(result.brief_emphasis.physical_surface_refs, [physicalId], node.kind);
  }
});

test("physical deny provenance survives frontier projection and cannot be widened back to web", () => {
  withTempHome(() => {
    const domain = "physical-projection-roundtrip.example.test";
    const surfaceId = "surface:api-shaped-physical";
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      surface_id: surfaceId,
      payload: {
        title: "API-shaped physical control",
        surface_type: "api",
        surface_class: "physical",
        required_capability_pack: "physical",
        required_capability_pack_version: PHYSICAL_CAPABILITY_PACK.capability_pack_version,
        disposition: "unroutable",
        reason: PHYSICAL_CAPABILITY_PACK_UNAVAILABLE_REASON,
      },
    });
    materializeFrontier(domain, { write: true });

    const projected = currentSurfaces(domain).document.surfaces.find(
      (surface) => surface.id === surfaceId,
    );
    assert.ok(projected);
    assert.equal(projected.surface_type, "api");
    assert.equal(projected.surface_class, "physical");
    assert.equal(projected.required_capability_pack, "physical");
    assert.equal(
      projected.required_capability_pack_version,
      PHYSICAL_CAPABILITY_PACK.capability_pack_version,
    );
    assert.equal(projected.disposition, "unroutable");

    const route = buildSurfaceRoutesDocument(domain).routes[0];
    assert.equal(route.surface_class, "physical");
    assert.equal(route.capability_pack, undefined);
    assert.equal(route.required_capability_pack, "physical");
    assert.equal(route.disposition, "unroutable");

    const wave = buildWaveBriefDerivation({
      domain,
      surfaceId,
      surfaceObj: projected,
      waveNumber: 1,
      frontierEvents: [{
        kind: "observation.recorded",
        surface_id: surfaceId,
        payload: {
          observation_kind: "capability_friction_observed",
          surface_id: surfaceId,
          friction_kind: "tool_inadequate",
          wanted_tool: "bob_http_scan",
        },
      }],
      explicitTargetClass: "phishing_fraud",
      includeInadequacy: true,
    });
    assert.equal(wave.dispatch_blocked, true);
    assert.equal(wave.physical_dispatch_blocked, true);
    assert.equal(wave.capability_pack, null);
    assert.deepEqual(wave.added_tools, []);
    assert.deepEqual(wave.target_class_auxiliary_tools, []);
    assert.deepEqual(wave.technique_pack_ids, []);
  });
});

test("a quarantined physical route becomes an explicit deny tombstone", () => {
  withTempHome(() => {
    const domain = "physical-route-quarantine.example.test";
    const surfaceId = "surface:quarantined-physical";
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      surface_id: surfaceId,
      payload: {
        surface_type: "api",
        surface_class: "physical",
      },
    });
    materializeFrontier(domain, { write: true });
    writeFileAtomic(surfaceRoutesPath(domain), `${JSON.stringify({
      version: 1,
      route_version: 1,
      routes: [{
        surface_id: surfaceId,
        surface_type: "api",
        surface_class: "physical",
        capability_pack: "web",
        capability_pack_version: 1,
        evaluator_agent: "evaluator-agent",
        brief_profile: "web",
        context_budget: { candidate_pack_limit: 5, full_pack_read_limit: 2, attempt_log_required: true },
      }],
    }, null, 2)}\n`);

    const metadata = safeSurfaceRouteMap(domain)[surfaceId];
    assert.ok(metadata);
    assert.equal(metadata.route_metadata_status, "quarantined");
    assert.equal(metadata.dispatch_blocked, true);
    assert.equal(metadata.surface_class, "physical");
    assert.equal(metadata.capability_pack, null);
    assert.equal(metadata.required_capability_pack, "physical");

    const result = derivePackForNode(physicalSurfaceNode(surfaceId), {
      adjacent_nodes: [],
      incident_edges: [],
      surface_metadata_by_id: { [surfaceId]: metadata },
    }, [], null, {
      friction_history: [{ wanted_tool: "bob_http_scan" }],
      target_class: "phishing_fraud",
    });
    assert.deepEqual(result.allowed_tools_for_node, []);
    assert.deepEqual(result.technique_packs, []);
    assert.equal(result.brief_emphasis.physical_dispatch_blocked, true);
  });
});

test("public prepare-node refuses a physical-bound graph node before dispatch mutation", () => {
  withTempHome(() => {
    const domain = "physical-routing-prepare.example.test";
    const surfaceId = "surface:physical-marker-on-api";
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-07-19T00:00:00.000Z",
      surface_id: surfaceId,
      payload: { title: "opaque physical fixture", surface_type: "api" },
    });
    appendHypothesisProposal({
      target_domain: domain,
      ts: "2026-07-19T00:01:00.000Z",
      hypothesis_statement: "A physical transition may affect an adjacent control.",
      surface_refs: [surfaceId],
      proposal_id: "physical-routing-refusal",
    });
    materializeTaskGraph(domain, { write: true });
    const nodeId = `${TASK_GRAPH_NODE_ID_PREFIX}H-physical-routing-refusal`;
    appendContract({
      target_domain: domain,
      node_id: nodeId,
      ts: "2026-07-19T00:02:00.000Z",
      contract: {
        contract_id: "C-physical-routing-refusal",
        severity_floor: "high",
        invariants: [{ id: "I1", statement: "No physical effect is dispatched through a web evaluator." }],
        witnesses: [{
          id: "W1",
          kind: "tool_output_match",
          predicate: { tool: "bob_http_scan", match: { path: "$.status", equals: 200 } },
        }],
        production_paths: [{
          description: "Hostile web-shaped path that physical deny precedence must suppress.",
          tool_call_pattern: [{ tool: "bob_http_scan" }],
        }],
      },
    });
    materializeTaskGraph(domain, { write: true });
    writeFileAtomic(surfaceRoutesPath(domain), `${JSON.stringify({
      version: 1,
      route_version: 1,
      routes: [{
        surface_id: surfaceId,
        surface_type: "api",
        surface_class: "physical",
        disposition: "unroutable",
        reason: PHYSICAL_CAPABILITY_PACK_UNAVAILABLE_REASON,
        confidence: "high",
        reasons: ["surface_class:physical"],
        required_capability_pack: "physical",
        required_capability_pack_version: PHYSICAL_CAPABILITY_PACK.capability_pack_version,
      }],
    }, null, 2)}\n`);

    assert.throws(
      () => TOOL_HANDLERS.bob_prepare_node({ target_domain: domain, node_id: nodeId }),
      (error) => error.code === "physical_capability_pack_unavailable",
    );
    assert.equal(
      readNodeTransitions(domain).some((row) => (
        row.node_id === nodeId && row.payload && row.payload.to_state === "dispatched"
      )),
      false,
      "physical refusal must occur before the ready/dispatched state mutation",
    );
  });
});

test("verified physical-only nucleus keeps missing route metadata fail-closed", () => {
  withTempHome(() => {
    const domain = `physical-${"b".repeat(24)}`;
    const surfaceId = "surface:route-artifact-missing";
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-07-19T00:00:00.000Z",
      surface_id: surfaceId,
      payload: { title: "opaque physical surface" },
    });
    const axis = normalizePhysicalScopeNucleusAxis({
      version: 1,
      physical_enabled: true,
      policy_version: 1,
      policy_id: "physical_routing_test",
      policy_digest: "1".repeat(64),
      projection_version: 1,
      projection_digest: "2".repeat(64),
      provenance_digest: "3".repeat(64),
      compatibility_digest: "4".repeat(64),
      transition_receipt_registry_digest: "5".repeat(64),
      authority_epoch: 1,
      revocation_generation: 0,
    });
    const nucleus = buildSessionNucleus({
      target_domain: domain,
      scope_policy: {
        target_domain: domain,
        checkpoint_mode: "normal",
        block_internal_hosts: false,
        block_internal_hosts_source: "mode_default",
      },
      physical_scope: axis,
      egress_identity: { egress_profile: "default", proxy_configured: false },
      auth_context: { auth_status: "pending" },
      operator_constraint: { handoff_provenance_required: true },
      lifecycle_state: "SETUP",
    });
    writeFileAtomic(sessionNucleusPath(domain), `${JSON.stringify(nucleus, null, 2)}\n`);

    appendHypothesisProposal({
      target_domain: domain,
      ts: "2026-07-19T00:01:00.000Z",
      hypothesis_statement: "Missing route metadata must not recover the historical web default.",
      surface_refs: [surfaceId],
      proposal_id: "physical-missing-route-refusal",
    });
    materializeTaskGraph(domain, { write: true });
    const nodeId = `${TASK_GRAPH_NODE_ID_PREFIX}H-physical-missing-route-refusal`;
    appendContract({
      target_domain: domain,
      node_id: nodeId,
      ts: "2026-07-19T00:02:00.000Z",
      contract: {
        contract_id: "C-physical-missing-route-refusal",
        severity_floor: "high",
        invariants: [{ id: "I1", statement: "Physical-only authority never defaults to web dispatch." }],
        witnesses: [{
          id: "W1",
          kind: "tool_output_match",
          predicate: { tool: "bob_http_scan", match: { path: "$.status", equals: 200 } },
        }],
        production_paths: [{
          description: "Hostile caller-authored web production path.",
          tool_call_pattern: [{ tool: "bob_http_scan" }],
        }],
      },
    });
    materializeTaskGraph(domain, { write: true });
    assert.equal(fs.existsSync(surfaceRoutesPath(domain)), false, "fixture must exercise the missing-route path");
    assert.throws(
      () => TOOL_HANDLERS.bob_prepare_node({ target_domain: domain, node_id: nodeId }),
      (error) => error.code === "physical_capability_pack_unavailable",
    );
    assert.equal(
      readNodeTransitions(domain).some((row) => (
        row.node_id === nodeId && row.payload && row.payload.to_state === "dispatched"
      )),
      false,
    );
  });
});

test("assignment and context consumers reject physical until its pack-owned consumers exist", () => {
  for (const assignment of [
    { surface_type: "physical" },
    { surface_type: "api", surface_class: "physical" },
    { surface_type: "api", required_capability_pack: "physical" },
  ]) {
    assert.throws(
      () => normalizeAssignmentRouteMetadata(assignment),
      /physical surface metadata is missing a dispatchable capability_pack/,
    );
  }

  assert.throws(
    () => normalizeAssignmentRouteMetadata({
      surface_type: "physical",
      capability_pack: "physical",
      capability_pack_version: 1,
      evaluator_agent: "evaluator-web-agent",
      brief_profile: "web",
    }),
    /non-dispatchable capability_pack physical/,
  );
  assert.throws(
    () => normalizeAssignmentRouteMetadata({
      surface_type: "physical_future_medium",
      capability_pack: "web",
      capability_pack_version: 1,
      evaluator_agent: "evaluator-agent",
      brief_profile: "web",
    }),
    /physical surface metadata cannot bind active capability_pack web/,
  );
  assert.throws(
    () => getContextBudget({ capability_pack: "physical" }),
    /Unavailable capability_pack physical/,
  );
  assert.throws(
    () => validateSurfaceRoute({
      surface_id: "surface:physical:active-spoof",
      surface_type: "physical",
      capability_pack: "physical",
      capability_pack_version: 1,
      evaluator_agent: "evaluator-web-agent",
      brief_profile: "web",
    }, 0, "surface-routes.json"),
    /non-dispatchable capability_pack: physical/,
  );
  assert.throws(
    () => validateSurfaceRoute({
      surface_id: "surface:physical:web-spoof",
      surface_type: "physical_future_medium",
      capability_pack: "web",
      capability_pack_version: 1,
      evaluator_agent: "evaluator-agent",
      brief_profile: "web",
    }, 0, "surface-routes.json"),
    /physical surface metadata and cannot bind active capability_pack: web/,
  );
});

test("legacy physical findings never backfill to web and the finding schema remains unchanged", () => {
  for (const surfaceType of ["physical", "asset", "physical_future_medium"]) {
    assert.equal(capabilityPackForLegacyFinding({ surface_type: surfaceType }), null);
  }
  assert.equal(capabilityPackForLegacyFinding({ surface_type: "api" }).capability_pack, "web");
  assert.deepEqual(SURFACE_TYPE_VALUES, ["web", "smart_contract"]);
  assert.equal(SURFACE_TYPE_VALUES.includes("physical"), false);
});
