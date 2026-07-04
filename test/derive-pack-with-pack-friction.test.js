"use strict";

// derivePackForNode PACK-level friction-aggregate widening tests.
//
// A chronic pack deficiency (aggregated across every surface routed to a pack)
// widens that pack's derived allowed_tools_for_node[] for EVERY surface routed
// to it — not just the surface that happened to hit the friction. The aggregate
// is the caller-side pack-friction rollup (frontier-events.js#aggregateFrictionByPack)
// keyed by capability_pack id → { wanted_tool → { count, surface_ids } }; the
// deriver consumes it as a pure input via options.pack_friction_aggregate.
//
// Coverage:
//   (a) a chronic aggregated deficiency widens a surface whose OWN
//       friction_history is empty (cross-surface propagation);
//   (b) a second surface routed to the SAME pack also gets the widened tool;
//   (c) a below-threshold count does NOT widen (noise floor);
//   (d) an UNROUTABLE surface (smart_contract w/o chain_family) stays on the
//       evaluator-shared baseline and is NOT widened to web;
//   (e) determinism (three calls JSON.stringify-equal);
//   (f) back-compat (omitting pack_friction_aggregate == current result).

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  PACK_FRICTION_CHRONIC_MIN_COUNT,
  derivePackForNode,
} = require("../mcp/lib/capability-pack-derivation.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
} = require("../mcp/lib/task-graph-events.js");
const {
  buildWaveBriefDerivation,
} = require("../mcp/lib/wave-brief-derivation.js");
const {
  routeSurfacesInternal,
} = require("../mcp/lib/surface-router.js");
const {
  sessionDir,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-pack-friction-wave-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function uniqueDomain(prefix) {
  return `${prefix}-${crypto.randomBytes(4).toString("hex")}.example`;
}

// A capability_friction_observed frontier event (the shape buildWaveBriefDerivation
// scans via capabilityFrictionPayloads).
function frictionEvent(surfaceId, wantedTool) {
  return {
    kind: "observation.recorded",
    payload: {
      observation_kind: "capability_friction_observed",
      run_id: "run_pack_wave",
      node_id: "TG-S-pack",
      wanted_tool: wantedTool,
      friction_kind: "tool_absent",
      detected_by: "agent_self_report",
      surface_id: surfaceId,
      purpose: "fetch_target_response",
    },
  };
}

function webSurfaceNode(nodeId, surfaceId) {
  return {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}S-${nodeId}`,
    kind: "surface",
    surface_refs: [surfaceId],
  };
}

// A web-pack graph context: the surface routes to the DEFAULT web pack.
function webCtx(surfaceId) {
  return {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { [surfaceId]: { surface_type: "api" } },
  };
}

// A pack-friction aggregate mirroring aggregateFrictionByPack's real nested
// shape: { [pack_id]: { [wanted_tool]: { count, surface_ids } } }.
function aggregate(packId, wantedTool, count, surfaceIds) {
  return {
    [packId]: {
      [wantedTool]: { count, surface_ids: surfaceIds },
    },
  };
}

test("chronic pack deficiency widens a surface whose OWN friction_history is empty (cross-surface propagation)", () => {
  const node = webSurfaceNode("1", "surf1");
  // The aggregate says the web pack chronically lacks bob_aptos_run across
  // surfaces {surf7, surf8} — NEITHER of them is surf1. surf1's own friction
  // is empty, yet it must still receive the widened tool because it routes to
  // the same web pack.
  const agg = aggregate("web", "bob_aptos_run", PACK_FRICTION_CHRONIC_MIN_COUNT, ["surf7", "surf8"]);
  const pack = derivePackForNode(node, webCtx("surf1"), [], null, {
    friction_history: [],
    pack_friction_aggregate: agg,
  });
  assert.ok(
    pack.allowed_tools_for_node.includes("bob_aptos_run"),
    "chronic pack-level wanted_tool MUST widen a sibling surface with empty per-surface friction",
  );
  assert.equal(pack.brief_emphasis.pack_friction_widened_tools_count, 1);
  // The list itself (single source for the wave-brief added_tools fold) rides
  // alongside the count, sorted/deduped.
  assert.deepEqual(pack.brief_emphasis.pack_friction_widened_tools, ["bob_aptos_run"]);
});

test("a second surface routed to the SAME pack also gets the widened tool", () => {
  const agg = aggregate("web", "bob_aptos_run", PACK_FRICTION_CHRONIC_MIN_COUNT, ["surf7", "surf8"]);
  const nodeA = webSurfaceNode("A", "surfA");
  const nodeB = webSurfaceNode("B", "surfB");
  const packA = derivePackForNode(nodeA, webCtx("surfA"), [], null, { pack_friction_aggregate: agg });
  const packB = derivePackForNode(nodeB, webCtx("surfB"), [], null, { pack_friction_aggregate: agg });
  assert.ok(packA.allowed_tools_for_node.includes("bob_aptos_run"), "surfA widened");
  assert.ok(packB.allowed_tools_for_node.includes("bob_aptos_run"), "surfB (same pack) widened too");
});

test("below-threshold aggregate count does NOT widen (noise floor)", () => {
  const node = webSurfaceNode("1", "surf1");
  const agg = aggregate("web", "bob_aptos_run", PACK_FRICTION_CHRONIC_MIN_COUNT - 1, ["surf7"]);
  const pack = derivePackForNode(node, webCtx("surf1"), [], null, {
    pack_friction_aggregate: agg,
  });
  assert.ok(
    !pack.allowed_tools_for_node.includes("bob_aptos_run"),
    "a one-off (below-threshold) pack friction must NOT widen — it is noise, not a chronic deficiency",
  );
  assert.equal(pack.brief_emphasis.pack_friction_widened_tools_count, 0);
});

test("an UNROUTABLE surface stays on the evaluator-shared baseline and is NOT widened to web", () => {
  // A smart_contract surface with NO chain_family is unroutable:
  // deriveSurfacePack returns capability_pack_ids: [] and the evaluator-shared
  // baseline. A non-empty aggregate keyed by "web" must not reach it (it has no
  // pack id to look up), and the baseline read-only tools must still be present.
  const node = webSurfaceNode("sc", "surfSC");
  const ctx = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { surfSC: { surface_type: "smart_contract" } },
  };
  const agg = aggregate("web", "bob_aptos_run", PACK_FRICTION_CHRONIC_MIN_COUNT + 5, ["surf7", "surf8"]);
  const pack = derivePackForNode(node, ctx, [], null, {
    pack_friction_aggregate: agg,
  });
  assert.deepEqual(
    pack.brief_emphasis.capability_pack_ids,
    [],
    "unroutable smart_contract surface has no capability pack id",
  );
  assert.ok(
    !pack.allowed_tools_for_node.includes("bob_aptos_run"),
    "the web-keyed aggregate tool must NOT reach an unroutable surface (no web fallback)",
  );
  assert.equal(pack.brief_emphasis.pack_friction_widened_tools_count, 0);
  assert.deepEqual(
    pack.brief_emphasis.pack_friction_widened_tools,
    [],
    "an unroutable surface widens no pack tool — the list is empty",
  );
  // Baseline read-only evaluator-shared tools remain present (unroutable-never-web).
  assert.ok(
    pack.allowed_tools_for_node.includes("bob_read_assignment_brief"),
    "unroutable surface keeps its evaluator-shared baseline tools",
  );
});

test("PACK widening is deterministic (three calls JSON.stringify-equal)", () => {
  const node = webSurfaceNode("1", "surf1");
  // Multiple chronic tools + a below-threshold one, to exercise the sort path.
  const agg = {
    web: {
      bob_aptos_run: { count: PACK_FRICTION_CHRONIC_MIN_COUNT + 3, surface_ids: ["surf7", "surf8"] },
      bob_sui_run: { count: PACK_FRICTION_CHRONIC_MIN_COUNT + 1, surface_ids: ["surf7", "surf8"] },
      bob_svm_fetch_program: { count: PACK_FRICTION_CHRONIC_MIN_COUNT - 1, surface_ids: ["surf9"] },
    },
  };
  const opts = { pack_friction_aggregate: agg };
  const a = JSON.stringify(derivePackForNode(node, webCtx("surf1"), [], null, opts));
  const b = JSON.stringify(derivePackForNode(node, webCtx("surf1"), [], null, opts));
  const c = JSON.stringify(derivePackForNode(node, webCtx("surf1"), [], null, opts));
  assert.equal(a, b);
  assert.equal(b, c);
});

test("back-compat: omitting pack_friction_aggregate equals the current 4-/5-arg result", () => {
  const node = webSurfaceNode("1", "surf1");
  const ctx = webCtx("surf1");
  const fourArg = derivePackForNode(node, ctx, [], null);
  const fiveArgNoAgg = derivePackForNode(node, ctx, [], null, { friction_history: [] });
  const fiveArgEmptyAgg = derivePackForNode(node, ctx, [], null, {
    friction_history: [],
    pack_friction_aggregate: {},
  });
  assert.equal(fourArg.brief_emphasis.pack_friction_widened_tools_count, 0);
  assert.deepEqual(fourArg.brief_emphasis.pack_friction_widened_tools, []);
  assert.deepEqual(fourArg.allowed_tools_for_node, fiveArgNoAgg.allowed_tools_for_node);
  assert.deepEqual(fourArg.allowed_tools_for_node, fiveArgEmptyAgg.allowed_tools_for_node);
  assert.equal(fiveArgEmptyAgg.brief_emphasis.pack_friction_widened_tools_count, 0);
  assert.deepEqual(fiveArgEmptyAgg.brief_emphasis.pack_friction_widened_tools, []);
});

test("a tool wanted BOTH per-surface and pack-level appears once (idempotence / no double-count)", () => {
  const node = webSurfaceNode("1", "surf1");
  const agg = aggregate("web", "bob_aptos_run", PACK_FRICTION_CHRONIC_MIN_COUNT, ["surf7", "surf8"]);
  const pack = derivePackForNode(node, webCtx("surf1"), [], null, {
    friction_history: [
      {
        run_id: "run_abc",
        node_id: "TG-S-1",
        wanted_tool: "bob_aptos_run",
        friction_kind: "tool_absent",
        detected_by: "agent_self_report",
        surface_id: "surf1",
        purpose: "fetch_target_response",
      },
    ],
    pack_friction_aggregate: agg,
  });
  const occurrences = pack.allowed_tools_for_node.filter((t) => t === "bob_aptos_run");
  assert.equal(occurrences.length, 1, "tool wanted per-surface AND pack-level appears exactly once");
});

test("a single surface's repeated friction does NOT widen the pack (chronic = across surfaces)", () => {
  const node = webSurfaceNode("1", "surf1");
  // High record count but only ONE surface_id: a single surface hitting the same
  // missing tool repeatedly is not a systematic PACK deficiency, so it must not
  // widen the pack for its sibling surfaces.
  const agg = aggregate("web", "bob_aptos_run", PACK_FRICTION_CHRONIC_MIN_COUNT + 5, ["surf7"]);
  const pack = derivePackForNode(node, webCtx("surf1"), [], null, { pack_friction_aggregate: agg });
  assert.deepEqual(pack.brief_emphasis.pack_friction_widened_tools, [], "single-surface friction does not pack-widen");
  assert.ok(!pack.allowed_tools_for_node.includes("bob_aptos_run"), "the tool is not added pack-wide from one surface");
});

test("buildWaveBriefDerivation folds the deriver's pack-widened tool into added_tools[] (WAVE path, single-sourced)", () => {
  withTempHome(() => {
    // Two api surfaces routed to the SAME web pack. The surface under test
    // (surfA) has NO friction of its own; the chronic deficiency lives on
    // sibling surfaces (surfB, surfC) — >= PACK_FRICTION_CHRONIC_MIN_COUNT
    // friction events for bob_aptos_run against the shared web pack. The pack
    // aggregate is joined caller-side from the frontier events + persisted
    // routes, so seeding routes on disk + passing sibling friction events is
    // enough to make the widened tool reach surfA's wave brief via the
    // added_tools fold (NOT via surfA's own friction).
    const domain = uniqueDomain("pack-wave");
    const surfA = "web-a";
    const surfB = "web-b";
    const surfC = "web-c";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    const surfaces = [
      { id: surfA, surface_type: "api", hosts: [`https://a.${domain}`], title: "A", tech_stack: ["Express"], endpoints: ["/api/a"] },
      { id: surfB, surface_type: "api", hosts: [`https://b.${domain}`], title: "B", tech_stack: ["Express"], endpoints: ["/api/b"] },
      { id: surfC, surface_type: "api", hosts: [`https://c.${domain}`], title: "C", tech_stack: ["Express"], endpoints: ["/api/c"] },
    ];
    routeSurfacesInternal(domain, { attackSurfaceInfo: { source: "agent", document: { surfaces } } });

    // >= PACK_FRICTION_CHRONIC_MIN_COUNT sibling frictions clear the noise floor.
    const frontierEvents = [];
    frontierEvents.push(frictionEvent(surfB, "bob_aptos_run"));
    frontierEvents.push(frictionEvent(surfC, "bob_aptos_run"));
    assert.ok(frontierEvents.length >= PACK_FRICTION_CHRONIC_MIN_COUNT);

    const derivation = buildWaveBriefDerivation({
      surfaceObj: surfaces[0],
      surfaceId: surfA,
      waveNumber: 1,
      frontierEvents,
      queuePolicy: null,
      domain,
      explicitTargetClass: null,
      includeInadequacy: false,
    });

    // surfA's OWN friction is empty, yet the pack-widened tool must appear in
    // added_tools[] — folded from derivation.brief_emphasis via the deriver,
    // single-sourced (no threshold re-derived in the caller).
    assert.equal(
      derivation.friction_history_count,
      0,
      "surfA has no per-surface friction — the tool can only arrive via the pack fold",
    );
    assert.ok(
      derivation.added_tools.includes("bob_aptos_run"),
      "the chronic pack-widened tool MUST appear in the wave brief's added_tools[]",
    );
  });
});
