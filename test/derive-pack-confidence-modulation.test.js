"use strict";

// Y-P16 — route.confidence modulates friction-widening eagerness inside
// derivePackForNode. A LOW-confidence surface widens from a single friction
// record (threshold 1); a HIGH-confidence surface under the SAME single
// record does NOT widen (threshold 3). Modulation only ever RAISES the bar
// for confident routes and only ADDS friction-derived tools — the
// absent-confidence default (threshold 1) is never LESS eager than the
// unconditional union (RANKED, not bounded).

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  derivePackForNode,
  widenThresholdForConfidence,
  FRICTION_WIDEN_THRESHOLD_BY_CONFIDENCE,
} = require("../mcp/lib/capability-pack-derivation.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
} = require("../mcp/lib/task-graph-events.js");

function surfaceNode(nodeId, surfaceId) {
  return {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}S-${nodeId}`,
    kind: "surface",
    surface_refs: [surfaceId],
  };
}

function ctxFor(surfaceId, meta) {
  return {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { [surfaceId]: meta },
  };
}

function frictionRecord(overrides) {
  return Object.assign({
    run_id: "run_abc",
    node_id: "TG-S-1",
    wanted_tool: "bob_aptos_run",
    friction_kind: "tool_absent",
    detected_by: "agent_self_report",
    surface_id: "s1",
    purpose: "fetch_target_response",
  }, overrides);
}

// Off-pack tool: NOT granted by the web/api pack by default, so its presence
// in allowed_tools_for_node[] can only come from friction widening.
const OFF_PACK_TOOL = "bob_aptos_run";

test("widenThresholdForConfidence maps low/medium/high and defaults to 1", () => {
  assert.equal(widenThresholdForConfidence("low"), 1);
  assert.equal(widenThresholdForConfidence("medium"), 2);
  assert.equal(widenThresholdForConfidence("high"), 3);
  assert.equal(widenThresholdForConfidence(null), 1);
  assert.equal(widenThresholdForConfidence(undefined), 1);
  assert.equal(widenThresholdForConfidence("bogus"), 1);
});

test("FRICTION_WIDEN_THRESHOLD_BY_CONFIDENCE matches the resolver + is frozen", () => {
  assert.equal(FRICTION_WIDEN_THRESHOLD_BY_CONFIDENCE.low, 1);
  assert.equal(FRICTION_WIDEN_THRESHOLD_BY_CONFIDENCE.medium, 2);
  assert.equal(FRICTION_WIDEN_THRESHOLD_BY_CONFIDENCE.high, 3);
  assert.ok(Object.isFrozen(FRICTION_WIDEN_THRESHOLD_BY_CONFIDENCE));
  for (const c of ["low", "medium", "high"]) {
    assert.equal(
      widenThresholdForConfidence(c),
      FRICTION_WIDEN_THRESHOLD_BY_CONFIDENCE[c],
      `resolver must echo the frozen literal for ${c}`,
    );
  }
});

test("THE DECISION FLIP: one friction record widens low-confidence, not high-confidence", () => {
  const node = surfaceNode("1", "s1");
  const single = { friction_history: [frictionRecord({ wanted_tool: OFF_PACK_TOOL })] };

  const lowPack = derivePackForNode(
    node,
    ctxFor("s1", { surface_type: "api", confidence: "low" }),
    [],
    null,
    single,
  );
  assert.ok(
    lowPack.allowed_tools_for_node.includes(OFF_PACK_TOOL),
    "a single friction record MUST widen a low-confidence surface (threshold 1)",
  );

  const highPack = derivePackForNode(
    node,
    ctxFor("s1", { surface_type: "api", confidence: "high" }),
    [],
    null,
    single,
  );
  assert.ok(
    !highPack.allowed_tools_for_node.includes(OFF_PACK_TOOL),
    "the SAME single friction record MUST NOT widen a high-confidence surface (threshold 3)",
  );
});

test("high-confidence surface DOES widen on 3 distinct (6-tuple-distinct) records", () => {
  const node = surfaceNode("1", "s1");
  const pack = derivePackForNode(
    node,
    ctxFor("s1", { surface_type: "api", confidence: "high" }),
    [],
    null,
    {
      friction_history: [
        frictionRecord({ wanted_tool: OFF_PACK_TOOL, friction_kind: "tool_absent", detected_by: "agent_self_report", purpose: "p1" }),
        frictionRecord({ wanted_tool: OFF_PACK_TOOL, friction_kind: "tool_absent", detected_by: "mcp_runtime_auto_emit", purpose: "p2" }),
        frictionRecord({ wanted_tool: OFF_PACK_TOOL, friction_kind: "tool_absent", detected_by: "agent_self_report", purpose: "p3", run_id: "run_other" }),
      ],
    },
  );
  assert.ok(
    pack.allowed_tools_for_node.includes(OFF_PACK_TOOL),
    "3 distinct friction records for the same tool MUST widen even a high-confidence surface",
  );
});

test("RANKED back-compat: absent confidence + single record still widens (default threshold 1)", () => {
  const node = surfaceNode("1", "s1");
  const pack = derivePackForNode(
    node,
    ctxFor("s1", { surface_type: "api" }),
    [],
    null,
    { friction_history: [frictionRecord({ wanted_tool: OFF_PACK_TOOL })] },
  );
  assert.ok(
    pack.allowed_tools_for_node.includes(OFF_PACK_TOOL),
    "no confidence must default to the eager threshold 1 — never LESS eager than the unconditional union",
  );
});

test("brief_emphasis.route_confidence echoes the resolved confidence", () => {
  const node = surfaceNode("1", "s1");
  const highPack = derivePackForNode(
    node,
    ctxFor("s1", { surface_type: "api", confidence: "high" }),
    [],
    null,
    {},
  );
  assert.equal(highPack.brief_emphasis.route_confidence, "high");

  const barePack = derivePackForNode(
    node,
    ctxFor("s1", { surface_type: "api" }),
    [],
    null,
    {},
  );
  assert.equal(
    barePack.brief_emphasis.route_confidence,
    null,
    "absent confidence resolves to null in brief_emphasis",
  );
});
