"use strict";

// Plane Y Cycle Y.4 — derivePackForNode friction-history extension tests.
//
// Y.4 ships:
//   - Optional `friction_history` parameter on derivePackForNode (Y-P6).
//   - mcp/lib/friction-selection.js exporting selectRelevantFrictions —
//     the caller-side bounded selector that Y.5 wave scheduler threads
//     into derivation.
//
// Coverage per Y.4 Reviewer bullets:
//   1. derivePackForNode UNIONs friction_history[].wanted_tool into
//      allowed_tools_for_node[] (Y-P6 widen-before-attach).
//   2. selectRelevantFrictions wave-scopes by surface_id and bounds the
//      slice to friction_history hard cap (32).
//   3. tool_absent vs tool_inadequate remain distinct (no merge, Y-P11).
//   4. tool_inadequate is QUARANTINED by default (Y-P11), surfaces only
//      when options.include_inadequacy === true.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  FRICTION_HISTORY_HARD_CAP,
  derivePackForNode,
} = require("../mcp/lib/capability-pack-derivation.js");
const {
  selectRelevantFrictions,
  DEFAULT_LIMIT,
} = require("../mcp/lib/friction-selection.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
} = require("../mcp/lib/task-graph-events.js");

function webSurfaceNode(nodeId, surfaceId) {
  return {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}S-${nodeId}`,
    kind: "surface",
    surface_refs: [surfaceId],
  };
}

function frictionRecord(overrides) {
  return Object.assign({
    run_id: "run_abc",
    node_id: "TG-S-1",
    wanted_tool: "bob_browser_navigate",
    friction_kind: "tool_absent",
    detected_by: "agent_self_report",
    surface_id: "surf1",
    purpose: "fetch_target_response",
  }, overrides);
}

test("derivePackForNode UNIONs friction wanted_tool into allowed_tools_for_node[] (Y-P6)", () => {
  const node = webSurfaceNode("1", "surf1");
  const ctx = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { surf1: { surface_type: "api" } },
  };
  // A friction asks for `bob_aptos_run` — a tool the web pack does NOT
  // grant by default. The Y-P6 widening folds it in.
  const pack = derivePackForNode(node, ctx, [], null, {
    friction_history: [
      frictionRecord({ wanted_tool: "bob_aptos_run" }),
    ],
  });
  assert.ok(
    pack.allowed_tools_for_node.includes("bob_aptos_run"),
    "wanted_tool from friction_history MUST appear in allowed_tools_for_node[]",
  );
});

test("derivePackForNode treats friction_history as optional (back-compat: positional call still works)", () => {
  const node = webSurfaceNode("1", "surf1");
  const ctx = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { surf1: { surface_type: "api" } },
  };
  // Old four-arg signature — no options object.
  const pack = derivePackForNode(node, ctx, [], null);
  assert.ok(Array.isArray(pack.allowed_tools_for_node), "allowed_tools_for_node[] still present");
  assert.equal(pack.brief_emphasis.friction_history_count, 0);
  assert.equal(pack.brief_emphasis.target_class, null);
});

test("derivePackForNode caps friction_history at FRICTION_HISTORY_HARD_CAP (Y-P4)", () => {
  const node = webSurfaceNode("1", "surf1");
  const ctx = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { surf1: { surface_type: "api" } },
  };
  const overlong = [];
  for (let i = 0; i < FRICTION_HISTORY_HARD_CAP + 8; i++) {
    overlong.push(frictionRecord({ wanted_tool: `bob_tool_${i}` }));
  }
  const pack = derivePackForNode(node, ctx, [], null, { friction_history: overlong });
  // The cap is applied to friction_history.length, so brief_emphasis sees the capped count.
  assert.equal(
    pack.brief_emphasis.friction_history_count,
    FRICTION_HISTORY_HARD_CAP,
    "friction_history capped at FRICTION_HISTORY_HARD_CAP",
  );
});

test("derivePackForNode is deterministic when friction_history is supplied (3 calls bit-identical)", () => {
  const node = webSurfaceNode("1", "surf1");
  const ctx = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { surf1: { surface_type: "api" } },
  };
  const fh = [frictionRecord({ wanted_tool: "bob_aptos_run" })];
  const a = JSON.stringify(derivePackForNode(node, ctx, [], null, { friction_history: fh }));
  const b = JSON.stringify(derivePackForNode(node, ctx, [], null, { friction_history: fh }));
  const c = JSON.stringify(derivePackForNode(node, ctx, [], null, { friction_history: fh }));
  assert.equal(a, b);
  assert.equal(b, c);
});

test("selectRelevantFrictions wave-scopes to surface_refs (Y-P5)", () => {
  const node = webSurfaceNode("1", "surf1");
  const all = [
    frictionRecord({ surface_id: "surf1", wanted_tool: "bob_a" }),
    frictionRecord({ surface_id: "surf2", wanted_tool: "bob_b" }),
    frictionRecord({ surface_id: "surf1", wanted_tool: "bob_c", run_id: "run_xyz" }),
  ];
  const selected = selectRelevantFrictions(all, node, {});
  assert.equal(selected.length, 2);
  assert.deepEqual(
    selected.map((r) => r.wanted_tool).sort(),
    ["bob_a", "bob_c"],
    "surf2 friction excluded (not in node.surface_refs)",
  );
});

test("selectRelevantFrictions dedupes by Y-P3 5-tuple", () => {
  const node = webSurfaceNode("1", "surf1");
  const dup = frictionRecord({ wanted_tool: "bob_x" });
  const all = [dup, { ...dup }, { ...dup }];
  const selected = selectRelevantFrictions(all, node, {});
  assert.equal(selected.length, 1, "three identical 5-tuples collapse to one");
});

test("selectRelevantFrictions keeps tool_absent + tool_inadequate distinct (Y-P11)", () => {
  const node = webSurfaceNode("1", "surf1");
  const all = [
    frictionRecord({
      friction_kind: "tool_absent",
      wanted_tool: "bob_aptos_run",
    }),
    frictionRecord({
      friction_kind: "tool_inadequate",
      wanted_tool: "bob_aptos_run",
    }),
  ];
  // tool_inadequate excluded by default (Y-P11 quarantine).
  const defaultSelected = selectRelevantFrictions(all, node, {});
  assert.equal(defaultSelected.length, 1);
  assert.equal(defaultSelected[0].friction_kind, "tool_absent");
  // With include_inadequacy: true both surface, distinct records.
  const includedSelected = selectRelevantFrictions(all, node, { include_inadequacy: true });
  assert.equal(includedSelected.length, 2);
  const kinds = includedSelected.map((r) => r.friction_kind).sort();
  assert.deepEqual(kinds, ["tool_absent", "tool_inadequate"]);
});

test("selectRelevantFrictions clamps limit to [1, DEFAULT_LIMIT]", () => {
  const node = webSurfaceNode("1", "surf1");
  const all = [];
  for (let i = 0; i < 64; i++) {
    all.push(frictionRecord({ wanted_tool: `bob_tool_${i}`, run_id: `run_${i}` }));
  }
  // Caller asks for 999 — must be clamped to DEFAULT_LIMIT (32).
  const clampedHigh = selectRelevantFrictions(all, node, { limit: 999 });
  assert.equal(clampedHigh.length, DEFAULT_LIMIT);
  // Caller asks for 0 — must be clamped to 1.
  const clampedLow = selectRelevantFrictions(all, node, { limit: 0 });
  assert.equal(clampedLow.length, 1);
});

test("selectRelevantFrictions returns empty array on non-array input", () => {
  const node = webSurfaceNode("1", "surf1");
  assert.deepEqual(selectRelevantFrictions(null, node, {}), []);
  assert.deepEqual(selectRelevantFrictions(undefined, node, {}), []);
  assert.deepEqual(selectRelevantFrictions({}, node, {}), []);
});

test("selectRelevantFrictions throws when node is not an object", () => {
  assert.throws(() => selectRelevantFrictions([], null, {}), /node must be an object/);
  assert.throws(() => selectRelevantFrictions([], "TG-S-1", {}), /node must be an object/);
});

test("friction with no surface_id is excluded from selection (Y-P5)", () => {
  const node = webSurfaceNode("1", "surf1");
  const all = [
    frictionRecord({ surface_id: undefined, wanted_tool: "bob_no_surface" }),
    frictionRecord({ wanted_tool: "bob_with_surface" }),
  ];
  const selected = selectRelevantFrictions(all, node, {});
  assert.equal(selected.length, 1);
  assert.equal(selected[0].wanted_tool, "bob_with_surface");
});
