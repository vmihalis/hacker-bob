"use strict";

// Plane Y Cycle Y.4 (rev 4 — O5) — derivePackForNode target_class extension.
//
// Y.4 ships:
//   - mcp/lib/target-classes.js exporting the closed enum + assertion.
//   - mcp/lib/target-class-pack-derivation.js exporting
//     deriveAuxiliaryToolsForTargetClass — pure per-target_class
//     auxiliary tool table. phishing_fraud surfaces 4 tools; other
//     target_class values return empty.
//
// Coverage per Y.4 Reviewer bullets (rev 4 O5):
//   - target_class: "phishing_fraud" surfaces all four browser/public_intel
//     tools in allowed_tools_for_node[].
//   - target_class: "web_application" does NOT auto-include phishing-
//     specific tools (the bob_public_intel auxiliary is the distinctive
//     marker — phishing_fraud adds it, web_application does not).
//   - target_class unknown rejected (closed enum bounded input).
//   - TARGET_CLASS_VALUES is Object.freeze'd.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  TARGET_CLASS_VALUES,
  assertTargetClass,
} = require("../mcp/lib/target-classes.js");
const {
  AUXILIARY_TOOLS_BY_TARGET_CLASS,
  deriveAuxiliaryToolsForTargetClass,
} = require("../mcp/lib/target-class-pack-derivation.js");
const {
  derivePackForNode,
} = require("../mcp/lib/capability-pack-derivation.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
} = require("../mcp/lib/task-graph-events.js");

const PHISHING_AUX_TOOLS = [
  "bob_public_intel",
  "bob_browser_evaluate",
  "bob_browser_take_screenshot",
  "bob_browser_console_messages",
];

// The marker tool that uniquely identifies "phishing_fraud target_class
// fed into derivation" — bob_public_intel is NOT in the evaluator-shared
// or evaluator-web role bundles, so its presence is a positive proof.
const PHISHING_MARKER_TOOL = "bob_public_intel";

function webSurfaceNode(id, surfaceId) {
  return {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}S-${id}`,
    kind: "surface",
    surface_refs: [surfaceId],
  };
}

function webCtx(surfaceId) {
  return {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { [surfaceId]: { surface_type: "api" } },
  };
}

// ─── target-classes.js module ────────────────────────────────────────────

test("TARGET_CLASS_VALUES is Object.freeze'd (Y.4 Reviewer bullet)", () => {
  assert.ok(Object.isFrozen(TARGET_CLASS_VALUES));
  assert.throws(() => { TARGET_CLASS_VALUES.push("rogue"); });
});

test("TARGET_CLASS_VALUES contains the six closed values", () => {
  assert.deepEqual(
    [...TARGET_CLASS_VALUES].sort(),
    [
      "infrastructure",
      "mobile_app",
      "other",
      "phishing_fraud",
      "smart_contract",
      "web_application",
    ],
  );
});

test("assertTargetClass accepts every closed-enum value", () => {
  for (const v of TARGET_CLASS_VALUES) {
    assert.equal(assertTargetClass(v), v);
  }
});

test("assertTargetClass rejects unknown target_class", () => {
  assert.throws(() => assertTargetClass("rogue"), /not in the closed enum/);
  assert.throws(() => assertTargetClass(""), /must be a non-empty string/);
  assert.throws(() => assertTargetClass(null), /must be a non-empty string/);
  assert.throws(() => assertTargetClass(123), /must be a non-empty string/);
});

// ─── target-class-pack-derivation.js module ──────────────────────────────

test("AUXILIARY_TOOLS_BY_TARGET_CLASS is Object.freeze'd top + leaves", () => {
  assert.ok(Object.isFrozen(AUXILIARY_TOOLS_BY_TARGET_CLASS));
  for (const v of TARGET_CLASS_VALUES) {
    assert.ok(
      Object.isFrozen(AUXILIARY_TOOLS_BY_TARGET_CLASS[v]),
      `${v} leaf array must be frozen`,
    );
  }
});

test("phishing_fraud auxiliaries are exactly the four documented tools", () => {
  const tools = deriveAuxiliaryToolsForTargetClass("phishing_fraud");
  assert.deepEqual([...tools].sort(), [...PHISHING_AUX_TOOLS].sort());
});

test("smart_contract auxiliaries are empty (per-stack handled by capability_pack)", () => {
  const tools = deriveAuxiliaryToolsForTargetClass("smart_contract");
  assert.deepEqual([...tools], []);
});

test("web_application + mobile_app + infrastructure + other auxiliaries are empty", () => {
  for (const v of ["web_application", "mobile_app", "infrastructure", "other"]) {
    const tools = deriveAuxiliaryToolsForTargetClass(v);
    assert.deepEqual([...tools], [], `${v} auxiliaries must be empty`);
  }
});

test("deriveAuxiliaryToolsForTargetClass rejects unknown target_class (closed enum)", () => {
  assert.throws(() => deriveAuxiliaryToolsForTargetClass("not_a_real_class"), /not in the closed enum/);
  assert.throws(() => deriveAuxiliaryToolsForTargetClass(""), /non-empty string/);
});

// ─── derivePackForNode end-to-end ─────────────────────────────────────────

test("derivePackForNode with target_class: phishing_fraud surfaces all four aux tools", () => {
  const node = webSurfaceNode("1", "surf1");
  const ctx = webCtx("surf1");
  const pack = derivePackForNode(node, ctx, [], null, { target_class: "phishing_fraud" });
  for (const tool of PHISHING_AUX_TOOLS) {
    assert.ok(
      pack.allowed_tools_for_node.includes(tool),
      `phishing_fraud derivation MUST surface ${tool}`,
    );
  }
  assert.equal(pack.brief_emphasis.target_class, "phishing_fraud");
});

test("derivePackForNode with target_class: web_application does NOT auto-include phishing marker", () => {
  const node = webSurfaceNode("1", "surf1");
  const ctx = webCtx("surf1");
  const pack = derivePackForNode(node, ctx, [], null, { target_class: "web_application" });
  assert.equal(
    pack.allowed_tools_for_node.includes(PHISHING_MARKER_TOOL),
    false,
    "web_application MUST NOT auto-include bob_public_intel (phishing-specific marker)",
  );
  assert.equal(pack.brief_emphasis.target_class, "web_application");
});

test("derivePackForNode rejects unknown target_class through assertTargetClass", () => {
  const node = webSurfaceNode("1", "surf1");
  const ctx = webCtx("surf1");
  assert.throws(
    () => derivePackForNode(node, ctx, [], null, { target_class: "rogue_class" }),
    /not in the closed enum/,
  );
});

test("derivePackForNode without target_class option preserves prior behavior (no aux union)", () => {
  const node = webSurfaceNode("1", "surf1");
  const ctx = webCtx("surf1");
  const pack = derivePackForNode(node, ctx, [], null);
  assert.equal(pack.brief_emphasis.target_class, null);
  // bob_public_intel is the unique phishing marker; it must NOT appear by default.
  assert.equal(
    pack.allowed_tools_for_node.includes(PHISHING_MARKER_TOOL),
    false,
    "default derivation MUST NOT carry phishing marker",
  );
});

test("derivePackForNode is deterministic across target_class (3 calls bit-identical)", () => {
  const node = webSurfaceNode("1", "surf1");
  const ctx = webCtx("surf1");
  const a = JSON.stringify(derivePackForNode(node, ctx, [], null, { target_class: "phishing_fraud" }));
  const b = JSON.stringify(derivePackForNode(node, ctx, [], null, { target_class: "phishing_fraud" }));
  const c = JSON.stringify(derivePackForNode(node, ctx, [], null, { target_class: "phishing_fraud" }));
  assert.equal(a, b);
  assert.equal(b, c);
});
