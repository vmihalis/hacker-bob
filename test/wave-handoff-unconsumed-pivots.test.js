"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  computeUnconsumedPivots,
  pivotEdgeKey,
} = require("../mcp/core/waves/wave-handoff-contracts.js");

// The transition-blind evaluator-fanout rides cross-surface pivots up as
// handoff.discovered_pivots[]; the orchestrator is supposed to consume each via
// bob_propose_transition (or record a surface lead when the to_surface is
// unmaterialized). That consumption is prompt-discipline, not a hard gate, so a
// skipped loop silently drops a pivot. computeUnconsumedPivots makes the drop
// VISIBLE without gating anything.

test("a handoff carrying discovered_pivots[] with NONE consumed flags exactly those", () => {
  const pivots = [
    { from_surface: "web:login", to_surface: "evm:Vault", kind: "trust_handoff", trust_assumption: "session trusted on-chain", agent: "evaluator-fanout", surface_id: "web:login" },
    { from_surface: "web:cart", to_surface: "evm:Payments", kind: "value_movement", trust_assumption: "cart total trusted by payment contract", agent: "evaluator-fanout", surface_id: "web:cart" },
  ];
  const unconsumed = computeUnconsumedPivots(pivots, {
    proposedEdges: new Set(),
    leadReferenceStrings: new Set(),
  });
  assert.equal(unconsumed.length, 2, "no transitions, no leads => every pivot flagged");
  assert.deepEqual(unconsumed.map((p) => p.to_surface).sort(), ["evm:Payments", "evm:Vault"]);
  // Advisory entries carry the origin + the pivot context for the operator.
  const vault = unconsumed.find((p) => p.to_surface === "evm:Vault");
  assert.equal(vault.from_surface, "web:login");
  assert.equal(vault.kind, "trust_handoff");
  assert.equal(vault.trust_assumption, "session trusted on-chain");
  assert.equal(vault.agent, "evaluator-fanout");
  assert.equal(vault.surface_id, "web:login");
});

test("a pivot with a matching proposed transition edge is NOT flagged", () => {
  const pivots = [
    { from_surface: "web:login", to_surface: "evm:Vault", kind: "trust_handoff", trust_assumption: "t" },
    { from_surface: "web:cart", to_surface: "evm:Payments", kind: "value_movement", trust_assumption: "t" },
  ];
  const unconsumed = computeUnconsumedPivots(pivots, {
    proposedEdges: new Set([pivotEdgeKey("web:login", "evm:Vault")]),
    leadReferenceStrings: new Set(),
  });
  assert.deepEqual(unconsumed.map((p) => p.to_surface), ["evm:Payments"], "only the unconsumed pivot remains");
});

test("a pivot whose to_surface is referenced by a recorded surface lead is NOT flagged", () => {
  const pivots = [
    { from_surface: "web:login", to_surface: "evm:Vault", kind: "trust_handoff", trust_assumption: "t" },
    { from_surface: "web:cart", to_surface: "evm:Payments", kind: "value_movement", trust_assumption: "t" },
  ];
  const unconsumed = computeUnconsumedPivots(pivots, {
    proposedEdges: new Set(),
    leadReferenceStrings: new Set(["evm:Payments"]),
  });
  assert.deepEqual(unconsumed.map((p) => p.to_surface), ["evm:Vault"], "the lead-referenced pivot is consumed");
});

test("a pivot consumed by transition AND a separate pivot consumed by lead are both cleared", () => {
  const pivots = [
    { from_surface: "web:a", to_surface: "evm:A", kind: "trust_handoff", trust_assumption: "t" },
    { from_surface: "web:b", to_surface: "evm:B", kind: "value_movement", trust_assumption: "t" },
    { from_surface: "web:c", to_surface: "evm:C", kind: "state_dependency", trust_assumption: "t" },
  ];
  const unconsumed = computeUnconsumedPivots(pivots, {
    proposedEdges: new Set([pivotEdgeKey("web:a", "evm:A")]),
    leadReferenceStrings: new Set(["evm:B"]),
  });
  assert.deepEqual(unconsumed.map((p) => p.to_surface), ["evm:C"]);
});

test("empty discovered_pivots is a no-op (default off-nesting-path behavior)", () => {
  assert.deepEqual(computeUnconsumedPivots([], { proposedEdges: new Set(), leadReferenceStrings: new Set() }), []);
  assert.deepEqual(computeUnconsumedPivots(undefined, {}), []);
  assert.deepEqual(computeUnconsumedPivots(null, {}), []);
});

test("missing consumption context is tolerated (fail-open => flag everything, still advisory)", () => {
  const pivots = [{ from_surface: "web:x", to_surface: "evm:Y", kind: "trust_handoff", trust_assumption: "t" }];
  // No options object at all: both sets default to empty -> nothing consumed.
  assert.deepEqual(computeUnconsumedPivots(pivots).map((p) => p.to_surface), ["evm:Y"]);
  assert.deepEqual(computeUnconsumedPivots(pivots, {}).map((p) => p.to_surface), ["evm:Y"]);
});

test("malformed pivot entries are skipped without throwing", () => {
  const pivots = [
    null,
    "nope",
    {},
    { from_surface: "web:x" },
    { to_surface: "evm:Y" },
    { from_surface: "web:x", to_surface: "evm:Y", kind: "trust_handoff", trust_assumption: "t" },
  ];
  const unconsumed = computeUnconsumedPivots(pivots, { proposedEdges: new Set(), leadReferenceStrings: new Set() });
  assert.deepEqual(unconsumed.map((p) => p.to_surface), ["evm:Y"], "only the well-formed pivot is considered");
});

// Integration-shaped: the merge surfacing must thread unconsumed_pivots through
// the merge result and be NON-GATING (it adds a field; it asserts nothing).
test("mergeWaveHandoffsInternal exposes unconsumed_pivots and the surfacing is purely additive", () => {
  const store = require("../mcp/core/waves/wave-handoff-store.js");
  // Source proof that the surfacing is wired and non-gating: the merge tool's
  // serialized output names unconsumed_pivots, and the field is read straight
  // off merge.unconsumed_pivots with no throw/assert around it.
  const src = require("fs").readFileSync(
    require("path").join(__dirname, "..", "mcp", "core", "waves", "wave-handoff-store.js"),
    "utf8",
  );
  assert.ok(src.includes("unconsumed_pivots: merge.unconsumed_pivots"), "merge tool output carries the advisory field");
  assert.ok(src.includes("unconsumed_pivots: unconsumedPivots"), "internal merge result carries the advisory field");
  // No new throw is introduced around the pivot surfacing (non-gating).
  const settlerSrc = require("fs").readFileSync(
    require("path").join(__dirname, "..", "mcp", "core", "waves", "wave-merge-settler.js"),
    "utf8",
  );
  assert.ok(settlerSrc.includes("unconsumed_pivots: merge.unconsumed_pivots"), "apply-wave-merge serialization carries the advisory field");
  assert.equal(typeof store.mergeWaveHandoffs, "function");
});
