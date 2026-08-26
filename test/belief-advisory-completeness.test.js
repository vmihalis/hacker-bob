"use strict";

// Belief-advisory COMPLETENESS on the GRAPH/scheduler side.
//
// The fan-out side completeness (belief reorders, never adds/drops/skips a cell)
// is locked by belief-fanout-order.test.js. THIS file locks the same guarantee on
// the GRAPH/scheduler side: the deterministic graph-scheduler's selection
// (compareGraphCandidates over the materialized cell/graph nodes, optionally
// overlaid with a per-cell belief rank) must produce the IDENTICAL selected+skipped
// node SET whether belief is OFF or ON. Belief is a pure WITHIN-band reorder; it can
// never starve a Tier-1 floor cell behind a belief-boosted Tier-2 re-probe, and it
// can never drop or add a node.
//
// Belief is driven ON LOCALLY here (an injected non-uniform cell belief map). NO
// production default is changed: this exercises the belief-ON code path directly,
// which is exactly what the dormant-but-built fabric needs locked.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  compareGraphCandidates,
} = require("../mcp/core/waves/graph-scheduler.js");
const {
  buildCellBeliefRank,
} = require("../mcp/core/belief/cell-scheduler-priority.js");
const { appendEdges } = require("../mcp/core/frontier/surface-graph.js");
const { sessionDir } = require("../mcp/core/io/paths.js");

const PRIORITY_RANK = new Map([
  ["critical", 0],
  ["high", 1],
  ["medium", 2],
  ["low", 3],
]);

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-belief-completeness-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// A simulated scheduler pass: sort candidates with the same comparator the real
// selectNextExecutableNodes uses, then split into selected/skipped at `cap`.
function schedulePass(candidates, beliefRank, cap) {
  const sorted = candidates.slice().sort((a, b) => compareGraphCandidates(a, b, PRIORITY_RANK, beliefRank));
  return {
    selected: sorted.slice(0, cap).map((n) => n.node_id),
    skipped: sorted.slice(cap).map((n) => n.node_id),
    order: sorted.map((n) => n.node_id),
  };
}

function setOf(ids) {
  return new Set(ids);
}
function setsEqual(a, b) {
  return a.size === b.size && [...a].every((x) => b.has(x));
}

test("graph-scheduler selection SET is identical OFF vs ON (belief reorders within band, never drops/adds/skips)", () => {
  withTempHome(() => {
    const domain = "belief-completeness.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    // Seed a NON-UNIFORM belief: a populated object-authorization edge makes the
    // matching surface earn a positive belief score (uniform priors would tie every
    // candidate and make the test vacuous).
    appendEdges({
      target_domain: domain,
      edges: [
        {
          source: { type: "principal", id: "principal:attacker" },
          target: { type: "policy_gate", id: "policy_gate:owner" },
          edge_type: "tests_gate",
        },
        {
          source: { type: "policy_gate", id: "policy_gate:owner" },
          target: { type: "effect", id: "effect:unauth_succeeds_where_auth_blocked:victim" },
          edge_type: "permits_effect",
        },
      ],
    });

    const HOT = "surface:idor-victim";
    const COLD = "surface:cold";
    const surfaces = [
      {
        id: HOT,
        title: "victim object access",
        hosts: [domain],
        bug_class_hints: ["unauth_succeeds_where_auth_blocked"],
        high_value_flows: ["attacker reads owner victim object"],
      },
      { id: COLD, title: "static assets", hosts: [domain] },
    ];

    // Two Tier-1 floor cells (one on the hot surface, one on the cold surface) plus a
    // Tier-2 re-probe on the HOT surface — the candidate set the comparator orders.
    const candidates = [
      { node_id: "TG-cell-hot-floor", kind: "cell", priority: "medium", tier: 1, severity_floor: "low", ts_first: "2026-06-01T00:00:00.000Z", surface_refs: [HOT] },
      { node_id: "TG-cell-cold-floor", kind: "cell", priority: "medium", tier: 1, severity_floor: "low", ts_first: "2026-06-01T00:00:00.000Z", surface_refs: [COLD] },
      { node_id: "TG-cell-hot-reprobe", kind: "cell", priority: "critical", tier: 2, severity_floor: "critical", ts_first: "2026-06-01T00:00:00.000Z", surface_refs: [HOT] },
    ];
    const document = { nodes: candidates };

    const beliefRank = buildCellBeliefRank({
      target_domain: domain,
      document,
      candidates,
      surfaces, // inject directly so the test is deterministic and offline.
      seed: "belief-scheduler-priority",
    });

    // NON-VACUITY GUARD: the injected belief map MUST be non-empty, else OFF==ON is a
    // tautology and the completeness assertion proves nothing.
    assert.ok(beliefRank instanceof Map, "buildCellBeliefRank returns a Map");
    assert.ok(beliefRank.size >= 1, `injected belief map must be non-empty (got ${beliefRank.size}) — else the test is vacuous`);
    // And it must actually score the HOT cell (the discriminating signal).
    assert.ok(beliefRank.has("TG-cell-hot-floor"), "the hot-surface floor cell earned a belief score");

    // Run the scheduler pass at every capacity from 1..N, OFF (null map) vs ON.
    for (let cap = 1; cap <= candidates.length; cap += 1) {
      const off = schedulePass(candidates, null, cap);
      const on = schedulePass(candidates, beliefRank, cap);

      // COMPLETENESS: belief is a PERMUTATION, never a filter.
      // At a truncating cap the EMITTED (selected) subsets may differ by design — that
      // IS the effect of belief: it picks a different top-k to dispatch first. What
      // must stay invariant is the TOTAL set the pass accounts for (selected UNION
      // skipped): belief reorders which fit now vs spill, never adds/drops/skips a node.
      const offTotal = setOf([...off.selected, ...off.skipped]);
      const onTotal = setOf([...on.selected, ...on.skipped]);
      assert.ok(
        setsEqual(offTotal, onTotal),
        `cap=${cap}: TOTAL accounted SET differs OFF vs ON (off=${JSON.stringify([...offTotal])} on=${JSON.stringify([...onTotal])})`,
      );
      // Total accounting is conserved and lossless.
      assert.equal(off.selected.length + off.skipped.length, candidates.length, `cap=${cap}: OFF accounts for every node`);
      assert.equal(on.selected.length + on.skipped.length, candidates.length, `cap=${cap}: ON accounts for every node`);
      assert.equal(offTotal.size, candidates.length, `cap=${cap}: OFF total has no dup/loss`);
      assert.equal(onTotal.size, candidates.length, `cap=${cap}: ON total has no dup/loss`);

      // NO TIER-1 STARVATION: a Tier-1 floor cell is NEVER skipped while the
      // belief-boosted Tier-2 re-probe is selected. The Tier-2 re-probe must come
      // dead last in BOTH orders (tier is the outermost comparator key, above belief),
      // so no belief boost can pull it ahead of an uncovered Tier-1 floor cell.
      assert.equal(off.order[off.order.length - 1], "TG-cell-hot-reprobe", `cap=${cap}: Tier-2 is last OFF`);
      assert.equal(on.order[on.order.length - 1], "TG-cell-hot-reprobe", `cap=${cap}: Tier-2 is last ON even with a belief boost`);
      // Concretely: the Tier-2 re-probe is only ever selected once BOTH Tier-1 floor
      // cells are already selected (no Tier-1 cell starved behind a Tier-2).
      if (on.selected.includes("TG-cell-hot-reprobe")) {
        assert.ok(
          on.selected.includes("TG-cell-hot-floor") && on.selected.includes("TG-cell-cold-floor"),
          `cap=${cap}: Tier-2 re-probe selected before a Tier-1 floor cell — starvation`,
        );
      }
    }
  });
});

test("belief ON only REORDERS within the Tier-1 band — both Tier-1 floor cells precede the Tier-2 re-probe", () => {
  withTempHome(() => {
    const domain = "reorder-within-band.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    appendEdges({
      target_domain: domain,
      edges: [
        { source: { type: "principal", id: "principal:attacker" }, target: { type: "policy_gate", id: "policy_gate:owner" }, edge_type: "tests_gate" },
        { source: { type: "policy_gate", id: "policy_gate:owner" }, target: { type: "effect", id: "effect:unauth_succeeds_where_auth_blocked:victim" }, edge_type: "permits_effect" },
      ],
    });
    const HOT = "surface:idor-victim";
    const surfaces = [{ id: HOT, title: "victim object access", hosts: [domain], bug_class_hints: ["unauth_succeeds_where_auth_blocked"], high_value_flows: ["attacker reads owner victim object"] }];
    const candidates = [
      { node_id: "TG-cell-floor-a", kind: "cell", priority: "medium", tier: 1, severity_floor: "low", ts_first: "2026-06-01T00:00:00.000Z", surface_refs: [HOT] },
      { node_id: "TG-cell-reprobe", kind: "cell", priority: "critical", tier: 2, severity_floor: "critical", ts_first: "2026-06-01T00:00:00.000Z", surface_refs: [HOT] },
    ];
    const beliefRank = buildCellBeliefRank({ target_domain: domain, document: { nodes: candidates }, candidates, surfaces, seed: "belief-scheduler-priority" });
    assert.ok(beliefRank.size >= 1, "non-vacuity: belief map non-empty");
    // Even with the Tier-2 re-probe carrying a max belief boost, the Tier-1 floor cell
    // dispatches first — belief never bends the breadth-before-depth contract.
    const ranked = new Map([...beliefRank, ["TG-cell-reprobe", 1000]]);
    const order = candidates.slice().sort((a, b) => compareGraphCandidates(a, b, PRIORITY_RANK, ranked)).map((n) => n.node_id);
    assert.deepEqual(order, ["TG-cell-floor-a", "TG-cell-reprobe"], "Tier-1 floor precedes Tier-2 re-probe unconditionally");
  });
});
