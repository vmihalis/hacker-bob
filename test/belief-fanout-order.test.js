const test = require("node:test");
const assert = require("node:assert/strict");

const {
  deriveChildFanoutPlan,
} = require("../mcp/lib/capability-pack-derivation.js");

const META = { capability_pack: "web_generic" };
const BUG_CLASSES = ["idor", "xss", "ssrf"];
const AUTH = ["admin", "user"];

function baseOpts(maxChildren) {
  return {
    bug_class_hints: BUG_CLASSES,
    auth_profiles: AUTH,
    budget: { remaining_depth: 1, max_children: maxChildren },
  };
}

function keysOf(plan) {
  return plan.children.map((c) => c.planning_key);
}

function setOf(plan) {
  return new Set(keysOf(plan));
}

function setsEqual(a, b) {
  return a.size === b.size && [...a].every((k) => b.has(k));
}

// A deterministic NON-UNIFORM per-cell belief map: rank ssrf cells hottest, then
// xss, idor coldest; admin hotter than user within a bug_class. No two cells tie,
// so the expected order is fully determined.
function nonUniformBeliefMap(plan) {
  const order = [
    ["ssrf", "admin"],
    ["ssrf", "user"],
    ["xss", "admin"],
    ["xss", "user"],
    ["idor", "admin"],
    ["idor", "user"],
  ];
  const map = new Map();
  let score = order.length;
  for (const [bc, auth] of order) {
    map.set(JSON.stringify([bc, auth]), score);
    score -= 1;
  }
  // Sanity: every emitted/eligible cell has a score so the test's expectation is
  // total (not partially uniform).
  for (const child of plan.children) {
    assert.ok(map.has(child.planning_key), `belief map covers ${child.planning_key}`);
  }
  return map;
}

const EXPECTED_BELIEF_ORDER = [
  ["ssrf", "admin"],
  ["ssrf", "user"],
  ["xss", "admin"],
  ["xss", "user"],
  ["idor", "admin"],
  ["idor", "user"],
].map(([bc, auth]) => JSON.stringify([bc, auth]));

// (1) PERMUTATION, NEVER A FILTER: across every (budget, depth) the belief-ordered
// (emitted UNION spilled) SET equals the belief-free (emitted UNION spilled) SET.
// At a truncating budget the EMITTED subsets differ by design (that is the whole
// effect of belief — it picks a different top-k to dispatch first); what must
// stay invariant is the TOTAL set of cells the plan accounts for. Belief reorders
// which fit now vs. spill, never adds/drops/skips a cell.
test("belief order is a permutation of the baseline set for every (budget, depth)", () => {
  const fullBaseline = deriveChildFanoutPlan("S-x", META, baseOpts(64));
  const full = nonUniformBeliefMap(fullBaseline);
  const baselineFullSet = setOf(fullBaseline);
  for (const remainingDepth of [1, 2, 3]) {
    for (const maxChildren of [1, 2, 3, 4, 5, 6, 64]) {
      const opts = {
        bug_class_hints: BUG_CLASSES,
        auth_profiles: AUTH,
        budget: { remaining_depth: remainingDepth, max_children: maxChildren },
      };
      const baseline = deriveChildFanoutPlan("S-x", META, opts);
      const ordered = deriveChildFanoutPlan("S-x", META, {
        ...opts,
        belief: { enabled: true, score_by_planning_key: full },
      });
      // Belief never enlarges or shrinks the work: same emitted COUNT as the
      // deterministic cut, same budget_pruned count, same total accounted set.
      assert.equal(
        ordered.children.length,
        baseline.children.length,
        `emitted count unchanged at depth=${remainingDepth} budget=${maxChildren}`,
      );
      assert.equal(
        ordered.budget_pruned_count,
        baseline.budget_pruned_count,
        `spill count unchanged at depth=${remainingDepth} budget=${maxChildren}`,
      );
      // The emitted set is always a SUBSET of the full baseline set (never a cell
      // the baseline would not produce — no fabrication, no filter onto a new set).
      assert.ok(
        [...setOf(ordered)].every((k) => baselineFullSet.has(k)),
        `emitted ⊆ baseline set at depth=${remainingDepth} budget=${maxChildren}`,
      );
      // emitted + spilled == total eligible (= the full uncapped baseline child
      // count): the residual that did NOT fit is accounted as budget_pruned, never
      // silently dropped.
      assert.equal(
        ordered.children.length + ordered.budget_pruned_count,
        fullBaseline.children.length,
        `emitted + spilled == eligible at depth=${remainingDepth} budget=${maxChildren}`,
      );
    }
  }
});

// (2) HIGHER BELIEF DISPATCHED FIRST: the emitted children come out in strict
// belief-score-descending order (top-k of the non-uniform ranking).
test("higher-belief children are ordered (and emitted) earlier", () => {
  const fullBaseline = deriveChildFanoutPlan("S-x", META, baseOpts(64));
  const full = nonUniformBeliefMap(fullBaseline);
  const ordered = deriveChildFanoutPlan("S-x", META, {
    ...baseOpts(64),
    belief: { enabled: true, score_by_planning_key: full },
  });
  assert.deepEqual(keysOf(ordered), EXPECTED_BELIEF_ORDER);

  // Under truncation, the SURVIVORS are exactly the highest-belief prefix — the
  // belief signal decides which cells dispatch now vs. spill to a later wave.
  const trunc = deriveChildFanoutPlan("S-x", META, {
    ...baseOpts(3),
    belief: { enabled: true, score_by_planning_key: full },
  });
  assert.deepEqual(keysOf(trunc), EXPECTED_BELIEF_ORDER.slice(0, 3));
});

// (3) TRUNCATION SPILLS, NEVER DROPS: the residual (lower-ranked) children are
// re-emitted to a later wave. The cell floor models a "later wave" as a fresh
// derive pass whose covered_cell_keys exclude the now-tested high-belief cells;
// the previously-spilled cells must reappear (the floor reaches fixpoint).
test("max_children truncation spills the residual to a later wave (never dropped)", () => {
  const fullBaseline = deriveChildFanoutPlan("S-x", META, baseOpts(64));
  const full = nonUniformBeliefMap(fullBaseline);

  // Wave 1: only the top-2 belief cells fit.
  const wave1 = deriveChildFanoutPlan("S-x", META, {
    ...baseOpts(2),
    belief: { enabled: true, score_by_planning_key: full },
  });
  const wave1Keys = keysOf(wave1);
  assert.equal(wave1.children.length, 2);
  assert.equal(wave1.budget_pruned_count, fullBaseline.children.length - 2);

  // Wave 2: the wave-1 cells are now covered (terminal), so the caller prunes
  // them; the residual (spilled) cells re-derive — proving they were never lost.
  const wave2 = deriveChildFanoutPlan("S-x", META, {
    ...baseOpts(2),
    covered_cell_keys: wave1Keys,
    belief: { enabled: true, score_by_planning_key: full },
  });
  const wave2Keys = keysOf(wave2);
  for (const k of wave2Keys) {
    assert.ok(!wave1Keys.includes(k), "a later wave never re-dispatches a covered cell");
  }

  // Continue draining until the floor reaches fixpoint (no eligible cells left).
  const dispatched = new Set([...wave1Keys, ...wave2Keys]);
  let guard = 0;
  let covered = [...dispatched];
  for (;;) {
    if (guard++ > 16) assert.fail("cell floor did not reach fixpoint");
    const plan = deriveChildFanoutPlan("S-x", META, {
      ...baseOpts(2),
      covered_cell_keys: covered,
      belief: { enabled: true, score_by_planning_key: full },
    });
    if (plan.children.length === 0) break;
    for (const k of keysOf(plan)) dispatched.add(k);
    covered = [...dispatched];
  }
  // Every baseline cell was eventually dispatched — the residual spilled, the
  // floor closed, and nothing was dropped.
  assert.ok(
    setsEqual(dispatched, setOf(fullBaseline)),
    "every eligible cell is eventually dispatched across waves (no drop)",
  );
});

// (4) DEFAULT-OFF BYTE-IDENTICAL: with belief absent OR explicitly disabled, the
// plan deep-equals the belief-free baseline for every (budget, depth).
test("flag-off plan is deepEqual to the belief-free baseline", () => {
  const fullBaseline = deriveChildFanoutPlan("S-x", META, baseOpts(64));
  const full = nonUniformBeliefMap(fullBaseline);
  for (const remainingDepth of [0, 1, 2, 3]) {
    for (const maxChildren of [0, 1, 2, 3, 4, 6, 64]) {
      const opts = {
        bug_class_hints: BUG_CLASSES,
        auth_profiles: AUTH,
        budget: { remaining_depth: remainingDepth, max_children: maxChildren },
      };
      const baseline = deriveChildFanoutPlan("S-x", META, opts);
      // belief key absent => baseline
      const absent = deriveChildFanoutPlan("S-x", META, { ...opts });
      assert.deepEqual(absent, baseline, "no belief key => byte-identical");
      // belief present but disabled, even with a non-uniform map => baseline
      const disabled = deriveChildFanoutPlan("S-x", META, {
        ...opts,
        belief: { enabled: false, score_by_planning_key: full },
      });
      assert.deepEqual(disabled, baseline, "belief disabled => byte-identical");
    }
  }
});

// Determinism: the same fed signals + the same plan derive the same child order.
test("belief order is deterministic for identical inputs", () => {
  const fullBaseline = deriveChildFanoutPlan("S-x", META, baseOpts(64));
  const full = nonUniformBeliefMap(fullBaseline);
  const a = deriveChildFanoutPlan("S-x", META, {
    ...baseOpts(64),
    belief: { enabled: true, score_by_planning_key: full },
  });
  const b = deriveChildFanoutPlan("S-x", META, {
    ...baseOpts(64),
    belief: { enabled: true, score_by_planning_key: full },
  });
  assert.deepEqual(keysOf(a), keysOf(b));
});

// Equal-score cells keep their deterministic baseline relative order (stable
// permutation): an unranked / tied cell is never reshuffled.
test("equal-score (and unranked) cells keep their deterministic baseline order", () => {
  const baseline = deriveChildFanoutPlan("S-x", META, baseOpts(64));
  // Lift exactly ONE cell; every other cell scores 0 and must keep baseline order.
  const lift = new Map([[JSON.stringify(["xss", "user"]), 100]]);
  const ordered = deriveChildFanoutPlan("S-x", META, {
    ...baseOpts(64),
    belief: { enabled: true, score_by_planning_key: lift },
  });
  assert.equal(ordered.children[0].planning_key, JSON.stringify(["xss", "user"]));
  // The remaining cells are the baseline minus the lifted one, in baseline order.
  const expectedTail = keysOf(baseline).filter((k) => k !== JSON.stringify(["xss", "user"]));
  assert.deepEqual(keysOf(ordered).slice(1), expectedTail);
});

// The belief overlay genuinely REUSES buildCellBeliefRank: when no injected map
// is given but caller-provided surfaces are, the ranker is consulted. With no
// belief state for the (test) domain it returns no hints, so the plan degrades to
// the deterministic baseline — proving the reuse path is wired AND fail-soft.
test("buildCellBeliefRank reuse path degrades to baseline when it yields no signal", () => {
  const baseline = deriveChildFanoutPlan("S-x", META, baseOpts(64));
  const viaRanker = deriveChildFanoutPlan("S-x", META, {
    ...baseOpts(64),
    belief: {
      enabled: true,
      target_domain: "belief-fanout-order.test.invalid",
      surfaces: [{ id: "S-x" }],
    },
  });
  assert.deepEqual(viaRanker, baseline);
});
