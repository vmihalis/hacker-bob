const test = require("node:test");
const assert = require("node:assert/strict");

const {
  deriveChildFanoutPlan,
  mechanismDedupKey,
  mechanismTierWeight,
  mechanismMatchesBugClass,
  mechanismChainingFactor,
  mechanismCellLift,
  dedupeMechanismTemplates,
} = require("../mcp/lib/capability-pack-derivation.js");

const META = { capability_pack: "web_generic" };

// A web surface whose bug_class hints each have a corresponding mechanism
// template in the registry below. Three bug classes so a registry larger than a
// single window's budget must fan out across waves.
const BUG_CLASSES = ["idor", "ssrf", "xss"];
const AUTH = ["admin"];

// A registry spanning the trust gradient. Each template names its bug_class in
// the mechanism_id / name / required_entities so the structural matcher binds it
// to the right cell.
//   - idor: TWO templates — a tier-2 corpus template AND a tier-3 candidate, so
//     the same bug_class fans out to MORE agent-states (one per distinct mechanism).
//   - ssrf: a tier-1 (oracle-backed) template with a chaining edge.
//   - xss: a tier-3 candidate, single-hop.
const REGISTRY = [
  {
    id: "object_authorization",
    mechanism_id: "CWE-639",
    name: "idor object authorization",
    tier: 2,
    candidate: false,
    required_entities: ["principal", "object", "idor"],
    evidence_predicate: { kind: "differential_effect", required_edges: ["principal->gate"] },
  },
  {
    id: "idor_candidate",
    mechanism_id: "CWE-639",
    name: "idor synthesis candidate",
    tier: 3,
    candidate: true,
    claim_authority: false,
    required_entities: ["idor", "selector"],
    evidence_predicate: { kind: "differential_effect", required_edges: ["selector->effect"] },
  },
  {
    id: "ssrf_oracle",
    mechanism_id: "CWE-918",
    name: "ssrf",
    tier: 2,
    candidate: false,
    oracle_backed: true,
    required_entities: ["ssrf", "fetcher", "target"],
    evidence_predicate: {
      kind: "differential_effect",
      required_edges: ["fetcher->internal", "internal->effect", "effect->exfil"],
    },
  },
  {
    id: "xss_candidate",
    mechanism_id: "CWE-79",
    name: "xss",
    tier: 3,
    candidate: true,
    claim_authority: false,
    required_entities: ["xss", "sink"],
    evidence_predicate: { kind: "differential_effect" },
  },
];

function baseOpts(maxChildren, extra) {
  return {
    bug_class_hints: BUG_CLASSES,
    auth_profiles: AUTH,
    budget: { remaining_depth: 1, max_children: maxChildren },
    ...(extra || {}),
  };
}

function keysOf(plan) {
  return plan.children.map((c) => c.planning_key);
}

function setOf(plan) {
  return new Set(keysOf(plan));
}

function beliefOn(extra) {
  return { enabled: true, mechanism_templates: REGISTRY, ...(extra || {}) };
}

// ── (0) The match / tier / chaining / dedup primitives ─────────────────────

test("mechanismMatchesBugClass binds a template to a structurally-applicable bug_class only", () => {
  const ssrf = REGISTRY.find((t) => t.id === "ssrf_oracle");
  assert.equal(mechanismMatchesBugClass(ssrf, "ssrf"), 1);
  // A non-applicable bug_class earns no match (no false route — the ranking quality
  // guard). A zero match is NOT a drop; the cell still stands on its baseline slot.
  assert.equal(mechanismMatchesBugClass(ssrf, "reentrancy"), 0);
  assert.equal(mechanismMatchesBugClass(ssrf, ""), 0);
});

test("mechanismTierWeight honors the trust gradient (oracle > tier-2 > tier-3)", () => {
  const oracle = REGISTRY.find((t) => t.id === "ssrf_oracle"); // oracle_backed
  const corpus = REGISTRY.find((t) => t.id === "object_authorization"); // tier 2
  const candidate = REGISTRY.find((t) => t.id === "xss_candidate"); // tier 3
  assert.ok(mechanismTierWeight(oracle) > mechanismTierWeight(corpus));
  assert.ok(mechanismTierWeight(corpus) > mechanismTierWeight(candidate));
});

test("mechanismChainingFactor front-loads a multi-hop (transition-feeding) mechanism", () => {
  const multi = REGISTRY.find((t) => t.id === "ssrf_oracle"); // 3 required_edges
  const single = REGISTRY.find((t) => t.id === "object_authorization"); // 1 edge
  const none = REGISTRY.find((t) => t.id === "xss_candidate"); // no edges
  assert.ok(mechanismChainingFactor(multi) > mechanismChainingFactor(single));
  assert.ok(mechanismChainingFactor(single) > mechanismChainingFactor(none));
  assert.equal(mechanismChainingFactor(none), 1);
});

test("dedupeMechanismTemplates collapses near-identical templates, keeps every DISTINCT mechanism", () => {
  const dup = { ...REGISTRY[0] }; // a re-registered byte-equal object_authorization
  const noisy = [...REGISTRY, dup];
  const deduped = dedupeMechanismTemplates(noisy);
  // The byte-equal duplicate is folded...
  assert.equal(deduped.filter((t) => t.id === "object_authorization").length, 1);
  // ...but every DISTINCT mechanism survives (rank-not-bound: nothing distinct dropped).
  const distinctKeys = new Set(REGISTRY.map((t) => mechanismDedupKey(t)));
  const dedupedKeys = new Set(deduped.map((t) => mechanismDedupKey(t)));
  assert.equal(dedupedKeys.size, distinctKeys.size);
  for (const k of distinctKeys) assert.ok(dedupedKeys.has(k), `distinct mechanism ${k} survives`);
});

test("two distinct mechanisms sharing a CWE keep DISTINCT dedup keys (no over-collapse)", () => {
  // object_authorization and idor_candidate both carry CWE-639 but are distinct
  // mechanisms (distinct ids). Over-collapsing them would sever a chain link.
  const a = mechanismDedupKey(REGISTRY.find((t) => t.id === "object_authorization"));
  const b = mechanismDedupKey(REGISTRY.find((t) => t.id === "idor_candidate"));
  assert.notEqual(a, b);
  const deduped = dedupeMechanismTemplates([
    REGISTRY.find((t) => t.id === "object_authorization"),
    REGISTRY.find((t) => t.id === "idor_candidate"),
  ]);
  assert.equal(deduped.length, 2, "two distinct CWE-639 mechanisms both survive dedup");
});

// ── (1) FLAG-OFF BYTE-IDENTICAL ────────────────────────────────────────────

test("flag-off (no belief / disabled) is byte-identical to the deterministic baseline", () => {
  for (const remainingDepth of [0, 1, 2]) {
    for (const maxChildren of [0, 1, 2, 3, 64]) {
      const opts = {
        bug_class_hints: BUG_CLASSES,
        auth_profiles: AUTH,
        budget: { remaining_depth: remainingDepth, max_children: maxChildren },
      };
      const baseline = deriveChildFanoutPlan("S-x", META, opts);
      // belief absent => baseline
      const absent = deriveChildFanoutPlan("S-x", META, { ...opts });
      assert.deepEqual(absent, baseline, "no belief key => byte-identical");
      // belief present but DISABLED, even with a full registry => baseline (the
      // mechanism axis is gated on enabled:true).
      const disabled = deriveChildFanoutPlan("S-x", META, {
        ...opts,
        belief: { enabled: false, mechanism_templates: REGISTRY },
      });
      assert.deepEqual(disabled, baseline, "belief disabled => byte-identical (no mechanism axis)");
    }
  }
});

// ── (2) FAN-OUT TO MORE STATES, NOT A TOP-K ────────────────────────────────

test("the open registry adds mechanism cells — MORE agent-states, never a top-K cut", () => {
  const baseline = deriveChildFanoutPlan("S-x", META, baseOpts(64));
  const withRegistry = deriveChildFanoutPlan("S-x", META, baseOpts(64, { belief: beliefOn() }));

  // The base (bug_class x auth) cells are STILL all present (a superset — nothing dropped).
  const baseKeys = setOf(baseline);
  const fullKeys = setOf(withRegistry);
  for (const k of baseKeys) {
    assert.ok(fullKeys.has(k), `base cell ${k} still present with the registry on`);
  }
  // The registry STRICTLY grows the eligible set (each applicable mechanism = a
  // distinct cell). idor has 2 mechanisms, ssrf 1, xss 1 => 4 mechanism cells
  // added on top of the 3 base cells.
  assert.equal(baseline.children.length, BUG_CLASSES.length); // 3 base cells (1 auth)
  assert.equal(withRegistry.children.length, BUG_CLASSES.length + 4);

  // Every mechanism cell is DISTINCT (its own planning_key) — no collision with
  // the base cell or with a sibling mechanism cell on the same bug_class.
  assert.equal(new Set(keysOf(withRegistry)).size, withRegistry.children.length);

  // The same idor bug_class now has THREE cells (1 base + 2 mechanisms): the
  // window fans out to more agent-states for a bug_class touched by more
  // mechanisms — the UNION is exhaustive, never a single top-K slot.
  const idorCells = withRegistry.children.filter((c) => c.bug_class === "idor");
  assert.equal(idorCells.length, 3);
});

// ── (3) RANK != BOUND: at a truncating budget the residual SPILLS, never dropped ─

test("a registry larger than one window fans out across waves to fixpoint (no drop)", () => {
  const full = deriveChildFanoutPlan("S-x", META, baseOpts(64, { belief: beliefOn() }));
  const totalEligible = full.children.length; // 3 base + 4 mechanism = 7

  // Wave budget of 2: only 2 cells fit; the rest are budget_pruned (the spill).
  const dispatched = new Set();
  let covered = [];
  let guard = 0;
  for (;;) {
    if (guard++ > 32) assert.fail("cell floor did not reach fixpoint");
    const plan = deriveChildFanoutPlan("S-x", META, baseOpts(2, {
      covered_cell_keys: covered,
      belief: beliefOn(),
    }));
    if (plan.children.length === 0) break;
    // The emitted set is a SUBSET-by-budget of the enumerated eligible set; the
    // residual is COUNTED as budget_pruned, never silently dropped. The full
    // accounting per pass: emitted + budget_pruned (this wave's spill) +
    // covered_pruned (already terminal) == the total eligible set.
    assert.ok(plan.children.length <= 2, "emitted respects the external budget ceiling");
    assert.equal(
      plan.children.length + plan.budget_pruned_count + plan.covered_pruned_count,
      totalEligible,
      "emitted + spilled + covered == full eligible (residual accounted, never dropped)",
    );
    for (const k of keysOf(plan)) {
      assert.ok(!dispatched.has(k), "a later wave never re-dispatches a covered cell");
      dispatched.add(k);
    }
    covered = [...dispatched];
  }
  // Every eligible cell (base + every distinct mechanism) was eventually
  // dispatched: the floor reached fixpoint over the WHOLE open mechanism space.
  assert.equal(dispatched.size, totalEligible, "coverage == full registry at fixpoint (no drop)");
  assert.ok(
    [...setOf(full)].every((k) => dispatched.has(k)),
    "the fixpoint set equals the full uncapped eligible set",
  );
});

// ── (4) BELIEF-ORDERED BY THE TRUST GRADIENT x MATCH x CHAINING ────────────

test("dispatch is ordered by tier x match x chaining (oracle/tier-2 before tier-3)", () => {
  const plan = deriveChildFanoutPlan("S-x", META, baseOpts(64, { belief: beliefOn() }));

  // Each MECHANISM cell is scored by its OWN template's tier x chaining. Ordering
  // among the mechanism cells must follow the trust gradient.
  const mechIdxById = new Map();
  plan.children.forEach((c, i) => {
    if (typeof c.mechanism_template_id === "string") mechIdxById.set(c.mechanism_template_id, i);
  });
  const ssrfMechIdx = mechIdxById.get("ssrf_oracle");
  const xssMechIdx = mechIdxById.get("xss_candidate");
  const idorCorpusIdx = mechIdxById.get("object_authorization");
  const idorCandIdx = mechIdxById.get("idor_candidate");
  for (const v of [ssrfMechIdx, xssMechIdx, idorCorpusIdx, idorCandIdx]) {
    assert.ok(Number.isInteger(v), "every applicable mechanism produced a cell");
  }
  // The oracle-backed, 3-hop ssrf mechanism cell dispatches before every tier-3
  // candidate mechanism cell.
  assert.ok(ssrfMechIdx < xssMechIdx, "tier-1 oracle ssrf before tier-3 xss candidate");
  assert.ok(ssrfMechIdx < idorCandIdx, "tier-1 oracle ssrf before tier-3 idor candidate");
  // For the same bug_class, the tier-2 corpus mechanism cell out-ranks the tier-3
  // candidate mechanism cell.
  assert.ok(idorCorpusIdx < idorCandIdx, "tier-2 corpus idor before tier-3 idor candidate");

  // Under a truncating budget the SURVIVORS are the highest-scoring prefix. The
  // hottest cell is the ssrf cluster (oracle-backed, 3-hop mechanism): the base
  // ssrf cell carries that mechanism's aggregate lift and ties the oracle cell,
  // so at budget 1 the single survivor is an ssrf cell (base or its oracle
  // mechanism) — never a tier-3-only bug_class.
  const trunc = deriveChildFanoutPlan("S-x", META, baseOpts(1, { belief: beliefOn() }));
  assert.equal(trunc.children.length, 1);
  assert.equal(trunc.children[0].bug_class, "ssrf",
    "the single survivor belongs to the hottest (oracle-backed) bug_class cluster");
});

// ── (5) NO-GATING: ranking REORDERS, never prunes/blocks/skips a candidate ──

test("ranking never drops a candidate — the ordered SET equals the baseline-on SET", () => {
  // The deterministic (unranked) eligible set: same registry, but force the
  // ranker to a no-op by giving every cell an equal score (the order may change,
  // the SET must not). We assert SET invariance across truncating budgets: the
  // emitted UNION spilled is invariant, ranking only changes which fit now.
  const full = deriveChildFanoutPlan("S-x", META, baseOpts(64, { belief: beliefOn() }));
  const fullSet = setOf(full);
  for (const maxChildren of [1, 2, 3, 4, 5, 6, 7, 64]) {
    const plan = deriveChildFanoutPlan("S-x", META, baseOpts(maxChildren, { belief: beliefOn() }));
    // emitted ⊆ full set (no fabricated cell), and emitted + spilled == full set
    // size (every candidate is accounted — emitted now or spilled to a later wave).
    assert.ok([...setOf(plan)].every((k) => fullSet.has(k)), `emitted ⊆ full set at budget ${maxChildren}`);
    assert.equal(
      plan.children.length + plan.budget_pruned_count,
      full.children.length,
      `emitted + spilled == full eligible at budget ${maxChildren} (nothing skipped)`,
    );
  }
});

test("mechanismCellLift sums applicable mechanisms for a bug_class (more surface = higher rank)", () => {
  // idor is touched by TWO mechanisms (tier-2 + tier-3); xss by ONE (tier-3).
  // The aggregate lift for idor must exceed xss's, so a multi-mechanism bug_class
  // base cell front-loads. A non-matched bug_class earns zero (no false lift).
  const idorLift = mechanismCellLift(REGISTRY, "idor");
  const xssLift = mechanismCellLift(REGISTRY, "xss");
  const noneLift = mechanismCellLift(REGISTRY, "reentrancy");
  assert.ok(idorLift > xssLift);
  assert.equal(noneLift, 0);
});

// ── (6) DETERMINISM ────────────────────────────────────────────────────────

test("the open-registry plan is deterministic for identical inputs", () => {
  const a = deriveChildFanoutPlan("S-x", META, baseOpts(64, { belief: beliefOn() }));
  const b = deriveChildFanoutPlan("S-x", META, baseOpts(64, { belief: beliefOn() }));
  assert.deepEqual(keysOf(a), keysOf(b));
  assert.deepEqual(a, b);
});
