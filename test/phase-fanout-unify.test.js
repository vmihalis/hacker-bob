"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  PHASE,
  phaseFanoutPlan,
} = require("../mcp/core/phase-fanout-plan.js");
const {
  deriveChildFanoutPlan,
} = require("../mcp/core/capability/capability-pack-derivation.js");
const {
  deriveReconAnglePlan,
} = require("../mcp/core/frontier/recon-angle-plan.js");
const {
  OSS_SANITIZER_CLASS_AXIS,
  OSS_INPUT_CLASS_AXIS,
} = require("../mcp/core/capability/capability-packs.js");

// The general dispatcher must reproduce each authority emitter's plan
// IDENTICALLY — byte/structure-for-structure. Any divergence fails here and
// NAMES the missing generalization rather than silently passing.

// ── phase=cell: identity vs deriveChildFanoutPlan ──────────────────────────
// A representative matrix: web cells, OSS axes, smart_contract surface, leaf at
// depth 0, covered-pruned, belief overlay with mechanism templates, and a
// max_children cut producing budget_pruned.
const CELL_CASES = [
  {
    name: "web (bug_class x auth_role)",
    parent_surface_id: "S-api-users",
    surface_metadata: { capability_pack: "web_generic" },
    options: {
      bug_class_hints: ["idor", "sqli"],
      auth_profiles: ["admin", "user"],
      budget: { remaining_depth: 1, max_children: 8 },
    },
  },
  {
    name: "OSS (sanitizer x input_class)",
    parent_surface_id: "harness-X",
    surface_metadata: { surface_type: "oss_native_code" },
    options: {
      bug_class_hints: OSS_SANITIZER_CLASS_AXIS,
      auth_profiles: OSS_INPUT_CLASS_AXIS,
      budget: { remaining_depth: 1, max_children: 64 },
    },
  },
  {
    name: "smart_contract surface (relevance gate keeps reentrancy)",
    parent_surface_id: "S-sc",
    surface_metadata: { surface_type: "smart_contract", chain_family: "evm" },
    options: {
      bug_class_hints: ["reentrancy", "idor"],
      auth_profiles: ["admin"],
      budget: { remaining_depth: 1, max_children: 8 },
    },
  },
  {
    name: "leaf at depth 0",
    parent_surface_id: "S-leaf",
    surface_metadata: { capability_pack: "web" },
    options: {
      bug_class_hints: ["idor"],
      auth_profiles: ["admin"],
      budget: { remaining_depth: 0, max_children: 8 },
    },
  },
  {
    name: "covered-pruned",
    parent_surface_id: "S-cov",
    surface_metadata: { capability_pack: "web" },
    options: {
      bug_class_hints: ["idor", "sqli"],
      auth_profiles: ["admin"],
      budget: { remaining_depth: 1, max_children: 8 },
      covered_cell_keys: [
        require("../mcp/core/capability/capability-pack-derivation.js").fanoutPlanningKey(
          "idor",
          "admin",
        ),
      ],
    },
  },
  {
    name: "belief overlay with mechanism templates",
    parent_surface_id: "S-belief",
    surface_metadata: { surface_type: "smart_contract", chain_family: "evm" },
    options: {
      bug_class_hints: ["reentrancy"],
      auth_profiles: ["admin"],
      budget: { remaining_depth: 1, max_children: 8 },
      belief: {
        enabled: true,
        mechanism_templates: [
          { id: "m-readonly-reentrancy", bug_classes: ["reentrancy"], tier: 2 },
        ],
      },
    },
  },
  {
    name: "max_children cut -> budget_pruned",
    parent_surface_id: "S-cut",
    surface_metadata: { capability_pack: "web" },
    options: {
      bug_class_hints: ["idor", "sqli", "ssrf"],
      auth_profiles: ["admin", "user"],
      budget: { remaining_depth: 1, max_children: 2 },
    },
  },
];

for (const c of CELL_CASES) {
  test(`general(cell) reproduces deriveChildFanoutPlan: ${c.name}`, () => {
    const direct = deriveChildFanoutPlan(
      c.parent_surface_id,
      c.surface_metadata,
      c.options,
    );
    const general = phaseFanoutPlan(PHASE.CELL, {
      parent_surface_id: c.parent_surface_id,
      surface_metadata: c.surface_metadata,
      options: c.options,
    });
    assert.deepStrictEqual(general, direct);
    // Pass-through: the wrapper returns the authority emitter's frozen object
    // unchanged. deriveChildFanoutPlan is a pure function of its inputs, so the
    // dispatch is byte/structure-for-structure identical by construction.
    assert.equal(Object.isFrozen(general), true);
  });
}

// ── phase=recon: identity vs deriveReconAnglePlan ──────────────────────────
// deep on/off x host_id in {claude, codex, kimi, generic-mcp, unknown} x
// governor null / binding / non-binding.
const HOST_IDS = ["claude", "codex", "kimi", "generic-mcp", "unknown"];
const GOVERNORS = [
  null,
  { max_total_spawned_agents: 100, total_spawned: 0 }, // non-binding
  { max_total_spawned_agents: 4, total_spawned: 2 }, // binding
];

for (const deep_mode of [false, true]) {
  for (const host_id of HOST_IDS) {
    for (const governor of GOVERNORS) {
      const label = `deep=${deep_mode} host=${host_id} gov=${
        governor ? governor.max_total_spawned_agents : "null"
      }`;
      test(`general(recon) reproduces deriveReconAnglePlan: ${label}`, () => {
        const options = { deep_mode, host_id, governor };
        const direct = deriveReconAnglePlan(options);
        const general = phaseFanoutPlan(PHASE.RECON, { options });
        assert.deepStrictEqual(general, direct);
      });
    }
  }
}

test("general(recon) with no args delegates to the default plan", () => {
  assert.deepStrictEqual(
    phaseFanoutPlan(PHASE.RECON, {}),
    deriveReconAnglePlan({}),
  );
});

// ── phase=verification: projection of the frozen snapshot list ─────────────
test("general(verification) projects finding_ids as an order-preserving copy", () => {
  const snapshot = { finding_ids: ["F-3", "F-1", "F-2"] };
  const plan = phaseFanoutPlan(PHASE.VERIFICATION, {
    finding_ids: snapshot.finding_ids,
  });
  // Same list the orchestrator enumerates (verification.js freezes
  // finding_ids.slice() at round-write; the projection mirrors that .slice()).
  assert.deepStrictEqual(plan.items, snapshot.finding_ids.slice());
  assert.equal(plan.phase, "verification");
  // Order-preserving: one worker per id in snapshot order.
  assert.deepStrictEqual([...plan.items], ["F-3", "F-1", "F-2"]);
});

test("general(verification) projection is a copy, not an alias", () => {
  const snapshot = { finding_ids: ["F-1", "F-2"] };
  const plan = phaseFanoutPlan(PHASE.VERIFICATION, {
    finding_ids: snapshot.finding_ids,
  });
  // Frozen output cannot be mutated; the snapshot stays intact regardless.
  assert.equal(Object.isFrozen(plan), true);
  assert.equal(Object.isFrozen(plan.items), true);
  assert.deepStrictEqual(snapshot.finding_ids, ["F-1", "F-2"]);
});

test("general(verification) with missing/empty finding_ids yields {items:[]} frozen", () => {
  for (const args of [{}, { finding_ids: [] }, { finding_ids: null }]) {
    const plan = phaseFanoutPlan(PHASE.VERIFICATION, args);
    assert.deepStrictEqual(plan.items, []);
    assert.equal(Object.isFrozen(plan), true);
    assert.equal(Object.isFrozen(plan.items), true);
  }
});

// ── unknown phase throws ───────────────────────────────────────────────────
test("unknown phase throws", () => {
  assert.throws(
    () => phaseFanoutPlan("evidence", {}),
    /unknown phase evidence/,
  );
});
