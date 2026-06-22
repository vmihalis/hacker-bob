const test = require("node:test");
const assert = require("node:assert/strict");

const {
  deriveChildFanoutPlan,
  fanoutPlanningKey,
  CHILD_FANOUT_HARD_CAP,
} = require("../mcp/lib/capability-pack-derivation.js");

const META = { capability_pack: "web_generic" };

test("crosses bug_class x auth_role into child cells keyed on the REAL surface id", () => {
  const plan = deriveChildFanoutPlan("S-api-users", META, {
    bug_class_hints: ["idor", "sqli"],
    auth_profiles: ["admin", "user"],
    budget: { remaining_depth: 1, max_children: 8 },
  });
  assert.equal(plan.parent_surface_id, "S-api-users");
  assert.equal(plan.children.length, 4); // 2 bug classes x 2 auth roles
  assert.ok(plan.children.every((c) => c.surface_id === "S-api-users"), "no synthetic surface ids");
  // coverage-shaped cell_key (method/endpoint runtime-filled => "")
  assert.equal(plan.children[0].cell_key, JSON.stringify(["S-api-users", "", "", "idor", "admin"]));
  assert.ok(plan.children.every((c) => c.allowed_tools_for_node.length > 0), "each child carries its tools");
});

test("OSS surfaces fan out (sanitizer-class x input-class) cells, no auth axis", () => {
  const {
    isOssSurfaceMetadata,
    OSS_SANITIZER_CLASS_AXIS,
    OSS_INPUT_CLASS_AXIS,
  } = require("../mcp/lib/capability-packs.js");
  const ossMeta = { surface_type: "oss_native_code" };
  assert.equal(isOssSurfaceMetadata(ossMeta), true);
  assert.equal(isOssSurfaceMetadata({ capability_pack: "web" }), false);
  // Fed the OSS axes (sanitizer x input_class), no auth, the plan crosses them.
  const plan = deriveChildFanoutPlan("harness-X", ossMeta, {
    bug_class_hints: OSS_SANITIZER_CLASS_AXIS,
    auth_profiles: OSS_INPUT_CLASS_AXIS,
    budget: { remaining_depth: 1, max_children: 64 },
  });
  assert.equal(plan.children.length, OSS_SANITIZER_CLASS_AXIS.length * OSS_INPUT_CLASS_AXIS.length);
  // cell_key carries sanitizer in the bug_class slot, input_class in the auth
  // slot — all lowercase, reconcilable with coverageRecordKey unchanged.
  const sample = plan.children.find((c) => c.bug_class === "asan" && c.auth_profile === "value_profile");
  assert.ok(sample, "asan x value_profile cell exists");
  assert.equal(sample.cell_key, JSON.stringify(["harness-X", "", "", "asan", "value_profile"]));
});

test("reachability/type gate prunes structurally-impossible (surface x bug_class) cells", () => {
  // reentrancy cannot occur on a web surface -> pruned; idol stays (fail-open).
  const web = deriveChildFanoutPlan("S-web", { capability_pack: "web" }, {
    bug_class_hints: ["reentrancy", "idor"],
    auth_profiles: ["admin"],
    budget: { remaining_depth: 1, max_children: 8 },
  });
  assert.deepEqual(web.children.map((c) => c.bug_class), ["idor"]);
  assert.equal(web.relevance_pruned_count, 1);

  // on a smart-contract surface, reentrancy IS relevant -> kept, nothing pruned.
  const sc = deriveChildFanoutPlan("S-sc", { surface_type: "smart_contract", chain_family: "evm" }, {
    bug_class_hints: ["reentrancy", "idor"],
    auth_profiles: ["admin"],
    budget: { remaining_depth: 1, max_children: 8 },
  });
  assert.ok(sc.children.some((c) => c.bug_class === "reentrancy"));
  assert.equal(sc.relevance_pruned_count, 0);
});

test("each cell adopts the technique pack(s) targeting its bug_class (weapon-per-cell)", () => {
  const plan = deriveChildFanoutPlan("S-bridge", META, {
    bug_class_hints: ["replay", "idor"],
    auth_profiles: ["admin"],
    budget: { remaining_depth: 1, max_children: 8 },
  });
  const byClass = Object.fromEntries(plan.children.map((c) => [c.bug_class, c.technique_pack_ids]));
  // cross-chain replay adopts the web3 identity-handoff weapon (the cross-surface
  // technique a per-surface model never reaches for)...
  assert.deepEqual(byClass.replay, ["web3_identity_handoff"]);
  // ...while a class with no mapped weapon adopts none and stands on the base pack.
  assert.deepEqual(byClass.idor, []);
  // so two cells on the same surface are NOT byte-identical: capability is now
  // per-(bug_class), not hoisted per-surface.
  assert.notDeepEqual(byClass.replay, byClass.idor);
});

test("dedupes bug classes and caps at max_children, counting budget-pruned", () => {
  const plan = deriveChildFanoutPlan("S", META, {
    bug_class_hints: ["idor", "idor", "sqli"], // dup collapses
    auth_profiles: ["admin", "user"],
    budget: { remaining_depth: 1, max_children: 3 },
  });
  assert.equal(plan.children.length, 3);
  assert.equal(plan.budget_pruned_count, 1); // 4 candidate cells, cap 3
});

test("prunes already-covered (bug_class, auth_profile) cells", () => {
  const covered = fanoutPlanningKey("idor", "admin");
  const plan = deriveChildFanoutPlan("S", META, {
    bug_class_hints: ["idor"],
    auth_profiles: ["admin", "user"],
    budget: { remaining_depth: 1, max_children: 8 },
    covered_cell_keys: [covered],
  });
  assert.equal(plan.covered_pruned_count, 1);
  assert.ok(!plan.children.some((c) => c.bug_class === "idor" && c.auth_profile === "admin"));
  assert.ok(plan.children.some((c) => c.bug_class === "idor" && c.auth_profile === "user"));
});

test("remaining_depth <= 0 yields a leaf (no fan-out) — the default-off case", () => {
  const plan = deriveChildFanoutPlan("S", META, {
    bug_class_hints: ["idor"],
    auth_profiles: ["admin"],
    budget: { remaining_depth: 0, max_children: 8 },
  });
  assert.equal(plan.children.length, 0);
  assert.match(plan.rationale, /depth budget exhausted/);
});

test("empty bug-class axis yields a leaf", () => {
  const plan = deriveChildFanoutPlan("S", META, {
    bug_class_hints: [],
    auth_profiles: ["admin"],
    budget: { remaining_depth: 1, max_children: 8 },
  });
  assert.equal(plan.children.length, 0);
});

test("no auth profiles -> single anonymous baseline cell per bug class", () => {
  const plan = deriveChildFanoutPlan("S", META, {
    bug_class_hints: ["ssrf"],
    auth_profiles: [],
    budget: { remaining_depth: 1, max_children: 8 },
  });
  assert.equal(plan.children.length, 1);
  assert.equal(plan.children[0].auth_profile, "");
  assert.match(plan.children[0].rationale, /anonymous/);
});

test("hard cap defends the spawn budget against a pathological axis", () => {
  const plan = deriveChildFanoutPlan("S", META, {
    bug_class_hints: Array.from({ length: 40 }, (_, i) => `b${i}`),
    auth_profiles: Array.from({ length: 5 }, (_, i) => `a${i}`),
    budget: { remaining_depth: 1, max_children: 999 },
  });
  assert.ok(plan.children.length <= CHILD_FANOUT_HARD_CAP);
});

test("deterministic: output is independent of input axis order (X-P4 purity)", () => {
  const a = deriveChildFanoutPlan("S", META, {
    bug_class_hints: ["z", "a"],
    auth_profiles: ["u", "t"],
    budget: { remaining_depth: 1, max_children: 8 },
  });
  const b = deriveChildFanoutPlan("S", META, {
    bug_class_hints: ["a", "z"],
    auth_profiles: ["t", "u"],
    budget: { remaining_depth: 1, max_children: 8 },
  });
  assert.deepEqual(a, b);
});

test("rejects a missing parent surface id", () => {
  assert.throws(
    () => deriveChildFanoutPlan("", META, { bug_class_hints: ["idor"], budget: { remaining_depth: 1, max_children: 8 } }),
    /parentSurfaceId must be a non-empty string/,
  );
});
