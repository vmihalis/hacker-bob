const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  isOpenForAssignment,
  planNextWave,
} = require("../mcp/core/waves/wave-planner.js");
const {
  DEFAULT_QUEUE_POLICY,
  LEAN_PROFILE,
} = require("../mcp/core/io/queue-policy.js");
const {
  appendEdges,
} = require("../mcp/core/frontier/surface-graph.js");
const {
  sessionDir,
  surfaceRoutesPath,
} = require("../mcp/core/io/paths.js");
const {
  SURFACE_ROUTE_VERSION,
  SURFACE_ROUTES_VERSION,
} = require("../mcp/core/frontier/surface-router.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-wave-planner-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function surface(id, priority, score = 0) {
  return {
    id,
    priority,
    ranking: { version: 1, score, priority, reasons: [] },
  };
}

function describedSurface(id, priority, score, text) {
  return {
    ...surface(id, priority, score),
    evidence: [text],
    bug_class_hints: [text],
  };
}

function planned(agent, surfaceId) {
  return {
    agent,
    surface_id: surfaceId,
    task_lens: DEFAULT_QUEUE_POLICY.default_wave_task_lens,
    budget: { ...DEFAULT_QUEUE_POLICY.default_wave_task_budget },
  };
}

test("planNextWave wave 1 orders buckets, fills to target, caps high-priority overflow, and labels after dedupe", () => {
  // Cycle D.3 removed the state.explored / state.terminally_blocked /
  // state.lead_surface_ids projection arrays; planNextWave accepts the
  // projected sets explicitly via exploredSurfaceIds /
  // terminallyBlockedSurfaceIds / leadSurfaceIds options.
  const state = { evaluation_wave: 0, pending_wave: null };
  const overflowSurfaces = [
    surface("h5", "HIGH", 10),
    surface("h1", "CRITICAL", 99),
    surface("h4", "HIGH", 20),
    surface("h3", "HIGH", 30),
    surface("h2", "CRITICAL", 80),
    surface("h6", "HIGH", 5),
    surface("h7", "HIGH", 1),
    surface("m1", "MEDIUM", 100),
  ];
  // Off-path via an explicit LEAN override: the conservative 4/6 wave caps overflow
  // the high bucket to max=6 (the original bucket-fill/overflow semantics).
  const highOverflow = planNextWave({
    state,
    surfaces: overflowSurfaces,
    exploredSurfaceIds: [],
    terminallyBlockedSurfaceIds: [],
    leadSurfaceIds: [],
    queuePolicy: LEAN_PROFILE,
  });
  assert.equal(highOverflow.decision, "start_wave");
  assert.deepEqual(highOverflow.assignments, [
    planned("a1", "h1"),
    planned("a2", "h2"),
    planned("a3", "h3"),
    planned("a4", "h4"),
    planned("a5", "h5"),
    planned("a6", "h6"),
  ]);

  // On-default: the raised wave cap (128) lets the same bucket layout reach the
  // full candidate count (min(8, 128) = 8) — no artificial overflow throttle.
  const onDefaultOverflow = planNextWave({
    state,
    surfaces: overflowSurfaces,
    exploredSurfaceIds: [],
    terminallyBlockedSurfaceIds: [],
    leadSurfaceIds: [],
    queuePolicy: DEFAULT_QUEUE_POLICY,
  });
  assert.equal(onDefaultOverflow.assignments.length, 8, "the on-default reaches all 8 candidates");

  const fill = planNextWave({
    state,
    surfaces: [
      surface("low-a", "LOW", 100),
      surface("high-a", "HIGH", 10),
      surface("med-b", "MEDIUM", 20),
      surface("high-b", "HIGH", 5),
      surface("med-a", "MEDIUM", 50),
    ],
    exploredSurfaceIds: [],
    terminallyBlockedSurfaceIds: [],
    leadSurfaceIds: [],
    queuePolicy: LEAN_PROFILE,
  });
  assert.deepEqual(fill.assignments, [
    planned("a1", "high-a"),
    planned("a2", "high-b"),
    planned("a3", "med-a"),
    planned("a4", "med-b"),
  ]);
});

test("planNextWave wave 2+ prioritizes open requeue, lead IDs, remaining priorities, and dedupes earlier buckets", () => {
  const state = {
    evaluation_wave: 1,
    pending_wave: null,
  };
  const surfaces = [
    surface("requeue-high", "HIGH", 20),
    surface("lead-high", "HIGH", 90),
    surface("critical", "CRITICAL", 50),
    surface("medium", "MEDIUM", 99),
    surface("low", "LOW", 99),
    surface("done", "CRITICAL", 100),
    surface("blocked", "CRITICAL", 100),
  ];
  const coverageRecords = [
    { surface_id: "requeue-high", status: "requeue", endpoint: "/a", bug_class: "idor" },
    { surface_id: "done", status: "needs_auth", endpoint: "/b", bug_class: "auth" },
    { surface_id: "blocked", status: "promising", endpoint: "/c", bug_class: "auth" },
  ];

  // Off-path via an explicit LEAN override: the conservative target=4 fills to 4,
  // dropping the lowest-priority `low` below the target (the original semantics).
  const plan = planNextWave({
    state,
    surfaces,
    coverageRecords,
    exploredSurfaceIds: ["done"],
    terminallyBlockedSurfaceIds: ["blocked"],
    leadSurfaceIds: ["lead-high", "requeue-high", "missing-lead"],
    queuePolicy: LEAN_PROFILE,
  });
  assert.deepEqual(plan.buckets.map((bucket) => [bucket.name, bucket.surface_ids]), [
    ["open_requeue", ["requeue-high"]],
    ["lead_surface_ids", ["lead-high"]],
    ["critical_high", ["critical"]],
    ["medium", ["medium"]],
    ["low", ["low"]],
  ]);
  assert.deepEqual(plan.assignments, [
    planned("a1", "requeue-high"),
    planned("a2", "lead-high"),
    planned("a3", "critical"),
    planned("a4", "medium"),
  ]);

  // On-default: the raised target (64) reaches the full candidate count, so `low`
  // is no longer dropped below the target — every open surface is admitted.
  const onDefaultPlan = planNextWave({
    state,
    surfaces,
    coverageRecords,
    exploredSurfaceIds: ["done"],
    terminallyBlockedSurfaceIds: ["blocked"],
    leadSurfaceIds: ["lead-high", "requeue-high", "missing-lead"],
    queuePolicy: DEFAULT_QUEUE_POLICY,
  });
  assert.deepEqual(onDefaultPlan.assignments.map((a) => a.surface_id), [
    "requeue-high", "lead-high", "critical", "medium", "low",
  ]);
});

test("isOpenForAssignment excludes invalid, explored, and terminally blocked surfaces only", () => {
  // Projection sets are passed explicitly after D.3; state.json no longer
  // carries the explored / terminally_blocked arrays.
  const state = {
    dead_ends: ["/closed-endpoint"],
    waf_blocked_endpoints: ["/waf"],
  };
  const options = {
    surfaceIdSet: new Set(["open", "done", "blocked"]),
    exploredSurfaceIds: new Set(["done"]),
    terminallyBlockedSurfaceIds: new Set(["blocked"]),
  };
  assert.equal(isOpenForAssignment("open", state, options), true);
  assert.equal(isOpenForAssignment("done", state, options), false);
  assert.equal(isOpenForAssignment("blocked", state, options), false);
  assert.equal(isOpenForAssignment("missing", state, options), false);
  assert.equal(isOpenForAssignment("", state, options), false);
});

test("planNextWave Test J: max_concurrent_evaluators caps within-wave fan-out (both target and max clamped)", () => {
  // 10 open surfaces, all HIGH so they flow through the overflow-capable
  // critical_high bucket. Standard mode: target=4, max=6.
  const state = { evaluation_wave: 0, pending_wave: null };
  const tenSurfaces = Array.from({ length: 10 }, (_, i) => surface(`h${i}`, "HIGH", 100 - i));
  const baseArgs = {
    state,
    surfaces: tenSurfaces,
    exploredSurfaceIds: [],
    terminallyBlockedSurfaceIds: [],
    leadSurfaceIds: [],
  };

  // cap:3 with standard_wave_max:6 -> exactly 3 assignments.
  const capped3 = planNextWave({
    ...baseArgs,
    queuePolicy: { ...DEFAULT_QUEUE_POLICY, max_concurrent_evaluators: 3 },
  });
  assert.equal(capped3.assignments.length, 3);
  assert.equal(capped3.max_concurrent_evaluators, 3);
  assert.equal(capped3.target_assignments, 3);
  assert.equal(capped3.max_assignments, 3);

  // Deep mode cap:5 -> exactly 5 assignments (deep target=6, max=8).
  const capped5 = planNextWave({
    ...baseArgs,
    state: { ...state, deep_mode: true },
    queuePolicy: { ...DEFAULT_QUEUE_POLICY, max_concurrent_evaluators: 5 },
  });
  assert.equal(capped5.assignments.length, 5);
  assert.equal(capped5.max_concurrent_evaluators, 5);

  // Cap UNSET via an explicit LEAN override -> standard fan-out fills to the
  // conservative max=6 (the off-path behavior, still asserted).
  const uncappedLean = planNextWave({ ...baseArgs, queuePolicy: LEAN_PROFILE });
  assert.equal(uncappedLean.assignments.length, 6);
  assert.equal(uncappedLean.max_concurrent_evaluators, null);

  // Cap UNSET under the on-default -> the raised wave cap (128) lets the wave reach
  // the full candidate count (min(10, 128) = 10): no artificial throttle.
  const uncappedOnDefault = planNextWave({ ...baseArgs });
  assert.equal(uncappedOnDefault.assignments.length, 10, "the on-default reaches all 10 candidates (width = min(candidates, cap))");
  assert.equal(uncappedOnDefault.max_concurrent_evaluators, 128, "the on-default carries the sized in-flight cap");

  // PROVE clamping target too: a low cap that bites a NON-overflow bucket.
  // 1 HIGH (overflow critical_high bucket) + 5 MEDIUM (non-overflow medium
  // bucket, whose limit is remainingTarget). With the naive "clamp max only"
  // bug, target stays at 4 and selection leaks to 4 evaluators despite cap:2.
  // Clamping BOTH target and max caps it at 2.
  const leakProof = planNextWave({
    state,
    surfaces: [
      surface("hi", "HIGH", 100),
      surface("m1", "MEDIUM", 90),
      surface("m2", "MEDIUM", 80),
      surface("m3", "MEDIUM", 70),
      surface("m4", "MEDIUM", 60),
      surface("m5", "MEDIUM", 50),
    ],
    exploredSurfaceIds: [],
    terminallyBlockedSurfaceIds: [],
    leadSurfaceIds: [],
    queuePolicy: { ...DEFAULT_QUEUE_POLICY, max_concurrent_evaluators: 2 },
  });
  assert.equal(leakProof.assignments.length, 2);
});

test("planNextWave: max_total_spawned_agents is the binding breadth ceiling on wave size", () => {
  // The session spawn governor must clamp the WAVE evaluator count, not just the
  // nested-child depth axis. 20 open HIGH surfaces flow through the overflow bucket;
  // width is lifted past the baseline so only the governor can bind the count.
  const state = { evaluation_wave: 0, pending_wave: null };
  const surfaces = Array.from({ length: 20 }, (_, i) => surface(`h${i}`, "HIGH", 100 - i));
  const widePolicy = {
    ...DEFAULT_QUEUE_POLICY,
    standard_wave_target: 500,
    standard_wave_max: 500,
    max_concurrent_evaluators: 500,
  };
  const baseArgs = {
    state,
    surfaces,
    exploredSurfaceIds: [],
    terminallyBlockedSurfaceIds: [],
    leadSurfaceIds: [],
  };

  // Governor 3, nothing reserved -> exactly 3 assignments (the binding ceiling).
  const budget3 = planNextWave({
    ...baseArgs,
    queuePolicy: { ...widePolicy, max_total_spawned_agents: 3 },
    reservedSpawnTotal: 0,
  });
  assert.equal(budget3.assignments.length, 3, "governor clamps wave breadth to the remaining budget");
  assert.equal(budget3.target_assignments, 3);
  assert.equal(budget3.max_assignments, 3);

  // Governor 5 with 2 already reserved -> remaining budget 3.
  const reserved = planNextWave({
    ...baseArgs,
    queuePolicy: { ...widePolicy, max_total_spawned_agents: 5 },
    reservedSpawnTotal: 2,
  });
  assert.equal(reserved.assignments.length, 3, "prior reservations subtract from the breadth budget");

  // Exhausted budget -> zero assignments, spawn_budget_exhausted coverage gap that
  // NAMES the uncovered open surfaces (RANK != BOUND: STOP + report, never a silent
  // drop; the surfaces ride the next drain once budget frees).
  const exhausted = planNextWave({
    ...baseArgs,
    queuePolicy: { ...widePolicy, max_total_spawned_agents: 5 },
    reservedSpawnTotal: 5,
  });
  assert.equal(exhausted.assignments.length, 0);
  assert.equal(exhausted.decision, "spawn_budget_exhausted");
  assert.ok(exhausted.coverage_gap, "exhaustion surfaces a coverage_gap");
  assert.equal(exhausted.coverage_gap.kind, "spawn_budget_exhausted");
  assert.equal(exhausted.coverage_gap.remaining_budget, 0);
  assert.ok(
    exhausted.coverage_gap.uncovered_surface_ids.length > 0,
    "the coverage gap names the uncovered open surfaces, not a silent drop",
  );

  // Governor null via an explicit LEAN override -> byte-identical to the old
  // conservative run (fills to standard_wave_max=6 with baseline width;
  // reservedSpawnTotal is ignored when the governor is unset).
  const offLean = planNextWave({
    ...baseArgs,
    queuePolicy: LEAN_PROFILE,
    reservedSpawnTotal: 999,
  });
  assert.equal(offLean.assignments.length, 6, "the lean override's null governor ignores reservedSpawnTotal — byte-identical");

  // Governor null under the on-default -> the raised wave cap reaches the full
  // candidate count and the null governor still ignores reservedSpawnTotal (no
  // coverage cap; the in-flight cap 128 bounds peak, not total).
  const offOnDefault = planNextWave({
    ...baseArgs,
    queuePolicy: DEFAULT_QUEUE_POLICY,
    reservedSpawnTotal: 999,
  });
  assert.equal(offOnDefault.assignments.length, 20, "the on-default reaches all 20 candidates; the null governor does not bound coverage");
});

test("belief-assisted priority is policy-gated and re-ranks through existing priority bridge", () => {
  withTempHome(() => {
    const domain = "belief-assisted-wave.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
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
    const state = { target: domain, evaluation_wave: 0, pending_wave: null };
    const surfaces = [
      describedSurface("surface:generic", "MEDIUM", 80, "generic admin dashboard"),
      describedSurface("surface:idor", "MEDIUM", 10, "idor victim object unauth succeeds where auth blocked"),
    ];

    const disabled = planNextWave({
      state,
      surfaces,
      exploredSurfaceIds: [],
      terminallyBlockedSurfaceIds: [],
      leadSurfaceIds: [],
      queuePolicy: {
        ...DEFAULT_QUEUE_POLICY,
        standard_wave_target: 1,
        standard_wave_max: 1,
        // The advisory is default-ON; an explicit operator `false` disables it per
        // session (assertBoolean only falls back to the default for null inputs).
        belief_assisted_priority_enabled: false,
      },
    });
    assert.equal(disabled.belief_assisted_priority.enabled, false);
    assert.deepEqual(disabled.assignments, [planned("a1", "surface:generic")]);

    const enabled = planNextWave({
      state,
      surfaces,
      exploredSurfaceIds: [],
      terminallyBlockedSurfaceIds: [],
      leadSurfaceIds: [],
      queuePolicy: {
        ...DEFAULT_QUEUE_POLICY,
        standard_wave_target: 1,
        standard_wave_max: 1,
        belief_assisted_priority_enabled: true,
      },
    });
    assert.equal(enabled.belief_assisted_priority.enabled, true);
    assert.equal(enabled.belief_assisted_priority.applied, true);
    assert.equal(enabled.belief_assisted_priority.hint_count, 1);
    assert.deepEqual(enabled.assignments, [planned("a1", "surface:idor")]);
  });
});

test("isOpenForAssignment excludes an unroutable-route surface (durable coverage gap)", () => {
  const state = {};
  const options = {
    surfaceIdSet: new Set(["routable", "unroutable"]),
    exploredSurfaceIds: new Set(),
    terminallyBlockedSurfaceIds: new Set(),
    unroutableSurfaceIds: new Set(["unroutable"]),
  };
  assert.equal(isOpenForAssignment("routable", state, options), true);
  assert.equal(isOpenForAssignment("unroutable", state, options), false);
  // An empty unroutable set is a no-op: routable planning stays byte-identical.
  assert.equal(
    isOpenForAssignment("unroutable", state, {
      ...options,
      unroutableSurfaceIds: new Set(),
    }),
    true,
  );
});

test("planNextWave excludes a pre-computed unroutable surface without starving its routable sibling", () => {
  const state = { evaluation_wave: 0, pending_wave: null };
  const surfaces = [
    surface("routable-high", "HIGH", 50),
    surface("unroutable-sc", "HIGH", 90),
  ];
  const plan = planNextWave({
    state,
    surfaces,
    exploredSurfaceIds: [],
    terminallyBlockedSurfaceIds: [],
    leadSurfaceIds: [],
    unroutableSurfaceIds: ["unroutable-sc"],
    queuePolicy: DEFAULT_QUEUE_POLICY,
  });
  const plannedIds = plan.assignments.map((a) => a.surface_id);
  assert.ok(!plannedIds.includes("unroutable-sc"), "unroutable surface is never scheduled");
  assert.ok(!plan.candidate_surface_ids.includes("unroutable-sc"), "unroutable surface is not even a candidate");
  assert.ok(plannedIds.includes("routable-high"), "the routable sibling is still scheduled (no starvation)");
});

function writeUnroutableRoutes(domain, unroutableIds, routableIds = []) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const routes = [
    ...routableIds.map((id) => ({
      surface_id: id,
      surface_type: "api",
      capability_pack: "web",
      capability_pack_version: 1,
      evaluator_agent: "evaluator-agent",
      brief_profile: "web",
      context_budget: {
        candidate_pack_limit: 5,
        full_pack_read_limit: 2,
        attempt_log_required: true,
      },
      confidence: "high",
      reasons: [],
    })),
    ...unroutableIds.map((id) => ({
      surface_id: id,
      surface_type: "smart_contract",
      disposition: "unroutable",
      reason: `unresolved chain_family for ${id}`,
      confidence: "low",
      reasons: [],
    })),
  ];
  fs.writeFileSync(
    surfaceRoutesPath(domain),
    `${JSON.stringify({ version: SURFACE_ROUTES_VERSION, route_version: SURFACE_ROUTE_VERSION, routes }, null, 2)}\n`,
  );
}

test("planNextWave does NOT re-schedule an unroutable surface across two consecutive waves (durable, from surface-routes.json)", () => {
  withTempHome(() => {
    const domain = "unroutable-durable-plan.example.com";
    writeUnroutableRoutes(domain, ["unroutable-sc"], ["routable-high"]);
    const surfaces = [
      surface("routable-high", "HIGH", 50),
      surface("unroutable-sc", "HIGH", 90),
    ];

    for (const evaluationWave of [0, 1]) {
      const plan = planNextWave({
        state: { target: domain, evaluation_wave: evaluationWave, pending_wave: null },
        surfaces,
        coverageRecords: [
          { surface_id: "routable-high", status: "requeue", endpoint: "/a", bug_class: "idor" },
          { surface_id: "unroutable-sc", status: "requeue", endpoint: "/b", bug_class: "sc" },
        ],
        queuePolicy: DEFAULT_QUEUE_POLICY,
      });
      const plannedIds = plan.assignments.map((a) => a.surface_id);
      assert.ok(
        !plannedIds.includes("unroutable-sc"),
        `wave ${evaluationWave + 1}: durable unroutable surface is never re-scheduled`,
      );
      assert.ok(
        !plan.candidate_surface_ids.includes("unroutable-sc"),
        `wave ${evaluationWave + 1}: durable unroutable surface is not a candidate`,
      );
      assert.ok(
        plannedIds.includes("routable-high"),
        `wave ${evaluationWave + 1}: the routable sibling is still scheduled (no starvation)`,
      );
    }
  });
});

test("planNextWave with no unroutable routes is byte-identical (missing routes file fails open)", () => {
  withTempHome(() => {
    const domain = "no-unroutable-routes.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    // No surface-routes.json written → readSurfaceRoutesStrict throws (missing)
    // → empty unroutable set → routable planning unchanged.
    const plan = planNextWave({
      state: { target: domain, evaluation_wave: 0, pending_wave: null },
      surfaces: [surface("routable-a", "HIGH", 50), surface("routable-b", "HIGH", 40)],
      queuePolicy: DEFAULT_QUEUE_POLICY,
    });
    const plannedIds = plan.assignments.map((a) => a.surface_id).sort();
    assert.deepEqual(plannedIds, ["routable-a", "routable-b"]);
  });
});

function writeCorruptRoutes(domain, content) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.writeFileSync(surfaceRoutesPath(domain), content);
}

test("deriveUnroutableSurfacesFromRoutes: missing routes fail-open, valid routes yield the set/rows, corrupt routes surface a sanitized error", () => {
  withTempHome(() => {
    const { deriveUnroutableSurfacesFromRoutes } = require("../mcp/core/frontier/surface-router.js");

    // Missing routes file: fail-open (empty set, empty rows, no error).
    const missingDomain = "helper-missing.example.com";
    fs.mkdirSync(sessionDir(missingDomain), { recursive: true });
    const missing = deriveUnroutableSurfacesFromRoutes(missingDomain);
    assert.equal(missing.error, null);
    assert.equal(missing.surfaceIds.size, 0);
    assert.deepEqual(missing.surfaces, []);

    // Valid routes: the unroutable disposition rows flow into both the Set and the rows.
    const validDomain = "helper-valid.example.com";
    writeUnroutableRoutes(validDomain, ["unroutable-sc"], ["routable-high"]);
    const valid = deriveUnroutableSurfacesFromRoutes(validDomain);
    assert.equal(valid.error, null);
    assert.deepEqual(Array.from(valid.surfaceIds), ["unroutable-sc"]);
    assert.deepEqual(valid.surfaces, [
      { surface_id: "unroutable-sc", surface_type: "smart_contract", unroutable_reason: "unresolved chain_family for unroutable-sc" },
    ]);

    // Corrupt routes: distinct sanitized error, empty set (never resurrect).
    const corruptDomain = "helper-corrupt.example.com";
    writeCorruptRoutes(corruptDomain, JSON.stringify({ version: 999, route_version: 999, routes: "nope" }));
    const corrupt = deriveUnroutableSurfacesFromRoutes(corruptDomain);
    assert.equal(corrupt.surfaceIds.size, 0);
    assert.deepEqual(corrupt.surfaces, []);
    assert.ok(corrupt.error, "corruption yields an error");
    assert.equal(corrupt.error.code, "routes_unreadable");
    assert.match(corrupt.error.message, /surface-routes\.json/);
    assert.ok(
      !corrupt.error.message.includes(surfaceRoutesPath(corruptDomain)),
      "the absolute session path is basename-sanitized out of the helper error",
    );
  });
});

test("planNextWave FAILS CLOSED on a corrupt routes file: no plan, no resurrection of a parked surface, sanitized error", () => {
  withTempHome(() => {
    const domain = "planner-corrupt-routes.example.com";
    // First write a VALID routes file that parks `unroutable-sc`, then corrupt it.
    // The corrupt read must NOT resurrect `unroutable-sc` into an assignment.
    writeCorruptRoutes(domain, JSON.stringify({ version: 999, route_version: 999, routes: "not-an-array" }));

    const plan = planNextWave({
      state: { target: domain, evaluation_wave: 0, pending_wave: null },
      surfaces: [surface("routable-high", "HIGH", 50), surface("unroutable-sc", "HIGH", 90)],
      queuePolicy: DEFAULT_QUEUE_POLICY,
    });

    assert.equal(plan.decision, "routes_unreadable", "the planner fails closed with a no-plan decision");
    assert.deepEqual(plan.assignments, [], "no assignments are minted off a corrupt artifact");
    assert.deepEqual(plan.candidate_surface_ids, [], "no candidates are selected off a corrupt artifact");
    // The never-reschedule invariant: the parked surface is NOT resurrected, and
    // neither is any routable sibling planned off the corrupt read.
    assert.ok(plan.routes_error, "the corruption is surfaced, not swallowed");
    assert.equal(plan.routes_error.code, "routes_unreadable");
    assert.match(plan.reason, /surface-routes\.json/);
    assert.ok(
      !plan.reason.includes(surfaceRoutesPath(domain)),
      "the planner routes_error basename-sanitizes (no absolute session path leak)",
    );
  });
});

test("planNextWave FAILS CLOSED when any route row is quarantined", () => {
  withTempHome(() => {
    const domain = "planner-quarantined-route.example.com";
    writeCorruptRoutes(domain, JSON.stringify({
      version: SURFACE_ROUTES_VERSION,
      route_version: SURFACE_ROUTE_VERSION,
      routes: [{
        surface_id: "surface:physical",
        surface_type: "api",
        surface_class: "physical",
        capability_pack: "web",
        capability_pack_version: 1,
        evaluator_agent: "evaluator-agent",
        brief_profile: "web",
        context_budget: {
          candidate_pack_limit: 5,
          full_pack_read_limit: 2,
          attempt_log_required: true,
        },
      }],
    }));

    const plan = planNextWave({
      state: { target: domain, evaluation_wave: 0, pending_wave: null },
      surfaces: [surface("surface:physical", "HIGH", 90)],
      queuePolicy: DEFAULT_QUEUE_POLICY,
    });

    assert.equal(plan.decision, "routes_quarantined");
    assert.deepEqual(plan.assignments, []);
    assert.deepEqual(plan.candidate_surface_ids, []);
    assert.equal(plan.routes_quarantine.malformed_route_count, 1);
    assert.match(plan.routes_quarantine.repair_hint, /bob_route_surfaces/);
  });
});

test("planNextWave + deriveUnroutableSurfacesFromRoutes derive the identical unroutable set from one file", () => {
  withTempHome(() => {
    const { deriveUnroutableSurfacesFromRoutes } = require("../mcp/core/frontier/surface-router.js");
    const domain = "planner-status-parity.example.com";
    writeUnroutableRoutes(domain, ["unroutable-sc"], ["routable-high"]);

    const helper = deriveUnroutableSurfacesFromRoutes(domain);
    const plan = planNextWave({
      state: { target: domain, evaluation_wave: 0, pending_wave: null },
      surfaces: [surface("routable-high", "HIGH", 50), surface("unroutable-sc", "HIGH", 90)],
      queuePolicy: DEFAULT_QUEUE_POLICY,
    });

    // The planner excludes exactly the helper's parked surface, and admits the sibling.
    for (const parkedId of helper.surfaceIds) {
      assert.ok(!plan.candidate_surface_ids.includes(parkedId), `planner never schedules parked ${parkedId}`);
    }
    assert.ok(plan.assignments.map((a) => a.surface_id).includes("routable-high"), "routable sibling still planned");
  });
});

test("planNextWave returns pending-wave settle before selecting candidates", () => {
  const plan = planNextWave({
    state: {
      evaluation_wave: 2,
      pending_wave: 3,
    },
    surfaces: [surface("high", "CRITICAL", 100)],
    exploredSurfaceIds: [],
    terminallyBlockedSurfaceIds: [],
    leadSurfaceIds: [],
  });
  assert.equal(plan.decision, "pending_wave_settle");
  assert.deepEqual(plan.assignments, []);
  assert.deepEqual(plan.buckets, []);
  assert.equal(plan.pending_wave, 3);
});
