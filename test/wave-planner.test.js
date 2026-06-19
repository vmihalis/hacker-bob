const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  isOpenForAssignment,
  planNextWave,
} = require("../mcp/lib/wave-planner.js");
const {
  DEFAULT_QUEUE_POLICY,
} = require("../mcp/lib/queue-policy.js");
const {
  appendEdges,
} = require("../mcp/lib/surface-graph.js");
const {
  sessionDir,
} = require("../mcp/lib/paths.js");

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
  const highOverflow = planNextWave({
    state,
    surfaces: [
      surface("h5", "HIGH", 10),
      surface("h1", "CRITICAL", 99),
      surface("h4", "HIGH", 20),
      surface("h3", "HIGH", 30),
      surface("h2", "CRITICAL", 80),
      surface("h6", "HIGH", 5),
      surface("h7", "HIGH", 1),
      surface("m1", "MEDIUM", 100),
    ],
    exploredSurfaceIds: [],
    terminallyBlockedSurfaceIds: [],
    leadSurfaceIds: [],
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

  const plan = planNextWave({
    state,
    surfaces,
    coverageRecords,
    exploredSurfaceIds: ["done"],
    terminallyBlockedSurfaceIds: ["blocked"],
    leadSurfaceIds: ["lead-high", "requeue-high", "missing-lead"],
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

  // Cap UNSET -> backward compatible: standard fan-out fills to max=6.
  const uncapped = planNextWave({ ...baseArgs });
  assert.equal(uncapped.assignments.length, 6);
  assert.equal(uncapped.max_concurrent_evaluators, null);

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
