const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  CLAMP_CEILING,
  DEFAULT_NESTING_SPAWN_BUDGET,
  MAX_COVERAGE_PROFILE,
  DEFAULT_QUEUE_POLICY,
  loadQueuePolicy,
  normalizeQueuePolicy,
  writeQueuePolicy,
} = require("../mcp/lib/queue-policy.js");

// Review HIGH: nesting opt-in must never be ungoverned. Lifting max_spawn_depth past 1
// without a session spawn budget would expose the large CLAMP_CEILING width with no
// preventive spawn-tree bound, so normalizeQueuePolicy fills the governor.
test("normalizeQueuePolicy: nesting opt-in without a budget defaults the spawn governor", () => {
  const nested = normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_depth: 3 });
  assert.equal(nested.max_total_spawned_agents, DEFAULT_NESTING_SPAWN_BUDGET, "depth>1 + null budget => safe default governor");

  const explicit = normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_depth: 3, max_total_spawned_agents: 1000 });
  assert.equal(explicit.max_total_spawned_agents, 1000, "an explicit budget is respected, never overridden");

  const off = normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY });
  assert.equal(off.max_spawn_depth, 1);
  assert.equal(off.max_total_spawned_agents, null, "default-off (depth=1) stays ungoverned-but-inert — byte-identical");
});
const {
  planNextWave,
} = require("../mcp/lib/wave-planner.js");
const {
  queuePolicyPath,
  sessionDir,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-queue-policy-wiring-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function ensureSessionDir(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

function surface(id, priority, score = 0) {
  return {
    id,
    priority,
    ranking: { version: 1, score, priority, reasons: [] },
  };
}

function baseState() {
  return {
    evaluation_wave: 0,
    pending_wave: null,
    explored: [],
    terminally_blocked: [],
    lead_surface_ids: [],
  };
}

test("CN clamp lift: an operator may widen waves/concurrency past the old 128 (up to CLAMP_CEILING)", () => {
  // "fuck the clamp": 128 was an arbitrary sanity bound, not a physical limit. The
  // operator sets the width; the host pool + spawn budget are the real governors.
  assert.equal(CLAMP_CEILING, 4096);
  const p = normalizeQueuePolicy({
    deep_wave_max: 500,
    deep_wave_target: 500,
    standard_wave_max: 500,
    standard_wave_target: 500,
    max_concurrent_evaluators: 500,
    max_parallel_tasks: 500,
  });
  assert.equal(p.deep_wave_max, 500, "deep_wave_max honors 500 (was clamped to 128)");
  assert.equal(p.max_concurrent_evaluators, 500, "max_concurrent_evaluators honors 500");
  assert.equal(p.max_parallel_tasks, 500, "max_parallel_tasks honors 500 (feeds cell-floor capacity)");
  // The ceiling stays finite: a value above CLAMP_CEILING is rejected, as is garbage.
  assert.throws(() => normalizeQueuePolicy({ deep_wave_max: CLAMP_CEILING + 1, deep_wave_target: 1 }), /<= 4096/, "above CLAMP_CEILING is rejected (finite ceiling)");
  assert.throws(() => normalizeQueuePolicy({ deep_wave_max: -1 }), "negative is still rejected");
});

test("CN clamp lift does NOT touch friction_promotion_threshold (unrelated knob keeps its own 128 cap)", () => {
  assert.throws(() => normalizeQueuePolicy({ friction_promotion_threshold: 500 }), /<= 128/, "friction_promotion_threshold rejects >128, unchanged by the lift");
});

test("MAX_COVERAGE_PROFILE applies in one call: depth-3 nested + maxed cell floor + governor, cross-guards satisfied", () => {
  const p = normalizeQueuePolicy(MAX_COVERAGE_PROFILE);
  assert.equal(p.max_spawn_depth, 3, "3 degrees of nesting");
  assert.equal(p.max_spawn_children, 64);
  assert.equal(p.max_concurrent_evaluators, 128, "in-flight cap (cell floor + waves share it)");
  assert.equal(p.max_total_spawned_agents, 512, "the spawn budget governor is set (not null)");
  assert.equal(p.deep_wave_max, 128);
  assert.ok(p.deep_wave_max >= p.deep_wave_target, "cross-guard pre-satisfied");
  assert.ok(p.standard_wave_max >= p.standard_wave_target);
  // It is an OPT-IN, not the default: DEFAULT_QUEUE_POLICY stays nesting-off.
  assert.equal(DEFAULT_QUEUE_POLICY.max_spawn_depth, 1, "default stays flat/no-nesting");
  assert.equal(DEFAULT_QUEUE_POLICY.max_total_spawned_agents, null, "default governor is unset");
});

test("reversed priority_order in queue-policy.json reorders wave-planner buckets", () => {
  withTempHome(() => {
    const domain = "reversed-priority.example.com";
    ensureSessionDir(domain);
    // The "critical_high" bucket from the cycle spec is a bucket label, not a
    // queue priority token; the policy's priority_order operates on the four
    // queue-priority tokens. A reversed order that places low/medium before
    // critical/high captures the cycle's intent: schedule low-priority surfaces
    // before high-priority ones.
    writeQueuePolicy(domain, {
      priority_order: ["low", "medium", "critical", "high"],
    });
    const policy = loadQueuePolicy(domain);
    assert.deepEqual(policy.priority_order, ["low", "medium", "critical", "high"]);

    const plan = planNextWave({
      state: baseState(),
      surfaces: [
        surface("h1", "CRITICAL", 99),
        surface("h2", "HIGH", 50),
        surface("m1", "MEDIUM", 80),
        surface("l1", "LOW", 10),
      ],
      queuePolicy: policy,
    });
    assert.equal(plan.decision, "start_wave");
    // With priority_order=[low, medium, critical, high], the wave-planner
    // produces a low-first bucket layout. The low-priority surface should be
    // scheduled before any critical/high one.
    assert.equal(plan.assignments[0].surface_id, "l1");
    assert.equal(plan.assignments[1].surface_id, "m1");
  });
});

test("default queue policy produces the same wave-1 ordering as the legacy constants", () => {
  withTempHome(() => {
    const domain = "default-policy.example.com";
    ensureSessionDir(domain);

    const policy = loadQueuePolicy(domain);
    assert.deepEqual(policy.priority_order, DEFAULT_QUEUE_POLICY.priority_order);
    assert.equal(policy.standard_wave_target, 4);
    assert.equal(policy.standard_wave_max, 6);
    assert.equal(policy.deep_wave_target, 6);
    assert.equal(policy.deep_wave_max, 8);
    assert.equal(policy.default_wave_task_lens, "surface_scout");
    assert.deepEqual(policy.default_wave_task_budget, { max_steps: 6, max_context_tokens: 24000 });

    const surfaces = [
      surface("h5", "HIGH", 10),
      surface("h1", "CRITICAL", 99),
      surface("h4", "HIGH", 20),
      surface("h3", "HIGH", 30),
      surface("h2", "CRITICAL", 80),
      surface("h6", "HIGH", 5),
      surface("h7", "HIGH", 1),
      surface("m1", "MEDIUM", 100),
    ];
    const plan = planNextWave({
      state: baseState(),
      surfaces,
      queuePolicy: policy,
    });
    assert.deepEqual(
      plan.assignments.map((assignment) => assignment.surface_id),
      ["h1", "h2", "h3", "h4", "h5", "h6"],
    );
    for (const assignment of plan.assignments) {
      assert.equal(assignment.task_lens, "surface_scout");
      assert.deepEqual(assignment.budget, { max_steps: 6, max_context_tokens: 24000 });
    }
  });
});

test("loadQueuePolicy falls back to DEFAULT_QUEUE_POLICY when queue-policy.json absent", () => {
  withTempHome(() => {
    const domain = "absent-policy.example.com";
    ensureSessionDir(domain);
    assert.equal(fs.existsSync(queuePolicyPath(domain)), false);
    const policy = loadQueuePolicy(domain);
    assert.deepEqual(policy, normalizeQueuePolicy(DEFAULT_QUEUE_POLICY));
  });
});

test("wave-planner.js no longer carries the legacy queue constants", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "mcp", "lib", "wave-planner.js"), "utf8");
  for (const constant of [
    "STANDARD_WAVE_TARGET",
    "STANDARD_WAVE_MAX",
    "DEEP_WAVE_TARGET",
    "DEEP_WAVE_MAX",
    "DEFAULT_WAVE_TASK_LENS",
    "DEFAULT_WAVE_TASK_BUDGET",
  ]) {
    assert.ok(
      !source.includes(constant),
      `wave-planner.js still references legacy constant ${constant}`,
    );
  }
});

test("task-queue.json materialized view drives wave ordering when present", () => {
  withTempHome(() => {
    const domain = "materialized-queue.example.com";
    ensureSessionDir(domain);

    const surfaces = [
      surface("s-low", "LOW", 0),
      surface("s-crit", "CRITICAL", 0),
      surface("s-med", "MEDIUM", 0),
    ];
    const taskQueueTasks = [
      {
        task_id: "T-1",
        surface_id: "s-low",
        priority: "low",
        status: "queued",
        created_at: "2026-01-01T00:00:00.000Z",
      },
      {
        task_id: "T-2",
        surface_id: "s-crit",
        priority: "critical",
        status: "queued",
        created_at: "2026-01-01T00:00:01.000Z",
      },
      {
        task_id: "T-3",
        surface_id: "s-med",
        priority: "medium",
        status: "queued",
        created_at: "2026-01-01T00:00:02.000Z",
      },
    ];

    const policyDefault = loadQueuePolicy(domain);
    const planDefault = planNextWave({
      state: baseState(),
      surfaces,
      taskQueueTasks,
      queuePolicy: policyDefault,
    });
    assert.deepEqual(
      planDefault.assignments.map((a) => a.surface_id),
      ["s-crit", "s-med", "s-low"],
      "default policy sorts task-queue rows critical → medium → low",
    );

    writeQueuePolicy(domain, { priority_order: ["low", "medium", "critical", "high"] });
    const policyLowFirst = loadQueuePolicy(domain);
    const planLowFirst = planNextWave({
      state: baseState(),
      surfaces,
      taskQueueTasks,
      queuePolicy: policyLowFirst,
    });
    assert.deepEqual(
      planLowFirst.assignments.map((a) => a.surface_id),
      ["s-low", "s-med", "s-crit"],
      "reversed priority_order schedules low-priority task-queue rows first",
    );
  });
});
