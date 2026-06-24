"use strict";

// Cross-role fan-out on-default lock. The shipped DEFAULT_QUEUE_POLICY now drives
// recon multi-modal sweep + cell-floor/nested width with raised WIDTH/PARALLELISM
// caps and a NULL lifetime governor (unbounded fixpoint, no coverage cap). These
// tests pin the flipped default field-by-field, prove normalizeQueuePolicy does
// NOT auto-fill a coverage-bounding governor for the shipped default (RANK !=
// BOUND), prove an operator who raises a knob ABOVE the default still re-arms the
// safety governor, prove LEAN_PROFILE restores the old conservative run, prove
// host-fail-closed degrades non-self-managing hosts to flat/single, and drive the
// real multi-wave drain to a fixpoint that covers every surface.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  DEFAULT_QUEUE_POLICY,
  CONSERVATIVE_WIDTH_BASELINE,
  DEFAULT_NESTING_SPAWN_BUDGET,
  LEAN_PROFILE,
  MAX_COVERAGE_PROFILE,
  normalizeQueuePolicy,
} = require("../mcp/lib/queue-policy.js");
const {
  effectiveConcurrencyCap,
  effectiveSpawnDepth,
} = require("../mcp/lib/nested-spawn.js");
const { deriveReconAnglePlan } = require("../mcp/lib/recon-angle-plan.js");
const { planNextWave } = require("../mcp/lib/wave-planner.js");
const { appendSpawnLedgerEntry, readSpawnLedgerEntries, spawnLedgerTotal } = require("../mcp/lib/spawn-ledger.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-on-default-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function surface(id) {
  return {
    id,
    hosts: [`https://${id}.example.com`],
    priority: "HIGH",
    ranking: { version: 1, score: 100, priority: "HIGH", reasons: [] },
  };
}

// ── the flipped default, field by field ──────────────────────────────────────

test("the shipped DEFAULT_QUEUE_POLICY drives cross-role fan-out: depth 3, 64 children, 128 in-flight, 64/128 waves", () => {
  assert.equal(DEFAULT_QUEUE_POLICY.max_spawn_depth, 3, "nesting on (one level of child cells)");
  assert.equal(DEFAULT_QUEUE_POLICY.max_spawn_children, 64);
  assert.equal(DEFAULT_QUEUE_POLICY.max_concurrent_evaluators, 128, "the sized in-flight peak-load cap");
  assert.equal(DEFAULT_QUEUE_POLICY.max_parallel_tasks, 128);
  assert.equal(DEFAULT_QUEUE_POLICY.standard_wave_target, 64);
  assert.equal(DEFAULT_QUEUE_POLICY.standard_wave_max, 128);
  assert.equal(DEFAULT_QUEUE_POLICY.deep_wave_target, 64);
  assert.equal(DEFAULT_QUEUE_POLICY.deep_wave_max, 128);
  // THE CRUX — RANK != BOUND: width is raised WITHOUT a coverage cap.
  assert.equal(DEFAULT_QUEUE_POLICY.max_total_spawned_agents, null, "lifetime governor stays null = unbounded fixpoint");
  // The normalized default carries the same field values (round-trips clean).
  const n = normalizeQueuePolicy(DEFAULT_QUEUE_POLICY);
  assert.equal(n.max_spawn_depth, 3);
  assert.equal(n.max_spawn_children, 64);
  assert.equal(n.max_concurrent_evaluators, 128);
  assert.equal(n.max_parallel_tasks, 128);
  assert.equal(n.standard_wave_max, 128);
  assert.equal(n.deep_wave_max, 128);
});

// ── the RANK != BOUND guard: the shipped default is exempt from the auto-fill ──

test("the shipped on-default is EXEMPT from the governor auto-fill — its null governor survives normalization", () => {
  // The auto-fill would otherwise see depth>1 / raised width and bound coverage at
  // DEFAULT_NESTING_SPAWN_BUDGET on a big target. The frozen-baseline comparison +
  // shipped-default exemption keep the governor null.
  assert.equal(normalizeQueuePolicy(DEFAULT_QUEUE_POLICY).max_total_spawned_agents, null);
  assert.equal(normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY }).max_total_spawned_agents, null);
});

test("an operator who raises a knob ABOVE the on-default still gets the safety auto-fill", () => {
  // wave width above 128 -> re-arm.
  const wideWave = normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, standard_wave_max: 256, standard_wave_target: 256 });
  assert.equal(wideWave.max_total_spawned_agents, DEFAULT_NESTING_SPAWN_BUDGET, "wave width above the default re-arms the governor");
  // depth above 3 -> re-arm.
  const deeper = normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_depth: 5 });
  assert.equal(deeper.max_total_spawned_agents, DEFAULT_NESTING_SPAWN_BUDGET, "depth above the default re-arms the governor");
  // in-flight cap above 128 -> re-arm.
  const wideConc = normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_concurrent_evaluators: 256 });
  assert.equal(wideConc.max_total_spawned_agents, DEFAULT_NESTING_SPAWN_BUDGET, "in-flight cap above the default re-arms the governor");
});

test("an explicit max_total_spawned_agents on top of the on-default is never overridden", () => {
  const explicit = normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_total_spawned_agents: 777 });
  assert.equal(explicit.max_total_spawned_agents, 777, "an explicit governor is respected — never overridden");
  const explicitWide = normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, standard_wave_max: 256, standard_wave_target: 256, max_total_spawned_agents: 2000 });
  assert.equal(explicitWide.max_total_spawned_agents, 2000);
});

// ── off-path reachability: LEAN restores the old conservative run ─────────────

test("LEAN_PROFILE restores the old conservative run byte-identically (the flip changed the default, not the floor)", () => {
  const lean = normalizeQueuePolicy(LEAN_PROFILE);
  assert.equal(lean.max_spawn_depth, 1, "no nesting");
  assert.equal(lean.max_spawn_children, 8);
  assert.equal(lean.max_concurrent_evaluators, null, "no in-flight cap — waves governed solely by the wave caps");
  assert.equal(lean.max_parallel_tasks, 4);
  assert.equal(lean.standard_wave_target, 4);
  assert.equal(lean.standard_wave_max, 6);
  assert.equal(lean.deep_wave_target, 6);
  assert.equal(lean.deep_wave_max, 8);
  assert.equal(lean.max_total_spawned_agents, null, "lean keeps the governor null — width is at/below the frozen baseline");
});

test("the frozen CONSERVATIVE_WIDTH_BASELINE captures the old conservative width/depth", () => {
  assert.equal(CONSERVATIVE_WIDTH_BASELINE.max_spawn_depth, 1);
  assert.equal(CONSERVATIVE_WIDTH_BASELINE.standard_wave_target, 4);
  assert.equal(CONSERVATIVE_WIDTH_BASELINE.standard_wave_max, 6);
  assert.equal(CONSERVATIVE_WIDTH_BASELINE.deep_wave_target, 6);
  assert.equal(CONSERVATIVE_WIDTH_BASELINE.deep_wave_max, 8);
});

test("planNextWave under LEAN_PROFILE selects exactly the legacy 6-of-8 wave (off-path still selects the conservative wave)", () => {
  const sfn = (id, prio, score) => ({ id, priority: prio, ranking: { version: 1, score, priority: prio, reasons: [] } });
  const plan = planNextWave({
    state: { evaluation_wave: 0, pending_wave: null },
    surfaces: [
      sfn("h5", "HIGH", 10), sfn("h1", "CRITICAL", 99), sfn("h4", "HIGH", 20),
      sfn("h3", "HIGH", 30), sfn("h2", "CRITICAL", 80), sfn("h6", "HIGH", 5),
      sfn("h7", "HIGH", 1), sfn("m1", "MEDIUM", 100),
    ],
    exploredSurfaceIds: [],
    terminallyBlockedSurfaceIds: [],
    leadSurfaceIds: [],
    queuePolicy: normalizeQueuePolicy(LEAN_PROFILE),
  });
  assert.equal(plan.assignments.length, 6, "lean wave caps to standard_wave_max=6 of the 8 candidates");
  assert.deepEqual(plan.assignments.map((a) => a.surface_id), ["h1", "h2", "h3", "h4", "h5", "h6"]);
});

test("MAX_COVERAGE_PROFILE differs from the on-default ONLY by setting a finite governor", () => {
  const max = normalizeQueuePolicy(MAX_COVERAGE_PROFILE);
  const def = normalizeQueuePolicy(DEFAULT_QUEUE_POLICY);
  for (const k of ["max_spawn_depth", "max_spawn_children", "max_concurrent_evaluators", "max_parallel_tasks", "standard_wave_max", "deep_wave_max"]) {
    assert.equal(max[k], def[k], `${k} matches the on-default`);
  }
  assert.equal(max.max_total_spawned_agents, 512, "the cost-ceilinged profile sets a finite governor");
  assert.equal(def.max_total_spawned_agents, null, "the default keeps it null");
});

// ── host-fail-closed under the on-default ────────────────────────────────────

test("host-fail-closed: the on-default in-flight cap and depth degrade to 1/1 on non-self-managing hosts", () => {
  // claude/codex self-manage -> honor the requested width/depth.
  assert.equal(effectiveConcurrencyCap(DEFAULT_QUEUE_POLICY.max_concurrent_evaluators, "claude"), 128);
  assert.equal(effectiveSpawnDepth(DEFAULT_QUEUE_POLICY.max_spawn_depth, "claude"), 3);
  assert.equal(effectiveSpawnDepth(DEFAULT_QUEUE_POLICY.max_spawn_depth, "codex"), 3);
  // finite-pool / unknown / empty hosts clamp the raised default to a single agent.
  for (const host of ["kimi", "generic-mcp", "unknown-host", ""]) {
    assert.equal(effectiveConcurrencyCap(DEFAULT_QUEUE_POLICY.max_concurrent_evaluators, host), 1, `${host} in-flight clamps to 1`);
    assert.equal(effectiveSpawnDepth(DEFAULT_QUEUE_POLICY.max_spawn_depth, host), 1, `${host} depth clamps to 1`);
  }
});

test("host-fail-closed: recon fans out only on a self-managing host under the on-default's null governor", () => {
  // The on-default keeps the governor null, so recon never degrades on its budget.
  for (const host of ["claude", "codex"]) {
    const plan = deriveReconAnglePlan({ host_id: host, governor: { max_total_spawned_agents: DEFAULT_QUEUE_POLICY.max_total_spawned_agents, total_spawned: 0 } });
    assert.equal(plan.mode, "fanout", `${host} fans recon under the on-default`);
  }
  for (const host of ["kimi", "generic-mcp", "unknown", ""]) {
    const plan = deriveReconAnglePlan({ host_id: host, governor: { max_total_spawned_agents: DEFAULT_QUEUE_POLICY.max_total_spawned_agents, total_spawned: 0 } });
    assert.equal(plan.mode, "sequential", `${host} fails closed to a single sequential recon agent`);
    assert.equal(plan.degrade_reason, "host_pool_finite");
    // RANK != BOUND: every angle is still present in the degraded single agent.
    assert.equal(plan.angles.length, 4);
  }
});

// ── the on-default does NOT bound coverage: a multi-wave drain reaches fixpoint ─

test("on-default coverage-not-bounded: the SHIPPED default drains every surface with no coverage gap (governor null = no cap)", () => withTempHome(() => {
  const domain = "on-default-drain.example.com";
  const TOTAL = 40;
  // The literal shipped on-default (governor null). Its raised wave caps (128) admit
  // every surface; the null governor must never STOP the drain or emit a gap.
  const surfaces = Array.from({ length: TOTAL }, (_, i) => surface(`s${String(i).padStart(2, "0")}`));
  const policy = normalizeQueuePolicy(DEFAULT_QUEUE_POLICY);
  assert.equal(policy.max_total_spawned_agents, null, "the shipped on-default keeps the governor null");

  const explored = new Set();
  let evaluationWave = 0;
  const dispatched = [];
  for (let i = 0; i < TOTAL + 10; i += 1) {
    const plan = planNextWave({
      state: { target: domain, evaluation_wave: evaluationWave, pending_wave: null },
      surfaces,
      exploredSurfaceIds: explored,
      terminallyBlockedSurfaceIds: [],
      leadSurfaceIds: [],
      queuePolicy: policy,
      reservedSpawnTotal: spawnLedgerTotal(domain),
    });
    assert.equal(plan.coverage_gap, undefined, "null governor never STOPS with a coverage gap");
    if (plan.decision !== "start_wave") break;
    for (const a of plan.assignments) {
      explored.add(a.surface_id);
      dispatched.push(a.surface_id);
    }
    evaluationWave += 1;
  }

  assert.deepEqual(readSpawnLedgerEntries(domain), [], "null governor writes no ledger rows");
  assert.equal(new Set(dispatched).size, TOTAL, "fixpoint: every surface covered — coverage is NOT bounded by the on-default");
}));

test("coverage-not-bounded across waves: a null-governor profile with small per-wave caps still reaches fixpoint over all surfaces", () => withTempHome(() => {
  const domain = "on-default-drain-multiwave.example.com";
  const TOTAL = 40;
  // Nesting off + small wave caps below the conservative baseline keep the governor
  // null (no auto-fill), so the ONLY axis that could bound coverage is the governor —
  // and a null governor must drain across many waves to a fixpoint that covers all.
  const surfaces = Array.from({ length: TOTAL }, (_, i) => surface(`s${String(i).padStart(2, "0")}`));
  // LEAN width is at the conservative baseline, so the governor stays null; the
  // small standard_wave_max=6 forces the 40 surfaces across many waves.
  const policy = normalizeQueuePolicy(LEAN_PROFILE);
  assert.equal(policy.max_total_spawned_agents, null, "a null-governor profile stays null (no coverage cap)");

  const explored = new Set();
  let evaluationWave = 0;
  const dispatched = [];
  for (let i = 0; i < TOTAL + 10; i += 1) {
    const plan = planNextWave({
      state: { target: domain, evaluation_wave: evaluationWave, pending_wave: null },
      surfaces,
      exploredSurfaceIds: explored,
      terminallyBlockedSurfaceIds: [],
      leadSurfaceIds: [],
      queuePolicy: policy,
      reservedSpawnTotal: spawnLedgerTotal(domain),
    });
    assert.equal(plan.coverage_gap, undefined, "null governor never STOPS with a coverage gap");
    if (plan.decision !== "start_wave") break;
    for (const a of plan.assignments) {
      explored.add(a.surface_id);
      dispatched.push(a.surface_id);
    }
    evaluationWave += 1;
  }

  assert.equal(new Set(dispatched).size, TOTAL, "fixpoint: every surface covered across waves — coverage NOT bounded");
  assert.ok(evaluationWave >= 2, "the drain spanned multiple waves (cross-wave coverage)");
}));

test("explicit-governor-under-on-default: an operator-set lifetime cap STOPS+reports the coverage gap (RANK != BOUND report path intact)", () => withTempHome(() => {
  const domain = "on-default-capped.example.com";
  const TOTAL = 20;
  const GOVERNOR = 5;
  const surfaces = Array.from({ length: TOTAL }, (_, i) => surface(`s${String(i).padStart(2, "0")}`));
  // The on-default plus an explicit lifetime ceiling, nesting off so each root costs
  // one slot. The drain must STOP at the ceiling and NAME the uncovered surfaces.
  const policy = normalizeQueuePolicy({
    ...DEFAULT_QUEUE_POLICY,
    max_spawn_depth: 1,
    standard_wave_target: 3,
    standard_wave_max: 3,
    max_total_spawned_agents: GOVERNOR,
  });
  assert.equal(policy.max_total_spawned_agents, GOVERNOR, "explicit governor honored");

  const explored = new Set();
  let evaluationWave = 0;
  const dispatched = [];
  let finalPlan = null;
  for (let i = 0; i < TOTAL + 5; i += 1) {
    const reservedSpawnTotal = spawnLedgerTotal(domain);
    const plan = planNextWave({
      state: { target: domain, evaluation_wave: evaluationWave, pending_wave: null },
      surfaces,
      exploredSurfaceIds: explored,
      terminallyBlockedSurfaceIds: [],
      leadSurfaceIds: [],
      queuePolicy: policy,
      reservedSpawnTotal,
    });
    finalPlan = plan;
    if (plan.decision !== "start_wave") break;
    for (const a of plan.assignments) {
      appendSpawnLedgerEntry(domain, {
        ts: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
        wave: `w${plan.wave_number}`,
        parent_agent: a.agent,
        surface_id: a.surface_id,
        depth: 0,
        branching: 0,
        root_count: 1,
        descendant_tree: 0,
        worst_case_tree: 1,
      });
      explored.add(a.surface_id);
      dispatched.push(a.surface_id);
    }
    evaluationWave += 1;
  }

  assert.equal(spawnLedgerTotal(domain), GOVERNOR, "never over-spawns past the explicit ceiling");
  assert.equal(dispatched.length, GOVERNOR);
  assert.equal(finalPlan.decision, "spawn_budget_exhausted", "STOP + report, not a silent drop");
  assert.equal(finalPlan.coverage_gap.kind, "spawn_budget_exhausted");
  assert.equal(finalPlan.coverage_gap.uncovered_surface_ids.length, TOTAL - GOVERNOR, "the remainder is named, not dropped");
}));
