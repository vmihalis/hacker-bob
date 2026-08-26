"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  RECON_ANGLES,
  deriveReconAnglePlan,
} = require("../mcp/core/frontier/recon-angle-plan.js");

const EXPECTED_ANGLE_IDS = ["host_family", "urls", "nuclei", "js_jwt"];

// The union of all four angles' steps must equal the full 7-step coverage
// (step 1, the binary check, is re-run by every angle; steps 2-7 are partitioned
// disjointly across the angles). No step is dropped.
test("the four angles partition steps 2-7 disjointly and cover them exhaustively", () => {
  const ids = RECON_ANGLES.map((a) => a.id);
  assert.deepEqual(ids, EXPECTED_ANGLE_IDS);

  const seen = [];
  for (const angle of RECON_ANGLES) {
    for (const step of angle.steps) seen.push(step);
  }
  // Disjoint: no step appears twice.
  assert.deepEqual([...seen].sort((x, y) => x - y), [...new Set(seen)].sort((x, y) => x - y));
  // Exhaustive over steps 2..7 (step 1 is per-angle, the assembly is the Last step).
  assert.deepEqual([...seen].sort((x, y) => x - y), [2, 3, 4, 5, 6, 7]);
});

test("default (claude host, no governor) fans out all four angles in order", () => {
  const plan = deriveReconAnglePlan({ deep_mode: false, host_id: "claude", governor: null });
  assert.equal(plan.mode, "fanout");
  assert.deepEqual(plan.angles.map((a) => a.id), EXPECTED_ANGLE_IDS);
  assert.equal(plan.degrade_reason, undefined);
  assert.equal(plan.governor_gap, undefined);
});

test("codex (self-managing pool) also fans out", () => {
  const plan = deriveReconAnglePlan({ deep_mode: false, host_id: "codex", governor: null });
  assert.equal(plan.mode, "fanout");
  assert.deepEqual(plan.angles.map((a) => a.id), EXPECTED_ANGLE_IDS);
});

test("finite-pool hosts degrade to a single sequential agent that still runs all angles", () => {
  for (const host of ["kimi", "generic-mcp", "unknown", "", "some-future-host"]) {
    const plan = deriveReconAnglePlan({ deep_mode: false, host_id: host, governor: null });
    assert.equal(plan.mode, "sequential", `host ${host} must fail-closed to sequential`);
    assert.equal(plan.degrade_reason, "host_pool_finite");
    // RANK != BOUND: even degraded, ALL four angles are present (the single agent runs them all).
    assert.deepEqual(plan.angles.map((a) => a.id), EXPECTED_ANGLE_IDS);
  }
});

test("a missing/undefined host_id fail-closes to sequential (no over-spawn on an unknown host)", () => {
  const plan = deriveReconAnglePlan({});
  assert.equal(plan.mode, "sequential");
  assert.equal(plan.degrade_reason, "host_pool_finite");
  assert.deepEqual(plan.angles.map((a) => a.id), EXPECTED_ANGLE_IDS);
});

test("governor with ample budget keeps fanout", () => {
  const plan = deriveReconAnglePlan({
    host_id: "claude",
    governor: { max_total_spawned_agents: 64, total_spawned: 0 },
  });
  assert.equal(plan.mode, "fanout");
  assert.deepEqual(plan.angles.map((a) => a.id), EXPECTED_ANGLE_IDS);
});

test("null max_total_spawned_agents (default, unbounded) keeps fanout", () => {
  const plan = deriveReconAnglePlan({
    host_id: "claude",
    governor: { max_total_spawned_agents: null, total_spawned: 999 },
  });
  assert.equal(plan.mode, "fanout");
});

test("the shipped cross-role fan-out default (governor null) still fans recon on a self-managing host", () => {
  // The flipped DEFAULT_QUEUE_POLICY keeps max_total_spawned_agents null, so a
  // session loading it hands deriveReconAnglePlan a null lifetime governor and
  // recon fans out on claude/codex (and fails closed on a finite-pool host).
  const { DEFAULT_QUEUE_POLICY } = require("../mcp/core/io/queue-policy.js");
  assert.equal(DEFAULT_QUEUE_POLICY.max_total_spawned_agents, null);
  const governor = { max_total_spawned_agents: DEFAULT_QUEUE_POLICY.max_total_spawned_agents, total_spawned: 0 };
  assert.equal(deriveReconAnglePlan({ host_id: "claude", governor }).mode, "fanout");
  assert.equal(deriveReconAnglePlan({ host_id: "codex", governor }).mode, "fanout");
  assert.equal(deriveReconAnglePlan({ host_id: "kimi", governor }).mode, "sequential");
  assert.equal(deriveReconAnglePlan({ host_id: "unknown", governor }).degrade_reason, "host_pool_finite");
});

test("governor exhausted degrades to sequential and REPORTS the uncovered-as-parallel angles (never drops)", () => {
  // Remaining budget below the parallel cost (4 angles + 1 assembly = 5).
  const plan = deriveReconAnglePlan({
    host_id: "claude",
    governor: { max_total_spawned_agents: 10, total_spawned: 8 }, // remaining 2 < 5
  });
  assert.equal(plan.mode, "sequential");
  assert.equal(plan.degrade_reason, undefined);
  assert.ok(plan.governor_gap, "a governor-forced degrade must carry a governor_gap");
  assert.equal(plan.governor_gap.remaining, 2);
  assert.equal(plan.governor_gap.required_for_parallel, 5);
  // RANK != BOUND: ALL four angles still present; the single agent runs them all.
  assert.deepEqual(plan.angles.map((a) => a.id), EXPECTED_ANGLE_IDS);
  // remaining 2 -> 1 assembly slot reserved -> 1 admissible angle -> 3 uncovered-as-parallel.
  assert.deepEqual(plan.governor_gap.uncovered_as_parallel, ["urls", "nuclei", "js_jwt"]);
});

test("governor exhausted to zero reports ALL angles as uncovered-as-parallel (still none dropped)", () => {
  const plan = deriveReconAnglePlan({
    host_id: "claude",
    governor: { max_total_spawned_agents: 5, total_spawned: 5 }, // remaining 0
  });
  assert.equal(plan.mode, "sequential");
  assert.deepEqual(plan.governor_gap.uncovered_as_parallel, EXPECTED_ANGLE_IDS);
  assert.deepEqual(plan.angles.map((a) => a.id), EXPECTED_ANGLE_IDS);
});

test("host-fail-closed precedes the governor check (a finite host is sequential regardless of budget)", () => {
  const plan = deriveReconAnglePlan({
    host_id: "kimi",
    governor: { max_total_spawned_agents: 1000, total_spawned: 0 },
  });
  assert.equal(plan.mode, "sequential");
  assert.equal(plan.degrade_reason, "host_pool_finite");
  assert.equal(plan.governor_gap, undefined);
});

test("deep_mode enriches the urls angle without adding a fifth angle", () => {
  const plan = deriveReconAnglePlan({ deep_mode: true, host_id: "claude", governor: null });
  assert.equal(plan.mode, "fanout");
  assert.deepEqual(plan.angles.map((a) => a.id), EXPECTED_ANGLE_IDS);
  const urls = plan.angles.find((a) => a.id === "urls");
  assert.equal(urls.deep, true);
  // No other angle gains a deep flag.
  for (const angle of plan.angles) {
    if (angle.id !== "urls") assert.equal(angle.deep, undefined);
  }
});

test("deterministic / replayable: same input yields deep-equal output across calls", () => {
  const input = {
    deep_mode: true,
    host_id: "claude",
    governor: { max_total_spawned_agents: 7, total_spawned: 6 },
  };
  const a = deriveReconAnglePlan(input);
  const b = deriveReconAnglePlan(input);
  assert.deepEqual(a, b);

  const c = deriveReconAnglePlan({ host_id: "claude", governor: null });
  const d = deriveReconAnglePlan({ host_id: "claude", governor: null });
  assert.deepEqual(c, d);
});

test("the emitter is pure: it reads no clock/random/env/IO (stable across env mutation)", () => {
  const before = deriveReconAnglePlan({ host_id: "claude", governor: null });
  const savedClient = process.env.BOB_CLIENT;
  const savedProj = process.env.CLAUDE_PROJECT_DIR;
  try {
    process.env.BOB_CLIENT = "kimi";
    delete process.env.CLAUDE_PROJECT_DIR;
    const after = deriveReconAnglePlan({ host_id: "claude", governor: null });
    // host_id is an explicit ARGUMENT, not read from env — output is unchanged.
    assert.deepEqual(after, before);
  } finally {
    if (savedClient === undefined) delete process.env.BOB_CLIENT;
    else process.env.BOB_CLIENT = savedClient;
    if (savedProj === undefined) delete process.env.CLAUDE_PROJECT_DIR;
    else process.env.CLAUDE_PROJECT_DIR = savedProj;
  }
});
