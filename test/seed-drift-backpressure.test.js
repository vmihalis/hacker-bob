"use strict";

// Seed-producer drift backpressure. When independent producers land surfaces
// concurrently, the task-graph hash drifts between two successive read-only
// materializes (a thundering herd). The scheduler halves the dispatch batch on
// each drift retry — flooring at one so every round still makes forward progress
// — and, if the graph never quiesces within the bounded retry budget, emits a
// REPORTED seed_loop_nonquiescent gap NAMING the still-undispatched producers
// rather than silently abandoning them. RANK != BOUND. On the no-concurrency path
// the loop runs once at the cap, drift_retries is 0, and the output matches the
// single-pass scheduler byte-for-byte.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  nextDispatchBatch,
  planDriftBackpressure,
  buildSeedLoopNonquiescentGap,
  SEED_DRIFT_RETRY_BUDGET,
} = require("../mcp/lib/tools/schedule-seed-producers.js");
const { executeTool } = require("../mcp/lib/dispatch.js");
const { appendFrontierEvent } = require("../mcp/lib/frontier-events.js");

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-seed-drift-backpressure-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

test("nextDispatchBatch halves and floors at one — the termination guarantee", () => {
  assert.equal(nextDispatchBatch(8), 4);
  assert.equal(nextDispatchBatch(4), 2);
  assert.equal(nextDispatchBatch(2), 1);
  assert.equal(nextDispatchBatch(1), 1, "floors at one, never zero — forward progress is guaranteed");
  assert.equal(nextDispatchBatch(3), 1, "floor(3/2) is one");
  assert.equal(nextDispatchBatch(0), 1, "a degenerate batch still floors at one");
});

test("planDriftBackpressure: a graph that never quiesces within budget is non-quiescent and the gap names the undispatched producers", () => {
  const budget = SEED_DRIFT_RETRY_BUDGET;
  // budget+2 distinct hashes ⇒ keeps drifting past the budget without stabilizing.
  const hashSequence = [];
  for (let i = 0; i < budget + 2; i += 1) hashSequence.push(`h${i}`);
  const plan = planDriftBackpressure({ initialBatch: 32, retryBudget: budget, hashSequence });
  assert.equal(plan.quiescent, false, "the hashes never stabilized within the budget");
  assert.equal(plan.driftRetries, budget, "drift retries are bounded by the budget");
  assert.ok(plan.finalBatch >= 1, "the batch never floors below one");

  // RANK != BOUND: the still-undispatched producers are NAMED in a reported gap.
  const undispatched = ["TG-producer-1", "TG-producer-2"];
  const gap = buildSeedLoopNonquiescentGap(undispatched);
  assert.equal(gap.kind, "seed_loop_nonquiescent");
  assert.deepEqual(gap.undispatched_producer_node_ids, undispatched,
    "the gap names every undispatched producer — REPORTED, never silent");
});

test("planDriftBackpressure: a graph that stabilizes within budget is quiescent and the batch shrinks by the drift-retry count", () => {
  const plan = planDriftBackpressure({
    initialBatch: 8,
    retryBudget: 4,
    hashSequence: ["a", "b", "c", "c"],
  });
  assert.equal(plan.quiescent, true, "two successive reads agreed ⇒ quiescent");
  assert.equal(plan.driftRetries, 2, "two drift retries before stabilization");
  assert.equal(plan.finalBatch, 2, "8 halved twice ⇒ 2 (shrunk by the drift-retry count)");
});

test("handler smoke: over-cap producers are named in skipped and the no-drift path reports drift_retries 0", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    const session = await executeTool("bob_init_session", {
      target_domain: domain,
      target_url: "https://example.com",
    });
    assert.equal(session.ok, true, `expected init ok:true, got ${JSON.stringify(session)}`);

    // Stage three independent producer nodes directly (proposed state). The
    // scheduler folds each producer_proposed event into a 'producer' node.
    const stagedKeys = ["syn_p_alpha", "syn_p_bravo", "syn_p_charlie"];
    for (const key of stagedKeys) {
      appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        payload: { observation_kind: "producer_proposed", producer_key: key, producer_id: key },
        actor: "orchestrator",
      });
    }

    // capacity 1 forces the over-cap path; dispatch:false keeps it a dry-run.
    const sched = await executeTool("bob_schedule_seed_producers", {
      target_domain: domain,
      dispatch: false,
      capacity: 1,
    });
    assert.equal(sched.ok, true, `expected schedule ok:true, got ${JSON.stringify(sched)}`);
    assert.ok(sched.data.considered_count >= 3, "all three staged producers are considered");
    assert.equal(sched.data.selected_node_ids.length, 1, "capacity 1 selects exactly one");
    assert.ok(sched.data.skipped.length >= 2, "the over-cap producers land in skipped, never dropped");
    assert.ok(sched.data.spawn_budget_exhausted, "skipped producers are reported as a gap");
    // The synchronous no-concurrency path: two successive read-only materializes
    // agree, so there is no drift and the output matches the single-pass scheduler.
    assert.equal(sched.data.drift_retries, 0, "the no-concurrency path reports no drift");
    assert.equal(typeof sched.data.final_dispatch_batch, "number");
    assert.equal(sched.data.seed_loop_nonquiescent, undefined,
      "no non-quiescent gap on the stable-hash path");
  });
});
