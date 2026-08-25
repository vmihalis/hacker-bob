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
} = require("../mcp/tools/schedule-seed-producers.js");
const { executeTool } = require("../mcp/core/dispatch/dispatch.js");
const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");

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

// ── Concurrency seams ──────────────────────────────────────────────────────
// The drift re-read and the reserve-before-dispatch ordering are handler-internal
// and can only be observed by controlling the read-only materialize / producer_run
// / dispatch dependencies. schedule-seed-producers.js destructures those at require
// time, so we swap them in require.cache and re-require a FRESH copy of the handler
// bound to the stubs, then restore. No production seam is added for the test.
const TARGET = require.resolve("../mcp/tools/schedule-seed-producers.js");
const DEP_PATHS = {
  materializer: require.resolve("../mcp/core/waves/task-graph-materializer.js"),
  producerRun: require.resolve("../mcp/core/producer-run-ledger.js"),
  frontier: require.resolve("../mcp/core/frontier/frontier-events.js"),
  toolRegistry: require.resolve("../mcp/core/dispatch/tool-registry.js"),
  spawnLedger: require.resolve("../mcp/core/session/spawn-ledger.js"),
};

function stubModule(absPath, exports) {
  require.cache[absPath] = { id: absPath, filename: absPath, loaded: true, exports, paths: [] };
}

function loadSeedHandlerWithStubs(stubs, fn) {
  const savedTarget = require.cache[TARGET];
  const savedDeps = {};
  for (const p of Object.values(DEP_PATHS)) savedDeps[p] = require.cache[p];
  delete require.cache[TARGET];
  if (stubs.materializer) stubModule(DEP_PATHS.materializer, stubs.materializer);
  if (stubs.producerRun) stubModule(DEP_PATHS.producerRun, stubs.producerRun);
  if (stubs.frontier) stubModule(DEP_PATHS.frontier, stubs.frontier);
  if (stubs.toolRegistry) stubModule(DEP_PATHS.toolRegistry, stubs.toolRegistry);
  if (stubs.spawnLedger) stubModule(DEP_PATHS.spawnLedger, stubs.spawnLedger);
  try {
    return fn(require(TARGET));
  } finally {
    delete require.cache[TARGET];
    if (savedTarget) require.cache[TARGET] = savedTarget;
    for (const [p, entry] of Object.entries(savedDeps)) {
      if (entry) require.cache[p] = entry;
      else delete require.cache[p];
    }
  }
}

// producerNodeId maps a producer_key to its node id; the stubs mirror it as
// `TG-producer-<key>` so the staged nodes and the producer_proposed events line up.
function stubProducerNodeId({ producerKey }) {
  return `TG-producer-${producerKey}`;
}
function stubProducerNodes(keys) {
  return keys.map((key, i) => ({
    node_id: `TG-producer-${key}`,
    kind: "producer",
    ts_first: `2026-01-01T00:00:0${i}.000Z`,
  }));
}
function stubProposedEvents(keys) {
  return keys.map((key) => ({
    kind: "observation.recorded",
    payload: { observation_kind: "producer_proposed", producer_key: key },
  }));
}

test("drift re-read: a producer finalized concurrently during a drift retry is filtered by the RE-READ runSet — not double-dispatched", () => {
  const keys = ["p_alpha", "p_bravo"];
  const nodes = stubProducerNodes(keys);
  // The graph_hash drifts once (H0 -> H1), then quiesces (H1 == H1). The stale
  // initial runSet is empty; the SECOND producerRunSet read (only reached because
  // the fix re-reads on drift) reports p_bravo as terminal — a concurrent finalize.
  const matSeq = [
    { document: { nodes, hashes: { graph_hash: "H0" } } },
    { document: { nodes, hashes: { graph_hash: "H1" } } },
    { document: { nodes, hashes: { graph_hash: "H1" } } },
  ];
  const runSetSeq = [new Set(), new Set(["p_bravo"])];
  let matIdx = 0;
  let producerRunSetCalls = 0;

  loadSeedHandlerWithStubs({
    materializer: { materializeTaskGraph: () => matSeq[matIdx++], producerNodeId: stubProducerNodeId },
    producerRun: {
      producerRunSet: () => {
        const set = runSetSeq[Math.min(producerRunSetCalls, runSetSeq.length - 1)];
        producerRunSetCalls += 1;
        return set;
      },
    },
    frontier: { readFrontierEvents: () => stubProposedEvents(keys) },
  }, (mod) => {
    const out = JSON.parse(mod.handler({
      target_domain: "example.com",
      dispatch: false,
      capacity: 8,
      retry_budget: 4,
      policy: {},
    }));

    assert.equal(out.drift_retries, 1, "the graph drifted once before quiescing");
    assert.equal(producerRunSetCalls, 2,
      "producerRunSet is read AGAIN on drift — the stale terminal set is never trusted across a retry");
    assert.deepEqual(out.selected_node_ids, ["TG-producer-p_alpha"],
      "only the still-live producer is selected after the re-read");
    assert.ok(!out.selected_node_ids.includes("TG-producer-p_bravo"),
      "the concurrently-finalized producer is NOT re-selected — no double-dispatch, monotonicity holds");
  });
});

test("dispatch order: the spawn-ledger reservation precedes the bob_prepare_node state mutation, and a ledger-write failure is SURFACED (not swallowed)", () => {
  const keys = ["p_solo"];
  const nodes = stubProducerNodes(keys);
  // A stable hash (no drift): one initial materialize + one remat that agrees.
  const stableMat = () => ({ document: { nodes, hashes: { graph_hash: "H0" } } });

  function runScenario({ failReserve }) {
    const callOrder = [];
    let matIdx = 0;
    return loadSeedHandlerWithStubs({
      materializer: {
        materializeTaskGraph: () => { matIdx += 1; return stableMat(); },
        producerNodeId: stubProducerNodeId,
      },
      producerRun: { producerRunSet: () => new Set() },
      frontier: { readFrontierEvents: () => stubProposedEvents(keys) },
      toolRegistry: {
        TOOL_HANDLERS: {
          bob_prepare_node: (args) => {
            callOrder.push(`dispatch:${args.node_id}`);
            return JSON.stringify({ prep_token: "t", brief_hash: "b", graph_context_hash: "g", event_id: "e" });
          },
        },
      },
      spawnLedger: {
        appendSpawnLedgerEntry: (_domain, entry) => {
          callOrder.push(`reserve:${entry.surface_id}`);
          if (failReserve) throw new Error("simulated ledger IO failure");
          return entry;
        },
      },
    }, (mod) => {
      const out = JSON.parse(mod.handler({ target_domain: "example.com", capacity: 8, policy: {} }));
      return { out, callOrder };
    });
  }

  // Happy path: the reservation is written FIRST, then the dispatch mutates state.
  const ok = runScenario({ failReserve: false });
  assert.deepEqual(ok.callOrder, ["reserve:TG-producer-p_solo", "dispatch:TG-producer-p_solo"],
    "the ledger reservation precedes/co-occurs with the dispatch — never a separate post-loop pass");
  assert.deepEqual(ok.out.dispatched.map((d) => d.node_id), ["TG-producer-p_solo"]);
  assert.deepEqual(ok.out.failed, [], "no failures on the happy path");

  // Failure path: a ledger-write failure gates the dispatch — the producer lands in
  // failed[] with the reservation error, bob_prepare_node is NEVER called, so no
  // prepared producer can exist without a ledger record (the gate cannot undercount).
  const bad = runScenario({ failReserve: true });
  assert.deepEqual(bad.callOrder, ["reserve:TG-producer-p_solo"],
    "the reservation is attempted BEFORE dispatch; its failure short-circuits — bob_prepare_node never runs");
  assert.deepEqual(bad.out.dispatched, [], "a failed reservation dispatches nothing");
  assert.equal(bad.out.failed.length, 1);
  assert.equal(bad.out.failed[0].node_id, "TG-producer-p_solo");
  assert.equal(bad.out.failed[0].code, "spawn_ledger_reservation_failed",
    "the ledger-write failure is SURFACED in failed[], never swallowed");
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
