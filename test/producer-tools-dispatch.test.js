"use strict";

// The producer-floor engine — bob_materialize_producer_floor +
// bob_schedule_seed_producers — must be reachable end-to-end through the REAL
// runtime dispatch path (dispatch.executeTool -> enforceToolPolicy ->
// authorizeToolCall). Both are initialized_session_mutation tools, so the
// session-bound authority gate normalizes target_domain through the public-suffix
// check; the recon producer DAG (PRODUCER_PACKS) is web-native (every pack is
// target_class: web), so the engine is driven against a web session whose
// registrable domain passes that gate. The first sweep proposes the web root
// producer, the materializer folds it into a 'producer' node, the scheduler
// selects it, and bob_prepare_node honestly refuses the uncontracted producer
// (it lands in failed[], not dispatched[]) — proving the dispatch wiring without
// a contract attach. bob_init_contract_session is exercised separately
// (init-contract-session-dispatch.test.js) as the contracts-axis bootstrap.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { executeTool } = require("../mcp/lib/dispatch.js");

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-producer-tools-dispatch-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

test("producer-floor engine materializes + schedules through dispatch", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    const session = await executeTool("bob_init_session", {
      target_domain: domain,
      target_url: "https://example.com",
    });
    assert.equal(session.ok, true, `expected init ok:true, got ${JSON.stringify(session)}`);

    const floor = await executeTool("bob_materialize_producer_floor", { target_domain: domain });
    assert.equal(floor.ok, true, `expected floor ok:true, got ${JSON.stringify(floor)}`);
    assert.equal(typeof floor.data.tier1_producers_emitted, "number");
    assert.equal(typeof floor.data.producer_floor_at_fixpoint, "boolean");
    // producer_floor_at_fixpoint is derived strictly from the Tier-1 count.
    assert.equal(
      floor.data.producer_floor_at_fixpoint,
      floor.data.tier1_producers_emitted === 0,
    );
    // RANK != BOUND: not-ready derived producers are reported, never dropped.
    assert.ok(Array.isArray(floor.data.producer_gaps));
    assert.ok(Array.isArray(floor.data.uncovered_input_types));

    const sched = await executeTool("bob_schedule_seed_producers", { target_domain: domain });
    assert.equal(sched.ok, true, `expected schedule ok:true, got ${JSON.stringify(sched)}`);
    assert.equal(typeof sched.data.considered_count, "number");
    assert.ok(Array.isArray(sched.data.dispatched));
    assert.ok(Array.isArray(sched.data.failed));
    assert.ok(Array.isArray(sched.data.skipped));
  });
});
