"use strict";

// CN (coverage-nesting) Step B — the dispatch-side spawn-ledger writer (C5),
// the piece the brutalist review flagged as missing: the read-path width bound
// in buildChildFanoutPlanForSurface subtracted spawnLedgerTotal(), but NOTHING
// wrote the ledger, so the session governor max_total_spawned_agents never engaged.
// startWaveLocked now reserves each spawn-capable root's worst-case subtree at the
// mutating dispatch step. These tests prove: (1) the ledger is non-empty after a
// nested dispatch, (2) reservations accumulate greedy-sequentially across roots and
// stay within budget, (3) the read-path exclude-self lets each root reproduce its own
// allocation, and (4) default-off (no governor) writes nothing — byte-identical.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { attackSurfacePath } = require("../mcp/lib/paths.js");
const { writeFileAtomic } = require("../mcp/lib/storage.js");
const { initSession, advanceSession } = require("../mcp/lib/session-state.js");
const { startWave } = require("../mcp/lib/waves.js");
const {
  DEFAULT_QUEUE_POLICY,
  LEAN_PROFILE,
  normalizeQueuePolicy,
  writeQueuePolicy,
} = require("../mcp/lib/queue-policy.js");
const {
  appendSpawnLedgerEntry,
  readSpawnLedgerEntries,
  spawnLedgerTotal,
} = require("../mcp/lib/spawn-ledger.js");
const { planNextWave } = require("../mcp/lib/wave-planner.js");

const HINTS = ["idor", "ssrf", "xss", "ssti", "auth_bypass"];

function withClaudeHome(fn) {
  const prevHome = process.env.HOME;
  const prevClient = process.env.BOB_CLIENT;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-ledger-dispatch-"));
  process.env.HOME = home;
  process.env.BOB_CLIENT = "claude"; // nesting is claude-only (NS-3)
  try {
    return fn(home);
  } finally {
    process.env.HOME = prevHome;
    if (prevClient === undefined) delete process.env.BOB_CLIENT;
    else process.env.BOB_CLIENT = prevClient;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function seedSurfaces(domain, surfaces) {
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function bootstrap(domain, surfaces, policyOverride) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
  seedSurfaces(domain, surfaces);
  JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
  writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, ...policyOverride }));
}

test("dispatch writer: a nested wave start reserves a non-empty spawn-ledger entry", () => {
  withClaudeHome(() => {
    const domain = "ledger-one.example.com";
    bootstrap(domain, [{ id: "surface:api", hosts: [`https://${domain}`], priority: "HIGH", bug_class_hints: HINTS }], {
      max_spawn_depth: 3,
      max_spawn_children: 8,
      max_total_spawned_agents: 512,
    });

    startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface:api" }] });

    const rows = readSpawnLedgerEntries(domain);
    assert.equal(rows.length, 1, "exactly one reservation for the single nested root");
    assert.equal(rows[0].surface_id, "surface:api");
    assert.equal(rows[0].wave, "w1");
    assert.ok(rows[0].worst_case_tree > 0, "reserved a positive worst-case subtree");
    assert.ok(spawnLedgerTotal(domain) > 0, "governor is no longer a no-op");
  });
});

test("dispatch writer: K roots accumulate greedy-sequentially within budget; exclude-self isolates each", () => {
  withClaudeHome(() => {
    const domain = "ledger-k.example.com";
    // Tight budget so the greedy split is observable: root1 takes the lion's share,
    // root2 is sized against what remains.
    bootstrap(domain, [
      { id: "surface:api", hosts: [`https://${domain}`], priority: "HIGH", bug_class_hints: HINTS },
      { id: "surface:admin", hosts: [`https://${domain}`], priority: "HIGH", bug_class_hints: HINTS },
    ], {
      max_spawn_depth: 3,
      max_spawn_children: 8,
      max_total_spawned_agents: 100,
    });

    startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [
        { agent: "a1", surface_id: "surface:api" },
        { agent: "a2", surface_id: "surface:admin" },
      ],
    });

    const rows = readSpawnLedgerEntries(domain);
    assert.equal(rows.length, 2, "one reservation per nested root");
    const total = rows.reduce((acc, r) => acc + Number(r.worst_case_tree), 0);
    assert.ok(total <= 100, `cumulative worst case (${total}) stays within max_total_spawned_agents`);
    assert.equal(spawnLedgerTotal(domain), total);

    // Greedy-sequential: the two reservations differ (the second was sized against the
    // budget the first already consumed), proving cross-root accounting actually ran.
    const worsts = rows.map((r) => Number(r.worst_case_tree)).sort((a, b) => b - a);
    assert.ok(worsts[0] > worsts[1], "first root reserved more than the second (budget shrank)");

    // Exclude-self: a root's own reservation is removed from the total it sees, so each
    // reproduces the allocation dispatch reserved for it rather than subtracting itself.
    for (const row of rows) {
      const seenByThisRoot = spawnLedgerTotal(domain, { excludeWave: row.wave, excludeSurfaceId: row.surface_id });
      assert.equal(seenByThisRoot, total - Number(row.worst_case_tree), `${row.surface_id} excludes only its own reservation`);
    }
  });
});

test("dispatch writer: governor set + nesting OFF still counts each root (cross-wave bind)", () => {
  withClaudeHome(() => {
    const domain = "ledger-roots.example.com";
    // The cross-wave overrun bug: with nesting OFF (max_spawn_depth=1) the old
    // writer skipped roots entirely (gated on remaining_depth>0), so the ledger
    // stayed empty and N waves x governor exceeded the lifetime ceiling. Each
    // dispatched root must now reserve one lifetime slot regardless of nesting.
    bootstrap(domain, [
      { id: "surface:api", hosts: [`https://${domain}`], priority: "HIGH", bug_class_hints: HINTS },
      { id: "surface:admin", hosts: [`https://${domain}`], priority: "HIGH", bug_class_hints: HINTS },
    ], {
      max_spawn_depth: 1, // nesting OFF
      max_total_spawned_agents: 50,
    });

    startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [
        { agent: "a1", surface_id: "surface:api" },
        { agent: "a2", surface_id: "surface:admin" },
      ],
    });

    const rows = readSpawnLedgerEntries(domain);
    assert.equal(rows.length, 2, "every dispatched root is reserved, even with nesting off");
    for (const row of rows) {
      assert.equal(row.root_count, 1, "root costs one lifetime slot");
      assert.equal(row.descendant_tree, 0, "nesting off => no nested descendants");
      assert.equal(row.worst_case_tree, 1, "lifetime reservation = root + descendants");
    }
    // Two roots reserved 2 lifetime slots — the governor now binds across waves.
    assert.equal(spawnLedgerTotal(domain), 2, "governor sees the two roots (was 0 before the fix)");
  });
});

test("dispatch writer: a null governor (explicit lean override) writes nothing — byte-identical", () => {
  withClaudeHome(() => {
    const domain = "ledger-off.example.com";
    // Off-path via an explicit LEAN override: depth 1, max_total_spawned_agents null.
    // The ledger writer is gated on the governor being an integer, so a null governor
    // reserves nothing regardless of depth.
    bootstrap(domain, [{ id: "surface:api", hosts: [`https://${domain}`], priority: "HIGH", bug_class_hints: HINTS }], LEAN_PROFILE);

    startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface:api" }] });

    assert.deepEqual(readSpawnLedgerEntries(domain), [], "null governor → no reservation rows");
    assert.equal(spawnLedgerTotal(domain), 0);
  });
});

test("dispatch writer: the on-default (nesting on, governor null) also writes nothing — the writer is governor-gated, not depth-gated", () => {
  withClaudeHome(() => {
    const domain = "ledger-on-default.example.com";
    // The shipped on-default: depth 3 (nesting ON) but max_total_spawned_agents null
    // (the exempt unbounded fixpoint). Even with nesting on, a null governor reserves
    // nothing — the writer only engages once the operator sets a finite cost ceiling.
    bootstrap(domain, [{ id: "surface:api", hosts: [`https://${domain}`], priority: "HIGH", bug_class_hints: HINTS }], {});
    assert.equal(normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY }).max_total_spawned_agents, null);

    startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface:api" }] });

    assert.deepEqual(readSpawnLedgerEntries(domain), [], "on-default's null governor → no reservation rows");
    assert.equal(spawnLedgerTotal(domain), 0);
  });
});

// The headline cross-wave-binding proof: drive the real drain loop (real ledger
// writer + real ledger reader feeding the real planner) over the canonical
// construction — 20 HIGH surfaces, governor 5, nesting OFF — and prove the
// LIFETIME TOTAL across ALL waves is bound to 5, with the remaining 15 reported
// as a coverage gap. Never spawned past the ceiling, never silently dropped.
//
// The loop is the production cycle minus the unowned settle plumbing: each
// iteration plans against the REAL accumulated spawnLedgerTotal (read from disk,
// non-forgeable), and on a start_wave writes one ledger row per planned root via
// the SAME appendSpawnLedgerEntry the dispatch step uses, then marks those
// surfaces explored and advances evaluation_wave so the next wave plans the
// remainder. A single planNextWave call only proves one wave's clamp; this proves
// the budget binds ACROSS waves through the ledger.
function buildSurfaces(domain, n) {
  return Array.from({ length: n }, (_, i) => ({
    id: `surface:h${String(i).padStart(2, "0")}`,
    hosts: [`https://${domain}`],
    priority: "HIGH",
    ranking: { version: 1, score: 100 - i, priority: "HIGH", reasons: [] },
  }));
}

test("cross-wave bind: TOTAL across a multi-wave drain is bound to the governor; the remainder is a named coverage gap", () => withClaudeHome(() => {
  const domain = "ledger-drain.example.com";
  const TOTAL_SURFACES = 20;
  const GOVERNOR = 5;
  const surfaces = buildSurfaces(domain, TOTAL_SURFACES);
  // Width lifted far past the baseline so ONLY the lifetime governor can bind the
  // count — the per-wave target/max would otherwise admit all 20 across two waves.
  // Nesting OFF (max_spawn_depth 1) so each dispatched root costs exactly one
  // lifetime slot; this is the flat per-surface topology that used to reserve ZERO
  // and let N waves x width blow past the ceiling.
  const policy = {
    ...DEFAULT_QUEUE_POLICY,
    standard_wave_target: 3,
    standard_wave_max: 3,
    max_spawn_depth: 1,
    max_total_spawned_agents: GOVERNOR,
  };

  const explored = new Set();
  let evaluationWave = 0;
  const dispatchedSurfaceIds = [];
  let finalPlan = null;
  // Bound the loop generously; it must terminate via spawn_budget_exhausted long
  // before this, but a runaway (over-spawn) would trip the assertion below.
  for (let i = 0; i < TOTAL_SURFACES + 5; i += 1) {
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
    // Reserve each planned root exactly as startWaveLocked does at dispatch.
    const waveLabel = `w${plan.wave_number}`;
    for (const a of plan.assignments) {
      appendSpawnLedgerEntry(domain, {
        ts: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
        wave: waveLabel,
        parent_agent: a.agent,
        surface_id: a.surface_id,
        depth: 0,
        branching: 0,
        root_count: 1,
        descendant_tree: 0,
        worst_case_tree: 1,
      });
      explored.add(a.surface_id);
      dispatchedSurfaceIds.push(a.surface_id);
    }
    evaluationWave += 1;
  }

  // 1) The LIFETIME total is bound to the governor — never over-spawned, even
  //    though width admitted 3 per wave and 20 surfaces were open.
  assert.equal(spawnLedgerTotal(domain), GOVERNOR, "cumulative spawn across all waves == governor (never over-spawns)");
  assert.equal(dispatchedSurfaceIds.length, GOVERNOR, "exactly governor-many roots ever dispatched across the drain");
  // It took more than one wave to reach the ceiling (3 + 2), so this proves the
  // bind is CROSS-WAVE through the accumulating ledger, not a single-wave clamp.
  assert.ok(evaluationWave >= 2, "the budget was consumed across multiple waves (cross-wave bind)");

  // 2) The drain stopped with a coverage gap that NAMES the uncovered surfaces —
  //    STOP + report, never a silent drop (RANK != BOUND).
  assert.equal(finalPlan.decision, "spawn_budget_exhausted", "drain terminates by reporting the gap, not by dropping work");
  assert.ok(finalPlan.coverage_gap, "the terminal plan carries a coverage_gap");
  assert.equal(finalPlan.coverage_gap.kind, "spawn_budget_exhausted");
  assert.equal(finalPlan.coverage_gap.remaining_budget, 0);
  const uncovered = finalPlan.coverage_gap.uncovered_surface_ids;
  assert.equal(uncovered.length, TOTAL_SURFACES - GOVERNOR, "the remaining 15 surfaces are reported as uncovered, not dropped");
  // The uncovered set is exactly the surfaces never dispatched — no surface is
  // both spawned and reported, and none vanished.
  const dispatchedSet = new Set(dispatchedSurfaceIds);
  for (const id of uncovered) {
    assert.ok(!dispatchedSet.has(id), `${id} reported as uncovered was never dispatched`);
  }
  const accountedFor = new Set([...dispatchedSurfaceIds, ...uncovered]);
  assert.equal(accountedFor.size, TOTAL_SURFACES, "every surface is either dispatched or named in the gap — none silently dropped");
}));

test("cross-wave bind: null governor drains to fixpoint (cell-floor reaches all surfaces, byte-identical)", () => withClaudeHome(() => {
  // The null-governor control for the drain above: with no governor the same loop
  // must cover EVERY surface (reach fixpoint) and never emit a coverage gap or
  // touch the ledger. Built off LEAN_PROFILE (depth 1, width at the conservative
  // baseline) with small per-wave caps so the auto-fill never arms — the governor
  // stays null and coverage is NOT bounded.
  const domain = "ledger-drain-off.example.com";
  const TOTAL_SURFACES = 20;
  const surfaces = buildSurfaces(domain, TOTAL_SURFACES);
  const policy = {
    ...LEAN_PROFILE,
    standard_wave_target: 3,
    standard_wave_max: 3,
    // max_total_spawned_agents stays null (governor off).
  };
  assert.equal(normalizeQueuePolicy(policy).max_total_spawned_agents, null, "the lean-based override keeps the governor null");

  const explored = new Set();
  let evaluationWave = 0;
  const dispatchedSurfaceIds = [];
  for (let i = 0; i < TOTAL_SURFACES + 5; i += 1) {
    const reservedSpawnTotal = spawnLedgerTotal(domain); // stays 0 — nothing writes
    const plan = planNextWave({
      state: { target: domain, evaluation_wave: evaluationWave, pending_wave: null },
      surfaces,
      exploredSurfaceIds: explored,
      terminallyBlockedSurfaceIds: [],
      leadSurfaceIds: [],
      queuePolicy: policy,
      reservedSpawnTotal,
    });
    assert.equal(plan.coverage_gap, undefined, "null governor never emits a coverage gap");
    if (plan.decision !== "start_wave") break;
    for (const a of plan.assignments) {
      explored.add(a.surface_id);
      dispatchedSurfaceIds.push(a.surface_id);
    }
    evaluationWave += 1;
  }

  assert.deepEqual(readSpawnLedgerEntries(domain), [], "null governor writes no ledger rows — byte-identical");
  assert.equal(new Set(dispatchedSurfaceIds).size, TOTAL_SURFACES, "fixpoint: every surface covered when the governor is null");
}));
