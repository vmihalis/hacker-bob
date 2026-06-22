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
  normalizeQueuePolicy,
  writeQueuePolicy,
} = require("../mcp/lib/queue-policy.js");
const { readSpawnLedgerEntries, spawnLedgerTotal } = require("../mcp/lib/spawn-ledger.js");

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

test("dispatch writer: default-off (no governor) writes nothing — byte-identical", () => {
  withClaudeHome(() => {
    const domain = "ledger-off.example.com";
    // DEFAULT_QUEUE_POLICY: max_spawn_depth=1, max_total_spawned_agents=null.
    bootstrap(domain, [{ id: "surface:api", hosts: [`https://${domain}`], priority: "HIGH", bug_class_hints: HINTS }], {});

    startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface:api" }] });

    assert.deepEqual(readSpawnLedgerEntries(domain), [], "no governor → no reservation rows");
    assert.equal(spawnLedgerTotal(domain), 0);
  });
});
