"use strict";

// CN (coverage-nesting) Step B — the MCP-owned spawn ledger (C4). The ledger is
// the detective-audit half of the preventive-at-depth-1-width governor: the MCP
// server appends one envelope row per emitted nesting root at the mutating
// dispatch step, and the read-path bounder reads the running total to cap the
// next plan's width against max_total_spawned_agents.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendSpawnLedgerEntry,
  readSpawnLedgerEntries,
  spawnLedgerTotal,
} = require("../mcp/core/session/spawn-ledger.js");
const { withSessionLock } = require("../mcp/core/io/storage.js");
const paths = require("../mcp/core/io/paths.js");

function withTempHome(fn) {
  const prev = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-spawn-ledger-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = prev;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

test("spawn-ledger: append → read → total roundtrips the reserved worst-case envelopes", () => {
  withTempHome(() => {
    const domain = "ledger.example.com";
    assert.deepEqual(readSpawnLedgerEntries(domain), [], "empty before any write");
    assert.equal(spawnLedgerTotal(domain), 0);

    appendSpawnLedgerEntry(domain, { ts: "2026-06-21T00:00:00.000Z", wave: "w1", parent_agent: "a1", surface_id: "surface:api", depth: 3, branching: 8, worst_case_tree: 72 });
    appendSpawnLedgerEntry(domain, { ts: "2026-06-21T00:01:00.000Z", wave: "w1", parent_agent: "a2", surface_id: "surface:ledger", depth: 2, branching: 8, worst_case_tree: 8 });

    const rows = readSpawnLedgerEntries(domain);
    assert.equal(rows.length, 2);
    assert.equal(rows[0].parent_agent, "a1");
    assert.equal(rows[0].worst_case_tree, 72);
    assert.equal(spawnLedgerTotal(domain), 80, "total sums the reserved worst-case trees across roots");
  });
});

test("spawn-ledger: a malformed/partial line is skipped, never thrown", () => {
  withTempHome(() => {
    const domain = "ledger2.example.com";
    appendSpawnLedgerEntry(domain, { ts: "2026-06-21T00:00:00.000Z", wave: "w1", parent_agent: "a1", depth: 1, branching: 0, worst_case_tree: 0 });
    fs.appendFileSync(paths.spawnLedgerJsonlPath(domain), "{not json\n");
    const rows = readSpawnLedgerEntries(domain);
    assert.equal(rows.length, 1, "the valid row survives a torn tail line");
    assert.equal(spawnLedgerTotal(domain), 0);
  });
});

test("spawn-ledger: the append takes the session lock — reentrant under a held lock, self-acquiring standalone", () => {
  withTempHome(() => {
    const domain = "ledger-lock.example.com";
    // The wave scheduler appends while ALREADY inside withSessionLock, so the
    // append must reuse that hold reentrantly rather than deadlocking on the lock
    // file. Every other session write in this path takes the lock; the append now
    // does too.
    const row = withSessionLock(domain, () => appendSpawnLedgerEntry(domain, {
      ts: "2026-06-21T00:00:00.000Z", wave: "w1", parent_agent: "a1",
      surface_id: "surface:api", depth: 0, branching: 0,
      root_count: 1, descendant_tree: 0, worst_case_tree: 1,
    }));
    assert.equal(row.surface_id, "surface:api", "the reentrant append returns the written row (no deadlock)");

    // A standalone append (no outer hold) acquires the lock itself and also writes.
    appendSpawnLedgerEntry(domain, {
      ts: "2026-06-21T00:01:00.000Z", wave: "w1", parent_agent: "a2",
      surface_id: "surface:admin", depth: 0, branching: 0,
      root_count: 1, descendant_tree: 0, worst_case_tree: 1,
    });

    assert.deepEqual(
      readSpawnLedgerEntries(domain).map((r) => r.surface_id),
      ["surface:api", "surface:admin"],
      "both the locked and the standalone reservations are durably appended in order",
    );
    assert.equal(spawnLedgerTotal(domain), 2, "both reserved lifetime slots count toward the governor");
  });
});

test("spawn-ledger basename is MCP-owned — the write-guard fences the agent Bash/Write channel (FIX-4)", () => {
  // Integrity comes from the hook-fenced basename, NOT toolset absence:
  // evaluator-fanout holds Bash for OSS harness work, so it could `>> spawn-ledger`
  // unless the session-write-guard classifies the basename mcp-owned.
  const basename = path.basename(paths.spawnLedgerJsonlPath("x.example.com"));
  assert.equal(basename, "spawn-ledger.jsonl");
  assert.ok(
    paths.WRITE_GUARD_TABLES.mcp_owned_basenames.includes("spawn-ledger.jsonl"),
    "spawn-ledger.jsonl must classify mcp-owned in WRITE_GUARD_TABLES so the hook blocks agent writes",
  );
  // And it must NOT be agent-writable nor audit-graded (no double-maintain).
  assert.ok(
    !paths.isAuditGradedPath(paths.spawnLedgerJsonlPath("x.example.com"), "x.example.com"),
    "spawn-ledger is hook-mcp-owned, not audit-graded (a read-tool emitter has no composer)",
  );
});
