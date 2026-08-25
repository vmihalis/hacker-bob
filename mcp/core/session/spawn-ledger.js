"use strict";

// CN (coverage-nesting) Step B — the MCP-owned spawn-ledger writer/reader.
//
// One row per emitted nesting fan-out envelope. The basename is HOOK_MCP_OWNED
// (mcp/core/io/paths.js), so the session-write-guard fences the evaluator-fanout
// Bash/Write channel — the spawner holds Bash for OSS harness work, so toolset
// absence cannot guarantee integrity; the hook-fenced basename does.
//
// It is written at the mutating dispatch step (the orchestrator handing out a
// nesting root), NEVER on the read-brief path (bob_read_assignment_brief is
// mutating:false). The read-path bounder reads spawnLedgerTotal() to cap the next
// plan's width so the cumulative worst-case spawn tree stays within the session
// budget (max_total_spawned_agents). This is the detective-audit half of the
// preventive-at-depth-1-width governor; validateSpawnFanout cross-checks at finalize.

const fs = require("fs");
const path = require("path");
const { spawnLedgerJsonlPath } = require("../io/paths.js");
const { withSessionLock } = require("../io/storage.js");

// Append one envelope row. The caller supplies ts (deterministic, testable) and
// the worst-case tree size it reserved for this root. `worst_case_tree` is the
// LIFETIME reservation summed by spawnLedgerTotal: the root agent itself
// (root_count, always 1 for a dispatched root/cell) PLUS its worst-case nested
// descendant subtree (descendant_tree, 0 when the root does not fan out). The
// root_count / descendant_tree split is recorded for audit; the governor binds on
// worst_case_tree so a flat root still consumes one lifetime slot. Returns the
// written row.
function appendSpawnLedgerEntry(domain, entry) {
  const rootCount = Number.isInteger(entry.root_count) ? entry.root_count : null;
  const descendantTree = Number.isInteger(entry.descendant_tree) ? entry.descendant_tree : null;
  const row = {
    ts: entry.ts,
    wave: entry.wave,
    parent_agent: entry.parent_agent,
    surface_id: entry.surface_id || null,
    depth: entry.depth,
    branching: entry.branching,
    worst_case_tree: entry.worst_case_tree,
  };
  if (rootCount != null) row.root_count = rootCount;
  if (descendantTree != null) row.descendant_tree = descendantTree;
  if (entry.kind) row.kind = entry.kind;
  const file = spawnLedgerJsonlPath(domain);
  // Take the session lock for the append like every other session-owned write.
  // withSessionLock is reentrant, so callers already holding the lock (the wave
  // scheduler's dispatch step) reuse the hold rather than deadlocking. The write
  // is NOT swallowed here — an IO failure propagates so the dispatch step that
  // reserved this slot can surface it rather than leaving the gate undercounted.
  return withSessionLock(domain, () => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, `${JSON.stringify(row)}\n`, "utf8");
    return row;
  });
}

function readSpawnLedgerEntries(domain) {
  let raw;
  try {
    raw = fs.readFileSync(spawnLedgerJsonlPath(domain), "utf8");
  } catch {
    return [];
  }
  const out = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed));
    } catch {
      // skip a malformed/partial line rather than throwing the whole read
    }
  }
  return out;
}

// The session-wide total worst-case spawn-tree size already handed out. The
// read-path bounder subtracts this from max_total_spawned_agents to size the next
// root's envelope, so the cumulative worst case stays within budget.
//
// excludeWave + excludeSurfaceId skip the caller's OWN reservation row: the
// dispatch step writes a root's reservation before its evaluator reads the brief,
// so without the exclusion that evaluator would subtract its own reservation and
// under-fan-out. Excluding self lets each root reproduce exactly the allocation it
// was reserved (dispatch is greedy-sequential, so earlier roots in a wave already
// shrink the budget the later ones — and their own briefs — see). PURE read.
function spawnLedgerTotal(domain, { excludeWave = null, excludeSurfaceId = null } = {}) {
  const excludeSelf = excludeWave != null && excludeSurfaceId != null;
  let total = 0;
  for (const row of readSpawnLedgerEntries(domain)) {
    if (excludeSelf && row.wave === excludeWave && row.surface_id === excludeSurfaceId) continue;
    const n = Number(row.worst_case_tree);
    if (Number.isFinite(n) && n > 0) total += n;
  }
  return total;
}

module.exports = {
  appendSpawnLedgerEntry,
  readSpawnLedgerEntries,
  spawnLedgerTotal,
};
