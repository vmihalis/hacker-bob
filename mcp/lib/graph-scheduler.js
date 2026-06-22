"use strict";

// Plane X Cycle X.9 — Graph-walking scheduler.
//
// Per X-D7 the wave-scheduler stays in place for Surface and Claim nodes;
// the graph-scheduler dispatches Transition and Hypothesis nodes (the
// X-P1 split). This module exposes:
//
//   selectNextExecutableNodes(targetDomain, queuePolicy, capacity, options?)
//     → { selected[], skipped[], source_graph_hash, capacity_used,
//         materialized_at, considered_count }
//
// PURE selection. Reads the materialized task-graph (X.2), filters to
// Transition + Hypothesis nodes whose state is dispatch-eligible per the
// X.8 prepare-node contract (`contracted` or `ready`), sorts by priority
// then node_id for determinism, caps at `capacity`. Does not promote
// node state and does not append to any ledger; the X.9 tool
// (bob_schedule_graph_nodes) is the only sanctioned writer and it wraps
// this selection with a graph-hash-drift check and the dispatch dance
// (a thin call to bob_prepare_node per selected node).
//
// The X.9 spec's "filters to `ready`" prose is satisfied by `ready`
// always being eligible; `contracted` is included too because the X.8
// frozen state-transition table allows both `contracted → ready →
// dispatched` (prepare-node handles the auto-promotion). Adding
// `contracted` here would otherwise force operators to first run a
// no-op promotion call before the scheduler can pick a freshly attached
// Contract — that bookkeeping does not serve any safety property and
// regresses the X.8 atomic-protocol guarantee.

const {
  CLAMP_CEILING,
  loadQueuePolicy,
  normalizeQueuePolicy,
  TASK_PRIORITY_VALUES,
} = require("./queue-policy.js");
const {
  materializeTaskGraph,
} = require("./task-graph-materializer.js");
const {
  assertSafeDomain,
} = require("./paths.js");
const {
  SEVERITY_VALUES,
} = require("./constants.js");

// Severity ordering for the deterministic Tier-1 breadth order: SEVERITY_VALUES
// is critical -> high -> medium -> low -> info, so a lower index sorts first.
// An absent/unknown severity_floor ranks last, deterministically.
function severityFloorRank(severityFloor) {
  const idx = typeof severityFloor === "string" ? SEVERITY_VALUES.indexOf(severityFloor) : -1;
  return idx >= 0 ? idx : SEVERITY_VALUES.length;
}

// Closed enum of node kinds the graph-scheduler owns (X-D7 / X-P1).
// Surface + Claim are wave-scheduled and intentionally excluded; this
// constant doubles as the "what does the regression test check?" anchor
// so the wave-scheduler-owned kinds never leak into a graph-decision.
const GRAPH_SCHEDULED_KINDS = Object.freeze(["transition", "hypothesis", "cell"]);

// Dispatch-eligible states per X.8 prepare-node. `contracted` is the
// landing state after `bob_attach_contract`; `ready` is reserved for
// the X.9 graph-scheduler's promotion path (prepare-node auto-promotes
// from `contracted` if needed). Both are dispatch-legal.
const DISPATCH_ELIGIBLE_STATES = Object.freeze(["contracted", "ready"]);

function priorityRankFromPolicy(policy) {
  const order = Array.isArray(policy.priority_order) && policy.priority_order.length > 0
    ? policy.priority_order
    : TASK_PRIORITY_VALUES.slice();
  const map = new Map();
  order.forEach((priority, index) => {
    if (!map.has(priority)) map.set(priority, index);
  });
  // Any priority not in the policy order ranks after the last entry but
  // in a deterministic spot (alpha by priority name) so a malformed
  // priority does not crash selection.
  return map;
}

function compareGraphCandidates(a, b, priorityRank, beliefRank = null) {
  // Tier (C1): breadth precedes depth, UNCONDITIONALLY. A Tier-1 uncovered floor
  // cell dispatches before any Tier-2 depth re-probe even when the re-probe is
  // higher priority — the exhaustive-first contract that forbids depth-first
  // cherry-picking. The tier key is therefore the OUTERMOST key, above priority.
  // Default tier 1 (Tier-1), so with no Tier-2 node present this is a no-op and
  // the sort is byte-identical to the priority-first baseline. E2 (residual depth
  // trigger) is what mints Tier-2 re-probe nodes; until then every cell is Tier-1.
  const ta = Number.isInteger(a.tier) ? a.tier : 1;
  const tb = Number.isInteger(b.tier) ? b.tier : 1;
  if (ta !== tb) return ta - tb;
  const fallback = priorityRank.size;
  const ra = priorityRank.has(a.priority) ? priorityRank.get(a.priority) : fallback;
  const rb = priorityRank.has(b.priority) ? priorityRank.get(b.priority) : fallback;
  if (ra !== rb) return ra - rb;
  // Optional belief overlay (CB-C1 belief_assisted_priority_enabled). When an
  // operator opts in, selectNextExecutableNodes supplies a Map<node_id, score>
  // and a higher score sorts a cell earlier. It sits AFTER the priority compare
  // so it can only RAISE within a band — never across one — and is consulted
  // only when the map is non-empty, so the default path (no map) is byte-
  // identical to the deterministic baseline below.
  if (beliefRank && beliefRank.size > 0) {
    const ba = beliefRank.has(a.node_id) ? beliefRank.get(a.node_id) : 0;
    const bb = beliefRank.has(b.node_id) ? beliefRank.get(b.node_id) : 0;
    if (ba !== bb) return bb - ba;
  }
  // Tier-1 deterministic breadth order (C1): cover the highest-value uncovered
  // cell first. Reuses the severity_floor already on the candidate (dead in the
  // sort until now) — a belief-free signal, so the spine orders breadth without
  // belief. Uniform severity falls through to the ts_first/node_id tie-break, so
  // existing same-severity orderings stay byte-identical.
  const sa = severityFloorRank(a.severity_floor);
  const sb = severityFloorRank(b.severity_floor);
  if (sa !== sb) return sa - sb;
  // Tie-break by ts_first ascending (older nodes first) — fairer than
  // strict node_id alpha when priorities tie. Falls through to node_id
  // for full determinism when timestamps tie (or are missing).
  const aTs = a.ts_first || "";
  const bTs = b.ts_first || "";
  if (aTs !== bTs) return aTs.localeCompare(bTs);
  return a.node_id.localeCompare(b.node_id);
}

function normalizeCapacity(value, policy) {
  const policyCap = policy && Number.isFinite(policy.max_parallel_tasks)
    ? policy.max_parallel_tasks
    : 4;
  if (value == null) return policyCap;
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) {
    throw new Error(`capacity must be a positive integer (received: ${String(value)})`);
  }
  // Hard upper bound to defend against pathological callers — lifted from 128 to
  // the shared CLAMP_CEILING (CN Step B) so the cell-floor closure dispatch can
  // scale with a raised max_concurrent_evaluators; the host pool is the real ceiling.
  return Math.min(Math.floor(num), CLAMP_CEILING);
}

function isGraphSchedulableNode(node) {
  if (!node || typeof node !== "object") return false;
  if (!GRAPH_SCHEDULED_KINDS.includes(node.kind)) return false;
  if (!DISPATCH_ELIGIBLE_STATES.includes(node.state)) return false;
  return true;
}

// Pure selection. Either reads the materialized task-graph (default) or
// uses a pre-materialized document the caller passes in via
// `options.document` (the X.9 tool passes one so it can match the
// `source_graph_hash` returned here against a fresh re-materialization
// just before dispatch).
function selectNextExecutableNodes(targetDomain, queuePolicy, capacity, options = {}) {
  const domain = assertSafeDomain(targetDomain);
  const policy = normalizeQueuePolicy(queuePolicy || {});
  const cap = normalizeCapacity(capacity, policy);

  let document;
  if (options.document && typeof options.document === "object") {
    document = options.document;
  } else {
    const result = materializeTaskGraph(domain, { write: false });
    document = result.document;
  }

  const candidates = [];
  const skipped = [];
  if (Array.isArray(document.nodes)) {
    for (const node of document.nodes) {
      if (!node || typeof node !== "object") continue;
      // Wave-scheduled kinds (surface + claim) are NEVER eligible here.
      // Per X-D7 they ride the wave-scheduler unchanged; surfacing them
      // in the graph-scheduler's skipped list would conflate authority.
      if (!GRAPH_SCHEDULED_KINDS.includes(node.kind)) continue;
      if (!DISPATCH_ELIGIBLE_STATES.includes(node.state)) continue;
      candidates.push({
        node_id: node.node_id,
        kind: node.kind,
        state: node.state,
        priority: node.priority || "medium",
        severity_floor: node.severity_floor || null,
        // Breadth-vs-depth tier: default 1 (Tier-1 breadth). E2 mints Tier-2
        // depth re-probe cell nodes carrying node.tier=2, which the comparator's
        // outermost tier key sorts after all Tier-1 work. Until a node sets tier,
        // this is a constant 1 and the sort is byte-identical.
        tier: Number.isInteger(node.tier) ? node.tier : 1,
        ts_first: node.ts_first || null,
        ts_last: node.ts_last || null,
      });
    }
  }

  const priorityRank = priorityRankFromPolicy(policy);
  // Optional, default-off belief overlay. Only when an operator opts into the
  // CB-C1 flag do we lazily pull the belief module and compute a per-cell
  // score map; with the flag off (the default) no belief code is required and
  // the sort runs exactly as it does without this branch. Any failure degrades
  // to the deterministic spine (null map → byte-identical ordering).
  let beliefRank = null;
  if (policy.belief_assisted_priority_enabled === true) {
    try {
      const { buildCellBeliefRank } = require("./belief/cell-scheduler-priority.js");
      beliefRank = buildCellBeliefRank({
        target_domain: domain,
        document,
        candidates,
        seed: policy.belief_assisted_priority_seed,
        rank_limit: policy.belief_assisted_priority_rank_limit,
      });
    } catch {
      beliefRank = null;
    }
  }
  candidates.sort((a, b) => compareGraphCandidates(a, b, priorityRank, beliefRank));

  // D2 (CN Step B) — per-kind cap split. By default (max_concurrent_evaluators
  // unset) every graph-scheduled kind shares the single `cap` (byte-identical to
  // before). When an operator sets max_concurrent_evaluators, the cell-floor kind
  // scales to that cap while transition/hypothesis stay at `cap` (= max_parallel_tasks),
  // taken in ONE pass over the already-sorted candidates so global tier/priority order
  // is preserved within each kind (no re-sort). capacity_limit becomes the combined
  // cell+graph budget so capacity_used === selected.length and <= capacity_limit hold.
  let selected;
  let capacityLimit;
  if (Number.isInteger(policy.max_concurrent_evaluators)) {
    const cellCap = policy.max_concurrent_evaluators;
    const graphCap = cap;
    selected = [];
    let cellTaken = 0;
    let graphTaken = 0;
    for (const node of candidates) {
      const isCell = node.kind === "cell";
      if (isCell ? cellTaken < cellCap : graphTaken < graphCap) {
        selected.push(node);
        if (isCell) cellTaken += 1;
        else graphTaken += 1;
      } else {
        skipped.push(node);
      }
    }
    capacityLimit = cellCap + graphCap;
  } else {
    selected = candidates.slice(0, cap);
    for (const node of candidates.slice(cap)) skipped.push(node);
    capacityLimit = cap;
  }

  const sourceGraphHash = document.hashes && typeof document.hashes.graph_hash === "string"
    ? document.hashes.graph_hash
    : null;

  return {
    target_domain: domain,
    materialized_at: document.materialized_at || null,
    source_graph_hash: sourceGraphHash,
    capacity_used: selected.length,
    capacity_limit: capacityLimit,
    considered_count: candidates.length,
    selected: selected.map((node) => ({ ...node })),
    skipped: skipped.map((node) => ({ ...node })),
    policy,
  };
}

module.exports = {
  DISPATCH_ELIGIBLE_STATES,
  GRAPH_SCHEDULED_KINDS,
  compareGraphCandidates,
  selectNextExecutableNodes,
};
