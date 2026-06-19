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

// Closed enum of node kinds the graph-scheduler owns (X-D7 / X-P1).
// Surface + Claim are wave-scheduled and intentionally excluded; this
// constant doubles as the "what does the regression test check?" anchor
// so the wave-scheduler-owned kinds never leak into a graph-decision.
const GRAPH_SCHEDULED_KINDS = Object.freeze(["transition", "hypothesis"]);

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

function compareGraphCandidates(a, b, priorityRank) {
  const fallback = priorityRank.size;
  const ra = priorityRank.has(a.priority) ? priorityRank.get(a.priority) : fallback;
  const rb = priorityRank.has(b.priority) ? priorityRank.get(b.priority) : fallback;
  if (ra !== rb) return ra - rb;
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
  // Hard upper bound to defend against pathological callers (matches the
  // existing scheduler-decisions hard cap on max_assignments).
  return Math.min(Math.floor(num), 128);
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
        ts_first: node.ts_first || null,
        ts_last: node.ts_last || null,
      });
    }
  }

  const priorityRank = priorityRankFromPolicy(policy);
  candidates.sort((a, b) => compareGraphCandidates(a, b, priorityRank));

  const selected = candidates.slice(0, cap);
  for (const node of candidates.slice(cap)) {
    skipped.push(node);
  }

  const sourceGraphHash = document.hashes && typeof document.hashes.graph_hash === "string"
    ? document.hashes.graph_hash
    : null;

  return {
    target_domain: domain,
    materialized_at: document.materialized_at || null,
    source_graph_hash: sourceGraphHash,
    capacity_used: selected.length,
    capacity_limit: cap,
    considered_count: candidates.length,
    selected: selected.map((node) => ({ ...node })),
    skipped: skipped.map((node) => ({ ...node })),
    policy,
  };
}

module.exports = {
  DISPATCH_ELIGIBLE_STATES,
  GRAPH_SCHEDULED_KINDS,
  selectNextExecutableNodes,
};
