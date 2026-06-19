"use strict";

// Plane X Cycle X.9 — bob_schedule_graph_nodes.
//
// Orchestrator-only graph-walking scheduler tool. Wraps the pure
// `selectNextExecutableNodes` selection with a graph-hash-drift check
// and the X.8 dispatch dance:
//
//   1. selectNextExecutableNodes(domain, policy, capacity) → captures
//      the materialized graph's `source_graph_hash`.
//   2. For each selected node id, re-materializes the graph and
//      cross-checks the live `graph_hash`. A mismatch between the
//      selection-time and dispatch-time hash means the ledger has
//      moved underfoot (another producer landed events while we were
//      mid-flight); refuse with structured `graph_hash_drift` so the
//      operator re-selects against the new graph state.
//   3. Dispatch each selected node via bob_prepare_node (the X.8
//      atomic protocol). Honors the X-D7 dual-write scope: Surface +
//      Claim nodes are filtered out at selection time so the
//      wave-scheduler retains authority over those kinds.
//   4. Persist a GraphSchedulerDecision row to scheduler-decisions.jsonl
//      via appendGraphSchedulerDecision — same ledger, different shape
//      from the wave-driven task decision (kind-discriminator routing).
//
// Per X-D7 there is no `dispatcher_preference` config. Node kind alone
// determines which scheduler owns dispatch; Surface + Claim ride the
// wave-scheduler unchanged.

const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  assertSafeDomain,
} = require("../paths.js");
// Resolve the selector via the module object (not a destructured binding)
// so test scaffolding can stub it to exercise the graph_hash_drift refusal
// path without forcing a real producer-event race. In production the
// indirection is a single property read.
const graphSchedulerModule = require("../graph-scheduler.js");
const {
  appendGraphSchedulerDecision,
} = require("../scheduler-decisions.js");
const {
  loadQueuePolicy,
} = require("../queue-policy.js");
const {
  materializeTaskGraph,
} = require("../task-graph-materializer.js");

function structuredError(code, message, details) {
  const err = new Error(`${code}: ${message}`);
  err.code = code;
  if (details) err.details = details;
  return err;
}

function handler(args) {
  const input = args || {};
  const domain = assertSafeDomain(
    assertNonEmptyString(input.target_domain, "target_domain"),
  );
  // Capacity defaults to the queue policy's max_parallel_tasks; tests
  // can override via the `capacity` argument.
  const policy = input.policy && typeof input.policy === "object"
    ? input.policy
    : loadQueuePolicy(domain);
  const capacity = input.capacity == null ? null : input.capacity;

  const selection = graphSchedulerModule.selectNextExecutableNodes(domain, policy, capacity);

  // Step 2: graph-hash drift check. Re-materialize the graph immediately
  // after selection (no agent calls have run yet) and compare hashes.
  // The selection function itself reads the materialized doc; this
  // second read catches a producer that landed a new event in the
  // microsecond gap between selection and dispatch.
  const liveResult = materializeTaskGraph(domain, { write: false });
  const liveGraphHash = liveResult.document.hashes
    && typeof liveResult.document.hashes.graph_hash === "string"
    ? liveResult.document.hashes.graph_hash
    : null;
  if (selection.source_graph_hash && liveGraphHash
      && selection.source_graph_hash !== liveGraphHash) {
    throw structuredError(
      "graph_hash_drift",
      `task-graph mutated between selection (${selection.source_graph_hash}) and dispatch (${liveGraphHash}); re-select against the live graph state`,
      {
        target_domain: domain,
        selection_graph_hash: selection.source_graph_hash,
        live_graph_hash: liveGraphHash,
        materialized_at_selection: selection.materialized_at,
        materialized_at_live: liveResult.document.materialized_at,
      },
    );
  }

  // Step 3: dispatch each selected node via bob_prepare_node. We use a
  // lazy require so the tool-registry's eager tools/index.js load does
  // not pull this module before bob_prepare_node is registered (both
  // tools are siblings in the registry, and prepare-node also requires
  // the materializer + capability-pack-derivation transitively).
  const dispatchEnabled = input.dispatch == null ? true : input.dispatch === true;
  const dispatched = [];
  const failed = [];
  if (dispatchEnabled && selection.selected.length > 0) {
    const { TOOL_HANDLERS } = require("../tool-registry.js");
    const prepareNode = TOOL_HANDLERS && TOOL_HANDLERS.bob_prepare_node;
    if (typeof prepareNode !== "function") {
      throw structuredError(
        "prepare_node_unavailable",
        "bob_prepare_node is not registered in the MCP tool registry; cannot dispatch graph-selected nodes",
        { target_domain: domain },
      );
    }
    for (const node of selection.selected) {
      try {
        const result = JSON.parse(prepareNode({
          target_domain: domain,
          node_id: node.node_id,
          actor: input.actor,
          ts: input.ts,
        }));
        dispatched.push({
          node_id: node.node_id,
          prep_token: result.prep_token,
          brief_hash: result.brief_hash,
          graph_context_hash: result.graph_context_hash,
          event_id: result.event_id,
        });
      } catch (err) {
        failed.push({
          node_id: node.node_id,
          code: err && err.code ? err.code : "prepare_node_failed",
          message: err && err.message ? err.message : String(err),
        });
      }
    }
  }

  // Step 4: persist the GraphSchedulerDecision row. The decision lands
  // even when no nodes were selected (empty selections are a useful
  // telemetry signal) and even when some dispatches failed (the
  // failures live in the response but the decision records WHAT was
  // selected against WHICH graph hash).
  const decision = appendGraphSchedulerDecision({
    target_domain: domain,
    ts: input.ts,
    decision_kind: "schedule_graph_nodes",
    policy,
    source_graph_hash: selection.source_graph_hash,
    capacity_limit: selection.capacity_limit,
    capacity_used: selection.capacity_used,
    considered_count: selection.considered_count,
    selected_node_ids: selection.selected.map((n) => n.node_id),
    skipped_node_ids: selection.skipped.map((n) => n.node_id),
    selected_nodes: selection.selected,
    skipped_nodes: selection.skipped,
  });

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    scheduler_decision_id: decision.scheduler_decision_id,
    scheduler_decision_hash: decision.scheduler_decision_hash,
    decision_kind: decision.decision_kind,
    source_graph_hash: decision.source_graph_hash,
    queue_policy_hash: decision.queue_policy_hash,
    capacity_used: decision.capacity_used,
    capacity_limit: decision.capacity_limit,
    considered_count: decision.considered_count,
    selected_node_ids: decision.selected_node_ids,
    skipped_node_ids: decision.skipped_node_ids,
    dispatched,
    failed,
  });
}

module.exports = Object.freeze({
  name: "bob_schedule_graph_nodes",
  description:
    "Graph-walking scheduler for Transition + Hypothesis nodes (X-P1, X-D7). "
    + "Reads the materialized task-graph, filters to dispatch-eligible "
    + "Transition + Hypothesis nodes (state ∈ {contracted, ready}; Surface "
    + "+ Claim ride the wave-scheduler unchanged per X-D7), sorts by "
    + "priority + queue_policy, caps at capacity, then dispatches each "
    + "selected node via bob_prepare_node. Refuses with structured "
    + "graph_hash_drift if the live task-graph hash differs from the "
    + "selection-time hash so the operator re-selects against the live "
    + "state. Persists a GraphSchedulerDecision row to scheduler-decisions.jsonl "
    + "(decision_kind: schedule_graph_nodes) with source_graph_hash, "
    + "selected_node_ids, skipped_node_ids, capacity_used. Orchestrator-only.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      capacity: {
        type: "integer",
        description:
          "Optional cap on the number of selected nodes. Defaults to the queue "
          + "policy's max_parallel_tasks; hard-capped at 128.",
      },
      policy: {
        type: "object",
        description:
          "Optional queue-policy override (defaults to the persisted "
          + "queue-policy.json). Useful for tests; in production the policy "
          + "should be loaded from disk so policy_hash drifts surface in the "
          + "decision row.",
      },
      dispatch: {
        type: "boolean",
        description:
          "When true (default) each selected node is dispatched via "
          + "bob_prepare_node. When false, the selection is computed and the "
          + "decision row is appended but no prepare_node call fires. Useful "
          + "for dry-runs and tests.",
      },
      ts: { type: "string" },
      actor: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler,
  // X.9 Do step 2: orchestrator-only. No new role bundle introduced; the
  // existing prepare-node + finalize-node tools are also orchestrator-only
  // so the graph-scheduler dispatch path inherits the same authority.
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [
    "scheduler-decisions.jsonl",
    "frontier-events.jsonl",
  ],
});
