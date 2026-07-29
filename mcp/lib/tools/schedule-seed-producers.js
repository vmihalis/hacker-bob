"use strict";

// bob_schedule_seed_producers — the seed-producer scheduler. Mirrors
// bob_schedule_graph_nodes but filtered to kind 'producer'. Selects executable
// producer nodes (materialized by the producer floor, not yet terminal in the
// producer_run ledger), caps the selection at the per-pass governor
// (seed_producer_per_pass_cap), and dispatches each via the bob_prepare_node path.
// Each dispatched producer reserves one spawn-ledger slot. Over-cap producers are
// reported in skipped[] + a spawn_budget_exhausted report naming their node ids —
// RANK != BOUND: the floor never silently drops a producer. Pure-selector +
// impure-dispatch split, like the graph scheduler. Orchestrator-only.

const { assertNonEmptyString } = require("../validation.js");
const { assertSafeDomain } = require("../paths.js");
const { loadQueuePolicy, normalizeQueuePolicy } = require("../queue-policy.js");
const { materializeTaskGraph, producerNodeId } = require("../task-graph-materializer.js");
const { readFrontierEvents } = require("../frontier-events.js");
const { producerRunSet } = require("../producer-run-ledger.js");
const { appendSpawnLedgerEntry } = require("../spawn-ledger.js");
const { withSessionLock } = require("../storage.js");
const { PRODUCER_NODE_KIND } = require("../constants.js");

// Bounded retry window for the drift backpressure. When independent producers
// land surfaces concurrently the task-graph hash churns between two successive
// read-only materializes (a thundering herd); each drift retry halves the dispatch
// batch, capped at this many retries. LOCAL constant — the backpressure is a
// scheduler-internal stabilization loop, not a persisted queue-policy governor.
const SEED_DRIFT_RETRY_BUDGET = 4;

// Pure: halve the dispatch batch on a drift retry, flooring at 1 (never 0) so
// every round still dispatches at least one producer — the forward-progress /
// termination guarantee for the backpressure loop.
function nextDispatchBatch(currentBatch) {
  const n = Number.isInteger(currentBatch) && currentBatch > 0 ? currentBatch : 1;
  return Math.max(1, Math.floor(n / 2));
}

// Drift-backpressure driver. Walks successive read-only graph_hashes; while
// adjacent hashes differ (drift from concurrent producer landings) and the retry
// budget is not yet spent, it shrinks the dispatch batch and counts the retry. The
// first adjacent pair that agrees is quiescence. The handler drives it with live
// callbacks (select against the current graph, readHash re-materializes read-only,
// onDrift refreshes nodes/runSet/producer-key map); the drift/termination tests
// drive it with a precomputed hashSequence and no callbacks. One control-flow
// implementation, one set of tests — the production path and the pinned path are
// the same code.
//
//   select(batch)  -> selection for the current batch (impure; may be omitted)
//   readHash()     -> the next read-only graph_hash (impure)
//   onDrift()      -> refresh derived state after a drift is observed (impure)
//
// Returns { finalBatch, driftRetries, quiescent, exhausted, selection }.
// quiescent=false with exhausted=true iff the graph never stabilized within the
// budget; the handler names the still-undispatched producers in that case.
function planDriftBackpressure(opts) {
  const o = opts || {};
  const budget = Number.isInteger(o.retryBudget) && o.retryBudget >= 0
    ? o.retryBudget
    : SEED_DRIFT_RETRY_BUDGET;
  let batch = Number.isInteger(o.initialBatch) && o.initialBatch > 0 ? o.initialBatch : 1;

  const noop = () => undefined;
  const select = typeof o.select === "function" ? o.select : noop;
  const onDrift = typeof o.onDrift === "function" ? o.onDrift : noop;

  // Source of successive hashes: the live re-materialize (handler) or a precomputed
  // sequence (tests). END marks a spent test sequence — the loop stops without
  // asserting quiescence, so a sequence that runs out mid-drift stays non-quiescent.
  const END = Symbol("hash_sequence_end");
  let prevHash;
  let readHash;
  if (Array.isArray(o.hashSequence)) {
    const seq = o.hashSequence;
    prevHash = seq.length > 0 ? seq[0] : END;
    let idx = 1;
    readHash = () => (idx < seq.length ? seq[idx++] : END);
  } else {
    prevHash = o.initialHash;
    readHash = typeof o.readHash === "function" ? o.readHash : () => prevHash;
  }

  let driftRetries = 0;
  // A stable adjacent pair confirms quiescence; budget exhaustion mid-drift marks it
  // non-quiescent. No adjacent pair observed ⇒ treat as quiescent (no drift).
  let quiescent = true;
  let exhausted = false;
  let selection;
  for (;;) {
    selection = select(batch);
    const nextHash = readHash();
    if (nextHash === END) break; // spent test sequence: keep the last-observed state
    if (nextHash === prevHash) { quiescent = true; break; }
    quiescent = false;
    prevHash = nextHash;
    onDrift();
    if (driftRetries >= budget) {
      // Budget spent while the graph still drifts: re-select once against the
      // freshest state at the shrunk batch, then report the non-quiescent gap.
      selection = select(batch);
      exhausted = true;
      break;
    }
    batch = nextDispatchBatch(batch);
    driftRetries += 1;
  }
  return { finalBatch: batch, driftRetries, quiescent, exhausted, selection };
}

// Pure: the REPORTED non-quiescent gap. RANK != BOUND — when the seed loop cannot
// quiesce within the retry budget the still-undispatched producers are NAMED, never
// silently abandoned.
function buildSeedLoopNonquiescentGap(undispatchedNodeIds) {
  return {
    kind: "seed_loop_nonquiescent",
    undispatched_producer_node_ids: Array.isArray(undispatchedNodeIds)
      ? undispatchedNodeIds.slice()
      : [],
  };
}

// Pure selector: from the materialized producer nodes, select the not-run
// producers up to `cap`, push the over-cap remainder to skipped. The producer
// floor emits a node before any node.transitioned, so a producer node's existence
// is its dispatch eligibility (deps are met by floor emission). Deterministic
// ordering (ts_first asc, then node_id) so a re-run selects the same set.
function selectExecutableProducers({ nodes, nodeIdToProducerKey, producerRunSet: runSet, cap }) {
  const runs = runSet instanceof Set ? runSet : new Set(runSet || []);
  const map = nodeIdToProducerKey instanceof Map ? nodeIdToProducerKey : new Map();
  const candidates = [];
  for (const node of Array.isArray(nodes) ? nodes : []) {
    if (!node || node.kind !== PRODUCER_NODE_KIND) continue;
    const producerKey = map.get(node.node_id);
    // A node whose producer_key is already terminal is done — never re-dispatch.
    if (typeof producerKey === "string" && runs.has(producerKey)) continue;
    candidates.push(node);
  }
  candidates.sort((a, b) => {
    const ta = typeof a.ts_first === "string" ? a.ts_first : "";
    const tb = typeof b.ts_first === "string" ? b.ts_first : "";
    if (ta !== tb) return ta.localeCompare(tb);
    return String(a.node_id).localeCompare(String(b.node_id));
  });
  const limit = Number.isInteger(cap) && cap > 0 ? cap : candidates.length;
  const selected = candidates.slice(0, limit);
  const skipped = candidates.slice(limit);
  return { selected, skipped, considered_count: candidates.length };
}

// Pure-read: rebuild the node_id -> producer_key map from the producer_proposed
// frontier events. Read fresh each time it is called so a drift retry resolves
// producer nodes against the current event stream, not a stale snapshot.
function buildNodeIdToProducerKey(domain) {
  const nodeIdToProducerKey = new Map();
  for (const event of readFrontierEvents(domain)) {
    if (!event || event.kind !== "observation.recorded") continue;
    const payload = event.payload;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) continue;
    const obsKind = (typeof payload.observation_kind === "string" && payload.observation_kind.trim())
      ? payload.observation_kind.trim()
      : (typeof payload.kind === "string" ? payload.kind.trim() : "");
    if (obsKind !== "producer_proposed") continue;
    const producerKey = (typeof payload.producer_key === "string" && payload.producer_key)
      ? payload.producer_key
      : (typeof payload.producer_id === "string" ? payload.producer_id : null);
    if (!producerKey) continue;
    nodeIdToProducerKey.set(producerNodeId({ producerKey }), producerKey);
  }
  return nodeIdToProducerKey;
}

function handler(args) {
  const input = args || {};
  const domain = assertSafeDomain(assertNonEmptyString(input.target_domain, "target_domain"));
  const policy = input.policy && typeof input.policy === "object"
    ? input.policy
    : loadQueuePolicy(domain);
  const normalizedPolicy = normalizeQueuePolicy(policy || {});
  // The per-pass governor is the cap; an explicit `capacity` overrides it for a
  // single dispatch (tests can force the over-cap skipped path).
  const cap = Number.isInteger(input.capacity) && input.capacity > 0
    ? input.capacity
    : normalizedPolicy.seed_producer_per_pass_cap;
  // Bounded drift-retry window; an explicit retry_budget overrides it for tests.
  const retryBudget = Number.isInteger(input.retry_budget) && input.retry_budget >= 0
    ? input.retry_budget
    : SEED_DRIFT_RETRY_BUDGET;

  // Serialize the whole select -> reserve -> dispatch sequence under the session
  // lock. Without it, two concurrent bob_schedule_seed_producers invocations read the
  // same graph, select the same producer nodes, and both reserve + dispatch (double-
  // dispatch), and the drift-backpressure loop churns to batch 1 reporting false
  // non-quiescence. The lock is reentrant, so the nested bob_prepare_node and
  // appendSpawnLedgerEntry locks compose without deadlock.
  const result = withSessionLock(domain, () => {
  // Materialize the producer nodes (read-only) and rebuild the node_id ->
  // producer_key map from the producer_proposed events so the selector can resolve
  // each producer node back to its pack key (and skip already-terminal producers).
  let liveResult = materializeTaskGraph(domain, { write: false });
  let nodes = liveResult.document.nodes || [];
  const initialGraphHash = liveResult.document.hashes ? liveResult.document.hashes.graph_hash : null;
  let nodeIdToProducerKey = buildNodeIdToProducerKey(domain);

  // The terminal producer_run set. Re-read on every drift retry (via onDrift below)
  // so a producer another process finalizes between now and a retry is filtered out.
  let runSet = producerRunSet(domain);

  // Drift-gated shrink loop, driven by planDriftBackpressure. select at the current
  // batch, then re-materialize read-only and compare the graph_hash. Two successive
  // synchronous reads with the SAME hash (the normal/no-concurrency path) run the
  // body exactly once and dispatch byte-identically to the single-pass scheduler.
  // On drift (concurrent producer landings churned the graph) the batch is halved
  // (backpressure) and the selection is recomputed against the fresher graph,
  // bounded by retryBudget. Budget exhaustion mid-drift is reported below — never a
  // silent abandon. onDrift re-reads the fresher nodes AND the terminal
  // producer_run set + node->producer_key map: another process may have finalized a
  // producer in the drift window, and selecting against the STALE runSet would fail
  // to filter it and could re-dispatch an already-terminal producer (double-dispatch,
  // a monotonicity violation).
  let lastRemat = liveResult;
  const plan = planDriftBackpressure({
    initialBatch: cap,
    retryBudget,
    initialHash: initialGraphHash,
    select: (currentBatch) => selectExecutableProducers({
      nodes,
      nodeIdToProducerKey,
      producerRunSet: runSet,
      cap: currentBatch,
    }),
    readHash: () => {
      lastRemat = materializeTaskGraph(domain, { write: false });
      return lastRemat.document.hashes ? lastRemat.document.hashes.graph_hash : null;
    },
    onDrift: () => {
      nodes = lastRemat.document.nodes || [];
      runSet = producerRunSet(domain);
      nodeIdToProducerKey = buildNodeIdToProducerKey(domain);
    },
  });
  const selection = plan.selection;
  const driftRetries = plan.driftRetries;
  const batch = plan.finalBatch;
  const nonQuiescent = plan.exhausted;

  // Dispatch each selected producer via the bob_prepare_node path. bob_prepare_node
  // is the single dispatch-eligibility authority; a producer it refuses (e.g. an
  // uncontracted producer in state 'proposed') lands in failed[] rather than
  // mutating node state here. Lazy require so the eager tools/index.js load does
  // not pull this module before bob_prepare_node is registered.
  const dispatchEnabled = input.dispatch !== false;
  const dispatched = [];
  const failed = [];
  if (dispatchEnabled && selection.selected.length > 0) {
    const { TOOL_HANDLERS } = require("../tool-registry.js");
    const prepareNode = TOOL_HANDLERS && TOOL_HANDLERS.bob_prepare_node;
    for (const node of selection.selected) {
      if (typeof prepareNode !== "function") {
        failed.push({
          node_id: node.node_id,
          code: "prepare_node_unavailable",
          message: "bob_prepare_node is not registered in the MCP tool registry",
        });
        continue;
      }
      // Reserve one lifetime spawn-ledger slot BEFORE the bob_prepare_node state
      // mutation. Ordering matters: if the reservation were written AFTER dispatch
      // (and its failure swallowed), a prepared producer could exist with no
      // ledger row and spawnLedgerTotal would UNDERCOUNT the max_total_spawned_agents
      // gate. Reserving first — and SURFACING a ledger-write failure by routing the
      // producer to failed[] without mutating node state — guarantees the gate can
      // never miss a dispatched producer. appendSpawnLedgerEntry holds the session
      // lock for the append. A refused-after-reserve producer over-counts by one
      // slot, the conservative (never-over-spawn) direction for a budget gate.
      try {
        appendSpawnLedgerEntry(domain, {
          ts: input.ts || new Date().toISOString(),
          wave: "seed_producer",
          parent_agent: input.actor || null,
          surface_id: node.node_id,
          depth: 0,
          branching: 0,
          kind: "seed_producer",
          root_count: 1,
          descendant_tree: 0,
          worst_case_tree: 1,
        });
      } catch (err) {
        failed.push({
          node_id: node.node_id,
          code: err && err.code ? err.code : "spawn_ledger_reservation_failed",
          message: err && err.message ? err.message : String(err),
        });
        continue;
      }
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

  const out = {
    version: 1,
    target_domain: domain,
    considered_count: selection.considered_count,
    selected_node_ids: selection.selected.map((node) => node.node_id),
    dispatched,
    failed,
    // RANK != BOUND: over-cap producers are reported, never silently dropped.
    skipped: selection.skipped.map((node) => node.node_id),
  };
  if (selection.skipped.length > 0) {
    out.spawn_budget_exhausted = {
      kind: "spawn_budget_exhausted",
      seed_producer_per_pass_cap: cap,
      uncovered_producer_node_ids: selection.skipped.map((node) => node.node_id),
    };
  }
  // Additive backpressure telemetry. On the no-concurrency path drift_retries is 0
  // and final_dispatch_batch equals the cap, so the dispatched/skipped output is
  // byte-identical to the single-pass scheduler.
  out.drift_retries = driftRetries;
  out.final_dispatch_batch = batch;
  // RANK != BOUND: the seed loop could not quiesce within the retry budget AND
  // executable producers remain undispatched — NAME them, never silently abandon.
  if (nonQuiescent && selection.skipped.length > 0) {
    out.seed_loop_nonquiescent = buildSeedLoopNonquiescentGap(
      selection.skipped.map((node) => node.node_id),
    );
  }
  return out;
  });
  return JSON.stringify(result);
}

module.exports = Object.freeze({
  name: "bob_schedule_seed_producers",
  description:
    "Seed-producer scheduler (sibling of bob_schedule_graph_nodes, filtered to "
    + "kind 'producer'). Reads the materialized task-graph, selects producer nodes "
    + "whose producer_key is not yet terminal in the producer_run ledger, caps the "
    + "selection at the seed_producer_per_pass_cap governor, then dispatches each "
    + "via bob_prepare_node (successes in dispatched[], refusals in failed[]). "
    + "Reserves one spawn-ledger slot per dispatched producer. Over-cap producers "
    + "are reported in skipped[] + a spawn_budget_exhausted report naming the "
    + "uncovered producer node ids — RANK != BOUND, never a silent drop. "
    + "Orchestrator-only.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      capacity: {
        type: "integer",
        description:
          "Optional override of the per-pass cap. Defaults to the queue policy's "
          + "seed_producer_per_pass_cap; over-cap producers go to skipped[].",
      },
      policy: {
        type: "object",
        description:
          "Optional queue-policy override (defaults to the persisted "
          + "queue-policy.json). Useful for tests.",
      },
      dispatch: {
        type: "boolean",
        description:
          "When true (default) each selected producer is dispatched via "
          + "bob_prepare_node. When false, the selection is computed but no "
          + "prepare_node call fires. Useful for dry-runs and tests.",
      },
      retry_budget: {
        type: "integer",
        description:
          "Optional override of the drift-backpressure retry budget (defaults to "
          + "SEED_DRIFT_RETRY_BUDGET). Bounds how many times a drifting graph_hash "
          + "halves the dispatch batch before the non-quiescent gap is reported.",
      },
      ts: { type: "string" },
      actor: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [
    "frontier-events.jsonl",
    "spawn-ledger.jsonl",
  ],
  // Inert extra descriptor keys (defineTool ignores unknown keys, same precedent
  // as planProducerFloor): the pure selector + drift-backpressure helpers are
  // reused by the termination/backpressure tests instead of being re-derived.
  selectExecutableProducers,
  nextDispatchBatch,
  planDriftBackpressure,
  buildSeedLoopNonquiescentGap,
  SEED_DRIFT_RETRY_BUDGET,
});
