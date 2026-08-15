"use strict";

// Plane X Cycle X.2 — TaskGraph materializer.
//
// Folds the frontier-events.jsonl stream into a deterministic task-graph.json
// document. Per X-P9 the materialized view is, by construction, a distilled
// summary: it carries node identifiers, hashes, state-transition counts, and
// timestamps — NOT raw bodies. Per the pre-flight sweep finding, TaskGraph
// node ids use the `TG-` prefix throughout so they cannot be confused with
// `mcp/core/frontier/surface-graph.js` adjacency `node_id` strings (a different graph).
//
// Per Cycle X.1 the ledger gained ONE new top-level kind, `node.transitioned`,
// plus two `observation.recorded` payload kinds: `transition_proposed` and
// `hypothesis_proposed`. The materializer derives 4 node kinds from those:
//   - Surface     ← surface.observed events
//   - Hypothesis  ← observation.recorded (hypothesis_proposed)
//   - Transition  ← observation.recorded (transition_proposed)
//   - Claim       ← claim.candidate.linked events (claim_id-keyed)
// State transitions for Transition + Hypothesis ride on `node.transitioned`
// (X-P1: TaskGraph is the dispatch authority for those two kinds). Surface +
// Claim are wave-scheduled per X-D7 and stay in their proposal/observation
// states in the materialized graph; their lifecycle is recorded elsewhere.
//
// Ledger-pressure guardrail (X.2 Do step 5 + X-R1):
//   - 12_000 events  → warning   "graph_ledger_pressure"
//   - 18_000 events  → refusal   structured ledger_pressure_refusal
// FRONTIER_EVENTS_MAX_RECORDS = 20_000 is enforced in frontier-events.js;
// the refusal threshold sits below that so a materializer call still has
// headroom to fold a final wave of events without bouncing the ledger cap.

const {
  FRONTIER_EVENTS_MAX_RECORDS,
  readFrontierEvents,
} = require("../frontier/frontier-events.js");
const {
  assertSafeDomain,
  taskGraphPath,
} = require("../io/paths.js");
const {
  sortByTextField,
} = require("../io/validation.js");
const {
  writeJsonDocument,
} = require("../io/storage.js");
const {
  withSessionLock,
} = require("../io/storage.js");
const {
  hashCanonicalJson,
} = require("../verification/verification-contracts.js");
const {
  normalizePhysicalResourceBundleBinding,
} = require("../physical-resource-contracts.js");
const {
  normalizePhysicalResourceDispatchBinding,
} = require("./task-graph-events.js");
const {
  NODE_STATE_VALUES,
  TASK_GRAPH_NODE_ID_PREFIX,
  cellNodeId,
  claimNodeId,
  hypothesisNodeId,
  isAllowedNodeTransition,
  producerNodeId,
  surfaceNodeId,
  transitionNodeId,
} = require("./task-graph-state-machine.js");
// X.3 / X-P6: the SURFACE_KIND_VALUES enum is the canonical SoT for the
// closed set of TaskGraph node kinds AND the kind discriminator persisted
// in surface-index.json. The X.2 materializer alias TASK_GRAPH_NODE_KIND_VALUES
// is preserved for back-compat re-export; both point at the same frozen array.
const {
  SURFACE_KIND_VALUES,
  PRODUCER_NODE_KIND,
} = require("./task-graph-scheduling.js");

// Ledger-pressure thresholds. Public for tests + downstream cycles that may
// surface them in summaries.
const LEDGER_PRESSURE_WARN_THRESHOLD = 12_000;
const LEDGER_PRESSURE_REFUSE_THRESHOLD = 18_000;

if (LEDGER_PRESSURE_REFUSE_THRESHOLD >= FRONTIER_EVENTS_MAX_RECORDS) {
  // Defensive: the refusal threshold MUST sit below the hard ledger cap so a
  // session whose event count is bumping the cap can still materialize one
  // last view before the appender starts rejecting writes. If a future cycle
  // bumps FRONTIER_EVENTS_MAX_RECORDS down, this module needs to revisit
  // the thresholds in lockstep.
  throw new Error(
    "LEDGER_PRESSURE_REFUSE_THRESHOLD must be below FRONTIER_EVENTS_MAX_RECORDS",
  );
}

// Closed set of TaskGraph node kinds. X.3 (X-P6) promoted this enum into
// task-graph-scheduling.js (SURFACE_KIND_VALUES) as the SoT shared with the
// surface-index materializer (transition surfaces persist with kind:
// "transition" per X-P6). The X.2 alias is preserved for back-compat
// re-export; both point at the same frozen array.
const TASK_GRAPH_NODE_KIND_VALUES = Object.freeze([...SURFACE_KIND_VALUES]);

// Closed set of edge kinds the materializer emits. X.8's finalize emits
// `unblocks` edges via `payload.edge_added_to[]`; surface adjacency for
// Transition nodes is captured via `bridges` edges keyed on the
// `transition_proposed` event's from_surface/to_surface pair.
const TASK_GRAPH_EDGE_KIND_VALUES = Object.freeze([
  "bridges",
  "unblocks",
  "claim_links",
]);

// Default priority when no Contract has been attached yet (X.4 ships the
// Contract attachment that overrides this). Mirrors queue-policy.js's
// "medium" default for unattributed tasks.
const DEFAULT_NODE_PRIORITY = "medium";

function ensureNode(nodesById, nodeId, kind, ts) {
  if (!nodesById.has(nodeId)) {
    nodesById.set(nodeId, {
      node_id: nodeId,
      kind,
      state: "proposed",
      surface_refs: [],
      contract_hash: null,
      severity_floor: null,
      priority: DEFAULT_NODE_PRIORITY,
      ts_first: ts,
      ts_last: ts,
      source_events: [],
      // Internal: the most recent failure_reason payload from a
      // node.transitioned → failed event. Carried so the X.2 summary view
      // (Do step 3) can surface it without rescanning the event log. Trimmed
      // from the raw fold so it stays bounded — only the most recent failure
      // is retained per node.
      _last_failure_reason: null,
      _physical_resource_bundle: null,
      _physical_resource_dispatch: null,
    });
  } else {
    const existing = nodesById.get(nodeId);
    // Best-effort kind consolidation. A node id collision across kinds is a
    // bug; we keep the first-seen kind and ignore later events. Surface and
    // Claim nodes can never collide with Hypothesis / Transition because the
    // sub-namespace discriminator differs (S/H/T/C).
    if (Date.parse(ts) < Date.parse(existing.ts_first)) existing.ts_first = ts;
    if (Date.parse(ts) > Date.parse(existing.ts_last)) existing.ts_last = ts;
  }
  return nodesById.get(nodeId);
}

function addSourceEvent(node, eventId) {
  if (typeof eventId !== "string" || !eventId.trim()) return;
  if (!node.source_events.includes(eventId)) {
    node.source_events.push(eventId);
  }
}

function addSurfaceRef(node, surfaceId) {
  if (typeof surfaceId !== "string" || !surfaceId.trim()) return;
  const ref = surfaceId.trim();
  if (!node.surface_refs.includes(ref)) {
    node.surface_refs.push(ref);
  }
}

function edgeKey(edge) {
  return `${edge.from_node_id}|${edge.to_node_id}|${edge.edge_kind}|${edge.source_event_id || ""}`;
}

function addEdge(edgesByKey, edge) {
  const key = edgeKey(edge);
  if (!edgesByKey.has(key)) {
    edgesByKey.set(key, edge);
  }
}

function foldEvent(event, { nodesById, edgesByKey }) {
  const ts = typeof event.ts === "string" ? event.ts : "";
  if (!ts) return;

  // ─── Surface nodes ────────────────────────────────────────────────────
  if (event.kind === "surface.observed" && event.surface_id) {
    const nodeId = surfaceNodeId(event.surface_id);
    if (!nodeId) return;
    const node = ensureNode(nodesById, nodeId, "surface", ts);
    addSurfaceRef(node, event.surface_id);
    addSourceEvent(node, event.event_id);
    return;
  }

  // ─── Claim nodes ──────────────────────────────────────────────────────
  if (event.kind === "claim.candidate.linked") {
    const claimId = event.claim_id
      || (event.payload && typeof event.payload.claim_id === "string" ? event.payload.claim_id : null);
    const nodeId = claimNodeId(claimId);
    if (!nodeId) return;
    const node = ensureNode(nodesById, nodeId, "claim", ts);
    addSourceEvent(node, event.event_id);
    if (event.surface_id) {
      addSurfaceRef(node, event.surface_id);
      // Edge from the claim's surface → the claim. Lets the summary view
      // count claim density per surface without a separate index.
      const surfaceNid = surfaceNodeId(event.surface_id);
      if (surfaceNid) {
        addEdge(edgesByKey, {
          from_node_id: surfaceNid,
          to_node_id: nodeId,
          edge_kind: "claim_links",
          weight: 1,
          source_event_id: event.event_id,
        });
      }
    }
    return;
  }

  // ─── Hypothesis / Transition proposals ────────────────────────────────
  if (event.kind === "observation.recorded" && event.payload) {
    const payload = event.payload;
    if (payload.kind === "hypothesis_proposed") {
      const nodeId = hypothesisNodeId({
        proposalId: payload.proposal_id,
        eventId: event.event_id,
      });
      const node = ensureNode(nodesById, nodeId, "hypothesis", ts);
      addSourceEvent(node, event.event_id);
      const surfaceRefs = Array.isArray(payload.surface_refs) ? payload.surface_refs : [];
      for (const ref of surfaceRefs) addSurfaceRef(node, ref);
      return;
    }
    if (payload.kind === "cell_proposed") {
      const nodeId = cellNodeId({
        cellKey: payload.cell_key,
        proposalId: payload.proposal_id,
        eventId: event.event_id,
      });
      const node = ensureNode(nodesById, nodeId, "cell", ts);
      addSourceEvent(node, event.event_id);
      // A cell is a leaf coverage obligation grounded in its parent surface(s) —
      // surface_ref(s), no bridge edges. The cell's (bug_class, auth_profile,
      // cell_key, technique_pack_ids) stay in the proposal payload and are
      // recovered at prepare/reconcile time. A transition-cell (A2) is grounded
      // in its EDGE — both endpoint surfaces; a surface-cell keeps its single ref.
      if (typeof payload.from_surface === "string" && payload.from_surface
        && typeof payload.to_surface === "string" && payload.to_surface) {
        addSurfaceRef(node, payload.from_surface);
        addSurfaceRef(node, payload.to_surface);
      } else if (typeof payload.surface_id === "string") {
        addSurfaceRef(node, payload.surface_id);
      }
      // Depth-tier marker: a residual-flagged depth re-probe (E2) carries tier=2
      // so the scheduler dispatches it after all Tier-1 breadth. Absent → Tier-1.
      if (Number.isInteger(payload.tier)) node.tier = payload.tier;
      return;
    }
    if (payload.kind === "transition_proposed") {
      const nodeId = transitionNodeId({
        proposalId: payload.proposal_id,
        eventId: event.event_id,
      });
      const node = ensureNode(nodesById, nodeId, "transition", ts);
      addSourceEvent(node, event.event_id);
      const fromSurface = typeof payload.from_surface === "string" ? payload.from_surface : null;
      const toSurface = typeof payload.to_surface === "string" ? payload.to_surface : null;
      if (fromSurface) addSurfaceRef(node, fromSurface);
      if (toSurface) addSurfaceRef(node, toSurface);
      // Transition nodes bridge two surfaces; record both edges so the
      // X.5 capability-pack derivation can recover both endpoints via a
      // ≤1-hop walk.
      const fromNid = surfaceNodeId(fromSurface);
      const toNid = surfaceNodeId(toSurface);
      if (fromNid) {
        addEdge(edgesByKey, {
          from_node_id: fromNid,
          to_node_id: nodeId,
          edge_kind: "bridges",
          weight: 1,
          source_event_id: event.event_id,
        });
      }
      if (toNid) {
        addEdge(edgesByKey, {
          from_node_id: nodeId,
          to_node_id: toNid,
          edge_kind: "bridges",
          weight: 1,
          source_event_id: event.event_id,
        });
      }
      return;
    }
    // ─── Producer nodes ─────────────────────────────────────────
    // A producer is a TaskGraph-only node (never persisted as a surface). The
    // subtype discriminator is read observation_kind-first then kind-fallback,
    // mirroring the canonical reader in frontier-projections.js, so the fold
    // matches `producer_proposed` regardless of which field the emitter stamps.
    const obsKind = (typeof payload.observation_kind === "string" && payload.observation_kind.trim())
      ? payload.observation_kind.trim()
      : (typeof payload.kind === "string" ? payload.kind.trim() : "");
    if (obsKind === "producer_proposed") {
      const nodeId = producerNodeId({
        producerKey: payload.producer_key || payload.producer_id,
        proposalId: payload.proposal_id,
        eventId: event.event_id,
      });
      const node = ensureNode(nodesById, nodeId, PRODUCER_NODE_KIND, ts);
      addSourceEvent(node, event.event_id);
      // Optional explicit grounding: fold surface_refs[] only when it is an
      // array of strings (defensive, mirrors the hypothesis branch). A producer
      // adds NO bridge/claim/unblocks edges — dispatch wiring is a later node.
      if (Array.isArray(payload.surface_refs)) {
        for (const ref of payload.surface_refs) addSurfaceRef(node, ref);
      }
      return;
    }
    return;
  }

  // ─── node.transitioned: state machine ────────────────────────────────
  if (event.kind === "node.transitioned" && event.payload) {
    const payload = event.payload;
    const nodeId = typeof payload.node_id === "string" ? payload.node_id : null;
    if (!nodeId) return;
    // A transition cannot create a node.  Proposal/observation events are the
    // sole node-establishment authority.  This also makes replay fail closed
    // for legacy ledgers that contain a raw or forged transition: an orphan,
    // stale, or invalid edge is ignored instead of synthesizing a dispatchable
    // node or replacing its current state.
    const node = nodesById.get(nodeId);
    if (!node) return;
    const fromState = typeof payload.from_state === "string"
      ? payload.from_state.trim()
      : "";
    const toState = typeof payload.to_state === "string"
      ? payload.to_state.trim()
      : "";
    if (!NODE_STATE_VALUES.includes(fromState)
        || !NODE_STATE_VALUES.includes(toState)
        || node.state !== fromState
        || !isAllowedNodeTransition(fromState, toState)) {
      return;
    }
    addSourceEvent(node, event.event_id);
    node.state = toState;
    if (Date.parse(ts) < Date.parse(node.ts_first)) node.ts_first = ts;
    if (Date.parse(ts) > Date.parse(node.ts_last)) node.ts_last = ts;
    if (typeof payload.contract_hash === "string" && payload.contract_hash.trim()) {
      node.contract_hash = payload.contract_hash.trim();
    }
    if (payload.to_state === "contracted" && payload.contract && typeof payload.contract === "object") {
      node._physical_resource_bundle = payload.contract.physical_resource_bundle == null
        ? null
        : normalizePhysicalResourceBundleBinding(
          payload.contract.physical_resource_bundle,
          "node.transitioned.contract.physical_resource_bundle",
        );
      // A re-contract after a failed attempt begins a new dispatch epoch. Do
      // not let the prior attempt's reservation proof masquerade as current.
      node._physical_resource_dispatch = null;
    }
    if (payload.to_state === "dispatched" && payload.physical_resource_dispatch != null) {
      node._physical_resource_dispatch = normalizePhysicalResourceDispatchBinding(
        payload.physical_resource_dispatch,
        "node.transitioned.physical_resource_dispatch",
      );
    }
    if (typeof payload.severity_floor === "string" && payload.severity_floor.trim()) {
      node.severity_floor = payload.severity_floor.trim();
    }
    if (typeof payload.priority === "string" && payload.priority.trim()) {
      node.priority = payload.priority.trim();
    }
    if (
      payload.to_state === "failed"
      && payload.failure_reason
      && typeof payload.failure_reason === "object"
    ) {
      node._last_failure_reason = payload.failure_reason;
    }
    // edge_added_to[] expresses downstream nodes that this transition has
    // unblocked. Emit an `unblocks` edge per downstream id. Per X-D7 +
    // X-P1, edges are derived from node.transitioned events with
    // payload.edge_added_to[] — never a separate ledger event.
    const downstream = Array.isArray(payload.edge_added_to) ? payload.edge_added_to : [];
    for (const downstreamId of downstream) {
      if (typeof downstreamId !== "string" || !downstreamId.trim()) continue;
      addEdge(edgesByKey, {
        from_node_id: nodeId,
        to_node_id: downstreamId.trim(),
        edge_kind: "unblocks",
        weight: 1,
        source_event_id: event.event_id,
      });
    }
    return;
  }
}

function compareEdges(a, b) {
  if (a.from_node_id !== b.from_node_id) return a.from_node_id.localeCompare(b.from_node_id);
  if (a.to_node_id !== b.to_node_id) return a.to_node_id.localeCompare(b.to_node_id);
  if (a.edge_kind !== b.edge_kind) return a.edge_kind.localeCompare(b.edge_kind);
  const aSrc = a.source_event_id || "";
  const bSrc = b.source_event_id || "";
  return aSrc.localeCompare(bSrc);
}

function finalizeNode(node) {
  // Strip the internal _last_failure_reason from the persisted node — the
  // summary view (Do step 3) pulls it via a separate per-node failure lookup
  // so the raw nodes[] doesn't carry stale per-state debris that bloats the
  // hash. We do, however, fold it into the summary view via the same fold
  // pass; the materializer carries it forward in the in-memory map but
  // doesn't bake it into the canonical nodes[] entry.
  const out = {
    node_id: node.node_id,
    kind: node.kind,
    state: node.state,
    surface_refs: node.surface_refs.slice().sort(),
    contract_hash: node.contract_hash,
    severity_floor: node.severity_floor,
    priority: node.priority,
    ts_first: node.ts_first,
    ts_last: node.ts_last,
    source_events: node.source_events.slice().sort(),
  };
  // Depth tier: persist only a non-default depth tier (an E2 Tier-2 re-probe),
  // so the graph-scheduler projection can sort it after Tier-1 breadth. Omitted
  // for every Tier-1 node, keeping the canonical nodes[] hash byte-identical for
  // sessions with no depth re-probe.
  if (Number.isInteger(node.tier) && node.tier > 1) out.tier = node.tier;
  if (node._physical_resource_bundle != null) {
    out.physical_resource_bundle = node._physical_resource_bundle;
  }
  if (node._physical_resource_dispatch != null) {
    out.physical_resource_dispatch = node._physical_resource_dispatch;
  }
  return out;
}

function materializeTaskGraphEvents(domain, events, { now = new Date() } = {}) {
  if (!Array.isArray(events)) throw new Error("TaskGraph event fold input must be an array");
  for (const event of events) {
    if (!event || typeof event !== "object" || Array.isArray(event)
        || event.target_domain !== domain) {
      throw new Error("TaskGraph event fold input must contain events bound to target_domain");
    }
  }
  const eventCount = events.length;

  // Ledger-pressure refusal (Do step 5). Surfaced as a structured error
  // with the count + threshold so the caller can report it without parsing
  // the message body. The refusal happens BEFORE the fold so a degenerate
  // event log doesn't burn CPU.
  if (eventCount >= LEDGER_PRESSURE_REFUSE_THRESHOLD) {
    const err = new Error(
      `ledger_pressure_refusal: ${eventCount} events ≥ refuse threshold ${LEDGER_PRESSURE_REFUSE_THRESHOLD}; rotate the session or split before materializing`,
    );
    err.code = "ledger_pressure_refusal";
    err.details = {
      event_count: eventCount,
      refuse_threshold: LEDGER_PRESSURE_REFUSE_THRESHOLD,
      warn_threshold: LEDGER_PRESSURE_WARN_THRESHOLD,
      max_records: FRONTIER_EVENTS_MAX_RECORDS,
    };
    throw err;
  }

  const ledgerPressureWarning = eventCount >= LEDGER_PRESSURE_WARN_THRESHOLD
    ? {
      code: "graph_ledger_pressure",
      event_count: eventCount,
      warn_threshold: LEDGER_PRESSURE_WARN_THRESHOLD,
      refuse_threshold: LEDGER_PRESSURE_REFUSE_THRESHOLD,
      max_records: FRONTIER_EVENTS_MAX_RECORDS,
    }
    : null;

  const nodesById = new Map();
  const edgesByKey = new Map();
  for (const event of events) {
    foldEvent(event, { nodesById, edgesByKey });
  }

  const rawNodes = Array.from(nodesById.values());
  const nodes = rawNodes
    .map(finalizeNode)
    .sort(sortByTextField("node_id"));
  const edges = Array.from(edgesByKey.values()).sort(compareEdges);

  // Hashes: the per-element hashes (nodes_hash, edges_hash) are computed
  // over the sorted arrays so a deterministic event log yields the same
  // hash across re-materializations. graph_hash binds both plus the node
  // and edge counts so the X.9 graph-scheduler can compare a snapshot's
  // graph_hash against the live one without re-hashing each element.
  const nodesHash = hashCanonicalJson(nodes);
  const edgesHash = hashCanonicalJson(edges);
  const graphHash = hashCanonicalJson({
    nodes_hash: nodesHash,
    edges_hash: edgesHash,
    node_count: nodes.length,
    edge_count: edges.length,
  });

  const materializedAt = now instanceof Date ? now.toISOString() : new Date(now).toISOString();
  const document = {
    version: 1,
    target_domain: domain,
    materialized_at: materializedAt,
    source_event_count: eventCount,
    node_count: nodes.length,
    edge_count: edges.length,
    nodes,
    edges,
    hashes: {
      nodes_hash: nodesHash,
      edges_hash: edgesHash,
      graph_hash: graphHash,
    },
  };
  if (ledgerPressureWarning) {
    document.warnings = [ledgerPressureWarning];
  }

  return {
    document,
    nodesById,
    ledgerPressureWarning,
    eventCount,
  };
}

function materializeTaskGraphDocument(domain, { now = new Date() } = {}) {
  return materializeTaskGraphEvents(domain, readFrontierEvents(domain), { now });
}

function materializeTaskGraph(targetDomain, options = {}) {
  const domain = assertSafeDomain(targetDomain);
  const result = materializeTaskGraphDocument(domain, options);
  if (options.write) {
    withSessionLock(domain, () => {
      writeJsonDocument(taskGraphPath(domain), result.document);
    });
  }
  return result;
}

// Top-level summary view (Do step 3). Folds per-state counts + top-N ready
// nodes + open Hypotheses + recent finalizations + cross-stack Transitions
// + failure-reason summaries from the most recent node.transitioned → failed
// event per failed node. Per X-P9 the summary itself is summary-grade — IDs,
// counts, structured failure_reason payloads; no raw bodies.
const SUMMARY_TOP_N = 10;

function summarizeTaskGraph(targetDomain, options = {}) {
  const result = materializeTaskGraph(targetDomain, { ...options, write: false });
  const { document, nodesById } = result;
  const stateCounts = {};
  const kindCounts = {};
  const readyNodes = [];
  const openHypotheses = [];
  const recentFinalizations = [];
  const crossStackTransitions = [];
  const failedNodes = [];
  for (const rawNode of nodesById.values()) {
    stateCounts[rawNode.state] = (stateCounts[rawNode.state] || 0) + 1;
    kindCounts[rawNode.kind] = (kindCounts[rawNode.kind] || 0) + 1;
    if (rawNode.state === "ready") {
      readyNodes.push({
        node_id: rawNode.node_id,
        kind: rawNode.kind,
        priority: rawNode.priority,
        severity_floor: rawNode.severity_floor,
        surface_refs: rawNode.surface_refs.slice().sort(),
        ts_last: rawNode.ts_last,
      });
    }
    if (rawNode.kind === "hypothesis" && rawNode.state === "proposed") {
      openHypotheses.push({
        node_id: rawNode.node_id,
        surface_refs: rawNode.surface_refs.slice().sort(),
        ts_first: rawNode.ts_first,
      });
    }
    if (rawNode.state === "finalized") {
      recentFinalizations.push({
        node_id: rawNode.node_id,
        kind: rawNode.kind,
        severity_floor: rawNode.severity_floor,
        ts_last: rawNode.ts_last,
      });
    }
    if (rawNode.kind === "transition" && rawNode.surface_refs.length >= 2) {
      // Cross-stack only when the two surfaces are distinct; a self-loop is
      // not cross-stack. The materializer dedupes surface_refs on push, so
      // two distinct entries imply two endpoints.
      crossStackTransitions.push({
        node_id: rawNode.node_id,
        state: rawNode.state,
        surface_refs: rawNode.surface_refs.slice().sort(),
        ts_first: rawNode.ts_first,
      });
    }
    if (rawNode.state === "failed") {
      failedNodes.push({
        node_id: rawNode.node_id,
        kind: rawNode.kind,
        ts_last: rawNode.ts_last,
        // Per Do step 3: the most recent failure_reason from node.transitioned
        // → failed events surfaces in the summary. Already bounded at write
        // time by the X.6 mechanical verifier's structured failure shape
        // (X-P9). Carry it forward as-is so the summary stays one query away.
        failure_reason: rawNode._last_failure_reason || null,
      });
    }
  }

  // Stable orderings: by-priority then by-node_id for readyNodes; by
  // ts_first then node_id for openHypotheses; by ts_last desc then node_id
  // for recentFinalizations + failedNodes; by node_id for crossStackTransitions.
  const PRIORITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
  readyNodes.sort((a, b) => {
    const ra = PRIORITY_RANK[a.priority] == null ? 99 : PRIORITY_RANK[a.priority];
    const rb = PRIORITY_RANK[b.priority] == null ? 99 : PRIORITY_RANK[b.priority];
    if (ra !== rb) return ra - rb;
    return a.node_id.localeCompare(b.node_id);
  });
  openHypotheses.sort((a, b) => {
    if (a.ts_first !== b.ts_first) return a.ts_first.localeCompare(b.ts_first);
    return a.node_id.localeCompare(b.node_id);
  });
  recentFinalizations.sort((a, b) => {
    if (a.ts_last !== b.ts_last) return b.ts_last.localeCompare(a.ts_last);
    return a.node_id.localeCompare(b.node_id);
  });
  failedNodes.sort((a, b) => {
    if (a.ts_last !== b.ts_last) return b.ts_last.localeCompare(a.ts_last);
    return a.node_id.localeCompare(b.node_id);
  });
  crossStackTransitions.sort((a, b) => a.node_id.localeCompare(b.node_id));

  // Composition telemetry: how far the graph moved past flat surface
  // enumeration. A graph that never proposes a hypothesis or a transition has
  // composed === false (the failure mode this measures); the per-node rates
  // quantify the hypothesis and transition layers. Summary-only: derived from
  // the read-only counts, never written into the hash-bound graph document.
  const compositionSurfaces = kindCounts.surface || 0;
  const compositionHypotheses = kindCounts.hypothesis || 0;
  const compositionTransitions = kindCounts.transition || 0;
  const ratio = (numerator, denominator) => (denominator > 0
    ? Math.round((numerator / denominator) * 1000) / 1000
    : 0);
  const composition = {
    surfaces: compositionSurfaces,
    hypotheses: compositionHypotheses,
    transitions: compositionTransitions,
    claims: kindCounts.claim || 0,
    edges: document.edge_count,
    hypotheses_per_surface: ratio(compositionHypotheses, compositionSurfaces),
    transitions_per_hypothesis: ratio(compositionTransitions, compositionHypotheses),
    composed: compositionHypotheses > 0 || compositionTransitions > 0,
  };

  return {
    version: 1,
    target_domain: document.target_domain,
    materialized_at: document.materialized_at,
    source_event_count: document.source_event_count,
    node_count: document.node_count,
    edge_count: document.edge_count,
    hashes: document.hashes,
    state_counts: stateCounts,
    kind_counts: kindCounts,
    composition,
    ready_nodes: readyNodes.slice(0, SUMMARY_TOP_N),
    open_hypotheses: openHypotheses.slice(0, SUMMARY_TOP_N),
    recent_finalizations: recentFinalizations.slice(0, SUMMARY_TOP_N),
    cross_stack_transitions: crossStackTransitions.slice(0, SUMMARY_TOP_N),
    failed_nodes: failedNodes.slice(0, SUMMARY_TOP_N),
    warnings: document.warnings || [],
  };
}

// Filter-aware reader for the raw view. Filters are intentionally narrow
// (kind, state, node_id) so the X.5 capability-pack derivation can ask
// "all hypothesis nodes in state X" without re-implementing the materializer.
function readTaskGraph(targetDomain, options = {}) {
  const result = materializeTaskGraph(targetDomain, { ...options, write: false });
  const document = result.document;
  const filters = options.filters && typeof options.filters === "object" && !Array.isArray(options.filters)
    ? options.filters
    : {};
  let nodes = document.nodes.slice();
  if (typeof filters.kind === "string" && filters.kind.trim()) {
    const wantKind = filters.kind.trim();
    nodes = nodes.filter((node) => node.kind === wantKind);
  }
  if (typeof filters.state === "string" && filters.state.trim()) {
    const wantState = filters.state.trim();
    nodes = nodes.filter((node) => node.state === wantState);
  }
  if (typeof filters.node_id === "string" && filters.node_id.trim()) {
    const wantId = filters.node_id.trim();
    nodes = nodes.filter((node) => node.node_id === wantId);
  }
  return {
    ...document,
    nodes,
    node_count: nodes.length,
    // edges intentionally NOT filtered — they're cheap and the caller may
    // want adjacency around filtered nodes. The hashes still reference the
    // un-filtered canonical document so a downstream graph_hash comparison
    // is stable even if the reader filters.
  };
}

module.exports = {
  DEFAULT_NODE_PRIORITY,
  LEDGER_PRESSURE_REFUSE_THRESHOLD,
  LEDGER_PRESSURE_WARN_THRESHOLD,
  TASK_GRAPH_EDGE_KIND_VALUES,
  TASK_GRAPH_NODE_KIND_VALUES,
  cellNodeId,
  claimNodeId,
  hypothesisNodeId,
  materializeTaskGraph,
  materializeTaskGraphEvents,
  producerNodeId,
  readTaskGraph,
  summarizeTaskGraph,
  surfaceNodeId,
  transitionNodeId,
};
