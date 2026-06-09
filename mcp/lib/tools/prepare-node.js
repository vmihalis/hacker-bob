"use strict";

// Plane X Cycle X.8 — bob_prepare_node.
//
// The first call of the clou-style three-call protocol (X-D8). Reads the
// dispatched node from the materialized TaskGraph, derives its capability
// pack via X.5 (≤1-hop graph context per X-P5), renders the per-node brief
// via the X.8 `node` profile slice registry (X.8 Do step 1), mints a
// `prep_token` that binds the graph_context_hash so post-dispatch drift is
// detectable (X-R15 mitigation), and emits the
// `node.transitioned (contracted | ready) → dispatched` event with the token
// inlined in the payload.
//
// Per X-P9 the brief renderer inlines DISTILLED SUMMARIES of every artifact
// the Contract names — never raw bodies. The agent calls bob_resolve_body
// (X.7) to pull bodies on demand. The `recommended_reads` slice is the X.5
// `recommended_reads_for_node[]` output projected through the resolver
// registry's per-prefix summary (for http_record the matching
// http_record_observed event from the ledger; for repo_check the
// repo_check_observed; for other prefixes a {artifact_ref, ref_kind, hint}
// pointer the agent resolves via bob_resolve_body).
//
// Per X.8 Do step 5 the tests cover:
//   - refuse on state ∉ {contracted, ready}
//   - empty agent_output refused at finalize (tested via finalize)
//   - stale prep_token refused at finalize (tested via finalize)
//   - successful flow with relational_value_match Contract
//   - mechanical-fail flow surfaces structured failure_reason
//   - re-prepare after failed finalize → brief contains prior_attempt slice
//   - graph drift detection via differing graph_context_hash
//   - hypothesis visibility for Surface nodes
//   - recommended_reads inlines DISTILLED SUMMARIES not bodies
//
// Allowed bundles per X.8 Do step 3: orchestrator + graph-scheduler-only.
// The graph-scheduler bundle ships in X.9; v1 here is realized as
// `orchestrator` (the only bundle wired to the operator-facing slash
// command at this point in the plane). X.9 will extend role_bundles[]
// when the dedicated graph-scheduler bundle lands.

const crypto = require("crypto");
const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  assertSafeDomain,
} = require("../paths.js");
const {
  assertTaskGraphNodeId,
  appendNodeTransition,
  findAttachedContract,
  readHypothesisProposals,
  readNodeTransitions,
  readTransitionProposals,
} = require("../task-graph-events.js");
const {
  materializeTaskGraph,
} = require("../task-graph-materializer.js");
const {
  buildOneHopGraphContext,
  derivePackForNode,
} = require("../capability-pack-derivation.js");
const {
  familyTagForCapabilityPackId,
} = require("../capability-packs.js");
const {
  scheduleMaterialization,
} = require("../frontier-materialize-debounce.js");
const {
  readSurfaceRoutesStrict,
} = require("../surface-router.js");
const {
  isPlainObject,
} = require("../verification-contracts.js");
const {
  readFrontierEvents,
} = require("../frontier-events.js");
const {
  renderNodeBriefExtras,
} = require("../assignment-brief.js");
const {
  OPEN_SENTINEL,
  CLOSE_SENTINEL,
  ENVELOPE_NONCE_HEX_CHARS,
  escapeRegExp,
} = require("../untrusted-envelope.js");
const {
  TRANSITION_KIND_HUNTING_VOCAB,
  transitionKindBriefContent,
} = require("../technique-packs.js");

// X.8 Do step 1: only nodes in state contracted or ready may be prepared.
// `ready` is reserved for X.9's graph-scheduler — the X.4 attach path
// lands the node in `contracted`. Both states are dispatch-legal because
// the frozen state-transition table permits ready → dispatched as well;
// X.8 keeps both legal so the X.9 scheduler can dispatch without
// re-emitting an interim transition.
//
// Retry-with-recall workflow (X.8 spec line 338): when a prior attempt
// landed the node in `failed`, the operator re-contracts via
// bob_attach_contract (the failed → contracted re-contract path) which
// lands the node back in `contracted`. At that point prepare_node accepts
// it here; the prior failure events stay on the ledger so
// collectPriorAttempts surfaces them in the brief's `prior_attempt`
// slice automatically.
const PREPARE_NODE_LEGAL_STATES = Object.freeze(["contracted", "ready"]);

// Cap the adjacent-observations slice to the most recent N events whose
// surface_id overlaps the dispatched node's surfaces. Per X-P9 the SHAPE of
// each observation is summary-grade at emit-time; we do not re-cap per-event
// text, only the count. The cap defends against pathological session ledgers
// with thousands of identical observations; 32 is enough to land the
// 5 most-touched surface threads without blowing the brief budget.
const ADJACENT_OBSERVATIONS_CAP = 32;

// Cap the prior-attempt failures slice to the most recent K failure events
// for the dispatched node. The failure payload is structured (X.6 verifier
// output) so each entry is bounded; K=3 lets the brief expose the last
// three attempts' verdicts without overwhelming the agent.
const PRIOR_ATTEMPT_CAP = 3;

// Adjacent hypotheses cap. Inline up to N open Hypothesis nodes whose
// surface_refs[] overlaps the dispatched node's surfaces. 8 is generous
// enough to surface every adjacent hypothesis in a typical run and small
// enough to never dominate the brief.
const ADJACENT_HYPOTHESES_CAP = 8;

// Plane X Cycle X.11 — caps for the cross-stack composition slice.
//
// `ENDPOINT_OBSERVATIONS_PER_SURFACE_CAP`: when a Transition brief inlines
// both endpoints' summary-grade observations (per X.11 Do step 1), each
// endpoint surface gets at most this many observations. Per X-P9 each
// observation is already shape-bounded at emit, so the cap defends against
// pathological session ledgers (thousands of identical observations on one
// endpoint) without re-capping per-event text. 8 is enough to land the most
// recent observations per endpoint while keeping the slice well under the
// 8KB cross_stack_composition budget for the 50-observation X.11 test case.
const ENDPOINT_OBSERVATIONS_PER_SURFACE_CAP = 8;

// `ADJACENT_TRANSITIONS_CAP`: when a Surface brief inlines a one-line
// summary of each adjacent Transition (per X.11 Do step 2), cap the list
// at this many entries. A Surface with ≥1 adjacent Transition is the
// trigger (per spec); we surface up to 8 transitions per Surface to avoid
// dominating the brief on dense graphs.
const ADJACENT_TRANSITIONS_CAP = 8;

// Plane X Cycle X.10 — generic agent shell + family-tagged labels.
//
// SPAWN_SUBAGENT_TYPE is the Claude/Codex subagent name dispatched by
// bob_prepare_node. Per X-D6 the generic shell handles every TaskGraph
// node kind via the union of evaluator-family bundles; the agent's
// per-node constraint is the brief's allowed_tools_for_node[] not the
// frontmatter (an ergonomics trade per X-P7, mechanically enforced at
// finalize via the X.6 verifier's tool_constraint_violation check).
const SPAWN_SUBAGENT_TYPE = "evaluator-spawn";

// Derive the family tag for a derived capability pack: e.g.
// "smart_contract_evm" → "evm", "web" → "web". Returns null when the
// pack id has no mapped family. Surfaced inside the spawn description
// (e.g., evaluator-spawn[web|evm] for a web↔EVM transition) so operator
// status reads make the stack mix visible at a glance (X.10 Do step 4).
function computeFamilyTag(pack) {
  if (!pack || !pack.brief_emphasis) return null;
  const emphasis = pack.brief_emphasis;
  // Transition nodes carry `endpoint_capability_packs[]`; Surface nodes
  // carry a single `capability_pack`; Hypothesis nodes derive their packs
  // from the Contract's production_paths and surface them in
  // `capability_pack_ids[]`. Honor whichever shape is present.
  const packIds = new Set();
  if (Array.isArray(emphasis.endpoint_capability_packs)) {
    for (const id of emphasis.endpoint_capability_packs) {
      if (typeof id === "string" && id.length > 0) packIds.add(id);
    }
  }
  if (Array.isArray(emphasis.capability_pack_ids)) {
    for (const id of emphasis.capability_pack_ids) {
      if (typeof id === "string" && id.length > 0) packIds.add(id);
    }
  }
  if (typeof emphasis.capability_pack === "string" && emphasis.capability_pack.length > 0) {
    packIds.add(emphasis.capability_pack);
  }
  const tags = new Set();
  for (const packId of packIds) {
    const tag = familyTagForCapabilityPackId(packId);
    if (typeof tag === "string" && tag.length > 0) tags.add(tag);
  }
  if (tags.size === 0) return null;
  return Array.from(tags).sort().join("|");
}

// Render the family-tagged spawn description per X.10 Do step 4:
//   "execute node <id> — evaluator-spawn[<family-tag>]"
// The bracketed tag MAY be empty (omitted entirely) when the dispatched
// node has no resolved capability_pack — operator status surfaces should
// still render a stable label.
function renderSpawnDescription(nodeId, familyTag) {
  if (familyTag && familyTag.length > 0) {
    return `execute node ${nodeId} — ${SPAWN_SUBAGENT_TYPE}[${familyTag}]`;
  }
  return `execute node ${nodeId} — ${SPAWN_SUBAGENT_TYPE}`;
}

function structuredError(code, message, details) {
  const err = new Error(`${code}: ${message}`);
  err.code = code;
  if (details) err.details = details;
  return err;
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizeUntrustedEnvelopeNoncesForHash(value) {
  const noncePattern = `[0-9a-f]{${ENVELOPE_NONCE_HEX_CHARS}}`;
  return String(value)
    .replace(new RegExp(`${escapeRegExp(OPEN_SENTINEL)} nonce=${noncePattern}`, "g"), `${OPEN_SENTINEL} nonce=<nonce>`)
    .replace(new RegExp(`${escapeRegExp(CLOSE_SENTINEL)} nonce=${noncePattern}`, "g"), `${CLOSE_SENTINEL} nonce=<nonce>`);
}

function safeSurfaceRouteMap(targetDomain) {
  let result;
  try {
    result = readSurfaceRoutesStrict(targetDomain);
  } catch {
    return {};
  }
  const map = {};
  const doc = result && result.document;
  if (!doc || !Array.isArray(doc.routes)) return map;
  for (const route of doc.routes) {
    if (!route || typeof route !== "object") continue;
    const surfaceId = typeof route.surface_id === "string" ? route.surface_id : null;
    if (!surfaceId) continue;
    map[surfaceId] = {
      id: surfaceId,
      surface_type: route.surface_type || null,
      chain_family: route.chain_family || null,
      capability_pack: route.capability_pack || null,
      brief_profile: route.brief_profile || null,
    };
  }
  return map;
}

// Build the ≤1-hop snapshot the X.5 pack derivation expects. Reads the
// materialized graph, walks edges incident to the dispatched node, and
// trims surface metadata to only the surfaces the dispatched + adjacent
// nodes touch (X-P5 bound).
function snapshotOneHopGraphContext({ document, nodeId, surfaceMetadataById }) {
  return buildOneHopGraphContext(document, nodeId, surfaceMetadataById);
}

// graph_context_hash binds the snapshot the agent's reasoning is grounded
// in. The hash is computed over a stable projection (node_ids, kinds,
// states, edges by (from, to, kind), surface_ids in the metadata) so a
// re-prepare after the same materialization produces the same hash.
function computeGraphContextHash(graphContext) {
  if (!isPlainObject(graphContext)) return null;
  const dispatched = graphContext.dispatched_node;
  const projection = {
    dispatched_node: dispatched
      ? {
        node_id: dispatched.node_id,
        kind: dispatched.kind,
        state: dispatched.state,
        contract_hash: dispatched.contract_hash || null,
        surface_refs: Array.isArray(dispatched.surface_refs)
          ? dispatched.surface_refs.slice().sort()
          : [],
      }
      : null,
    adjacent_nodes: (graphContext.adjacent_nodes || []).map((node) => ({
      node_id: node.node_id,
      kind: node.kind,
      state: node.state,
      surface_refs: Array.isArray(node.surface_refs)
        ? node.surface_refs.slice().sort()
        : [],
    })),
    incident_edges: (graphContext.incident_edges || []).map((edge) => ({
      from_node_id: edge.from_node_id,
      to_node_id: edge.to_node_id,
      edge_kind: edge.edge_kind,
    })),
    surface_metadata_keys: Object.keys(graphContext.surface_metadata_by_id || {}).sort(),
  };
  return sha256Hex(JSON.stringify(projection));
}

function findNodeInDocument(document, nodeId) {
  if (!document || !Array.isArray(document.nodes)) return null;
  for (const node of document.nodes) {
    if (node && node.node_id === nodeId) return node;
  }
  return null;
}

// Collect prior failed transitions for a node (Do step 1 prior_attempt
// slice). Returns the most recent PRIOR_ATTEMPT_CAP entries in
// reverse-chronological order (most-recent-first) so the brief renderer
// can lead with the latest failure.
function collectPriorAttempts(targetDomain, nodeId) {
  const events = readNodeTransitions(targetDomain);
  const failed = [];
  for (const event of events) {
    if (!event || !event.payload) continue;
    if (event.payload.node_id !== nodeId) continue;
    if (event.payload.to_state !== "failed") continue;
    failed.push({
      event_id: event.event_id,
      ts: event.ts,
      from_state: event.payload.from_state,
      failure_reason: event.payload.failure_reason || null,
      verification: event.payload.verification || null,
      prep_token: event.payload.prep_token_hash || null,
    });
  }
  failed.sort((a, b) => (b.ts || "").localeCompare(a.ts || ""));
  return failed.slice(0, PRIOR_ATTEMPT_CAP);
}

// Collect adjacent observations: observation.recorded events whose
// surface_id matches one of the dispatched node's surface_refs. Capped at
// ADJACENT_OBSERVATIONS_CAP (per X-P9 the SHAPE of each event is summary-
// grade; the cap defends against pathological session ledgers).
function collectAdjacentObservations(targetDomain, dispatchedNode) {
  if (!dispatchedNode) return [];
  const surfaces = Array.isArray(dispatchedNode.surface_refs)
    ? new Set(dispatchedNode.surface_refs.filter((s) => typeof s === "string"))
    : new Set();
  if (surfaces.size === 0) return [];
  const events = readFrontierEvents(targetDomain);
  const matched = [];
  for (const event of events) {
    if (!event || event.kind !== "observation.recorded") continue;
    const surfaceId = event.surface_id
      || (event.payload && typeof event.payload.surface_id === "string" ? event.payload.surface_id : null);
    if (surfaceId && surfaces.has(surfaceId)) {
      matched.push({
        event_id: event.event_id,
        ts: event.ts,
        surface_id: surfaceId,
        payload: event.payload || {},
      });
    }
  }
  // Most-recent-first so the brief leads with the latest observation.
  matched.sort((a, b) => (b.ts || "").localeCompare(a.ts || ""));
  return matched.slice(0, ADJACENT_OBSERVATIONS_CAP);
}

// Collect open Hypothesis nodes (state: proposed) whose surface_refs[]
// overlap the dispatched node's surface_refs[] OR adjacent-surface ids.
// Per the spec this slice is conditional: emitted for Surface AND
// Transition nodes (X.8 Do step 1) so the cross-stack composition (X.11)
// can pick it up. Hypothesis nodes themselves don't surface adjacent
// hypotheses (they ARE hypotheses; the brief renders the node's own
// statement separately via the contract slice).
function collectAdjacentHypotheses(document, dispatchedNode) {
  if (!dispatchedNode) return [];
  if (dispatchedNode.kind !== "surface" && dispatchedNode.kind !== "transition") return [];
  const wantSurfaces = new Set();
  if (Array.isArray(dispatchedNode.surface_refs)) {
    for (const ref of dispatchedNode.surface_refs) {
      if (typeof ref === "string") wantSurfaces.add(ref);
    }
  }
  // Also include adjacent surfaces via the document's edges.
  if (document && Array.isArray(document.edges)) {
    for (const edge of document.edges) {
      if (!edge) continue;
      if (edge.from_node_id === dispatchedNode.node_id) {
        const adj = findNodeInDocument(document, edge.to_node_id);
        if (adj && Array.isArray(adj.surface_refs)) {
          for (const ref of adj.surface_refs) {
            if (typeof ref === "string") wantSurfaces.add(ref);
          }
        }
      }
      if (edge.to_node_id === dispatchedNode.node_id) {
        const adj = findNodeInDocument(document, edge.from_node_id);
        if (adj && Array.isArray(adj.surface_refs)) {
          for (const ref of adj.surface_refs) {
            if (typeof ref === "string") wantSurfaces.add(ref);
          }
        }
      }
    }
  }
  if (wantSurfaces.size === 0) return [];
  const hypotheses = [];
  if (document && Array.isArray(document.nodes)) {
    for (const node of document.nodes) {
      if (!node || node.kind !== "hypothesis") continue;
      if (node.state !== "proposed") continue;
      const surfaceRefs = Array.isArray(node.surface_refs) ? node.surface_refs : [];
      const overlaps = surfaceRefs.some((ref) => wantSurfaces.has(ref));
      if (overlaps) hypotheses.push(node);
    }
  }
  // Look up the hypothesis_statement from the proposal events so the brief
  // can show the conjecture text — the materializer doesn't carry it.
  const proposalByNodeId = new Map();
  for (const proposal of readHypothesisProposals(getDomainFromDocument(document))) {
    const proposalId = proposal.payload && typeof proposal.payload.proposal_id === "string"
      ? proposal.payload.proposal_id
      : null;
    if (!proposalId) continue;
    proposalByNodeId.set(`TG-H-${proposalId}`, proposal);
  }
  const out = [];
  for (const node of hypotheses) {
    const proposal = proposalByNodeId.get(node.node_id);
    const statement = proposal && proposal.payload && typeof proposal.payload.hypothesis_statement === "string"
      ? proposal.payload.hypothesis_statement
      : null;
    out.push({
      node_id: node.node_id,
      surface_refs: node.surface_refs.slice().sort(),
      hypothesis_statement: statement,
    });
    if (out.length >= ADJACENT_HYPOTHESES_CAP) break;
  }
  return out;
}

// Pull the target_domain off a materialized document. Documents always
// carry it; defensive default so a malformed test fixture doesn't crash.
function getDomainFromDocument(document) {
  return document && typeof document.target_domain === "string" ? document.target_domain : null;
}

// Resolve the distilled summary for a given artifact_ref. The summary is
// the SHAPE-bounded brief-inlinable form. For prefixes that emit an
// observation.recorded summary event at write-time (http_record_observed,
// repo_check_observed, etc.) we look up the matching event by ref_id and
// return its payload. For prefixes without a paired summary event
// (finding, evidence_pack, frontier_event, evm_call) we return a typed
// pointer the agent resolves via bob_resolve_body. Per X-P9 the brief
// renderer NEVER inlines a body — bodies are pull-only.
function resolveRecommendedReadSummary(targetDomain, artifactRef, ledgerEvents) {
  if (typeof artifactRef !== "string" || !artifactRef.includes(":")) {
    return { artifact_ref: artifactRef, kind: null, summary: null };
  }
  const idx = artifactRef.indexOf(":");
  const prefix = artifactRef.slice(0, idx);
  const refId = artifactRef.slice(idx + 1);
  // For http_record_observed-style summaries, scan the cached ledger
  // events for the matching payload. The caller passes ledgerEvents to
  // avoid re-reading the JSONL once per ref.
  if (prefix === "http_record") {
    for (const event of ledgerEvents) {
      if (event.kind !== "observation.recorded") continue;
      if (!event.payload) continue;
      if (event.payload.observation_kind !== "http_record_observed") continue;
      if (event.payload.request_id !== refId) continue;
      return {
        artifact_ref: artifactRef,
        kind: "http_record_observed",
        summary: event.payload,
      };
    }
    return {
      artifact_ref: artifactRef,
      kind: "http_record",
      summary: { request_id: refId, hint: "call bob_resolve_body(http_record:<request_id>) for the body" },
    };
  }
  // Other prefixes: typed pointer with a hint. The agent calls
  // bob_resolve_body to pull the body. We do not inline anything else.
  return {
    artifact_ref: artifactRef,
    kind: prefix,
    summary: { ref_id: refId, hint: `call bob_resolve_body(${artifactRef}) for the body` },
  };
}

// ─── Plane X Cycle X.11 — cross-stack composition helpers ──────────────
//
// X.11 spec Do step 1: when the dispatched node is a Transition, the brief
// surfaces a focused "cross-stack composition" slice that names:
//   - both endpoint surfaces' summary-grade observations (per X-P9 these
//     are already distilled at emit; the helper below picks up to
//     ENDPOINT_OBSERVATIONS_PER_SURFACE_CAP per endpoint)
//   - the transition_kind (one of the X-D3 closed enum)
//   - the trust_assumption prose (capped at 512 chars per X-P9 at append)
//   - per-kind hunting vocabulary from `web3_identity_handoff` — surfaced
//     via `transitionKindBriefContent(kind).hunting_vocab`
//   - a worked Contract template carrying a complete relational_value_match
//     predicate skeleton the agent fills in — surfaced via
//     `transitionKindBriefContent(kind).contract_template`
//   - the endpoint_capability_packs[] union (already on pack.brief_emphasis)
//     so the agent reads both stack families in the same slice
//
// X.11 spec Do step 2: when the dispatched node is a Surface AND has ≥1
// adjacent Transition, the brief surfaces a one-line summary of each
// adjacent transition (node_id, transition_kind, trust_assumption, the
// other endpoint surface). The adjacent_hypotheses slice from X.8 stays
// where it is — this slice is purely about adjacent Transitions.

// Look up the transition proposal payload for a Transition node id. The
// materializer doesn't carry transition_kind or trust_assumption on the
// materialized node (it stays on the proposal event per X-D1); we pull
// the payload here so the brief can surface them. Returns null when the
// node id doesn't match any transition proposal (e.g., a synthetic node
// emitted via raw node.transitioned without a proposal).
function findTransitionProposal(targetDomain, nodeId) {
  const proposals = readTransitionProposals(targetDomain);
  for (const event of proposals) {
    const payload = event.payload || {};
    const proposalId = typeof payload.proposal_id === "string" ? payload.proposal_id : null;
    // Materializer derives node id as `TG-T-<proposal_id>` (or
    // `TG-T-<event_id>` when proposal_id is absent). Try both.
    const derivedById = proposalId ? `TG-T-${proposalId}` : null;
    const derivedByEvent = `TG-T-${event.event_id}`;
    if (derivedById === nodeId || derivedByEvent === nodeId) {
      return {
        transition_kind: typeof payload.transition_kind === "string" ? payload.transition_kind : null,
        trust_assumption: typeof payload.trust_assumption === "string" ? payload.trust_assumption : null,
        from_surface: typeof payload.from_surface === "string" ? payload.from_surface : null,
        to_surface: typeof payload.to_surface === "string" ? payload.to_surface : null,
        proposal_id: proposalId,
        event_id: event.event_id,
      };
    }
  }
  return null;
}

// Collect summary-grade observations for a single surface_id. Reuses the
// adjacent-observations pattern but scopes to ONE surface (so a Transition
// brief can show endpoint A's observations and endpoint B's observations
// as separate buckets — the cross-stack readability advantage X.11
// foregrounds). Returns up to ENDPOINT_OBSERVATIONS_PER_SURFACE_CAP most-
// recent observation.recorded events whose surface_id matches.
function collectObservationsForSurface(events, surfaceId) {
  if (typeof surfaceId !== "string" || !surfaceId.length) return [];
  const matched = [];
  for (const event of events) {
    if (!event || event.kind !== "observation.recorded") continue;
    const sid = event.surface_id
      || (event.payload && typeof event.payload.surface_id === "string" ? event.payload.surface_id : null);
    if (sid && sid === surfaceId) {
      matched.push({
        event_id: event.event_id,
        ts: event.ts,
        surface_id: surfaceId,
        payload: event.payload || {},
      });
    }
  }
  matched.sort((a, b) => (b.ts || "").localeCompare(a.ts || ""));
  return matched.slice(0, ENDPOINT_OBSERVATIONS_PER_SURFACE_CAP);
}

// Collect adjacent Transition nodes for a Surface node. Walks the document's
// edges and picks Transition nodes (kind === "transition") incident to the
// dispatched Surface node. For each adjacent Transition, the proposal event
// gives us the transition_kind + trust_assumption + the OTHER endpoint
// surface id. Capped at ADJACENT_TRANSITIONS_CAP.
function collectAdjacentTransitions(targetDomain, document, dispatchedNode) {
  if (!dispatchedNode || dispatchedNode.kind !== "surface") return [];
  if (!document || !Array.isArray(document.edges) || !Array.isArray(document.nodes)) return [];
  const transitionsByNodeId = new Map();
  for (const node of document.nodes) {
    if (node && node.kind === "transition") {
      transitionsByNodeId.set(node.node_id, node);
    }
  }
  const wantSurfaces = new Set(
    Array.isArray(dispatchedNode.surface_refs) ? dispatchedNode.surface_refs : [],
  );
  const adjacentTransitionIds = new Set();
  for (const edge of document.edges) {
    if (!edge) continue;
    if (edge.from_node_id === dispatchedNode.node_id && transitionsByNodeId.has(edge.to_node_id)) {
      adjacentTransitionIds.add(edge.to_node_id);
    } else if (edge.to_node_id === dispatchedNode.node_id && transitionsByNodeId.has(edge.from_node_id)) {
      adjacentTransitionIds.add(edge.from_node_id);
    }
  }
  if (adjacentTransitionIds.size === 0) return [];
  // Build the one-line summaries. For each adjacent Transition, look up its
  // proposal payload to read transition_kind + trust_assumption, and pick
  // the endpoint surface that ISN'T the dispatched Surface.
  const out = [];
  for (const transitionNodeId of adjacentTransitionIds) {
    const transitionNode = transitionsByNodeId.get(transitionNodeId);
    if (!transitionNode) continue;
    const proposal = findTransitionProposal(targetDomain, transitionNodeId);
    const transitionKind = proposal ? proposal.transition_kind : null;
    const trustAssumption = proposal ? proposal.trust_assumption : null;
    const surfaceRefs = Array.isArray(transitionNode.surface_refs)
      ? transitionNode.surface_refs
      : [];
    const otherEndpointSurface = surfaceRefs.find((ref) => !wantSurfaces.has(ref)) || null;
    out.push({
      node_id: transitionNodeId,
      state: transitionNode.state,
      transition_kind: transitionKind,
      trust_assumption: trustAssumption,
      other_endpoint_surface: otherEndpointSurface,
      surface_refs: surfaceRefs.slice().sort(),
    });
    if (out.length >= ADJACENT_TRANSITIONS_CAP) break;
  }
  // Stable ordering: most recently transitioned first via the node's
  // ts_last; ties broken by node_id for determinism.
  out.sort((a, b) => a.node_id.localeCompare(b.node_id));
  return out;
}

// Build the cross_stack_composition slice for a Transition node. Per X.11
// Do step 1 this is the Nike-fix-shaped slice: transition_kind + per-kind
// hunting vocab + worked Contract template + both endpoints' tools +
// both endpoints' summary-grade observations. Returns null when the node
// is not a Transition.
function buildCrossStackCompositionForTransition({
  targetDomain,
  dispatchedNode,
  pack,
  ledgerEvents,
}) {
  if (!dispatchedNode || dispatchedNode.kind !== "transition") return null;
  const proposal = findTransitionProposal(targetDomain, dispatchedNode.node_id);
  const transitionKind = proposal ? proposal.transition_kind : null;
  const trustAssumption = proposal ? proposal.trust_assumption : null;
  const fromSurface = proposal ? proposal.from_surface : (dispatchedNode.surface_refs || [])[0] || null;
  const toSurface = proposal ? proposal.to_surface : (dispatchedNode.surface_refs || [])[1] || null;

  // Pull per-kind hunting vocab + worked Contract template. When the
  // transition_kind is unknown (synthetic / out-of-enum), surface a null
  // hunting_vocab + null contract_template; the slice still inlines the
  // endpoint observations + endpoint tools so the agent has cross-stack
  // visibility even without the per-kind narrative.
  const briefContent = transitionKindBriefContent(transitionKind);

  const endpointCapabilityPacks = pack && pack.brief_emphasis
    && Array.isArray(pack.brief_emphasis.endpoint_capability_packs)
    ? pack.brief_emphasis.endpoint_capability_packs.slice()
    : [];

  // Both endpoints' summary-grade observations. Per X-P9 each event is
  // already shape-bounded; the cap is per-surface (not per-event-text).
  const fromObservations = collectObservationsForSurface(ledgerEvents, fromSurface);
  const toObservations = collectObservationsForSurface(ledgerEvents, toSurface);

  return {
    transition_kind: transitionKind,
    trust_assumption: trustAssumption,
    endpoint_surfaces: {
      from: fromSurface,
      to: toSurface,
    },
    endpoint_capability_packs: endpointCapabilityPacks,
    hunting_vocab: briefContent ? briefContent.hunting_vocab : null,
    contract_template: briefContent ? briefContent.contract_template : null,
    // Tools-from-both-endpoint-families per X.11 spec Do step 1. The
    // pack's allowed_tools_for_node[] already carries the UNION of both
    // endpoints' tools (deriveTransitionPack in X.5 unions them); the
    // brief's `allowed_tools_for_node` slice will show the canonical
    // constraint. This slice highlights that the constraint covers both
    // endpoint families so the agent reads the cross-stack signal here.
    cross_stack_tools_discipline: "Your allowed_tools_for_node[] carries the UNION of both endpoint families' evaluator-callable tools per X.5 deriveTransitionPack. Exercise BOTH stacks to capture the cross-artifact evidence the relational_value_match witness compares.",
    endpoint_observations: {
      [fromSurface || "_from"]: {
        surface_id: fromSurface,
        events: fromObservations,
        count: fromObservations.length,
        cap: ENDPOINT_OBSERVATIONS_PER_SURFACE_CAP,
      },
      [toSurface || "_to"]: {
        surface_id: toSurface,
        events: toObservations,
        count: toObservations.length,
        cap: ENDPOINT_OBSERVATIONS_PER_SURFACE_CAP,
      },
    },
    discipline: "X.11 cross-stack brief composition: the transition_kind + hunting_vocab + contract_template together encode the Nike-fix invariant — an off-chain identity / value / state must bind to its on-chain counterpart. Use the contract_template as the predicate skeleton; replace the placeholder artifact_refs (e.g. http_record:<auth_token_response>, evm_call:<verify_signature>) with the real refs from your dispatched observations BEFORE re-attaching a refined Contract.",
    transition_kinds_documented: Object.keys(TRANSITION_KIND_HUNTING_VOCAB).slice(),
  };
}

// Build the cross_stack_composition slice for a Surface node with ≥1
// adjacent Transition. Per X.11 Do step 2 this slice inlines a one-line
// summary of each adjacent Transition so the Surface evaluator can see
// the cross-stack handoffs that touch their surface. Returns null when
// the Surface has no adjacent Transitions (the slice key gets dropped
// by renderNodeBriefExtras).
function buildCrossStackCompositionForSurface({
  targetDomain,
  document,
  dispatchedNode,
}) {
  if (!dispatchedNode || dispatchedNode.kind !== "surface") return null;
  const adjacentTransitions = collectAdjacentTransitions(targetDomain, document, dispatchedNode);
  if (adjacentTransitions.length === 0) return null;
  return {
    surface_id: (dispatchedNode.surface_refs || [])[0] || null,
    adjacent_transitions: adjacentTransitions,
    count: adjacentTransitions.length,
    cap: ADJACENT_TRANSITIONS_CAP,
    discipline: "X.11 cross-stack visibility for Surface nodes: each adjacent_transition names a handoff that touches your surface. If your evaluation surfaces evidence that strengthens or contradicts a transition's trust_assumption, refine the Transition's Contract via bob_attach_contract and propose dispatch via the graph-scheduler.",
  };
}

// Build the brief context bag the NODE_BRIEF_SLICE_REGISTRY consumes.
function buildBriefContext({
  targetDomain,
  document,
  dispatchedNode,
  contract,
  pack,
  graphContext,
  graphContextHash,
  familyTag,
  spawnDescription,
}) {
  const surfaces = Array.isArray(dispatchedNode.surface_refs)
    ? dispatchedNode.surface_refs.slice().sort()
    : [];

  const governance = {
    target_domain: targetDomain,
    plane: "X",
    cycle: "X.8",
    discipline: [
      "X-P1: TaskGraph is the dispatch authority for Transition + Hypothesis nodes.",
      "X-P2: Every node carries a Contract before dispatch.",
      "X-P3: Mechanical verifier runs FIRST; LLM adjudication runs ONLY if mechanical passes.",
      "X-P7: evaluator-spawn shell is an ergonomics trade — preventive control is replaced with the X.6 verifier's detective check on agent_output.tool_invocations[].",
      "X-P9: Brief renderers inline DISTILLED SUMMARIES. Bodies are pull-only via bob_resolve_body.",
    ],
  };

  const nodeContext = {
    node_id: dispatchedNode.node_id,
    kind: dispatchedNode.kind,
    state: dispatchedNode.state,
    surface_refs: surfaces,
    contract_hash: dispatchedNode.contract_hash || null,
    severity_floor: contract ? contract.severity_floor : (dispatchedNode.severity_floor || null),
    priority: dispatchedNode.priority || null,
    graph_context_hash: graphContextHash,
    materialized_at: document.materialized_at,
    ts_first: dispatchedNode.ts_first,
    ts_last: dispatchedNode.ts_last,
    // Plane X Cycle X.10 — family-tagged spawn label. Surfaces the union
    // of endpoint capability_pack chain families (e.g., "web|evm" for a
    // web↔EVM transition) so operator status reads make the stack mix
    // visible. The orchestrator MUST spawn the generic shell with
    // `subagent_type: "evaluator-spawn"` and a description matching the
    // `spawn_description` field below.
    family_tag: familyTag,
    spawn_subagent_type: SPAWN_SUBAGENT_TYPE,
    spawn_description: spawnDescription,
  };

  // Inline the full Contract — already distilled per X-D4 + X-P9.
  const contractSlice = contract ? {
    contract_id: contract.contract_id,
    contract_hash: contract.contract_hash,
    severity_floor: contract.severity_floor,
    invariants: contract.invariants,
    witnesses: contract.witnesses,
    production_paths: contract.production_paths,
  } : null;

  const allowedToolsForNode = {
    // X.10 Do step 2 + step 5: the brief carries the honest X-P7 framing,
    // and bob_finalize_node emits failure_reason.reason
    // "tool_constraint_violation" when agent_output.tool_invocations[]
    // names a tool outside this set. The shell carries the UNION of
    // evaluator-family tools at frontmatter time (ergonomics trade); the
    // per-spawn constraint is enforced detectively at finalize.
    constraint: "The mechanical verifier (X.6) records a tool_constraint_violation when a tool outside this set is invoked. bob_finalize_node WILL emit node.transitioned executed → failed with failure_reason.reason=\"tool_constraint_violation\" if agent_output.tool_invocations[] names any tool outside allowed_tools. The evaluator-spawn shell carries the union of evaluator-family tools at frontmatter time (X-P7 ergonomics trade); your per-spawn constraint is this allowed_tools[] array.",
    allowed_tools: pack.allowed_tools_for_node.slice().sort(),
    positive_example: pack.allowed_tools_for_node.length > 0
      ? `INVOKE: ${pack.allowed_tools_for_node[0]}`
      : "INVOKE: <see allowed_tools>",
    negative_example: "REFUSED: any tool not in allowed_tools (e.g., bob_init_session — orchestrator-only) → finalize emits tool_constraint_violation.",
  };

  // recommended_reads slice: pull the distilled summary for each artifact_ref
  // in the pack's recommended_reads_for_node[]. Per X-P9 we inline SUMMARIES
  // not BODIES. The agent calls bob_resolve_body if they need the body.
  const ledgerEvents = readFrontierEvents(targetDomain);
  const recommendedReadsEntries = (pack.recommended_reads_for_node || []).map(
    (ref) => resolveRecommendedReadSummary(targetDomain, ref, ledgerEvents),
  );
  const recommendedReads = {
    refs: recommendedReadsEntries,
    discipline: "Each entry is a DISTILLED SUMMARY per X-P9. Call bob_resolve_body(<artifact_ref>) for the full body.",
    count: recommendedReadsEntries.length,
  };

  const adjacentObservationsList = collectAdjacentObservations(targetDomain, dispatchedNode);
  const adjacentObservations = {
    events: adjacentObservationsList,
    discipline: "Each event is already summary-grade per X-P9 (Plane T/O emit discipline). No top-N cap on per-event text.",
    count: adjacentObservationsList.length,
    cap: ADJACENT_OBSERVATIONS_CAP,
  };

  // Plane X Cycle X.11 — cross-stack brief composition (the Nike fix).
  // For Transition nodes: surface both endpoints' summary-grade
  // observations + per-kind hunting vocab + worked Contract template +
  // both endpoints' tools (via endpoint_capability_packs). For Surface
  // nodes with ≥1 adjacent Transition: surface a one-line summary of
  // each adjacent transition. Returns null for all other shapes; the
  // renderNodeBriefExtras helper drops the empty slice key per T-R1.
  let crossStackComposition = "";
  if (dispatchedNode.kind === "transition") {
    const transitionComposition = buildCrossStackCompositionForTransition({
      targetDomain,
      dispatchedNode,
      pack,
      ledgerEvents,
    });
    if (transitionComposition) {
      crossStackComposition = transitionComposition;
    }
  } else if (dispatchedNode.kind === "surface") {
    const surfaceComposition = buildCrossStackCompositionForSurface({
      targetDomain,
      document,
      dispatchedNode,
    });
    if (surfaceComposition) {
      crossStackComposition = surfaceComposition;
    }
  }

  const priorAttemptsList = collectPriorAttempts(targetDomain, dispatchedNode.node_id);
  const priorAttempt = priorAttemptsList.length > 0
    ? {
      attempts: priorAttemptsList,
      discipline: "Most recent failures listed first. The structured failure_reason carries witness ids, extracted values (for relational_value_match), and the failing predicate refs. Use this to refine the Contract or the production path.",
      count: priorAttemptsList.length,
      cap: PRIOR_ATTEMPT_CAP,
    }
    : "";

  const adjacentHypothesesList = collectAdjacentHypotheses(document, dispatchedNode);
  const adjacentHypotheses = adjacentHypothesesList.length > 0
    ? {
      hypotheses: adjacentHypothesesList,
      discipline: "If you find evidence touching one of these hypotheses, refine its Contract via bob_attach_contract and propose the next dispatch.",
      count: adjacentHypothesesList.length,
      cap: ADJACENT_HYPOTHESES_CAP,
    }
    : "";

  const recapAndHandoff = {
    next_steps: [
      "Execute the production_paths in the Contract against the dispatched node.",
      "Capture evidence via the appropriate evidence-emitting tools.",
      "Return your agent_output as a structured object; the finalize-node call runs the mechanical verifier first, then queues adjudication only if it passes.",
    ],
    contract_hash: contract ? contract.contract_hash : null,
    graph_context_hash: graphContextHash,
    drift_check: "Call bob_read_task_graph mid-run; if the live graph_context_hash differs from this brief's, re-prepare before continuing.",
    // Plane X Cycle X.10 — spawn directive. Orchestrator dispatches the
    // generic evaluator-spawn shell with this exact subagent_type and
    // description; the family_tag makes the stack mix visible at a
    // glance in operator status reads.
    spawn_directive: {
      subagent_type: SPAWN_SUBAGENT_TYPE,
      description: spawnDescription,
      family_tag: familyTag,
      framing: "X-P7 ergonomics trade: this shell carries the union of evaluator-family tools at frontmatter time. The per-spawn constraint is the brief's allowed_tools_for_node[] (enforced detectively at finalize via the X.6 tool_constraint_violation check).",
    },
  };

  return {
    governance,
    nodeContext,
    contract: contractSlice,
    crossStackComposition,
    allowedToolsForNode,
    recommendedReads,
    adjacentObservations,
    priorAttempt,
    adjacentHypotheses,
    recapAndHandoff,
  };
}

function handler(args) {
  const input = args || {};
  const domain = assertSafeDomain(
    assertNonEmptyString(input.target_domain, "target_domain"),
  );
  const nodeId = assertTaskGraphNodeId(input.node_id, "node_id");

  const result = materializeTaskGraph(domain, { write: false });
  const document = result.document;
  const dispatchedNode = findNodeInDocument(document, nodeId);
  if (!dispatchedNode) {
    throw structuredError(
      "unknown_node",
      `node ${nodeId} is not present in the materialized task-graph`,
      { node_id: nodeId },
    );
  }
  if (!PREPARE_NODE_LEGAL_STATES.includes(dispatchedNode.state)) {
    throw structuredError(
      "node_not_dispatch_ready",
      `node ${nodeId} is in state "${dispatchedNode.state}"; prepare-node requires one of ${PREPARE_NODE_LEGAL_STATES.join(", ")}`,
      {
        node_id: nodeId,
        current_state: dispatchedNode.state,
        legal_states: PREPARE_NODE_LEGAL_STATES.slice(),
      },
    );
  }

  // Recover the Contract. The materializer carries the contract_hash on
  // the node; the full content lives on the proposed → contracted
  // node.transitioned event payload (X.4 + X.8 appendContract extension).
  const attached = findAttachedContract(domain, nodeId);
  if (!attached || !attached.contract) {
    throw structuredError(
      "contract_not_attached",
      `node ${nodeId} has no attached Contract; call bob_attach_contract first`,
      { node_id: nodeId, contract_hash: dispatchedNode.contract_hash || null },
    );
  }

  // Build the ≤1-hop graph context and derive the per-node pack.
  const surfaceMetadataById = safeSurfaceRouteMap(domain);
  const graphContext = snapshotOneHopGraphContext({
    document,
    nodeId,
    surfaceMetadataById,
  });
  const graphContextHash = computeGraphContextHash(graphContext);
  const pack = derivePackForNode(
    dispatchedNode,
    graphContext,
    [], // observation_history — adjacent observations folded in the brief context separately
    attached.contract,
  );

  // Plane X Cycle X.10 — family-tagged spawn label. Derives from the
  // pack's brief_emphasis (endpoint packs for transitions, single pack
  // for surfaces, Contract-derived packs for hypotheses); UNKNOWN packs
  // resolve to a null tag so the rendered description omits the
  // brackets rather than emitting "evaluator-spawn[]".
  const familyTag = computeFamilyTag(pack);
  const spawnDescription = renderSpawnDescription(nodeId, familyTag);

  // Assemble the brief.
  const briefContext = buildBriefContext({
    targetDomain: domain,
    document,
    dispatchedNode,
    contract: attached.contract,
    pack,
    graphContext,
    graphContextHash,
    familyTag,
    spawnDescription,
  });
  const briefExtras = renderNodeBriefExtras(briefContext);
  const brief = {
    version: 1,
    profile: "node",
    target_domain: domain,
    node_id: nodeId,
    materialized_at: document.materialized_at,
    graph_context_hash: graphContextHash,
    ...briefExtras,
  };
  const briefJson = JSON.stringify(brief);
  // Node briefs may render nonce-fenced untrusted summaries; the prep token
  // binds the summary content and graph state, not the per-render nonce.
  const briefHash = sha256Hex(normalizeUntrustedEnvelopeNoncesForHash(briefJson));

  // Mint the prep_token. The token binds node_id + contract_hash + brief_hash
  // + materialized_at + graph_context_hash so any drift in the underlying
  // snapshot invalidates the token at finalize.
  const prepToken = sha256Hex([
    nodeId,
    attached.contract.contract_hash,
    briefHash,
    document.materialized_at,
    graphContextHash,
  ].join("|"));

  // Emit the node.transitioned events. The X.1 frozen table requires
  // contracted → ready → dispatched (the table forbids a direct
  // contracted → dispatched). When the node arrives in `contracted`,
  // prepare_node first promotes it to `ready` (the auxiliary transition
  // the X.9 graph scheduler would otherwise emit) and then immediately
  // emits the canonical ready → dispatched with the prep_token. When the
  // node is already in `ready` (the X.9 path) we skip the promotion.
  if (dispatchedNode.state === "contracted") {
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "contracted",
      to_state: "ready",
      contract_hash: attached.contract.contract_hash,
      ts: input.ts,
      source: { tool: "bob_prepare_node", reason: "auto_promote_for_dispatch" },
      actor: input.actor,
    });
  }
  const event = appendNodeTransition({
    target_domain: domain,
    node_id: nodeId,
    from_state: "ready",
    to_state: "dispatched",
    contract_hash: attached.contract.contract_hash,
    prep_token_hash: prepToken,
    ts: input.ts,
    source: { tool: "bob_prepare_node" },
    actor: input.actor,
  });

  try {
    scheduleMaterialization(domain);
  } catch {
    // Best-effort materialization debounce; do not regress the append.
  }

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    node_id: nodeId,
    prep_token: prepToken,
    brief_hash: briefHash,
    graph_context_hash: graphContextHash,
    materialized_at: document.materialized_at,
    contract_hash: attached.contract.contract_hash,
    allowed_tools_for_node: pack.allowed_tools_for_node.slice().sort(),
    recommended_reads_for_node: pack.recommended_reads_for_node.slice(),
    technique_pack_ids: pack.technique_packs.map((p) => p.id),
    // Plane X Cycle X.10 — orchestrator spawns the generic
    // evaluator-spawn shell with the labelled description so operator
    // status surfaces render the bracketed family tag.
    spawn_subagent_type: SPAWN_SUBAGENT_TYPE,
    family_tag: familyTag,
    spawn_description: spawnDescription,
    brief,
    event_id: event.event_id,
    event_hash: event.event_hash,
    to_state: event.payload.to_state,
  });
}

module.exports = Object.freeze({
  name: "bob_prepare_node",
  description:
    "Prepare a TaskGraph node for dispatch (clou-style three-call protocol, "
    + "first call). Reads the node from the materialized task-graph, derives "
    + "its capability pack via X.5 (≤1-hop graph context per X-P5), renders "
    + "the per-node brief via the X.8 `node` profile slice registry, and mints "
    + "a prep_token binding node_id + contract_hash + brief_hash + "
    + "materialized_at + graph_context_hash so post-dispatch drift is "
    + "detectable. Emits node.transitioned (contracted | ready) → dispatched "
    + "with prep_token in payload. Per X-P9 the brief inlines DISTILLED "
    + "SUMMARIES of recommended_reads — never bodies; the agent calls "
    + "bob_resolve_body for bodies. When the node has prior "
    + "node.transitioned → failed events on the ledger (operator re-contracted "
    + "a failed node via bob_attach_contract per the X.8 re-contract path), "
    + "the brief surfaces the prior failure payloads in the `prior_attempt` "
    + "slice so the agent reasons against the prior verdict. Refuses on state "
    + "∉ {contracted, ready} or when no Contract is attached. Orchestrator + "
    + "graph-scheduler only.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      node_id: {
        type: "string",
        description:
          "TaskGraph node id (TG-<prefix>-<slug>). Must be in state \"contracted\" or \"ready\".",
      },
      ts: { type: "string" },
      actor: { type: "string" },
    },
    required: ["target_domain", "node_id"],
  },
  handler,
  // orchestrator + graph-scheduler are the dispatch authorities. The
  // `evaluator-spawn` bundle (Plane X Cycle X.10) gets the tool too as
  // read-only-of-own-context: the agent shell may call bob_prepare_node
  // to re-read its own dispatched brief or detect graph drift; it must
  // not dispatch new nodes. The orchestrator owns dispatch.
  role_bundles: ["orchestrator", "evaluator-spawn"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
});
