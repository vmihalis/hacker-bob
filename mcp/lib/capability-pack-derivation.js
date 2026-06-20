"use strict";

// Plane X Cycle X.5 — Capability-pack derivation function.
//
// `derivePackForNode(node, graph_context, observation_history, contract)`
// returns the per-node bundle the X.8 prepare-node tool inlines in the
// dispatched brief:
//
//   {
//     technique_packs:           [{id, title, lens_affinity, summary}, ...],
//     cli_tool_packs:            [{id, narrative}, ...],
//     allowed_tools_for_node:    [tool_name, ...],
//     recommended_reads_for_node: [artifact_ref, ...],
//     brief_emphasis:            { ... node-kind-specific cues ... }
//   }
//
// PURE per X-P4. The function takes everything it needs in its arguments —
// the node, the ≤1-hop graph snapshot, the bounded observation history,
// and the optional Contract. No clock reads, no random, no env reads, no
// I/O. The test suite + the lint guard at the bottom enforce this so a
// future edit that breaks the determinism contract surfaces in CI before
// the X.8 brief renderer starts seeing drift.
//
// Per X-P5 the graph_context is ≤1-hop. Callers materialize it via
// `buildOneHopGraphContext(materializedDoc, nodeId, surfaceMetadataById)`
// (helper below) which walks edges incident to the dispatched node and
// returns only neighbors at distance 1. Any caller that pushes a richer
// graph_context risks blowing the bound; the helper exists so they don't
// have to write that walk themselves.

const {
  WEB3_IDENTITY_HANDOFF_TECHNIQUE_PACK,
  getTechniquePackById,
} = require("./technique-packs.js");
const {
  CAPABILITY_PACKS,
  getCapabilityPack,
  classifySurfaceCapability,
} = require("./capability-packs.js");
const {
  collectContractArtifactRefs,
} = require("./contracts.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
} = require("./task-graph-events.js");
const {
  deriveAuxiliaryToolsForTargetClass,
} = require("./target-class-pack-derivation.js");
const {
  assertTargetClass,
} = require("./target-classes.js");
// tool-registry.js eagerly loads every tool module via tools/index.js;
// tools that themselves require capability-pack-derivation (e.g. X.8's
// prepare-node) create a module-load cycle when this file requires
// tool-registry at top scope. We lazy-resolve toolNamesForRoleBundle on
// first call so the registry has fully materialized by then.
let _toolNamesForRoleBundleCache = null;
function toolNamesForRoleBundle(roleBundle) {
  if (_toolNamesForRoleBundleCache == null) {
    _toolNamesForRoleBundleCache = require("./tool-registry.js").toolNamesForRoleBundle;
  }
  return _toolNamesForRoleBundleCache(roleBundle);
}

// ─── Constants (frozen) ──────────────────────────────────────────────────

// Cross-stack identity technique pack id — UNION-included for every
// Transition node. Surface and Hypothesis derivations may add it too via
// lens_affinity on Contract or surface metadata.
const WEB3_IDENTITY_HANDOFF_PACK_ID = "web3_identity_handoff";

// `recommended_reads_for_node[]` cap. Per X-P9 the SHAPE of the list is
// bounded by what the Contract referenced (a few artifact_refs per witness)
// plus a small slice of recent observations on ≤1-hop adjacent surfaces. We
// hard-cap at 16 to defend the brief budget against pathological graphs.
const RECOMMENDED_READS_HARD_CAP = 16;

// Per-Transition observation seeding: how many recent observation refs per
// adjacent surface get folded into `recommended_reads_for_node[]`. Mirrors
// the X.8 brief renderer's "summary-grade" semantics — a small number per
// surface, not a "top N across everything" render-cap (X-P9).
const RECOMMENDED_READS_PER_SURFACE = 3;

// Per-pack evaluator role bundles that define the universe of
// evaluator-callable tools per Surface kind, used to build
// `allowed_tools_for_node[]` deterministically. DERIVED:
// `CAPABILITY_PACKS[*].role_bundles` in capability-packs.js is the single
// source of truth, and this frozen projection exists only so a pack/bundle
// edit lands in exactly one place. (Was a hand-written literal that drifted
// from the manifest — OSS packs were mapped to a non-existent "evaluator-oss"
// bundle that no tool declares, so toolNamesForRoleBundle() resolved empty and
// every OSS surface was dispatched without its tools.) CAPABILITY_PACKS is a
// frozen constant imported above, so this stays deterministic and sits above
// the purity divider.
const EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK = Object.freeze(
  Object.fromEntries(
    Object.entries(CAPABILITY_PACKS).map(([packId, pack]) => {
      const bundles = Array.isArray(pack.role_bundles) ? pack.role_bundles : [];
      if (bundles.length === 0) {
        throw new Error(
          `capability-pack-derivation: capability pack "${packId}" declares no `
          + "role_bundles; every pack must carry at least one bundle in capability-packs.js",
        );
      }
      return [packId, Object.freeze(bundles.slice())];
    }),
  ),
);

// Defensive default when a Surface node's metadata doesn't classify into a
// known capability pack. The web pack is the historical default and is the
// only pack whose `allowed_tools` covers the cross-cutting Bob tools (read
// session state, read coverage, etc) that every evaluator needs.
const DEFAULT_CAPABILITY_PACK_ID = "web";

// Plane Y Cycle Y.4 — `friction_history` bounded input (Y-P4 + Y-P6).
// `derivePackForNode` accepts at most this many friction records; the
// caller-side selector (`friction-selection.js`) caps the slice it threads
// in. Mirroring the value here lets the derivation function reject a
// caller that ignored the contract.
const FRICTION_HISTORY_HARD_CAP = 32;

// ─── Internal helpers ────────────────────────────────────────────────────

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function asStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((entry) => typeof entry === "string" && entry.length > 0);
}

function dedupeSorted(values) {
  return Array.from(new Set(values.filter((v) => typeof v === "string" && v.length > 0))).sort();
}

// Stable insertion-order dedupe; preserves the first occurrence of each
// value so callers depending on ordering (Contract witness reads land before
// observation-derived reads) get the order they wrote.
function dedupePreserveOrder(values) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    if (typeof value !== "string" || !value.length) continue;
    if (seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

function packIdForSurfaceMetadata(metadata) {
  if (!isPlainObject(metadata)) return DEFAULT_CAPABILITY_PACK_ID;
  // Two paths: (1) the metadata may carry a pre-classified `capability_pack`
  // (the surface-routes.json shape); (2) it may carry the raw fields the
  // classifier reads (surface_type + chain_family). Honor (1) when present so
  // a caller that already routed surfaces can short-circuit.
  if (typeof metadata.capability_pack === "string" && metadata.capability_pack.length > 0) {
    const pack = getCapabilityPack(metadata.capability_pack);
    if (pack) return pack.id;
  }
  try {
    const classified = classifySurfaceCapability(metadata);
    return classified.capability_pack;
  } catch {
    // classifySurfaceCapability throws on smart_contract with unsupported
    // chain_family. Fall back to the default web pack; the caller will see
    // a pack that doesn't carry the chain-specific tools and the brief
    // renderer surfaces that as a missing-pack signal in a later cycle.
    return DEFAULT_CAPABILITY_PACK_ID;
  }
}

function toolsForCapabilityPack(packId) {
  const bundles = EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK[packId];
  if (!bundles) return [];
  const tools = new Set();
  for (const bundle of bundles) {
    for (const tool of toolNamesForRoleBundle(bundle)) {
      tools.add(tool);
    }
  }
  return Array.from(tools);
}

// Pull a stable set of artifact_refs from the bounded observation history.
// Per X-P9 the observation events themselves are summary-grade at emit, so
// the refs we surface here are pointers an agent can resolve via
// bob_resolve_body if the body matters. We do NOT inline observation bodies
// from this function; the X.8 prepare-node brief renderer is responsible
// for inlining the distilled summary form.
function artifactRefsFromObservationHistory(observationHistory, { limit }) {
  if (!Array.isArray(observationHistory)) return [];
  const out = [];
  for (const observation of observationHistory) {
    if (!isPlainObject(observation)) continue;
    // Observations may surface a single artifact_ref or an array. Both
    // shapes are common across plane T / O emit paths.
    const refs = [];
    if (typeof observation.artifact_ref === "string") {
      refs.push(observation.artifact_ref);
    }
    if (Array.isArray(observation.artifact_refs)) {
      for (const ref of observation.artifact_refs) {
        if (typeof ref === "string") refs.push(ref);
      }
    }
    // Some observation payloads carry the ref inside `payload.artifact_ref`
    // (the post-X.7 distilled-summary shape).
    if (isPlainObject(observation.payload)) {
      if (typeof observation.payload.artifact_ref === "string") {
        refs.push(observation.payload.artifact_ref);
      }
      if (Array.isArray(observation.payload.artifact_refs)) {
        for (const ref of observation.payload.artifact_refs) {
          if (typeof ref === "string") refs.push(ref);
        }
      }
    }
    for (const ref of refs) {
      out.push(ref);
      if (out.length >= limit) return out;
    }
  }
  return out;
}

function packsFromContractProductionPaths(contract) {
  if (!isPlainObject(contract) || !Array.isArray(contract.production_paths)) return [];
  // Group tools by their owning capability_pack so a Hypothesis-node pack
  // ends up with the union of every capability_pack the Contract's
  // production_paths touch. Iterates the closed CAPABILITY_PACKS registry —
  // a tool that doesn't fit a registered pack falls through silently here
  // (it's still surfaced via `allowed_tools_for_node[]` directly from the
  // Contract's production_paths.tool_call_pattern[].tool list at the
  // caller's discretion).
  const seenPacks = new Set();
  const orderedPacks = [];
  for (const path of contract.production_paths) {
    if (!isPlainObject(path)) continue;
    const tcp = Array.isArray(path.tool_call_pattern) ? path.tool_call_pattern : [];
    for (const entry of tcp) {
      const tool = isPlainObject(entry) ? entry.tool : null;
      if (typeof tool !== "string") continue;
      for (const packId of Object.keys(CAPABILITY_PACKS)) {
        if (seenPacks.has(packId)) continue;
        const packTools = toolsForCapabilityPack(packId);
        if (packTools.includes(tool)) {
          seenPacks.add(packId);
          orderedPacks.push(packId);
        }
      }
    }
  }
  return orderedPacks;
}

function toolsFromContractProductionPaths(contract) {
  if (!isPlainObject(contract) || !Array.isArray(contract.production_paths)) return [];
  const tools = [];
  for (const path of contract.production_paths) {
    if (!isPlainObject(path)) continue;
    const tcp = Array.isArray(path.tool_call_pattern) ? path.tool_call_pattern : [];
    for (const entry of tcp) {
      const tool = isPlainObject(entry) ? entry.tool : null;
      if (typeof tool === "string" && tool.length > 0) {
        tools.push(tool);
      }
    }
  }
  return tools;
}

function techniquePackEntryForId(packId) {
  const pack = getTechniquePackById(packId);
  if (!pack) return null;
  // Project to brief-inlinable shape per X-P9 — id + title + lens_affinity
  // + the summary line. The brief renderer pulls `full` only on opt-in;
  // X.5 returns the summary-grade projection so the X.8 brief stays under
  // the budget without a render-time cap.
  const out = {
    id: pack.id,
    title: pack.title,
    summary: pack.summary,
  };
  if (Array.isArray(pack.lens_affinity)) {
    out.lens_affinity = pack.lens_affinity.slice();
  }
  return out;
}

// ─── ≤1-hop adjacency helper (X-P5) ──────────────────────────────────────
//
// Walk edges incident to `nodeId` from the materialized graph and return a
// snapshot containing only direct neighbors. The result is the bound the
// derivePackForNode function expects via `graph_context` — anything outside
// the 1-hop neighborhood is intentionally discarded so a downstream caller
// can't smuggle extra context past the X-P5 bound.
function buildOneHopGraphContext(materializedDoc, nodeId, surfaceMetadataById = {}) {
  if (!isPlainObject(materializedDoc)) {
    throw new Error("buildOneHopGraphContext: materialized document must be an object");
  }
  if (typeof nodeId !== "string" || !nodeId.length) {
    throw new Error("buildOneHopGraphContext: nodeId must be a non-empty string");
  }
  const nodes = Array.isArray(materializedDoc.nodes) ? materializedDoc.nodes : [];
  const edges = Array.isArray(materializedDoc.edges) ? materializedDoc.edges : [];
  const nodesById = new Map();
  for (const node of nodes) {
    if (isPlainObject(node) && typeof node.node_id === "string") {
      nodesById.set(node.node_id, node);
    }
  }
  const adjacentNodeIds = new Set();
  const incidentEdges = [];
  for (const edge of edges) {
    if (!isPlainObject(edge)) continue;
    if (edge.from_node_id === nodeId) {
      adjacentNodeIds.add(edge.to_node_id);
      incidentEdges.push(edge);
    } else if (edge.to_node_id === nodeId) {
      adjacentNodeIds.add(edge.from_node_id);
      incidentEdges.push(edge);
    }
  }
  const adjacentNodes = [];
  for (const id of adjacentNodeIds) {
    const node = nodesById.get(id);
    if (node) adjacentNodes.push(node);
  }
  // Stable orderings so the same input → same graph_context → same pack.
  adjacentNodes.sort((a, b) => a.node_id.localeCompare(b.node_id));
  incidentEdges.sort((a, b) => {
    if (a.from_node_id !== b.from_node_id) return a.from_node_id.localeCompare(b.from_node_id);
    if (a.to_node_id !== b.to_node_id) return a.to_node_id.localeCompare(b.to_node_id);
    if (a.edge_kind !== b.edge_kind) return a.edge_kind.localeCompare(b.edge_kind);
    return (a.source_event_id || "").localeCompare(b.source_event_id || "");
  });
  // Project surface metadata only for the surface_refs we actually see (the
  // dispatched node's surface_refs + every adjacent node's surface_refs). A
  // caller-supplied surface_metadata_by_id map keyed beyond those refs is
  // intentionally trimmed: the X-P5 bound says ≤1-hop, full stop.
  const wantSurfaceIds = new Set();
  const dispatchedNode = nodesById.get(nodeId);
  if (isPlainObject(dispatchedNode) && Array.isArray(dispatchedNode.surface_refs)) {
    for (const ref of dispatchedNode.surface_refs) wantSurfaceIds.add(ref);
  }
  for (const node of adjacentNodes) {
    if (Array.isArray(node.surface_refs)) {
      for (const ref of node.surface_refs) wantSurfaceIds.add(ref);
    }
  }
  const trimmedSurfaceMetadata = {};
  for (const surfaceId of wantSurfaceIds) {
    if (Object.prototype.hasOwnProperty.call(surfaceMetadataById, surfaceId)) {
      trimmedSurfaceMetadata[surfaceId] = surfaceMetadataById[surfaceId];
    }
  }
  return {
    dispatched_node: dispatchedNode || null,
    adjacent_nodes: adjacentNodes,
    incident_edges: incidentEdges,
    surface_metadata_by_id: trimmedSurfaceMetadata,
  };
}

// ─── Per-node-kind derivations ───────────────────────────────────────────

function deriveSurfacePack(node, graph_context) {
  const surfaceRefs = asStringArray(node.surface_refs);
  const primarySurfaceId = surfaceRefs[0] || null;
  const surfaceMetadata = primarySurfaceId
    ? graph_context.surface_metadata_by_id[primarySurfaceId]
    : null;
  const packId = packIdForSurfaceMetadata(surfaceMetadata);
  const allowedTools = dedupeSorted(toolsForCapabilityPack(packId));
  return {
    capability_pack_ids: [packId],
    allowed_tools: allowedTools,
    brief_emphasis: {
      node_kind: "surface",
      capability_pack: packId,
      primary_surface_id: primarySurfaceId,
    },
  };
}

function deriveTransitionPack(node, graph_context) {
  // Transition nodes carry TWO surface_refs (the from_surface and to_surface
  // captured by the transition_proposed event). Look both up in the
  // surface_metadata_by_id map to pick each endpoint's capability_pack;
  // UNION the resulting tool sets.
  const surfaceRefs = asStringArray(node.surface_refs);
  const endpointPackIds = [];
  for (const surfaceId of surfaceRefs) {
    const metadata = graph_context.surface_metadata_by_id[surfaceId];
    const packId = packIdForSurfaceMetadata(metadata);
    if (!endpointPackIds.includes(packId)) endpointPackIds.push(packId);
  }
  if (endpointPackIds.length === 0) {
    endpointPackIds.push(DEFAULT_CAPABILITY_PACK_ID);
  }
  const allowedToolSet = new Set();
  for (const packId of endpointPackIds) {
    for (const tool of toolsForCapabilityPack(packId)) {
      allowedToolSet.add(tool);
    }
  }
  return {
    capability_pack_ids: endpointPackIds,
    allowed_tools: dedupeSorted(Array.from(allowedToolSet)),
    brief_emphasis: {
      node_kind: "transition",
      endpoint_capability_packs: endpointPackIds.slice(),
      endpoint_surface_refs: surfaceRefs.slice(),
    },
  };
}

function deriveHypothesisPack(node, graph_context, contract) {
  // Hypothesis nodes derive their pack from the Contract's
  // production_paths[].tool_call_pattern[]. The Contract is OPTIONAL — a
  // proposed Hypothesis without a Contract is brief-derivable but the agent
  // will see a minimal allowed_tools_for_node[] (just the evaluator-shared
  // bundle) until a Contract attaches.
  const allowedTools = new Set();
  const capabilityPackIds = [];
  if (contract) {
    const contractTools = toolsFromContractProductionPaths(contract);
    for (const tool of contractTools) allowedTools.add(tool);
    for (const packId of packsFromContractProductionPaths(contract)) {
      capabilityPackIds.push(packId);
    }
  }
  // Always include the evaluator-shared bundle so the agent can read
  // session state + record evidence regardless of which chain-specific
  // bundles the Contract pulls in.
  for (const tool of toolNamesForRoleBundle("evaluator-shared")) {
    allowedTools.add(tool);
  }
  return {
    capability_pack_ids: capabilityPackIds,
    allowed_tools: dedupeSorted(Array.from(allowedTools)),
    brief_emphasis: {
      node_kind: "hypothesis",
      contract_pack_ids: capabilityPackIds.slice(),
      surface_refs: asStringArray(node.surface_refs),
    },
  };
}

// ─── Top-level derivePackForNode ─────────────────────────────────────────

function derivePackForNode(node, graph_context, observation_history, contract, options) {
  if (!isPlainObject(node)) {
    throw new Error("derivePackForNode: node must be an object");
  }
  if (typeof node.node_id !== "string" || !node.node_id.startsWith(TASK_GRAPH_NODE_ID_PREFIX)) {
    throw new Error("derivePackForNode: node.node_id must be a TaskGraph id (TG- prefix)");
  }
  const kind = node.kind;
  if (typeof kind !== "string" || !kind.length) {
    throw new Error("derivePackForNode: node.kind must be set");
  }
  const ctx = isPlainObject(graph_context)
    ? {
      adjacent_nodes: Array.isArray(graph_context.adjacent_nodes) ? graph_context.adjacent_nodes : [],
      incident_edges: Array.isArray(graph_context.incident_edges) ? graph_context.incident_edges : [],
      surface_metadata_by_id: isPlainObject(graph_context.surface_metadata_by_id)
        ? graph_context.surface_metadata_by_id
        : {},
    }
    : { adjacent_nodes: [], incident_edges: [], surface_metadata_by_id: {} };
  const history = Array.isArray(observation_history) ? observation_history : [];
  const normalizedContract = isPlainObject(contract) ? contract : null;

  // Plane Y Cycle Y.4 — optional bounded inputs (Y-P4 + Y-P6 + O5).
  //
  // `friction_history` is the caller-side selector output (see
  // `friction-selection.js#selectRelevantFrictions`). We accept either
  // `options.friction_history` (preferred) or fall back to no history.
  // Hard-cap at FRICTION_HISTORY_HARD_CAP so a buggy caller cannot blow
  // the Y-P4 bound.
  const opts = isPlainObject(options) ? options : {};
  let frictionHistory = Array.isArray(opts.friction_history) ? opts.friction_history : [];
  if (frictionHistory.length > FRICTION_HISTORY_HARD_CAP) {
    frictionHistory = frictionHistory.slice(0, FRICTION_HISTORY_HARD_CAP);
  }
  // `target_class` is a closed enum (Y.4 O5). When supplied it MUST satisfy
  // assertTargetClass; an unknown value throws synchronously so a stray
  // free-form string from queue-policy cannot smuggle in a side-channel.
  let targetClass = null;
  if (opts.target_class !== undefined && opts.target_class !== null) {
    targetClass = assertTargetClass(opts.target_class);
  }

  let perKind;
  if (kind === "surface") {
    perKind = deriveSurfacePack(node, ctx);
  } else if (kind === "transition") {
    perKind = deriveTransitionPack(node, ctx);
  } else if (kind === "hypothesis") {
    perKind = deriveHypothesisPack(node, ctx, normalizedContract);
  } else if (kind === "claim") {
    // Claim nodes ride the wave-scheduler per X-D7 and don't dispatch via
    // the TaskGraph executor. derivePackForNode still returns a stable
    // bundle so downstream callers (e.g., the X.2 summary view) can pull a
    // consistent shape without special-casing claim.
    perKind = {
      capability_pack_ids: [],
      allowed_tools: dedupeSorted(toolNamesForRoleBundle("evaluator-shared")),
      brief_emphasis: { node_kind: "claim" },
    };
  } else {
    throw new Error(`derivePackForNode: unsupported node kind "${kind}"`);
  }

  // Technique packs: every Transition node UNION-includes web3_identity_handoff.
  // Surface and Hypothesis nodes only include it when an adjacent Transition
  // exists at ≤1-hop OR the Contract's witnesses include `relational_value_match`
  // (which is the X.5 signal that the witness expects a cross-stack equality).
  const techniquePackIds = new Set();
  if (kind === "transition") {
    techniquePackIds.add(WEB3_IDENTITY_HANDOFF_PACK_ID);
  } else {
    const hasAdjacentTransition = ctx.adjacent_nodes.some((adj) => adj && adj.kind === "transition");
    const contractHasRelational = normalizedContract
      && Array.isArray(normalizedContract.witnesses)
      && normalizedContract.witnesses.some((w) => w && w.kind === "relational_value_match");
    if (hasAdjacentTransition || contractHasRelational) {
      techniquePackIds.add(WEB3_IDENTITY_HANDOFF_PACK_ID);
    }
  }
  const techniquePacks = Array.from(techniquePackIds)
    .sort()
    .map(techniquePackEntryForId)
    .filter((entry) => entry != null);

  // recommended_reads_for_node[]:
  //   (a) every artifact_ref surfaced by the Contract's witness predicates
  //       (left + right for relational_value_match; the single artifact_ref
  //       for hash_equals). Insertion order preserves Contract order so the
  //       brief stays deterministic.
  //   (b) the top-N most recent artifact_refs from the observation history
  //       on adjacent surfaces. The cap is per-surface (RECOMMENDED_READS_PER_SURFACE)
  //       and the total is hard-capped at RECOMMENDED_READS_HARD_CAP.
  // Per X-P9 these are POINTERS not bodies. The X.8 brief renderer inlines
  // the distilled summary of each ref; the agent calls bob_resolve_body if
  // they need the body.
  const contractRefs = normalizedContract
    ? collectContractArtifactRefs(normalizedContract)
    : [];
  const observationRefs = artifactRefsFromObservationHistory(history, {
    limit: RECOMMENDED_READS_PER_SURFACE * Math.max(1, ctx.adjacent_nodes.length + 1),
  });
  const recommendedReads = dedupePreserveOrder([
    ...contractRefs,
    ...observationRefs,
  ]).slice(0, RECOMMENDED_READS_HARD_CAP);

  // Plane Y Cycle Y.4 — UNION friction-wanted tools + target_class auxiliaries
  // into `allowed_tools_for_node[]` (Y-P6 + O5). Both sources are caller-
  // bounded already; this block only de-dupes and stable-sorts the result.
  //
  // (1) `friction_history[*].wanted_tool` — the tool the agent declared it
  //     needed. Y-P6 widens the Contract via this set so the next dispatch
  //     of the same surface lands with the tool present.
  // (2) `deriveAuxiliaryToolsForTargetClass(target_class)` — per-target-class
  //     auxiliary tools (e.g., phishing kit triage surfacing OSINT + 3
  //     browser tools).
  //
  // Both unions defend against pack-bypass: the Y.5 scheduler MUST emit
  // the underlying `wanted_tool` strings through the closed TOOL_REGISTRY,
  // so a friction record can never smuggle a non-registered tool name.
  const frictionWantedTools = [];
  for (const record of frictionHistory) {
    if (!isPlainObject(record)) continue;
    if (typeof record.wanted_tool === "string" && record.wanted_tool.length > 0) {
      frictionWantedTools.push(record.wanted_tool);
    }
  }
  const targetClassAuxTools = targetClass
    ? deriveAuxiliaryToolsForTargetClass(targetClass).slice()
    : [];
  const unionedAllowedTools = dedupeSorted([
    ...perKind.allowed_tools,
    ...frictionWantedTools,
    ...targetClassAuxTools,
  ]);

  return Object.freeze({
    technique_packs: Object.freeze(techniquePacks),
    cli_tool_packs: Object.freeze([]),
    allowed_tools_for_node: Object.freeze(unionedAllowedTools),
    recommended_reads_for_node: Object.freeze(recommendedReads),
    brief_emphasis: Object.freeze({
      ...perKind.brief_emphasis,
      capability_pack_ids: perKind.capability_pack_ids.slice(),
      technique_pack_ids: Array.from(techniquePackIds).sort(),
      target_class: targetClass,
      friction_history_count: frictionHistory.length,
    }),
  });
}

// Module-load-time lint guard. The derivePackForNode body MUST stay pure per
// X-P4; this guard reads its own source and refuses to load if a forbidden
// pattern appears below the
// `─── Per-node-kind derivations ───` divider. Putting the guard inside the
// module itself means the contract holds in every consumer that requires
// this module, including test fixtures that monkey-patch globals.
(function lintPureDerivation() {
  const fs = require("fs");
  const path = require("path");
  let source;
  try {
    source = fs.readFileSync(__filename, "utf8");
  } catch {
    // If we can't read the source (e.g., bundled), skip the lint. The unit
    // tests for X.5 enforce the same property at test-time so an installer
    // bundle still gets the property checked at CI.
    return;
  }
  // Slice the source to the body we want to enforce purity on — everything
  // below the divider. The header may legitimately reference these patterns
  // in comments or imports for documentation purposes.
  const divider = "─── Per-node-kind derivations ───";
  const dividerIdx = source.indexOf(divider);
  const body = dividerIdx >= 0 ? source.slice(dividerIdx) : source;
  // Strip line comments + block comments so a documentation reference to the
  // forbidden pattern doesn't trip the guard. Order matters: block comments
  // first, then line comments. We also strip string literals (single, double,
  // and template) so the regex patterns + their labels (which live as string
  // contents below) don't self-trigger.
  const stripped = body
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/`(?:\\.|[^`\\])*`/g, "``")
    // Strip regex literals (they are not source-level expressions calling
    // the forbidden APIs; the regex pattern characters would self-trigger
    // the guard otherwise). Conservative: only match /.../ when preceded by
    // `=` / `(` / `,` / `:` / `&` / `|` / `!` to avoid touching division.
    .replace(/([=(,:&|!])\s*\/(?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\])+\/[a-z]*/g, "$1 /__re__/");
  const forbidden = [
    { re: new RegExp("\\b" + "Date" + "\\s*\\."), label: ["Date", "."].join("") },
    { re: new RegExp("\\b" + "Date" + "\\s*\\("), label: ["Date", "()"].join("") },
    { re: new RegExp("\\bnew\\s+" + "Date" + "\\b"), label: ["new ", "Date"].join("") },
    { re: new RegExp("\\b" + "Math" + "\\.random\\b"), label: ["Math", ".random"].join("") },
    { re: new RegExp("\\b" + "process" + "\\.env\\b"), label: ["process", ".env"].join("") },
    { re: new RegExp("\\b" + "performance" + "\\.now\\b"), label: ["performance", ".now"].join("") },
  ];
  for (const { re, label } of forbidden) {
    if (re.test(stripped)) {
      throw new Error(
        `capability-pack-derivation purity lint: forbidden pattern \`${label}\` `
        + "found in derivation body — X-P4 requires pure inputs only "
        + "(no clock, no random, no env reads). Move the side effect into "
        + "the caller and pass the value through graph_context.",
      );
    }
  }
  // Defensive: confirm the module path includes the expected basename so a
  // bundled rename doesn't silently bypass the guard.
  if (!__filename.endsWith(path.sep + "capability-pack-derivation.js")) {
    throw new Error(
      `capability-pack-derivation purity lint: unexpected filename ${__filename}; `
      + "the lint guard expects this module to live at mcp/lib/capability-pack-derivation.js.",
    );
  }
})();

module.exports = {
  DEFAULT_CAPABILITY_PACK_ID,
  EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK,
  FRICTION_HISTORY_HARD_CAP,
  RECOMMENDED_READS_HARD_CAP,
  RECOMMENDED_READS_PER_SURFACE,
  WEB3_IDENTITY_HANDOFF_PACK_ID,
  buildOneHopGraphContext,
  derivePackForNode,
};
