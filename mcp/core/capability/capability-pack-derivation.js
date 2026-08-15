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
} = require("../dispatch/technique-packs.js");
const {
  PHYSICAL_CAPABILITY_PACK,
  dispatchableCapabilityPacks,
  getCapabilityPack,
  classifySurfaceCapability,
  isCapabilityPackDispatchable,
  isPhysicalSurfaceMetadata,
  isBugClassRelevantForSurface,
} = require("./capability-packs.js");
const {
  collectContractArtifactRefs,
} = require("../contract/contracts.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
} = require("../waves/task-graph-events.js");
const {
  deriveAuxiliaryToolsForTargetClass,
} = require("./target-class-pack-derivation.js");
const {
  assertTargetClass,
} = require("../target-classes.js");
// tool-registry.js eagerly loads every tool module via tools/index.js;
// tools that themselves require capability-pack-derivation (e.g. X.8's
// prepare-node) create a module-load cycle when this file requires
// tool-registry at top scope. We lazy-resolve toolNamesForRoleBundle on
// first call so the registry has fully materialized by then.
let _toolNamesForRoleBundleCache = null;
function toolNamesForRoleBundle(roleBundle) {
  if (_toolNamesForRoleBundleCache == null) {
    _toolNamesForRoleBundleCache = require("../dispatch/tool-registry.js").toolNamesForRoleBundle;
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
    dispatchableCapabilityPacks().map((pack) => {
      const packId = pack.id;
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

// A tool must be wanted at least this many times across a capability pack's
// surfaces (per the caller-side pack-friction aggregate) before it counts as a
// chronic pack deficiency worth widening the pack for; a single stray friction
// record is one-off noise, not a systematic pack gap. Y-P6 widening semantics:
// clearing this threshold only ADDS the tool to the pack union; it never removes
// or truncates a tool.
const PACK_FRICTION_CHRONIC_MIN_COUNT = 2;

// Confidence modulates friction-widening eagerness. A LOW-confidence route
// widens from a single friction record; a MEDIUM or HIGH route needs 2 distinct
// records (the pack routing was confident, so it takes repeated friction to
// override it). Absent/unknown confidence falls to the eager default
// (threshold 1) so widening is never LESS eager than the unconditional union —
// modulation only ever RAISES the bar, never truncates.
const FRICTION_WIDEN_THRESHOLD_BY_CONFIDENCE = Object.freeze({ low: 1, medium: 2, high: 2 });

function widenThresholdForConfidence(confidence) {
  if (typeof confidence === "string"
    && Object.prototype.hasOwnProperty.call(FRICTION_WIDEN_THRESHOLD_BY_CONFIDENCE, confidence)) {
    return FRICTION_WIDEN_THRESHOLD_BY_CONFIDENCE[confidence];
  }
  return 1;
}

// CN (coverage-nesting) — defensive caps on the (bug_class x auth_role) child
// fan-out plan. CHILD_FANOUT_HARD_CAP mirrors the queue-policy max_spawn_children
// ceiling so a buggy caller cannot blow the spawn budget; CHILD_FANOUT_BUG_CLASS_CAP
// re-bounds the bug-class axis (already capped at 20 on the surface) defensively.
const CHILD_FANOUT_HARD_CAP = 64;
const CHILD_FANOUT_BUG_CLASS_CAP = 32;

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

// The authoritative routability of a surface's metadata, consumed by the
// single-surface deriver (and by downstream disposition recorders). Returns
// `{ pack_id, required_pack_id?, routable, surface_type, surface_class?, reason }`.
// An unavailable physical pack and a smart_contract surface whose chain_family
// is missing/unsupported are `routable:false` with a null active pack and a
// human-readable reason; neither is ever laundered into the web pack. Web/OSS/
// resolved-SC/unknown-type surfaces are routable with their resolved pack.
// PURE: consults only classifySurfaceCapability + getCapabilityPack (both pure).
function routabilityForSurfaceMetadata(metadata) {
  if (!isPlainObject(metadata)) {
    return { pack_id: DEFAULT_CAPABILITY_PACK_ID, routable: true, surface_type: "unknown", reason: null };
  }
  // A persisted unroutable disposition and, especially, an in-memory
  // quarantine tombstone are authority facts.  They must be interpreted
  // before the historical unknown->web classifier fallback.
  if (metadata.disposition === "unroutable" || metadata.dispatch_blocked === true) {
    const surfaceClass = typeof metadata.surface_class === "string"
      ? metadata.surface_class
      : (isPhysicalSurfaceMetadata(metadata) ? "physical" : null);
    return {
      pack_id: null,
      required_pack_id: typeof metadata.required_capability_pack === "string"
        ? metadata.required_capability_pack
        : null,
      required_pack_version: Number.isInteger(metadata.required_capability_pack_version)
        ? metadata.required_capability_pack_version
        : null,
      routable: false,
      surface_type: typeof metadata.surface_type === "string" && metadata.surface_type.length > 0
        ? metadata.surface_type
        : "unknown",
      surface_class: surfaceClass,
      reason: typeof metadata.reason === "string" && metadata.reason.length > 0
        ? metadata.reason
        : "unroutable surface",
      dispatch_blocked: metadata.dispatch_blocked === true,
      route_metadata_status: typeof metadata.route_metadata_status === "string"
        ? metadata.route_metadata_status
        : null,
    };
  }
  // Pre-classified short-circuit: the metadata may already carry a resolved
  // `capability_pack` (the surface-routes.json shape). Honor it directly.
  if (!isPhysicalSurfaceMetadata(metadata)
      && typeof metadata.capability_pack === "string"
      && metadata.capability_pack.length > 0) {
    const pack = getCapabilityPack(metadata.capability_pack);
    if (isCapabilityPackDispatchable(pack)) {
      return {
        pack_id: pack.id,
        routable: true,
        surface_type: typeof metadata.surface_type === "string" && metadata.surface_type.length > 0
          ? metadata.surface_type
          : "unknown",
        reason: null,
      };
    }
    if (pack) {
      return {
        pack_id: null,
        required_pack_id: pack.id,
        required_pack_version: pack.capability_pack_version,
        routable: false,
        surface_type: typeof metadata.surface_type === "string" && metadata.surface_type.length > 0
          ? metadata.surface_type
          : "unknown",
        surface_class: pack.surface_class || null,
        reason: pack.dispatch_block_reason || `capability pack ${pack.id} is not dispatchable`,
      };
    }
  }
  // The classifier is the single routing source of truth and never throws for a
  // smart_contract with an unresolved chain_family — it returns routable:false.
  try {
    const classified = classifySurfaceCapability(metadata);
    if (classified.routable === false) {
      const reason = classified.unroutable_reason
        || (Array.isArray(classified.reasons) && classified.reasons[0])
        || "unroutable surface";
      return {
        pack_id: null,
        required_pack_id: classified.required_capability_pack || null,
        required_pack_version: classified.required_capability_pack_version || null,
        routable: false,
        surface_type: classified.surface_type || "unknown",
        surface_class: classified.surface_class || null,
        reason,
      };
    }
    return {
      pack_id: classified.capability_pack,
      routable: true,
      surface_type: classified.surface_type || "unknown",
      surface_class: classified.surface_class || null,
      reason: null,
    };
  } catch (err) {
    // Defensive: any unexpected classifier error must not launder a typed
    // surface into the web pack; surface it as an unroutable disposition.
    return {
      pack_id: null,
      routable: false,
      surface_type: typeof metadata.surface_type === "string" && metadata.surface_type.length > 0
        ? metadata.surface_type
        : "unknown",
      surface_class: null,
      reason: (err && err.message) ? err.message : "unroutable surface",
    };
  }
}

function packIdForSurfaceMetadata(metadata) {
  // Only a genuinely routable surface owns a capability pack. Returning null
  // for unavailable physical and ambiguous smart-contract surfaces prevents a
  // caller from mistaking either for the historical web default.
  const r = routabilityForSurfaceMetadata(metadata);
  return r.routable ? r.pack_id : null;
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

function toolsForUnroutableSurface(routability) {
  // The legacy smart-contract disposition keeps the existing shared baseline.
  // A physical surface gets no model-callable fallback tools at all: even the
  // historical "shared" bundle contains web/browser/repo surfaces and would be
  // an accidental authority expansion while the physical role is unregistered.
  if (routability && (
    routability.surface_class === "physical"
    || routability.dispatch_blocked === true
  )) return [];
  return toolNamesForRoleBundle("evaluator-shared");
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
  // production_paths touch. Iterates the dispatchable capability-pack registry —
  // a tool that doesn't fit a registered pack falls through silently here
  // (it's still surfaced via `allowed_tools_for_node[]` directly from the
  // Contract's production_paths.tool_call_pattern[].tool list at the
  // caller's discretion).
  const seenPacks = new Set();
  const orderedPacks = [];
  const dispatchablePackIds = dispatchableCapabilityPacks().map((pack) => pack.id);
  for (const path of contract.production_paths) {
    if (!isPlainObject(path)) continue;
    const tcp = Array.isArray(path.tool_call_pattern) ? path.tool_call_pattern : [];
    for (const entry of tcp) {
      const tool = isPlainObject(entry) ? entry.tool : null;
      if (typeof tool !== "string") continue;
      for (const packId of dispatchablePackIds) {
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
  const routability = routabilityForSurfaceMetadata(surfaceMetadata);
  // An unroutable smart_contract surface is NEVER routed to the web pack. It
  // gets the read-only evaluator-shared baseline (so the agent can still read
  // session state and record the disposition — NOT a web attack toolset) and a
  // structured `routable:false` + `unroutable_reason` signal that a downstream
  // node records as a non-halting partial disposition.
  if (routability.routable === false) {
    return {
      capability_pack_ids: [],
      allowed_tools: dedupeSorted(toolsForUnroutableSurface(routability)),
      brief_emphasis: {
        node_kind: "surface",
        capability_pack: null,
        ...(routability.required_pack_id
          ? {
            required_capability_pack: routability.required_pack_id,
            required_capability_pack_version: routability.required_pack_version,
          }
          : {}),
        routable: false,
        unroutable_reason: routability.reason,
        primary_surface_id: primarySurfaceId,
      },
    };
  }
  const packId = routability.pack_id;
  const allowedTools = dedupeSorted(toolsForCapabilityPack(packId)); // X.6
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

// Per-cell weapon adoption: the technique pack(s) that target a given
// bug_class, keyed on the normalized bug_class axis. Additive over the base
// surface pack (monotonic-up — a cell's broad evaluator toolset is never
// narrowed; the weapon is the specialized technique a cell adopts). A bug_class
// with no mapped weapon adopts none and stands on the base pack. The cross-
// stack identity/replay classes adopt the web3 identity-handoff technique — the
// cross-surface weapon a per-surface model never reaches for.
const BUG_CLASS_WEAPON = Object.freeze({
  replay: Object.freeze([WEB3_IDENTITY_HANDOFF_PACK_ID]),
  cross_chain: Object.freeze([WEB3_IDENTITY_HANDOFF_PACK_ID]),
  cross_chain_replay: Object.freeze([WEB3_IDENTITY_HANDOFF_PACK_ID]),
  identity_handoff: Object.freeze([WEB3_IDENTITY_HANDOFF_PACK_ID]),
  cross_stack_identity: Object.freeze([WEB3_IDENTITY_HANDOFF_PACK_ID]),
});

function weaponForBugClass(bugClass) {
  if (typeof bugClass !== "string") return [];
  const key = bugClass.trim().toLowerCase().replace(/[\s-]+/g, "_");
  return BUG_CLASS_WEAPON[key] || [];
}

// ─── Mechanism-template ranking + axis (the open-registry dispatch driver) ──
//
// A mechanism template (corpus tier-2 or registered tier-3 advisory candidate)
// is matched against a cell so its dispatch order reflects the trust gradient.
// EVERYTHING here is PURE: the registry is read by the (impure) caller and
// passed in via `opts.belief.mechanism_templates`. Nothing below reads I/O.
//
// The score is TIER x MATCH x CHAINING:
//   TIER     — the trust gradient. An oracle-backed mechanism (a template that
//              carries an executed oracle handle) outranks a validated corpus
//              template (tier 2) which outranks a synthesis candidate (tier 3).
//   MATCH    — does this template STRUCTURALLY apply to this cell? Its
//              mechanism_id / name / required_entities must line up with the
//              cell's bug_class. A non-matching template scores 0 (no lift).
//   CHAINING — front-load a mechanism whose effect feeds a transition edge:
//              an evidence_predicate.required_edges entry is a chaining token,
//              so a mechanism that produces a cross-surface effect ranks higher.
//
// The score only RAISES (it is added to the planning-key score), so a cell with
// no matching template keeps its deterministic slot. RANK != BOUND: the score
// reorders dispatch; it never drops, filters, or caps a cell.

const MECHANISM_TIER_WEIGHT = Object.freeze({
  1: 3, // oracle-backed (executed oracle handle present)
  2: 2, // validated corpus template
  3: 1, // synthesis candidate (advisory)
});

// Normalize a token for structural matching (lowercase, separators collapsed).
function normalizeMatchToken(value) {
  if (typeof value !== "string") return "";
  return value.trim().toLowerCase().replace(/[\s-]+/g, "_");
}

// A stable dedup key for a mechanism template so near-identical templates
// (CWE-639 ≡ cwe-639, a re-registered corpus lift, ...) collapse to ONE
// agent-state. Mirrors the producers' candidateDedupKey contract: a DISTINCT
// mechanism always yields a DISTINCT key (first occurrence wins; nothing
// distinct is ever dropped). Prefers the canonical mechanism_id, falling back
// to the template id so an id-only candidate still keys stably.
function mechanismDedupKey(template) {
  if (!isPlainObject(template)) return null;
  const mech = normalizeMatchToken(template.mechanism_id);
  const id = normalizeMatchToken(template.id);
  if (mech && id) return `${mech}::${id}`;
  return mech || id || null;
}

// Resolve a template's effective tier. An oracle handle (an executed
// mechanism-agnostic oracle bound to the template) promotes it to tier 1 for
// ranking; otherwise the registry-preserved tier (2 corpus / 3 candidate)
// applies. Defaults to tier 3 (advisory) for an untagged record so an unknown
// template never out-ranks a confirmed one.
function mechanismTierWeight(template) {
  if (!isPlainObject(template)) return 0;
  const oracleBacked = template.oracle_backed === true
    || (isPlainObject(template.advisory_evidence) && template.advisory_evidence.oracle_backed === true);
  const tier = oracleBacked
    ? 1
    : (Number.isInteger(template.tier) ? template.tier : 3);
  return MECHANISM_TIER_WEIGHT[tier] || MECHANISM_TIER_WEIGHT[3];
}

// MATCH: does this template structurally apply to this bug_class? A template
// applies when its mechanism_id, id, or any name/required_entity token shares a
// normalized token with the bug_class. Fail-OPEN is deliberately NOT used here
// — an unrelated template must NOT lift an unrelated cell (that would be a noisy
// false route, the ranking quality risk) — but a zero match is never a DROP: the
// cell still stands on its deterministic slot. Returns 1 on match, 0 otherwise.
function mechanismMatchesBugClass(template, bugClass) {
  if (!isPlainObject(template)) return 0;
  const target = normalizeMatchToken(bugClass);
  if (!target) return 0;
  const tokens = new Set();
  for (const field of [template.mechanism_id, template.id, template.name]) {
    const t = normalizeMatchToken(field);
    if (t) tokens.add(t);
  }
  if (Array.isArray(template.required_entities)) {
    for (const entity of template.required_entities) {
      const t = normalizeMatchToken(entity);
      if (t) tokens.add(t);
    }
  }
  for (const token of tokens) {
    if (token === target || token.includes(target) || target.includes(token)) return 1;
  }
  return 0;
}

// CHAINING potential: a mechanism whose effect feeds a transition edge is
// front-loaded (its effect is a chain link). The evidence_predicate's
// required_edges are the chaining tokens; a cross-surface/transition effect
// earns a higher chaining factor than a purely local one. Returns >= 1.
function mechanismChainingFactor(template) {
  if (!isPlainObject(template)) return 1;
  const predicate = template.evidence_predicate;
  if (!isPlainObject(predicate)) return 1;
  const edges = Array.isArray(predicate.required_edges) ? predicate.required_edges : [];
  if (edges.length === 0) return 1;
  // 1 + a bounded contribution per chaining edge so a multi-hop mechanism ranks
  // above a single-hop one, without a single template dominating the order.
  return 1 + Math.min(edges.length, 3);
}

// The composite per-cell mechanism lift over a registry: SUM over every
// template that MATCHES this bug_class of (tier_weight x chaining). The sum (not
// max) so a cell touched by several applicable mechanisms ranks above one
// touched by a single mechanism — more mechanism surface area = dispatch first.
// PURE: `templates` is the caller-merged registry passed via opts.belief.
function mechanismCellLift(templates, bugClass) {
  if (!Array.isArray(templates) || templates.length === 0) return 0;
  let lift = 0;
  for (const template of templates) {
    if (mechanismMatchesBugClass(template, bugClass) !== 1) continue;
    lift += mechanismTierWeight(template) * mechanismChainingFactor(template);
  }
  return lift;
}

// Deduped registry view: collapse near-identical templates to one entry by
// mechanismDedupKey (first occurrence wins). Every DISTINCT mechanism survives
// (rank-not-bound); only redundant duplicates are folded so the axis does not
// spawn two agent-states for the same mechanism. A template with no resolvable
// key is kept (it cannot be proven a duplicate, so it is never dropped).
function dedupeMechanismTemplates(templates) {
  if (!Array.isArray(templates)) return [];
  const seen = new Set();
  const out = [];
  for (const template of templates) {
    if (!isPlainObject(template)) continue;
    const key = mechanismDedupKey(template);
    if (key === null) {
      out.push(template);
      continue;
    }
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(template);
  }
  return out;
}

// Canonical planning key over the (bug_class, auth_profile) axes for a single
// surface. JSON-array form (same idiom as coverageRecordKey) so a value
// containing the separator can never collide.
// The caller derives the "already-covered" key set from the coverage summary
// and passes it in for pruning; this keeps the deriver pure (no ledger reads).
function fanoutPlanningKey(bugClass, authProfile) {
  return JSON.stringify([bugClass, authProfile || ""]);
}

// Belief-ordering overlay for the fan-out children. Default-off and
// permute-never-filter: given the eligible (bug_class x auth_role) cells in
// deterministic baseline order, return a STABLE permutation ranked by their
// belief score (higher first), or the input UNCHANGED when belief is disabled
// or supplies no usable signal. The SET is invariant — only the order changes —
// so the downstream max_children cut emits a top-k of the same set and the
// residual spills through the always-on floor.
//
// PURE per X-P4: every belief input is passed in via `belief`. The honest
// signal is per-surface (the existing buildCellBeliefRank scores a cell from its
// PARENT surface), so within one surface's children it is uniform — a stable
// no-op permutation. A caller that already holds a per-cell score map (e.g. a
// cross-surface ranking, or a test) may inject `belief.score_by_planning_key`
// to discriminate among siblings; the same stable-sort machinery applies. Both
// paths reuse buildCellBeliefRank's contract (RAISE-only, score>0 ranks).
function orderEligibleByBelief(eligible, parentSurfaceId, belief) {
  if (!isPlainObject(belief) || belief.enabled !== true) return eligible;
  if (eligible.length <= 1) return eligible;

  // The open mechanism registry (corpus tier-2 + registered tier-3 candidates),
  // deduped so near-identical templates collapse to one ranking contribution.
  // Read by the impure caller (getMechanismTemplatesForDomain) and passed in —
  // this function stays pure. Empty/absent => no mechanism lift (the score path
  // below degrades to the planning-key-only behavior, byte-identical).
  const mechanismTemplates = dedupeMechanismTemplates(
    Array.isArray(belief.mechanism_templates) ? belief.mechanism_templates : [],
  );

  // Resolve a planning_key -> score map. Prefer a directly-injected per-cell map
  // (caller already ran the ranker); otherwise reuse buildCellBeliefRank with
  // CALLER-PROVIDED surfaces (no I/O — purity holds) over per-child cell
  // candidates keyed on the planning_key.
  let scoreByPlanningKey = null;
  if (belief.score_by_planning_key instanceof Map) {
    scoreByPlanningKey = belief.score_by_planning_key;
  } else if (Array.isArray(belief.surfaces)) {
    try {
      const { buildCellBeliefRank } = require("../belief/cell-scheduler-priority.js");
      const candidates = eligible.map((cell) => ({
        kind: "cell",
        node_id: cell.planning_key,
        surface_refs: [cell.surface_id || parentSurfaceId],
      }));
      const rank = buildCellBeliefRank({
        target_domain: belief.target_domain,
        document: { nodes: candidates },
        candidates,
        surfaces: belief.surfaces,
        seed: belief.seed,
        rank_limit: belief.rank_limit,
      });
      scoreByPlanningKey = rank instanceof Map ? rank : null;
    } catch {
      scoreByPlanningKey = null;
    }
  }
  // The overlay reorders when EITHER signal is live: the surface-belief
  // planning-key map OR the mechanism-template registry. With neither, there is
  // nothing to rank by, so the deterministic baseline order stands (byte-
  // identical to flag-off).
  const haveSurfaceScore = scoreByPlanningKey instanceof Map && scoreByPlanningKey.size > 0;
  const haveMechanismLift = mechanismTemplates.length > 0;
  if (!haveSurfaceScore && !haveMechanismLift) {
    return eligible;
  }

  // For a mechanism-axis cell (one carrying a mechanism_template_id), the lift is
  // its OWN template's tier x chaining, so a tier-1/tier-2 mechanism cell front-
  // loads above a tier-3 candidate cell for the same bug_class. A base cell (no
  // mechanism id) gets the AGGREGATE lift over every applicable template. This is
  // what makes dispatch belief-ORDERED over the trust gradient: oracle > tier-2 >
  // tier-3, times match, times chaining.
  const templatesById = new Map();
  if (haveMechanismLift) {
    for (const template of mechanismTemplates) {
      if (isPlainObject(template) && typeof template.id === "string") {
        templatesById.set(template.id, template);
      }
    }
  }
  const liftForCell = (cell) => {
    if (!haveMechanismLift) return 0;
    if (typeof cell.mechanism_template_id === "string") {
      const template = templatesById.get(cell.mechanism_template_id);
      if (!template) return 0;
      return mechanismTierWeight(template) * mechanismChainingFactor(template);
    }
    return mechanismCellLift(mechanismTemplates, cell.bug_class);
  };

  // Stable permutation: rank by score DESC, ties broken by the baseline index so
  // equal-score cells keep their deterministic relative order. A cell with no
  // entry scores 0 (RAISE-only: never pushed below a deterministic peer it tied
  // with, only kept where unranked cells already sit relative to each other).
  // The per-cell score sums the surface-belief score (if any) with the mechanism
  // lift. Both are RAISE-only and additive — a cell touched by a hotter surface
  // AND a high-tier chaining mechanism ranks above one touched by neither.
  const indexed = eligible.map((cell, index) => ({
    cell,
    index,
    score: (haveSurfaceScore ? (scoreByPlanningKey.get(cell.planning_key) || 0) : 0)
      + liftForCell(cell),
  }));
  indexed.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.index - b.index;
  });
  return indexed.map((entry) => entry.cell);
}

// deriveChildFanoutPlan — the brain-owned, host-agnostic decomposition of a
// surface into bounded (bug_class x auth_role) child cells. Consumed two ways
// (the host muscle, not the brain, decides which): a fanning-out per-surface
// evaluator spawns each child as a nested subagent where the host supports
// nesting (Claude depth-5, Codex agents.max_depth), OR the orchestrator
// enqueues them as extra flat wave assignments where it does not (Kimi,
// generic-mcp).
//
// PURE per X-P4 (this lives below the divider; the load-time lint guard
// enforces it). Every input is passed in:
//   parentSurfaceId  — the REAL materialized surface id (never synthetic);
//                      children key on it + (bug_class, auth_profile) so the
//                      coverage / technique-attempt validators still bind.
//   surfaceMetadata  — the surface's graph metadata, for the capability pack /
//                      child allowed_tools_for_node (null -> default pack).
//   options.bug_class_hints — the bug-class axis (surface field, pre-capped 20).
//   options.auth_profiles   — the auth-role axis: REDACTED profile names from
//                      bob_list_auth_profiles. Empty -> single unauth baseline.
//   options.budget   — { remaining_depth, max_children }. remaining_depth <= 0
//                      means this node is a leaf (no recursive fan-out).
//   options.covered_cell_keys — planning keys (fanoutPlanningKey form) for
//                      cells already terminally covered; pruned from the plan.
function deriveChildFanoutPlan(parentSurfaceId, surfaceMetadata, options) {
  if (typeof parentSurfaceId !== "string" || parentSurfaceId.length === 0) {
    throw new Error("deriveChildFanoutPlan: parentSurfaceId must be a non-empty string");
  }
  const opts = isPlainObject(options) ? options : {};
  const budget = isPlainObject(opts.budget) ? opts.budget : {};
  const remainingDepth = Number.isInteger(budget.remaining_depth) ? budget.remaining_depth : 0;
  const maxChildrenRaw = Number.isInteger(budget.max_children) ? budget.max_children : 0;
  const maxChildren = Math.max(0, Math.min(maxChildrenRaw, CHILD_FANOUT_HARD_CAP));

  const bugClasses = dedupeSorted(asStringArray(opts.bug_class_hints)).slice(0, CHILD_FANOUT_BUG_CLASS_CAP);
  let authAxis = dedupeSorted(asStringArray(opts.auth_profiles));
  if (authAxis.length === 0) authAxis = [""];
  const coveredKeys = new Set(asStringArray(opts.covered_cell_keys));

  // Route the child allow-list off the parent's routability, not a bare pack
  // id. An UNROUTABLE parent (a smart_contract with a missing/unsupported
  // chain_family) is NEVER laundered into the web pack: it yields the read-only
  // evaluator-shared baseline and NO capability_pack id on its children,
  // mirroring deriveSurfacePack's routable:false stance. packIdForSurfaceMetadata
  // returns "web" for both a genuine web parent (correct) and an unroutable SC
  // (wrong), so routabilityForSurfaceMetadata is the discriminator.
  const r = routabilityForSurfaceMetadata(surfaceMetadata || null);
  const packId = r.routable === true ? r.pack_id : null;
  const allowedToolsForChild = r.routable === true
    ? dedupeSorted(toolsForCapabilityPack(r.pack_id))
    : dedupeSorted(toolsForUnroutableSurface(r));
  const childCapabilityPackIds = r.routable === true
    ? Object.freeze([packId])
    : Object.freeze([]);

  // The open mechanism registry (corpus tier-2 + registered tier-3 candidates),
  // deduped so near-identical templates collapse to one axis entry. Read by the
  // impure caller (getMechanismTemplatesForDomain) and passed via opts.belief —
  // this function stays pure. Only consulted when belief is enabled with a
  // registry; otherwise the axis is empty and the plan is byte-identical to the
  // deterministic baseline.
  const mechanismRegistry = (isPlainObject(opts.belief)
    && opts.belief.enabled === true
    && Array.isArray(opts.belief.mechanism_templates))
    ? dedupeMechanismTemplates(opts.belief.mechanism_templates)
    : [];

  // Collect EVERY eligible (bug_class x auth_role) cell first — relevance- and
  // covered-pruned in the deterministic bug_class-outer/auth-inner baseline
  // order — BEFORE applying the max_children cut. Decoupling enumeration from
  // truncation is what lets the optional belief overlay PERMUTE the eligible set
  // and still keep the emitted SET a subset of the same baseline set: the cut is
  // a stable top-k of a permutation, never a filter on a different set.
  const eligible = [];
  let coveredPruned = 0;
  let budgetPruned = 0;
  let relevancePruned = 0;
  const leaf = remainingDepth <= 0 || maxChildren <= 0 || bugClasses.length === 0;
  if (!leaf) {
    for (const bugClass of bugClasses) {
      // Reachability/type gate: drop a bug_class that cannot structurally occur
      // on this surface's class (e.g. reentrancy on web). Fail-open, so only
      // the impossible is pruned — the floor stays reachable, not a blind cross-
      // product.
      if (!isBugClassRelevantForSurface(surfaceMetadata, bugClass)) {
        relevancePruned += authAxis.length;
        continue;
      }
      for (const authProfile of authAxis) {
        const planningKey = fanoutPlanningKey(bugClass, authProfile);
        const authLabel = authProfile || "anonymous";
        // Per-cell weapon: the technique pack(s) that target this bug_class,
        // adopted additively over the base surface pack (the cell's specialized
        // weapon vs the shared evaluator toolset).
        const techniquePackIds = weaponForBugClass(bugClass);
        // The base (bug_class x auth) cell. Covered => pruned, but its mechanism
        // cells below are DISTINCT coverage obligations and are enumerated
        // independently (covering the broad cell never retires the open mechanism
        // axis).
        if (coveredKeys.has(planningKey)) {
          coveredPruned += 1;
        } else {
          eligible.push(Object.freeze({
            // coverage-shaped key (method/endpoint runtime-filled => "") so a
            // downstream bob_log_coverage cell on this child reconciles 1:1.
            cell_key: JSON.stringify([parentSurfaceId, "", "", bugClass, authProfile || ""]),
            planning_key: planningKey,
            surface_id: parentSurfaceId,
            bug_class: bugClass,
            auth_profile: authProfile || "",
            capability_pack_ids: childCapabilityPackIds,
            allowed_tools_for_node: Object.freeze(allowedToolsForChild.slice()),
            technique_pack_ids: Object.freeze(techniquePackIds.slice()),
            rationale: `Uncovered ${bugClass} cell under ${authLabel} on ${parentSurfaceId}`,
          }));
        }

        // Open-registry axis: each (this cell x applicable registered mechanism)
        // is ALSO a cell candidate, so the cell-floor's fixpoint covers the WHOLE
        // mechanism space — corpus templates AND tier-3 candidates — by spawning
        // MORE agent-states (each a bounded window slice; the UNION is exhaustive),
        // never a top-K cut. The mechanism rides in the bug_class slot as a
        // composite token (bug_class@@mechanism_id) so the 5-slot cell_key shape
        // stays valid and reconciles DISJOINT from the base cell and from every
        // other mechanism. A mechanism that does not structurally apply is skipped
        // (no false fan-out); a distinct applicable mechanism is NEVER dropped.
        for (const template of mechanismRegistry) {
          if (mechanismMatchesBugClass(template, bugClass) !== 1) continue;
          const mechanismToken = mechanismDedupKey(template);
          if (mechanismToken === null) continue;
          const compositeBugClass = `${bugClass}@@${mechanismToken}`;
          const mechanismPlanningKey = fanoutPlanningKey(compositeBugClass, authProfile);
          if (coveredKeys.has(mechanismPlanningKey)) {
            coveredPruned += 1;
            continue;
          }
          eligible.push(Object.freeze({
            cell_key: JSON.stringify([parentSurfaceId, "", "", compositeBugClass, authProfile || ""]),
            planning_key: mechanismPlanningKey,
            surface_id: parentSurfaceId,
            bug_class: bugClass,
            auth_profile: authProfile || "",
            mechanism_template_id: typeof template.id === "string" ? template.id : null,
            mechanism_tier: Number.isInteger(template.tier) ? template.tier : 3,
            capability_pack_ids: childCapabilityPackIds,
            allowed_tools_for_node: Object.freeze(allowedToolsForChild.slice()),
            technique_pack_ids: Object.freeze(techniquePackIds.slice()),
            rationale: `Uncovered ${bugClass} cell under ${authLabel} on ${parentSurfaceId} via mechanism ${template.id || mechanismToken}`,
          }));
        }
      }
    }
  }

  // Belief-ORDER overlay (default-off). When an operator opts into
  // belief-assisted priority, dispatch the higher-belief cells first by
  // PERMUTING `eligible` — same SET, reordered. This ONLY changes which cells
  // survive the max_children cut; the lower-ranked residual is counted in
  // budget_pruned_count exactly as a deterministic cut would, and the
  // always-on cell floor re-emits those uncovered cells to a later wave (the
  // existing generic/Kimi spill path), so the floor still reaches fixpoint.
  // Flag off => no permutation => byte-identical to the deterministic baseline.
  // The overlay can never gate a cell: it reorders, never drops or skips.
  const orderedEligible = orderEligibleByBelief(eligible, parentSurfaceId, opts.belief);

  // Apply the (post-permutation) budget cut. The first maxChildren survive as
  // emitted children; the rest become budget_pruned (the spill the floor re-emits).
  const children = orderedEligible.slice(0, maxChildren);
  budgetPruned = orderedEligible.length - children.length;

  return Object.freeze({
    parent_surface_id: parentSurfaceId,
    remaining_depth: remainingDepth,
    max_children: maxChildren,
    capability_pack: packId,
    children: Object.freeze(children), // X.6 — packId is null for an unroutable parent (evaluator-shared baseline)
    covered_pruned_count: coveredPruned,
    budget_pruned_count: budgetPruned,
    relevance_pruned_count: relevancePruned,
    rationale: leaf
      ? (remainingDepth <= 0
        ? "depth budget exhausted — leaf evaluator, no recursive fan-out"
        : "no fan-out — empty bug-class axis or zero child budget")
      : `fan out ${children.length} (bug_class x auth_role) child cell(s) on ${parentSurfaceId}`,
  });
}

// A transition-cell's coverage-shaped cell_key (A2). Same 5-slot shape as a
// surface cell — so cellNodeId's cell_key hash and bob_log_coverage reconcile
// work unchanged — but the surface slot carries the EDGE TOKEN and there is no
// auth slot (a cross-surface invariant is auth-agnostic).
function transitionCellKey(edgeToken, bugClass) {
  return JSON.stringify([edgeToken, "", "", bugClass, ""]);
}

// planTransitionCellsForEdge — the brain-owned decomposition of one transition
// EDGE into bounded (edge x bug_class) child cells. A sibling of
// deriveChildFanoutPlan with two deliberate differences: NO relevance gate (the
// bug_class axis is already derived from the transition KIND, so every entry is
// structurally relevant to that trust hop) and NO auth axis (the planning key
// keys on (bug_class, "")). PURE per X-P4: the edge token, axis, and covered set
// are all passed in (the non-pure caller computes the deterministic edge token).
function planTransitionCellsForEdge(edgeToken, options) {
  if (typeof edgeToken !== "string" || edgeToken.length === 0) {
    throw new Error("planTransitionCellsForEdge: edgeToken must be a non-empty string");
  }
  const opts = isPlainObject(options) ? options : {};
  const maxChildrenRaw = Number.isInteger(opts.max_children) ? opts.max_children : 0;
  const maxChildren = Math.max(0, Math.min(maxChildrenRaw, CHILD_FANOUT_HARD_CAP));
  const bugClasses = dedupeSorted(asStringArray(opts.bug_class_axis)).slice(0, CHILD_FANOUT_BUG_CLASS_CAP);
  const coveredKeys = new Set(asStringArray(opts.covered_cell_keys));

  const children = [];
  let coveredPruned = 0;
  let budgetPruned = 0;
  const leaf = maxChildren <= 0 || bugClasses.length === 0;
  if (!leaf) {
    for (const bugClass of bugClasses) {
      const planningKey = fanoutPlanningKey(bugClass, "");
      if (coveredKeys.has(planningKey)) {
        coveredPruned += 1;
        continue;
      }
      if (children.length >= maxChildren) {
        budgetPruned += 1;
        continue;
      }
      children.push(Object.freeze({
        cell_key: transitionCellKey(edgeToken, bugClass),
        planning_key: planningKey,
        surface_id: edgeToken,
        bug_class: bugClass,
        auth_profile: "",
        capability_pack_ids: Object.freeze([]),
        technique_pack_ids: Object.freeze(weaponForBugClass(bugClass).slice()),
        rationale: `Uncovered ${bugClass} cross-surface invariant on ${edgeToken}`,
      }));
    }
  }
  return Object.freeze({
    edge_token: edgeToken,
    max_children: maxChildren,
    children: Object.freeze(children),
    covered_pruned_count: coveredPruned,
    budget_pruned_count: budgetPruned,
  });
}

function deriveTransitionPack(node, graph_context) {
  // Transition nodes carry TWO surface_refs (the from_surface and to_surface
  // captured by the transition_proposed event). Look both up in the
  // surface_metadata_by_id map to pick each endpoint's capability_pack;
  // UNION the resulting tool sets. An UNROUTABLE endpoint (a smart_contract
  // whose chain_family is missing/unsupported) is NEVER laundered into the web
  // pack — it contributes the read-only evaluator-shared baseline, mirroring
  // deriveSurfacePack's routable:false stance. routabilityForSurfaceMetadata is
  // the discriminator: packIdForSurfaceMetadata returns "web" for BOTH a genuine
  // web endpoint (correct) AND an unroutable SC (wrong), so the pack id alone
  // cannot tell them apart.
  const surfaceRefs = asStringArray(node.surface_refs);
  const endpointPackIds = [];
  const allowedToolSet = new Set();
  for (const surfaceId of surfaceRefs) {
    const metadata = graph_context.surface_metadata_by_id[surfaceId];
    const r = routabilityForSurfaceMetadata(metadata);
    if (r.routable === true) {
      if (!endpointPackIds.includes(r.pack_id)) endpointPackIds.push(r.pack_id);
      for (const tool of toolsForCapabilityPack(r.pack_id)) {
        allowedToolSet.add(tool);
      }
    } else {
      // An unavailable physical endpoint contributes no model tools. Other
      // legacy unroutable types retain their prior shared baseline.
      for (const tool of toolsForUnroutableSurface(r)) {
        allowedToolSet.add(tool);
      }
    }
  }
  // Only the truly-empty-surface_refs case falls back to the web default. An
  // all-unroutable transition (endpoints seen, all routable:false) already
  // carries the evaluator-shared baseline in allowedToolSet and keeps
  // endpointPackIds empty — it must NOT degrade to web.
  if (surfaceRefs.length === 0 && allowedToolSet.size === 0) {
    endpointPackIds.push(DEFAULT_CAPABILITY_PACK_ID);
    for (const tool of toolsForCapabilityPack(DEFAULT_CAPABILITY_PACK_ID)) {
      allowedToolSet.add(tool);
    }
  }
  return {
    capability_pack_ids: endpointPackIds,
    allowed_tools: dedupeSorted(Array.from(allowedToolSet)), // X.6
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
  // Physical is a deny-precedence family while its pack is registered but
  // non-dispatchable. Apply that fact at the final per-node boundary, not just
  // inside deriveSurfacePack: Transition, Hypothesis, and Cell nodes can carry
  // physical refs too, and their other endpoint/Contract/overlay tool unions
  // must not turn a physical-connected node into a web-shaped dispatch.
  const physicalSurfaceRefs = dedupeSorted(
    asStringArray(node.surface_refs).filter((surfaceId) => (
      isPhysicalSurfaceMetadata(ctx.surface_metadata_by_id[surfaceId])
    )),
  );
  const physicalDispatchBlocked = physicalSurfaceRefs.length > 0;
  const quarantinedSurfaceRefs = dedupeSorted(
    asStringArray(node.surface_refs).filter((surfaceId) => (
      routabilityForSurfaceMetadata(ctx.surface_metadata_by_id[surfaceId]).dispatch_blocked === true
    )),
  );
  const hardDispatchBlocked = physicalDispatchBlocked || quarantinedSurfaceRefs.length > 0;

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
  } else if (kind === "cell") {
    // A surface cell (element x bug_class x auth_role) carries the evaluator-shared
    // baseline. A TRANSITION cell is grounded in a cross-surface EDGE — its node
    // carries surface_refs = [from, to], and its correct work spans BOTH stacks, so
    // its allow-list must UNION both endpoints' packs exactly as a transition NODE
    // does (deriveTransitionPack). Without this a web->EVM transition cell gets only
    // the web baseline (no bob_evm_*), so the cell agent's honest cross-stack work is
    // rejected by the X.6 tool_constraint_violation check at bob_finalize_node.
    if (asStringArray(node.surface_refs).length >= 2) {
      const tp = deriveTransitionPack(node, ctx);
      perKind = {
        capability_pack_ids: tp.capability_pack_ids,
        allowed_tools: tp.allowed_tools,
        brief_emphasis: { ...tp.brief_emphasis, node_kind: "cell" },
      };
    } else {
      perKind = {
        capability_pack_ids: [],
        allowed_tools: dedupeSorted(toolNamesForRoleBundle("evaluator-shared")),
        brief_emphasis: { node_kind: "cell" },
      };
    }
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
  const primarySurfaceId = asStringArray(node.surface_refs)[0];
  const primaryMeta = primarySurfaceId ? ctx.surface_metadata_by_id[primarySurfaceId] : null;
  const routeConfidence = isPlainObject(primaryMeta) && typeof primaryMeta.confidence === "string"
    ? primaryMeta.confidence
    : null;
  const widenThreshold = widenThresholdForConfidence(routeConfidence);
  const frictionOccurrenceCount = new Map();
  for (const record of frictionHistory) {
    if (!isPlainObject(record)) continue;
    if (typeof record.wanted_tool === "string" && record.wanted_tool.length > 0) {
      frictionOccurrenceCount.set(
        record.wanted_tool,
        (frictionOccurrenceCount.get(record.wanted_tool) || 0) + 1,
      );
    }
  }
  const frictionWantedTools = [];
  for (const [wantedTool, count] of frictionOccurrenceCount) {
    // Y-P16 — confidence modulates friction-widening eagerness: a wanted_tool
    // joins the pack only once its occurrence count clears the confidence
    // threshold (low/absent=1 eager default, medium=2, high=2). This only ADDS
    // friction-derived tools; it never removes a tool that clears its threshold.
    if (count >= widenThreshold) {
      frictionWantedTools.push(wantedTool);
    }
  }
  const targetClassAuxTools = targetClass && !hardDispatchBlocked
    ? deriveAuxiliaryToolsForTargetClass(targetClass).slice()
    : [];
  // PACK-level friction widening (Y-P6). A chronic deficiency observed on ANY
  // surface routed to this node's own capability pack(s) widens the pack for
  // EVERY sibling surface. The aggregate is the caller-side pack-friction
  // rollup keyed by capability_pack id → { wanted_tool → { count, surface_ids } }
  // (built caller-side; the deriver stays pure). A tool joins only once its
  // cross-surface count clears PACK_FRICTION_CHRONIC_MIN_COUNT (noise floor); an
  // unroutable node has an empty `capability_pack_ids` so the lookup returns
  // nothing and the node keeps its evaluator-shared baseline — no web fallback.
  // Widening only ADDS: the final dedupeSorted union collapses a tool wanted
  // both per-surface and pack-level to a single entry.
  const packFrictionAggregate = isPlainObject(opts.pack_friction_aggregate)
    ? opts.pack_friction_aggregate
    : null;
  const packWidenedToolSet = new Set();
  if (packFrictionAggregate && !hardDispatchBlocked) {
    for (const packId of perKind.capability_pack_ids) {
      const toolBuckets = packFrictionAggregate[packId];
      if (!isPlainObject(toolBuckets)) continue;
      for (const [wantedTool, bucket] of Object.entries(toolBuckets)) {
        if (typeof wantedTool !== "string" || wantedTool.length === 0) continue;
        // Chronic = deficient across MULTIPLE surfaces of the pack, not one
        // surface hitting friction repeatedly. Gate on the count of DISTINCT
        // surface_ids so a single surface's repeated friction never widens the
        // whole pack for its siblings.
        const surfaceCount = isPlainObject(bucket) && Array.isArray(bucket.surface_ids)
          ? bucket.surface_ids.length
          : 0;
        if (surfaceCount >= PACK_FRICTION_CHRONIC_MIN_COUNT) {
          packWidenedToolSet.add(wantedTool);
        }
      }
    }
  }
  const packWidenedTools = Array.from(packWidenedToolSet).sort();
  const unionedAllowedTools = hardDispatchBlocked
    ? []
    : dedupeSorted([
      ...perKind.allowed_tools,
      ...frictionWantedTools,
      ...targetClassAuxTools,
      ...packWidenedTools,
    ]);
  const resultTechniquePacks = hardDispatchBlocked ? [] : techniquePacks;
  const resultCapabilityPackIds = hardDispatchBlocked
    ? []
    : perKind.capability_pack_ids.slice();
  const resultBriefEmphasis = physicalDispatchBlocked
    ? {
      ...perKind.brief_emphasis,
      capability_pack: null,
      endpoint_capability_packs: [],
      capability_pack_ids: [],
      required_capability_pack: PHYSICAL_CAPABILITY_PACK.id,
      required_capability_pack_version: PHYSICAL_CAPABILITY_PACK.capability_pack_version,
      routable: false,
      physical_dispatch_blocked: true,
      physical_surface_refs: physicalSurfaceRefs,
    }
    : quarantinedSurfaceRefs.length > 0
      ? {
        ...perKind.brief_emphasis,
        capability_pack: null,
        endpoint_capability_packs: [],
        capability_pack_ids: [],
        routable: false,
        route_metadata_blocked: true,
        blocked_surface_refs: quarantinedSurfaceRefs,
      }
      : {
      ...perKind.brief_emphasis,
      capability_pack_ids: resultCapabilityPackIds,
      };

  return Object.freeze({
    technique_packs: Object.freeze(resultTechniquePacks),
    cli_tool_packs: Object.freeze([]),
    allowed_tools_for_node: Object.freeze(unionedAllowedTools),
    recommended_reads_for_node: Object.freeze(recommendedReads),
    brief_emphasis: Object.freeze({
      ...resultBriefEmphasis,
      technique_pack_ids: hardDispatchBlocked ? [] : Array.from(techniquePackIds).sort(),
      target_class: targetClass,
      friction_history_count: frictionHistory.length,
      pack_friction_widened_tools_count: packWidenedTools.length,
      pack_friction_widened_tools: packWidenedTools.slice(),
      route_confidence: routeConfidence,
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
      + "the lint guard expects this module to live at mcp/core/capability/capability-pack-derivation.js.",
    );
  }
})();

module.exports = {
  DEFAULT_CAPABILITY_PACK_ID,
  EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK,
  FRICTION_HISTORY_HARD_CAP,
  PACK_FRICTION_CHRONIC_MIN_COUNT,
  FRICTION_WIDEN_THRESHOLD_BY_CONFIDENCE,
  widenThresholdForConfidence,
  RECOMMENDED_READS_HARD_CAP,
  RECOMMENDED_READS_PER_SURFACE,
  WEB3_IDENTITY_HANDOFF_PACK_ID,
  CHILD_FANOUT_HARD_CAP,
  CHILD_FANOUT_BUG_CLASS_CAP,
  routabilityForSurfaceMetadata,
  buildOneHopGraphContext,
  derivePackForNode,
  deriveChildFanoutPlan,
  planTransitionCellsForEdge,
  transitionCellKey,
  fanoutPlanningKey,
  mechanismDedupKey,
  mechanismTierWeight,
  mechanismMatchesBugClass,
  mechanismChainingFactor,
  mechanismCellLift,
  dedupeMechanismTemplates,
};
