"use strict";

// Plane Y Cycle Y.5 — Wave-scheduler derivation helper.
//
// Y.5 wires the per-node capability-pack derivation (Y.4 / X.5) into the
// wave-side assignment brief. For each Surface/Claim wave assignment the
// scheduler builds the real Surface node (`surfaceNodeId(surfaceId)`,
// `kind: "surface"`, `surface_refs: [surfaceId]`) and a wave-scoped ≤1-hop
// graph context (Y-P5) whose `surface_metadata_by_id[surfaceId]` carries the
// routed surface metadata — crucially `chain_family` — so `deriveSurfacePack`
// routes an EVM/SVM/Move/Substrate/CosmWasm surface to its chain pack instead
// of the DEFAULT web pack. It threads `friction_history` (Y-P6) and
// `target_class` (rev-4 O5), then calls the pure `derivePackForNode`. The
// caller (assignment-brief.js readAssignmentBrief) consumes the bounded
// result to (a) extend the brief's allowed-tools surface via the Y-P6
// friction widening, and (b) carry target-class auxiliaries (e.g.,
// phishing_fraud → public_intel + 3 browser tools) into the brief's
// allowed_tools_for_node[].
//
// `derivePackForNode` itself is PURE (Y-P4). All non-pure work
// (filesystem reads for surface routes, friction events, and queue policy)
// happens here, in the caller side, mirroring the friction-selection.js /
// target-class-pack-derivation.js layering. The helper exports
// `buildWaveBriefDerivation` which the brief renderer invokes with
// already-loaded session artifacts.

const fs = require("fs");

const {
  derivePackForNode,
} = require("./capability-pack-derivation.js");
const {
  selectRelevantFrictions,
} = require("./friction-selection.js");
const {
  assertTargetClass,
  TARGET_CLASS_VALUES,
} = require("./target-classes.js");
const {
  deriveAuxiliaryToolsForTargetClass,
} = require("./target-class-pack-derivation.js");
const {
  surfaceNodeId,
} = require("./task-graph-materializer.js");
const {
  readSurfaceRoutesStrict,
} = require("./surface-router.js");
const {
  queuePolicyPath,
} = require("./paths.js");
const {
  aggregateFrictionByPack,
  capabilityFrictionPayloads,
} = require("./frontier-events.js");
const {
  FRICTION_KIND_VALUES,
} = require("./capability-observations.js");
const {
  deriveSurfaceIdToPack,
} = require("./pipeline-analytics.js");

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

// Filter the frontier-event log down to capability_friction_observed
// payloads matching the assignment surface. Returns plain payloads — the
// `surface_id` field is required so friction-selection can wave-scope.
// Delegates to the shared capabilityFrictionPayloads predicate; the explicit
// non-string/empty surfaceId guard yields [] here (an omitted surfaceId means
// GLOBAL in the shared helper, so this call site keeps its per-surface intent).
function frictionPayloadsForSurface(frontierEvents, surfaceId) {
  if (typeof surfaceId !== "string" || surfaceId.length === 0) return [];
  return capabilityFrictionPayloads(frontierEvents, { surfaceId });
}

// Read the raw queue-policy JSON for the target without going through
// loadQueuePolicy's normalizer. The normalizer (mcp/lib/queue-policy.js)
// drops fields it does not yet know about; the rev-4 `target_class_default`
// field lands in Y.6 schema-side. Until Y.6 lands its writer, the
// caller-side resolver must read the raw file to surface the field that
// the (future) writer would set. Returns null on any I/O / parse failure
// so the brief composer never aborts.
function readRawQueuePolicy(domain) {
  if (typeof domain !== "string" || domain.length === 0) return null;
  let filePath;
  try { filePath = queuePolicyPath(domain); } catch { return null; }
  if (!fs.existsSync(filePath)) return null;
  let raw;
  try { raw = fs.readFileSync(filePath, "utf8"); } catch { return null; }
  try { return JSON.parse(raw); } catch { return null; }
}

// Resolve `target_class` per Y.5 Do step 1:
//   1. explicit `args.target_class` (caller override; not currently routed
//      through readAssignmentBrief but exposed here so future per-call
//      overrides need no helper edit)
//   2. queue-policy `target_class_default` from the raw JSON (Y.6 lands
//      the schema validator + writer; reading raw lets Y.5 surface the
//      value the moment Y.6's writer ships, with zero further edits)
//   3. null (the derivation function treats null as "no target_class
//      threading" — Y-P4 closed-enum default)
function resolveTargetClassForBrief({ explicitTargetClass, queuePolicy }) {
  if (typeof explicitTargetClass === "string" && explicitTargetClass.length > 0) {
    return assertTargetClass(explicitTargetClass);
  }
  if (isPlainObject(queuePolicy)) {
    const raw = queuePolicy.target_class_default;
    if (typeof raw === "string" && raw.length > 0) {
      // Defensive: queue-policy may carry a stale value that no longer
      // satisfies assertTargetClass (e.g., an operator hand-edit). Skip
      // rather than throw — the brief still composes without the axis.
      if (TARGET_CLASS_VALUES.includes(raw)) return raw;
    }
  }
  return null;
}

// Build the `surface_metadata_by_id` map the deriver keys on
// (`graph_context.surface_metadata_by_id[surface_refs[0]]`), carrying the
// routed surface metadata — crucially `chain_family` — so
// `deriveSurfacePack` routes an EVM/SVM/Move/Substrate/CosmWasm surface to
// its chain pack instead of the DEFAULT web pack. Mirrors the canonical
// `safeSurfaceRouteMap` shape at tools/prepare-node.js: read the routes
// strictly, find the route for this surface, and stamp
// `{ id, surface_type, chain_family, capability_pack, brief_profile }`.
// When routing artifacts are absent OR this surface has no route yet, fall
// back to the same shape from the in-hand assignment surface so the wave
// path still routes. Never throws; returns `{}` only when there is truly
// nothing — an empty map preserves the graceful web fallback
// (`packIdForSurfaceMetadata(null) → DEFAULT_CAPABILITY_PACK_ID`) for
// web/OSS surfaces.
function buildRoutedSurfaceMetadataById(domain, surfaceId, surfaceObj) {
  if (typeof surfaceId !== "string" || surfaceId.length === 0) return {};
  let routes = null;
  try {
    const result = readSurfaceRoutesStrict(domain);
    const doc = result && result.document;
    if (doc && Array.isArray(doc.routes)) routes = doc.routes;
  } catch {
    routes = null;
  }
  if (Array.isArray(routes)) {
    for (const route of routes) {
      if (!route || typeof route !== "object") continue;
      if (route.surface_id !== surfaceId) continue;
      return {
        [surfaceId]: {
          id: surfaceId,
          surface_type: route.surface_type || null,
          chain_family: route.chain_family || null,
          capability_pack: route.capability_pack || null,
          brief_profile: route.brief_profile || null,
          confidence: route.confidence || null,
        },
      };
    }
  }
  // Fall back to the in-hand assignment surface. Pass `chain_family`
  // through faithfully (including null) so an ambiguous smart_contract is
  // never silently routed to web here — the deriver classifies the truth.
  const source = isPlainObject(surfaceObj) ? surfaceObj : {};
  if (source.surface_type == null && source.chain_family == null) return {};
  const metadata = {
    id: surfaceId,
    surface_type: source.surface_type || null,
    chain_family: source.chain_family || null,
    confidence: source.confidence || null,
  };
  if (source.capability_pack != null) metadata.capability_pack = source.capability_pack;
  if (source.brief_profile != null) metadata.brief_profile = source.brief_profile;
  return { [surfaceId]: metadata };
}

// Top-level helper. The brief renderer feeds in already-loaded session
// artifacts; this function performs the pure derivation work + returns a
// bounded summary the renderer adds to the brief JSON.
//
// `queuePolicy` is optional. When omitted, the helper resolves the raw
// queue-policy JSON from `domain` directly — bypassing the normalizer
// that drops the rev-4 `target_class_default` field until Y.6 lands the
// schema-level support. Pass an explicit queuePolicy object only when
// the caller already holds the normalized policy AND has populated
// `target_class_default` on it.
function buildWaveBriefDerivation({
  surfaceObj,
  surfaceId,
  waveNumber,
  frontierEvents,
  queuePolicy,
  domain,
  explicitTargetClass,
  includeInadequacy,
}) {
  const realNode = {
    node_id: surfaceNodeId(surfaceId),
    kind: "surface",
    surface_refs: [surfaceId],
  };
  const allFrictionPayloads = frictionPayloadsForSurface(frontierEvents, surfaceId);
  const frictionHistory = selectRelevantFrictions(
    allFrictionPayloads,
    realNode,
    { include_inadequacy: includeInadequacy === true },
  );
  const effectivePolicy = queuePolicy != null ? queuePolicy : readRawQueuePolicy(domain);
  const targetClass = resolveTargetClassForBrief({ explicitTargetClass, queuePolicy: effectivePolicy });
  // X-P5 — the wave scope IS the ≤1-hop bound: no adjacency walk, the map
  // is keyed only by the single dispatched surface_id.
  const surfaceMetadataById = buildRoutedSurfaceMetadataById(domain, surfaceId, surfaceObj);
  const realGraphContext = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: surfaceMetadataById,
  };
  // PACK-level friction aggregate (caller-side IO; the deriver stays pure).
  // `allFrictionPayloads` above is surface-SCOPED (the per-surface widening
  // input); the pack aggregate needs the GLOBAL friction set so a deficiency
  // observed on a SIBLING surface widens this pack too. Gate with
  // FRICTION_KIND_VALUES (the single authority for the actionable friction
  // kinds). The surface_id → capability_pack join reuses deriveSurfaceIdToPack
  // over the persisted routes (unroutable rows contribute no pack). Both the
  // frontier scan and the routes read are caller-side; aggregateFrictionByPack
  // is pure. Fails open to {} on any read error so the brief still composes.
  let packFrictionAggregate = {};
  try {
    const globalFriction = capabilityFrictionPayloads(frontierEvents, {
      frictionKinds: FRICTION_KIND_VALUES,
    });
    const surfaceIdToPack = deriveSurfaceIdToPack(readSurfaceRoutesStrict(domain).document.routes);
    packFrictionAggregate = aggregateFrictionByPack(globalFriction, surfaceIdToPack);
  } catch {
    packFrictionAggregate = {};
  }
  // X.5 — the primary surface's pack is derived from
  // graph_context.surface_metadata_by_id[surface_refs[0]] (chain_family
  // carried), and the full tool set is surfaced RANKED, not BOUNDED.
  const derivation = derivePackForNode(
    realNode,
    realGraphContext,
    [],
    null,
    {
      friction_history: frictionHistory,
      target_class: targetClass,
      pack_friction_aggregate: packFrictionAggregate,
    },
  );

  // Bounded summary — the renderer adds this to the brief JSON. We
  // surface ONLY the Y.5-added tools (friction-widened wanted_tools +
  // target-class auxiliaries) under `added_tools[]`, NOT the full
  // derivation.allowed_tools_for_node[]. The full union is already
  // present implicitly via per-spawn frontmatter narrowing on the
  // dispatched evaluator shell (Y.5 Do step 5); echoing it back into the
  // brief JSON would (a) inflate the brief budget unnecessarily and
  // (b) re-surface per-pack default tools (e.g., bob_browser_* under the
  // web pack) at brief sites that the lens-specific renderers
  // intentionally suppress (see T.4 browser_workflow lens regression).
  // `added_tools[]` is the load-bearing Y-P6 widening signal; the full
  // pack stays on the role-bundle layer.
  const seenAdded = new Set();
  const addedTools = [];
  for (const record of frictionHistory) {
    if (!isPlainObject(record)) continue;
    if (typeof record.wanted_tool === "string" && record.wanted_tool.length > 0) {
      if (!seenAdded.has(record.wanted_tool)) {
        seenAdded.add(record.wanted_tool);
        addedTools.push(record.wanted_tool);
      }
    }
  }
  const targetClassAuxTools = targetClass
    ? deriveAuxiliaryToolsForTargetClass(targetClass).slice()
    : [];
  for (const tool of targetClassAuxTools) {
    if (!seenAdded.has(tool)) {
      seenAdded.add(tool);
      addedTools.push(tool);
    }
  }
  // Fold in the deriver's pack-friction-widened tools (chronic cross-surface
  // pack deficiencies whose count cleared PACK_FRICTION_CHRONIC_MIN_COUNT).
  // Single-sourced from derivePackForNode's brief_emphasis — the threshold is
  // NOT re-derived here. RANKED not BOUNDED: this only ADDS via the same
  // seenAdded de-dupe, so a tool already surfaced per-surface or via
  // target-class aux is not duplicated.
  const packWidened = Array.isArray(derivation.brief_emphasis && derivation.brief_emphasis.pack_friction_widened_tools)
    ? derivation.brief_emphasis.pack_friction_widened_tools
    : [];
  for (const tool of packWidened) {
    if (typeof tool === "string" && tool.length > 0 && !seenAdded.has(tool)) {
      seenAdded.add(tool);
      addedTools.push(tool);
    }
  }
  addedTools.sort();

  return {
    surface_node_id: realNode.node_id,
    // The routed capability pack id is the routing witness: it confirms an
    // EVM/SVM/Move/Substrate/CosmWasm surface routed to its chain pack instead
    // of the DEFAULT web pack. The pack's full tool union is intentionally NOT
    // inlined here — wave-dispatched evaluators receive it via frontmatter, and
    // surfacing it in the brief would leak cross-lens tools (e.g. the browser
    // driver) into a projection whose task_lens excludes them. `added_tools[]`
    // below carries this brief's widening delta (RANKED not BOUNDED).
    capability_pack: derivation.brief_emphasis && derivation.brief_emphasis.capability_pack
      ? derivation.brief_emphasis.capability_pack
      : null,
    target_class: targetClass,
    friction_history_count: frictionHistory.length,
    friction_history_total_for_surface: allFrictionPayloads.length,
    // `added_tools[]` is the Y-P6 + O5 widening that THIS brief
    // composition contributes on top of the base capability pack. Empty
    // when there is no friction history and no target_class auxiliary
    // surface. Wave-dispatched evaluators receive the full union via
    // frontmatter narrowing (Y.5 Do step 5).
    added_tools: addedTools,
    target_class_auxiliary_tools: targetClassAuxTools,
    // technique_pack_ids surfaces the Y.4 brief_emphasis projection so
    // operators can audit which pack ids the pure derivation chose
    // without re-running it. Bounded (cap inherited from
    // derivePackForNode's per-kind logic).
    technique_pack_ids: derivation.brief_emphasis.technique_pack_ids
      ? derivation.brief_emphasis.technique_pack_ids.slice()
      : [],
  };
}

module.exports = {
  buildWaveBriefDerivation,
  frictionPayloadsForSurface,
  readRawQueuePolicy,
  resolveTargetClassForBrief,
};
