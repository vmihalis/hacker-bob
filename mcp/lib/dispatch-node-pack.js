"use strict";

// Single-source the dispatch-node pack derivation that bob_prepare_node and
// bob_finalize_node share. Reading the routes into surface metadata, building
// the ≤1-hop graph context, and calling the pure derivePackForNode in ONE place
// makes the X.6 invariant — finalize re-derives the SAME allowed_tools_for_node[]
// prepare briefed — hold by construction rather than by two hand-duplicated
// copies happening to match.
//
// This is a LEAF module: it is required by the prepare/finalize tools and
// requires the routes reader (surface-router) + the pure deriver
// (capability-pack-derivation), neither of which requires it back. Living here
// (rather than in surface-router) keeps both requires at top scope without a
// load-time cycle — surface-router → capability-pack-derivation → technique-packs
// → surface-router would otherwise close a cycle, which no lazy require may hide.

const {
  readSurfaceRoutesStrict,
} = require("./surface-router.js");
const {
  buildOneHopGraphContext,
  derivePackForNode,
} = require("./capability-pack-derivation.js");

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
  // readSurfaceRoutesStrict is now tolerant: it QUARANTINES stale/duplicate routes (it used to throw,
  // which the catch above turned into a silent empty {} — losing ALL routes). The valid routes survive
  // in doc.routes; the quarantined ones are omitted from this metadata map. Surface a diagnostic so a
  // fully- or partially-corrupt routing artifact is not silently indistinguishable from "no routes were
  // set up". This map only enriches one-hop graph context, so we degrade gracefully (no throw) — unlike
  // getContextBudget/findRoutedSurface, where a wrong/missing route must hard-fail the operation.
  if (Array.isArray(result.malformed_routes) && result.malformed_routes.length > 0) {
    const quarantinedIds = result.malformed_routes
      .map((m) => (m && m.surface_id) || `routes[${m && m.index}]`)
      .join(", ");
    process.stderr.write(
      `WARNING: surface-routes.json has ${result.malformed_routes.length} quarantined route(s) [${quarantinedIds}] omitted from the surface metadata map; re-run bob_route_surfaces to regenerate (${doc.routes.length} valid route(s) retained).\n`,
    );
  }
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

// Derive the per-node pack the same way for both prepare and finalize.
// `surfaceMetadataById` may be passed pre-computed so a caller that already read
// the routes for another purpose (finalize's cross-stack mechanism gate) does
// not read surface-routes.json — or re-emit its quarantine WARNING — twice.
function deriveDispatchNodePack({ targetDomain, document, nodeId, node, contract, surfaceMetadataById }) {
  const metadata = surfaceMetadataById != null ? surfaceMetadataById : safeSurfaceRouteMap(targetDomain);
  const graphContext = buildOneHopGraphContext(document, nodeId, metadata);
  const pack = derivePackForNode(node, graphContext, [], contract);
  return { pack, graphContext, surfaceMetadataById: metadata };
}

module.exports = {
  safeSurfaceRouteMap,
  deriveDispatchNodePack,
};
