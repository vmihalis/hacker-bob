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
  quarantinedRouteMetadata,
  readSurfaceRoutesStrict,
} = require("../frontier/surface-router.js");
const {
  buildOneHopGraphContext,
  derivePackForNode,
} = require("../capability/capability-pack-derivation.js");
const {
  PHYSICAL_CAPABILITY_PACK,
  isPhysicalSurfaceMetadata,
} = require("../capability/capability-packs.js");
const {
  currentSurfaces,
} = require("../frontier/frontier-projections.js");
const {
  readVerifiedSessionNucleus,
} = require("../governance/governance-store.js");

function surfaceMetadataFromRoute(route) {
  const surfaceId = route && typeof route.surface_id === "string"
    ? route.surface_id
    : null;
  if (!surfaceId) return null;
  // Keep every deny-precedence routing marker. In particular, a provider-
  // neutral surface may retain an ordinary-looking type such as `api` while
  // `surface_class: physical` + `required_capability_pack: physical` carries
  // the authoritative unavailable-family disposition. Dropping those fields
  // here launders that route back through the historical web fallback.
  return {
    id: surfaceId,
    surface_type: route.surface_type || null,
    surface_class: route.surface_class || null,
    chain_family: route.chain_family || null,
    capability_pack: route.capability_pack || null,
    required_capability_pack: route.required_capability_pack || null,
    required_capability_pack_version: route.required_capability_pack_version || null,
    disposition: route.disposition || null,
    reason: route.reason || null,
    brief_profile: route.brief_profile || null,
    confidence: route.confidence || null,
  };
}

function safeSurfaceRouteMap(targetDomain) {
  const map = {};
  const currentById = {};
  try {
    const current = currentSurfaces(targetDomain);
    const surfaces = current && current.document && Array.isArray(current.document.surfaces)
      ? current.document.surfaces
      : [];
    for (const surface of surfaces) {
      if (!surface || typeof surface.id !== "string" || !surface.id) continue;
      currentById[surface.id] = surface;
    }
  } catch {}

  let result = null;
  try {
    result = readSurfaceRoutesStrict(targetDomain);
  } catch {}
  const doc = result && result.document;
  const routes = doc && Array.isArray(doc.routes) ? doc.routes : [];
  // readSurfaceRoutesStrict is now tolerant: it QUARANTINES stale/duplicate routes (it used to throw,
  // which the catch above turned into a silent empty {} — losing ALL routes). The valid routes survive
  // in doc.routes; the quarantined ones are omitted from this metadata map. Surface a diagnostic so a
  // fully- or partially-corrupt routing artifact is not silently indistinguishable from "no routes were
  // set up". This map only enriches one-hop graph context, so we degrade gracefully (no throw) — unlike
  // getContextBudget/findRoutedSurface, where a wrong/missing route must hard-fail the operation.
  if (result && Array.isArray(result.malformed_routes) && result.malformed_routes.length > 0) {
    const quarantinedIds = result.malformed_routes
      .map((m) => (m && m.surface_id) || `routes[${m && m.index}]`)
      .join(", ");
    process.stderr.write(
      `WARNING: surface-routes.json has ${result.malformed_routes.length} quarantined route(s) [${quarantinedIds}] omitted from the surface metadata map; re-run bob_route_surfaces to regenerate (${doc.routes.length} valid route(s) retained).\n`,
    );
  }
  for (const route of routes) {
    if (!route || typeof route !== "object") continue;
    const metadata = surfaceMetadataFromRoute(route);
    if (!metadata) continue;
    map[metadata.id] = metadata;
  }

  // Quarantine wins even when a valid duplicate row survived.  A corrupt row
  // for this exact surface is an authority conflict, not permission to reuse
  // the first active route.
  if (result && Array.isArray(result.malformed_routes)) {
    for (const malformed of result.malformed_routes) {
      if (!malformed || typeof malformed.surface_id !== "string" || !malformed.surface_id) continue;
      map[malformed.surface_id] = quarantinedRouteMetadata({
        surfaceId: malformed.surface_id,
        reason: malformed.reason,
        rawMetadata: malformed.route_metadata,
        fallbackMetadata: currentById[malformed.surface_id],
      });
    }
  }

  // The materialized surface ledger is authoritative for deny provenance.  A
  // stale/missing route cannot turn an explicitly physical API/asset surface
  // into a web surface.  Preserve a quarantine tombstone's stronger conflict
  // marker when one already exists.
  for (const [surfaceId, surface] of Object.entries(currentById)) {
    if (!isPhysicalSurfaceMetadata(surface)) continue;
    const prior = map[surfaceId] && typeof map[surfaceId] === "object"
      ? map[surfaceId]
      : {};
    map[surfaceId] = {
      ...prior,
      id: surfaceId,
      surface_type: surface.surface_type || prior.surface_type || "physical",
      surface_class: "physical",
      capability_pack: null,
      required_capability_pack: PHYSICAL_CAPABILITY_PACK.id,
      required_capability_pack_version: PHYSICAL_CAPABILITY_PACK.capability_pack_version,
      disposition: "unroutable",
      reason: prior.reason || PHYSICAL_CAPABILITY_PACK.dispatch_block_reason,
    };
  }
  return map;
}

function applyPhysicalOnlySessionDenyPrecedence(targetDomain, node, metadataInput) {
  let nucleus;
  try {
    nucleus = readVerifiedSessionNucleus(targetDomain);
  } catch {
    // Legacy sessions may not carry a persisted nucleus. Preserve their
    // historical route-derived behavior; a physical-only session, by
    // contrast, always has a verified nucleus written by its bootstrap.
    return metadataInput;
  }
  const policy = nucleus && nucleus.scope_policy;
  const physicalOnly = nucleus && nucleus.physical_scope != null
    && policy && policy.target_url == null
    && policy.target_repo == null
    && (!Array.isArray(policy.target_contracts) || policy.target_contracts.length === 0);
  if (!physicalOnly) return metadataInput;

  const metadata = { ...metadataInput };
  const surfaceRefs = node && Array.isArray(node.surface_refs)
    ? node.surface_refs
    : [];
  for (const surfaceId of surfaceRefs) {
    if (typeof surfaceId !== "string" || surfaceId.length === 0) continue;
    const prior = metadata[surfaceId] && typeof metadata[surfaceId] === "object"
      ? metadata[surfaceId]
      : {};
    metadata[surfaceId] = {
      ...prior,
      id: surfaceId,
      surface_type: prior.surface_type || "physical",
      surface_class: "physical",
      capability_pack: null,
      required_capability_pack: PHYSICAL_CAPABILITY_PACK.id,
      required_capability_pack_version: PHYSICAL_CAPABILITY_PACK.capability_pack_version,
      disposition: "unroutable",
      reason: PHYSICAL_CAPABILITY_PACK.dispatch_block_reason,
    };
  }
  return metadata;
}

// Derive the per-node pack the same way for both prepare and finalize.
// `surfaceMetadataById` may be passed pre-computed so a caller that already read
// the routes for another purpose (finalize's cross-stack mechanism gate) does
// not read surface-routes.json — or re-emit its quarantine WARNING — twice.
function deriveDispatchNodePack({ targetDomain, document, nodeId, node, contract, surfaceMetadataById }) {
  const routeMetadata = surfaceMetadataById != null
    ? surfaceMetadataById
    : safeSurfaceRouteMap(targetDomain);
  const metadata = applyPhysicalOnlySessionDenyPrecedence(targetDomain, node, routeMetadata);
  const graphContext = buildOneHopGraphContext(document, nodeId, metadata);
  const pack = derivePackForNode(node, graphContext, [], contract);
  return { pack, graphContext, surfaceMetadataById: metadata };
}

module.exports = {
  applyPhysicalOnlySessionDenyPrecedence,
  safeSurfaceRouteMap,
  surfaceMetadataFromRoute,
  deriveDispatchNodePack,
};
