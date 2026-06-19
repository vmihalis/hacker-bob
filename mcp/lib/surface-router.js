"use strict";

const fs = require("fs");
const {
  surfaceRoutesPath,
} = require("./paths.js");
const {
  writeFileAtomic,
  readJsonFile,
  withSessionLock,
} = require("./storage.js");
const {
  assertNonEmptyString,
} = require("./validation.js");
const {
  classifySurfaceCapability,
  getCapabilityPack,
  normalizeContextBudget,
} = require("./capability-packs.js");
const {
  currentSurfaces,
} = require("./frontier-projections.js");

const SURFACE_ROUTES_VERSION = 1;
const SURFACE_ROUTE_VERSION = 1;

function buildSurfaceRoutesDocument(domain, { attackSurfaceInfo = null } = {}) {
  // Surface input read from currentSurfaces (Cycle F.5): surface-index.json
  // is authoritative when present; legacy attack_surface.json is only used
  // when the materialized view is absent (transitional fallback removed in D.3).
  const attackSurface = attackSurfaceInfo || currentSurfaces(domain);
  if (attackSurface.source === "missing") {
    // Preserve the legacy contract: routing requires surface input. A session
    // with neither a materialized surface-index.json nor an agent-written
    // attack_surface.json cannot be routed.
    throw new Error(`Missing attack surface JSON: ${attackSurface.path}`);
  }
  const routes = [];
  const seenSurfaceIds = new Set();

  for (const surface of attackSurface.document.surfaces) {
    const surfaceId = assertNonEmptyString(surface.id, "surface.id");
    if (seenSurfaceIds.has(surfaceId)) continue;
    seenSurfaceIds.add(surfaceId);

    const classification = classifySurfaceCapability(surface);
    routes.push({
      surface_id: surfaceId,
      surface_type: classification.surface_type,
      capability_pack: classification.capability_pack,
      capability_pack_version: classification.capability_pack_version,
      evaluator_agent: classification.evaluator_agent,
      brief_profile: classification.brief_profile,
      context_budget: classification.context_budget,
      confidence: classification.confidence,
      reasons: classification.reasons,
    });
  }

  return {
    version: SURFACE_ROUTES_VERSION,
    route_version: SURFACE_ROUTE_VERSION,
    routes,
  };
}

function countRoutesByCapabilityPack(routes) {
  const counts = {};
  for (const route of routes) {
    counts[route.capability_pack] = (counts[route.capability_pack] || 0) + 1;
  }
  return counts;
}

function validateSurfaceRoute(route, index, filePath) {
  if (route == null || typeof route !== "object" || Array.isArray(route)) {
    throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}] must be an object)`);
  }
  const surfaceId = assertNonEmptyString(route.surface_id, `routes[${index}].surface_id`);
  const capabilityPack = assertNonEmptyString(route.capability_pack, `routes[${index}].capability_pack`);
  const evaluatorAgent = assertNonEmptyString(route.evaluator_agent, `routes[${index}].evaluator_agent`);
  const briefProfile = assertNonEmptyString(route.brief_profile, `routes[${index}].brief_profile`);
  const pack = getCapabilityPack(capabilityPack);
  if (!pack) {
    throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}] references unknown capability_pack: ${capabilityPack})`);
  }
  if (evaluatorAgent !== pack.evaluator_agent) {
    throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}].evaluator_agent ${evaluatorAgent} does not match pack ${capabilityPack})`);
  }
  if (briefProfile !== pack.brief_profile) {
    throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}].brief_profile ${briefProfile} does not match pack ${capabilityPack})`);
  }
  const capabilityPackVersion = route.capability_pack_version == null
    ? pack.capability_pack_version
    : route.capability_pack_version;
  if (!Number.isInteger(capabilityPackVersion) || capabilityPackVersion <= 0) {
    throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}].capability_pack_version must be a positive integer)`);
  }
  return {
    ...route,
    surface_id: surfaceId,
    capability_pack: capabilityPack,
    capability_pack_version: capabilityPackVersion,
    evaluator_agent: evaluatorAgent,
    brief_profile: briefProfile,
    context_budget: normalizeContextBudget(route.context_budget, pack),
  };
}

function routeSurfacesInternal(domain, { attackSurfaceInfo = null } = {}) {
  const targetDomain = assertNonEmptyString(domain, "target_domain");
  const document = buildSurfaceRoutesDocument(targetDomain, { attackSurfaceInfo });
  const filePath = surfaceRoutesPath(targetDomain);
  writeFileAtomic(filePath, `${JSON.stringify(document, null, 2)}\n`);

  return {
    path: filePath,
    document,
    counts: countRoutesByCapabilityPack(document.routes),
  };
}

function readSurfaceRoutesStrict(domain) {
  const filePath = surfaceRoutesPath(domain);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing surface routes JSON: ${filePath}`);
  }
  let parsed;
  try {
    parsed = readJsonFile(filePath);
  } catch (error) {
    throw new Error(`Malformed surface routes JSON: ${filePath} (${error.message || String(error)})`);
  }
  if (
    parsed == null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    parsed.version !== SURFACE_ROUTES_VERSION ||
    parsed.route_version !== SURFACE_ROUTE_VERSION ||
    !Array.isArray(parsed.routes)
  ) {
    throw new Error(`Malformed surface routes JSON: ${filePath} (expected versioned routes document)`);
  }
  const seenSurfaceIds = new Set();
  const routes = parsed.routes.map((route, index) => {
    const normalized = validateSurfaceRoute(route, index, filePath);
    if (seenSurfaceIds.has(normalized.surface_id)) {
      throw new Error(`Malformed surface routes JSON: ${filePath} (duplicate surface_id: ${normalized.surface_id})`);
    }
    seenSurfaceIds.add(normalized.surface_id);
    return normalized;
  });
  return { path: filePath, document: { ...parsed, routes } };
}

function routeSurfaces(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return withSessionLock(domain, () => {
    const routed = routeSurfacesInternal(domain);
    return JSON.stringify({
      version: SURFACE_ROUTES_VERSION,
      routed: true,
      target_domain: domain,
      route_version: SURFACE_ROUTE_VERSION,
      surface_count: routed.document.routes.length,
      counts: routed.counts,
      surface_routes_path: routed.path,
    });
  });
}

module.exports = {
  SURFACE_ROUTE_VERSION,
  SURFACE_ROUTES_VERSION,
  buildSurfaceRoutesDocument,
  countRoutesByCapabilityPack,
  readSurfaceRoutesStrict,
  routeSurfaces,
  routeSurfacesInternal,
  validateSurfaceRoute,
};
