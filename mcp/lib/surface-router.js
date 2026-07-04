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
  deriveConfidenceAdjustment,
  getCapabilityPack,
  normalizeContextBudget,
} = require("./capability-packs.js");
const {
  capabilityFrictionPayloads,
  readFrontierEvents,
} = require("./frontier-events.js");
const {
  currentSurfaces,
} = require("./frontier-projections.js");
const SURFACE_ROUTES_VERSION = 1;
const SURFACE_ROUTE_VERSION = 1;

function buildSurfaceRoutesDocument(domain, { attackSurfaceInfo = null, frictionEvents = null } = {}) {
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
    // An unroutable smart-contract surface (unknown/unresolved chain_family)
    // carries no capability pack: it is recorded as a disposition-only route
    // with an evidenced reason, never laundered into the web pack.
    if (classification.routable === false) {
      const route = {
        surface_id: surfaceId,
        surface_type: classification.surface_type,
        disposition: "unroutable",
        reason: classification.unroutable_reason,
        confidence: classification.confidence,
        reasons: classification.reasons,
      };
      if (classification.chain_family != null) {
        route.chain_family = classification.chain_family;
      }
      routes.push(route);
      continue;
    }
    // Optional friction-driven confidence demotion (routable routes only).
    // route.confidence is regenerated only by bob_route_surfaces ->
    // buildSurfaceRoutesDocument, so demotion takes effect on (re-)route —
    // cross-run, or on a frontier re-open that re-routes this surface — NOT
    // mid-run. deriveConfidenceAdjustment only LOWERS confidence: it never
    // promotes above the base classification confidence and never changes
    // routability. When frictionEvents is null/absent, confidence is
    // classification.confidence verbatim (byte-identical to no-friction routing).
    let routeConfidence = classification.confidence;
    if (Array.isArray(frictionEvents) && frictionEvents.length > 0) {
      const sliced = capabilityFrictionPayloads(frictionEvents, {
        surfaceId,
        frictionKinds: ["tool_inadequate"],
      });
      const aggregate = { tool_inadequate_count: sliced.length };
      routeConfidence = deriveConfidenceAdjustment(classification.confidence, aggregate);
    }
    const route = {
      surface_id: surfaceId,
      surface_type: classification.surface_type,
      capability_pack: classification.capability_pack,
      capability_pack_version: classification.capability_pack_version,
      evaluator_agent: classification.evaluator_agent,
      brief_profile: classification.brief_profile,
      context_budget: classification.context_budget,
      confidence: routeConfidence,
      reasons: classification.reasons,
    };
    // chain_family is a resolved smart-contract's routing key; web/OSS routes
    // have none, so it is only persisted when the classifier resolved one.
    if (classification.chain_family != null) {
      route.chain_family = classification.chain_family;
    }
    routes.push(route);
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
    // An unroutable route has no capability_pack; skip it so counts do not
    // gain an `undefined` bucket.
    if (route.capability_pack == null) continue;
    counts[route.capability_pack] = (counts[route.capability_pack] || 0) + 1;
  }
  return counts;
}

function validateSurfaceRoute(route, index, filePath) {
  if (route == null || typeof route !== "object" || Array.isArray(route)) {
    throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}] must be an object)`);
  }
  // An unroutable smart-contract route carries a disposition + reason and no
  // pack; validate it as a disposition-only record so it reads back cleanly
  // (a plain Error on bad data keeps a malformed row quarantinable, not a
  // re-thrown code bug).
  if (route.disposition === "unroutable" || route.capability_pack == null) {
    const unroutableId = assertNonEmptyString(route.surface_id, `routes[${index}].surface_id`);
    assertNonEmptyString(route.reason, `routes[${index}].reason`);
    return { ...route, surface_id: unroutableId };
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

function routeSurfacesInternal(domain, { attackSurfaceInfo = null, frictionEvents = null } = {}) {
  const targetDomain = assertNonEmptyString(domain, "target_domain");
  const document = buildSurfaceRoutesDocument(targetDomain, { attackSurfaceInfo, frictionEvents });
  const filePath = surfaceRoutesPath(targetDomain);
  // Validate every generated route BEFORE persisting. classifySurfaceCapability cannot emit an
  // empty/pack-mismatched evaluator_agent today, but a future pack/derivation regression that did
  // would otherwise be silently written and only blow up later on read (bricking unrelated
  // artifacts). Fail fast here with the validator's actionable message instead of persisting a
  // landmine. (Forward-discipline: a breaking route-field change must also bump SURFACE_ROUTE_VERSION
  // above — the un-bumped rename is what let a stale file masquerade as field corruption.)
  document.routes.forEach((route, index) => validateSurfaceRoute(route, index, filePath));
  writeFileAtomic(filePath, `${JSON.stringify(document, null, 2)}\n`);

  return {
    path: filePath,
    document,
    counts: countRoutesByCapabilityPack(document.routes),
  };
}

// validateSurfaceRoute embeds the absolute surface-routes.json path in some error messages. Strip
// it to the basename so a quarantine reason surfaced to a caller (getContextBudget, or the
// malformed_routes returned to read-all consumers) never leaks the local session filesystem path.
function sanitizeRouteReason(message, filePath) {
  const text = typeof message === "string" ? message : String(message);
  return filePath ? text.split(filePath).join("surface-routes.json") : text;
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
  // Per-route resilience: a single malformed/stale route — e.g. one written by a PRIOR framework
  // version after a route-field rename (the hunter_agent -> evaluator_agent v2.1 drift) — must NOT
  // abort the whole read and brick every consumer that funnels through this function (routing,
  // context-budget, the offensive HTTP confirmers, and the downstream verifier/evidence/grader/
  // reporter agents). Quarantine bad/duplicate routes into malformed_routes[] and emit a repair
  // hint; surface-routes.json is fully regenerable via bob_route_surfaces. Genuinely unrecoverable
  // top-level shape (unparseable JSON, version mismatch, routes-not-an-array) still fails hard above.
  const seenSurfaceIds = new Set();
  const routes = [];
  const malformedRoutes = [];
  parsed.routes.forEach((route, index) => {
    let normalized;
    try {
      normalized = validateSurfaceRoute(route, index, filePath);
    } catch (error) {
      // Only a DATA problem (a stale/malformed route) is quarantine-able. validateSurfaceRoute and
      // every helper it calls (assertNonEmptyString, getCapabilityPack, normalizeContextBudget) signal
      // a data-validation failure with a plain `Error`. A JS error SUBCLASS
      // (TypeError/RangeError/ReferenceError/SyntaxError/EvalError/URIError) can therefore only come
      // from a PROGRAMMING regression inside the validator (a null deref, a renamed import). Masking
      // that as a quarantined "stale route" behind a "re-run bob_route_surfaces" hint would hide the
      // bug, so re-throw it loudly. (This also pins the convention: data validation throws plain Error.)
      if (error instanceof TypeError || error instanceof RangeError || error instanceof ReferenceError
        || error instanceof SyntaxError || error instanceof EvalError || error instanceof URIError) {
        throw error;
      }
      const rawSurfaceId = route && typeof route === "object" ? route.surface_id : null;
      malformedRoutes.push({
        index,
        // Trim the stored surface_id: getContextBudget/findRoutedSurface reject a corrupt file by
        // matching the malformed entry's surface_id against the (trimmed) request id, and
        // validateSurfaceRoute trims on the valid path — so a quarantined entry that kept a
        // whitespace-padded id (e.g. " surface:api ") would otherwise EVADE that rejection.
        surface_id: (typeof rawSurfaceId === "string" ? rawSurfaceId.trim() : rawSurfaceId) || null,
        reason: sanitizeRouteReason(error.message || String(error), filePath),
      });
      return;
    }
    if (seenSurfaceIds.has(normalized.surface_id)) {
      malformedRoutes.push({ index, surface_id: normalized.surface_id, reason: `duplicate surface_id: ${normalized.surface_id}` });
      return;
    }
    seenSurfaceIds.add(normalized.surface_id);
    routes.push(normalized);
  });
  const result = { path: filePath, document: { ...parsed, routes } };
  if (malformedRoutes.length > 0) {
    result.malformed_routes = malformedRoutes;
    result.repair_hint = "re-run bob_route_surfaces to regenerate surface-routes.json from the current surface index";
  }
  return result;
}

// Single source of the "unroutable" derivation. planNextWave (fail-CLOSED on
// corruption) and bob_wave_status (additive diagnostic) both call this so they
// share ONE read of surface-routes.json and ONE corruption policy — no divergent
// inline reads that could disagree on whether a parked surface is unroutable.
//   - Missing routes file (no routing yet) -> empty set, empty rows, error:null
//     (fail-open: there are no routes, planning is byte-identical to today).
//   - Corrupt/unreadable/version-mismatch/not-an-array -> empty set, empty rows,
//     error:{code:"routes_unreadable", message} with any absolute session path
//     basename-sanitized (never leak the local filesystem path).
//   - Valid -> the unroutable set + rows; a per-route quarantine (a single stale
//     row the reader dropped) is reported via malformed_route_count + repair_hint
//     so a partial drop is not under-reported either.
function deriveUnroutableSurfacesFromRoutes(domain) {
  const filePath = surfaceRoutesPath(domain);
  let routesResult;
  try {
    routesResult = readSurfaceRoutesStrict(domain);
  } catch (error) {
    const message = error && error.message ? error.message : String(error);
    // A missing routes file is the expected back-compat path (no routing yet),
    // NOT corruption: fail-open with an empty set and no error. Any other hard
    // failure (unparseable JSON, version mismatch, routes-not-an-array) is
    // genuinely unrecoverable — surface a sanitized diagnostic so no absolute
    // session path leaks and callers can fail closed on it.
    if (/^Missing surface routes JSON:/.test(message)) {
      return { surfaceIds: new Set(), surfaces: [], error: null };
    }
    return {
      surfaceIds: new Set(),
      surfaces: [],
      error: { code: "routes_unreadable", message: sanitizeRouteReason(message, filePath) },
    };
  }
  const routes = routesResult && routesResult.document && Array.isArray(routesResult.document.routes)
    ? routesResult.document.routes
    : [];
  const surfaceIds = new Set();
  const surfaces = [];
  for (const route of routes) {
    if (route && route.disposition === "unroutable" && typeof route.surface_id === "string" && route.surface_id) {
      surfaceIds.add(route.surface_id);
      surfaces.push({
        surface_id: route.surface_id,
        surface_type: route.surface_type,
        unroutable_reason: route.reason,
      });
    }
  }
  const result = { surfaceIds, surfaces, error: null };
  // Per-route corruption (a single stale/malformed row the reader dropped) is
  // quarantined, not thrown. Expose the count + repair hint so wave-status can
  // keep its quarantine diagnostic from ONE call instead of re-reading routes.
  if (Array.isArray(routesResult.malformed_routes) && routesResult.malformed_routes.length > 0) {
    result.malformed_route_count = routesResult.malformed_routes.length;
    result.repair_hint = routesResult.repair_hint
      || "re-run bob_route_surfaces to regenerate surface-routes.json from the current surface index";
  }
  return result;
}

function routeSurfaces(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return withSessionLock(domain, () => {
    // Thread friction into the live route so demotion fires on (re-)route.
    // The read is fail-open: a missing/corrupt frontier-events.jsonl yields
    // frictionEvents=null and routing proceeds with base-confidence routes
    // identical to no-friction routing. A friction read NEVER gates or breaks
    // bob_route_surfaces.
    let frictionEvents = null;
    try {
      const ev = readFrontierEvents(domain);
      if (Array.isArray(ev)) frictionEvents = ev;
    } catch {
      frictionEvents = null;
    }
    const routed = routeSurfacesInternal(domain, { frictionEvents });
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
  deriveUnroutableSurfacesFromRoutes,
  readSurfaceRoutesStrict,
  routeSurfaces,
  routeSurfacesInternal,
  validateSurfaceRoute,
};
