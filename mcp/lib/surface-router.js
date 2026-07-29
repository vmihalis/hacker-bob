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
  listAuthProfiles,
} = require("./auth.js");
const {
  loadQueuePolicy,
} = require("./queue-policy.js");
const {
  effectiveSpawnDepth,
} = require("./nested-spawn.js");
const {
  runtimeClient,
} = require("./runtime-resources.js");
const {
  classifySurfaceCapability,
  selectWebEvaluatorPack,
  deriveConfidenceAdjustment,
  getCapabilityPack,
  isCapabilityPackDispatchable,
  isPhysicalSurfaceMetadata,
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

// S1 id-bearing detection is INJECTED by the tool handler (route-surfaces.js),
// never required here: surface-router.js is inside the lead-closure that must
// not reach an alias-require file, and the detector's module transitively does.
function buildSurfaceRoutesDocument(domain, { attackSurfaceInfo = null, frictionEvents = null, authProfileCount = 0, idBearingDetector = null, idBearingEndpoints = null, queuePolicy = null } = {}) {
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
    // An unroutable typed surface carries no active capability pack: it is
    // recorded as a disposition-only route with an evidenced reason, never
    // laundered into the web pack. A registered-but-unavailable family also
    // persists the exact pack/version it requires without granting that pack.
    if (classification.routable === false) {
      const route = {
        surface_id: surfaceId,
        surface_type: classification.surface_type,
        disposition: "unroutable",
        reason: classification.unroutable_reason,
        confidence: classification.confidence,
        reasons: classification.reasons,
      };
      if (classification.surface_class != null) {
        route.surface_class = classification.surface_class;
      }
      if (classification.required_capability_pack != null) {
        route.required_capability_pack = classification.required_capability_pack;
        route.required_capability_pack_version = classification.required_capability_pack_version;
      }
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
    // S1 auth-differential routing obligation is computed from MCP-owned ledgers only.
    // id_bearing is the DETECTOR result, INDEPENDENT of principal count: a single-account run
    // still marks the surface id-bearing so the grade gate keeps the strong no-bypass branch
    // (an id-bearing surface never launders to complete via an agent-authored bypass_attempt
    // narrative). auth_differential_required is the stronger FLIP obligation, which additionally
    // needs >=2 distinct principals to be satisfiable.
    const isIdBearing = !!(idBearingDetector && idBearingDetector(surface));
    route.id_bearing = isIdBearing;
    route.auth_differential_required = isIdBearing && authProfileCount >= 2;
    // Freeze the surface's id-bearing endpoints (template form) onto the MCP-owned route so
    // the completion gates bind coverage to endpoints the agent cannot tamper post-route.
    if (isIdBearing && typeof idBearingEndpoints === "function") {
      const eps = idBearingEndpoints(surface);
      route.id_bearing_endpoints = Array.isArray(eps) ? eps.filter((e) => typeof e === "string" && e) : [];
    }
    // Route a HIGH-VALUE web surface to the spawn-capable web_fanout variant (evaluator-fanout)
    // when nesting can fire, so the (bug_class x auth) child fan-out actuates — the ns.com gap.
    // Overwrite the pack fields from the SELECTED pack so route.evaluator_agent===pack.evaluator_agent
    // stays green (idBearing is the frozen route.id_bearing, never re-derived here).
    // Gate the reroute on the EXACT actuation predicate (assignment-brief:
    // remainingDepth = hostId==="claude" ? effectiveSpawnDepth(...)-1 : 0).
    // effectiveSpawnDepth consumes the registry-declared Claude runtime flag, so
    // default Claude (agent teams off), non-Claude hosts, and depth-1 policies all
    // keep flat web routing and never get a transition-blind evaluator-fanout whose
    // child plan cannot fire.
    const routeHostId = runtimeClient();
    const routeSpawnDepth = routeHostId === "claude"
      ? effectiveSpawnDepth(queuePolicy && queuePolicy.max_spawn_depth, routeHostId)
      : 1;
    const selectedPack = selectWebEvaluatorPack(classification, {
      idBearing: isIdBearing,
      highPriority: String((surface && surface.priority) || "").toUpperCase() === "HIGH",
      spawnDepth: routeSpawnDepth,
      hasBugClassHints: Array.isArray(surface && surface.bug_class_hints) && surface.bug_class_hints.length > 0,
      queuePolicy,
    });
    if (selectedPack && selectedPack.id !== route.capability_pack) {
      route.capability_pack = selectedPack.id;
      route.capability_pack_version = selectedPack.capability_pack_version;
      route.evaluator_agent = selectedPack.evaluator_agent;
      route.brief_profile = selectedPack.brief_profile;
      route.context_budget = selectedPack.context_budget;
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
    // An unroutable route contributes no pack bucket (via the canonical predicate,
    // not a rogue inline null-pack check — one definition even in-file).
    if (isUnroutableRoute(route)) continue;
    counts[route.capability_pack] = (counts[route.capability_pack] || 0) + 1;
  }
  return counts;
}

// The single canonical predicate for "this persisted route is unroutable": it
// carries the disposition marker OR has no capability pack. The write side pairs
// both for a current-version unroutable route (buildSurfaceRoutesDocument), so on
// fresh data disposition ⟺ null-pack; keying on the union closes the SC+null-pack
// wave-halt a cross-version route (one field present without the other) would open,
// and keeps every consumer — the validator, the wave partition, the analytics
// derivation, and technique-pack selection — reading ONE definition.
function isUnroutableRoute(route) {
  return route != null && typeof route === "object"
    && (route.disposition === "unroutable" || route.capability_pack == null);
}

function validateSurfaceRoute(route, index, filePath) {
  if (route == null || typeof route !== "object" || Array.isArray(route)) {
    throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}] must be an object)`);
  }
  // An unroutable route carries a disposition + reason and no active pack.
  // Registered-but-unavailable families may name the exact required pack and
  // version, but that marker is descriptive only and must never carry active
  // evaluator/brief/budget authority.
  if (isUnroutableRoute(route)) {
    const unroutableId = assertNonEmptyString(route.surface_id, `routes[${index}].surface_id`);
    assertNonEmptyString(route.reason, `routes[${index}].reason`);
    const hasRequiredPack = route.required_capability_pack != null;
    const hasRequiredPackVersion = route.required_capability_pack_version != null;
    if (hasRequiredPack !== hasRequiredPackVersion) {
      throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}].required_capability_pack and required_capability_pack_version must be provided together)`);
    }
    const routeSurfaceClass = route.surface_class == null
      ? null
      : assertNonEmptyString(route.surface_class, `routes[${index}].surface_class`);
    const carriesPhysicalSignal = isPhysicalSurfaceMetadata(route);
    if (carriesPhysicalSignal && routeSurfaceClass !== "physical") {
      throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}] with physical surface metadata requires surface_class physical)`);
    }
    if (carriesPhysicalSignal && !hasRequiredPack) {
      throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}] with surface_class physical requires required_capability_pack physical and its version)`);
    }
    let requiredPackId = null;
    if (hasRequiredPack) {
      requiredPackId = assertNonEmptyString(
        route.required_capability_pack,
        `routes[${index}].required_capability_pack`,
      );
      const requiredPack = getCapabilityPack(requiredPackId);
      if (!requiredPack) {
        throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}] references unknown required_capability_pack: ${requiredPackId})`);
      }
      if (isCapabilityPackDispatchable(requiredPack)) {
        throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}].required_capability_pack ${requiredPackId} is dispatchable and cannot describe an unroutable route)`);
      }
      if (requiredPack.surface_class != null && routeSurfaceClass !== requiredPack.surface_class) {
        throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}].surface_class ${routeSurfaceClass || "(missing)"} does not match required_capability_pack ${requiredPackId} surface_class ${requiredPack.surface_class})`);
      }
      if (routeSurfaceClass === "physical" && requiredPackId !== "physical") {
        throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}] with surface_class physical requires required_capability_pack physical)`);
      }
      if (!Number.isInteger(route.required_capability_pack_version)
          || route.required_capability_pack_version <= 0) {
        throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}].required_capability_pack_version must be a positive integer)`);
      }
      if (route.required_capability_pack_version !== requiredPack.capability_pack_version) {
        throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}].required_capability_pack_version ${route.required_capability_pack_version} does not match pack ${requiredPackId})`);
      }
      for (const field of ["capability_pack", "evaluator_agent", "brief_profile", "context_budget"]) {
        if (route[field] != null) {
          throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}].${field} must be absent for required_capability_pack ${requiredPackId})`);
        }
      }
    }
    return {
      ...route,
      surface_id: unroutableId,
      ...(routeSurfaceClass != null ? { surface_class: routeSurfaceClass } : {}),
      ...(requiredPackId != null ? { required_capability_pack: requiredPackId } : {}),
    };
  }
  const surfaceId = assertNonEmptyString(route.surface_id, `routes[${index}].surface_id`);
  const capabilityPack = assertNonEmptyString(route.capability_pack, `routes[${index}].capability_pack`);
  const evaluatorAgent = assertNonEmptyString(route.evaluator_agent, `routes[${index}].evaluator_agent`);
  const briefProfile = assertNonEmptyString(route.brief_profile, `routes[${index}].brief_profile`);
  const pack = getCapabilityPack(capabilityPack);
  if (!pack) {
    throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}] references unknown capability_pack: ${capabilityPack})`);
  }
  if (!isCapabilityPackDispatchable(pack)) {
    throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}] references non-dispatchable capability_pack: ${capabilityPack})`);
  }
  if (isPhysicalSurfaceMetadata(route)) {
    throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}] carries physical surface metadata and cannot bind active capability_pack: ${capabilityPack})`);
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
  const hasAuthDifferentialRequired = Object.prototype.hasOwnProperty.call(route, "auth_differential_required");
  if (hasAuthDifferentialRequired && typeof route.auth_differential_required !== "boolean") {
    throw new Error(`Malformed surface routes JSON: ${filePath} (routes[${index}].auth_differential_required must be a boolean)`);
  }
  return {
    ...route,
    surface_id: surfaceId,
    capability_pack: capabilityPack,
    capability_pack_version: capabilityPackVersion,
    evaluator_agent: evaluatorAgent,
    brief_profile: briefProfile,
    context_budget: normalizeContextBudget(route.context_budget, pack),
    id_bearing: route.id_bearing === true,
    auth_differential_required: route.auth_differential_required === true,
  };
}

function routeSurfacesInternal(domain, { attackSurfaceInfo = null, frictionEvents = null, authProfileCount = 0, idBearingDetector = null, idBearingEndpoints = null, queuePolicy = null } = {}) {
  const targetDomain = assertNonEmptyString(domain, "target_domain");
  const document = buildSurfaceRoutesDocument(targetDomain, { attackSurfaceInfo, frictionEvents, authProfileCount, idBearingDetector, idBearingEndpoints, queuePolicy });
  const filePath = surfaceRoutesPath(targetDomain);
  // Monotonic id-bearing guard: a surface a PRIOR sanctioned route recorded as
  // id_bearing:true can never be silently DOWNGRADED to id_bearing:false by a
  // re-derive. The downgrade needs no signing key: an agent edits the
  // agent-writable attack_surface.json to strip the id markers the detector keys
  // on, then triggers a sanctioned bob_route_surfaces re-route which mints a fresh
  // route (and a fresh MAC) with id_bearing:false — silently un-crowning the
  // surface so the earned-done gate stops requiring a real cross-tenant isolation
  // test. MAC-binding surface-routes.json does not close this: the re-derive
  // re-signs. So bind to the PRIOR route's assertion directly — a surface that was
  // EVER id-bearing stays id_bearing:true and keeps its frozen id_bearing_endpoints.
  // Fail-open on the prior read: first run (no prior file) or an unrecoverable prior
  // simply means no monotonic floor to enforce; routing proceeds byte-identical. The
  // guard is purely ADDITIVE — it only re-asserts id_bearing (over-tag toward the
  // safe HOLD direction), and a genuine first-time false / legit true->true /
  // false->true is never touched.
  let priorIdBearing = null;
  try {
    const prior = readSurfaceRoutesStrict(targetDomain);
    const priorRoutes = prior && prior.document && Array.isArray(prior.document.routes)
      ? prior.document.routes
      : [];
    for (const priorRoute of priorRoutes) {
      if (priorRoute && priorRoute.id_bearing === true
        && typeof priorRoute.surface_id === "string" && priorRoute.surface_id) {
        if (priorIdBearing === null) priorIdBearing = new Map();
        priorIdBearing.set(
          priorRoute.surface_id,
          Array.isArray(priorRoute.id_bearing_endpoints) ? priorRoute.id_bearing_endpoints : [],
        );
      }
    }
  } catch {
    priorIdBearing = null;
  }
  if (priorIdBearing !== null && priorIdBearing.size > 0) {
    for (const route of document.routes) {
      // Only a freshly-derived routable route carries id_bearing:false (an
      // unroutable route has no id_bearing field, so `=== false` skips it — the
      // guard never forces an id-bearing marker onto an unroutable disposition).
      if (route && route.id_bearing === false && priorIdBearing.has(route.surface_id)) {
        route.id_bearing = true;
        // Preserve the frozen prior endpoints; a false-derived route never wrote its
        // own set, so the prior template list is the authoritative coverage binding.
        const priorEps = priorIdBearing.get(route.surface_id);
        route.id_bearing_endpoints = Array.isArray(priorEps) ? priorEps.slice() : [];
        // The stronger FLIP obligation is a LIVE derivation of the now-true id_bearing
        // and the current distinct-principal count (a 2nd principal added/removed
        // between runs legitimately changes it), never a frozen field.
        route.auth_differential_required = authProfileCount >= 2;
      }
    }
  }
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

const QUARANTINED_ROUTE_METADATA_STATUS = "quarantined";

// Preserve only routing-relevant, non-sensitive fields from a quarantined raw
// row.  The full row may contain stale context or future fields and must never
// become an alternate authority surface.
function compactQuarantinedRouteMetadata(route) {
  if (route == null || typeof route !== "object" || Array.isArray(route)) return null;
  const out = {};
  for (const field of [
    "surface_type",
    "surface_class",
    "capability_pack",
    "required_capability_pack",
    "disposition",
  ]) {
    if (typeof route[field] === "string" && route[field].trim()) {
      out[field] = route[field].trim();
    }
  }
  for (const field of ["capability_pack_version", "required_capability_pack_version"]) {
    if (Number.isInteger(route[field])) out[field] = route[field];
  }
  return Object.keys(out).length > 0 ? out : null;
}

// A quarantined route is represented in memory as an explicit deny tombstone,
// never as missing metadata.  Consumers can therefore distinguish a legacy
// surface with no routing artifact from a surface whose routing authority was
// present but failed validation.  Physical provenance wins over every other
// field, including a stale active web pack in the malformed row.
function quarantinedRouteMetadata({ surfaceId, reason, rawMetadata = null, fallbackMetadata = null }) {
  const id = assertNonEmptyString(surfaceId, "quarantined route surface_id");
  const raw = rawMetadata && typeof rawMetadata === "object" ? rawMetadata : {};
  const fallback = fallbackMetadata && typeof fallbackMetadata === "object"
    ? fallbackMetadata
    : {};
  const physical = isPhysicalSurfaceMetadata(raw) || isPhysicalSurfaceMetadata(fallback);
  const surfaceType = [raw.surface_type, fallback.surface_type]
    .find((value) => typeof value === "string" && value.trim()) || "unknown";
  const tombstone = {
    id,
    surface_id: id,
    surface_type: surfaceType.trim(),
    capability_pack: null,
    disposition: "unroutable",
    reason: typeof reason === "string" && reason.trim()
      ? reason.trim()
      : "route metadata was quarantined",
    route_metadata_status: QUARANTINED_ROUTE_METADATA_STATUS,
    dispatch_blocked: true,
  };
  if (physical) {
    const physicalPack = getCapabilityPack("physical");
    tombstone.surface_class = "physical";
    tombstone.required_capability_pack = "physical";
    tombstone.required_capability_pack_version = physicalPack.capability_pack_version;
  }
  return tombstone;
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
        route_metadata: compactQuarantinedRouteMetadata(route),
      });
      return;
    }
    if (seenSurfaceIds.has(normalized.surface_id)) {
      malformedRoutes.push({
        index,
        surface_id: normalized.surface_id,
        reason: `duplicate surface_id: ${normalized.surface_id}`,
        route_metadata: compactQuarantinedRouteMetadata(route),
      });
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
    if (isUnroutableRoute(route) && typeof route.surface_id === "string" && route.surface_id) {
      surfaceIds.add(route.surface_id);
      surfaces.push({
        surface_id: route.surface_id,
        surface_type: route.surface_type,
        ...(route.surface_class != null ? { surface_class: route.surface_class } : {}),
        ...(route.required_capability_pack != null
          ? {
            required_capability_pack: route.required_capability_pack,
            required_capability_pack_version: route.required_capability_pack_version,
          }
          : {}),
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

function routeSurfaces(args, { idBearingDetector = null, idBearingEndpoints = null } = {}) {
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
    let authProfileCount = 0;
    try {
      const authProfiles = JSON.parse(listAuthProfiles({ target_domain: domain }));
      // DISTINCT AUTHENTICATED principals (non-null MCP-owned fingerprints), not raw
      // names — flag the auth-differential obligation only when >=2 real tenants exist
      // (aligns the flag with the completion gate's distinct-principal clearance).
      authProfileCount = Array.isArray(authProfiles.profiles)
        ? new Set(authProfiles.profiles.map((p) => p && p.principal_fingerprint).filter(Boolean)).size
        : 0;
    } catch {
      authProfileCount = 0;
    }
    let queuePolicy = null;
    try { queuePolicy = loadQueuePolicy(domain); } catch { queuePolicy = null; }
    const routed = routeSurfacesInternal(domain, { frictionEvents, authProfileCount, idBearingDetector, idBearingEndpoints, queuePolicy });
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
  QUARANTINED_ROUTE_METADATA_STATUS,
  buildSurfaceRoutesDocument,
  countRoutesByCapabilityPack,
  deriveUnroutableSurfacesFromRoutes,
  isUnroutableRoute,
  quarantinedRouteMetadata,
  readSurfaceRoutesStrict,
  routeSurfaces,
  routeSurfacesInternal,
  validateSurfaceRoute,
};
