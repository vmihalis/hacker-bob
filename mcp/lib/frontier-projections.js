"use strict";

const fs = require("fs");

const {
  assertSafeDomain,
  attackSurfacePath,
  frontierEventsJsonlPath,
  surfaceIndexPath,
} = require("./paths.js");
const {
  readFrontierEvents,
} = require("./frontier-events.js");
const {
  readJsonFile,
} = require("./storage.js");

// frontier-projections fold frontier-events.jsonl into per-surface views that
// downstream readers (frontier-readiness, wave planner, coverage gating)
// consume in place of state.json arrays.
//
// Cycle F.3 established the ledger as the read source. Cycle D.3 deleted the
// legacy state arrays (state.explored, state.terminally_blocked,
// state.lead_surface_ids) along with the transitional state-fallback paths;
// the ledger is now the sole source of surface-level closure / blocker /
// lead truth.
//
// Surface-level state events are authoritative when they:
//   - carry the explicit payload marker (`surface_fully_explored: true` for
//     closures, `terminally_blocked: true` for blockers), or
//   - originate from the wave-merge tool (`source.tool === bob_apply_wave_merge`).
// Coarse-grained signals (per-endpoint coverage rows from log_coverage,
// dead-end batches from log_dead_ends) are excluded from the surface-state
// projection so they do not mask the merge-promotion's surface-level truth.

const SURFACE_STATE_MERGE_SOURCE = "bob_apply_wave_merge";

const LEAD_SURFACE_LABEL = "promoted_surface_lead";

function frontierEventsExist(domain) {
  return fs.existsSync(frontierEventsJsonlPath(domain));
}

function loadFrontierEventsSafely(domain) {
  if (!frontierEventsExist(domain)) return [];
  try {
    return readFrontierEvents(domain);
  } catch {
    return [];
  }
}

function pickReasonFromPayload(payload) {
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) return null;
  if (typeof payload.reason === "string" && payload.reason.trim()) return payload.reason.trim();
  if (typeof payload.code === "string" && payload.code.trim()) return payload.code.trim();
  if (typeof payload.outcome === "string" && payload.outcome.trim()) return payload.outcome.trim();
  return null;
}

function isMergeSourcedEvent(event) {
  const source = event.source;
  if (source == null || typeof source !== "object" || Array.isArray(source)) return false;
  return source.tool === SURFACE_STATE_MERGE_SOURCE;
}

function isSurfaceClosureEvent(event) {
  if (event.kind !== "closure.recorded") return false;
  if (typeof event.surface_id !== "string" || !event.surface_id) return false;
  const payload = event.payload;
  if (payload && typeof payload === "object" && !Array.isArray(payload)
    && payload.surface_fully_explored === true) {
    return true;
  }
  return isMergeSourcedEvent(event);
}

function isSurfaceBlockerEvent(event) {
  if (event.kind !== "blocker.asserted") return false;
  if (typeof event.surface_id !== "string" || !event.surface_id) return false;
  const payload = event.payload;
  if (payload && typeof payload === "object" && !Array.isArray(payload)
    && payload.terminally_blocked === true) {
    return true;
  }
  return isMergeSourcedEvent(event);
}

// A surface-state event is the union of closure / blocker surface-state
// events. Folding "latest of either kind" lets a clear or re-closure
// supersede a prior block, which is the semantic the merge-promotion and
// operator clear paths rely on after D.3.
function isSurfaceStateEvent(event) {
  return isSurfaceClosureEvent(event) || isSurfaceBlockerEvent(event);
}

function compareEventOrder(a, b) {
  const tsA = Date.parse(a.ts || "");
  const tsB = Date.parse(b.ts || "");
  if (Number.isFinite(tsA) && Number.isFinite(tsB) && tsA !== tsB) {
    return tsA - tsB;
  }
  return 0;
}

function foldLatestBySurface(events, predicate, surfaceStatePredicate) {
  const latestState = new Map();
  for (const event of events) {
    if (!surfaceStatePredicate(event)) continue;
    const existing = latestState.get(event.surface_id);
    if (existing == null || compareEventOrder(existing, event) <= 0) {
      latestState.set(event.surface_id, event);
    }
  }
  return Array.from(latestState.values())
    .filter((event) => predicate(event))
    .map((event) => ({
      surface_id: event.surface_id,
      closed_at: typeof event.ts === "string" ? event.ts : null,
      reason: pickReasonFromPayload(event.payload),
      source_event_id: typeof event.event_id === "string" ? event.event_id : null,
    }))
    .sort((a, b) => a.surface_id.localeCompare(b.surface_id));
}

function currentClosures(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const events = loadFrontierEventsSafely(domain);
  return foldLatestBySurface(events, isSurfaceClosureEvent, isSurfaceStateEvent);
}

function currentBlockers(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const events = loadFrontierEventsSafely(domain);
  return foldLatestBySurface(events, isSurfaceBlockerEvent, isSurfaceStateEvent);
}

// A surface is a "lead" if its labels (folded across surface.observed
// events) include the promoted-surface-lead marker. The projection excludes
// surfaces whose latest surface-state event is closure or blocker — the
// wave planner consumes only actionable leads.
function eventCarriesLeadLabel(event) {
  if (event.kind !== "surface.observed") return false;
  if (typeof event.surface_id !== "string" || !event.surface_id) return false;
  const payload = event.payload && typeof event.payload === "object" && !Array.isArray(event.payload)
    ? event.payload
    : null;
  if (!payload) return false;
  if (Array.isArray(payload.labels) && payload.labels.includes(LEAD_SURFACE_LABEL)) {
    return true;
  }
  if (Array.isArray(event.tags) && event.tags.includes(LEAD_SURFACE_LABEL)) {
    return true;
  }
  return false;
}

function currentLeadSurfaceIds(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const events = loadFrontierEventsSafely(domain);
  const leadSurfaceIds = new Set();
  for (const event of events) {
    if (eventCarriesLeadLabel(event)) {
      leadSurfaceIds.add(event.surface_id);
    }
  }
  if (leadSurfaceIds.size === 0) return [];
  // Drop lead surfaces whose latest surface-state event is a closure or a
  // blocker; the wave planner can only assign actionable lead surfaces.
  const latestState = new Map();
  for (const event of events) {
    if (!isSurfaceStateEvent(event)) continue;
    const existing = latestState.get(event.surface_id);
    if (existing == null || compareEventOrder(existing, event) <= 0) {
      latestState.set(event.surface_id, event);
    }
  }
  // Membership: union of attack_surface.json (legacy projection) and the
  // materialized surface-index.json (or its synthesized projection). Either
  // source is enough to keep a lead surface visible to the planner. The
  // union avoids stale-state false negatives between materializer runs and
  // the attack-surface promotion pipeline.
  const knownSurfaceIds = new Set();
  try {
    if (fs.existsSync(attackSurfacePath(domain))) {
      const legacy = readJsonFile(attackSurfacePath(domain), { label: "attack_surface.json" });
      if (legacy && Array.isArray(legacy.surfaces)) {
        for (const surface of legacy.surfaces) {
          if (surface && typeof surface.id === "string" && surface.id) knownSurfaceIds.add(surface.id);
        }
      }
    }
  } catch {
    // Malformed attack_surface.json — surface-index.json is consulted below.
  }
  try {
    const surfaceProjection = currentSurfaces(domain);
    if (surfaceProjection && surfaceProjection.source !== "missing") {
      for (const surface of surfaceProjection.surfaces || []) {
        if (surface && typeof surface.id === "string" && surface.id) knownSurfaceIds.add(surface.id);
      }
    }
  } catch {
    // Projection unavailable; the legacy projection above may still have entries.
  }
  // Also surface.observed events from lead-promotion's promote-to-frontier
  // path constitute "known" surfaces — the promotion writer emits a rich
  // payload (title, hosts, endpoints, score) that the planner can use even
  // before the materializer flushes. Handoff-only lead events (payload only
  // has labels) do not count: handoff-discovered surface ids without a
  // surface.observed body are still leads pending future promotion.
  for (const event of events) {
    if (event.kind !== "surface.observed") continue;
    if (typeof event.surface_id !== "string" || !event.surface_id) continue;
    const payload = event.payload && typeof event.payload === "object" && !Array.isArray(event.payload)
      ? event.payload
      : null;
    if (!payload) continue;
    // Heuristic: a "rich" surface.observed payload carries at least one of
    // the planner-relevant scalar fields. A label-only event (e.g. emitted
    // by appendHandoffLeadSurfaceFrontierEvents) does not promote the
    // surface to known-surface status here.
    if (typeof payload.title === "string"
      || typeof payload.surface_type === "string"
      || Array.isArray(payload.hosts)
      || Array.isArray(payload.endpoints)
      || Number.isFinite(payload.score)
    ) {
      knownSurfaceIds.add(event.surface_id);
    }
  }
  const useFilter = knownSurfaceIds.size > 0;
  const result = [];
  for (const surfaceId of leadSurfaceIds) {
    if (useFilter && !knownSurfaceIds.has(surfaceId)) continue;
    const state = latestState.get(surfaceId);
    if (state == null) {
      result.push(surfaceId);
      continue;
    }
    if (isSurfaceClosureEvent(state) || isSurfaceBlockerEvent(state)) continue;
    result.push(surfaceId);
  }
  return result.sort((a, b) => a.localeCompare(b));
}

function normalizeObservationEvent(event) {
  const payload = event.payload && typeof event.payload === "object" && !Array.isArray(event.payload)
    ? event.payload
    : {};
  // F.4 normalized shape: `kind` carries the observation-class label (e.g.
  // "http_route", "schema_field", "auth_redirect"). Producers stamp this on
  // `payload.observation_kind`; callers can also stash it under `payload.kind`
  // for backward compatibility. Falls back to the event source artifact name.
  let observationKind = null;
  if (typeof payload.observation_kind === "string" && payload.observation_kind.trim()) {
    observationKind = payload.observation_kind.trim();
  } else if (typeof payload.kind === "string" && payload.kind.trim()) {
    observationKind = payload.kind.trim();
  } else if (event.source && typeof event.source === "object" && !Array.isArray(event.source)
    && typeof event.source.artifact === "string" && event.source.artifact.trim()) {
    observationKind = event.source.artifact.trim();
  }
  const source = event.source && typeof event.source === "object" && !Array.isArray(event.source)
    ? {
      artifact: typeof event.source.artifact === "string" ? event.source.artifact : null,
      ref: typeof event.source.ref === "string"
        ? event.source.ref
        : (typeof event.source.tool === "string" ? event.source.tool : null),
    }
    : { artifact: null, ref: null };
  return {
    event_id: typeof event.event_id === "string" ? event.event_id : null,
    surface_id: typeof event.surface_id === "string" ? event.surface_id : null,
    ts: typeof event.ts === "string" ? event.ts : null,
    kind: observationKind,
    payload,
    source,
  };
}

function compareObservationEvents(a, b) {
  const tsA = Date.parse(a.ts || "");
  const tsB = Date.parse(b.ts || "");
  if (Number.isFinite(tsA) && Number.isFinite(tsB) && tsA !== tsB) {
    return tsA - tsB;
  }
  return String(a.event_id || "").localeCompare(String(b.event_id || ""));
}

function observationsForSurface(targetDomain, surfaceId) {
  const domain = assertSafeDomain(targetDomain);
  if (typeof surfaceId !== "string" || !surfaceId.trim()) {
    throw new Error("surface_id must be a non-empty string");
  }
  const trimmed = surfaceId.trim();
  const events = loadFrontierEventsSafely(domain);
  return events
    .filter((event) => event.kind === "observation.recorded" && event.surface_id === trimmed)
    .sort(compareObservationEvents)
    .map(normalizeObservationEvent);
}

// surface-index.json is the authoritative surface source (Cycle F.5).
// currentSurfaces reads it strictly and projects each materialized surface
// into the legacy attack_surface.json shape (id-keyed, with the rich text
// fields that ranking, phase-gates, surface-router, and pipeline-session-
// artifacts consume). When surface-index.json does not exist for a session
// (legacy or pre-F.1), the projection falls back to attack_surface.json.
// The fallback is transitional and removed in D.3.

const SURFACE_INDEX_SCALAR_FIELDS = [
  "title",
  "uri",
  "method",
  "kind",
  "owner",
  "surface_type",
  "attack_vector",
  "severity_ceiling",
  "chain_family",
  "file_path",
  "language",
];

const SURFACE_INDEX_BOOLEAN_FIELDS = [
  "network_reachable",
  "native_source",
  "native_build",
];

const SURFACE_INDEX_ARRAY_FIELDS = [
  "hosts",
  "tech_stack",
  "endpoints",
  "interesting_params",
  "nuclei_hits",
  "js_hints",
  "leaked_secrets",
  "bug_class_hints",
  "high_value_flows",
  "evidence",
  "network_reachable_anchors",
  "network_reachable_dirs",
  "local_only_candidate_dirs",
  "residual_hunt_targets",
];

function readSurfaceIndexDocument(domain) {
  const filePath = surfaceIndexPath(domain);
  if (!fs.existsSync(filePath)) return null;
  // Surface-index.json being on disk but malformed is a hard failure: the
  // ledger is authoritative, so silent fallback to attack_surface.json on
  // corruption would hide ledger-truth divergence. The reader throws and the
  // caller decides whether to swallow.
  return readJsonFile(filePath, { label: "surface-index.json" });
}

function readAttackSurfaceDocumentLegacy(domain) {
  const filePath = attackSurfacePath(domain);
  if (!fs.existsSync(filePath)) return null;
  try {
    return readJsonFile(filePath, { label: "attack_surface.json" });
  } catch (error) {
    // Mirror the legacy readAttackSurfaceStrict error shape so consumers that
    // pattern-match on "Malformed attack surface JSON:" keep working through
    // the deprecation window.
    throw new Error(`Malformed attack surface JSON: ${filePath} (${error.message || String(error)})`);
  }
}

function projectMaterializedSurface(materialized) {
  if (materialized == null || typeof materialized !== "object" || Array.isArray(materialized)) {
    return null;
  }
  const surfaceId = typeof materialized.surface_id === "string" ? materialized.surface_id.trim() : "";
  if (!surfaceId) return null;
  const projected = { id: surfaceId };
  for (const field of SURFACE_INDEX_SCALAR_FIELDS) {
    if (typeof materialized[field] === "string" && materialized[field].trim()) {
      projected[field] = materialized[field].trim();
    }
  }
  for (const field of SURFACE_INDEX_BOOLEAN_FIELDS) {
    if (typeof materialized[field] === "boolean") {
      projected[field] = materialized[field];
    }
  }
  for (const field of SURFACE_INDEX_ARRAY_FIELDS) {
    if (Array.isArray(materialized[field]) && materialized[field].length > 0) {
      projected[field] = materialized[field].slice();
    }
  }
  if (typeof materialized.priority === "string" && materialized.priority.trim()) {
    projected.priority = materialized.priority.trim().toUpperCase();
  }
  if (Array.isArray(materialized.labels) && materialized.labels.length > 0) {
    projected.labels = materialized.labels.slice();
  }
  if (typeof materialized.state === "string" && materialized.state) {
    projected.surface_state = materialized.state;
  }
  return projected;
}

function currentSurfaces(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  // Parse surface-index.json strictly: a malformed file fails loud. The
  // projection does not silently fall back to attack_surface.json on
  // corruption in the runtime hot path (F.5 review gate). When the
  // materialized view is present, it is the authoritative source for the
  // surfaces it knows about; legacy attack_surface.json entries that the
  // ledger has not yet observed (e.g., operator-seeded baseline surfaces
  // during the D.3 deprecation window) are unioned in so promotion paths
  // that emit surface.observed events do not silently drop the baseline.
  const surfaceIndex = readSurfaceIndexDocument(domain);
  if (surfaceIndex && Array.isArray(surfaceIndex.surfaces) && surfaceIndex.surfaces.length > 0) {
    let legacy = null;
    let legacyWarning = null;
    try {
      legacy = readAttackSurfaceDocumentLegacy(domain);
    } catch (error) {
      // The materialized surface-index is authoritative in the hot path;
      // a corrupted legacy attack_surface.json must not block current readers.
      legacyWarning = {
        code: "legacy_attack_surface_unreadable",
        path: attackSurfacePath(domain),
        message: error && error.message ? error.message : String(error),
      };
      legacy = null;
    }
    const surfaces = [];
    const seen = new Set();
    for (const entry of surfaceIndex.surfaces) {
      const projected = projectMaterializedSurface(entry);
      if (!projected) continue;
      if (seen.has(projected.id)) continue;
      seen.add(projected.id);
      surfaces.push(projected);
    }
    if (legacy && Array.isArray(legacy.surfaces)) {
      for (const legacySurface of legacy.surfaces) {
        if (legacySurface == null || typeof legacySurface !== "object" || Array.isArray(legacySurface)) continue;
        const legacyId = typeof legacySurface.id === "string" ? legacySurface.id.trim() : "";
        if (!legacyId || seen.has(legacyId)) continue;
        seen.add(legacyId);
        surfaces.push({ ...legacySurface, id: legacyId });
      }
    }
    return {
      source: "surface_index",
      path: surfaceIndexPath(domain),
      document: { surfaces },
      surfaces,
      warnings: legacyWarning ? [legacyWarning] : [],
      surface_index_hash: typeof surfaceIndex.surface_index_hash === "string"
        ? surfaceIndex.surface_index_hash
      : null,
    };
  }
  const legacy = readAttackSurfaceDocumentLegacy(domain);
  if (legacy == null) {
    return {
      source: "missing",
      path: surfaceIndexPath(domain),
      document: { surfaces: [] },
      surfaces: [],
      warnings: [],
      surface_index_hash: null,
    };
  }
  const surfacesArray = Array.isArray(legacy.surfaces) ? legacy.surfaces.slice() : [];
  return {
    source: "attack_surface_legacy",
    path: attackSurfacePath(domain),
    document: legacy,
    surfaces: surfacesArray,
    warnings: [],
    surface_index_hash: null,
  };
}

module.exports = {
  compareObservationEvents,
  currentBlockers,
  currentClosures,
  currentLeadSurfaceIds,
  currentSurfaces,
  normalizeObservationEvent,
  observationsForSurface,
};
