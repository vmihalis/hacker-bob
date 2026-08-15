"use strict";

// E2 — residual-anomaly depth trigger.
//
// A residual anomaly (bob_run_belief_residual) is a model-uncertainty diagnostic
// over belief-window latents — high surprise + entropy mass on mechanism
// entities (effects / policy_gates / endpoints), NOT a per-cell result. There is
// no residual signal keyed to a coverage cell, so E2 is a deterministic JOIN: it
// matches a high/medium-band residual's flagged scopes to a parent SURFACE (via
// token overlap, the existing belief->surface bridge), then re-proposes that
// surface's already-COVERED cells as Tier-2 DEPTH re-probes. The scheduler (C1)
// dispatches Tier-2 after all Tier-1 breadth is exhausted, so the residual only
// deepens proven-live surfaces once coverage is otherwise complete.
//
// DIAGNOSTIC + NON-GATING: E2 only ADDS Tier-2 nodes. It never removes coverage,
// never lowers a Tier-1 node, and never blocks closure — the freeze gate counts
// only the re-derived Tier-1 floor, so an unprobed Tier-2 re-probe can never
// block CLAIM_FREEZE. DEFAULT-OFF: nothing here runs unless the producer is
// called behind residual_depth_reprobe_enabled. DETERMINISTIC: residual is
// deterministic given window+seed; coverage.jsonl is append-only; surfaces +
// covered cells are read deterministically and the output is sorted by cell_key.

// Only a high/medium residual band bumps — low-band noise must not mint depth
// work (classifyResidual already filters score<0.75 to "low").
const REPROBE_BANDS = new Set(["high", "medium"]);

function tokenize(value) {
  return String(value == null ? "" : value)
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length >= 3);
}

function surfaceTokens(surface) {
  const parts = [
    surface && surface.id,
    surface && surface.title,
    surface && surface.name,
    ...(Array.isArray(surface && surface.hosts) ? surface.hosts : []),
    ...(Array.isArray(surface && surface.endpoints) ? surface.endpoints : []),
    ...(Array.isArray(surface && surface.bug_class_hints) ? surface.bug_class_hints : []),
  ];
  const out = new Set();
  for (const part of parts) for (const token of tokenize(part)) out.add(token);
  return out;
}

// Tokens of one residual decomposition entry: its variable id plus every scalar
// in its scope (effect_id / policy_gate_id / principal_id / endpoint / ...).
function decompositionTokens(entry) {
  const out = new Set(tokenize(entry && entry.variable_id));
  const scope = entry && entry.scope && typeof entry.scope === "object" ? entry.scope : {};
  for (const value of Object.values(scope)) {
    for (const token of tokenize(value)) out.add(token);
  }
  return out;
}

function tokensOverlap(a, b) {
  for (const token of a) if (b.has(token)) return true;
  return false;
}

// The latest residual_anomaly signal whose band warrants a depth re-probe,
// keeping its decomposition (latestResidualHint discards it). Null when none.
function latestReprobeAnomaly(targetDomain) {
  try {
    const { queryBeliefSignals } = require("./authority.js");
    const read = queryBeliefSignals({
      target_domain: targetDomain,
      provenance: "residual_anomaly",
      role: "diagnostic",
      limit: 25,
    });
    const signals = Array.isArray(read.signals) ? read.signals : [];
    for (let i = signals.length - 1; i >= 0; i -= 1) {
      const payload = signals[i] && signals[i].payload;
      if (payload && REPROBE_BANDS.has(payload.residual_band) && Array.isArray(payload.decomposition)) {
        return {
          residual_hash: typeof payload.residual_hash === "string" ? payload.residual_hash : "",
          residual_band: payload.residual_band,
          decomposition: payload.decomposition,
        };
      }
    }
  } catch {}
  return null;
}

// A Tier-2 re-probe's cell_key. Same 5-slot coverage shape as a surface cell,
// but the endpoint slot carries a `reprobe:<residual_hash_prefix>` discriminator
// so the re-probe (a) mints a DISTINCT node id (never collides with the finalized
// Tier-1 cell) and (b) is a fresh obligation per residual generation.
function reprobeCellKey(surfaceId, bugClass, authProfile, residualHashPrefix) {
  return JSON.stringify([surfaceId, "", `reprobe:${residualHashPrefix}`, bugClass, authProfile]);
}

// Derive the Tier-2 depth re-probes a residual anomaly bumps. Returns
// [{surface_id, bug_class, auth_profile, cell_key, residual_hash, tier:2}],
// deterministically ordered; empty when no high/medium residual exists or no
// covered cell sits on a residual-flagged surface. Pure read — no writes.
function deriveResidualDepthReprobes(domain) {
  const anomaly = latestReprobeAnomaly(domain);
  if (!anomaly) return [];

  let surfaces;
  let coverageRecords;
  let buildCoverageSummaryForSurface;
  try {
    surfaces = require("../frontier/frontier-projections.js").currentSurfaces(domain).surfaces || [];
    const coverage = require("../frontier/coverage.js");
    coverageRecords = coverage.readCoverageRecordsFromJsonl(domain);
    buildCoverageSummaryForSurface = coverage.buildCoverageSummaryForSurface;
  } catch {
    return [];
  }
  if (!Array.isArray(surfaces) || surfaces.length === 0) return [];

  const decompTokenSets = anomaly.decomposition.map(decompositionTokens);
  const residualHashPrefix = (anomaly.residual_hash || "none").slice(0, 12);

  const flaggedSurfaceIds = [];
  for (const surface of surfaces) {
    const surfaceId = surface && surface.id;
    if (typeof surfaceId !== "string" || !surfaceId) continue;
    const stoks = surfaceTokens(surface);
    if (decompTokenSets.some((dtoks) => tokensOverlap(dtoks, stoks))) {
      flaggedSurfaceIds.push(surfaceId);
    }
  }
  if (flaggedSurfaceIds.length === 0) return [];

  const reprobes = [];
  const seen = new Set();
  for (const surfaceId of flaggedSurfaceIds.sort()) {
    const summary = buildCoverageSummaryForSurface(coverageRecords, surfaceId);
    const covered = [
      ...(Array.isArray(summary.tested) ? summary.tested : []),
      ...(Array.isArray(summary.blocked) ? summary.blocked : []),
    ];
    for (const item of covered) {
      if (!item || typeof item.bug_class !== "string") continue;
      const bugClass = item.bug_class;
      const authProfile = typeof item.auth_profile === "string" ? item.auth_profile : "";
      const cellKey = reprobeCellKey(surfaceId, bugClass, authProfile, residualHashPrefix);
      if (seen.has(cellKey)) continue;
      seen.add(cellKey);
      reprobes.push({
        surface_id: surfaceId,
        bug_class: bugClass,
        auth_profile: authProfile,
        cell_key: cellKey,
        residual_hash: anomaly.residual_hash,
        tier: 2,
      });
    }
  }
  return reprobes.sort((a, b) => a.cell_key.localeCompare(b.cell_key));
}

module.exports = {
  reprobeCellKey,
  deriveResidualDepthReprobes,
};
