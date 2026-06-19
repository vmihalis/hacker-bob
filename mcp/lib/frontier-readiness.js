"use strict";

// Frontier readiness analytics. Cycle D.1 of the frontier-topology
// realization hypergraph deletes phase-gates.js and the legacy phase FSM;
// the analytics functions that compute "is the frontier ready to close into
// a claim batch" survive here because wave-status and other read-only
// surfaces still need them. The numerical outputs are unchanged from the
// pre-D.1 phase-gates module; only the home and the vocabulary moved.
//
// Concretely, this module computes:
//   - openRequeueSurfaceIds: which surfaces still have unfinished coverage,
//   - attackSurfaceCoverage: explored / closed / unexplored breakdown,
//   - frontierReadiness: blocker list explaining why the frontier cannot
//     yet be safely frozen into a CLAIM_FREEZE batch.
//
// The gating outputs are consumed by:
//   - waveStatus (wave-prereq-snapshots.js) — operator visibility,
//   - test suites validating the analytics contract,
//   - future lifecycle-gates hooks (Cycle G.2 noted the hook architecture;
//     the OPEN_FRONTIER -> CLAIM_FREEZE gate will hang on this readiness
//     output once promotable-lead and unexplored-high invariants land in
//     the lifecycle plane).

const {
  COVERAGE_UNFINISHED_STATUS_VALUES,
} = require("./constants.js");
const {
  rankAttackSurfaces,
} = require("./ranking.js");
const {
  latestCoverageRecordsByKey,
  readCoverageRecordsFromJsonl,
} = require("./coverage.js");
const {
  currentBlockers,
  currentClosures,
  currentSurfaces,
} = require("./frontier-projections.js");

function compactErrorMessage(error) {
  return error && error.message ? error.message : String(error);
}

function surfaceLeadsLib() {
  return require("./surface-leads.js");
}

function blocker(code, message, fields = {}) {
  return {
    code,
    message,
    ...fields,
  };
}

function pushUnique(target, seen, value) {
  if (!value || seen.has(value)) return;
  seen.add(value);
  target.push(value);
}

// Closures and blockers are read from frontier-projections (Cycle F.3 / D.3):
// the frontier-events.jsonl ledger is the authoritative source for
// surface-level closure / blocker truth. After D.3 the legacy state.json
// arrays were removed and the wave-merge path emits authoritative
// surface_fully_explored / terminally_blocked frontier events as the sole
// surface-state writer.
function exploredSurfaceIdsForDomain(domain) {
  return currentClosures(domain).map((closure) => closure.surface_id);
}

function terminallyBlockedSurfaceIdsForDomain(domain) {
  return currentBlockers(domain).map((entry) => entry.surface_id);
}

// Surface-level "open" status is governed by frontier-projections derived
// from `closure.recorded` and `blocker.asserted` events (Cycle F.3), not by
// per-endpoint coverage rows. A complete handoff says the evaluator declared
// the surface done; a terminally-blocked surface has been classified as
// blocked-by-prereq across waves and should not requeue until an operator
// clears it. An old coverage row with status=requeue from an earlier wave is
// endpoint-level history, not the surface's current state. Options-bag
// signature so additional closure reasons in future cycles do not shift
// positional arg meaning.
function computeOpenRequeueSurfaceIds(records, options = {}) {
  const exploredSet = new Set(options.exploredSurfaceIds || []);
  const terminallyBlockedSet = new Set(options.terminallyBlockedSurfaceIds || []);
  const latestRecords = Array.from(latestCoverageRecordsByKey(records).values());
  const surfaceIds = [];
  const seen = new Set();

  for (const record of latestRecords) {
    if (!COVERAGE_UNFINISHED_STATUS_VALUES.includes(record.status)) continue;
    if (exploredSet.has(record.surface_id)) continue;
    if (terminallyBlockedSet.has(record.surface_id)) continue;
    pushUnique(surfaceIds, seen, record.surface_id);
  }

  return surfaceIds.sort((a, b) => a.localeCompare(b));
}

function computeAttackSurfaceCoverage(surfaces, exploredSurfaceIds, terminallyBlockedSurfaceIds, openRequeueSurfaceIds) {
  const exploredSet = new Set(exploredSurfaceIds || []);
  const terminallyBlockedSet = new Set(terminallyBlockedSurfaceIds || []);
  const isHighOrCritical = (surface) =>
    ["CRITICAL", "HIGH"].includes(String(surface.priority || "").toUpperCase());
  const nonLowSurfaces = surfaces.filter(
    (surface) => surface.priority && String(surface.priority).toUpperCase() !== "LOW",
  );
  const nonLowExplored = nonLowSurfaces.filter((surface) => exploredSet.has(surface.id)).length;
  const nonLowTerminallyBlocked = nonLowSurfaces.filter((surface) => terminallyBlockedSet.has(surface.id)).length;
  // unexplored_high is the operator-actionable HIGH/CRITICAL set: surfaces
  // that are neither explored nor terminally_blocked. blocked_high is the
  // separately-actionable set: HIGH/CRITICAL surfaces classified blocked
  // by the merge promotion. Each demands a different operator response, so
  // they are surfaced as distinct fields rather than collapsed into one
  // "non-explored" list.
  const unexploredHighSurfaceIds = surfaces
    .filter((surface) => (
      isHighOrCritical(surface) &&
      !exploredSet.has(surface.id) &&
      !terminallyBlockedSet.has(surface.id)
    ))
    .map((surface) => surface.id);
  const blockedHighSurfaceIds = surfaces
    .filter((surface) => isHighOrCritical(surface) && terminallyBlockedSet.has(surface.id))
    .map((surface) => surface.id);

  return {
    total_surfaces: surfaces.length,
    non_low_total: nonLowSurfaces.length,
    non_low_explored: nonLowExplored,
    non_low_terminally_blocked: nonLowTerminallyBlocked,
    non_low_closed: nonLowExplored + nonLowTerminallyBlocked,
    // coverage_pct keeps the explored-only meaning for back-compat with
    // existing analytics/report consumers. closed_pct includes
    // terminally-blocked surfaces (which are closed for the purposes of
    // frontier-readiness gating), so it represents "how much work is actually
    // off the queue" — neglected gap is non_low_total - non_low_closed.
    coverage_pct: nonLowSurfaces.length > 0
      ? Math.round((nonLowExplored / nonLowSurfaces.length) * 100)
      : 100,
    closed_pct: nonLowSurfaces.length > 0
      ? Math.round(((nonLowExplored + nonLowTerminallyBlocked) / nonLowSurfaces.length) * 100)
      : 100,
    unexplored_high: unexploredHighSurfaceIds.length,
    unexplored_high_surface_ids: unexploredHighSurfaceIds,
    blocked_high: blockedHighSurfaceIds.length,
    blocked_high_surface_ids: blockedHighSurfaceIds,
    open_requeue_surface_ids: openRequeueSurfaceIds,
  };
}

// Readiness analytics for closing the frontier into a CLAIM_FREEZE batch.
// Replaces phase-gates.js:computeEvaluationToChainGate. The blocker list is
// observational — wave-status surfaces it to the operator; the lifecycle
// gate engine (lifecycle-gates.js) can hang an OPEN_FRONTIER -> CLAIM_FREEZE
// gate on the same output without depending on legacy phase FSM helpers.
function computeFrontierReadiness(domain, state) {
  const blockers = [];
  if (state.pending_wave !== null) {
    blockers.push(blocker(
      "pending_wave",
      `pending_wave is still set to ${state.pending_wave}`,
      { pending_wave: state.pending_wave },
    ));
  }

  let surfaces = null;
  let rankedSurfaces = null;
  try {
    rankedSurfaces = rankAttackSurfaces(domain)?.surfaces || null;
  } catch {}
  // Surface coverage reads from currentSurfaces (Cycle F.5): surface-index.json
  // is authoritative when present and falls back to attack_surface.json for
  // legacy sessions only via the explicit projection. D.3 removes the fallback.
  try {
    if (rankedSurfaces) {
      surfaces = rankedSurfaces;
    } else {
      const projection = currentSurfaces(domain);
      if (projection.source === "missing") {
        blockers.push(blocker(
          "attack_surface_unavailable",
          "attack surface could not be read for frontier readiness",
          { error: `Missing attack surface JSON: ${projection.path}` },
        ));
      } else {
        surfaces = projection.surfaces;
      }
    }
  } catch (error) {
    blockers.push(blocker(
      "attack_surface_unavailable",
      "attack surface could not be read for frontier readiness",
      { error: compactErrorMessage(error) },
    ));
  }

  const exploredSurfaceIds = exploredSurfaceIdsForDomain(domain);
  const terminallyBlockedSurfaceIds = terminallyBlockedSurfaceIdsForDomain(domain);

  let openRequeueSurfaceIds = [];
  try {
    openRequeueSurfaceIds = computeOpenRequeueSurfaceIds(
      readCoverageRecordsFromJsonl(domain),
      {
        exploredSurfaceIds,
        terminallyBlockedSurfaceIds,
      },
    );
  } catch (error) {
    blockers.push(blocker(
      "coverage_unavailable",
      "coverage could not be read for frontier readiness",
      { error: compactErrorMessage(error) },
    ));
  }

  let coverage = null;
  if (surfaces) {
    coverage = computeAttackSurfaceCoverage(
      surfaces,
      exploredSurfaceIds,
      terminallyBlockedSurfaceIds,
      openRequeueSurfaceIds,
    );
    if (coverage.unexplored_high_surface_ids.length > 0) {
      blockers.push(blocker(
        "unexplored_high_surfaces",
        "HIGH or CRITICAL attack surfaces remain unexplored",
        { surface_ids: coverage.unexplored_high_surface_ids },
      ));
    }
    if (coverage.blocked_high_surface_ids.length > 0) {
      blockers.push(blocker(
        "blocked_high_surfaces",
        "HIGH or CRITICAL surfaces are terminally blocked by missing prerequisites; add the registered material and clear via bob_clear_terminal_block, or accept the gap with override_reason",
        { surface_ids: coverage.blocked_high_surface_ids },
      ));
    }
  }

  if (openRequeueSurfaceIds.length > 0) {
    blockers.push(blocker(
      "open_requeue_coverage",
      "latest coverage has unfinished promising, needs_auth, or requeue work",
      { surface_ids: openRequeueSurfaceIds },
    ));
  }

  if (state.deep_mode === true) {
    try {
      const preview = surfaceLeadsLib().previewSurfaceLeadPromotion(domain, {
        limit: 8,
        min_score: 60,
        include_medium: false,
      });
      if (preview.would_promote_lead_ids.length > 0) {
        blockers.push(blocker(
          "promotable_surface_leads",
          "deep mode has assignable unpromoted surface leads; call bob_start_next_wave to promote and assign the next runtime-owned wave",
          { lead_ids: preview.would_promote_lead_ids },
        ));
      }
    } catch (error) {
      blockers.push(blocker(
        "surface_leads_unavailable",
        "surface leads could not be read for deep-mode frontier readiness",
        { error: compactErrorMessage(error) },
      ));
    }
  }

  return {
    coverage,
    transition_blockers: blockers,
  };
}

module.exports = {
  computeAttackSurfaceCoverage,
  computeFrontierReadiness,
  computeOpenRequeueSurfaceIds,
};
