"use strict";

const {
  COVERAGE_UNFINISHED_STATUS_VALUES,
  CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES,
} = require("./constants.js");
const fs = require("fs");
const path = require("path");
const {
  readAttackSurfaceStrict,
} = require("./attack-surface.js");
const {
  rankAttackSurfaces,
} = require("./ranking.js");
const {
  latestCoverageRecordsByKey,
  readCoverageRecordsFromJsonl,
} = require("./coverage.js");
const {
  readFindingsFromJsonl,
} = require("./findings.js");
const {
  readChainAttemptsFromJsonl,
  summarizeChainAttempts,
} = require("./chain-attempts.js");
const {
  sessionDir,
} = require("./paths.js");

function compactErrorMessage(error) {
  return error && error.message ? error.message : String(error);
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

function computeOpenRequeueSurfaceIds(records) {
  const latestRecords = Array.from(latestCoverageRecordsByKey(records).values());
  const surfaceIds = [];
  const seen = new Set();

  for (const record of latestRecords) {
    if (!COVERAGE_UNFINISHED_STATUS_VALUES.includes(record.status)) continue;
    pushUnique(surfaceIds, seen, record.surface_id);
  }

  return surfaceIds.sort((a, b) => a.localeCompare(b));
}

function computeAttackSurfaceCoverage(surfaces, state, openRequeueSurfaceIds) {
  const exploredSet = new Set(Array.isArray(state.explored) ? state.explored : []);
  const nonLowSurfaces = surfaces.filter(
    (surface) => surface.priority && String(surface.priority).toUpperCase() !== "LOW",
  );
  const nonLowExplored = nonLowSurfaces.filter((surface) => exploredSet.has(surface.id)).length;
  const unexploredHighSurfaceIds = surfaces
    .filter((surface) => (
      ["CRITICAL", "HIGH"].includes(String(surface.priority || "").toUpperCase()) &&
      !exploredSet.has(surface.id)
    ))
    .map((surface) => surface.id);

  return {
    total_surfaces: surfaces.length,
    non_low_total: nonLowSurfaces.length,
    non_low_explored: nonLowExplored,
    coverage_pct: nonLowSurfaces.length > 0
      ? Math.round((nonLowExplored / nonLowSurfaces.length) * 100)
      : 100,
    unexplored_high: unexploredHighSurfaceIds.length,
    unexplored_high_surface_ids: unexploredHighSurfaceIds,
    open_requeue_surface_ids: openRequeueSurfaceIds,
  };
}

function computeHuntToChainGate(domain, state) {
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
    rankedSurfaces = rankAttackSurfaces(domain, { write: false })?.surfaces || null;
  } catch {}
  try {
    surfaces = rankedSurfaces || readAttackSurfaceStrict(domain).document.surfaces;
  } catch (error) {
    blockers.push(blocker(
      "attack_surface_unavailable",
      "attack surface could not be read for HUNT -> CHAIN gating",
      { error: compactErrorMessage(error) },
    ));
  }

  let openRequeueSurfaceIds = [];
  try {
    openRequeueSurfaceIds = computeOpenRequeueSurfaceIds(readCoverageRecordsFromJsonl(domain));
  } catch (error) {
    blockers.push(blocker(
      "coverage_unavailable",
      "coverage could not be read for HUNT -> CHAIN gating",
      { error: compactErrorMessage(error) },
    ));
  }

  let coverage = null;
  if (surfaces) {
    coverage = computeAttackSurfaceCoverage(surfaces, state, openRequeueSurfaceIds);
    if (coverage.unexplored_high_surface_ids.length > 0) {
      blockers.push(blocker(
        "unexplored_high_surfaces",
        "HIGH or CRITICAL attack surfaces remain unexplored",
        { surface_ids: coverage.unexplored_high_surface_ids },
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

  return {
    coverage,
    transition_blockers: blockers,
  };
}

function readStructuredHandoffChainNotes(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) {
    return [];
  }

  const refs = [];
  for (const fileName of fs.readdirSync(dir).sort()) {
    const match = fileName.match(/^handoff-(w[1-9][0-9]*)-(a[1-9][0-9]*)\.json$/);
    if (!match) continue;
    let document;
    try {
      document = JSON.parse(fs.readFileSync(path.join(dir, fileName), "utf8"));
    } catch {
      continue;
    }
    if (!document || typeof document !== "object" || Array.isArray(document)) continue;
    if (document.target_domain != null && document.target_domain !== domain) continue;
    const chainNotes = Array.isArray(document.chain_notes)
      ? document.chain_notes.filter((note) => typeof note === "string" && note.trim())
      : [];
    if (chainNotes.length === 0) continue;
    refs.push({
      wave: match[1],
      agent: match[2],
      surface_id: typeof document.surface_id === "string" ? document.surface_id.trim() : null,
      chain_notes_count: chainNotes.length,
    });
  }
  return refs;
}

function computeChainRequirement(domain) {
  const findings = readFindingsFromJsonl(domain);
  const handoffChainNotes = readStructuredHandoffChainNotes(domain);
  const reasons = [];
  if (findings.length >= 2) reasons.push("multiple_findings");
  if (handoffChainNotes.length > 0) reasons.push("handoff_chain_notes");

  return {
    required: reasons.length > 0,
    reasons,
    findings_count: findings.length,
    finding_ids: findings.map((finding) => finding.id),
    handoff_chain_notes_count: handoffChainNotes.reduce((total, handoff) => total + handoff.chain_notes_count, 0),
    handoff_refs: handoffChainNotes,
  };
}

function computeChainToVerifyGate(domain) {
  const blockers = [];
  let requirement = null;
  let attempts = [];
  let attemptsSummary = null;

  try {
    requirement = computeChainRequirement(domain);
  } catch (error) {
    blockers.push(blocker(
      "chain_context_unavailable",
      "chain context could not be read for CHAIN -> VERIFY gating",
      { error: compactErrorMessage(error) },
    ));
  }

  try {
    attempts = readChainAttemptsFromJsonl(domain);
    attemptsSummary = summarizeChainAttempts(attempts);
  } catch (error) {
    blockers.push(blocker(
      "chain_attempts_unavailable",
      "chain attempts could not be read for CHAIN -> VERIFY gating",
      { error: compactErrorMessage(error) },
    ));
  }

  const terminalAttempts = attempts.filter((attempt) => (
    CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES.includes(attempt.outcome)
  ));

  if (requirement && requirement.required && attemptsSummary && terminalAttempts.length === 0) {
    blockers.push(blocker(
      "chain_attempts_missing",
      "CHAIN phase requires at least one terminal chain attempt before VERIFY",
      {
        findings_count: requirement.findings_count,
        handoff_chain_notes_count: requirement.handoff_chain_notes_count,
        outcomes: attemptsSummary.by_outcome,
      },
    ));
  }

  return {
    chain: {
      requirement,
      attempts: {
        total: attempts.length,
        terminal: terminalAttempts.length,
        by_outcome: attemptsSummary
          ? attemptsSummary.by_outcome
          : null,
      },
    },
    transition_blockers: blockers,
  };
}

function formatTransitionBlockers(blockers) {
  return blockers.map((item) => {
    if (Array.isArray(item.surface_ids) && item.surface_ids.length > 0) {
      return `${item.message}: ${item.surface_ids.join(", ")}`;
    }
    if (item.outcomes) {
      return `${item.message}: ${JSON.stringify(item.outcomes)}`;
    }
    if (item.pending_wave != null) {
      return item.message;
    }
    if (item.error) {
      return `${item.message}: ${item.error}`;
    }
    return item.message;
  }).join("; ");
}

module.exports = {
  computeChainRequirement,
  computeChainToVerifyGate,
  computeHuntToChainGate,
  formatTransitionBlockers,
  readStructuredHandoffChainNotes,
};
