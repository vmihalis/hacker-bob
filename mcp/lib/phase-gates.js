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
  readGradeVerdict,
} = require("./findings.js");
const {
  requireVerificationCompleteForGrade,
} = require("./verification.js");
const {
  readChainAttemptsFromJsonl,
  summarizeChainAttempts,
} = require("./chain-attempts.js");
const {
  sessionDir,
  statePath,
} = require("./paths.js");
const {
  readJsonFile,
} = require("./storage.js");
const {
  loadWaveAssignments,
} = require("./assignments.js");
const {
  readHandoffSigningKey,
} = require("./handoff-signing-key.js");
const {
  assignmentRequiresToken,
  validateHandoffProvenance,
} = require("./wave-handoff-contracts.js");

// Read the session's handoff_provenance_required flag directly from state.json
// (no normalization, no lock — call sites are read-only). See wave-handoff-store
// for the equivalent helper; we duplicate rather than circular-import.
function readHandoffProvenanceRequired(domain) {
  try {
    const raw = readJsonFile(statePath(domain));
    return raw && raw.handoff_provenance_required === true;
  } catch {
    return false;
  }
}

// Inline rather than importing terminallyBlockedSurfaceIds from
// session-state.js to avoid a circular dep (session-state.js depends on
// phase-gates.js for transition gating).
function extractTerminallyBlockedSurfaceIds(state) {
  const list = Array.isArray(state.terminally_blocked) ? state.terminally_blocked : [];
  return list.map((entry) => entry.surface_id);
}

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

// Surface-level "open" status is governed by `state.explored` and
// `state.terminally_blocked` (both populated from handoffs by
// applyWaveMerge), not by per-endpoint coverage rows. A complete handoff
// says the hunter declared the surface done; a terminally-blocked surface
// has been classified as blocked-by-prereq across waves and should not
// requeue until an operator clears it. An old coverage row with
// status=requeue from an earlier wave is endpoint-level history, not the
// surface's current state. Options-bag signature so additional closure
// reasons in future cycles do not shift positional arg meaning.
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

function computeAttackSurfaceCoverage(surfaces, state, openRequeueSurfaceIds) {
  const exploredSet = new Set(Array.isArray(state.explored) ? state.explored : []);
  const terminallyBlockedSet = new Set(extractTerminallyBlockedSurfaceIds(state));
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
  const unexploredMediumSurfaceIds = surfaces
    .filter((surface) => (
      String(surface.priority || "").toUpperCase() === "MEDIUM" &&
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
    // HUNT -> CHAIN gating), so it represents "how much work is actually
    // off the queue" — neglected gap is non_low_total - non_low_closed.
    coverage_pct: nonLowSurfaces.length > 0
      ? Math.round((nonLowExplored / nonLowSurfaces.length) * 100)
      : 100,
    closed_pct: nonLowSurfaces.length > 0
      ? Math.round(((nonLowExplored + nonLowTerminallyBlocked) / nonLowSurfaces.length) * 100)
      : 100,
    unexplored_high: unexploredHighSurfaceIds.length,
    unexplored_high_surface_ids: unexploredHighSurfaceIds,
    unexplored_medium: unexploredMediumSurfaceIds.length,
    unexplored_medium_surface_ids: unexploredMediumSurfaceIds,
    blocked_high: blockedHighSurfaceIds.length,
    blocked_high_surface_ids: blockedHighSurfaceIds,
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
    rankedSurfaces = rankAttackSurfaces(domain)?.surfaces || null;
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
    openRequeueSurfaceIds = computeOpenRequeueSurfaceIds(
      readCoverageRecordsFromJsonl(domain),
      {
        exploredSurfaceIds: Array.isArray(state.explored) ? state.explored : [],
        terminallyBlockedSurfaceIds: extractTerminallyBlockedSurfaceIds(state),
      },
    );
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
    if (coverage.blocked_high_surface_ids.length > 0) {
      blockers.push(blocker(
        "blocked_high_surfaces",
        "HIGH or CRITICAL surfaces are terminally blocked by missing prerequisites; add the registered material and clear via bounty_clear_terminal_block, or accept the gap with override_reason",
        { surface_ids: coverage.blocked_high_surface_ids },
      ));
    }
    if (state.deep_mode === true && coverage.unexplored_medium_surface_ids.length > 0) {
      blockers.push(blocker(
        "unexplored_medium_surfaces",
        "deep mode: MEDIUM attack surfaces remain unexplored; start the next wave to cover them, or accept the gap with override_reason",
        { surface_ids: coverage.unexplored_medium_surface_ids },
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
        limit: 25,
        min_score: 40,
        include_medium: true,
      });
      if (preview.would_promote_lead_ids.length > 0) {
        blockers.push(blocker(
          "promotable_surface_leads",
          "deep mode has assignable unpromoted surface leads; call bounty_start_next_wave to promote and assign the next runtime-owned wave",
          { lead_ids: preview.would_promote_lead_ids },
        ));
      }
    } catch (error) {
      blockers.push(blocker(
        "surface_leads_unavailable",
        "surface leads could not be read for deep-mode HUNT -> CHAIN gating",
        { error: compactErrorMessage(error) },
      ));
    }
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

  const requireProvenance = readHandoffProvenanceRequired(domain);
  const refs = [];
  const assignmentContexts = new Map();

  function contextFor(wave, agent) {
    if (!assignmentContexts.has(wave)) {
      const waveNumber = Number(wave.slice(1));
      const artifacts = loadWaveAssignments(domain, waveNumber);
      const signingKey = artifacts.assignments.some((assignment) => assignmentRequiresToken(assignment))
        ? readHandoffSigningKey(domain)
        : null;
      assignmentContexts.set(wave, { artifacts, signingKey });
    }
    const context = assignmentContexts.get(wave);
    const assignment = context.artifacts.assignmentByAgent.get(agent);
    if (!assignment) throw new Error(`Unexpected handoff agent ${agent} in ${wave}`);
    return { assignment, signingKey: context.signingKey };
  }

  for (const fileName of fs.readdirSync(dir).sort()) {
    const match = fileName.match(/^handoff-(w[1-9][0-9]*)-(a[1-9][0-9]*)\.json$/);
    if (!match) continue;
    let document;
    try {
      document = readJsonFile(path.join(dir, fileName), { label: fileName });
    } catch {
      continue;
    }
    if (!document || typeof document !== "object" || Array.isArray(document)) continue;
    let assignment;
    try {
      const context = contextFor(match[1], match[2]);
      assignment = context.assignment;
      if (document.target_domain != null && document.target_domain !== domain) continue;
      if (document.wave !== match[1] || document.agent !== match[2] || document.surface_id !== assignment.surface_id) continue;
      validateHandoffProvenance(document, assignment, { signingKey: context.signingKey, requireProvenance });
    } catch {
      continue;
    }
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

function computeVerifyToGradeGate(domain) {
  const blockers = [];
  let evidence = null;
  let verification = null;

  try {
    const validation = requireVerificationCompleteForGrade(domain);
    const evidenceValidation = validation.evidence;
    evidence = {
      valid: true,
      skipped: evidenceValidation.skipped,
      packs_count: evidenceValidation.packs_count,
      representative_samples_count: evidenceValidation.representative_samples_count,
      final_reportable_count: evidenceValidation.final_reportable_count,
      reportable_findings_covered: evidenceValidation.reportable_findings_covered,
      missing_finding_ids: evidenceValidation.missing_finding_ids,
    };
    if (validation.schema_version === 2) {
      verification = {
        schema_version: 2,
        verification_attempt_id: validation.verification_attempt_id,
        verification_snapshot_hash: validation.verification_snapshot_hash,
        adjudication_plan_hash: validation.adjudication_plan_hash,
        final_verification_hash: validation.final_verification_hash,
        counts: validation.counts,
      };
    }
  } catch (error) {
    const message = compactErrorMessage(error);
    const evidenceLike = /Evidence packs|evidence packs|Missing evidence packs|final reportable/i.test(message);
    blockers.push(blocker(
      evidenceLike ? "evidence_packs_invalid" : "verification_chain_incomplete",
      evidenceLike
        ? "evidence packs are missing or invalid for final reportable findings"
        : "verification v2 chain is incomplete or stale",
      { error: message },
    ));
  }

  return {
    evidence,
    verification,
    transition_blockers: blockers,
  };
}

function computeGradeToReportGate(domain) {
  const blockers = [];
  let grade = null;

  try {
    const document = JSON.parse(readGradeVerdict({ target_domain: domain }));
    const feedback = typeof document.feedback === "string" ? document.feedback.trim() : "";
    grade = {
      valid: true,
      verdict: document.verdict,
      total_score: document.total_score,
      findings_count: Array.isArray(document.findings) ? document.findings.length : 0,
      feedback_present: feedback.length > 0,
    };
    if (!feedback) {
      grade.valid = false;
      blockers.push(blocker(
        "grade_feedback_missing",
        "grade verdict feedback is required before REPORT",
      ));
    }
  } catch (error) {
    blockers.push(blocker(
      "grade_verdict_invalid",
      "grade verdict is missing or invalid for REPORT",
      { error: compactErrorMessage(error) },
    ));
  }

  return {
    grade,
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
  computeGradeToReportGate,
  computeHuntToChainGate,
  computeOpenRequeueSurfaceIds,
  computeVerifyToGradeGate,
  formatTransitionBlockers,
  readStructuredHandoffChainNotes,
};
