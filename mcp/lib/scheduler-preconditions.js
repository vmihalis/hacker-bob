"use strict";

// Y.10 (Y-D12 / Y-P12) — scheduler-precondition registry.
//
// Each scheduler precondition is a closed-enum name that maps to a check
// function returning `{satisfied: boolean, blocked_surface_ids?: string[]}`.
// The runtime gate at bob_advance_session consults these checks before
// allowing OPEN_FRONTIER -> CLAIM_FREEZE; the CI marker scan at
// scripts/check-skill-scheduler-coherence.js consumes the closed enum to
// assert that committed skill / role markdown carries the `@precondition:`
// directive on the relevant state-block.
//
// The set is intentionally narrow: only conditions the runtime gate
// mechanically enforces appear here. New preconditions extend the enum
// AND register a check function in PRECONDITION_CHECKS at the same time
// (paired safety enforcement — see test/scheduler-preconditions-shape.test.js).

const {
  getLatestMergedWavePartialSurfaceIds,
} = require("./wave-handoff-store.js");

const SCHEDULER_PRECONDITION_VALUES = Object.freeze([
  "partial_surfaces_drained",
  "chain_work_terminal",
]);

// Each check receives `{target_domain}` and returns an object with at minimum
// `{satisfied: boolean}`. When unsatisfied, the check MAY return additional
// structured context (e.g., `blocked_surface_ids`) that the gate surfaces in
// the STATE_CONFLICT payload.
const PRECONDITION_CHECKS = Object.freeze({
  partial_surfaces_drained(context) {
    const targetDomain = context && context.target_domain;
    if (typeof targetDomain !== "string" || targetDomain.length === 0) {
      throw new Error("partial_surfaces_drained: target_domain is required");
    }
    const blockedSurfaceIds = getLatestMergedWavePartialSurfaceIds(targetDomain);
    return {
      satisfied: blockedSurfaceIds.length === 0,
      blocked_surface_ids: blockedSurfaceIds,
    };
  },
  // Chain work that is recorded must produce a terminal structured chain
  // attempt before CLAIM_FREEZE. The required-work signal is the same one
  // pipeline-analytics surfaces as `chain_phase_no_attempts`
  // (findings.total >= 2 OR handoff chain_notes_count > 0); the precondition
  // reads it from the canonical session-artifact summary rather than
  // recomputing it, and is satisfied when no chain work is required or a
  // terminal attempt already exists.
  chain_work_terminal(context) {
    const targetDomain = context && context.target_domain;
    if (typeof targetDomain !== "string" || targetDomain.length === 0) {
      throw new Error("chain_work_terminal: target_domain is required");
    }
    const {
      readSessionArtifactSummary,
      chainWorkRequired,
    } = require("./pipeline-session-artifacts.js");
    const summary = readSessionArtifactSummary(targetDomain);
    const findingsTotal = summary && summary.findings && Number.isInteger(summary.findings.total)
      ? summary.findings.total
      : 0;
    const chainNotesCount = summary && summary.chain_handoffs
      && Number.isInteger(summary.chain_handoffs.chain_notes_count)
      ? summary.chain_handoffs.chain_notes_count
      : 0;
    const terminalTotal = summary && summary.chain_attempts
      && Number.isInteger(summary.chain_attempts.terminal_total)
      ? summary.chain_attempts.terminal_total
      : 0;
    const required = chainWorkRequired(summary);
    return {
      satisfied: !required || terminalTotal > 0,
      chain_work_required: required,
      findings_total: findingsTotal,
      chain_notes_count: chainNotesCount,
      terminal_total: terminalTotal,
    };
  },
});

function evaluateSchedulerPrecondition(name, context) {
  if (!SCHEDULER_PRECONDITION_VALUES.includes(name)) {
    throw new Error(`unknown scheduler precondition: ${name}`);
  }
  const check = PRECONDITION_CHECKS[name];
  if (typeof check !== "function") {
    throw new Error(`scheduler precondition ${name} has no check function`);
  }
  return check(context || {});
}

module.exports = {
  SCHEDULER_PRECONDITION_VALUES,
  PRECONDITION_CHECKS,
  evaluateSchedulerPrecondition,
};
