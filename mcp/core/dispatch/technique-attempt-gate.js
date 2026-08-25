"use strict";

// Shared technique-attempt requirement, used by BOTH the finalize/SubagentStop
// gate (agent-run-completion.js evaluateAgentCompletion) and the
// started -> merge path (wave-handoff-store.js). Single-sourcing the matching
// here keeps the two gates from diverging: a surface assigned with
// `attempt_log_required` must carry a same-domain, same-surface technique
// attempt in a completion status before its handoff is honored. The lead-*
// relaxation is NOT applied inside this function — it stays a separate
// caller-side predicate (isRecoverableBlockCode) so the finalize gate keeps
// blocking uniformly at SubagentStop while the merge gate composes the
// relaxation on its own branch.

const {
  readTechniqueAttemptRecordsFromJsonl,
} = require("./technique-packs.js");

const TECHNIQUE_ATTEMPT_COMPLETION_STATUSES = new Set([
  "attempted",
  "not_applicable",
  "promising",
  "validated",
  "failed",
  "skipped",
]);

function evaluateTechniqueAttemptRequirement(marker, assignment) {
  if (
    !assignment ||
    !assignment.context_budget ||
    assignment.context_budget.attempt_log_required !== true
  ) {
    return null;
  }

  let attempts;
  try {
    attempts = readTechniqueAttemptRecordsFromJsonl(marker.target_domain);
  } catch (error) {
    return {
      ok: false,
      status: "blocked",
      block_code: "invalid_technique_attempt_log",
      reason: `Evaluator ${marker.wave}/${marker.agent} has unreadable technique attempt history: ${error.message || String(error)}`,
      marker,
      handoff: null,
    };
  }

  // wave/agent are OPTIONAL on bob_log_technique_attempt (technique-packs.js
  // resolves the route directly when they are omitted), so a valid
  // completion-status attempt may be recorded with no wave/agent at all. Only
  // reject on a wave/agent MISMATCH (a value that belongs to a different run);
  // an absent wave/agent on a same-domain, same-surface, completion-status
  // attempt satisfies the requirement. This prevents a phantom
  // missing_technique_attempt_log on a genuinely-evaluated surface.
  //
  // Accepted residual: an attempt logged WITHOUT wave/agent for a stable
  // surface_id that is later requeued into a new wave would also satisfy that
  // new wave's finalize. This is bounded and acceptable — the gate is an
  // anti-laziness signal, not a security boundary; the wave handoff itself
  // stays wave-bound (a lazy later-wave run must still produce a fresh handoff),
  // and the evaluator prompt now mandates passing wave/agent, so a compliant
  // attempt carries the wave and is mismatch-rejected for any other wave.
  const matchingAttempt = attempts.find((attempt) =>
    attempt.target_domain === marker.target_domain &&
    attempt.surface_id === marker.surface_id &&
    (attempt.wave == null || attempt.wave === marker.wave) &&
    (attempt.agent == null || attempt.agent === marker.agent) &&
    TECHNIQUE_ATTEMPT_COMPLETION_STATUSES.has(attempt.status)
  );
  if (matchingAttempt) return null;

  return {
    ok: false,
    status: "blocked",
    block_code: "missing_technique_attempt_log",
    reason: `Evaluator ${marker.wave}/${marker.agent} must call bob_log_technique_attempt with a real attempt outcome before finalizing this surface.`,
    marker,
    handoff: null,
  };
}

module.exports = {
  TECHNIQUE_ATTEMPT_COMPLETION_STATUSES,
  evaluateTechniqueAttemptRequirement,
};
